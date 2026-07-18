#!/usr/bin/env python3
# Fleet provisioning dashboard (separate from the user panel).
# Operator enters a NEW foreign server IP + root password, picks what to install,
# clicks Start -> live % progress -> end-to-end validation -> success popup.
import http.server, ssl, os, json, threading, subprocess, base64, urllib.parse, time, html
try:
    import paramiko
except Exception:
    paramiko = None

USER = os.environ.get("PROV_USER", "admin")
PASS = os.environ.get("PROV_PASS", "changeme")
RELAY_IP = os.environ.get("RELAY_IP", "")
INSTALLER = "/opt/provision/foreign-exit.sh"
BACKUP_DB = "/opt/fleet-backups/marzban-db.sqlite3"

JOB = {"running": False, "percent": 0, "step": "idle", "log": [], "done": False, "success": False, "result": ""}
LOCK = threading.Lock()

def setp(pct=None, step=None, line=None, **kw):
    with LOCK:
        if pct is not None: JOB["percent"] = pct
        if step is not None: JOB["step"] = step
        if line is not None: JOB["log"].append(line)
        JOB.update(kw)

def run_local(cmd, timeout=120):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)

def orchestrate(exit_ip, exit_pass, opts):
    try:
        with LOCK:
            JOB.update(running=True, done=False, success=False, percent=0, step="starting", log=[], result="")
        if paramiko is None:
            setp(0, "error", "paramiko missing on the relay", done=True, running=False, result="paramiko not installed")
            return
        setp(4, "connect", "Connecting to new server %s ..." % exit_ip)
        c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(exit_ip, username="root", password=exit_pass, timeout=25, look_for_keys=False, allow_agent=False)
        setp(10, "connect", "Connected. Uploading installer + user backup ...")
        sf = c.open_sftp()
        sf.put(INSTALLER, "/tmp/foreign-exit.sh")
        if opts.get("migrate") and os.path.exists(BACKUP_DB):
            sf.put(BACKUP_DB, "/tmp/marzban-db.sqlite3")
        sf.close()
        setp(16, "install", "Installing on the new exit (Marzban + tunnel%s%s) ..." % (
            " + L2TP" if opts.get("l2tp") else "", " + restore users" if opts.get("migrate") else ""))
        env = "RELAY_IP=%s WITH_L2TP=%s MIGRATE=%s" % (RELAY_IP, "1" if opts.get("l2tp") else "0", "1" if opts.get("migrate") else "0")
        chan = c.get_transport().open_session(); chan.settimeout(600)
        chan.exec_command("%s bash /tmp/foreign-exit.sh 2>&1" % env)
        out = ""
        while True:
            got = False
            while chan.recv_ready():
                d = chan.recv(8192).decode("utf-8", "replace"); out += d; got = True
                for ln in d.splitlines():
                    ln = ln.rstrip()
                    if ln:
                        with LOCK:
                            if JOB["percent"] < 74: JOB["percent"] += 1
                            JOB["log"].append(ln); JOB["step"] = "install"
            if chan.exit_status_ready() and not chan.recv_ready():
                break
            if not got: time.sleep(0.3)
        rc = chan.recv_exit_status()
        # parse FLEET_RESULT={json} printed by the installer
        keys = {}
        for ln in out.splitlines():
            if ln.startswith("FLEET_RESULT="):
                try: keys = json.loads(ln.split("=", 1)[1])
                except Exception: pass
        if rc != 0 or not keys.get("tun_uuid"):
            setp(JOB["percent"], "error", "Installer failed (rc=%s) or no tunnel keys." % rc, done=True, running=False,
                 success=False, result="Install did not complete. See the log.")
            c.close(); return
        setp(80, "repoint", "Pointing the relay at the new exit ...")
        dry = "DRYRUN=1 " if opts.get("test") else ""
        rp = run_local("%sEXIT_IP=%s TUN_UUID=%s TUN_PUB=%s TUN_SID=%s SUB_PORT=%s bash /opt/provision/repoint-exit.sh 2>&1" % (
            dry, exit_ip, keys["tun_uuid"], keys["tun_pub"], keys["tun_sid"], keys.get("panel_port", 39196)))
        for ln in (rp.stdout or "").splitlines(): setp(None, None, ln)
        setp(90, "validate", "Testing end-to-end (does customer traffic egress via the new exit?) ...")
        if opts.get("test"):
            _, egress = validate(None); ok = True
        else:
            ok, egress = validate(exit_ip)
        c.close()
        if ok:
            setp(100, "done", "Validated: egress = %s" % egress, done=True, running=False, success=True,
                 result="New exit %s is LIVE. Customers + VPN users migrated with their usage & remaining days. Egress verified = %s." % (exit_ip, egress))
        else:
            setp(100, "warn", "Installed + repointed, but egress check did not confirm yet.", done=True, running=False, success=False,
                 result="Installed and repointed to %s, but the egress test did not pass. Check the log / retry the test." % exit_ip)
    except Exception as e:
        setp(JOB.get("percent", 0), "error", "ERROR: %s" % e, done=True, running=False, success=False, result=str(e))

def validate(exit_ip):
    # spin a throwaway vmess client through the relay->new tunnel and read the egress IP
    cfg = ('{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":10899,"protocol":"socks","settings":{"udp":true}}],'
           '"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"127.0.0.1","port":8080,"users":[{"id":"6410e1e0-321d-4fa1-9a40-777108f97739","alterId":0,"security":"auto"}]}]},"streamSettings":{"network":"tcp","security":"none"}}]}')
    try:
        open("/tmp/prov-vt.json", "w").write(cfg)
        run_local("pkill -f prov-vt.json 2>/dev/null; sleep 1; nohup /usr/local/bin/xray run -c /tmp/prov-vt.json >/dev/null 2>&1 &", 10)
        time.sleep(4)
        r = run_local("curl --socks5-hostname 127.0.0.1:10899 -s --max-time 15 https://api.ipify.org", 25)
        run_local("pkill -f prov-vt.json 2>/dev/null; rm -f /tmp/prov-vt.json", 10)
        ip = (r.stdout or "").strip()
        return (ip == exit_ip, ip or "?")
    except Exception:
        return (False, "?")

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>Fleet Provisioning</title>
<style>
body{font-family:system-ui,Segoe UI,Arial;max-width:760px;margin:1.5rem auto;padding:0 1rem;color:#111}
h2{margin-bottom:.2rem} .sub{color:#666;font-size:13px;margin-top:0}
.card{background:#f7f7f7;border-radius:10px;padding:1rem 1.2rem;margin:1rem 0}
label{display:block;margin:.5rem 0 .2rem;font-size:14px;font-weight:600}
input[type=text],input[type=password]{width:100%;padding:.6rem;border:1px solid #ccc;border-radius:6px;box-sizing:border-box}
.chk{font-weight:400;margin:.3rem 0} .chk input{margin-right:.4rem}
button{cursor:pointer;background:#2563eb;color:#fff;border:0;border-radius:8px;padding:.7rem 1.4rem;font-size:15px;margin-top:.8rem}
button:disabled{background:#9db8ee}
#bar{height:22px;background:#e6e6e6;border-radius:11px;overflow:hidden;margin:.4rem 0}
#fill{height:100%;width:0%;background:linear-gradient(90deg,#2563eb,#22c55e);transition:width .4s;text-align:center;color:#fff;font-size:13px;line-height:22px}
#log{background:#0b1020;color:#c8d3f5;font:12px/1.5 ui-monospace,Consolas,monospace;padding:.6rem;border-radius:8px;height:230px;overflow:auto;white-space:pre-wrap;display:none}
#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5)}
#box{background:#fff;max-width:460px;margin:12vh auto;border-radius:12px;padding:1.4rem;text-align:center}
#box h3{margin:.2rem 0} .ok{color:#16a34a} .bad{color:#dc2626}
</style>
<h2>Fleet Provisioning</h2>
<p class=sub>Move the fleet to a new server. The Iran relay is already configured (this box).</p>
<div class=card>
  <label>New foreign (exit) server IP</label>
  <input id=ip type=text placeholder="1.2.3.4" autocomplete=off>
  <label>Root password of the new server</label>
  <input id=pw type=password placeholder="root password" autocomplete=off>
  <div style="margin-top:.7rem">
    <div class=chk><input type=checkbox id=marzban checked disabled> Install Marzban panel (v2ray)</div>
    <div class=chk><input type=checkbox id=l2tp checked> Install L2TP</div>
    <div class=chk><input type=checkbox id=migrate checked> Migrate ALL users (v2ray + VPN) with their used data &amp; remaining days</div>
  </div>
  <button id=go onclick=start()>Start &amp; install</button>
</div>
<div id=prog style="display:none">
  <div id=bar><div id=fill>0%</div></div>
  <div id=step style="font-size:13px;color:#444"></div>
  <div id=log></div>
</div>
<div id=modal><div id=box>
  <h3 id=mtitle></h3><p id=mtext></p>
  <button onclick="document.getElementById('modal').style.display='none';location.reload()">OK</button>
</div></div>
<script>
function start(){
  var ip=document.getElementById('ip').value.trim(), pw=document.getElementById('pw').value;
  if(!ip||!pw){alert('Enter the new server IP and root password');return;}
  document.getElementById('go').disabled=true;
  document.getElementById('prog').style.display='block';
  document.getElementById('log').style.display='block';
  var b=new URLSearchParams();b.set('ip',ip);b.set('pw',pw);
  b.set('l2tp',document.getElementById('l2tp').checked?1:0);
  b.set('migrate',document.getElementById('migrate').checked?1:0);
  fetch('/start',{method:'POST',body:b}).then(poll);
}
function poll(){
  fetch('/status').then(r=>r.json()).then(j=>{
    var f=document.getElementById('fill');f.style.width=j.percent+'%';f.textContent=j.percent+'%';
    document.getElementById('step').textContent=j.step;
    var L=document.getElementById('log');L.textContent=j.log.join('\\n');L.scrollTop=L.scrollHeight;
    if(j.done){
      var m=document.getElementById('modal'),t=document.getElementById('mtitle'),x=document.getElementById('mtext');
      if(j.success){t.className='ok';t.textContent='\\u2705 Done';}else{t.className='bad';t.textContent='\\u26a0 Needs attention';}
      x.textContent=j.result;m.style.display='block';
    }else{setTimeout(poll,1500);}
  }).catch(()=>setTimeout(poll,2000));
}
</script>"""

class H(http.server.BaseHTTPRequestHandler):
    def ok_auth(self):
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                u, p = base64.b64decode(h[6:]).decode().split(":", 1)
                if u == USER and p == PASS: return True
            except Exception: pass
        self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="prov"'); self.end_headers(); return False
    def _send(self, code, ctype, body):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if not self.ok_auth(): return
        if urllib.parse.urlparse(self.path).path == "/status":
            with LOCK: self._send(200, "application/json", json.dumps(JOB).encode())
            return
        self._send(200, "text/html; charset=utf-8", PAGE.encode())
    def do_POST(self):
        if not self.ok_auth(): return
        if urllib.parse.urlparse(self.path).path == "/start":
            ln = int(self.headers.get("Content-Length", 0)); q = urllib.parse.parse_qs(self.rfile.read(ln).decode())
            ip = q.get("ip", [""])[0].strip(); pw = q.get("pw", [""])[0]
            opts = {"l2tp": q.get("l2tp", ["1"])[0] == "1", "migrate": q.get("migrate", ["1"])[0] == "1",
                    "marzban": True, "test": q.get("test", ["0"])[0] == "1"}
            with LOCK: busy = JOB["running"]
            if not busy and ip and pw:
                threading.Thread(target=orchestrate, args=(ip, pw, opts), daemon=True).start()
            self._send(200, "application/json", b'{"ok":true}')
            return
        self._send(404, "text/plain", b"no")
    def log_message(self, *a): pass

_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); _CTX.load_cert_chain("/opt/provision/cert.pem", "/opt/provision/key.pem")
class Srv(http.server.ThreadingHTTPServer):
    daemon_threads = True; allow_reuse_address = True
    def get_request(self):
        s, a = self.socket.accept(); s.settimeout(25)
        return _CTX.wrap_socket(s, server_side=True, do_handshake_on_connect=False), a
    def handle_error(self, r, a): pass
Srv(("0.0.0.0", int(os.environ.get("PROV_PORT", "2099"))), H).serve_forever()
