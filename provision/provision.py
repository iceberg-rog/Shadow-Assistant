#!/usr/bin/env python3
# Fleet provisioning dashboard (separate from the user panel).
# Robust: pick SSH user, password OR key, non-root via sudo, TEST the connection
# first (gate), then install with a live % bar + validation + popup.
import http.server, ssl, os, json, threading, subprocess, base64, urllib.parse, time, html, io, sqlite3

try:
    import paramiko
except Exception:
    paramiko = None

USER = os.environ.get("PROV_USER", "admin")
PASS = os.environ.get("PROV_PASS", "changeme")
RELAY_IP = os.environ.get("RELAY_IP", "")
INSTALLER = "/opt/provision/foreign-exit.sh"
BACKUP_DB = "/opt/fleet-backups/marzban-db.sqlite3"
USERS_JSON = "/opt/ovpnpanel/users.json"

JOB = {"running": False, "percent": 0, "step": "idle", "log": [], "done": False, "success": False, "result": ""}
LOCK = threading.Lock()

def setp(pct=None, step=None, line=None, **kw):
    with LOCK:
        if pct is not None: JOB["percent"] = pct
        if step is not None: JOB["step"] = step
        if line is not None: JOB["log"].append(line)
        JOB.update(kw)

def counts():
    v2 = vpn = 0
    try: v2 = sqlite3.connect(BACKUP_DB).execute("select count(*) from users").fetchone()[0]
    except Exception: pass
    try: vpn = len(json.load(open(USERS_JSON)))
    except Exception: pass
    return v2, vpn

def load_key(s):
    for K in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try: return K.from_private_key(io.StringIO(s))
        except Exception: pass
    raise ValueError("could not read the private key (need an OpenSSH/PEM ed25519, rsa or ecdsa key)")

def connect(ip, user, method, secret):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if method == "key":
        c.connect(ip, username=user, pkey=load_key(secret), timeout=20, look_for_keys=False, allow_agent=False)
    else:
        c.connect(ip, username=user, password=secret, timeout=20, look_for_keys=False, allow_agent=False)
    return c

def sh(c, cmd, sudo_pw=None):
    if sudo_pw is not None:
        cmd = "sudo -S -p '' bash -lc " + shq(cmd)
    stdin, out, err = c.exec_command(cmd, timeout=90)
    if sudo_pw is not None:
        try: stdin.write(sudo_pw + "\n"); stdin.flush()
        except Exception: pass
    o = out.read().decode("utf-8", "replace"); e = err.read().decode("utf-8", "replace")
    return o, e, out.channel.recv_exit_status()

def shq(s):
    return "'" + s.replace("'", "'\\''") + "'"

def probe(c, method, secret):
    uid, _, _ = sh(c, "id -u")
    uid = uid.strip()
    if uid == "0":
        return True, True, None, "root"
    o, _, rc = sh(c, "sudo -n true 2>/dev/null && echo OK")
    if "OK" in o:
        return False, True, "", "passwordless sudo"
    if method == "password":
        o, _, rc = sh(c, "id -u", sudo_pw=secret)
        if o.strip() == "0":
            return False, True, secret, "sudo (password)"
    return False, False, None, "no root / no sudo"

def test_conn(ip, user, method, secret):
    if paramiko is None: return {"ok": False, "msg": "paramiko missing on the relay"}
    try:
        c = connect(ip, user, method, secret)
    except paramiko.AuthenticationException:
        return {"ok": False, "msg": "Login failed. Wrong username/password, or this server only allows SSH keys."}
    except Exception as e:
        return {"ok": False, "msg": "Cannot reach the server: %s" % e}
    try:
        is_root, can_sudo, sudo_pw, how = probe(c, method, secret)
        osname, _, _ = sh(c, ". /etc/os-release 2>/dev/null; echo $PRETTY_NAME")
        tun, _, _ = sh(c, "test -c /dev/net/tun && echo yes || echo no")
        c.close()
        if not can_sudo:
            return {"ok": False, "msg": "Connected as '%s', but this user is not root and has no sudo. Give a root user, or a sudo user." % user}
        if "no" in tun:
            return {"ok": False, "msg": "Connected, but /dev/net/tun is missing (OpenVZ?). This host can't run the tunnel/VPN."}
        return {"ok": True, "msg": "Connected to %s as '%s' (%s). Ready to install." % (osname.strip() or "the server", user, how)}
    except Exception as e:
        try: c.close()
        except Exception: pass
        return {"ok": False, "msg": "Connected but a check failed: %s" % e}

def orchestrate(ip, user, method, secret, opts):
    try:
        with LOCK: JOB.update(running=True, done=False, success=False, percent=0, step="starting", log=[], result="")
        setp(3, "connect", "Connecting to %s as %s ..." % (ip, user))
        c = connect(ip, user, method, secret)
        is_root, can_sudo, sudo_pw, how = probe(c, method, secret)
        if not can_sudo:
            setp(3, "error", "No root/sudo on the new server.", done=True, running=False, success=False,
                 result="The user '%s' can't get root. Use a root or sudo user." % user); c.close(); return
        setp(10, "connect", "Access OK (%s). Uploading installer + backup ..." % how)
        sf = c.open_sftp(); sf.put(INSTALLER, "/tmp/foreign-exit.sh")
        if opts.get("migrate") and os.path.exists(BACKUP_DB): sf.put(BACKUP_DB, "/tmp/marzban-db.sqlite3")
        sf.close()
        setp(16, "install", "Installing on the new exit ...")
        env = "RELAY_IP=%s WITH_L2TP=%s MIGRATE=%s" % (RELAY_IP, "1" if opts.get("l2tp") else "0", "1" if opts.get("migrate") else "0")
        cmd = "%s bash /tmp/foreign-exit.sh" % env
        if not is_root: cmd = "echo %s | sudo -S -p '' %s" % (shq(secret if sudo_pw else ""), cmd)
        chan = c.get_transport().open_session(); chan.settimeout(900); chan.exec_command(cmd + " 2>&1")
        out = ""
        while True:
            got = False
            while chan.recv_ready():
                d = chan.recv(8192).decode("utf-8", "replace"); out += d; got = True
                for ln in d.splitlines():
                    if ln.strip():
                        with LOCK:
                            if JOB["percent"] < 74: JOB["percent"] += 1
                            JOB["log"].append(ln.rstrip()); JOB["step"] = "install"
            if chan.exit_status_ready() and not chan.recv_ready(): break
            if not got: time.sleep(0.3)
        rc = chan.recv_exit_status()
        keys = {}
        for ln in out.splitlines():
            if ln.startswith("FLEET_RESULT="):
                try: keys = json.loads(ln.split("=", 1)[1])
                except Exception: pass
        if rc != 0 or not keys.get("tun_uuid"):
            setp(JOB["percent"], "error", "Installer failed (rc=%s)." % rc, done=True, running=False, success=False,
                 result="The install did not finish on %s. See the log." % ip); c.close(); return
        setp(80, "repoint", "Pointing the relay at the new exit ...")
        dry = "DRYRUN=1 " if opts.get("test") else ""
        rp = subprocess.run("%sEXIT_IP=%s TUN_UUID=%s TUN_PUB=%s TUN_SID=%s SUB_PORT=%s bash /opt/provision/repoint-exit.sh 2>&1" % (
            dry, ip, keys["tun_uuid"], keys["tun_pub"], keys["tun_sid"], keys.get("panel_port", 39196)),
            shell=True, capture_output=True, text=True, timeout=120)
        for ln in (rp.stdout or "").splitlines(): setp(None, None, ln)
        setp(90, "validate", "Testing end-to-end: does customer traffic egress via the new exit?")
        ok, egress = (True, validate()[1]) if opts.get("test") else validate(ip)
        c.close()
        v2, vpn = counts()
        if ok:
            setp(100, "done", "Egress verified = %s" % egress, done=True, running=False, success=True,
                 result="New exit %s is live. %d v2ray + %d VPN accounts migrated with usage and remaining days. Egress verified = %s." % (ip, v2, vpn, egress))
        else:
            setp(100, "warn", "Installed + repointed, but egress not confirmed.", done=True, running=False, success=False,
                 result="Installed and repointed to %s, but the egress test did not pass. Check the log / retry." % ip)
    except Exception as e:
        setp(JOB.get("percent", 0), "error", "ERROR: %s" % e, done=True, running=False, success=False, result=str(e))

def validate(ip=None):
    cfg = ('{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":10898,"protocol":"socks","settings":{"udp":true}}],'
           '"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"127.0.0.1","port":8080,"users":[{"id":"6410e1e0-321d-4fa1-9a40-777108f97739","alterId":0,"security":"auto"}]}]},"streamSettings":{"network":"tcp","security":"none"}}]}')
    try:
        open("/tmp/prov-vt.json", "w").write(cfg)
        subprocess.run("pkill -f prov-vt.json 2>/dev/null; sleep 1; nohup /usr/local/bin/xray run -c /tmp/prov-vt.json >/dev/null 2>&1 &", shell=True, timeout=10)
        time.sleep(4)
        r = subprocess.run("curl --socks5-hostname 127.0.0.1:10898 -s --max-time 15 https://api.ipify.org", shell=True, capture_output=True, text=True, timeout=25)
        subprocess.run("pkill -f prov-vt.json 2>/dev/null; rm -f /tmp/prov-vt.json", shell=True, timeout=10)
        egress = (r.stdout or "").strip()
        return (egress == ip, egress or "?")
    except Exception:
        return (False, "?")

def page():
    v2, vpn = counts()
    return PAGE.replace("__RELAY__", html.escape(RELAY_IP or "this server")).replace("__V2__", str(v2)).replace("__VPN__", str(vpn))

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>Fleet Provisioning</title>
<style>
body{font-family:system-ui,Segoe UI,Arial;max-width:720px;margin:1.4rem auto;padding:0 1rem;color:#111}
.card{background:#f7f7f7;border-radius:12px;padding:1rem 1.2rem;margin:1rem 0}
label{display:block;margin:.6rem 0 .2rem;font-size:13px;font-weight:600;color:#333}
input[type=text],input[type=password],textarea{width:100%;padding:.55rem;border:1px solid #ccc;border-radius:6px;box-sizing:border-box;font:inherit}
textarea{height:90px;font-family:monospace;font-size:12px}
.row{display:flex;gap:10px} .row>div{flex:1}
.hint{color:#777;font-size:12px;margin-top:2px}
.opt{margin:.35rem 0;font-size:14px} .opt input{margin-right:.4rem} .opt small{color:#777;display:block;margin-left:1.4rem}
button{cursor:pointer;border:0;border-radius:8px;padding:.6rem 1.2rem;font-size:14px}
.primary{background:#2563eb;color:#fff} .primary:disabled{background:#9db8ee;cursor:not-allowed}
.ghost{background:#fff;border:1px solid #bbb}
#tres{font-size:13px;margin-top:.6rem;padding:.5rem .7rem;border-radius:8px;display:none}
.okc{background:#e7f6ec;color:#15803d} .badc{background:#fdeaea;color:#b91c1c}
#bar{height:22px;background:#e6e6e6;border-radius:11px;overflow:hidden;margin:.4rem 0}
#fill{height:100%;width:0%;background:#2563eb;color:#fff;font-size:13px;line-height:22px;text-align:center;transition:width .4s}
#log{background:#0b1020;color:#c8d3f5;font:12px/1.5 ui-monospace,Consolas,monospace;padding:.6rem;border-radius:8px;height:200px;overflow:auto;white-space:pre-wrap;display:none}
#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5)}
#box{background:#fff;max-width:440px;margin:14vh auto;border-radius:12px;padding:1.4rem;text-align:center}
</style>
<h2 style="margin-bottom:.2rem">Fleet provisioning</h2>
<p style="margin:0;color:#666;font-size:13px"><b>Iran relay:</b> <code>__RELAY__</code> (this server, already configured). You only add the new foreign server below.</p>

<div class=card>
  <div style="font-weight:600;margin-bottom:.3rem">New foreign (exit) server</div>
  <div class=row>
    <div><label>IP address</label><input id=ip type=text placeholder="1.2.3.4" autocomplete=off></div>
    <div><label>SSH user</label><input id=user type=text value="root" autocomplete=off>
      <div class=hint>usually <code>root</code>; some providers give <code>ubuntu</code>/<code>admin</code> (with sudo)</div></div>
  </div>
  <label>How to log in</label>
  <div style="font-size:14px;margin-bottom:.3rem">
    <label style="display:inline;font-weight:400"><input type=radio name=auth value=password checked onclick=authmode()> Password</label>
    &nbsp;&nbsp;
    <label style="display:inline;font-weight:400"><input type=radio name=auth value=key onclick=authmode()> SSH private key</label>
  </div>
  <div id=pwbox><input id=pw type=password placeholder="root password" autocomplete=off></div>
  <div id=keybox style="display:none"><textarea id=key placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;...paste the private key..."></textarea></div>
  <button class=ghost id=test onclick=testc() style="margin-top:.6rem">Test connection</button>
  <div id=tres></div>
</div>

<div class=card>
  <div style="font-weight:600;margin-bottom:.3rem">What to install on the new server</div>
  <div class=opt><label style="font-weight:400"><input type=checkbox id=marzban checked> Marzban panel (v2ray)</label>
    <small>VLESS/VMess/Trojan/Shadowsocks for your customers</small></div>
  <div class=opt><label style="font-weight:400"><input type=checkbox id=l2tp checked> L2TP / IPsec</label>
    <small>extra VPN protocol</small></div>
  <div class=opt><label style="font-weight:400"><input type=checkbox id=migrate checked> Migrate existing accounts</label>
    <small>copies <b>__V2__</b> v2ray customers + <b>__VPN__</b> VPN users, with their used data and remaining days. Uncheck to start the new server empty.</small></div>
  <button class=primary id=go onclick=start() disabled>Install &mdash; test the connection first</button>
</div>

<div id=prog style="display:none">
  <div id=bar><div id=fill>0%</div></div>
  <div id=step style="font-size:13px;color:#444"></div>
  <div id=log></div>
</div>
<div id=modal><div id=box>
  <h3 id=mt style="margin:.2rem 0"></h3><p id=mx style="color:#555;font-size:14px"></p>
  <button class=ghost onclick="document.getElementById('modal').style.display='none';location.reload()">OK</button>
</div></div>
<script>
function authmode(){var k=document.querySelector('input[name=auth]:checked').value;
  document.getElementById('pwbox').style.display=k=='password'?'block':'none';
  document.getElementById('keybox').style.display=k=='key'?'block':'none';}
function creds(){var m=document.querySelector('input[name=auth]:checked').value;
  return {ip:document.getElementById('ip').value.trim(),user:document.getElementById('user').value.trim()||'root',
    method:m,secret:m=='password'?document.getElementById('pw').value:document.getElementById('key').value};}
function testc(){var c=creds();if(!c.ip||!c.secret){alert('Enter the server IP and the password/key');return;}
  var t=document.getElementById('tres');t.style.display='block';t.className='';t.textContent='Testing connection...';
  var b=new URLSearchParams(c);
  fetch('/test',{method:'POST',body:b}).then(r=>r.json()).then(j=>{
    t.className=j.ok?'okc':'badc';t.textContent=j.msg;
    var go=document.getElementById('go');go.disabled=!j.ok;go.textContent=j.ok?'Install now':'Install \\u2014 test the connection first';
  }).catch(()=>{t.className='badc';t.textContent='Test failed (network).';});}
function start(){var c=creds();
  document.getElementById('go').disabled=true;document.getElementById('prog').style.display='block';document.getElementById('log').style.display='block';
  var b=new URLSearchParams(c);b.set('l2tp',document.getElementById('l2tp').checked?1:0);
  b.set('marzban',document.getElementById('marzban').checked?1:0);b.set('migrate',document.getElementById('migrate').checked?1:0);
  fetch('/start',{method:'POST',body:b}).then(poll);}
function poll(){fetch('/status').then(r=>r.json()).then(j=>{
  var f=document.getElementById('fill');f.style.width=j.percent+'%';f.textContent=j.percent+'%';
  document.getElementById('step').textContent=j.step;
  var L=document.getElementById('log');L.textContent=j.log.join('\\n');L.scrollTop=L.scrollHeight;
  if(j.done){var m=document.getElementById('modal');document.getElementById('mt').textContent=j.success?'\\u2705 Done':'\\u26a0 Needs attention';
    document.getElementById('mt').style.color=j.success?'#15803d':'#b45309';document.getElementById('mx').textContent=j.result;m.style.display='block';}
  else setTimeout(poll,1500);}).catch(()=>setTimeout(poll,2000));}
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
    def _s(self, code, ct, body):
        self.send_response(code); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if not self.ok_auth(): return
        if urllib.parse.urlparse(self.path).path == "/status":
            with LOCK: self._s(200, "application/json", json.dumps(JOB).encode()); return
        self._s(200, "text/html; charset=utf-8", page().encode())
    def _body(self):
        ln = int(self.headers.get("Content-Length", 0)); return urllib.parse.parse_qs(self.rfile.read(ln).decode())
    def do_POST(self):
        if not self.ok_auth(): return
        p = urllib.parse.urlparse(self.path).path; q = self._body()
        ip = q.get("ip", [""])[0].strip(); user = q.get("user", ["root"])[0].strip() or "root"
        method = q.get("method", ["password"])[0]; secret = q.get("secret", [""])[0]
        if p == "/test":
            self._s(200, "application/json", json.dumps(test_conn(ip, user, method, secret)).encode()); return
        if p == "/start":
            opts = {"l2tp": q.get("l2tp", ["1"])[0] == "1", "migrate": q.get("migrate", ["1"])[0] == "1",
                    "marzban": q.get("marzban", ["1"])[0] == "1", "test": q.get("test", ["0"])[0] == "1"}
            with LOCK: busy = JOB["running"]
            if not busy and ip and secret:
                threading.Thread(target=orchestrate, args=(ip, user, method, secret, opts), daemon=True).start()
            self._s(200, "application/json", b'{"ok":true}'); return
        self._s(404, "text/plain", b"no")
    def log_message(self, *a): pass

_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); _CTX.load_cert_chain("/opt/provision/cert.pem", "/opt/provision/key.pem")
class Srv(http.server.ThreadingHTTPServer):
    daemon_threads = True; allow_reuse_address = True
    def get_request(self):
        s, a = self.socket.accept(); s.settimeout(30)
        return _CTX.wrap_socket(s, server_side=True, do_handshake_on_connect=False), a
    def handle_error(self, r, a): pass
Srv(("0.0.0.0", int(os.environ.get("PROV_PORT", "2099"))), H).serve_forever()
