#!/usr/bin/env python3
# Fleet provisioning dashboard. Change the exit, the relay, or both.
# Robust SSH (custom user, password OR key, sudo), required Test-connection gate,
# live % + validation + popup.
import http.server, ssl, os, json, threading, subprocess, base64, urllib.parse, time, html, io, sqlite3
try:
    import paramiko
except Exception:
    paramiko = None

USER = os.environ.get("PROV_USER", "admin"); PASS = os.environ.get("PROV_PASS", "changeme")
RELAY_IP = os.environ.get("RELAY_IP", "")
EXIT_INSTALLER = "/opt/provision/foreign-exit.sh"
RELAY_INSTALLER = "/opt/provision/build-relay.sh"
BACKUP_DB = "/opt/fleet-backups/marzban-db.sqlite3"; USERS_JSON = "/opt/ovpnpanel/users.json"
RELAY_CFG = "/usr/local/etc/xray/config.json"

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

def current_exit():
    try:
        c = json.load(open(RELAY_CFG))
        for ob in c.get("outbounds", []):
            if ob.get("tag") == "tunnel":
                v = ob["settings"]["vnext"][0]; rs = ob["streamSettings"]["realitySettings"]
                return {"ip": v["address"], "uuid": v["users"][0]["id"], "pub": rs["publicKey"], "sid": rs["shortId"]}
    except Exception: pass
    return {}

def shq(s): return "'" + s.replace("'", "'\\''") + "'"

def load_key(s):
    s = (s or "").strip()
    if s and "-----BEGIN" not in s:
        # bare base64 body pasted (no header lines) -> rewrap as an OpenSSH key
        body = "".join(s.split())
        s = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(body[i:i+70] for i in range(0, len(body), 70)) + "\n-----END OPENSSH PRIVATE KEY-----\n"
    for K in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try: return K.from_private_key(io.StringIO(s))
        except Exception: pass
    raise ValueError("unreadable private key")

FLEET_KEY = "/opt/provision/prov_key"

def fleet_pub():
    try: return open(FLEET_KEY + ".pub").read().strip()
    except Exception: return ""

def connect(ip, user, method, secret):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if method == "fleet": c.connect(ip, username=user, pkey=paramiko.Ed25519Key.from_private_key_file(FLEET_KEY), timeout=20, look_for_keys=False, allow_agent=False)
    elif method == "key": c.connect(ip, username=user, pkey=load_key(secret), timeout=20, look_for_keys=False, allow_agent=False)
    else: c.connect(ip, username=user, password=secret, timeout=20, look_for_keys=False, allow_agent=False)
    return c

def sh(c, cmd, sudo_pw=None):
    if sudo_pw is not None: cmd = "sudo -S -p '' bash -lc " + shq(cmd)
    stdin, out, err = c.exec_command(cmd, timeout=90)
    if sudo_pw is not None:
        try: stdin.write(sudo_pw + "\n"); stdin.flush()
        except Exception: pass
    return out.read().decode("utf-8", "replace"), err.read().decode("utf-8", "replace"), out.channel.recv_exit_status()

def probe(c, method, secret):
    uid, _, _ = sh(c, "id -u"); uid = uid.strip()
    if uid == "0": return True, True, None, "root"
    o, _, _ = sh(c, "sudo -n true 2>/dev/null && echo OK")
    if "OK" in o: return False, True, "", "passwordless sudo"
    if method == "password":
        o, _, _ = sh(c, "id -u", sudo_pw=secret)
        if o.strip() == "0": return False, True, secret, "sudo (password)"
    return False, False, None, "no root / no sudo"

def test_one(ip, user, method, secret):
    if not ip: return {"ok": False, "msg": "Enter the server IP."}
    if method != "fleet" and not secret: return {"ok": False, "msg": "Enter the password/key (or use the Fleet key)."}
    if paramiko is None: return {"ok": False, "msg": "paramiko missing on the relay."}
    if method == "key":
        try: load_key(secret)
        except Exception: return {"ok": False, "msg": "That private key can't be read. Paste the WHOLE key file (the -----BEGIN...----- and -----END...----- lines and everything between)."}
    try: c = connect(ip, user, method, secret)
    except paramiko.AuthenticationException:
        if method == "fleet":
            return {"ok": False, "msg": "%s refused the fleet key. Add this exact line to the new server (root SSH keys), then Test again:  %s" % (ip, fleet_pub())}
        if method == "key":
            try:
                pk = load_key(secret)
                return {"ok": False, "msg": "%s refused this key. The PUBLIC key for what you pasted is:  %s %s  — exactly this line must be in the new server's root authorized_keys. If your Hetzner SSH key differs, you pasted the wrong private key." % (ip, pk.get_name(), pk.get_base64())}
            except Exception: pass
        return {"ok": False, "msg": "Login failed on %s: wrong username or password." % ip}
    except Exception as e: return {"ok": False, "msg": "Cannot reach %s: %s" % (ip, e)}
    try:
        is_root, can_sudo, _, how = probe(c, method, secret)
        osname, _, _ = sh(c, ". /etc/os-release 2>/dev/null; echo $PRETTY_NAME")
        tun, _, _ = sh(c, "test -c /dev/net/tun && echo yes || echo no")
        c.close()
        if not can_sudo: return {"ok": False, "msg": "Connected as '%s' but no root/sudo. Give a root or sudo user." % user}
        if "no" in tun: return {"ok": False, "msg": "Connected, but /dev/net/tun is missing (OpenVZ?). Can't run the tunnel here."}
        return {"ok": True, "msg": "%s is reachable as '%s' (%s), %s." % (ip, user, how, osname.strip() or "linux")}
    except Exception as e:
        try: c.close()
        except Exception: pass
        return {"ok": False, "msg": "Connected but a check failed: %s" % e}

def run_installer(c, method, secret, path, env):
    is_root, _, _, _ = probe(c, method, secret)
    cmd = "%s bash %s" % (env, path)
    if not is_root: cmd = "echo %s | sudo -S -p '' %s" % (shq(secret if method == "password" else ""), cmd)
    chan = c.get_transport().open_session(); chan.settimeout(1200); chan.exec_command(cmd + " 2>&1")
    out = ""
    while True:
        got = False
        while chan.recv_ready():
            d = chan.recv(8192).decode("utf-8", "replace"); out += d; got = True
            for ln in d.splitlines():
                if ln.strip():
                    with LOCK:
                        if JOB["percent"] < 72: JOB["percent"] += 1
                        JOB["log"].append(ln.rstrip())
        if chan.exit_status_ready() and not chan.recv_ready(): break
        if not got: time.sleep(0.3)
    keys = {}
    for ln in out.splitlines():
        if ln.startswith("FLEET_RESULT="):
            try: keys = json.loads(ln.split("=", 1)[1])
            except Exception: pass
    return chan.recv_exit_status(), keys

def upload(c, migrate):
    sf = c.open_sftp()
    if os.path.exists(EXIT_INSTALLER): sf.put(EXIT_INSTALLER, "/tmp/foreign-exit.sh")
    if os.path.exists(RELAY_INSTALLER): sf.put(RELAY_INSTALLER, "/tmp/build-relay.sh")
    if migrate and os.path.exists(BACKUP_DB): sf.put(BACKUP_DB, "/tmp/marzban-db.sqlite3")
    if migrate and os.path.exists(USERS_JSON): sf.put(USERS_JSON, "/tmp/users.json")
    sf.close()

def orchestrate(mode, ex, re, opts):
    try:
        with LOCK: JOB.update(running=True, done=False, success=False, percent=0, step="starting", log=[], result="")
        newexit = None
        if mode in ("exit", "both"):
            setp(4, "exit", "Connecting to new exit %s ..." % ex["ip"])
            ce = connect(ex["ip"], ex["user"], ex["method"], ex["secret"])
            upload(ce, opts.get("migrate"))
            setp(14, "exit", "Building the exit (Marzban%s%s) ..." % (" + L2TP" if opts.get("l2tp") else "", " + users" if opts.get("migrate") else ""))
            env = "RELAY_IP=%s WITH_L2TP=%s MIGRATE=%s" % (RELAY_IP, "1" if opts.get("l2tp") else "0", "1" if opts.get("migrate") else "0")
            rc, keys = run_installer(ce, ex["method"], ex["secret"], "/tmp/foreign-exit.sh", env); ce.close()
            if rc != 0 or not keys.get("tun_uuid"):
                setp(JOB["percent"], "error", "Exit installer failed (rc=%s)." % rc, done=True, running=False, success=False, result="Exit build did not finish on %s." % ex["ip"]); return
            newexit = {"ip": ex["ip"], **keys}
        target_exit = newexit or current_exit()
        if not target_exit.get("uuid"):
            setp(JOB["percent"], "error", "No exit tunnel params.", done=True, running=False, success=False, result="Could not determine the exit to point at."); return

        if mode == "exit":
            setp(80, "repoint", "Pointing THIS relay at the new exit ...")
            dry = "DRYRUN=1 " if opts.get("test") else ""
            rp = subprocess.run("%sEXIT_IP=%s TUN_UUID=%s TUN_PUB=%s TUN_SID=%s bash /opt/provision/repoint-exit.sh 2>&1" % (
                dry, target_exit["ip"], target_exit["uuid"], target_exit["pub"], target_exit["sid"]), shell=True, capture_output=True, text=True, timeout=120)
            for ln in (rp.stdout or "").splitlines(): setp(None, None, ln)

        if mode in ("relay", "both"):
            setp(78, "relay", "Connecting to new relay %s ..." % re["ip"])
            cr = connect(re["ip"], re["user"], re["method"], re["secret"])
            upload(cr, opts.get("migrate"))
            setp(84, "relay", "Building the relay (xray + tunnel + OpenVPN/L2TP + panel) ...")
            env = "EXIT_IP=%s TUN_UUID=%s TUN_PUB=%s TUN_SID=%s WITH_L2TP=%s MIGRATE=%s" % (
                target_exit["ip"], target_exit["uuid"], target_exit["pub"], target_exit["sid"],
                "1" if opts.get("l2tp") else "0", "1" if opts.get("migrate") else "0")
            rc, _ = run_installer(cr, re["method"], re["secret"], "/tmp/build-relay.sh", env); cr.close()
            if rc != 0:
                setp(JOB["percent"], "error", "Relay installer failed (rc=%s)." % rc, done=True, running=False, success=False, result="Relay build did not finish on %s." % re["ip"]); return

        setp(92, "validate", "Validating ...")
        v2, vpn = counts()
        if mode == "exit":
            ok, egress = ((True, validate()[1]) if opts.get("test") else validate(target_exit["ip"]))
            res = "New exit %s is live. %d v2ray + %d VPN accounts kept their usage & days. Egress = %s." % (target_exit["ip"], v2, vpn, egress) if ok else "Installed + repointed to %s, but egress not confirmed." % target_exit["ip"]
        elif mode == "relay":
            ok = True; res = "New relay %s is ready with all %d v2ray + %d VPN accounts (usage & days kept). Point your customers/DNS at %s." % (re["ip"], v2, vpn, re["ip"], re["ip"])
        else:
            ok = True; res = "New exit %s + new relay %s are up with all %d v2ray + %d VPN accounts. Point customers at %s." % (target_exit["ip"], re["ip"], v2, vpn, re["ip"])
        setp(100, "done" if ok else "warn", "Done.", done=True, running=False, success=ok, result=res)
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
        eg = (r.stdout or "").strip(); return (eg == ip, eg or "?")
    except Exception: return (False, "?")

def srv_block(pfx, title, subtitle):
    return ("<div class=card><div style='font-weight:600'>" + title + "</div><div class=hint>" + subtitle + "</div>"
        "<div class=row><div><label>IP address</label><input id=" + pfx + "ip type=text placeholder='1.2.3.4' autocomplete=off></div>"
        "<div><label>SSH user</label><input id=" + pfx + "user type=text value=root autocomplete=off></div></div>"
        "<label>Login</label><div style='font-size:14px'>"
        "<label style='display:inline;font-weight:400'><input type=radio name=" + pfx + "auth value=fleet checked onclick=am('" + pfx + "')> Fleet key</label>&nbsp;&nbsp;"
        "<label style='display:inline;font-weight:400'><input type=radio name=" + pfx + "auth value=password onclick=am('" + pfx + "')> Password</label>&nbsp;&nbsp;"
        "<label style='display:inline;font-weight:400'><input type=radio name=" + pfx + "auth value=key onclick=am('" + pfx + "')> Paste a key</label></div>"
        "<div id=" + pfx + "fleetbox class=hint>Uses the fleet key shown at the top &mdash; just add that key to the server, nothing to type here.</div>"
        "<div id=" + pfx + "pwbox style='display:none'><input id=" + pfx + "pw type=password placeholder='root password' autocomplete=off></div>"
        "<div id=" + pfx + "keybox style='display:none'><textarea id=" + pfx + "key placeholder='paste private key'></textarea></div>"
        "<button class=ghost onclick=\"testc('" + pfx + "')\" style='margin-top:.5rem'>Test connection</button>"
        "<div id=" + pfx + "res class=tres></div></div>")

def page():
    v2, vpn = counts()
    return PAGE.replace("__RELAY__", html.escape(RELAY_IP or "this server")).replace("__V2__", str(v2)).replace("__VPN__", str(vpn)) \
               .replace("__FLEETPUB__", html.escape(fleet_pub() or "(key not generated yet)")) \
               .replace("__FLEETCMD__", html.escape('mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "' + (fleet_pub() or "") + '" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys', quote=True)) \
               .replace("__EXITCARD__", srv_block("e", "New foreign (exit) server", "the box abroad that customers egress through")) \
               .replace("__RELAYCARD__", srv_block("r", "New Iran (relay) server", "the domestic box customers connect to; after install, point them at its IP"))

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Fleet Provisioning</title>
<style>
body{font-family:system-ui,Segoe UI,Arial;max-width:720px;margin:1.4rem auto;padding:0 1rem;color:#111}
.card{background:#f7f7f7;border-radius:12px;padding:1rem 1.2rem;margin:1rem 0}
label{display:block;margin:.6rem 0 .2rem;font-size:13px;font-weight:600;color:#333}
input[type=text],input[type=password],textarea{width:100%;padding:.55rem;border:1px solid #ccc;border-radius:6px;box-sizing:border-box;font:inherit}
textarea{height:80px;font-family:monospace;font-size:12px} .row{display:flex;gap:10px}.row>div{flex:1}
.hint{color:#777;font-size:12px;margin-top:2px} .tres{font-size:13px;margin-top:.5rem;padding:.45rem .6rem;border-radius:8px;display:none}
.okc{background:#e7f6ec;color:#15803d}.badc{background:#fdeaea;color:#b91c1c}
button{cursor:pointer;border:0;border-radius:8px;padding:.55rem 1.1rem;font-size:14px}
.primary{background:#2563eb;color:#fff}.primary:disabled{background:#9db8ee;cursor:not-allowed}.ghost{background:#fff;border:1px solid #bbb}
.seg label{display:inline-block;font-weight:400;margin:0;padding:.4rem .7rem;border:1px solid #ccc;cursor:pointer;font-size:14px}
.seg input{display:none} .seg label:has(input:checked){background:#2563eb;color:#fff;border-color:#2563eb}
#bar{height:22px;background:#e6e6e6;border-radius:11px;overflow:hidden;margin:.4rem 0}
#fill{height:100%;width:0%;background:#2563eb;color:#fff;font-size:13px;line-height:22px;text-align:center;transition:width .4s}
#log{background:#0b1020;color:#c8d3f5;font:12px/1.5 ui-monospace,Consolas,monospace;padding:.6rem;border-radius:8px;height:200px;overflow:auto;white-space:pre-wrap;display:none}
#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5)}#box{background:#fff;max-width:440px;margin:14vh auto;border-radius:12px;padding:1.4rem;text-align:center}
</style>
<h2 style="margin-bottom:.2rem">Fleet provisioning</h2>
<p style="margin:0 0 .6rem;color:#666;font-size:13px">This dashboard runs on the current Iran relay <code>__RELAY__</code>. Current fleet: <b>__V2__</b> v2ray customers, <b>__VPN__</b> VPN users.</p>
<div class=card style="background:#eef4ff"><b>Fleet key</b> &mdash; the easiest login. Get this key onto the new server, then pick <b>Fleet key</b> below &mdash; no key to paste in the dashboard, no mismatch.
<div style="margin-top:.5rem"><b style="font-size:13px">A) Server already exists?</b> Copy this whole command and run it on the server as root:</div>
<div style="display:flex;gap:6px;margin-top:.3rem"><input readonly id=fcmd value="__FLEETCMD__" onclick="this.select()" style="flex:1;font-family:monospace;font-size:11px;background:#fff;border:1px solid #cbd5e1;border-radius:6px;padding:.5rem"><button class=ghost type=button onclick="cp('fcmd',this)">Copy</button></div>
<div style="margin-top:.6rem"><b style="font-size:13px">B) Creating a fresh server?</b> Paste just this key in the provider's &ldquo;SSH key&rdquo; box:</div>
<div style="display:flex;gap:6px;margin-top:.3rem"><input readonly id=fpub value="__FLEETPUB__" onclick="this.select()" style="flex:1;font-family:monospace;font-size:11px;background:#fff;border:1px solid #cbd5e1;border-radius:6px;padding:.5rem"><button class=ghost type=button onclick="cp('fpub',this)">Copy</button></div></div>
<div class=card><label style="margin-top:0">What do you want to change?</label>
  <div class=seg>
    <label><input type=radio name=mode value=exit checked onclick=setmode()> Foreign server only</label>
    <label><input type=radio name=mode value=relay onclick=setmode()> Iran server only</label>
    <label><input type=radio name=mode value=both onclick=setmode()> Both servers</label>
  </div>
  <div class=hint id=modehint>Keep the Iran relay, move the exit abroad.</div>
</div>
<div id=exitwrap>__EXITCARD__</div>
<div id=relaywrap style="display:none">__RELAYCARD__</div>
<div class=card><div style="font-weight:600;margin-bottom:.3rem">What to install</div>
  <div style="font-size:14px"><label style="font-weight:400"><input type=checkbox id=marzban checked> Marzban (v2ray)</label></div>
  <div style="font-size:14px"><label style="font-weight:400"><input type=checkbox id=l2tp checked> L2TP / IPsec</label></div>
  <div style="font-size:14px"><label style="font-weight:400"><input type=checkbox id=migrate checked> Migrate accounts</label>
    <small style="color:#777;display:block;margin-left:1.4rem">copies <b>__V2__</b> v2ray + <b>__VPN__</b> VPN users with used data &amp; remaining days. Uncheck to start empty.</small></div>
  <button class=primary id=go onclick=start() disabled>Install &mdash; test the connection(s) first</button>
</div>
<div id=prog style="display:none"><div id=bar><div id=fill>0%</div></div><div id=step style="font-size:13px;color:#444"></div><div id=log></div></div>
<div id=modal><div id=box><h3 id=mt style="margin:.2rem 0"></h3><p id=mx style="color:#555;font-size:14px"></p>
  <button class=ghost onclick="document.getElementById('modal').style.display='none';location.reload()">OK</button></div></div>
<script>
function cp(id,btn){var e=document.getElementById(id);e.focus();e.select();try{document.execCommand('copy');}catch(_){}
  if(navigator.clipboard){navigator.clipboard.writeText(e.value).catch(function(){});}
  var t=btn.textContent;btn.textContent='Copied';setTimeout(function(){btn.textContent=t;},1200);}
var okState={e:false,r:false};
function mode(){return document.querySelector('input[name=mode]:checked').value;}
function need(){var m=mode();return m=='exit'?['e']:m=='relay'?['r']:['e','r'];}
function setmode(){var m=mode();
  document.getElementById('exitwrap').style.display=(m=='exit'||m=='both')?'block':'none';
  document.getElementById('relaywrap').style.display=(m=='relay'||m=='both')?'block':'none';
  document.getElementById('modehint').textContent=m=='exit'?'Keep the Iran relay, move the exit abroad.':m=='relay'?'Keep the current exit, move the Iran relay.':'Move both servers.';
  refresh();}
function am(p){var k=document.querySelector('input[name='+p+'auth]:checked').value;
  document.getElementById(p+'fleetbox').style.display=k=='fleet'?'block':'none';
  document.getElementById(p+'pwbox').style.display=k=='password'?'block':'none';
  document.getElementById(p+'keybox').style.display=k=='key'?'block':'none';}
function creds(p){var m=document.querySelector('input[name='+p+'auth]:checked').value;
  var sec=m=='password'?document.getElementById(p+'pw').value:m=='key'?document.getElementById(p+'key').value:'fleet';
  return {ip:document.getElementById(p+'ip').value.trim(),user:document.getElementById(p+'user').value.trim()||'root',method:m,secret:sec};}
function testc(p){var c=creds(p);if(!c.ip){alert('Enter the server IP');return;}
  var t=document.getElementById(p+'res');t.style.display='block';t.className='tres';t.textContent='Testing...';
  fetch('/test',{method:'POST',body:new URLSearchParams(c)}).then(r=>r.json()).then(j=>{t.className='tres '+(j.ok?'okc':'badc');t.textContent=j.msg;okState[p]=j.ok;refresh();})
  .catch(()=>{t.className='tres badc';t.textContent='Test failed.';okState[p]=false;refresh();});}
function refresh(){var ok=need().every(p=>okState[p]);var g=document.getElementById('go');g.disabled=!ok;g.textContent=ok?'Install now':'Install \\u2014 test the connection(s) first';}
function start(){var b=new URLSearchParams();b.set('mode',mode());
  need().forEach(p=>{var c=creds(p);b.set(p+'ip',c.ip);b.set(p+'user',c.user);b.set(p+'method',c.method);b.set(p+'secret',c.secret);});
  b.set('l2tp',document.getElementById('l2tp').checked?1:0);b.set('migrate',document.getElementById('migrate').checked?1:0);
  document.getElementById('go').disabled=true;document.getElementById('prog').style.display='block';document.getElementById('log').style.display='block';
  fetch('/start',{method:'POST',body:b}).then(poll);}
function poll(){fetch('/status').then(r=>r.json()).then(j=>{var f=document.getElementById('fill');f.style.width=j.percent+'%';f.textContent=j.percent+'%';
  document.getElementById('step').textContent=j.step;var L=document.getElementById('log');L.textContent=j.log.join('\\n');L.scrollTop=L.scrollHeight;
  if(j.done){document.getElementById('mt').textContent=j.success?'\\u2705 Done':'\\u26a0 Needs attention';document.getElementById('mt').style.color=j.success?'#15803d':'#b45309';document.getElementById('mx').textContent=j.result;document.getElementById('modal').style.display='block';}
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
    def do_POST(self):
        if not self.ok_auth(): return
        p = urllib.parse.urlparse(self.path).path
        ln = int(self.headers.get("Content-Length", 0)); q = urllib.parse.parse_qs(self.rfile.read(ln).decode())
        g = lambda k, d="": q.get(k, [d])[0]
        if p == "/test":
            self._s(200, "application/json", json.dumps(test_one(g("ip").strip(), g("user", "root").strip() or "root", g("method", "password"), g("secret"))).encode()); return
        if p == "/start":
            mode = g("mode", "exit")
            ex = {"ip": g("eip").strip(), "user": g("euser", "root").strip() or "root", "method": g("emethod", "password"), "secret": g("esecret")}
            re = {"ip": g("rip").strip(), "user": g("ruser", "root").strip() or "root", "method": g("rmethod", "password"), "secret": g("rsecret")}
            opts = {"l2tp": g("l2tp", "1") == "1", "migrate": g("migrate", "1") == "1", "test": g("test", "0") == "1"}
            with LOCK: busy = JOB["running"]
            if not busy: threading.Thread(target=orchestrate, args=(mode, ex, re, opts), daemon=True).start()
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
