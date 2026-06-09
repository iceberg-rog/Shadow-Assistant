"""
Fleet provisioning dashboard (SSH-key based).

The dashboard holds a single Ed25519 keypair (generated on first run, private key
stored 0600 in DATA_DIR). To onboard a server you either:
  - pre-install the dashboard's PUBLIC key on it (e.g. via the VPS provider), then
    add it with just IP + user (no password ever), or
  - give a ONE-TIME root password used only to append the dashboard public key to
    the server's authorized_keys; the password is never stored.

After that, all provisioning runs over key auth. Role 'foreign' = exit + Marzban
panel, role 'iran' = relay to a foreign exit.
"""
import os
import json
import sqlite3
import threading
import time

import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, abort, Response,
)

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "fleet.db")
PRIV_PATH = os.path.join(DATA_DIR, "id_ed25519")
PUB_PATH = PRIV_PATH + ".pub"
LOG_DIR = os.path.join(DATA_DIR, "logs")
INSTALLER_DIR = os.path.join(os.path.dirname(__file__), "installer")
ADMIN_PASS = os.environ.get("DASH_ADMIN_PASS", "changeme")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24).hex())


# ---------- ssh keypair (the dashboard's identity) ----------
def ensure_keypair():
    if not os.path.exists(PRIV_PATH):
        key = Ed25519PrivateKey.generate()
        priv = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        pub = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        with open(PRIV_PATH, "wb") as f:
            f.write(priv)
        os.chmod(PRIV_PATH, 0o600)
        with open(PUB_PATH, "wb") as f:
            f.write(pub + b" fleet-panel\n")
    with open(PUB_PATH, "r") as f:
        return f.read().strip()


def load_pkey():
    return paramiko.Ed25519Key.from_private_key_file(PRIV_PATH)


# ---------- db ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                ip TEXT NOT NULL,
                ssh_user TEXT NOT NULL DEFAULT 'root',
                ssh_port INTEGER NOT NULL DEFAULT 22,
                role TEXT NOT NULL,            -- 'foreign' | 'iran'
                exit_ip TEXT,
                key_installed INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'new',
                result TEXT,
                relay_id INTEGER,            -- foreign node's paired relay (set by /pair)
                created_at INTEGER
            )
            """
        )
        # migrate older DBs that predate the relay_id column
        try:
            conn.execute("ALTER TABLE nodes ADD COLUMN relay_id INTEGER")
        except Exception:
            pass


def logfile(nid):
    return os.path.join(LOG_DIR, f"{nid}.log")


def log(nid, msg):
    with open(logfile(nid), "a", encoding="utf-8") as f:
        f.write(msg.rstrip("\n") + "\n")


def set_status(nid, status, result=None):
    with db() as conn:
        if result is None:
            conn.execute("UPDATE nodes SET status=? WHERE id=?", (status, nid))
        else:
            conn.execute("UPDATE nodes SET status=?, result=? WHERE id=?",
                         (status, json.dumps(result), nid))


def set_key_installed(nid):
    with db() as conn:
        conn.execute("UPDATE nodes SET key_installed=1 WHERE id=?", (nid,))


# ---------- ssh ----------
def connect_key(ip, port, user, timeout=20):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(hostname=ip, port=port, username=user, pkey=load_pkey(),
                timeout=timeout, allow_agent=False, look_for_keys=False)
    return cli


def connect_password(ip, port, user, password, timeout=20):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(hostname=ip, port=port, username=user, password=password,
                timeout=timeout, allow_agent=False, look_for_keys=False)
    return cli


def install_pubkey(ip, port, user, password, pubkey):
    """One-time: append the dashboard public key to the server (password not stored)."""
    cli = connect_password(ip, port, user, password)
    cmd = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && "
        "chmod 600 ~/.ssh/authorized_keys && "
        f"grep -qF '{pubkey}' ~/.ssh/authorized_keys || echo '{pubkey}' >> ~/.ssh/authorized_keys"
    )
    _, out, err = cli.exec_command(cmd)
    out.channel.recv_exit_status()
    cli.close()


def run_stream(cli, nid, command):
    chan = cli.get_transport().open_session()
    chan.get_pty()
    chan.exec_command(command)
    buf = b""
    while True:
        if chan.recv_ready():
            buf += chan.recv(4096)
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                log(nid, line.decode(errors="replace"))
        elif chan.exit_status_ready():
            break
        else:
            time.sleep(0.1)
    if buf:
        log(nid, buf.decode(errors="replace"))
    return chan.recv_exit_status()


def render_installer(role, params):
    with open(os.path.join(INSTALLER_DIR, f"{role}.sh"), "r", encoding="utf-8") as f:
        body = f.read()
    header = "#!/usr/bin/env bash\nset -uo pipefail\n"
    for k, v in params.items():
        header += f"export {k}={json.dumps(str(v))}\n"
    return header + body


# ---------- Marzban host automation (point customer configs at the relay) ----------
import urllib.request as _urlreq
import urllib.parse as _urlparse
import ssl as _ssl

_NOVERIFY = _ssl.create_default_context()
_NOVERIFY.check_hostname = False
_NOVERIFY.verify_mode = _ssl.CERT_NONE


def _http_json(url, headers=None, data=None, method=None):
    req = _urlreq.Request(url, data=data, headers=headers or {}, method=method)
    with _urlreq.urlopen(req, context=_NOVERIFY, timeout=20) as r:
        body = r.read().decode()
    return json.loads(body) if body.strip() else {}


# Marzban inbound tag -> the customer port the relay listens on for it
RELAY_PORTS = {
    "VLESS_REALITY": 443,
    "VMESS_TCP": 8080,
    "TROJAN_TLS": 8443,
    "SHADOWSOCKS": 8388,
}


def marzban_link_relay(panel_base, admin_user, admin_pass, relay_ip, nid):
    """Point EVERY customer config at the Iran relay: for each known inbound, replace its
    Host list with a single host = relay_ip:port. This also drops the default direct-exit
    host, so no config ever exposes the foreign IP. Trojan gets allowinsecure (self-signed)."""
    tok = _http_json(
        panel_base + "/api/admin/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=_urlparse.urlencode({"username": admin_user, "password": admin_pass}).encode(),
    )
    auth = {"Authorization": "Bearer " + tok["access_token"]}
    hosts = _http_json(panel_base + "/api/hosts", headers=auth)
    linked = []
    for tag, port in RELAY_PORTS.items():
        if tag not in hosts:
            continue
        hosts[tag] = [{
            "remark": f"iran-relay {relay_ip}", "address": relay_ip, "port": port,
            "sni": "", "host": "", "path": "", "security": "inbound_default",
            "alpn": "", "fingerprint": "",
            "allowinsecure": (tag == "TROJAN_TLS") or None,
            "is_disabled": False, "mux_enable": False, "fragment_setting": None,
            "noise_setting": None, "random_user_agent": False, "use_sni_as_host": False,
        }]
        linked.append(tag)
    _http_json(
        panel_base + "/api/hosts",
        headers={**auth, "Content-Type": "application/json"},
        data=json.dumps(hosts).encode(), method="PUT",
    )
    log(nid, f"Marzban Hosts linked -> all customer configs use the relay {relay_ip} ({', '.join(linked)})")


# ---------- provisioning worker ----------
def provision(nid, bootstrap_password=None):
    with db() as conn:
        row = conn.execute("SELECT * FROM nodes WHERE id=?", (nid,)).fetchone()
    if not row:
        return
    cli = None
    try:
        open(logfile(nid), "w").close()
        log(nid, f"=== Provisioning {row['name']} ({row['ip']}) role={row['role']} ===")
        set_status(nid, "connecting")
        ip, port, user = row["ip"], row["ssh_port"], row["ssh_user"]

        # 1) establish key-based auth
        log(nid, f"[1/3] SSH key auth {user}@{ip}:{port} ...")
        try:
            cli = connect_key(ip, port, user)
            log(nid, "Key auth OK.")
        except paramiko.AuthenticationException:
            if bootstrap_password:
                log(nid, "Key not present — installing dashboard key via one-time password ...")
                install_pubkey(ip, port, user, bootstrap_password, ensure_keypair())
                cli = connect_key(ip, port, user)
                set_key_installed(nid)
                log(nid, "Dashboard key installed; key auth OK. (password discarded)")
            else:
                log(nid, "Key auth failed and no one-time password provided.")
                log(nid, "Add the dashboard public key to this server, or re-add it with a one-time password.")
                set_status(nid, "failed")
                return

        _, out, _ = cli.exec_command("whoami; hostname; uname -sr")
        for ln in out.read().decode(errors="replace").strip().splitlines():
            log(nid, "    " + ln)
        set_status(nid, "installing")

        # 2) run role installer
        params = {"SERVER_IP": ip, "ROLE": row["role"], "EXIT_IP": row["exit_ip"] or ""}
        # An Iran relay needs the exit's tunnel params (generated by the foreign installer).
        if row["role"] == "iran":
            with db() as conn:
                fr = conn.execute(
                    "SELECT result FROM nodes WHERE ip=? AND role='foreign' "
                    "AND result IS NOT NULL ORDER BY id DESC LIMIT 1",
                    (row["exit_ip"],)).fetchone()
            fres = json.loads(fr["result"]) if fr and fr["result"] else {}
            if not fres.get("tun_pub"):
                log(nid, "Exit not ready: no tunnel params found. Provision the foreign exit "
                         "first (with the current installer), then retry this relay.")
                set_status(nid, "failed")
                return
            params["TUN_UUID"] = fres.get("tun_uuid", "")
            params["TUN_PUB"] = fres.get("tun_pub", "")
            params["TUN_SID"] = fres.get("tun_sid", "")
            # Optional fast-path (Hysteria2) params — the relay probes UDP and uses these
            # if a sustained UDP flow survives this ISP, else it falls back to REALITY-TCP.
            params["HY_PORT"] = fres.get("hy_port", "")
            params["HY_AUTH"] = fres.get("hy_auth", "")
            params["HY_OBFS"] = fres.get("hy_obfs", "")
        log(nid, f"[2/3] Running '{row['role']}' installer ...")
        script = render_installer(row["role"], params)
        code = run_stream(cli, nid, f"bash -s <<'__FLEET_EOF__'\n{script}\n__FLEET_EOF__")
        log(nid, f"installer exit code = {code}")

        # 3) collect result marker
        result = {}
        try:
            with open(logfile(nid), "r", encoding="utf-8") as f:
                for line in f:
                    if "FLEET_RESULT=" in line:
                        result = json.loads(line.split("FLEET_RESULT=", 1)[1].strip())
        except Exception:
            pass

        if code == 0:
            log(nid, "[3/3] Done ✅")
            set_status(nid, "ready", result)
            # auto-link: point customer configs at this relay (iran role only)
            if row["role"] == "iran" and row["exit_ip"]:
                try:
                    with db() as conn:
                        fr = conn.execute(
                            "SELECT result FROM nodes WHERE ip=? AND role='foreign' "
                            "AND result IS NOT NULL ORDER BY id DESC LIMIT 1",
                            (row["exit_ip"],)).fetchone()
                    if fr and fr["result"]:
                        fres = json.loads(fr["result"])
                        base = (fres.get("panel_url") or "").replace("/dashboard/", "")
                        if base and fres.get("admin_user"):
                            log(nid, "Linking relay in Marzban (pointing all 4 protocols at the relay)...")
                            marzban_link_relay(base, fres["admin_user"],
                                               fres["admin_pass"], row["ip"], nid)
                    else:
                        log(nid, "Foreign exit not found in panel DB - add the Marzban Hosts manually.")
                except Exception as e:
                    log(nid, f"Host auto-link skipped ({e}) - add the Marzban Hosts manually.")
        else:
            log(nid, "[3/3] Installer reported non-zero exit ❌")
            set_status(nid, "failed", result)
    except Exception as e:
        log(nid, f"ERROR: {e}")
        set_status(nid, "failed")
    finally:
        if cli is not None:
            try:
                cli.close()
            except Exception:
                pass


# ---------- paired (exit + relay) provisioning ----------
_pair_locks = {}
_pair_locks_guard = threading.Lock()


def _pair_lock(fnid):
    with _pair_locks_guard:
        return _pair_locks.setdefault(fnid, threading.Lock())
def pair_logfile(fnid):
    return os.path.join(LOG_DIR, f"pair-{fnid}.log")


def pairlog(fnid, msg):
    with open(pair_logfile(fnid), "a", encoding="utf-8") as f:
        f.write(msg.rstrip("\n") + "\n")


def precheck_ssh(ip, port, user, password):
    """Confirm we can reach + authenticate to a server BEFORE installing anything."""
    try:
        connect_key(ip, port, user, timeout=15).close()
        return True, "key auth OK"
    except paramiko.AuthenticationException:
        if password:
            try:
                connect_password(ip, port, user, password, timeout=15).close()
                return True, "password OK (dashboard key will be installed)"
            except Exception as e:
                return False, f"root password rejected ({e})"
        return False, "dashboard key not on server and no root password given"
    except Exception as e:
        return False, f"unreachable ({e})"


def provision_pair(foreign_nid, iran_nid, foreign_pw, iran_pw):
    """One-shot pair install: pre-check BOTH, then exit, then relay, then summarize.
    Pre-checks run first so we never install a foreign exit when the relay is unreachable.
    Serialized per foreign node so a re-run can never overlap an in-flight install."""
    lock = _pair_lock(foreign_nid)
    lock.acquire()
    try:
        with db() as conn:
            f = conn.execute("SELECT * FROM nodes WHERE id=?", (foreign_nid,)).fetchone()
            r = conn.execute("SELECT * FROM nodes WHERE id=?", (iran_nid,)).fetchone()
        if not f or not r:
            return
        pairlog(foreign_nid, "=== Pair install ===")
        pairlog(foreign_nid, "[pre-flight] checking SSH access to both servers ...")
        set_status(foreign_nid, "connecting")
        set_status(iran_nid, "new")
        ok_f, msg_f = precheck_ssh(f["ip"], f["ssh_port"], f["ssh_user"], foreign_pw)
        pairlog(foreign_nid, f"    foreign {f['ip']}: {msg_f}")
        ok_r, msg_r = precheck_ssh(r["ip"], r["ssh_port"], r["ssh_user"], iran_pw)
        pairlog(foreign_nid, f"    iran    {r['ip']}: {msg_r}")
        if not (ok_f and ok_r):
            pairlog(foreign_nid, "PRE-CHECK FAILED — nothing was installed. Fix access and retry.")
            set_status(foreign_nid, "failed")
            set_status(iran_nid, "failed")
            return

        pairlog(foreign_nid, "[1/2] installing foreign exit (Marzban + 4 protocols + tunnels) ...")
        provision(foreign_nid, foreign_pw)
        with db() as conn:
            fstat = conn.execute("SELECT status FROM nodes WHERE id=?", (foreign_nid,)).fetchone()["status"]
        if fstat != "ready":
            pairlog(foreign_nid, "Foreign exit failed — relay SKIPPED (see the exit's own log).")
            set_status(iran_nid, "failed")
            return
        pairlog(foreign_nid, "[1/2] foreign exit READY.")

        pairlog(foreign_nid, "[2/2] installing iran relay — probing UDP to auto-pick the tunnel ...")
        provision(iran_nid, iran_pw)
        with db() as conn:
            rr = conn.execute("SELECT status, result FROM nodes WHERE id=?", (iran_nid,)).fetchone()
        mode, fwd = "?", "?"
        try:
            rres = json.loads(rr["result"]) if rr and rr["result"] else {}
            mode, fwd = rres.get("tunnel", "?"), rres.get("forwarding", "?")
        except Exception:
            pass
        if rr and rr["status"] == "ready":
            tier = "FAST (Hysteria/UDP)" if mode == "hysteria" else "REALITY-TCP (UDP filtered on this ISP)"
            pairlog(foreign_nid, f"=== PAIR READY ✅   tunnel={mode} -> {tier}   end-to-end test: {fwd} ===")
            pairlog(foreign_nid, "Open the exit's Marzban panel and create users — configs auto-point at the relay.")
        else:
            pairlog(foreign_nid, f"Relay install did not finish cleanly (status={rr['status'] if rr else '?'}). See the relay's log.")
    except Exception as e:
        pairlog(foreign_nid, f"PAIR ERROR: {e}")
        try:
            set_status(foreign_nid, "failed")
            set_status(iran_nid, "failed")
        except Exception:
            pass
    finally:
        lock.release()


def require_login():
    return bool(session.get("auth"))


# ---------- templates ----------
BASE = """
<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Fleet Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
 :root{
  --bg:#0a0c12; --bg2:#0e1118; --surface:#141925; --surface2:#1a2030; --line:#232b3b; --line2:#2e394d;
  --text:#e8edf6; --muted:#8b97ad; --faint:#5d6779;
  --accent:#5b8cff; --accent2:#7c5cff; --grad:linear-gradient(135deg,#5b8cff,#7c5cff);
  --green:#3ad29f; --green-bg:rgba(58,210,159,.13); --red:#ff7a85; --red-bg:rgba(255,122,133,.13);
  --amber:#ffcf5c; --amber-bg:rgba(255,207,92,.13);
 }
 *{box-sizing:border-box}
 body{font-family:'Vazirmatn',system-ui,Segoe UI,Tahoma,sans-serif;background:
   radial-gradient(1200px 600px at 80% -10%,rgba(124,92,255,.10),transparent 60%),
   radial-gradient(1000px 500px at -10% 10%,rgba(91,140,255,.08),transparent 55%),var(--bg);
   color:var(--text);margin:0;min-height:100vh;-webkit-font-smoothing:antialiased}
 a{color:var(--accent);text-decoration:none;transition:.15s}a:hover{color:#86a9ff}
 .wrap{max-width:1040px;margin:30px auto;padding:0 20px}
 header{position:sticky;top:0;z-index:10;background:rgba(10,12,18,.72);backdrop-filter:blur(14px);
   padding:14px 24px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line)}
 .logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:17px;color:var(--text)}
 .logo .mark{width:30px;height:30px;border-radius:9px;background:var(--grad);display:grid;place-items:center;font-size:16px;box-shadow:0 4px 14px rgba(91,140,255,.4)}
 .nav{display:flex;align-items:center;gap:6px}
 .nav a{padding:7px 12px;border-radius:9px;color:var(--muted);font-size:14px}
 .nav a:hover{background:var(--surface);color:var(--text)}
 h2{font-size:22px;font-weight:700;margin:0} h3{font-size:18px;font-weight:600;margin:0 0 6px} h4{color:var(--muted);font-weight:600;font-size:14px;margin:18px 0 8px}
 .btn{background:var(--grad);color:#fff;padding:9px 16px;border-radius:10px;border:0;cursor:pointer;font-family:inherit;font-size:14px;font-weight:600;
   display:inline-flex;align-items:center;gap:6px;transition:.15s;box-shadow:0 3px 12px rgba(91,140,255,.28)}
 .btn:hover{filter:brightness(1.08);transform:translateY(-1px)}
 .btn.gray{background:var(--surface2);color:var(--text);box-shadow:none;border:1px solid var(--line2)}
 .btn.gray:hover{background:#222a3c}
 .btn.sm{padding:6px 12px;font-size:13px}
 .card{background:linear-gradient(180deg,var(--surface),var(--bg2));border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:0 8px 30px rgba(0,0,0,.25)}
 input,select{background:var(--bg);border:1px solid var(--line2);color:var(--text);padding:11px 12px;border-radius:10px;width:100%;box-sizing:border-box;font-family:inherit;font-size:14px;transition:.15s}
 input:focus,select:focus{outline:0;border-color:var(--accent);box-shadow:0 0 0 3px rgba(91,140,255,.16)}
 input::placeholder{color:var(--faint)}
 label{display:block;margin:13px 0 6px;color:var(--muted);font-size:13px;font-weight:500}
 .badge{padding:4px 11px;border-radius:30px;font-size:12px;font-weight:600;display:inline-flex;align-items:center;gap:6px;line-height:1}
 .badge::before{content:'';width:7px;height:7px;border-radius:50%;background:currentColor}
 .s-ready{background:var(--green-bg);color:var(--green)}.s-failed{background:var(--red-bg);color:var(--red)}
 .s-installing,.s-connecting{background:var(--amber-bg);color:var(--amber)}
 .s-installing::before,.s-connecting::before{animation:pulse 1.1s infinite}
 .s-new{background:rgba(139,151,173,.13);color:var(--muted)}
 @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
 pre{background:#070a10;border:1px solid var(--line);border-radius:12px;padding:15px;max-height:440px;overflow:auto;
   font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12.5px;line-height:1.6;direction:ltr;text-align:left;color:#c7d0de}
 pre::-webkit-scrollbar{width:9px;height:9px}pre::-webkit-scrollbar-thumb{background:var(--line2);border-radius:9px}
 code{background:#070a10;border:1px solid var(--line);padding:2px 7px;border-radius:6px;direction:ltr;display:inline-block;font-family:'JetBrains Mono',monospace;font-size:12.5px}
 table{width:100%;border-collapse:separate;border-spacing:0;background:var(--surface);border:1px solid var(--line);border-radius:14px;overflow:hidden}
 th,td{padding:13px 15px;text-align:right;border-bottom:1px solid var(--line);font-size:14px}
 th{background:var(--bg2);color:var(--muted);font-weight:600}tr:last-child td{border-bottom:0}tbody tr:hover{background:var(--surface2)}
 .mono{font-family:'JetBrains Mono',monospace;direction:ltr;font-size:13px}
 .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:680px){.grid2{grid-template-columns:1fr}}
 .row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
 hr{border:0;border-top:1px solid var(--line);margin:14px 0}
 .kv b{color:var(--muted);font-weight:500}
</style></head><body>
<header>
 <a href="/" class="logo"><span class="mark">🛰️</span> Fleet Panel</a>
 <div class="nav">{% if session.auth %}<a href="/key">🔑 کلید عمومی</a><a href="/logout">خروج</a>{% endif %}</div>
</header>
<div class="wrap">{{ body|safe }}</div></body></html>
"""

LOGIN = """
<div style="max-width:380px;margin:7vh auto">
 <div style="text-align:center;margin-bottom:22px">
  <div style="width:56px;height:56px;border-radius:16px;background:var(--grad);display:inline-grid;place-items:center;font-size:27px;box-shadow:0 10px 30px rgba(91,140,255,.45)">🛰️</div>
  <h2 style="margin-top:14px">Fleet Panel</h2>
  <p style="color:var(--muted);margin:5px 0 0;font-size:14px">برای مدیریت فلیت وارد شو</p>
 </div>
 <div class="card">
  {% if err %}<div style="background:var(--red-bg);color:var(--red);padding:10px 13px;border-radius:10px;font-size:13px;margin-bottom:4px">{{ err }}</div>{% endif %}
  <form method="post"><label>رمز عبور پنل</label><input type="password" name="password" autofocus>
  <div style="margin-top:18px"><button class="btn" style="width:100%;justify-content:center">ورود</button></div></form>
 </div>
</div>
"""

KEY = """
<div class="row" style="margin-bottom:18px"><h2>🔑 کلید عمومی</h2><a class="btn gray sm" href="/">← بازگشت</a></div>
<div class="card">
<p style="color:var(--muted);font-size:13.5px;line-height:1.75;margin-top:0">این کلید را موقع ساخت سرور جدید (بخش SSH Keys سرویس‌دهنده) اضافه کن تا بدون پسورد وصل شود،
یا روی سرور موجود در <code>~/.ssh/authorized_keys</code> بگذار.</p>
<pre id="pk">{{ pub }}</pre>
<button class="btn gray sm" onclick="navigator.clipboard.writeText(document.getElementById('pk').textContent.trim());this.textContent='کپی شد ✓'">📋 کپی کلید</button>
</div>
"""

INDEX = """
<style>
 .servers{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
 .srv{background:linear-gradient(180deg,var(--surface),var(--bg2));border:1px solid var(--line);border-radius:15px;padding:17px;transition:.16s}
 .srv:hover{border-color:var(--line2);transform:translateY(-2px);box-shadow:0 12px 30px rgba(0,0,0,.32)}
 .srv .ip{font-family:'JetBrains Mono',monospace;direction:ltr;color:var(--muted);font-size:12.5px;margin-top:3px}
 .srv .meta{color:var(--faint);font-size:12.5px;margin:11px 0}
 .srv .acts{display:flex;justify-content:space-between;align-items:center;border-top:1px solid var(--line);padding-top:12px;margin-top:3px}
 .ricon{width:30px;height:30px;border-radius:9px;display:inline-grid;place-items:center;background:var(--surface2);border:1px solid var(--line2);font-size:15px;flex:none}
 .empty{text-align:center;color:var(--muted);padding:48px 20px}
</style>
<div class="row" style="margin-bottom:20px">
 <h2>سرورها</h2>
 <div style="display:flex;gap:8px"><a class="btn" href="/pair">➕ جفت سرور</a><a class="btn gray" href="/add">+ تکی</a></div>
</div>
{% if nodes %}
<div class="servers">
{% for s in nodes %}
 <div class="srv">
  <div class="row" style="align-items:flex-start">
   <div style="display:flex;align-items:center;gap:10px"><span class="ricon">{{ '🌍' if s['role']=='foreign' else '🇮🇷' }}</span>
    <div><b>{{ s['name'] or 'بدون‌نام' }}</b><div class="ip">{{ s['ip'] }}</div></div></div>
   <span class="badge s-{{ s['status'] }}">{{ s['status'] }}</span>
  </div>
  <div class="meta">{{ 'خارج · اکسیت + پنل' if s['role']=='foreign' else 'ایران · رله' }}{% if s['key_installed'] %} · کلید ✓{% endif %}</div>
  <div class="acts">
   {% if s['panel_url'] %}<a class="btn gray sm" href="{{ s['panel_url'] }}" target="_blank">پنل ↗</a>{% else %}<span style="color:var(--faint);font-size:13px">بدون پنل</span>{% endif %}
   <a href="/node/{{ s['id'] }}">جزئیات →</a>
  </div>
 </div>
{% endfor %}
</div>
{% else %}
<div class="card empty">🛰️<br><br>هنوز سروری اضافه نشده.<br><br><a class="btn" href="/pair">➕ اولین جفت را اضافه کن</a></div>
{% endif %}
"""

ADD = """
<div class="row" style="margin-bottom:18px"><h2>افزودن سرور تکی</h2><a class="btn gray sm" href="/">← بازگشت</a></div>
<div class="card" style="max-width:560px">
<form method="post">
 <label>نام (دلخواه)</label><input name="name" placeholder="exit-de-1">
 <label>نقش سرور</label>
 <select name="role" onchange="document.getElementById('eb').style.display=this.value==='iran'?'block':'none'">
   <option value="foreign">🌍 خارج — اکسیت + پنل</option>
   <option value="iran">🇮🇷 ایران — رله به اکسیت</option></select>
 <div id="eb" style="display:none"><label>IP اکسیت خارج (که این رله به آن وصل می‌شود)</label>
   <input name="exit_ip" placeholder="آی‌پی سرور خارجِ نصب‌شده"></div>
 <label>IP سرور</label><input name="ip" required placeholder="1.2.3.4">
 <div style="display:flex;gap:10px"><div style="flex:2"><label>یوزر SSH</label><input name="ssh_user" value="root"></div>
   <div style="flex:1"><label>پورت</label><input name="ssh_port" value="22"></div></div>
 <label>پسورد روت — فقط یک‌بار برای نصب کلید (ذخیره نمی‌شود)</label>
 <input type="password" name="password" placeholder="اگر کلید را از قبل گذاشته‌ای، خالی بگذار">
 <p style="color:var(--faint);font-size:12.5px;margin-top:10px;line-height:1.7">اول «خارج» را نصب کن، بعد «ایران» — یا از دکمه‌ی «جفت سرور» استفاده کن تا خودکار و یک‌مرحله‌ای شود.</p>
 <div style="margin-top:16px;display:flex;gap:8px"><button class="btn">اتصال و نصب</button> <a class="btn gray" href="/">انصراف</a></div>
</form></div>
"""

NODE = """
<div class="row" style="margin-bottom:18px">
 <h2>{{ s['name'] or s['ip'] }} &nbsp;<span class="badge s-{{ s['status'] }}">{{ s['status'] }}</span></h2>
 <div style="display:flex;gap:8px"><a class="btn gray sm" href="/">← همه</a>
 <form method="post" action="/node/{{ s['id'] }}/install" style="display:inline"><button class="btn sm">▶ نصب مجدد</button></form></div></div>
<div class="card" style="margin-bottom:16px">
 <div class="kv" style="display:flex;flex-wrap:wrap;gap:8px 22px;font-size:14px">
  <span><b>IP:</b> <span class="mono">{{ s['ip'] }}:{{ s['ssh_port'] }}</span></span>
  <span><b>نقش:</b> {{ 'خارج (اکسیت)' if s['role']=='foreign' else 'ایران (رله)' }}</span>
  <span><b>کلید:</b> {{ '✓' if s['key_installed'] else '—' }}</span>
  {% if s['exit_ip'] %}<span><b>اکسیت:</b> <span class="mono">{{ s['exit_ip'] }}</span></span>{% endif %}
 </div>
 {% if result %}<hr>
   {% if result.panel_url %}<div style="margin-bottom:7px"><b style="color:var(--muted)">پنل:</b> <a href="{{ result.panel_url }}" target="_blank" class="mono">{{ result.panel_url }}</a></div>{% endif %}
   {% if result.admin_user %}<div><b style="color:var(--muted)">یوزر:</b> <code>{{ result.admin_user }}</code> &nbsp; <b style="color:var(--muted)">پسورد:</b> <code>{{ result.admin_pass }}</code></div>{% endif %}
   {% if result.tunnel %}<div style="margin-top:7px"><b style="color:var(--muted)">تونل:</b> {{ result.tunnel }}</div>{% endif %}
 {% endif %}</div>
<h4>لاگ نصب</h4><pre id="logbox">{{ logtext }}</pre>
<script>
 const st="{{ s['status'] }}";
 function poll(){fetch("/node/{{ s['id'] }}/log").then(r=>r.text()).then(t=>{
   const b=document.getElementById('logbox');b.textContent=t;b.scrollTop=b.scrollHeight;});}
 if(["connecting","installing","new"].includes(st)){setInterval(poll,2000);}
</script>
"""

PAIR_FORM = """
<div class="row" style="margin-bottom:18px"><h2>➕ جفت سرور جدید</h2><a class="btn gray sm" href="/">← بازگشت</a></div>
<div class="card" style="max-width:720px">
{% if err %}<div style="background:var(--red-bg);color:var(--red);padding:10px 13px;border-radius:10px;font-size:13px;margin-bottom:12px">{{ err }}</div>{% endif %}
<p style="color:var(--muted);font-size:13.5px;line-height:1.8;margin-top:0">هر دو IP را بده. خودش <b style="color:var(--text)">اول دسترسیِ هر دو را چک می‌کند</b> (اگر یکی در دسترس نبود هیچ‌چیز نصب نمی‌شود)، بعد اول خارج بعد ایران را نصب می‌کند، <b style="color:var(--text)">UDP را تست می‌کند و بهترین تونل را خودکار انتخاب می‌کند</b> و نتیجه را نشان می‌دهد.</p>
<form method="post">
 <div class="grid2">
  <div style="border:1px solid var(--line2);border-radius:13px;padding:16px;background:var(--bg2)">
   <div style="font-weight:600;margin-bottom:4px">🌍 سرور خارج (اکسیت)</div>
   <label>نام</label><input name="f_name" placeholder="exit-de-1">
   <label>IP</label><input name="f_ip" required placeholder="1.2.3.4">
   <div style="display:flex;gap:8px"><div style="flex:2"><label>یوزر</label><input name="f_user" value="root"></div><div style="flex:1"><label>پورت</label><input name="f_port" value="22"></div></div>
   <label>پسورد روت (اختیاری)</label><input type="password" name="f_password" placeholder="اگر کلید را گذاشته‌ای خالی">
  </div>
  <div style="border:1px solid var(--line2);border-radius:13px;padding:16px;background:var(--bg2)">
   <div style="font-weight:600;margin-bottom:4px">🇮🇷 سرور ایران (رله)</div>
   <label>نام</label><input name="r_name" placeholder="relay-ir-1">
   <label>IP</label><input name="r_ip" required placeholder="5.6.7.8">
   <div style="display:flex;gap:8px"><div style="flex:2"><label>یوزر</label><input name="r_user" value="root"></div><div style="flex:1"><label>پورت</label><input name="r_port" value="22"></div></div>
   <label>پسورد روت (اختیاری)</label><input type="password" name="r_password" placeholder="اگر کلید را گذاشته‌ای خالی">
  </div>
 </div>
 <div style="margin-top:18px;display:flex;gap:8px"><button class="btn">⚡ چک، نصب و تست</button> <a class="btn gray" href="/">انصراف</a></div>
</form></div>
"""

PAIR_VIEW = """
<div class="row" style="margin-bottom:18px">
 <h2>جفت: {{ f['name'] or f['ip'] }} <span style="color:var(--faint)">↔</span> {{ (r['name'] or r['ip']) if r else '—' }}</h2>
 <div style="display:flex;gap:8px"><a class="btn gray sm" href="/">← همه</a>
 {% if r %}<form method="post" action="/pair/{{ f['id'] }}/install" style="display:inline"><button class="btn sm">▶ نصب مجدد جفت</button></form>{% endif %}</div></div>
<div class="grid2" style="margin-bottom:16px">
 <div class="card">
  <div class="row"><span style="font-weight:600">🌍 خارج</span><span class="badge s-{{ f['status'] }}">{{ f['status'] }}</span></div>
  <div class="mono" style="color:var(--muted);font-size:13px;margin-top:6px">{{ f['ip'] }}</div>
  {% if fres and fres.panel_url %}<hr>
   <div style="margin-bottom:6px"><b style="color:var(--muted)">پنل:</b> <a href="{{ fres.panel_url }}" target="_blank" class="mono">{{ fres.panel_url }}</a></div>
   <div><b style="color:var(--muted)">یوزر:</b> <code>{{ fres.admin_user }}</code> &nbsp; <b style="color:var(--muted)">پسورد:</b> <code>{{ fres.admin_pass }}</code></div>{% endif %}
  <div style="margin-top:12px"><a href="/node/{{ f['id'] }}">لاگ خارج →</a></div>
 </div>
 <div class="card">
  <div class="row"><span style="font-weight:600">🇮🇷 ایران</span>{% if r %}<span class="badge s-{{ r['status'] }}">{{ r['status'] }}</span>{% endif %}</div>
  {% if r %}<div class="mono" style="color:var(--muted);font-size:13px;margin-top:6px">{{ r['ip'] }}</div>{% endif %}
  {% if rres %}<hr>
   <div><b style="color:var(--muted)">تونل:</b> {% if rres.tunnel=='hysteria' %}<span style="color:var(--green)">🟢 Hysteria — سریع</span>{% elif rres.tunnel=='reality' %}<span style="color:var(--amber)">🟡 REALITY-TCP</span> <span style="color:var(--faint);font-size:12px">(UDP این ISP فیلتره)</span>{% else %}{{ rres.tunnel }}{% endif %}</div>
   <div style="margin-top:6px"><b style="color:var(--muted)">تستِ مسیر:</b> {% if rres.forwarding=='ok' %}<span style="color:var(--green)">✅ موفق</span>{% else %}{{ rres.forwarding }}{% endif %}</div>{% endif %}
  {% if r %}<div style="margin-top:12px"><a href="/node/{{ r['id'] }}">لاگ ایران →</a></div>{% endif %}
 </div>
</div>
<h4>پیشرفت جفت</h4><pre id="logbox">{{ plog }}</pre>
<script>
 function tick(){
   fetch("/pair/{{ f['id'] }}/log").then(r=>r.text()).then(t=>{const b=document.getElementById('logbox');b.textContent=t;b.scrollTop=b.scrollHeight;});
   fetch("/pair/{{ f['id'] }}/status").then(r=>r.json()).then(j=>{ if(j.done){ clearInterval(h); setTimeout(()=>location.reload(),900); } });
 }
 var h=null;
 if({{ 'true' if live else 'false' }}){ h=setInterval(tick,2500); }
</script>
"""


def page(tmpl, **kw):
    body = render_template_string(tmpl, **kw)
    return render_template_string(BASE, body=body, session=session)


# ---------- routes ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASS:
            session["auth"] = True
            return redirect(url_for("index"))
        err = "رمز اشتباه است."
    return page(LOGIN, err=err)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/key")
def key():
    if not require_login():
        return redirect(url_for("login"))
    return page(KEY, pub=ensure_keypair())


@app.route("/")
def index():
    if not require_login():
        return redirect(url_for("login"))
    with db() as conn:
        rows = conn.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
    nodes = []
    for r in rows:
        d = dict(r)
        try:
            d["panel_url"] = json.loads(r["result"]).get("panel_url") if r["result"] else None
        except Exception:
            d["panel_url"] = None
        nodes.append(d)
    return page(INDEX, nodes=nodes)


@app.route("/add", methods=["GET", "POST"])
def add():
    if not require_login():
        return redirect(url_for("login"))
    if request.method == "POST":
        f = request.form
        with db() as conn:
            cur = conn.execute(
                """INSERT INTO nodes (name, ip, ssh_user, ssh_port, role, exit_ip,
                   status, created_at) VALUES (?,?,?,?,?,?,?,?)""",
                (f.get("name", "").strip(), f["ip"].strip(),
                 f.get("ssh_user", "root").strip() or "root",
                 int(f.get("ssh_port", 22) or 22), f.get("role", "foreign"),
                 (f.get("exit_ip") or "").strip(), "new", int(time.time())),
            )
            nid = cur.lastrowid
        pw = f.get("password") or None  # transient, never stored
        threading.Thread(target=provision, args=(nid, pw), daemon=True).start()
        return redirect(url_for("node", nid=nid))
    return page(ADD)


def _find_relay(conn, foreign_row):
    """Resolve a foreign node's paired relay: by explicit relay_id, else fall back to the
    exit_ip linkage (covers pairs created before the relay_id column existed)."""
    try:
        rid = foreign_row["relay_id"]
    except (KeyError, IndexError):
        rid = None
    if rid:
        r = conn.execute("SELECT * FROM nodes WHERE id=? AND role='iran'", (rid,)).fetchone()
        if r:
            return r
    return conn.execute("SELECT * FROM nodes WHERE exit_ip=? AND role='iran' ORDER BY id DESC LIMIT 1",
                        (foreign_row["ip"],)).fetchone()


@app.route("/pair", methods=["GET", "POST"])
def pair():
    if not require_login():
        return redirect(url_for("login"))
    if request.method == "POST":
        f = request.form
        fip = f["f_ip"].strip()
        rip = f["r_ip"].strip()

        def port(v):
            try:
                p = int(v or 22)
            except Exception:
                p = 22
            return p if 1 <= p <= 65535 else 22
        if not fip or not rip:
            return page(PAIR_FORM, err="IP هر دو سرور لازم است.")
        now = int(time.time())
        try:
            with db() as conn:
                cur = conn.execute(
                    """INSERT INTO nodes (name, ip, ssh_user, ssh_port, role, exit_ip, status, created_at)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (f.get("f_name", "").strip() or "exit", fip,
                     f.get("f_user", "root").strip() or "root", port(f.get("f_port")),
                     "foreign", "", "new", now))
                fnid = cur.lastrowid
                rcur = conn.execute(
                    """INSERT INTO nodes (name, ip, ssh_user, ssh_port, role, exit_ip, status, created_at)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (f.get("r_name", "").strip() or "relay", rip,
                     f.get("r_user", "root").strip() or "root", port(f.get("r_port")),
                     "iran", fip, "new", now))
                rnid = rcur.lastrowid
                conn.execute("UPDATE nodes SET relay_id=? WHERE id=?", (rnid, fnid))
        except Exception as e:
            return page(PAIR_FORM, err=f"خطا در ساخت نودها: {e}")
        fpw = f.get("f_password") or None
        rpw = f.get("r_password") or None
        open(pair_logfile(fnid), "w").close()
        threading.Thread(target=provision_pair, args=(fnid, rnid, fpw, rpw), daemon=True).start()
        return redirect(url_for("pair_view", nid=fnid))
    return page(PAIR_FORM)


@app.route("/pair/<int:nid>")
def pair_view(nid):
    if not require_login():
        return redirect(url_for("login"))
    with db() as conn:
        f = conn.execute("SELECT * FROM nodes WHERE id=? AND role='foreign'", (nid,)).fetchone()
        if not f:
            abort(404)
        r = _find_relay(conn, f)
    fres = json.loads(f["result"]) if f["result"] else None
    rres = json.loads(r["result"]) if r and r["result"] else None
    plog = ""
    if os.path.exists(pair_logfile(nid)):
        with open(pair_logfile(nid), "r", encoding="utf-8") as fp:
            plog = fp.read()
    terminal = {"ready", "failed"}
    live = (f["status"] not in terminal) or (r is not None and r["status"] not in terminal)
    return page(PAIR_VIEW, f=f, r=r, fres=fres, rres=rres, plog=plog, live=live)


@app.route("/pair/<int:nid>/log")
def pair_log_route(nid):
    if not require_login():
        return Response("forbidden", status=403)
    if os.path.exists(pair_logfile(nid)):
        with open(pair_logfile(nid), "r", encoding="utf-8") as fp:
            return Response(fp.read(), mimetype="text/plain")
    return Response("", mimetype="text/plain")


@app.route("/pair/<int:nid>/status")
def pair_status(nid):
    if not require_login():
        return Response("forbidden", status=403)
    with db() as conn:
        f = conn.execute("SELECT * FROM nodes WHERE id=? AND role='foreign'", (nid,)).fetchone()
        if not f:
            return Response(json.dumps({"done": True}), mimetype="application/json")
        r = _find_relay(conn, f)
    terminal = {"ready", "failed"}
    # stop polling once the foreign is terminal and the relay is also terminal OR absent
    done = (f["status"] in terminal) and (r is None or r["status"] in terminal)
    return Response(json.dumps({"done": done}), mimetype="application/json")


@app.route("/pair/<int:nid>/install", methods=["POST"])
def pair_reinstall(nid):
    if not require_login():
        return redirect(url_for("login"))
    with db() as conn:
        f = conn.execute("SELECT * FROM nodes WHERE id=? AND role='foreign'", (nid,)).fetchone()
        if not f:
            abort(404)
        r = _find_relay(conn, f)
    if f["status"] in ("connecting", "installing"):
        return redirect(url_for("pair_view", nid=nid))  # a run is already in flight
    if not r:
        pairlog(nid, "ERROR: relay for this pair not found — recreate the pair.")
        return redirect(url_for("pair_view", nid=nid))
    open(pair_logfile(nid), "w").close()
    threading.Thread(target=provision_pair, args=(nid, r["id"], None, None), daemon=True).start()
    return redirect(url_for("pair_view", nid=nid))


@app.route("/node/<int:nid>")
def node(nid):
    if not require_login():
        return redirect(url_for("login"))
    with db() as conn:
        s = conn.execute("SELECT * FROM nodes WHERE id=?", (nid,)).fetchone()
    if not s:
        abort(404)
    result = json.loads(s["result"]) if s["result"] else None
    logtext = ""
    if os.path.exists(logfile(nid)):
        with open(logfile(nid), "r", encoding="utf-8") as fp:
            logtext = fp.read()
    return page(NODE, s=s, result=result, logtext=logtext)


@app.route("/node/<int:nid>/log")
def node_log(nid):
    if not require_login():
        return Response("forbidden", status=403)
    if os.path.exists(logfile(nid)):
        with open(logfile(nid), "r", encoding="utf-8") as fp:
            return Response(fp.read(), mimetype="text/plain")
    return Response("", mimetype="text/plain")


@app.route("/node/<int:nid>/install", methods=["POST"])
def reinstall(nid):
    if not require_login():
        return redirect(url_for("login"))
    threading.Thread(target=provision, args=(nid, None), daemon=True).start()
    return redirect(url_for("node", nid=nid))


init_db()
ensure_keypair()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8088)))
