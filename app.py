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
<style>
 body{font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0f1115;color:#e6e6e6;margin:0}
 header{background:#171a21;padding:14px 22px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #262b36}
 a{color:#5b9dff;text-decoration:none}.btn{background:#2d6cdf;color:#fff;padding:8px 14px;border-radius:8px;border:0;cursor:pointer;font-size:14px}
 .btn.gray{background:#39414f}.wrap{max-width:980px;margin:24px auto;padding:0 18px}
 table{width:100%;border-collapse:collapse;background:#171a21;border-radius:10px;overflow:hidden}
 th,td{padding:11px 13px;text-align:right;border-bottom:1px solid #262b36;font-size:14px}th{background:#1d212a;color:#9aa4b2}
 input,select{background:#0f1115;border:1px solid #303744;color:#e6e6e6;padding:9px;border-radius:8px;width:100%;box-sizing:border-box;font-size:14px}
 label{display:block;margin:12px 0 5px;color:#9aa4b2;font-size:13px}
 .card{background:#171a21;border:1px solid #262b36;border-radius:12px;padding:20px}
 .badge{padding:3px 9px;border-radius:20px;font-size:12px}
 .s-ready{background:#16432a;color:#5fd38a}.s-failed{background:#4a1f1f;color:#ff8a80}
 .s-installing,.s-connecting{background:#3a3414;color:#ffd95e}.s-new{background:#2a2f3a;color:#9aa4b2}
 pre{background:#0b0d11;border:1px solid #262b36;border-radius:10px;padding:14px;max-height:430px;overflow:auto;font-size:13px;line-height:1.5;direction:ltr;text-align:left}
 code{background:#0b0d11;padding:2px 6px;border-radius:5px;direction:ltr;display:inline-block}
</style></head><body>
<header><div><a href="/"><b>🛰️ Fleet Panel</b></a></div>
<div>{% if session.auth %}<a href="/key">🔑 کلید عمومی</a> &nbsp; <a href="/logout">خروج</a>{% endif %}</div></header>
<div class="wrap">{{ body|safe }}</div></body></html>
"""

LOGIN = """
<div class="card" style="max-width:360px;margin:60px auto"><h3>ورود</h3>
{% if err %}<p style="color:#ff8a80">{{ err }}</p>{% endif %}
<form method="post"><label>رمز عبور پنل</label><input type="password" name="password" autofocus>
<div style="margin-top:16px"><button class="btn">ورود</button></div></form></div>
"""

KEY = """
<div class="card"><h3>🔑 کلید عمومی داشبورد</h3>
<p style="color:#9aa4b2">این کلید را موقع ساخت سرور جدید (مثلاً بخش SSH Keys در Cloudzy) اضافه کن تا بدون پسورد وصل شود.
یا روی سرور موجود در <code>~/.ssh/authorized_keys</code> بگذار.</p>
<pre>{{ pub }}</pre></div>
"""

INDEX = """
<div style="display:flex;justify-content:space-between;align-items:center">
 <h2>سرورها</h2><div><a class="btn" href="/pair">➕ جفت سرور (خارج+ایران)</a> &nbsp;<a class="btn gray" href="/add">+ تکی</a></div></div>
<table><tr><th>نام</th><th>IP</th><th>نقش</th><th>کلید</th><th>وضعیت</th><th>پنل</th><th></th></tr>
{% for s in nodes %}
<tr><td>{{ s['name'] or '-' }}</td><td style="direction:ltr">{{ s['ip'] }}</td>
<td>{{ 'خارج (اکسیت)' if s['role']=='foreign' else 'ایران (relay)' }}</td>
<td>{{ '✅' if s['key_installed'] else '—' }}</td>
<td><span class="badge s-{{ s['status'] }}">{{ s['status'] }}</span></td>
<td>{% if s['panel_url'] %}<a href="{{ s['panel_url'] }}" target="_blank" style="direction:ltr">باز کردن ↗</a>{% else %}—{% endif %}</td>
<td><a href="/node/{{ s['id'] }}">جزئیات →</a></td></tr>
{% endfor %}
{% if not nodes %}<tr><td colspan="7" style="color:#9aa4b2">هنوز سروری اضافه نشده.</td></tr>{% endif %}
</table>
"""

ADD = """
<div class="card" style="max-width:560px;margin:0 auto"><h3>افزودن سرور</h3>
<form method="post">
 <label>نام (دلخواه)</label><input name="name" placeholder="exit-de-1">
 <label>نقش سرور</label>
 <select name="role" onchange="document.getElementById('eb').style.display=this.value==='iran'?'block':'none'">
   <option value="foreign">خارج — اکسیت + پنل</option>
   <option value="iran">ایران — relay به اکسیت</option></select>
 <div id="eb" style="display:none"><label>IP اکسیت خارج (که این relay به آن وصل می‌شود)</label>
   <input name="exit_ip" placeholder="آی‌پی سرور خارجِ نصب‌شده"></div>
 <label>IP سرور</label><input name="ip" required placeholder="1.2.3.4">
 <div style="display:flex;gap:10px"><div style="flex:2"><label>یوزر SSH</label><input name="ssh_user" value="root"></div>
   <div style="flex:1"><label>پورت</label><input name="ssh_port" value="22"></div></div>
 <label>پسورد روت — فقط یک‌بار برای نصب کلید (ذخیره نمی‌شود)</label>
 <input type="password" name="password" placeholder="اگر کلید عمومی داشبورد را از قبل گذاشته‌ای، خالی بگذار">
 <p style="color:#9aa4b2;font-size:12px">اول «خارج» را نصب کن، بعد «ایران». پسورد فقط برای افزودن کلیدِ داشبورد استفاده و سپس دور انداخته می‌شود.</p>
 <div style="margin-top:14px"><button class="btn">اتصال و نصب</button> <a class="btn gray" href="/">انصراف</a></div>
</form></div>
"""

NODE = """
<div style="display:flex;justify-content:space-between;align-items:center">
 <h2>{{ s['name'] or s['ip'] }} <span class="badge s-{{ s['status'] }}">{{ s['status'] }}</span></h2>
 <div><a class="btn gray" href="/">← همه</a>
 <form method="post" action="/node/{{ s['id'] }}/install" style="display:inline"><button class="btn">▶ نصب مجدد</button></form></div></div>
<div class="card" style="margin-bottom:16px">
 <b>IP:</b> <span style="direction:ltr">{{ s['ip'] }}:{{ s['ssh_port'] }}</span> &nbsp;|&nbsp;
 <b>نقش:</b> {{ 'خارج (اکسیت)' if s['role']=='foreign' else 'ایران (relay)' }}
 &nbsp;|&nbsp; <b>کلید نصب‌شده:</b> {{ '✅' if s['key_installed'] else '—' }}
 {% if s['exit_ip'] %}&nbsp;→ اکسیت {{ s['exit_ip'] }}{% endif %}
 {% if result %}<hr style="border-color:#262b36">
   {% if result.panel_url %}<b>پنل:</b> <a href="{{ result.panel_url }}" target="_blank" style="direction:ltr">{{ result.panel_url }}</a><br>{% endif %}
   {% if result.admin_user %}<b>یوزر:</b> {{ result.admin_user }} &nbsp; <b>پسورد:</b> {{ result.admin_pass }}{% endif %}
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
<div class="card" style="max-width:660px;margin:0 auto"><h3>➕ جفت سرور جدید (خارج + ایران)</h3>
{% if err %}<p style="color:#ff8a80">{{ err }}</p>{% endif %}
<p style="color:#9aa4b2;font-size:13px">هر دو IP را بده. خودش <b>اول دسترسیِ هر دو را چک می‌کند</b> (اگر یکی در دسترس نبود هیچ‌چیز نصب نمی‌شود)، بعد اول خارج بعد ایران را نصب می‌کند، <b>UDP را تست می‌کند و بهترین تونل را خودکار انتخاب می‌کند</b> و نتیجه را نشان می‌دهد.</p>
<form method="post">
 <div style="display:flex;gap:16px;flex-wrap:wrap">
  <div style="flex:1;min-width:270px;border:1px solid #262b36;border-radius:10px;padding:14px">
   <b>🌍 سرور خارج (اکسیت)</b>
   <label>نام</label><input name="f_name" placeholder="exit-de-1">
   <label>IP</label><input name="f_ip" required placeholder="1.2.3.4">
   <div style="display:flex;gap:8px"><div style="flex:2"><label>یوزر</label><input name="f_user" value="root"></div><div style="flex:1"><label>پورت</label><input name="f_port" value="22"></div></div>
   <label>پسورد روت (اختیاری)</label><input type="password" name="f_password" placeholder="اگر کلید را گذاشته‌ای خالی">
  </div>
  <div style="flex:1;min-width:270px;border:1px solid #262b36;border-radius:10px;padding:14px">
   <b>🇮🇷 سرور ایران (رله)</b>
   <label>نام</label><input name="r_name" placeholder="relay-ir-1">
   <label>IP</label><input name="r_ip" required placeholder="5.6.7.8">
   <div style="display:flex;gap:8px"><div style="flex:2"><label>یوزر</label><input name="r_user" value="root"></div><div style="flex:1"><label>پورت</label><input name="r_port" value="22"></div></div>
   <label>پسورد روت (اختیاری)</label><input type="password" name="r_password" placeholder="اگر کلید را گذاشته‌ای خالی">
  </div>
 </div>
 <div style="margin-top:16px"><button class="btn">چک، نصب و تست</button> <a class="btn gray" href="/">انصراف</a></div>
</form></div>
"""

PAIR_VIEW = """
<div style="display:flex;justify-content:space-between;align-items:center">
 <h2>جفت: {{ f['name'] or f['ip'] }} ↔ {{ (r['name'] or r['ip']) if r else '—' }}</h2>
 <div><a class="btn gray" href="/">← همه</a>
 {% if r %}<form method="post" action="/pair/{{ f['id'] }}/install" style="display:inline"><button class="btn">▶ نصب مجدد جفت</button></form>{% endif %}</div></div>
<div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px">
 <div class="card" style="flex:1;min-width:290px">
  <b>🌍 خارج</b> <span class="badge s-{{ f['status'] }}">{{ f['status'] }}</span>
  &nbsp;<span style="direction:ltr;color:#9aa4b2">{{ f['ip'] }}</span>
  {% if fres and fres.panel_url %}<hr style="border-color:#262b36">
   <b>پنل:</b> <a href="{{ fres.panel_url }}" target="_blank" style="direction:ltr">{{ fres.panel_url }}</a><br>
   <b>یوزر:</b> {{ fres.admin_user }} &nbsp; <b>پسورد:</b> {{ fres.admin_pass }}{% endif %}
  <br><a href="/node/{{ f['id'] }}">لاگ خارج →</a>
 </div>
 <div class="card" style="flex:1;min-width:290px">
  <b>🇮🇷 ایران</b> {% if r %}<span class="badge s-{{ r['status'] }}">{{ r['status'] }}</span>
  &nbsp;<span style="direction:ltr;color:#9aa4b2">{{ r['ip'] }}</span>{% endif %}
  {% if rres %}<hr style="border-color:#262b36">
   <b>تونل:</b> {% if rres.tunnel=='hysteria' %}🟢 Hysteria — سریع{% elif rres.tunnel=='reality' %}🟡 REALITY-TCP — UDP این ISP فیلتره{% else %}{{ rres.tunnel }}{% endif %}
   &nbsp;|&nbsp; <b>تستِ مسیر:</b> {% if rres.forwarding=='ok' %}✅ موفق{% else %}{{ rres.forwarding }}{% endif %}{% endif %}
  {% if r %}<br><a href="/node/{{ r['id'] }}">لاگ ایران →</a>{% endif %}
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
