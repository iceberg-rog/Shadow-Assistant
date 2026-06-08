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
                created_at INTEGER
            )
            """
        )


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


# ---------- provisioning worker ----------
def provision(nid, bootstrap_password=None):
    with db() as conn:
        row = conn.execute("SELECT * FROM nodes WHERE id=?", (nid,)).fetchone()
    if not row:
        return
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

        cli.close()
        if code == 0:
            log(nid, "[3/3] Done ✅")
            set_status(nid, "ready", result)
        else:
            log(nid, "[3/3] Installer reported non-zero exit ❌")
            set_status(nid, "failed", result)
    except Exception as e:
        log(nid, f"ERROR: {e}")
        set_status(nid, "failed")


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
 <h2>سرورها</h2><a class="btn" href="/add">➕ سرور جدید</a></div>
<table><tr><th>نام</th><th>IP</th><th>نقش</th><th>کلید</th><th>وضعیت</th><th></th></tr>
{% for s in nodes %}
<tr><td>{{ s['name'] or '-' }}</td><td style="direction:ltr">{{ s['ip'] }}</td>
<td>{{ 'خارج (اکسیت)' if s['role']=='foreign' else 'ایران (relay)' }}</td>
<td>{{ '✅' if s['key_installed'] else '—' }}</td>
<td><span class="badge s-{{ s['status'] }}">{{ s['status'] }}</span></td>
<td><a href="/node/{{ s['id'] }}">جزئیات →</a></td></tr>
{% endfor %}
{% if not nodes %}<tr><td colspan="6" style="color:#9aa4b2">هنوز سروری اضافه نشده.</td></tr>{% endif %}
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
        nodes = conn.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
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
