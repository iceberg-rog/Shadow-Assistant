"""v2ray (Marzban) services.

OpenVPN is identified and reset by DPI on the Iran path - proven on this fleet:
the TCP connection and the first control packet get through, then the handshake
dies, on 1194 and on 443 alike, and clamping MTU changes nothing. So a service
that has to work from Iran runs these protocols instead, on one foreign box that
customers dial directly:

    443/tcp   VLESS + REALITY + vision
    8443/tcp  Trojan + REALITY      (xray 26 removed allowInsecure, so a
                                     self-signed Trojan is unusable - REALITY
                                     needs no certificate)
    8080/tcp  VMess + TCP
    8388/tcp  Shadowsocks
    2096/tcp  Marzban panel + one subscription link carrying all of them

Everything talks to Marzban over SSH+curl on the server itself, because the panel
port is frequently unreachable from wherever the operator sits.
"""
import os, json, time, datetime
import core
from core import SSH, q, x, now, today

GB = 1024 ** 3
PROTO_PORTS = ((443, "VLESS-REALITY"), (8443, "Trojan-REALITY"),
               (8080, "VMess"), (8388, "Shadowsocks"))


def shq(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def api(s, method, path, payload=None):
    body = ""
    if payload is not None:
        body = " -H 'Content-Type: application/json' -d " + shq(json.dumps(payload))
    cmd = (
        "cd /opt/marzban-app && "
        "PP=$(grep -oP 'SUDO_PASSWORD=\\K\\S+' .env) && PU=$(grep -oP 'SUDO_USERNAME=\\K\\S+' .env) && "
        "PORT=$(grep -oP 'UVICORN_PORT=\\K\\S+' .env) && "
        "TOK=$(curl -sk -X POST \"https://127.0.0.1:$PORT/api/admin/token\" "
        "-d \"username=$PU&password=$PP\" | python3 -c "
        "'import sys,json;print(json.load(sys.stdin)[\"access_token\"])') && "
        "curl -sk -X " + method + " \"https://127.0.0.1:$PORT" + path + "\" "
        "-H \"Authorization: Bearer $TOK\"" + body)
    out = s.run(cmd, timeout=90)
    try:
        return json.loads(out)
    except Exception:
        return {"_raw": out}


def rebuild_hosts(s, ip):
    """One host row per inbound, pointing here.

    Marzban emits one share link per host row, and silently drops any row whose
    fingerprint is an empty string (its enum lookup raises), which loses the
    VMess and Shadowsocks links entirely. So write the rows explicitly.
    """
    rows = ",".join(
        "('{USERNAME} %s','%s',%d,'%s','inbound_default','none','chrome',0,0)" % (name, ip, port, tag)
        for port, name, tag in ((443, "REALITY", "VLESS_REALITY"), (8443, "Trojan", "TROJAN_REALITY"),
                                (8080, "VMess", "VMESS_TCP"), (8388, "Shadowsocks", "SHADOWSOCKS")))
    sql = ("delete from hosts; insert into hosts "
           "(remark,address,port,inbound_tag,security,alpn,fingerprint,allowinsecure,is_disabled) "
           "values " + rows + ";")
    s.run("sqlite3 /var/lib/marzban/db.sqlite3 " + shq(sql), timeout=60)
    s.run("systemctl restart marzban", timeout=90)
    for _ in range(30):
        time.sleep(2)
        if s.run("curl -sk -o /dev/null -m 5 -w '%{http_code}' https://127.0.0.1:2096/dashboard/").strip() == "200":
            return True
    return False


def install(srv, log, migrate_db=None, identity=None, panel_port=2096):
    """Install or repair the whole service on a foreign box."""
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        log(">> uploading the installer ...")
        s.put(asset_path(), "/tmp/marzban-direct.sh")
        s.run("sed -i 's/\\r$//' /tmp/marzban-direct.sh")
        if migrate_db and os.path.exists(migrate_db):
            s.put(migrate_db, "/tmp/marzban-db.sqlite3")
            log("   bringing the previous accounts with it")
        env = "MIGRATE=%s PANEL_PORT=%s " % ("1" if migrate_db else "0", panel_port)
        if identity and identity.get("reality_priv"):
            env += "CUST_PRIV=%s CUST_PUB=%s CUST_SID=%s " % (
                identity["reality_priv"], identity.get("reality_pub", ""), identity["reality_sid"])
            log("   reusing the REALITY identity, so links already handed out keep working")
        if identity and identity.get("admin_pass"):
            env += "ADMIN_USER=%s ADMIN_PASS=%s " % (
                identity.get("admin_user") or "admin", identity["admin_pass"])
        log(">> installing Marzban + xray (a few minutes on a fresh box) ...")
        rc, out = s.run_rc(env + "bash /tmp/marzban-direct.sh", timeout=2400)
        for ln in out.splitlines():
            t = ln.strip()
            if t and not t.startswith("Warning") and "FLEET_RESULT" not in t:
                log("   " + t[:150])
        res = [l for l in out.splitlines() if l.startswith("FLEET_RESULT=")]
        if rc != 0 or not res:
            raise RuntimeError("the v2ray install did not finish (rc=%s)" % rc)
        params = json.loads(res[-1].split("=", 1)[1])
        log(">> writing the link/host table ...")
        rebuild_hosts(s, srv["ip"])
    return params


def asset_path():
    import sys
    base = os.path.join(getattr(sys, "_MEIPASS", core.APP_DIR), "assets")
    return os.path.join(base, "marzban-direct.sh")


def verify(srv, probe=None):
    checks = []
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        st = s.run("systemctl is-active marzban").strip()
        checks.append(("panel service running", st == "active", st))
        listening = s.run(
            "ss -tln | grep -oE ':(443|8443|8080|8388|2096) ' | tr -d ' :' | sort -un | tr '\\n' ' '").split()
        for port, name in PROTO_PORTS:
            checks.append(("%s listening" % name, str(port) in listening,
                           "yes" if str(port) in listening else "NOT LISTENING"))
        code = s.run("curl -sk -o /dev/null -m 10 -w '%{http_code}' https://127.0.0.1:2096/dashboard/").strip()
        checks.append(("panel answering", code in ("200", "307", "308"), "HTTP " + code))
        out = s.run("curl -s --max-time 20 https://api.ipify.org || echo FAIL", timeout=45).strip()
        checks.append(("server reaches the internet", out == srv["ip"], out or "no answer"))
    if probe:
        checks += probe_from_iran(probe, srv["ip"])
    return checks


def probe_from_iran(probe, target_ip):
    """The only check that decides whether customers can actually use this server.

    A plain TCP reachability test from a box inside Iran: nothing is installed
    there and nothing is changed - it just tries to open each port.
    """
    out = []
    try:
        with SSH(probe["ip"], probe["ssh_user"], probe["auth_method"], probe["secret"]) as p:
            for port, name in PROTO_PORTS:
                r = p.run("timeout 8 bash -c 'true <>/dev/tcp/%s/%d' 2>/dev/null && echo OPEN || echo BLOCKED"
                          % (target_ip, port), timeout=30).strip()
                out.append(("from Iran: %s" % name, r == "OPEN", r))
    except Exception as e:
        out.append(("from Iran", False, "probe server unreachable: %s" % e))
    return out


def pull_users(srv, service_id):
    """Marzban owns the truth for a v2ray service; mirror it locally so quotas,
    expiry and usage survive the server being replaced."""
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        data = api(s, "GET", "/api/users?limit=1000")
    users = data.get("users") if isinstance(data, dict) else None
    if users is None:
        return 0
    names = set()
    for u in users:
        name = u.get("username")
        if not name:
            continue
        names.add(name)
        gb = ((u.get("data_limit") or 0) / GB) or None
        exp = None
        if u.get("expire"):
            try:
                exp = datetime.datetime.fromtimestamp(u["expire"]).date().isoformat()
            except Exception:
                exp = None
        row = q("SELECT id FROM users WHERE service_id=? AND username=?", (service_id, name), one=True)
        vals = (exp, gb, u.get("used_traffic") or 0,
                1 if u.get("status") == "active" else 0, u.get("subscription_url"))
        if row:
            x("UPDATE users SET expire=?,limit_gb=?,used_bytes=?,enabled=?,sub_url=? WHERE id=?",
              vals + (row["id"],))
        else:
            x("INSERT INTO users(service_id,username,password,expire,limit_gb,used_bytes,enabled,created_at,sub_url)"
              " VALUES(?,?,'',?,?,?,?,?,?)",
              (service_id, name, exp, gb, u.get("used_traffic") or 0,
               1 if u.get("status") == "active" else 0, today(), u.get("subscription_url")))
    for row in q("SELECT id, username FROM users WHERE service_id=?", (service_id,)):
        if row["username"] not in names:
            x("DELETE FROM users WHERE id=?", (row["id"],))
    return len(names)


def _service_server(service_id):
    svc = q("SELECT * FROM services WHERE id=?", (service_id,), one=True)
    return svc, q("SELECT * FROM servers WHERE id=?", (svc["foreign_id"],), one=True)


def add_user(service_id, username, gb, days):
    svc, srv = _service_server(service_id)
    expire = int(time.time()) + int(days) * 86400 if int(days or 0) > 0 else 0
    payload = {
        "username": username,
        "proxies": {"vless": {"flow": "xtls-rprx-vision"}, "trojan": {}, "vmess": {}, "shadowsocks": {}},
        "inbounds": {"vless": ["VLESS_REALITY"], "trojan": ["TROJAN_REALITY"],
                     "vmess": ["VMESS_TCP"], "shadowsocks": ["SHADOWSOCKS"]},
        "data_limit": int(float(gb or 0) * GB), "expire": expire, "status": "active",
    }
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        cur = api(s, "GET", "/api/user/" + username)
        if isinstance(cur, dict) and cur.get("username"):
            api(s, "PUT", "/api/user/" + username,
                {k: payload[k] for k in ("proxies", "inbounds", "data_limit", "expire", "status")})
        else:
            api(s, "POST", "/api/user", payload)
    return pull_users(srv, service_id)


def user_action(service_id, username, action):
    svc, srv = _service_server(service_id)
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        if action == "del":
            api(s, "DELETE", "/api/user/" + username)
        elif action == "reset":
            api(s, "POST", "/api/user/%s/reset" % username)
        elif action == "toggle":
            cur = api(s, "GET", "/api/user/" + username)
            api(s, "PUT", "/api/user/" + username,
                {"status": "disabled" if cur.get("status") == "active" else "active"})
    return pull_users(srv, service_id)


def links_for(srv, username):
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        u = api(s, "GET", "/api/user/" + username)
    return (u.get("subscription_url") or ""), (u.get("links") or [])


def fetch_db(srv, dest):
    """Copy the account database off a server so a replacement starts complete."""
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        s.run("sqlite3 /var/lib/marzban/db.sqlite3 \".backup '/tmp/mzb.sqlite3'\"", timeout=180)
        sf = s.c.open_sftp()
        sf.get("/tmp/mzb.sqlite3", dest)
        sf.close()
        s.run("rm -f /tmp/mzb.sqlite3")
    return dest
