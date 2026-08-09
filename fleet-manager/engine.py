"""Fleet Manager engine: build servers, wire services, migrate, verify.

Jobs run in a background thread and stream progress (percent + log lines) so
the UI can show a live bar. Everything is idempotent: re-running against an
existing box repairs it instead of duplicating work.
"""
import os, sys, json, re, time, threading, datetime, base64
import core
from core import SSH, q, x, log_event, now, today, tcp_open

APP_DIR = core.APP_DIR
ASSETS = os.path.join(getattr(sys, "_MEIPASS", APP_DIR), "assets")
GB = 1024 ** 3

JOB = {"running": False, "percent": 0, "step": "", "log": [], "done": False,
       "ok": False, "result": ""}
_JLOCK = threading.Lock()

# Serialises "read the server's list" against "write a change".  Without it the
# background sync can run between the local insert and the push of a new account
# and delete it as 'not on the server yet' - losing the account silently.
STATE_LOCK = threading.RLock()


def jset(pct=None, step=None, line=None, **kw):
    with _JLOCK:
        if pct is not None:
            JOB["percent"] = pct
        if step is not None:
            JOB["step"] = step
        if line:
            JOB["log"].append(line)
            if len(JOB["log"]) > 400:
                del JOB["log"][:100]
        JOB.update(kw)


def jreset():
    with _JLOCK:
        JOB.update(running=True, percent=0, step="starting", log=[], done=False, ok=False, result="")


def jsnapshot():
    with _JLOCK:
        return dict(JOB, log=list(JOB["log"]))


# ------------------------------------------------------------------ assets
def asset(*p):
    return os.path.join(ASSETS, *p)


VPN_FILES = ["install.sh", "accounting.py", "dns2socks.py", "ovpn-auth.py", "panel.py", "tcp2socks.py"]
VPN_TPL = ["config-ovpn.json", "ipsec.conf", "openvpn-server.conf", "options.xl2tpd",
           "ovpn-route-up.sh", "xl2tpd.conf"]


# ------------------------------------------------------- foreign exit build
def build_foreign(srv):
    """Install the REALITY tunnel receiver (:9443 -> freedom) on a foreign box.
    Returns tunnel params; reuses existing ones if already installed."""
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        existing = s.run("cat /usr/local/etc/xray-tunnel/tunnel.json 2>/dev/null || true")
        if existing.strip().startswith("{") and "tunnel-in" in existing:
            jset(line=">> foreign: tunnel already present, reusing its keys")
            cfg = json.loads(existing)
            ib = cfg["inbounds"][0]
            rs = ib["streamSettings"]["realitySettings"]
            priv = rs["privateKey"]
            pub = _derive_pub(s, priv)
            params = {"tun_uuid": ib["settings"]["clients"][0]["id"],
                      "tun_pub": pub, "tun_sid": rs["shortIds"][0]}
            s.run("systemctl restart xray-tunnel 2>/dev/null || true")
        else:
            jset(line=">> foreign: installing xray + REALITY tunnel receiver ...")
            s.put(asset("foreign-tunnel.sh"), "/tmp/foreign-tunnel.sh")
            s.run("sed -i 's/\\r$//' /tmp/foreign-tunnel.sh")
            rc, out = s.run_rc("bash /tmp/foreign-tunnel.sh", timeout=900)
            for ln in out.splitlines():
                if ln.strip():
                    jset(line="   " + ln.strip())
            m = [l for l in out.splitlines() if l.startswith("FLEET_RESULT=")]
            if rc != 0 or not m:
                raise RuntimeError("foreign tunnel build failed (rc=%s)" % rc)
            params = json.loads(m[-1].split("=", 1)[1])
        act = s.run("systemctl is-active xray-tunnel")
        listening = s.run("ss -tln | grep -c ':9443 ' || true")
        if act != "active" or listening.strip() in ("", "0"):
            raise RuntimeError("tunnel service not healthy on the foreign server")
    return params


def _derive_pub(s, priv):
    out = s.run("/usr/local/bin/xray x25519 -i %s 2>/dev/null" % priv)
    cands = [t for t in re.findall(r"[A-Za-z0-9_/+-]{42,44}", out) if t != priv]
    return cands[0] if cands else ""


# --------------------------------------------------------- iran relay build
def build_iran(srv, exit_ip, params, panel_user="admin", panel_pass=None, panel_port=2098):
    """Install OpenVPN + L2TP + panel on the Iran box, egressing through the tunnel."""
    panel_pass = panel_pass or base64.b64encode(os.urandom(9)).decode().replace("/", "").replace("+", "")[:12]
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        jset(line=">> iran: checking prerequisites ...")
        if "yes" not in s.run("[ -c /dev/net/tun ] && echo yes || echo no"):
            raise RuntimeError("/dev/net/tun missing on the Iran server (need KVM, not OpenVZ)")
        # xray is required by install.sh (it validates config-ovpn.json with it)
        if "26.3.27" not in s.run("/usr/local/bin/xray version 2>/dev/null || true"):
            jset(line=">> iran: installing xray-core ...")
            s.run("apt-get update -y >/dev/null 2>&1; apt-get install -y curl unzip >/dev/null 2>&1", timeout=600)
            rc, out = s.run_rc(
                "cd /tmp && curl -fsSL -o xray.zip "
                "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip && "
                "rm -rf /tmp/xr && mkdir -p /tmp/xr && python3 -m zipfile -e xray.zip /tmp/xr/ && "
                "install -m755 /tmp/xr/xray /usr/local/bin/xray && rm -rf xray.zip /tmp/xr && "
                "/usr/local/bin/xray version | head -1", timeout=900)
            jset(line="   " + out.strip().splitlines()[-1] if out.strip() else "   xray installed")
            if rc != 0:
                raise RuntimeError("xray install failed on the Iran server")

        jset(line=">> iran: uploading VPN stack ...")
        s.run("mkdir -p /root/vpn-stack/templates")
        for f in VPN_FILES:
            s.put(asset("vpn-stack", f), "/root/vpn-stack/" + f)
        for f in VPN_TPL:
            s.put(asset("vpn-stack", "templates", f), "/root/vpn-stack/templates/" + f)
        s.run("sed -i 's/\\r$//' /root/vpn-stack/* /root/vpn-stack/templates/* 2>/dev/null; true")

        jset(line=">> iran: installing OpenVPN + L2TP + panel (this takes a minute) ...")
        env = ("RELAY_IP=%s EXIT_IP=%s TUN_UUID=%s TUN_PUB=%s TUN_SID=%s "
               "PANEL_USER=%s PANEL_PASS=%s PANEL_PORT=%s " % (
                   srv["ip"], exit_ip, params["tun_uuid"], params["tun_pub"], params["tun_sid"],
                   panel_user, panel_pass, panel_port))
        rc, out = s.run_rc(env + "bash /root/vpn-stack/install.sh", timeout=1800)
        for ln in out.splitlines():
            if ln.strip() and not ln.startswith("Warning"):
                jset(line="   " + ln.strip()[:160])
        if rc != 0:
            raise RuntimeError("VPN stack install failed (rc=%s)" % rc)
        psk = ""
        m = re.search(r'PSK:\s*(\S+)', out)
        if m:
            psk = m.group(1)
        else:
            psk = _read_psk(s)
    return {"panel_user": panel_user, "panel_pass": panel_pass, "panel_port": panel_port, "l2tp_psk": psk}


def _read_psk(s):
    txt = s.run("cat /etc/ipsec.secrets 2>/dev/null || true")
    m = re.search(r'PSK\s+"([^"]+)"', txt)
    return m.group(1) if m else ""


def repoint_iran(srv, exit_ip, params):
    """Point an EXISTING Iran box at a new foreign exit. Users/usage untouched."""
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        script = r'''python3 - "%s" "%s" "%s" "%s" <<'PY'
import json,sys,glob
ip,uuid,pub,sid = sys.argv[1:5]
changed=[]
for p in glob.glob("/usr/local/etc/xray/*.json"):
    try: c=json.load(open(p))
    except Exception: continue
    hit=False
    for ob in c.get("outbounds",[]):
        if ob.get("tag")=="tunnel":
            v=ob["settings"]["vnext"][0]; v["address"]=ip; v["port"]=9443
            v["users"][0]["id"]=uuid
            rs=ob["streamSettings"]["realitySettings"]; rs["publicKey"]=pub; rs["shortId"]=sid
            hit=True
    if hit:
        json.dump(c,open(p,"w"),indent=2); changed.append(p)
print("REPOINTED:"+",".join(changed))
PY''' % (exit_ip, params["tun_uuid"], params["tun_pub"], params["tun_sid"])
        out = s.run(script, timeout=120)
        jset(line="   " + out.strip())
        for cfg in ["/usr/local/etc/xray/config-ovpn.json", "/usr/local/etc/xray/config.json",
                    "/usr/local/etc/xray/config-alt.json"]:
            chk = s.run('[ -f %s ] && /usr/local/bin/xray -test -c %s >/dev/null 2>&1 && echo OK || echo skip' % (cfg, cfg))
            if chk.strip() == "OK":
                jset(line="   config valid: " + os.path.basename(cfg))
        s.run("systemctl restart xray-ovpn xray-relay xray-relay-alt 2>/dev/null; "
              "[ -f /usr/local/sbin/ovpn-route-up.sh ] && bash /usr/local/sbin/ovpn-route-up.sh >/dev/null 2>&1; true",
              timeout=120)
    return True


# ------------------------------------------------------------ user syncing
def push_users(srv, service_id):
    """Write the DB's users (with used_bytes + expiry + device cap) onto the Iran
    box, so a rebuilt/replaced server keeps every account exactly as it was."""
    users = q("SELECT * FROM users WHERE service_id=?", (service_id,))
    blob = {}
    for u in users:
        blob[u["username"]] = {
            "password": u["password"],
            "expire": u["expire"],
            "limit_gb": u["limit_gb"],
            "max_conn": u["max_conn"],
            "used_bytes": float(u["used_bytes"] or 0),
            "enabled": bool(u["enabled"]),
            "created": u["created_at"] or today(),
        }
    with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
        s.run("mkdir -p /opt/ovpnpanel")
        s.put_text(json.dumps(blob, indent=2), "/opt/ovpnpanel/users.json", mode=0o640)
        # OpenVPN's auth script runs as "nobody" after the privilege drop, so the
        # store must be group-readable or every login fails (AUTH_FAILED).
        s.run("chgrp nogroup /opt/ovpnpanel/users.json 2>/dev/null; chmod 640 /opt/ovpnpanel/users.json; "
              "chmod 755 /opt/ovpnpanel; "
              "rm -f /run/vpn-acct-last.json; systemctl restart vpn-accounting ovpn-panel 2>/dev/null; true")
    return len(blob)


def pull_users(srv, service_id, log_usage=True):
    """Read the server's account list back into the DB.

    The SERVER is the source of truth: two people running this app on two PCs
    each have their own fleet.db, so the only way they agree is by both syncing
    from the box. That means accounts added/removed/changed anywhere show up
    everywhere without anyone pressing refresh.
    """
    try:
        with SSH(srv["ip"], srv["ssh_user"], srv["auth_method"], srv["secret"]) as s:
            raw = s.get_text("/opt/ovpnpanel/users.json")
            live = s.run("grep -c '^CLIENT_LIST,' /var/log/openvpn-status.log 2>/dev/null || echo 0")
    except Exception:
        return 0, 0
    try:
        blob = json.loads(raw)
    except Exception:
        return 0, 0
    with STATE_LOCK:
        return _apply_pull(blob, live, service_id, log_usage)


def _apply_pull(blob, live, service_id, log_usage):
    # accounts deleted on the server (or by the other operator) must disappear here too
    for row in q("SELECT id, username FROM users WHERE service_id=?", (service_id,)):
        if row["username"] not in blob:
            x("DELETE FROM users WHERE id=?", (row["id"],))
    n = 0
    for name, d in blob.items():
        row = q("SELECT id FROM users WHERE service_id=? AND username=?", (service_id, name), one=True)
        if row:
            x("UPDATE users SET used_bytes=?, expire=?, limit_gb=?, max_conn=?, enabled=?, password=? WHERE id=?",
              (float(d.get("used_bytes", 0)), d.get("expire"), d.get("limit_gb"),
               d.get("max_conn"), 1 if d.get("enabled", True) else 0, d.get("password"), row["id"]))
        else:
            x("INSERT INTO users(service_id,username,password,expire,limit_gb,max_conn,used_bytes,enabled,created_at)"
              " VALUES(?,?,?,?,?,?,?,?,?)",
              (service_id, name, d.get("password"), d.get("expire"), d.get("limit_gb"),
               d.get("max_conn"), float(d.get("used_bytes", 0)), 1 if d.get("enabled", True) else 0,
               d.get("created", today())))
        n += 1
    try:
        live_n = int(live.strip() or 0)
    except Exception:
        live_n = 0
    if log_usage:
        # only for the periodic snapshot - the fast sync must not flood the graph
        total = sum(float(d.get("used_bytes", 0)) for d in blob.values())
        x("INSERT INTO usage_log(ts,service_id,total_bytes,user_count,live_conns) VALUES(?,?,?,?,?)",
          (now(), service_id, total, len(blob), live_n))
    else:
        x("UPDATE services SET note=? WHERE id=?", ("live:%d" % live_n, service_id))
    return n, live_n


# ---------------------------------------------------------------- verify
def verify_service(iran, foreign):
    """Prove the whole chain works: tunnel port, socks egress == foreign IP,
    OpenVPN listening, panel answering, accounting alive."""
    checks = []
    with SSH(iran["ip"], iran["ssh_user"], iran["auth_method"], iran["secret"]) as s:
        t = s.run("timeout 6 bash -c 'true <>/dev/tcp/%s/9443' 2>/dev/null && echo YES || echo NO" % foreign["ip"])
        checks.append(("tunnel reachable (%s:9443)" % foreign["ip"], t.strip() == "YES", t.strip()))

        egress = s.run("curl -s --max-time 25 --socks5-hostname 127.0.0.1:11080 https://api.ipify.org || echo FAIL",
                       timeout=45).strip()
        checks.append(("egress goes through the foreign exit", egress == foreign["ip"], egress or "no answer"))

        ov = s.run("ss -tln | grep -c ':1194 ' || true").strip()
        checks.append(("OpenVPN listening on 1194", ov not in ("", "0"), "yes" if ov not in ("", "0") else "no"))

        pport = iran.get("panel_port") or 2098
        code = s.run("curl -sk -o /dev/null -m 10 -w '%%{http_code}' https://127.0.0.1:%s/" % pport).strip()
        checks.append(("panel answering on %s" % pport, code in ("200", "401"), "HTTP " + code))

        acct = s.run("systemctl is-active vpn-accounting").strip()
        checks.append(("accounting/quota daemon", acct == "active", acct))

        dns = s.run("systemctl is-active dns2socks").strip()
        checks.append(("DNS-through-tunnel", dns == "active", dns))
    return checks


# ------------------------------------------------------------------- jobs
def job_new_service(iran_id, foreign_id, name, panel_user, panel_pass, migrate_from=None,
                    migrate_usernames=None):
    def run():
        try:
            jreset()
            iran = q("SELECT * FROM servers WHERE id=?", (iran_id,), one=True)
            fgn = q("SELECT * FROM servers WHERE id=?", (foreign_id,), one=True)
            jset(6, "foreign", ">> building foreign exit %s ..." % fgn["ip"])
            params = build_foreign(fgn)
            x("UPDATE servers SET tun_uuid=?,tun_pub=?,tun_sid=?,status='installed',last_seen=? WHERE id=?",
              (params["tun_uuid"], params["tun_pub"], params["tun_sid"], now(), foreign_id))
            jset(35, "iran", ">> building Iran relay %s ..." % iran["ip"])
            pinfo = build_iran(iran, fgn["ip"], params, panel_user, panel_pass)
            x("UPDATE servers SET status='installed',panel_port=?,panel_user=?,panel_pass=?,l2tp_psk=?,last_seen=? WHERE id=?",
              (pinfo["panel_port"], pinfo["panel_user"], pinfo["panel_pass"], pinfo["l2tp_psk"], now(), iran_id))
            sid = x("INSERT INTO services(name,iran_id,foreign_id,status,created_at) VALUES(?,?,?,'building',?)",
                    (name or ("service-%s" % iran["ip"]), iran_id, foreign_id, now()))

            if migrate_from:
                jset(72, "users", ">> copying accounts (with used data + days) ...")
                copied = copy_users(migrate_from, sid, migrate_usernames)
                jset(line="   copied %d accounts" % copied)
            iran = q("SELECT * FROM servers WHERE id=?", (iran_id,), one=True)
            n = push_users(iran, sid)
            jset(80, "users", ">> pushed %d accounts to the panel" % n)

            jset(88, "verify", ">> verifying the whole chain ...")
            checks = verify_service(iran, fgn)
            ok = all(c[1] for c in checks)
            for label, good, detail in checks:
                jset(line=("   [OK] " if good else "   [!!] ") + label + " -> " + str(detail))
            x("UPDATE services SET status=? WHERE id=?", ("live" if ok else "degraded", sid))
            pull_users(iran, sid)
            panel = "https://%s:%s/" % (iran["ip"], pinfo["panel_port"])
            res = ("Service is LIVE.\nPanel: %s  (%s / %s)\nOpenVPN: %s:1194 (user/pass from the panel)\n"
                   "L2TP PSK: %s\nEgress: %s (foreign)" % (
                       panel, pinfo["panel_user"], pinfo["panel_pass"], iran["ip"], pinfo["l2tp_psk"], fgn["ip"])) \
                if ok else "Installed, but some checks failed - see the log above."
            log_event("service", "new service %s -> %s (%s)" % (iran["ip"], fgn["ip"], "live" if ok else "degraded"))
            jset(100, "done", done=True, running=False, ok=ok, result=res)
        except Exception as e:
            log_event("error", str(e))
            jset(step="error", line="!! " + str(e), done=True, running=False, ok=False, result=str(e))
    threading.Thread(target=run, daemon=True).start()


def copy_users(src_service_id, dst_service_id, usernames=None):
    rows = q("SELECT * FROM users WHERE service_id=?", (src_service_id,))
    n = 0
    for u in rows:
        if usernames and u["username"] not in usernames:
            continue
        exists = q("SELECT id FROM users WHERE service_id=? AND username=?",
                   (dst_service_id, u["username"]), one=True)
        if exists:
            x("UPDATE users SET password=?,expire=?,limit_gb=?,max_conn=?,used_bytes=?,enabled=? WHERE id=?",
              (u["password"], u["expire"], u["limit_gb"], u["max_conn"], u["used_bytes"], u["enabled"], exists["id"]))
        else:
            x("INSERT INTO users(service_id,username,password,expire,limit_gb,max_conn,used_bytes,enabled,created_at)"
              " VALUES(?,?,?,?,?,?,?,?,?)",
              (dst_service_id, u["username"], u["password"], u["expire"], u["limit_gb"], u["max_conn"],
               u["used_bytes"], u["enabled"], u["created_at"]))
        n += 1
    return n


def job_replace_foreign(service_id, new_foreign_id):
    """Swap ONLY the foreign exit. Iran box, users, usage and days stay put."""
    def run():
        try:
            jreset()
            svc = q("SELECT * FROM services WHERE id=?", (service_id,), one=True)
            iran = q("SELECT * FROM servers WHERE id=?", (svc["iran_id"],), one=True)
            fgn = q("SELECT * FROM servers WHERE id=?", (new_foreign_id,), one=True)
            jset(10, "foreign", ">> building new foreign exit %s ..." % fgn["ip"])
            params = build_foreign(fgn)
            x("UPDATE servers SET tun_uuid=?,tun_pub=?,tun_sid=?,status='installed',last_seen=? WHERE id=?",
              (params["tun_uuid"], params["tun_pub"], params["tun_sid"], now(), new_foreign_id))
            jset(55, "repoint", ">> pointing the Iran relay at the new exit (users untouched) ...")
            repoint_iran(iran, fgn["ip"], params)
            x("UPDATE services SET foreign_id=? WHERE id=?", (new_foreign_id, service_id))
            jset(80, "verify", ">> verifying ...")
            checks = verify_service(iran, fgn)
            ok = all(c[1] for c in checks)
            for label, good, detail in checks:
                jset(line=("   [OK] " if good else "   [!!] ") + label + " -> " + str(detail))
            pull_users(iran, service_id)
            x("UPDATE services SET status=? WHERE id=?", ("live" if ok else "degraded", service_id))
            log_event("migrate", "foreign swapped to %s" % fgn["ip"])
            jset(100, "done", done=True, running=False, ok=ok,
                 result=("Exit swapped to %s. All accounts kept their data + days." % fgn["ip"]) if ok
                        else "Swapped, but some checks failed - see log.")
        except Exception as e:
            log_event("error", str(e))
            jset(step="error", line="!! " + str(e), done=True, running=False, ok=False, result=str(e))
    threading.Thread(target=run, daemon=True).start()


def job_replace_iran(service_id, new_iran_id, usernames=None):
    """Swap the Iran box. The new one is built from scratch and every selected
    account is restored WITH its used data and remaining days."""
    def run():
        try:
            jreset()
            svc = q("SELECT * FROM services WHERE id=?", (service_id,), one=True)
            old_iran = q("SELECT * FROM servers WHERE id=?", (svc["iran_id"],), one=True)
            fgn = q("SELECT * FROM servers WHERE id=?", (svc["foreign_id"],), one=True)
            new_iran = q("SELECT * FROM servers WHERE id=?", (new_iran_id,), one=True)

            jset(8, "users", ">> saving the latest usage from the old Iran server (if reachable) ...")
            try:
                n, _ = pull_users(old_iran, service_id)
                jset(line="   captured %d accounts with current usage" % n)
            except Exception:
                jset(line="   old server unreachable - using the last saved state from the local DB")

            params = {"tun_uuid": fgn["tun_uuid"], "tun_pub": fgn["tun_pub"], "tun_sid": fgn["tun_sid"]}
            if not params["tun_uuid"]:
                jset(20, "foreign", ">> foreign tunnel params unknown, reading them from %s ..." % fgn["ip"])
                params = build_foreign(fgn)
                x("UPDATE servers SET tun_uuid=?,tun_pub=?,tun_sid=? WHERE id=?",
                  (params["tun_uuid"], params["tun_pub"], params["tun_sid"], fgn["id"]))

            jset(30, "iran", ">> building the new Iran relay %s ..." % new_iran["ip"])
            pinfo = build_iran(new_iran, fgn["ip"], params,
                               old_iran.get("panel_user") or "admin", old_iran.get("panel_pass"))
            x("UPDATE servers SET status='installed',panel_port=?,panel_user=?,panel_pass=?,l2tp_psk=?,last_seen=? WHERE id=?",
              (pinfo["panel_port"], pinfo["panel_user"], pinfo["panel_pass"], pinfo["l2tp_psk"], now(), new_iran_id))

            if usernames is not None:
                keep = set(usernames)
                for u in q("SELECT username FROM users WHERE service_id=?", (service_id,)):
                    if u["username"] not in keep:
                        x("UPDATE users SET enabled=0 WHERE service_id=? AND username=?",
                          (service_id, u["username"]))
            jset(70, "users", ">> restoring accounts with their used data + remaining days ...")
            new_iran = q("SELECT * FROM servers WHERE id=?", (new_iran_id,), one=True)
            n = push_users(new_iran, service_id)
            jset(line="   restored %d accounts" % n)

            x("UPDATE services SET iran_id=? WHERE id=?", (new_iran_id, service_id))
            jset(88, "verify", ">> verifying ...")
            checks = verify_service(new_iran, fgn)
            ok = all(c[1] for c in checks)
            for label, good, detail in checks:
                jset(line=("   [OK] " if good else "   [!!] ") + label + " -> " + str(detail))
            x("UPDATE services SET status=? WHERE id=?", ("live" if ok else "degraded", service_id))
            log_event("migrate", "iran swapped to %s" % new_iran["ip"])
            jset(100, "done", done=True, running=False, ok=ok,
                 result=("New Iran server %s is live with %d accounts (data + days preserved).\n"
                         "Panel: https://%s:%s/  (%s / %s)\n"
                         "IMPORTANT: give clients the new address %s - the old one is gone."
                         % (new_iran["ip"], n, new_iran["ip"], pinfo["panel_port"],
                            pinfo["panel_user"], pinfo["panel_pass"], new_iran["ip"])) if ok
                        else "Built, but some checks failed - see log.")
        except Exception as e:
            log_event("error", str(e))
            jset(step="error", line="!! " + str(e), done=True, running=False, ok=False, result=str(e))
    threading.Thread(target=run, daemon=True).start()


def job_adopt(service_id=None, iran_id=None, foreign_id=None, name=None):
    """Import an ALREADY-RUNNING pair into the app: read its users + tunnel params
    instead of reinstalling. Used when a service existed before the app did."""
    def run():
        try:
            jreset()
            iran = q("SELECT * FROM servers WHERE id=?", (iran_id,), one=True)
            fgn = q("SELECT * FROM servers WHERE id=?", (foreign_id,), one=True)
            jset(15, "read", ">> reading the foreign exit's tunnel parameters ...")
            params = build_foreign(fgn)
            x("UPDATE servers SET tun_uuid=?,tun_pub=?,tun_sid=?,status='installed' WHERE id=?",
              (params["tun_uuid"], params["tun_pub"], params["tun_sid"], foreign_id))
            jset(40, "read", ">> reading the panel + accounts from the Iran server ...")
            with SSH(iran["ip"], iran["ssh_user"], iran["auth_method"], iran["secret"]) as s:
                unit = s.run("cat /etc/systemd/system/ovpn-panel.service 2>/dev/null || true")
                pu = re.search(r"PANEL_USER=(\S+)", unit)
                pp = re.search(r"PANEL_PASS=(\S+)", unit)
                pt = re.search(r"PANEL_PORT=(\S+)", unit)
                psk = _read_psk(s)
            x("UPDATE servers SET status='installed',panel_user=?,panel_pass=?,panel_port=?,l2tp_psk=? WHERE id=?",
              (pu.group(1) if pu else "admin", pp.group(1) if pp else "", int(pt.group(1)) if pt else 2098,
               psk, iran_id))
            sid = service_id or x("INSERT INTO services(name,iran_id,foreign_id,status,created_at)"
                                  " VALUES(?,?,?,'live',?)",
                                  (name or ("adopted-%s" % iran["ip"]), iran_id, foreign_id, now()))
            iran = q("SELECT * FROM servers WHERE id=?", (iran_id,), one=True)
            n, live = pull_users(iran, sid)
            jset(70, "users", ">> imported %d accounts (with their usage)" % n)
            jset(85, "verify", ">> verifying ...")
            checks = verify_service(iran, fgn)
            ok = all(c[1] for c in checks)
            for label, good, detail in checks:
                jset(line=("   [OK] " if good else "   [!!] ") + label + " -> " + str(detail))
            x("UPDATE services SET status=? WHERE id=?", ("live" if ok else "degraded", sid))
            log_event("adopt", "adopted %s + %s (%d users)" % (iran["ip"], fgn["ip"], n))
            jset(100, "done", done=True, running=False, ok=ok,
                 result="Imported the existing service with %d accounts. You can now swap either server safely." % n)
        except Exception as e:
            log_event("error", str(e))
            jset(step="error", line="!! " + str(e), done=True, running=False, ok=False, result=str(e))
    threading.Thread(target=run, daemon=True).start()


# ------------------------------------------------------------ user actions
def add_user(service_id, username, password, days, gb, conns):
    exp = str(datetime.date.today() + datetime.timedelta(days=int(days))) if int(days or 0) > 0 else None
    with STATE_LOCK:   # hold off the background sync until this is on the server
        row = q("SELECT id FROM users WHERE service_id=? AND username=?", (service_id, username), one=True)
        if row:
            x("UPDATE users SET password=?,expire=?,limit_gb=?,max_conn=?,enabled=1 WHERE id=?",
              (password, exp, float(gb) if float(gb or 0) > 0 else None,
               int(conns) if int(conns or 0) > 0 else None, row["id"]))
        else:
            x("INSERT INTO users(service_id,username,password,expire,limit_gb,max_conn,used_bytes,enabled,created_at)"
              " VALUES(?,?,?,?,?,?,0,1,?)",
              (service_id, username, password, exp, float(gb) if float(gb or 0) > 0 else None,
               int(conns) if int(conns or 0) > 0 else None, today()))
        svc = q("SELECT * FROM services WHERE id=?", (service_id,), one=True)
        iran = q("SELECT * FROM servers WHERE id=?", (svc["iran_id"],), one=True)
        return push_users(iran, service_id)


def refresh_service(service_id):
    """Pull live usage from the Iran box into the DB (also feeds the graphs)."""
    svc = q("SELECT * FROM services WHERE id=?", (service_id,), one=True)
    if not svc:
        return 0, 0
    iran = q("SELECT * FROM servers WHERE id=?", (svc["iran_id"],), one=True)
    return pull_users(iran, service_id)
