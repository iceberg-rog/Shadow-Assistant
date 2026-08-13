"""Background jobs for v2ray services: build one, and move one to a new server."""
import os, json, threading, datetime
import core, v2ray
from core import q, x, now, today, log_event
import engine
from engine import jset, jreset


def _probe_server():
    """An Iran box flagged as a probe, used only to answer 'is this filtered?'."""
    return q("SELECT * FROM servers WHERE is_probe=1 LIMIT 1", one=True)


def _identity_of(srv):
    if not srv:
        return None
    if srv.get("reality_priv"):
        return {"reality_priv": srv["reality_priv"], "reality_pub": srv.get("reality_pub"),
                "reality_sid": srv["reality_sid"], "admin_user": srv.get("panel_user"),
                "admin_pass": srv.get("panel_pass")}
    return None


def _save_params(server_id, p):
    x("UPDATE servers SET status='installed', panel_port=?, panel_user=?, panel_pass=?,"
      " reality_priv=?, reality_pub=?, reality_sid=?, last_seen=? WHERE id=?",
      (int(p.get("panel_port") or 2096), p.get("admin_user"), p.get("admin_pass"),
       p.get("reality_priv"), p.get("reality_pub"), p.get("reality_sid"), now(), server_id))


def _report(checks):
    ok = all(c[1] for c in checks)
    for label, good, detail in checks:
        jset(line=("   [OK] " if good else "   [!!] ") + label + " -> " + str(detail))
    return ok


def job_build(foreign_id, name, copy_from=None):
    """Stand up a complete v2ray service on a foreign server."""
    def run():
        try:
            jreset()
            srv = q("SELECT * FROM servers WHERE id=?", (foreign_id,), one=True)
            jset(5, "install", ">> building a v2ray service on %s ..." % srv["ip"])

            db_copy = None
            if copy_from:
                src_svc = q("SELECT * FROM services WHERE id=?", (copy_from,), one=True)
                src_srv = q("SELECT * FROM servers WHERE id=?", (src_svc["foreign_id"],), one=True)
                if (src_svc.get("kind") or "vpn") == "v2ray":
                    try:
                        jset(15, "install", ">> copying the accounts off %s ..." % src_srv["ip"])
                        db_copy = v2ray.fetch_db(src_srv, os.path.join(core.APP_DIR, "mz-carry.sqlite3"))
                    except Exception as e:
                        jset(line="   could not read the old server (%s) - starting fresh" % e)

            params = v2ray.install(srv, lambda m: jset(line=m), migrate_db=db_copy,
                                   identity=_identity_of(srv))
            _save_params(foreign_id, params)

            sid = x("INSERT INTO services(name,iran_id,foreign_id,status,created_at,note,kind,panel_url)"
                    " VALUES(?,?,?,'building',?,'direct','v2ray',?)",
                    (name or ("v2ray-%s" % srv["ip"]), foreign_id, foreign_id, now(),
                     "https://%s:%s/dashboard/" % (srv["ip"], params.get("panel_port") or 2096)))

            n = v2ray.pull_users(srv, sid)
            jset(75, "users", ">> %d account(s) on the panel" % n)

            jset(85, "verify", ">> testing (including whether Iran can reach it) ...")
            checks = v2ray.verify(srv, _probe_server())
            ok = _report(checks)
            x("UPDATE services SET status=? WHERE id=?", ("live" if ok else "degraded", sid))
            res = ("v2ray service is LIVE on %s\n"
                   "Panel: https://%s:%s/dashboard/  (%s / %s)\n"
                   "Protocols: VLESS-REALITY 443 | Trojan-REALITY 8443 | VMess 8080 | Shadowsocks 8388\n"
                   "Give customers the subscription link from the Users tab - it carries all four."
                   % (srv["ip"], srv["ip"], params.get("panel_port") or 2096,
                      params.get("admin_user"), params.get("admin_pass"))) if ok \
                else "Installed on %s, but some checks failed - see the log above." % srv["ip"]
            log_event("build", "v2ray service on %s" % srv["ip"])
            jset(100, "done", done=True, running=False, ok=ok, result=res)
        except Exception as e:
            jset(step="error", line="ERROR: %s" % e, done=True, running=False, ok=False,
                 result="Failed: %s" % e)
    threading.Thread(target=run, daemon=True).start()


def job_replace(service_id, new_foreign_id):
    """Move a v2ray service to a new server, accounts and all.

    The REALITY identity and the panel credentials are carried over, so the
    subscription links customers already have keep working - only the address
    changes, and the subscription updates itself in their app.
    """
    def run():
        try:
            jreset()
            svc = q("SELECT * FROM services WHERE id=?", (service_id,), one=True)
            old = q("SELECT * FROM servers WHERE id=?", (svc["foreign_id"],), one=True)
            new = q("SELECT * FROM servers WHERE id=?", (new_foreign_id,), one=True)
            jset(5, "read", ">> moving %s: %s -> %s" % (svc["name"], old["ip"], new["ip"]))

            db_copy = None
            try:
                jset(15, "read", ">> reading the accounts off the old server ...")
                db_copy = v2ray.fetch_db(old, os.path.join(core.APP_DIR, "mz-carry.sqlite3"))
                jset(line="   got the live database")
            except Exception as e:
                jset(line="   old server unreachable (%s) - rebuilding from what is stored here" % e)

            # same identity => the links customers already hold still authenticate
            params = v2ray.install(new, lambda m: jset(line=m), migrate_db=db_copy,
                                   identity=_identity_of(old))
            _save_params(new_foreign_id, params)
            x("UPDATE services SET iran_id=?, foreign_id=?, panel_url=? WHERE id=?",
              (new_foreign_id, new_foreign_id,
               "https://%s:%s/dashboard/" % (new["ip"], params.get("panel_port") or 2096), service_id))

            n = v2ray.pull_users(new, service_id)
            jset(75, "users", ">> %d account(s) moved with their data and days" % n)

            jset(85, "verify", ">> testing the new server (including reachability from Iran) ...")
            checks = v2ray.verify(new, _probe_server())
            ok = _report(checks)
            x("UPDATE services SET status=? WHERE id=?", ("live" if ok else "degraded", service_id))
            log_event("migrate", "v2ray service %s -> %s" % (old["ip"], new["ip"]))
            res = ("Moved to %s with %d account(s).\n"
                   "Panel: https://%s:%s/dashboard/\n"
                   "Hand customers the NEW subscription link from the Users tab."
                   % (new["ip"], n, new["ip"], params.get("panel_port") or 2096)) if ok \
                else "Rebuilt on %s but some checks failed - see the log." % new["ip"]
            jset(100, "done", done=True, running=False, ok=ok, result=res)
        except Exception as e:
            jset(step="error", line="ERROR: %s" % e, done=True, running=False, ok=False,
                 result="Failed: %s" % e)
    threading.Thread(target=run, daemon=True).start()


def job_test(service_id):
    """Re-run the health + Iran-reachability tests on demand."""
    def run():
        try:
            jreset()
            svc = q("SELECT * FROM services WHERE id=?", (service_id,), one=True)
            srv = q("SELECT * FROM servers WHERE id=?", (svc["foreign_id"],), one=True)
            probe = _probe_server()
            jset(20, "verify", ">> testing %s%s ..." % (
                srv["ip"], "" if probe else "  (no Iran probe configured - skipping the filter check)"))
            checks = v2ray.verify(srv, probe)
            ok = _report(checks)
            v2ray.pull_users(srv, service_id)
            x("UPDATE services SET status=? WHERE id=?", ("live" if ok else "degraded", service_id))
            blocked = [c[0] for c in checks if c[0].startswith("from Iran") and not c[1]]
            if blocked and probe:
                res = ("WARNING: Iran cannot reach %s on: %s\nCustomers on those protocols are cut off - "
                       "move the service to a new server." % (srv["ip"], ", ".join(b.split(': ')[-1] for b in blocked)))
            elif ok:
                res = "All good. %s is healthy%s." % (srv["ip"], " and reachable from Iran" if probe else "")
            else:
                res = "Some checks failed - see the log above."
            jset(100, "done", done=True, running=False, ok=ok and not blocked, result=res)
        except Exception as e:
            jset(step="error", line="ERROR: %s" % e, done=True, running=False, ok=False,
                 result="Failed: %s" % e)
    threading.Thread(target=run, daemon=True).start()
