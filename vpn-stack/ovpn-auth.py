#!/usr/bin/env python3
# OpenVPN auth-user-pass-verify (via-file): validate against the unified user store.
# argv[1] = temp file with "username\npassword". exit 0 = allow, 1 = deny.
import sys, json, datetime, os
USERS = "/opt/ovpnpanel/users.json"
LOG = "/var/log/vpn-auth.log"

def log(msg):
    try:
        open(LOG, "a").write(msg + "\n")
    except Exception:
        pass

def load():
    try:
        return json.load(open(USERS))
    except Exception:
        return {}

def allowed(u, p):
    users = load()
    x = users.get(u)
    if not x:
        return False, "no such user"
    if x.get("password") != p:
        return False, "bad password"
    if not x.get("enabled", True):
        return False, "disabled"
    exp = x.get("expire")
    if exp and str(datetime.date.today()) > exp:
        return False, "expired"
    lim = x.get("limit_gb")
    if lim and float(x.get("used_bytes", 0)) >= float(lim) * (1024**3):
        return False, "quota exceeded"
    return True, "ok"

def main():
    try:
        with open(sys.argv[1]) as f:
            u = f.readline().strip()
            p = f.readline().strip()
    except Exception as e:
        log("read error: %r" % e)
        sys.exit(1)
    ok, why = allowed(u, p)
    log("%s user=%s -> %s (%s)" % (datetime.datetime.now().isoformat(timespec="seconds"), u, "ALLOW" if ok else "DENY", why))
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
