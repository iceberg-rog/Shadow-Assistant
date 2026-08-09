"""Fleet Manager core: local SQLite state, SSH helpers, server role detection.

Everything the app knows lives in fleet.db next to the exe:
  servers   - every box we manage (role iran/foreign, creds, tunnel params)
  services  - an (iran, foreign) pair that forms one working VPN service
  users     - VPN accounts WITH their used bytes + expiry + device cap
  usage_log - periodic snapshots so the dashboard can draw graphs over time
The DB is the source of truth, so a server can be replaced and every account
comes back with its consumed data and remaining days intact.
"""
import os, sys, json, time, sqlite3, threading, datetime, io, socket

try:
    import paramiko
except Exception:
    paramiko = None

APP_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
DB_PATH = os.path.join(APP_DIR, "fleet.db")
KEY_PATH = os.path.join(APP_DIR, "fleet_key")
_LOCK = threading.Lock()


# ---------------------------------------------------------------- database
def db():
    c = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _LOCK, db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS servers(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ip TEXT UNIQUE NOT NULL,
          ssh_user TEXT DEFAULT 'root',
          auth_method TEXT DEFAULT 'password',   -- password | key
          secret TEXT,                            -- password (key auth uses fleet_key)
          role TEXT,                              -- iran | foreign
          label TEXT, country TEXT, city TEXT, isp TEXT,
          status TEXT DEFAULT 'new',              -- new | ready | installed | dead
          tun_uuid TEXT, tun_pub TEXT, tun_sid TEXT,   -- foreign: tunnel params it serves
          panel_port INTEGER, panel_user TEXT, panel_pass TEXT, l2tp_psk TEXT,
          added_at TEXT, last_seen TEXT, note TEXT
        );
        CREATE TABLE IF NOT EXISTS services(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT,
          iran_id INTEGER, foreign_id INTEGER,
          status TEXT DEFAULT 'building',         -- building | live | degraded
          created_at TEXT, note TEXT
        );
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          service_id INTEGER,
          username TEXT NOT NULL,
          password TEXT,
          expire TEXT,                            -- YYYY-MM-DD or NULL = never
          limit_gb REAL,                          -- NULL = unlimited
          max_conn INTEGER,                       -- NULL = unlimited devices
          used_bytes REAL DEFAULT 0,
          enabled INTEGER DEFAULT 1,
          created_at TEXT,
          UNIQUE(service_id, username)
        );
        CREATE TABLE IF NOT EXISTS usage_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT, service_id INTEGER,
          total_bytes REAL, user_count INTEGER, live_conns INTEGER
        );
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT, kind TEXT, msg TEXT
        );
        """)


def log_event(kind, msg):
    try:
        with _LOCK, db() as c:
            c.execute("INSERT INTO events(ts,kind,msg) VALUES(?,?,?)",
                      (datetime.datetime.now().isoformat(timespec="seconds"), kind, msg))
    except Exception:
        pass


def q(sql, args=(), one=False):
    with _LOCK, db() as c:
        cur = c.execute(sql, args)
        rows = [dict(r) for r in cur.fetchall()]
    return (rows[0] if rows else None) if one else rows


def x(sql, args=()):
    with _LOCK, db() as c:
        cur = c.execute(sql, args)
        return cur.lastrowid


# ---------------------------------------------------------------- ssh key
def ensure_key():
    """The app's own ed25519 key. Users paste the .pub on a server, then we
    connect with no password at all."""
    if not os.path.exists(KEY_PATH):
        k = paramiko.Ed25519Key.generate() if hasattr(paramiko.Ed25519Key, "generate") else None
        if k is None:
            # paramiko without generate(): shell out to ssh-keygen
            os.system('ssh-keygen -t ed25519 -N "" -C fleet-manager -f "%s" >nul 2>&1' % KEY_PATH)
        else:
            k.write_private_key_file(KEY_PATH)
            with open(KEY_PATH + ".pub", "w") as f:
                f.write("ssh-ed25519 %s fleet-manager\n" % k.get_base64())
    try:
        return open(KEY_PATH + ".pub").read().strip()
    except Exception:
        return ""


def fleet_pubkey():
    if not os.path.exists(KEY_PATH + ".pub"):
        ensure_key()
    try:
        return open(KEY_PATH + ".pub").read().strip()
    except Exception:
        return ""


def key_install_command():
    pub = fleet_pubkey()
    return ('mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "%s" >> ~/.ssh/authorized_keys '
            '&& chmod 600 ~/.ssh/authorized_keys' % pub)


# ---------------------------------------------------------------- ssh
class SSH:
    def __init__(self, ip, user="root", method="password", secret=""):
        self.ip, self.user, self.method, self.secret = ip, user or "root", method, secret or ""
        self.c = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *a):
        self.close()

    def connect(self, timeout=20):
        if paramiko is None:
            raise RuntimeError("paramiko missing")
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if self.method == "key":
            ensure_key()
            pk = paramiko.Ed25519Key.from_private_key_file(KEY_PATH)
            c.connect(self.ip, username=self.user, pkey=pk, timeout=timeout,
                      look_for_keys=False, allow_agent=False)
        else:
            c.connect(self.ip, username=self.user, password=self.secret, timeout=timeout,
                      look_for_keys=False, allow_agent=False)
        self.c = c
        return c

    def run(self, cmd, timeout=120):
        i, o, e = self.c.exec_command(cmd, timeout=timeout)
        out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
        return out.strip()

    def run_rc(self, cmd, timeout=600):
        ch = self.c.get_transport().open_session()
        ch.settimeout(timeout)
        ch.exec_command(cmd + " 2>&1")
        buf = ""
        while True:
            if ch.recv_ready():
                buf += ch.recv(65536).decode("utf-8", "replace")
            elif ch.exit_status_ready():
                while ch.recv_ready():
                    buf += ch.recv(65536).decode("utf-8", "replace")
                break
            else:
                time.sleep(0.2)
        return ch.recv_exit_status(), buf

    def put(self, local, remote):
        sf = self.c.open_sftp()
        try:
            sf.put(local, remote)
        finally:
            sf.close()

    def put_text(self, text, remote, mode=None):
        sf = self.c.open_sftp()
        try:
            with sf.open(remote, "w") as f:
                f.write(text)
            if mode:
                sf.chmod(remote, mode)
        finally:
            sf.close()

    def get_text(self, remote):
        sf = self.c.open_sftp()
        try:
            with sf.open(remote, "r") as f:
                return f.read().decode("utf-8", "replace")
        finally:
            sf.close()

    def close(self):
        try:
            self.c.close()
        except Exception:
            pass


def tcp_open(ip, port, timeout=6):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


# ------------------------------------------------- probe / role detection
IRAN_MARKERS = ["digikala.com", "aparat.com", "irancell.ir"]


def probe(ip, user, method, secret):
    """Connect and work out what this box is: reachable? root? tun? Iran or abroad?
    Returns a dict the UI can show verbatim."""
    r = {"ok": False, "msg": "", "role": None, "detail": {}}
    try:
        with SSH(ip, user, method, secret) as s:
            who = s.run("id -u; echo ---; . /etc/os-release 2>/dev/null; echo $PRETTY_NAME")
            parts = who.split("---")
            is_root = parts[0].strip().startswith("0")
            osname = parts[1].strip() if len(parts) > 1 else "?"
            tun = "yes" in s.run("[ -c /dev/net/tun ] && echo yes || echo no")
            pub_ip = s.run("curl -s --max-time 10 https://api.ipify.org || echo ?", timeout=25)
            geo = s.run("curl -s --max-time 12 'http://ip-api.com/line?fields=country,countryCode,city,isp' || true",
                        timeout=25).splitlines()
            country = geo[0].strip() if len(geo) > 0 else ""
            ccode = geo[1].strip() if len(geo) > 1 else ""
            city = geo[2].strip() if len(geo) > 2 else ""
            isp = geo[3].strip() if len(geo) > 3 else ""

            # Role detection. Geo is authoritative when we get it: a box that
            # reports a country is exactly where it says it is. Only when geo is
            # blocked (a common inside-Iran signature, since ip-api is filtered
            # there) do we fall back on "can it reach Iran-only services fast".
            # NOTE: reaching digikala fast does NOT mean Iran - foreign boxes
            # often reach it fine too, so this must never override a known geo.
            if ccode:
                role = "iran" if ccode == "IR" else "foreign"
                ir_hits = -1  # not needed
            else:
                ir_hits = 0
                for host in IRAN_MARKERS:
                    t = s.run("curl -s -o /dev/null -m 8 -w '%%{time_total}' https://%s || echo 9" % host, timeout=20)
                    try:
                        if float(t.strip().splitlines()[-1]) < 0.5:
                            ir_hits += 1
                    except Exception:
                        pass
                # geo blocked + Iranian sites answer quickly => almost certainly inside Iran
                role = "iran" if ir_hits >= 1 else "foreign"

            r.update(ok=True, role=role, detail={
                "os": osname, "root": is_root, "tun": tun, "public_ip": pub_ip.strip(),
                "country": country or ("Iran?" if role == "iran" else "?"),
                "city": city, "isp": isp, "iran_markers_fast": ir_hits,
            })
            how = ("geo says %s" % ccode) if ccode else ("geo blocked, Iran-only sites reachable" if ir_hits >= 1
                                                         else "geo blocked, no Iran signature")
            r["msg"] = "%s reachable as %s%s, %s%s. Detected: %s [%s]" % (
                ip, user, "" if is_root else " (non-root)", osname,
                "" if tun else ", WARNING /dev/net/tun missing",
                "IRAN server" if role == "iran" else "FOREIGN server (%s %s)" % (country or "?", city or ""),
                how)
    except Exception as e:
        name = type(e).__name__
        if "Authentication" in name:
            r["msg"] = ("Login refused. If this server only takes SSH keys, choose 'Fleet key' "
                        "and add this line on the server:\n" + key_install_command())
        elif "timed out" in str(e).lower() or "Timeout" in name:
            r["msg"] = "Cannot reach %s:22 (timed out). Server off, or SSH on another port/blocked." % ip
        else:
            r["msg"] = "Connection failed: %s: %s" % (name, e)
    return r


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def today():
    return str(datetime.date.today())
