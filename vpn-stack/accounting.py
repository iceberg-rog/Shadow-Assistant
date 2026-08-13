#!/usr/bin/env python3
# Per-user traffic accounting + quota/expiry enforcement for OpenVPN + L2TP.
import json, os, time, socket, datetime, fcntl, glob
USERS="/opt/ovpnpanel/users.json"
# One status log per OpenVPN instance (1194 and the 443 disguise instance). Quota
# and device counts must span ALL of them, or a user simply switches port to get
# unmetered traffic.
def status_logs():
    return sorted(glob.glob("/var/log/openvpn-status*.log")) or ["/var/log/openvpn-status.log"]
MGMT_PORTS=(7505, 7506)
OVPN_STATUS="/var/log/openvpn-status.log"
L2TP_MAP="/run/l2tp-map"; CHAP="/etc/ppp/chap-secrets"; GB=1024**3
LAST_FILE="/run/vpn-acct-last.json"
def load_last():
    try: return json.load(open(LAST_FILE))
    except Exception: return {}
def save_last(d):
    try: json.dump(d, open(LAST_FILE,"w"))
    except Exception: pass

def keep_readable():
    # OpenVPN's auth script runs as "nobody"; the store must stay group-readable
    # or every login fails with "external program exited with error status: 1".
    try:
        import grp
        os.chown(USERS, 0, grp.getgrnam("nogroup").gr_gid)
    except Exception: pass
    try: os.chmod(USERS, 0o640)
    except Exception: pass

def _rmw(fn):
    f=open(USERS,"a+"); fcntl.flock(f,fcntl.LOCK_EX)
    try:
        f.seek(0); s=f.read(); users=json.loads(s) if s.strip() else {}
        fn(users)
        f.seek(0); f.truncate(); f.write(json.dumps(users,indent=2)); f.flush()
        keep_readable()
        return users
    finally:
        fcntl.flock(f,fcntl.LOCK_UN); f.close()

def sample():
    out={}
    for path in status_logs():
        tag=os.path.basename(path)          # keeps 1194 and 443 sessions distinct
        try:
            inblk=False
            for ln in open(path).read().splitlines():
                if ln.startswith("CLIENT_LIST,"):
                    # OpenVPN 2.4+ machine format: CLIENT_LIST,CN,Real,Virtual,Virtual6,BytesRecv,BytesSent,...
                    p=ln.split(",")
                    if len(p)>=7 and p[1] and p[1]!="UNDEF":
                        # one row per connection, not per user: a user on two devices
                        # has two rows and both must be counted
                        try: out["ovpn:"+tag+":"+p[1]+":"+p[2]]=(p[1], int(p[5])+int(p[6]))
                        except Exception: pass
                elif ln.startswith("Common Name,"):
                    inblk=True
                elif ln.startswith("ROUTING TABLE") or ln.startswith("GLOBAL"):
                    inblk=False
                elif inblk and "," in ln:
                    # legacy v1 format: CN,Real,BytesRecv,BytesSent,Since
                    p=ln.split(",")
                    if len(p)>=4 and p[0] and p[0]!="UNDEF":
                        try: out["ovpn:"+tag+":"+p[0]+":"+p[1]]=(p[0], int(p[2])+int(p[3]))
                        except Exception: pass
        except Exception: pass
    try:
        for iface in os.listdir(L2TP_MAP):
            try:
                user=open(os.path.join(L2TP_MAP,iface)).read().strip()
                rx=int(open("/sys/class/net/%s/statistics/rx_bytes"%iface).read())
                tx=int(open("/sys/class/net/%s/statistics/tx_bytes"%iface).read())
                out["l2tp:"+iface]=(user,rx+tx)
            except Exception: pass
    except Exception: pass
    return out

def over_quota(users):
    today=str(datetime.date.today()); over=[]
    for u,x in users.items():
        exp=x.get("expire"); lim=x.get("limit_gb")
        if (not x.get("enabled",True)) or (exp and today>exp) or (lim and float(x.get("used_bytes",0))>=float(lim)*GB):
            over.append(u)
    return over

def sync_chap(users):
    today=str(datetime.date.today())
    try:
        with open(CHAP,"w") as f:
            f.write("# client\tserver\tsecret\tIP\n")
            for u,x in users.items():
                if not x.get("enabled",True): continue
                if x.get("expire") and today>x["expire"]: continue
                if x.get("limit_gb") and float(x.get("used_bytes",0))>=float(x["limit_gb"])*GB: continue
                f.write(u+"\t*\t"+x.get("password","")+"\t*\n")
        os.chmod(CHAP,0o600)
    except Exception: pass

def ovpn_kill(cn):
    # the same account can be on either instance, so ask both to drop it
    for port in MGMT_PORTS:
        try:
            s=socket.create_connection(("127.0.0.1",port),timeout=3)
            s.recv(4096); s.sendall(("kill %s\n"%cn).encode()); time.sleep(0.2); s.recv(4096); s.close()
        except Exception: pass

def ovpn_conns():
    """CN -> list of (real_addr, connected_since_epoch), one entry per live
    connection ACROSS every instance - the device cap counts 1194 and 443 together."""
    conns={}
    for path in status_logs():
        try:
            for ln in open(path).read().splitlines():
                if ln.startswith("CLIENT_LIST,"):
                    p=ln.split(",")
                    if len(p)>=9 and p[1] and p[1]!="UNDEF":
                        try: since=int(p[8])
                        except Exception: since=0
                        conns.setdefault(p[1],[]).append((p[2], since))
        except Exception: pass
    return conns

def enforce_maxconn(users):
    """Per-user simultaneous-connection cap. Keep the oldest max_conn sessions,
    kick the newer excess (a user can't exceed their device count)."""
    for u,lst in ovpn_conns().items():
        mc=users.get(u,{}).get("max_conn")
        try: mc=int(mc)
        except Exception: mc=0
        if mc and len(lst)>mc:
            for addr,_ in sorted(lst, key=lambda x: x[1])[mc:]:   # newest excess
                ovpn_kill(addr)   # management: "kill <IP:port>" drops that one session

def l2tp_kill(over):
    try:
        for iface in os.listdir(L2TP_MAP):
            try:
                if open(os.path.join(L2TP_MAP,iface)).read().strip() in over:
                    os.system("ip link set %s down 2>/dev/null"%iface)
            except Exception: pass
    except Exception: pass

def loop():
    last=load_last()
    while True:
        try:
            cur=sample(); deltas={}
            for key,(user,tot) in cur.items():
                prev=last.get(key)
                d=tot if prev is None else (tot-prev if tot>=prev else tot)  # first sight counts full; sessions start at 0
                last[key]=tot
                if d>0: deltas[user]=deltas.get(user,0)+d
            for key in list(last):
                if key not in cur: del last[key]
            save_last(last)
            if deltas:
                users=_rmw(lambda U: [U[u].__setitem__("used_bytes", float(U[u].get("used_bytes",0))+d) for u,d in deltas.items() if u in U])
            else:
                users=json.load(open(USERS)) if os.path.exists(USERS) else {}
            over=over_quota(users); sync_chap(users)
            if over:
                for cn in over: ovpn_kill(cn)
                l2tp_kill(set(over))
            enforce_maxconn(users)   # per-user simultaneous-connection cap
        except Exception:
            pass
        time.sleep(10)

if __name__=="__main__": loop()
