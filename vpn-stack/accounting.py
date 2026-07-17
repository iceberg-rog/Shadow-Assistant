#!/usr/bin/env python3
# Per-user traffic accounting + quota/expiry enforcement for OpenVPN + L2TP.
import json, os, time, socket, datetime, fcntl
USERS="/opt/ovpnpanel/users.json"
OVPN_STATUS="/var/log/openvpn-status.log"
L2TP_MAP="/run/l2tp-map"; CHAP="/etc/ppp/chap-secrets"; GB=1024**3
LAST_FILE="/run/vpn-acct-last.json"
def load_last():
    try: return json.load(open(LAST_FILE))
    except Exception: return {}
def save_last(d):
    try: json.dump(d, open(LAST_FILE,"w"))
    except Exception: pass

def _rmw(fn):
    f=open(USERS,"a+"); fcntl.flock(f,fcntl.LOCK_EX)
    try:
        f.seek(0); s=f.read(); users=json.loads(s) if s.strip() else {}
        fn(users)
        f.seek(0); f.truncate(); f.write(json.dumps(users,indent=2)); f.flush()
        return users
    finally:
        fcntl.flock(f,fcntl.LOCK_UN); f.close()

def sample():
    out={}
    try:
        inblk=False
        for ln in open(OVPN_STATUS).read().splitlines():
            if ln.startswith("Common Name,"): inblk=True; continue
            if ln.startswith("ROUTING TABLE") or ln.startswith("GLOBAL"): inblk=False
            if inblk and "," in ln:
                p=ln.split(",")
                if len(p)>=4 and p[0] and p[0]!="UNDEF":
                    try: out["ovpn:"+p[0]]=(p[0],int(p[2])+int(p[3]))
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
    try:
        s=socket.create_connection(("127.0.0.1",7505),timeout=3)
        s.recv(4096); s.sendall(("kill %s\n"%cn).encode()); time.sleep(0.2); s.recv(4096); s.close()
    except Exception: pass

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
        except Exception:
            pass
        time.sleep(10)

if __name__=="__main__": loop()
