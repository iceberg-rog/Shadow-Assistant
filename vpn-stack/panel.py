#!/usr/bin/env python3
import http.server, ssl, subprocess, os, re, json, base64, urllib.parse, html, datetime, fcntl
USER=os.environ.get("PANEL_USER","admin"); PASS=os.environ.get("PANEL_PASS","changeme")
SERVER_IP=os.environ.get("SERVER_IP","YOUR_RELAY_IP")
USERS="/opt/ovpnpanel/users.json"; CHAP="/etc/ppp/chap-secrets"
CA="/etc/openvpn/easy-rsa/pki/ca.crt"; TA="/etc/openvpn/ta.key"
NAME=re.compile(r"^[A-Za-z0-9_-]{1,32}$"); PWOK=re.compile(r"^[A-Za-z0-9_@!.+-]{1,64}$")
GB=1024**3

def _open():
    os.makedirs(os.path.dirname(USERS), exist_ok=True)
    f=open(USERS,"a+"); fcntl.flock(f,fcntl.LOCK_EX); return f
def load_locked(f):
    f.seek(0); s=f.read()
    try: return json.loads(s) if s.strip() else {}
    except Exception: return {}
def save_locked(f,d):
    f.seek(0); f.truncate(); f.write(json.dumps(d,indent=2)); f.flush()
def load():
    try: return json.load(open(USERS))
    except Exception: return {}

def sync_chap(users):
    # L2TP chap-secrets = enabled, non-expired, under-quota users
    today=str(datetime.date.today())
    with open(CHAP,"w") as f:
        f.write("# client\tserver\tsecret\tIP\n")
        for u,x in users.items():
            if not x.get("enabled",True): continue
            if x.get("expire") and today>x["expire"]: continue
            if x.get("limit_gb") and float(x.get("used_bytes",0))>=float(x["limit_gb"])*GB: continue
            f.write(u+"\t*\t"+x.get("password","")+"\t*\n")
    os.chmod(CHAP,0o600)

def get_psk():
    try:
        for line in open("/etc/ipsec.secrets"):
            m=re.search(r'PSK\s+"([^"]+)"',line)
            if m: return m.group(1)
    except Exception: pass
    return "?"
def svc(n):
    try: return subprocess.run(["systemctl","is-active",n],capture_output=True,text=True).stdout.strip()
    except Exception: return "?"
def fmt(b):
    b=float(b)
    for u in ("B","KB","MB","GB","TB"):
        if b<1024: return ("%.1f %s"%(b,u)) if u!="B" else ("%d B"%b)
        b/=1024
    return "%.1f PB"%b
def days_left(exp):
    if not exp: return "∞"
    try:
        d=(datetime.date.fromisoformat(exp)-datetime.date.today()).days
        return str(d)+"d" if d>=0 else "expired"
    except Exception: return "?"

def ovpn_template():
    try: ca=open(CA).read(); ta=open(TA).read()
    except Exception: return None
    return ("client\ndev tun\nproto tcp\nremote "+SERVER_IP+" 1194\nnobind\n"
            "auth-user-pass\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\n"
            "redirect-gateway def1\ndhcp-option DNS 1.1.1.1\ndhcp-option DNS 8.8.8.8\nverb 3\n"
            "<ca>\n"+ca+"</ca>\n<tls-crypt>\n"+ta+"</tls-crypt>\n")

class H(http.server.BaseHTTPRequestHandler):
    def ok_auth(self):
        h=self.headers.get("Authorization","")
        if h.startswith("Basic "):
            try:
                u,p=base64.b64decode(h[6:]).decode().split(":",1)
                if u==USER and p==PASS: return True
            except Exception: pass
        self.send_response(401); self.send_header("WWW-Authenticate",'Basic realm="vpn"'); self.end_headers(); return False
    def do_GET(self):
        if not self.ok_auth(): return
        u=urllib.parse.urlparse(self.path)
        if u.path=="/ovpn":
            t=ovpn_template()
            if t is None: self.send_response(500); self.end_headers(); return
            b=t.encode(); self.send_response(200)
            self.send_header("Content-Type","application/x-openvpn-profile")
            self.send_header("Content-Disposition",'attachment; filename="fleet-ovpn.ovpn"')
            self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b); return
        self.page()
    def do_POST(self):
        if not self.ok_auth(): return
        ln=int(self.headers.get("Content-Length",0)); q=urllib.parse.parse_qs(self.rfile.read(ln).decode())
        path=urllib.parse.urlparse(self.path).path
        n=q.get("name",[""])[0]
        f=_open()
        try:
            users=load_locked(f)
            if path=="/user-add" and NAME.match(n):
                pwd=q.get("password",[""])[0]
                days=q.get("days",["0"])[0]; gb=q.get("gb",["0"])[0]
                if PWOK.match(pwd):
                    try: days=int(days)
                    except Exception: days=0
                    try: gb=float(gb)
                    except Exception: gb=0
                    exp=str(datetime.date.today()+datetime.timedelta(days=days)) if days>0 else None
                    ex=users.get(n,{})
                    users[n]={"password":pwd,"expire":exp,"limit_gb":(gb if gb>0 else None),
                              "used_bytes":ex.get("used_bytes",0),"enabled":True,
                              "created":ex.get("created",str(datetime.date.today()))}
            elif path=="/user-del" and n in users:
                del users[n]
            elif path=="/user-toggle" and n in users:
                users[n]["enabled"]=not users[n].get("enabled",True)
            elif path=="/user-reset" and n in users:
                users[n]["used_bytes"]=0
            save_locked(f,users); sync_chap(users)
        finally:
            fcntl.flock(f,fcntl.LOCK_UN); f.close()
        self.send_response(303); self.send_header("Location","/"); self.end_headers()
    def page(self):
        users=load(); rows=""
        for u in sorted(users):
            x=users[u]
            used=float(x.get("used_bytes",0)); lim=x.get("limit_gb")
            pct=(min(100,int(used/(lim*GB)*100)) if lim else 0)
            usage=fmt(used)+(" / "+("%g GB"%lim) if lim else " / ∞")
            bar=("<div style='background:#eee;border-radius:4px;height:6px;width:120px;display:inline-block;vertical-align:middle'><div style='height:6px;border-radius:4px;width:"+str(pct)+"%;background:"+("#c0392b" if pct>=90 else "#2563eb")+"'></div></div>") if lim else ""
            en=x.get("enabled",True)
            today=str(datetime.date.today()); expd=x.get("expire")
            live = en and not (expd and today>expd) and not (lim and used>=lim*GB)
            stt='<b style="color:#27ae60">active</b>' if live else '<b style="color:#c0392b">off</b>'
            def form(action,label,confirm=None):
                on=(' onsubmit="return confirm(&quot;'+label+' '+u+'?&quot;)"') if confirm else ''
                return '<form method=post action=/'+action+' style=display:inline'+on+'><input type=hidden name=name value="'+u+'"><button>'+label+'</button></form>'
            rows+=("<tr><td>"+html.escape(u)+"</td><td><code>"+html.escape(x.get("password",""))+"</code></td>"
                   "<td>"+days_left(expd)+"</td><td>"+usage+" "+bar+"</td><td>"+stt+"</td>"
                   "<td>"+form("user-toggle","toggle")+" "+form("user-reset","reset")+" "+form("user-del","delete",1)+"</td></tr>")
        stat=("openvpn="+svc("openvpn-server@server")+" &middot; xray-ovpn="+svc("xray-ovpn")+" &middot; tcp2socks="+svc("tcp2socks")+
              " &middot; ipsec="+(svc("strongswan-starter") or svc("strongswan"))+" &middot; xl2tpd="+svc("xl2tpd")+" &middot; accounting="+svc("vpn-accounting"))
        body=("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Fleet VPN Panel</title>"
        "<style>body{font-family:system-ui,Segoe UI,Arial;max-width:960px;margin:1.5rem auto;padding:0 1rem;color:#111}"
        "table{width:100%;border-collapse:collapse;margin:.5rem 0 1.4rem;font-size:14px}td,th{padding:.5rem;border-bottom:1px solid #e5e5e5;text-align:left}"
        "button{cursor:pointer;padding:.25rem .6rem;font-size:13px}input{padding:.4rem;margin:2px}a{color:#2563eb;text-decoration:none}"
        "code{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px}h3{margin-top:1.4rem;border-bottom:2px solid #111;padding-bottom:.2rem}"
        ".box{background:#f7f7f7;padding:.6rem 1rem;border-radius:6px;margin:.4rem 0}</style>"
        "<h2>Fleet VPN Panel &mdash; relay 85</h2>"
        "<p style=color:#666;font-size:13px>services: "+stat+"<br>egress = 46.62 (foreign) &middot; one account works on BOTH OpenVPN and L2TP</p>"
        "<h3>Users</h3>"
        "<form method=post action=/user-add class=box>"
        "<input name=name placeholder='username' pattern='[A-Za-z0-9_-]{1,32}' required> "
        "<input name=password placeholder='password' required> "
        "<input name=days type=number min=0 placeholder='days (0=∞)' style=width:110px> "
        "<input name=gb type=number min=0 step=0.5 placeholder='GB (0=∞)' style=width:110px> "
        "<button>+ Add user</button></form>"
        "<table><tr><th>username</th><th>password</th><th>expires</th><th>data used</th><th>status</th><th>actions</th></tr>"+rows+"</table>"
        "<h3>How clients connect</h3>"
        "<div class=box><b>OpenVPN:</b> download <a href=/ovpn>fleet-ovpn.ovpn</a> (same file for everyone) &rarr; import in any OpenVPN app &rarr; it asks for <b>username + password</b> from the table above.</div>"
        "<div class=box><b>L2TP/IPsec:</b> Server <code>"+SERVER_IP+"</code> &middot; Pre-shared key <code>"+html.escape(get_psk())+"</code> &middot; username + password from the table.</div>")
        b=body.encode()
        self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass

httpd=http.server.ThreadingHTTPServer(("0.0.0.0",int(os.environ.get("PANEL_PORT","2098"))),H)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/opt/ovpnpanel/cert.pem","/opt/ovpnpanel/key.pem")
httpd.socket=ctx.wrap_socket(httpd.socket,server_side=True); httpd.serve_forever()
