#!/usr/bin/env python3
import socket, struct, threading, select, traceback
SO_ORIGINAL_DST=80
SOCKS=("127.0.0.1",11080); LISTEN=("0.0.0.0",12345)
def log(m):
    try:
        open("/tmp/tcp2socks.log","a").write(m+"\n")
    except: pass
def orig_dst(conn):
    d=conn.getsockopt(socket.SOL_IP,SO_ORIGINAL_DST,16)
    return socket.inet_ntoa(d[4:8]), struct.unpack("!H",d[2:4])[0]
def socks_connect(ip,port):
    s=socket.create_connection(SOCKS,timeout=10)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2)!=b"\x05\x00": s.close(); return None
    s.sendall(b"\x05\x01\x00\x01"+socket.inet_aton(ip)+struct.pack("!H",port))
    rep=s.recv(10)
    if len(rep)<2 or rep[1]!=0: s.close(); return None
    return s
def pipe(a,b):
    try:
        while True:
            r,_,_=select.select([a,b],[],[],120)
            if not r: break
            for s in r:
                try: data=s.recv(65536)
                except OSError: return
                if not data: return
                (b if s is a else a).sendall(data)
    finally:
        for x in (a,b):
            try: x.close()
            except: pass
def handle(conn,peer):
    up=None
    try:
        ip,port=orig_dst(conn)
        log(f"conn from {peer} orig_dst={ip}:{port}")
        up=socks_connect(ip,port)
        if up is None: log(f"  socks FAIL for {ip}:{port}"); conn.close(); return
        log(f"  socks OK -> {ip}:{port}")
        pipe(conn,up)
    except Exception as e:
        log("  ERR "+repr(e)); 
        try: conn.close()
        except: pass
srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
srv.bind(LISTEN); srv.listen(256)
log("tcp2socks started on "+str(LISTEN))
while True:
    c,a=srv.accept()
    threading.Thread(target=handle,args=(c,a),daemon=True).start()
