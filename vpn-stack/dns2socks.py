#!/usr/bin/env python3
# Local UDP DNS resolver that forwards every query as DNS-over-TCP through the
# fleet SOCKS (xray :11080) -> tunnel -> foreign exit -> upstream resolver.
# This makes VPN clients' DNS resolve ABROAD (un-poisoned), fixing Iran's
# 10.10.34.x sinkhole. dnsmasq forwards to this on 127.0.0.1:5300.
import socket, struct, threading
SOCKS=("127.0.0.1",11080); UPSTREAM=("1.1.1.1",53); LISTEN=("127.0.0.1",5300)

def via_socks(q):
    s=socket.create_connection(SOCKS,timeout=6)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2)!=b"\x05\x00": return None
        s.sendall(b"\x05\x01\x00\x01"+socket.inet_aton(UPSTREAM[0])+struct.pack("!H",UPSTREAM[1]))
        r=s.recv(10)
        if len(r)<2 or r[1]!=0: return None
        s.sendall(struct.pack("!H",len(q))+q)          # DNS-over-TCP: 2-byte length prefix
        hdr=b""
        while len(hdr)<2:
            c=s.recv(2-len(hdr))
            if not c: return None
            hdr+=c
        n=struct.unpack("!H",hdr)[0]; resp=b""
        while len(resp)<n:
            c=s.recv(n-len(resp))
            if not c: break
            resp+=c
        return resp
    finally:
        s.close()

srv=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
srv.bind(LISTEN)

def handle(data,addr):
    try:
        r=via_socks(data)
        if r: srv.sendto(r,addr)
    except Exception:
        pass

while True:
    try:
        data,addr=srv.recvfrom(4096)
        threading.Thread(target=handle,args=(data,addr),daemon=True).start()
    except Exception:
        pass
