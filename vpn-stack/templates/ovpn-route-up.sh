#!/bin/bash
# VPN clients -> tcp2socks(:12345) -> xray socks(:11080) -> fleet tunnel -> exit __EXIT_IP__
DEV=$(ip route show default | awk '{print $5; exit}')
sysctl -w net.ipv4.ip_forward=1 >/dev/null
# shared REDSOCKS chain: skip local/private/exit, redirect the rest of TCP to the forwarder
iptables -t nat -N REDSOCKS 2>/dev/null || iptables -t nat -F REDSOCKS
for n in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 __EXIT_IP__/32 __RELAY_IP__/32; do
  iptables -t nat -A REDSOCKS -d $n -j RETURN
done
iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345
for NET in 10.8.0.0/24 10.10.0.0/24; do
  iptables -C FORWARD -s $NET -j ACCEPT 2>/dev/null || iptables -I FORWARD -s $NET -j ACCEPT
  iptables -C FORWARD -d $NET -j ACCEPT 2>/dev/null || iptables -I FORWARD -d $NET -j ACCEPT
  iptables -t nat -C PREROUTING -s $NET -p tcp -j REDSOCKS 2>/dev/null || iptables -t nat -A PREROUTING -s $NET -p tcp -j REDSOCKS
  iptables -t nat -C POSTROUTING -s $NET -o $DEV -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s $NET -o $DEV -j MASQUERADE
done
# keep forwarder + socks off the public internet
iptables -C INPUT -i $DEV -p tcp --dport 12345 -j DROP 2>/dev/null || iptables -A INPUT -i $DEV -p tcp --dport 12345 -j DROP
iptables -C INPUT -i $DEV -p tcp --dport 11080 -j DROP 2>/dev/null || iptables -A INPUT -i $DEV -p tcp --dport 11080 -j DROP
# force all VPN DNS through the local tunnel-resolver (no Iran DNS leak)
iptables -t nat -C PREROUTING -s 10.8.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.8.0.1 2>/dev/null || iptables -t nat -A PREROUTING -s 10.8.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.8.0.1
iptables -t nat -C PREROUTING -s 10.10.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.10.0.1 2>/dev/null || iptables -t nat -A PREROUTING -s 10.10.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.10.0.1
# clamp MSS to path MTU on the VPN interfaces (avoids large-packet drops)
iptables -t mangle -C POSTROUTING -o tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A POSTROUTING -o tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -C POSTROUTING -o ppp+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A POSTROUTING -o ppp+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
