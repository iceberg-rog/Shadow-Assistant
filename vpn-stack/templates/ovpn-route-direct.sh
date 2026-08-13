#!/bin/bash
# DIRECT mode: this box IS the exit. VPN clients egress straight out of its own
# interface - no relay, no tunnel, no tcp2socks. Used when the Iran relays are
# blocked and customers must dial the foreign server itself.
DEV=$(ip route show default | awk '{print $5; exit}')
sysctl -w net.ipv4.ip_forward=1 >/dev/null
for NET in 10.8.0.0/24 10.9.0.0/24 10.10.0.0/24; do
  iptables -C FORWARD -s $NET -j ACCEPT 2>/dev/null || iptables -I FORWARD -s $NET -j ACCEPT
  iptables -C FORWARD -d $NET -j ACCEPT 2>/dev/null || iptables -I FORWARD -d $NET -j ACCEPT
  iptables -t nat -C POSTROUTING -s $NET -o $DEV -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s $NET -o $DEV -j MASQUERADE
done
# clients are pushed the VPN gateway as DNS; dnsmasq answers there and forwards
# to public resolvers over this server's own (unfiltered) connection
iptables -t nat -C PREROUTING -s 10.8.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.8.0.1 2>/dev/null || iptables -t nat -A PREROUTING -s 10.8.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.8.0.1
iptables -t nat -C PREROUTING -s 10.9.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.9.0.1 2>/dev/null || iptables -t nat -A PREROUTING -s 10.9.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.9.0.1
iptables -t nat -C PREROUTING -s 10.10.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.10.0.1 2>/dev/null || iptables -t nat -A PREROUTING -s 10.10.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.10.0.1
# clamp MSS to path MTU on the VPN interfaces (avoids large-packet drops)
iptables -t mangle -C POSTROUTING -o tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A POSTROUTING -o tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -C POSTROUTING -o ppp+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A POSTROUTING -o ppp+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
