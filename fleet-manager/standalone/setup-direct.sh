#!/bin/bash
# =====================================================================
#  setup-direct.sh - turn a fresh foreign server into a ready VPN service
#  in one command. No Iran relay: customers dial THIS box and exit here.
#
#  Usage (as root, on the new server):
#      bash setup-direct.sh
#
#  It prints every access detail at the end (panel URL + login, OpenVPN
#  address, L2TP PSK) and writes them to /root/vpn-access.txt as well.
# =====================================================================
set -uo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "Run this as root."; exit 1; }
[ -f vpn-stack/install.sh ] || { echo "vpn-stack/ folder is missing next to this script."; exit 1; }

IP="${PUBLIC_IP:-$(curl -s --max-time 15 https://api.ipify.org)}"
[ -n "$IP" ] || IP="$(hostname -I | awk '{print $1}')"
[ -n "$IP" ] || { echo "Could not work out this server's public IP. Re-run as: PUBLIC_IP=1.2.3.4 bash setup-direct.sh"; exit 1; }
echo ">> setting up a direct VPN service on $IP"

sed -i 's/\r$//' vpn-stack/* vpn-stack/templates/* 2>/dev/null || true
DIRECT=1 RELAY_IP="$IP" PANEL_USER="${PANEL_USER:-admin}" bash vpn-stack/install.sh
rc=$?
[ $rc -eq 0 ] || { echo "install failed (rc=$rc)"; exit $rc; }

PU=$(grep -oP 'PANEL_USER=\K\S+' /etc/systemd/system/ovpn-panel.service)
PP=$(grep -oP 'PANEL_PASS=\K\S+' /etc/systemd/system/ovpn-panel.service)
PSK=$(grep -oP 'PSK "\K[^"]+' /etc/ipsec.secrets 2>/dev/null)

cat > /root/vpn-access.txt <<EOF
================ VPN SERVER ACCESS ================
Panel     : https://$IP:2098/
  user    : $PU
  password: $PP
OpenVPN   : $IP  port 1194 (TCP)   - user/pass from the panel
L2TP/IPsec: $IP  PSK: $PSK
Client IP : $IP  (this is what customers appear as)

The .ovpn everyone shares: download it from the panel
  curl -sk -u '$PU:$PP' https://$IP:2098/ovpn -o client.ovpn
===================================================
EOF
chmod 600 /root/vpn-access.txt
echo
cat /root/vpn-access.txt
echo ">> also saved to /root/vpn-access.txt"
echo ">> add this server in Fleet Manager (Servers tab) to manage users from Windows"
