#!/bin/bash
# Lean foreign EXIT: just the relay->exit REALITY tunnel-in (:9443) -> freedom egress.
# No Marzban (this exit is only for the OpenVPN/L2TP egress path).
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
XC=/usr/local/etc/xray-tunnel
echo ">> apt + xray"
apt-get update -y >/dev/null 2>&1
apt-get install -y curl unzip openssl >/dev/null 2>&1 || { echo APTFAIL; exit 1; }
mkdir -p "$XC"
if ! /usr/local/bin/xray version 2>/dev/null | grep -q 26.3.27; then
  cd /tmp; curl -fsSL -o xray.zip https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip || { echo XRAYDL; exit 1; }
  rm -rf /tmp/xr; mkdir -p /tmp/xr; python3 -m zipfile -e xray.zip /tmp/xr/; install -m755 /tmp/xr/xray /usr/local/bin/xray; rm -rf xray.zip /tmp/xr
fi
/usr/local/bin/xray version | head -1
echo ">> tunnel keys"
KP="$(/usr/local/bin/xray x25519 2>/dev/null)"
TUN_PRIV=$(echo "$KP" | grep -i 'private' | grep -oE '[A-Za-z0-9_/+-]{42,44}' | head -1)
TUN_PUB=$(echo "$KP"  | grep -iv 'private' | grep -oE '[A-Za-z0-9_/+-]{42,44}' | head -1)
[ -n "$TUN_PRIV" ] && [ -n "$TUN_PUB" ] || { echo "KEYGEN FAIL"; exit 1; }
TUN_UUID="$(/usr/local/bin/xray uuid)"
TUN_SID="$(openssl rand -hex 8)"
echo ">> tunnel.json (:9443 REALITY -> freedom)"
cat > "$XC/tunnel.json" <<EOF
{ "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "tunnel-in", "listen": "0.0.0.0", "port": 9443, "protocol": "vless",
      "settings": { "clients": [ { "id": "${TUN_UUID}" } ], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "reality",
        "realitySettings": { "show": false, "dest": "www.cloudflare.com:443", "xver": 0, "serverNames": ["www.cloudflare.com"],
          "privateKey": "${TUN_PRIV}", "shortIds": ["${TUN_SID}"] } } }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ] }
EOF
/usr/local/bin/xray -test -c "$XC/tunnel.json" >/dev/null 2>&1 || { echo "TUNNEL CFG INVALID"; exit 1; }
modprobe tcp_bbr 2>/dev/null || true
printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' > /etc/sysctl.d/99-bbr.conf; sysctl --system >/dev/null 2>&1 || true
cat > /etc/systemd/system/xray-tunnel.service <<EOF
[Unit]
Description=xray tunnel-in (relay -> exit)
After=network.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/xray run -c $XC/tunnel.json
Restart=always
RestartSec=5
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now xray-tunnel >/dev/null 2>&1
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then ufw allow 9443/tcp >/dev/null 2>&1 || true; fi
sleep 2
echo "RESULT tunnel=$(systemctl is-active xray-tunnel) listening=$(ss -tln 2>/dev/null | grep -c :9443)"
echo "FLEET_RESULT={\"tun_uuid\":\"${TUN_UUID}\",\"tun_pub\":\"${TUN_PUB}\",\"tun_sid\":\"${TUN_SID}\"}"
