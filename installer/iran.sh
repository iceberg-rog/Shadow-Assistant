# === IRAN role: domestic relay -> foreign exit, over an encrypted REALITY tunnel ===
# Inherits exported env: SERVER_IP, ROLE, EXIT_IP, and the exit's tunnel params
# TUN_UUID, TUN_PUB, TUN_SID (the dashboard reads these from the foreign exit's result).
#
# Clients connect to THIS fast domestic IP on the customer ports (443/8080/8443/8388).
# A dokodemo-door grabs each connection and ships it to the exit inside a VLESS+REALITY
# tunnel (exit :9443). To Iran's DPI the Iran->exit hop is just TLS to Cloudflare, so
# EVERY customer protocol (incl. VMess/Shadowsocks) passes. The exit unwraps the tunnel
# and hands traffic to its local Marzban inbounds.
#
# Requires the foreign exit to be installed FIRST (EXIT_IP + TUN_* must be set).

XRAY_VER="24.12.31"   # PINNED: must match the exit's tunnel receiver for REALITY

echo ">> iran relay installer starting on $SERVER_IP -> exit $EXIT_IP"
[ -z "${EXIT_IP:-}" ]  && { echo "EXIT_IP is empty - install the foreign exit first, then set its IP."; exit 1; }
[ -z "${TUN_UUID:-}" ] && { echo "TUN_UUID missing - re-provision the foreign exit (it generates the tunnel params)."; exit 1; }
[ -z "${TUN_PUB:-}" ]  && { echo "TUN_PUB missing - re-provision the foreign exit."; exit 1; }
[ -z "${TUN_SID:-}" ]  && { echo "TUN_SID missing - re-provision the foreign exit."; exit 1; }

export DEBIAN_FRONTEND=noninteractive

# --- 1) install xray-core (pinned, must match the exit's tunnel receiver) ---
if ! /usr/local/bin/xray version 2>/dev/null | grep -q "$XRAY_VER"; then
  apt-get update -qq && apt-get install -y -qq unzip curl openssl >/dev/null 2>&1 || apt-get install -y unzip curl openssl
  arch=$(uname -m); Z=Xray-linux-64.zip; [ "$arch" = "aarch64" ] && Z=Xray-linux-arm64-v8a.zip
  mkdir -p /usr/local/bin /usr/local/etc/xray
  curl -fsSL --connect-timeout 15 --max-time 180 --retry 3 --retry-delay 3 \
    -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VER}/$Z" \
    || { echo "ERROR: failed to download xray ${XRAY_VER} (network/geo-block) - aborting."; exit 1; }
  unzip -tq /tmp/xray.zip >/dev/null 2>&1 || { echo "ERROR: xray.zip corrupt/incomplete - aborting."; exit 1; }
  unzip -o /tmp/xray.zip xray -d /usr/local/bin/ >/dev/null
  chmod +x /usr/local/bin/xray
fi
/usr/local/bin/xray version | head -1

# --- 2) relay config: dokodemo capture (per port) -> single REALITY tunnel to the exit ---
# Each dokodemo sets the destination to 127.0.0.1:<port>; the tunnel carries that to the
# exit, where freedom dials 127.0.0.1:<port> (the matching Marzban inbound on the exit).
mkdir -p /usr/local/etc/xray
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "in-443",  "listen": "0.0.0.0", "port": 443,  "protocol": "dokodemo-door", "settings": { "address": "127.0.0.1", "port": 443,  "network": "tcp" } },
    { "tag": "in-8080", "listen": "0.0.0.0", "port": 8080, "protocol": "dokodemo-door", "settings": { "address": "127.0.0.1", "port": 8080, "network": "tcp" } },
    { "tag": "in-8443", "listen": "0.0.0.0", "port": 8443, "protocol": "dokodemo-door", "settings": { "address": "127.0.0.1", "port": 8443, "network": "tcp" } },
    { "tag": "in-8388", "listen": "0.0.0.0", "port": 8388, "protocol": "dokodemo-door", "settings": { "address": "127.0.0.1", "port": 8388, "network": "tcp,udp" } }
  ],
  "outbounds": [
    {
      "tag": "tunnel", "protocol": "vless",
      "settings": { "vnext": [ { "address": "${EXIT_IP}", "port": 9443, "users": [ { "id": "${TUN_UUID}", "encryption": "none" } ] } ] },
      "streamSettings": {
        "network": "tcp", "security": "reality",
        "realitySettings": { "serverName": "www.cloudflare.com", "fingerprint": "chrome", "publicKey": "${TUN_PUB}", "shortId": "${TUN_SID}" }
      }
    },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": { "rules": [ { "type": "field", "inboundTag": ["in-443","in-8080","in-8443","in-8388"], "outboundTag": "tunnel" } ] }
}
EOF

# --- 3) systemd service ---
cat > /etc/systemd/system/xray-relay.service <<'EOF'
[Unit]
Description=Xray Iran Relay (encrypted REALITY tunnel to exit)
After=network.target
[Service]
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray-relay >/dev/null 2>&1
systemctl restart xray-relay
sleep 2
echo "relay service: $(systemctl is-active xray-relay)"

# --- 4) firewall: customer ports (clients connect to the relay here) ---
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
  for p in 443 8080 8443 8388; do ufw allow ${p}/tcp >/dev/null 2>&1 || true; done
fi

# --- 5) verify: listening + the tunnel actually reaches the exit's REALITY server ---
ss -tlnp | grep -q ':443 ' && echo "relay listening on :443" || { echo "ERROR: relay not listening on :443"; exit 1; }

# A TLS handshake to the relay's :443 travels through the tunnel to the exit's REALITY
# inbound, which fronts its 'dest' (cloudflare) for unauthenticated TLS -> returns a
# certificate. Getting one proves the full client->relay->[tunnel]->exit path works.
if echo | openssl s_client -connect 127.0.0.1:443 -servername www.cloudflare.com 2>/dev/null | grep -q 'BEGIN CERTIFICATE'; then
  echo "tunnel to exit OK (TLS handshake reached the exit's REALITY server through the tunnel)"
  FWD="ok"
else
  echo "WARN: could not confirm the tunnel to ${EXIT_IP}:9443 (check the exit's xray-tunnel + firewall)"
  FWD="unconfirmed"
fi

echo "FLEET_RESULT={\"role\":\"iran-relay\",\"relay_ip\":\"${SERVER_IP}\",\"exit_ip\":\"${EXIT_IP}\",\"tunnel\":\"reality:9443\",\"forwarding\":\"${FWD}\",\"note\":\"All 4 protocols tunnel through ${SERVER_IP} to the exit. Marzban Hosts auto-point customer configs here.\"}"
