# === IRAN role: transparent relay -> foreign exit ===
# Inherits exported env: SERVER_IP, ROLE, EXIT_IP (the foreign exit to forward to).
#
# Clients connect to THIS fast domestic IP on :443; all TCP is forwarded to the foreign
# exit's :443, where the REALITY handshake terminates. The foreign IP never touches the
# client. In Marzban (on the exit) add a Host with address = this relay's IP so issued
# configs point here.
#
# Requires the foreign exit to be installed first (EXIT_IP must be set).

echo ">> iran relay installer starting on $SERVER_IP -> exit $EXIT_IP"
[ -z "${EXIT_IP:-}" ] && { echo "EXIT_IP is empty - install the foreign exit first, then set its IP."; exit 1; }

export DEBIAN_FRONTEND=noninteractive

# --- 1) install xray-core (official binary, no piped script) ---
if ! /usr/local/bin/xray version >/dev/null 2>&1; then
  apt-get update -qq && apt-get install -y -qq unzip curl openssl >/dev/null 2>&1 || true
  arch=$(uname -m); Z=Xray-linux-64.zip; [ "$arch" = "aarch64" ] && Z=Xray-linux-arm64-v8a.zip
  mkdir -p /usr/local/bin /usr/local/etc/xray
  curl -fsSL --connect-timeout 15 --max-time 180 --retry 3 --retry-delay 3 \
    -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/latest/download/$Z" \
    || { echo "ERROR: failed to download xray from GitHub (network/geo-block) - aborting."; exit 1; }
  unzip -tq /tmp/xray.zip >/dev/null 2>&1 || { echo "ERROR: xray.zip is corrupt/incomplete - aborting."; exit 1; }
  unzip -o /tmp/xray.zip xray -d /usr/local/bin/ >/dev/null
  chmod +x /usr/local/bin/xray
fi
/usr/local/bin/xray version | head -1

# --- 2) relay config: dokodemo-door :443 -> EXIT_IP:443 ---
mkdir -p /usr/local/etc/xray
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "relay-443",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "dokodemo-door",
      "settings": { "address": "${EXIT_IP}", "port": 443, "network": "tcp" }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF

# --- 3) systemd service ---
cat > /etc/systemd/system/xray-relay.service <<'EOF'
[Unit]
Description=Xray Iran Relay (dokodemo-door)
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

# open OS firewall if active
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
  ufw allow 443/tcp >/dev/null 2>&1 || true
fi

# --- 4) verify: listening + actually forwards to the foreign REALITY exit ---
ss -tlnp | grep -q ':443 ' && echo "relay listening on :443" || { echo "ERROR: relay not listening on :443"; exit 1; }

# A REALITY server fronts its 'dest' (cloudflare) for unauthenticated TLS, so a TLS
# handshake through the relay should return a certificate -> proves end-to-end forwarding.
if echo | openssl s_client -connect 127.0.0.1:443 -servername www.cloudflare.com 2>/dev/null | grep -q 'BEGIN CERTIFICATE'; then
  echo "forwarding to exit OK (TLS handshake reached the foreign REALITY server)"
  FWD="ok"
else
  echo "WARN: could not confirm forwarding to ${EXIT_IP}:443 (check exit firewall / that the exit is up)"
  FWD="unconfirmed"
fi

echo "FLEET_RESULT={\"role\":\"iran-relay\",\"relay_ip\":\"${SERVER_IP}\",\"exit_ip\":\"${EXIT_IP}\",\"forwarding\":\"${FWD}\",\"note\":\"In Marzban on the exit, add a Host with address=${SERVER_IP} so customer configs point to this relay.\"}"
