# === IRAN role: domestic relay -> foreign exit ===
# Inherits exported env: SERVER_IP, ROLE, EXIT_IP (the foreign exit to forward to).
# Installs a lightweight xray relay: clients connect to this Iran box (fast, domestic
# IP), traffic is forwarded over an encrypted tunnel to the foreign exit. This keeps
# the foreign IP off the client and gives better in-country speed.
#
# NOTE: requires the foreign exit to be installed FIRST. EXIT_IP must be set.

echo ">> iran relay installer starting on $SERVER_IP -> exit $EXIT_IP"
[ -z "${EXIT_IP}" ] && { echo "EXIT_IP is empty — install the foreign exit first, then set its IP."; exit 1; }

# --- 1) install xray-core (official binary, no piped script) ---
mkdir -p /usr/local/bin /usr/local/etc/xray
if ! command -v /usr/local/bin/xray >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq unzip curl openssl >/dev/null
  arch=$(uname -m); Z=Xray-linux-64.zip; [ "$arch" = "aarch64" ] && Z=Xray-linux-arm64-v8a.zip
  curl -fsSL -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/latest/download/$Z"
  unzip -o /tmp/xray.zip xray -d /usr/local/bin/ >/dev/null
  chmod +x /usr/local/bin/xray
fi
/usr/local/bin/xray version | head -1

# --- 2) relay config ---
# Inbound (clients -> Iran relay) + outbound that forwards everything to the foreign
# exit. The exit forwarding params are read from /usr/local/etc/xray/exit.json which
# the dashboard fills with the foreign exit's REALITY details (pbk/sid/uuid).
RELAY_PORT="${RELAY_PORT:-443}"
echo "relay inbound port: ${RELAY_PORT}"

if [ ! -f /usr/local/etc/xray/exit.json ]; then
  echo "exit.json not provisioned yet (needs foreign exit's uuid/pbk/sid)."
  echo "Provide foreign exit details via the dashboard to complete the relay link."
fi

cat > /etc/systemd/system/xray-relay.service <<'EOF'
[Unit]
Description=Xray Iran Relay
After=network.target
[Service]
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF

# Minimal placeholder config so the service is valid; the full forwarding block is
# written once the foreign exit's client params are supplied.
if [ ! -f /usr/local/etc/xray/config.json ]; then
  cat > /usr/local/etc/xray/config.json <<EOF
{ "log": {"loglevel":"warning"},
  "inbounds": [ { "tag":"relay-in","listen":"0.0.0.0","port":${RELAY_PORT},"protocol":"vless",
    "settings":{"clients":[],"decryption":"none"},
    "streamSettings":{"network":"tcp","security":"none"} } ],
  "outbounds": [ {"protocol":"freedom","tag":"direct"} ] }
EOF
fi

systemctl daemon-reload
systemctl enable --now xray-relay >/dev/null 2>&1
systemctl restart xray-relay
sleep 2
systemctl is-active xray-relay

echo "FLEET_RESULT={\"role\":\"iran-relay\",\"relay_ip\":\"${SERVER_IP}\",\"exit_ip\":\"${EXIT_IP}\",\"relay_port\":\"${RELAY_PORT}\",\"note\":\"relay service installed; foreign-exit link params required to finalize forwarding\"}"
