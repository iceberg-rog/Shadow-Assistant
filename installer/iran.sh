# === IRAN role: domestic relay -> foreign exit, AUTO-PICKS the best tunnel ===
# Inherits exported env: SERVER_IP, ROLE, EXIT_IP
#   REALITY fallback params (always): TUN_UUID, TUN_PUB, TUN_SID
#   Hysteria fast-path params (optional): HY_PORT, HY_AUTH, HY_OBFS
#
# Clients connect to THIS domestic IP on 443/8080/8443/8388. A dokodemo-door grabs each
# connection (dest = 127.0.0.1:<port>) and ships it to the exit through ONE tunnel:
#   * Hysteria2 (UDP/QUIC) if this ISP lets a sustained UDP flow survive -> FAST
#   * REALITY over TCP otherwise (always works; TCP isn't UDP-filtered)        -> fallback
# The installer PROBES the UDP path with a real sustained transfer and chooses. The exit
# unwraps whichever tunnel and hands traffic to its local Marzban inbounds.
#
# Requires the foreign exit installed FIRST (EXIT_IP + TUN_* set; HY_* set if available).

XRAY_VER="24.12.31"   # PINNED: must match the exit's REALITY tunnel receiver

echo ">> iran relay installer starting on $SERVER_IP -> exit $EXIT_IP"
[ -z "${EXIT_IP:-}" ]  && { echo "EXIT_IP is empty - install the foreign exit first, then set its IP."; exit 1; }
[ -z "${TUN_UUID:-}" ] && { echo "TUN_UUID missing - re-provision the foreign exit (it generates the tunnel params)."; exit 1; }
[ -z "${TUN_PUB:-}" ]  && { echo "TUN_PUB missing - re-provision the foreign exit."; exit 1; }
[ -z "${TUN_SID:-}" ]  && { echo "TUN_SID missing - re-provision the foreign exit."; exit 1; }
HY_PORT="${HY_PORT:-9444}"

export DEBIAN_FRONTEND=noninteractive

install_hysteria() {
  /usr/local/bin/hysteria version >/dev/null 2>&1 && return 0
  local a=hysteria-linux-amd64; [ "$(uname -m)" = aarch64 ] && a=hysteria-linux-arm64
  curl -fsSL --connect-timeout 15 --max-time 180 --retry 3 --retry-delay 3 \
    -o /usr/local/bin/hysteria "https://github.com/apernet/hysteria/releases/latest/download/${a}" || return 1
  chmod +x /usr/local/bin/hysteria
  /usr/local/bin/hysteria version >/dev/null 2>&1 || return 1
}

tune_kernel() {
  local memkb udpmem
  memkb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 4000000)
  if [ "${memkb:-0}" -lt 2000000 ]; then udpmem="32768 65536 131072"; else udpmem="65536 131072 262144"; fi
  cat > /etc/sysctl.d/99-fleet.conf <<EOF
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.udp_mem = ${udpmem}
net.core.netdev_max_backlog = 16384
EOF
  modprobe tcp_bbr 2>/dev/null || true
  sysctl --system >/dev/null 2>&1 || true
  local iface; iface=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
  [ -n "$iface" ] && tc qdisc replace dev "$iface" root fq 2>/dev/null || true
}

# --- 1) install xray (pinned, for the REALITY fallback) + kernel tuning ---
if ! /usr/local/bin/xray version 2>/dev/null | grep -q "$XRAY_VER"; then
  apt-get update -qq && apt-get install -y -qq unzip curl openssl >/dev/null 2>&1 || apt-get install -y unzip curl openssl
  arch=$(uname -m); Z=Xray-linux-64.zip; [ "$arch" = "aarch64" ] && Z=Xray-linux-arm64-v8a.zip
  mkdir -p /usr/local/bin /usr/local/etc/xray
  curl -fsSL --connect-timeout 15 --max-time 180 --retry 3 --retry-delay 3 \
    -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VER}/$Z" \
    || { echo "ERROR: failed to download xray ${XRAY_VER} (network/geo-block) - aborting."; exit 1; }
  unzip -tq /tmp/xray.zip >/dev/null 2>&1 || { echo "ERROR: xray.zip corrupt/incomplete - aborting."; exit 1; }
  unzip -o /tmp/xray.zip xray -d /usr/local/bin/ >/dev/null || { echo "ERROR: failed to extract xray - aborting."; exit 1; }
  chmod +x /usr/local/bin/xray
fi
/usr/local/bin/xray version | head -1
tune_kernel

# --- 2) PROBE the UDP/Hysteria path (only if the exit offered hysteria params) ---
MODE="reality"   # safe default
if [ -n "${HY_AUTH:-}" ] && [ -n "${HY_OBFS:-}" ] && install_hysteria; then
  echo ">> probing UDP/Hysteria path to ${EXIT_IP}:${HY_PORT} (sustained transfer test) ..."
  mkdir -p /etc/hysteria
  cat > /etc/hysteria/client.yaml <<EOF
server: ${EXIT_IP}:${HY_PORT}
auth: ${HY_AUTH}
tls:
  insecure: true
obfs:
  type: salamander
  salamander:
    password: ${HY_OBFS}
socks5:
  listen: 127.0.0.1:1080
bandwidth:
  up: 9 mbps
  down: 80 mbps
EOF
  cat > /etc/systemd/system/hysteria-client.service <<'EOF'
[Unit]
Description=Hysteria2 Client (relay -> exit fast tunnel)
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria client -c /etc/hysteria/client.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl restart hysteria-client
  # wait up to 12s for the SOCKS port (it only opens after the QUIC handshake succeeds)
  for i in $(seq 1 12); do
    ss -tlnp 2>/dev/null | grep -q '127.0.0.1:1080' && break
    sleep 1
  done
  PROBE_BYTES=0
  if ss -tlnp 2>/dev/null | grep -q '127.0.0.1:1080'; then
    # sustained pull (~8MB / up to 15s) through the UDP tunnel. A stateful UDP filter that
    # kills the flow mid-transfer (or never completes the handshake) yields too few bytes.
    PROBE_BYTES=$(curl -s --max-time 15 -x socks5h://127.0.0.1:1080 -o /dev/null \
      -w '%{size_download}' "https://speed.cloudflare.com/__down?bytes=8000000" 2>/dev/null || echo 0)
  fi
  # Require ~81% of the 8MB pull (6.5MB). A stateful UDP filter that passes the QUIC
  # handshake then drops the flow after a few MB cannot reach this; only a genuinely open
  # path (which delivers the full 8MB well within 15s at the 80mbps cap) does.
  if [ "${PROBE_BYTES:-0}" -gt 6500000 ]; then
    MODE="hysteria"
    systemctl enable hysteria-client >/dev/null 2>&1
    echo ">> UDP/Hysteria path WORKS (${PROBE_BYTES} bytes sustained). Using the FAST tunnel."
  else
    systemctl disable --now hysteria-client >/dev/null 2>&1 || true
    echo ">> UDP/Hysteria filtered/unreliable (${PROBE_BYTES} bytes). Falling back to REALITY-TCP."
  fi
else
  echo ">> no hysteria params from the exit (or install failed); using REALITY-TCP."
fi

# --- 3) relay xray config: dokodemo inbounds -> the chosen tunnel outbound ---
mkdir -p /usr/local/etc/xray
if [ "$MODE" = "hysteria" ]; then
  TUNNEL_OUT='{ "tag": "tunnel", "protocol": "socks", "settings": { "servers": [ { "address": "127.0.0.1", "port": 1080 } ] } }'
else
  TUNNEL_OUT='{ "tag": "tunnel", "protocol": "vless", "settings": { "vnext": [ { "address": "'"${EXIT_IP}"'", "port": 9443, "users": [ { "id": "'"${TUN_UUID}"'", "encryption": "none" } ] } ] }, "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "serverName": "www.cloudflare.com", "fingerprint": "chrome", "publicKey": "'"${TUN_PUB}"'", "shortId": "'"${TUN_SID}"'" } } }'
fi
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
    ${TUNNEL_OUT},
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": { "rules": [ { "type": "field", "inboundTag": ["in-443","in-8080","in-8443","in-8388"], "outboundTag": "tunnel" } ] }
}
EOF
/usr/local/bin/xray -test -c /usr/local/etc/xray/config.json >/dev/null 2>&1 \
  || { echo "ERROR: generated relay config is invalid - aborting."; exit 1; }

# --- 4) systemd service ---
cat > /etc/systemd/system/xray-relay.service <<'EOF'
[Unit]
Description=Xray Iran Relay (auto-tunnel to exit)
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
systemctl is-active --quiet xray-relay || { echo "ERROR: xray-relay failed to start - aborting."; exit 1; }
echo "relay service: $(systemctl is-active xray-relay)  (mode=${MODE})"

# --- 5) firewall: customer ports (clients connect to the relay here) ---
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
  for p in 443 8080 8443 8388; do ufw allow ${p}/tcp >/dev/null 2>&1 || true; done
fi

# --- 6) verify: listening + the tunnel actually reaches the exit's REALITY server ---
ss -tlnp | grep -q ':443 ' && echo "relay listening on :443" || { echo "ERROR: relay not listening on :443"; exit 1; }

# A TLS handshake to the relay's :443 travels through the chosen tunnel to the exit's
# customer REALITY inbound, which fronts cloudflare for unauthenticated TLS -> returns a
# certificate. Getting one proves the full client->relay->[tunnel]->exit path works.
if echo | openssl s_client -connect 127.0.0.1:443 -servername www.cloudflare.com 2>/dev/null | grep -q 'BEGIN CERTIFICATE'; then
  echo "tunnel to exit OK (handshake reached the exit through the ${MODE} tunnel)"
  FWD="ok"
else
  echo "WARN: could not confirm the ${MODE} tunnel to ${EXIT_IP} (check the exit's services/firewall)"
  FWD="unconfirmed"
fi

echo "FLEET_RESULT={\"role\":\"iran-relay\",\"relay_ip\":\"${SERVER_IP}\",\"exit_ip\":\"${EXIT_IP}\",\"tunnel\":\"${MODE}\",\"forwarding\":\"${FWD}\",\"note\":\"Auto-selected ${MODE} tunnel. All 4 protocols route through ${SERVER_IP}; Marzban Hosts auto-point customer configs here.\"}"
