# === FOREIGN role: exit + Marzban (4 protocols) + BOTH tunnel receivers ===
# Inherits exported env from the dashboard: SERVER_IP, ROLE, EXIT_IP
#
# Installs Docker + Marzban with FOUR customer inbounds (VLESS+REALITY 443, VMess 8080,
# Trojan+TLS 8443, Shadowsocks 8388) and offers the relay BOTH tunnel options so it can
# auto-pick the best one:
#   * Hysteria2 server  (UDP 9444)  -> the FAST path (beats per-flow TCP throttling)
#   * REALITY-TCP receiver (TCP 9443) -> the always-works fallback when the relay's ISP
#                                        filters UDP/QUIC
# Both deliver to the local Marzban ports. Also applies kernel network tuning (BBR + big
# UDP buffers) which lifts throughput for either tunnel. Prints the params for both in
# FLEET_RESULT so iran.sh can probe + choose.

XRAY_VER="24.12.31"   # PINNED: the REALITY tunnel relay+receiver MUST run the same xray
HY_PORT="9444"        # Hysteria2 UDP port

echo ">> foreign installer starting on $SERVER_IP"
export DEBIAN_FRONTEND=noninteractive

# ---------- shared helpers ----------
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
# QUIC/UDP buffers (Hysteria) + BBR pacing — lifts throughput on high-RTT links
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

# --- 1) ensure docker + compose ---
if ! command -v docker >/dev/null 2>&1; then
  echo ">> installing docker (apt)"
  apt-get update -qq
  apt-get install -y -qq docker.io openssl >/dev/null 2>&1 || apt-get install -y docker.io openssl
  systemctl enable --now docker >/dev/null 2>&1 || true
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y -qq docker-compose-v2 >/dev/null 2>&1 \
    || apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 || true
fi
if ! docker compose version >/dev/null 2>&1; then
  echo ">> installing compose plugin from github release"
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m)" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi
docker --version
docker compose version >/dev/null 2>&1 || { echo "compose plugin still missing"; exit 1; }
apt-get install -y -qq unzip curl openssl >/dev/null 2>&1 || apt-get install -y unzip curl openssl

# --- 1b) kernel network tuning (benefits both tunnels) ---
tune_kernel

# --- 2) secrets / params ---
PANEL_PORT=$(shuf -i 20000-60000 -n1)
ADMIN_USER="admin$(shuf -i 1000-9999 -n1)"
ADMIN_PASS=$(openssl rand -base64 15 | tr -d '/+=' | cut -c1-16)
SID=$(openssl rand -hex 8)
TUN_SID=$(openssl rand -hex 8)
TUN_UUID=$(cat /proc/sys/kernel/random/uuid)
# Persist Hysteria creds so a REINSTALL keeps the same auth/obfs and already-provisioned
# relays don't lose the fast path (a reinstall that regenerated them would desync relays).
mkdir -p /etc/hysteria
[ -f /etc/hysteria/fleet-creds.env ] && . /etc/hysteria/fleet-creds.env
HY_AUTH="${HY_AUTH:-$(openssl rand -hex 12)}"
HY_OBFS="${HY_OBFS:-$(openssl rand -hex 12)}"
printf 'HY_AUTH=%s\nHY_OBFS=%s\n' "$HY_AUTH" "$HY_OBFS" > /etc/hysteria/fleet-creds.env
chmod 600 /etc/hysteria/fleet-creds.env

mkdir -p /opt/marzban /var/lib/marzban
docker pull gozargah/marzban:latest

# REALITY keypair for the customer VLESS inbound (443)
KP=$(docker run --rm --entrypoint xray gozargah/marzban:latest x25519 2>/dev/null)
PRIV=$(echo "$KP" | sed -n 's/.*[Pp]rivate.*: *//p' | head -1)
PUB=$(echo "$KP"  | sed -n 's/.*[Pp]ublic.*: *//p'  | head -1)
[ -z "$PRIV" ] && { echo "failed to generate reality keys"; exit 1; }

# SEPARATE REALITY keypair for the relay->exit TUNNEL (9443)
TKP=$(docker run --rm --entrypoint xray gozargah/marzban:latest x25519 2>/dev/null)
TUN_PRIV=$(echo "$TKP" | sed -n 's/.*[Pp]rivate.*: *//p' | head -1)
TUN_PUB=$(echo "$TKP"  | sed -n 's/.*[Pp]ublic.*: *//p'  | head -1)
[ -z "$TUN_PRIV" ] && { echo "failed to generate tunnel reality keys"; exit 1; }

# --- 3) self-signed TLS cert (used by Trojan inbound, Marzban panel SSL, Hysteria) ---
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=${SERVER_IP}" \
  -keyout /var/lib/marzban/ssl_key.pem -out /var/lib/marzban/ssl_cert.pem >/dev/null 2>&1

# --- 4) Marzban compose ---
cat > /opt/marzban/docker-compose.yml <<EOF
services:
  marzban:
    image: gozargah/marzban:latest
    restart: always
    network_mode: host
    environment:
      SUDO_USERNAME: "${ADMIN_USER}"
      SUDO_PASSWORD: "${ADMIN_PASS}"
      UVICORN_HOST: "0.0.0.0"
      UVICORN_PORT: "${PANEL_PORT}"
      UVICORN_SSL_CERTFILE: "/var/lib/marzban/ssl_cert.pem"
      UVICORN_SSL_KEYFILE: "/var/lib/marzban/ssl_key.pem"
      UVICORN_SSL_CA_TYPE: "private"
      XRAY_JSON: "/var/lib/marzban/xray_config.json"
      XRAY_SUBSCRIPTION_URL_PREFIX: "https://${SERVER_IP}:${PANEL_PORT}"
    volumes:
      - /var/lib/marzban:/var/lib/marzban
EOF

# --- 5) xray config: four customer inbounds ---
cat > /var/lib/marzban/xray_config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "VLESS_REALITY",
      "listen": "0.0.0.0", "port": 443, "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": {
        "network": "tcp", "security": "reality",
        "realitySettings": {
          "show": false, "dest": "www.cloudflare.com:443", "xver": 0,
          "serverNames": ["www.cloudflare.com"],
          "privateKey": "${PRIV}", "shortIds": ["${SID}"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] }
    },
    {
      "tag": "VMESS_TCP",
      "listen": "0.0.0.0", "port": 8080, "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "tcp", "security": "none" },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] }
    },
    {
      "tag": "TROJAN_TLS",
      "listen": "0.0.0.0", "port": 8443, "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": {
        "network": "tcp", "security": "tls",
        "tlsSettings": { "certificates": [{ "certificateFile": "/var/lib/marzban/ssl_cert.pem", "keyFile": "/var/lib/marzban/ssl_key.pem" }] }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] }
    },
    {
      "tag": "SHADOWSOCKS",
      "listen": "0.0.0.0", "port": 8388, "protocol": "shadowsocks",
      "settings": { "clients": [], "network": "tcp,udp" },
      "streamSettings": { "network": "tcp" },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "DIRECT" }, { "protocol": "blackhole", "tag": "BLOCK" } ]
}
EOF

# --- 6) standalone xray REALITY tunnel receiver (TCP 9443 -> local Marzban ports) ---
if ! /usr/local/bin/xray version 2>/dev/null | grep -q "$XRAY_VER"; then
  arch=$(uname -m); Z=Xray-linux-64.zip; [ "$arch" = "aarch64" ] && Z=Xray-linux-arm64-v8a.zip
  curl -fsSL --connect-timeout 15 --max-time 180 --retry 3 --retry-delay 3 \
    -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VER}/$Z" \
    || { echo "ERROR: failed to download xray ${XRAY_VER} (network/geo-block) - aborting."; exit 1; }
  unzip -tq /tmp/xray.zip >/dev/null 2>&1 || { echo "ERROR: xray.zip corrupt/incomplete - aborting."; exit 1; }
  mkdir -p /usr/local/bin && unzip -o /tmp/xray.zip xray -d /usr/local/bin/ >/dev/null && chmod +x /usr/local/bin/xray
fi
/usr/local/bin/xray version | head -1

mkdir -p /usr/local/etc/xray-tunnel
cat > /usr/local/etc/xray-tunnel/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "tunnel-in",
      "listen": "0.0.0.0", "port": 9443, "protocol": "vless",
      "settings": { "clients": [ { "id": "${TUN_UUID}" } ], "decryption": "none" },
      "streamSettings": {
        "network": "tcp", "security": "reality",
        "realitySettings": {
          "show": false, "dest": "www.cloudflare.com:443", "xver": 0,
          "serverNames": ["www.cloudflare.com"],
          "privateKey": "${TUN_PRIV}", "shortIds": ["${TUN_SID}"]
        }
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF
cat > /etc/systemd/system/xray-tunnel.service <<'EOF'
[Unit]
Description=Xray Tunnel Receiver (REALITY-TCP fallback)
After=network.target
[Service]
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray-tunnel/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable xray-tunnel >/dev/null 2>&1
systemctl restart xray-tunnel
sleep 2
echo "xray-tunnel (REALITY): $(systemctl is-active xray-tunnel)"

# --- 6b) Hysteria2 server (UDP 9444 -> local Marzban ports) — the FAST path ---
HY_READY=0
if install_hysteria; then
  mkdir -p /etc/hysteria
  cat > /etc/hysteria/server.yaml <<EOF
listen: :${HY_PORT}
tls:
  cert: /var/lib/marzban/ssl_cert.pem
  key: /var/lib/marzban/ssl_key.pem
auth:
  type: password
  password: ${HY_AUTH}
obfs:
  type: salamander
  salamander:
    password: ${HY_OBFS}
EOF
  cat > /etc/systemd/system/hysteria-server.service <<'EOF'
[Unit]
Description=Hysteria2 Server (fast UDP tunnel receiver)
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/server.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable hysteria-server >/dev/null 2>&1
  systemctl restart hysteria-server
  sleep 2
  if systemctl is-active --quiet hysteria-server; then HY_READY=1; fi
  echo "hysteria-server (UDP): $(systemctl is-active hysteria-server)"
else
  echo "WARN: hysteria install failed; exit will offer only the REALITY-TCP tunnel."
fi
# If hysteria did not come up, blank its params so the relay won't try the UDP path.
[ "$HY_READY" = 1 ] || { HY_AUTH=""; HY_OBFS=""; }

# --- 7) bring Marzban up ---
cd /opt/marzban
docker compose up -d

# --- 8) firewall: panel + REALITY cover (443) + REALITY tunnel (9443) + Hysteria (9444/udp).
#         vmess/trojan/ss ports are reached only via a tunnel over localhost, stay closed. ---
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
  for p in ${PANEL_PORT} 443 9443; do ufw allow ${p}/tcp >/dev/null 2>&1 || true; done
  ufw allow ${HY_PORT}/udp >/dev/null 2>&1 || true
fi

# --- 9) wait for the panel ---
ok=""
for i in $(seq 1 30); do
  code=$(curl -s -k -o /dev/null -w '%{http_code}' "https://127.0.0.1:${PANEL_PORT}/dashboard/" || true)
  if [ "$code" = "200" ] || [ "$code" = "307" ] || [ "$code" = "308" ]; then ok=1; break; fi
  sleep 2
done

# Verify Marzban's xray actually bound the customer inbounds the relay forwards to (a
# panel that answers HTTP doesn't prove xray loaded the customer ports).
for i in $(seq 1 10); do
  ss -tln 2>/dev/null | grep -qE ':(443|8080|8443|8388) ' && break
  sleep 1
done
ss -tln 2>/dev/null | grep -qE ':443 ' \
  || { echo "ERROR: xray customer inbounds (443/8080/8443/8388) not listening - Marzban config did not load."; exit 1; }

echo "REALITY_PUBLIC_KEY=${PUB}"
echo "REALITY_SHORT_ID=${SID}"
if [ -n "$ok" ] && systemctl is-active --quiet xray-tunnel; then
  echo "panel up on ${PANEL_PORT}; REALITY tunnel on 9443; hysteria ${HY_READY}"
  echo "FLEET_RESULT={\"panel_url\":\"https://${SERVER_IP}:${PANEL_PORT}/dashboard/\",\"admin_user\":\"${ADMIN_USER}\",\"admin_pass\":\"${ADMIN_PASS}\",\"reality_pbk\":\"${PUB}\",\"reality_sid\":\"${SID}\",\"tun_uuid\":\"${TUN_UUID}\",\"tun_pub\":\"${TUN_PUB}\",\"tun_sid\":\"${TUN_SID}\",\"hy_port\":\"${HY_PORT}\",\"hy_auth\":\"${HY_AUTH}\",\"hy_obfs\":\"${HY_OBFS}\"}"
else
  echo "panel or REALITY tunnel did not come up in time; check: docker compose -f /opt/marzban/docker-compose.yml logs ; systemctl status xray-tunnel"
  exit 1
fi
