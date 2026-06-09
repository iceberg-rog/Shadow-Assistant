# === FOREIGN role: exit + Marzban panel ===
# Inherits exported env from the dashboard: SERVER_IP, ROLE, EXIT_IP
# Installs Docker (if missing), deploys Marzban via docker compose with a
# VLESS+REALITY exit inbound, auto-creates a sudo admin, prints FLEET_RESULT.

echo ">> foreign installer starting on $SERVER_IP"

# --- 1) ensure docker + compose ---
export DEBIAN_FRONTEND=noninteractive
if ! command -v docker >/dev/null 2>&1; then
  echo ">> installing docker (apt)"
  apt-get update -qq
  apt-get install -y -qq docker.io openssl >/dev/null 2>&1 || apt-get install -y docker.io openssl
  systemctl enable --now docker >/dev/null 2>&1 || true
fi
# ensure the 'docker compose' plugin (package name differs across Ubuntu versions)
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

# --- 2) generate secrets / params ---
PANEL_PORT=$(shuf -i 20000-60000 -n1)
ADMIN_USER="admin$(shuf -i 1000-9999 -n1)"
ADMIN_PASS=$(openssl rand -base64 15 | tr -d '/+=' | cut -c1-16)
SID=$(openssl rand -hex 8)

mkdir -p /opt/marzban /var/lib/marzban
docker pull gozargah/marzban:latest

# REALITY keypair via the marzban image's xray
KP=$(docker run --rm --entrypoint xray gozargah/marzban:latest x25519 2>/dev/null)
PRIV=$(echo "$KP" | sed -n 's/.*[Pp]rivate.*: *//p' | head -1)
PUB=$(echo "$KP"  | sed -n 's/.*[Pp]ublic.*: *//p'  | head -1)
[ -z "$PRIV" ] && { echo "failed to generate reality keys"; exit 1; }

# --- 3) write config ---
# self-signed TLS cert — Marzban binds 0.0.0.0 only when SSL is configured
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=${SERVER_IP}" \
  -keyout /var/lib/marzban/ssl_key.pem -out /var/lib/marzban/ssl_cert.pem >/dev/null 2>&1

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

cat > /var/lib/marzban/xray_config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "VLESS_REALITY",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.cloudflare.com:443",
          "xver": 0,
          "serverNames": ["www.cloudflare.com"],
          "privateKey": "${PRIV}",
          "shortIds": ["${SID}"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "DIRECT" }, { "protocol": "blackhole", "tag": "BLOCK" } ]
}
EOF

# --- 4) up ---
cd /opt/marzban
docker compose up -d

# open OS firewall for panel + proxy (if ufw is active)
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
  ufw allow ${PANEL_PORT}/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
fi

# --- 5) wait for panel ---
ok=""
for i in $(seq 1 30); do
  code=$(curl -s -k -o /dev/null -w '%{http_code}' "https://127.0.0.1:${PANEL_PORT}/dashboard/" || true)
  if [ "$code" = "200" ] || [ "$code" = "307" ] || [ "$code" = "308" ]; then ok=1; break; fi
  sleep 2
done

echo "REALITY_PUBLIC_KEY=${PUB}"
echo "REALITY_SHORT_ID=${SID}"
if [ -n "$ok" ]; then
  echo "panel is up on ${PANEL_PORT}"
  echo "FLEET_RESULT={\"panel_url\":\"https://${SERVER_IP}:${PANEL_PORT}/dashboard/\",\"admin_user\":\"${ADMIN_USER}\",\"admin_pass\":\"${ADMIN_PASS}\",\"reality_pbk\":\"${PUB}\",\"reality_sid\":\"${SID}\"}"
else
  echo "panel did not answer in time; check: docker compose -f /opt/marzban/docker-compose.yml logs"
  exit 1
fi
