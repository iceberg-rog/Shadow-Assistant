#!/bin/bash
# ==========================================================================
# installer/marzban-direct.sh
# A complete v2ray service on ONE foreign server that customers dial directly.
# No Iran relay: OpenVPN is reliably identified and killed by DPI on that path,
# so the entry protocols here are the ones that survive it.
#
# Inbounds (all public on this box):
#   443/tcp  VLESS + REALITY + vision   <- the one that works when others don't
#   8443/tcp Trojan + REALITY           <- xray 26 dropped allowInsecure, so a
#                                          self-signed cert is unusable; REALITY needs none
#   8080/tcp VMess + TCP
#   8388/tcp Shadowsocks (chacha20-ietf-poly1305)
#   2096/tcp Marzban panel + subscription links
#
# Marzban gives per-user traffic quota, expiry, and one subscription link that
# carries every protocol, so a customer whose ISP blocks one can switch inside
# their app without new credentials.
#
# Usage:
#   [MIGRATE=1] [ADMIN_USER=..] [ADMIN_PASS=..] [PANEL_PORT=2096]
#   [CUST_PRIV=.. CUST_PUB=.. CUST_SID=..]   bash marzban-direct.sh
#   MIGRATE=1 expects a previous Marzban DB at /tmp/marzban-db.sqlite3
# Emits: FLEET_RESULT={...} with everything needed to rebuild elsewhere.
# ==========================================================================
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
SERVER_IP="${SERVER_IP:-$(curl -s --max-time 15 https://api.ipify.org)}"
[ -n "$SERVER_IP" ] || SERVER_IP="$(hostname -I | awk '{print $1}')"
MIGRATE="${MIGRATE:-0}"
PANEL_PORT="${PANEL_PORT:-2096}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-$(openssl rand -base64 12 | tr -dc 'A-Za-z0-9' | cut -c1-14)}"
APP=/opt/marzban-app; VLIB=/var/lib/marzban; XC="$VLIB/xray-core"
echo ">> [1/7] v2ray service on $SERVER_IP (migrate=$MIGRATE)"

# ---------- free the ports we need ----------
for u in xray-reality openvpn-server@server443; do systemctl disable --now "$u" >/dev/null 2>&1 || true; done

# ---------- base ----------
swapon --show 2>/dev/null | grep -q /swapfile || {
  fallocate -l 2G /swapfile 2>/dev/null && chmod 600 /swapfile && mkswap /swapfile >/dev/null 2>&1 \
    && swapon /swapfile 2>/dev/null && (grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab); }
apt-get update -y >/dev/null 2>&1
apt-get install -y git curl unzip openssl sqlite3 >/dev/null 2>&1 || { echo "ERROR: apt failed"; exit 1; }
command -v uv >/dev/null 2>&1 || [ -x "$HOME/.local/bin/uv" ] || curl -fsSL https://astral.sh/uv/install.sh | sh >/dev/null 2>&1
export PATH="$HOME/.local/bin:$PATH"; UV="$(command -v uv || echo "$HOME/.local/bin/uv")"
"$UV" --version >/dev/null 2>&1 || { echo "ERROR: uv unavailable"; exit 1; }

echo ">> [2/7] Marzban (native, python 3.12)"
if [ ! -d "$APP/.venv" ]; then
  cd /opt; rm -rf marzban-app
  git clone --depth 1 https://github.com/Gozargah/Marzban.git marzban-app >/dev/null 2>&1 || { echo "ERROR: clone failed"; exit 1; }
  cd "$APP"
  "$UV" venv --python 3.12 .venv >/dev/null 2>&1 || { echo "ERROR: venv failed"; exit 1; }
  "$UV" pip install --python .venv --no-cache -r requirements.txt grpcio grpcio-tools "setuptools<81" >/dev/null 2>&1 \
    || { echo "ERROR: deps failed"; exit 1; }
fi
cd "$APP"
"$APP/.venv/bin/python" -c "import pydantic_core,grpc,fastapi,uvicorn,alembic" 2>/dev/null || { echo "ERROR: dep check failed"; exit 1; }

echo ">> [3/7] xray-core 26.3.27"
systemctl stop xray-tunnel 2>/dev/null || true
mkdir -p "$XC"; cd "$XC"
if ! ./xray version 2>/dev/null | grep -q 26.3.27; then
  curl -fsSL -o xray.zip https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip || { echo "ERROR: xray dl"; exit 1; }
  python3 -m zipfile -e xray.zip . && rm -f xray.zip; chmod +x xray
fi
./xray version | head -1
modprobe tcp_bbr 2>/dev/null || true
printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\nnet.ipv4.tcp_mtu_probing=1\n' > /etc/sysctl.d/99-bbr.conf
sysctl --system >/dev/null 2>&1 || true

echo ">> [4/7] identity (REALITY keys, uuid, cert)"
x25519(){ local o; o="$("$XC/xray" x25519 2>/dev/null)"
  local p q; p=$(echo "$o"|grep -i private|grep -oE '[A-Za-z0-9_/+-]{42,44}'|head -1)
  q=$(echo "$o"|grep -iv private|grep -oE '[A-Za-z0-9_/+-]{42,44}'|head -1); echo "$p $q"; }
derive_pub(){ "$XC/xray" x25519 -i "$1" 2>/dev/null | grep -iv private | grep -oE '[A-Za-z0-9_/+-]{42,44}' | head -1; }
if [ -n "${CUST_PRIV:-}" ] && [ -n "${CUST_SID:-}" ]; then
  RPRIV="$CUST_PRIV"; RSID="$CUST_SID"; RPUB="${CUST_PUB:-$(derive_pub "$CUST_PRIV")}"
  echo "   reusing the fleet REALITY identity (existing customer links keep working)"
else
  read -r RPRIV RPUB < <(x25519); RSID="$(openssl rand -hex 8)"
  echo "   fresh REALITY identity"
fi
[ -n "$RPUB" ] || { echo "ERROR: no REALITY public key"; exit 1; }
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=${SERVER_IP}" \
  -keyout "$VLIB/ssl_key.pem" -out "$VLIB/ssl_cert.pem" >/dev/null 2>&1

echo ">> [5/7] inbounds: REALITY 443 / Trojan 8443 / VMess 8080 / SS 8388"
cat > "$VLIB/xray_config.json" <<EOF
{ "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "VLESS_REALITY", "listen": "0.0.0.0", "port": 443, "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "reality",
        "realitySettings": { "show": false, "dest": "www.cloudflare.com:443", "xver": 0,
          "serverNames": ["www.cloudflare.com"],
          "privateKey": "${RPRIV}", "publicKey": "${RPUB}", "shortIds": ["${RSID}"] } },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] } },
    { "tag": "TROJAN_REALITY", "listen": "0.0.0.0", "port": 8443, "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "tcp", "security": "reality",
        "realitySettings": { "show": false, "dest": "www.cloudflare.com:443", "xver": 0,
          "serverNames": ["www.cloudflare.com"],
          "privateKey": "${RPRIV}", "publicKey": "${RPUB}", "shortIds": ["${RSID}"] } },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] } },
    { "tag": "VMESS_TCP", "listen": "0.0.0.0", "port": 8080, "protocol": "vmess",
      "settings": { "clients": [] }, "streamSettings": { "network": "tcp", "security": "none" },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] } },
    { "tag": "SHADOWSOCKS", "listen": "0.0.0.0", "port": 8388, "protocol": "shadowsocks",
      "settings": { "clients": [], "network": "tcp,udp" }, "streamSettings": { "network": "tcp" },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] } }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "DIRECT" }, { "protocol": "blackhole", "tag": "BLOCK" } ] }
EOF
"$XC/xray" -test -c "$VLIB/xray_config.json" >/dev/null 2>&1 || { echo "ERROR: xray config invalid"; exit 1; }

cat > "$APP/.env" <<EOF
SUDO_USERNAME=${ADMIN_USER}
SUDO_PASSWORD=${ADMIN_PASS}
UVICORN_HOST=0.0.0.0
UVICORN_PORT=${PANEL_PORT}
UVICORN_SSL_CERTFILE=$VLIB/ssl_cert.pem
UVICORN_SSL_KEYFILE=$VLIB/ssl_key.pem
UVICORN_SSL_CA_TYPE=private
XRAY_JSON=$VLIB/xray_config.json
XRAY_EXECUTABLE_PATH=$XC/xray
XRAY_ASSETS_PATH=$XC
SQLALCHEMY_DATABASE_URL=sqlite:///$VLIB/db.sqlite3
XRAY_SUBSCRIPTION_URL_PREFIX=https://${SERVER_IP}:${PANEL_PORT}
EOF

echo ">> [6/7] database"
if [ "$MIGRATE" = 1 ] && [ -f /tmp/marzban-db.sqlite3 ]; then
  install -m640 /tmp/marzban-db.sqlite3 "$VLIB/db.sqlite3"
  echo "   restored a previous database"
fi
cd "$APP" && "$APP/.venv/bin/alembic" upgrade head >/dev/null 2>&1 || true
# every host must point at THIS server on the public ports (direct mode)
"$APP/.venv/bin/python" - "$SERVER_IP" <<'PY'
import sqlite3, sys
ip = sys.argv[1]
c = sqlite3.connect('/var/lib/marzban/db.sqlite3')
ports = {'VLESS_REALITY': 443, 'TROJAN_REALITY': 8443, 'VMESS_TCP': 8080, 'SHADOWSOCKS': 8388}
try:
    have = {r[0] for r in c.execute("select inbound_tag from hosts")}
    for tag, port in ports.items():
        if tag in have:
            c.execute("update hosts set address=?, port=? where inbound_tag=?", (ip, port, tag))
    c.commit()
    n = c.execute("select count(*) from users").fetchone()[0]
    print("   users in database: %d" % n)
except Exception as e:
    print("   (fresh database)")
c.close()
PY
printf '\n\n\n' | SUDO_USERNAME="$ADMIN_USER" MARZBAN_ADMIN_PASSWORD="$ADMIN_PASS" \
  "$APP/.venv/bin/python" "$APP/marzban-cli.py" admin create -u "$ADMIN_USER" --sudo >/dev/null 2>&1 || true

echo ">> [7/7] service"
cat > /etc/systemd/system/marzban.service <<EOF
[Unit]
Description=Marzban (v2ray panel)
After=network.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=$APP
ExecStart=$APP/.venv/bin/python main.py
Restart=always
RestartSec=5
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now marzban >/dev/null 2>&1
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
  for p in 443 8443 8080 8388 "$PANEL_PORT"; do ufw allow ${p}/tcp >/dev/null 2>&1; done
fi

ok=""
for i in $(seq 1 40); do
  code=$(curl -sk -o /dev/null -m 6 -w '%{http_code}' "https://127.0.0.1:${PANEL_PORT}/dashboard/" || true)
  case "$code" in 200|307|308) ok=1; break;; esac
  sleep 2
done
for i in $(seq 1 15); do ss -tln | grep -q ':443 ' && break; sleep 1; done

echo
echo "   marzban=$(systemctl is-active marzban)  panel=${ok:-0}"
echo "   listening: $(ss -tln | grep -oE ':(443|8443|8080|8388|'"$PANEL_PORT"') ' | tr -d ' :' | sort -un | tr '\n' ' ')"
[ -n "$ok" ] || { echo "ERROR: panel did not come up"; exit 1; }
ss -tln | grep -q ':443 ' || { echo "ERROR: REALITY inbound not listening"; exit 1; }
echo "FLEET_RESULT={\"ip\":\"${SERVER_IP}\",\"panel_port\":\"${PANEL_PORT}\",\"admin_user\":\"${ADMIN_USER}\",\"admin_pass\":\"${ADMIN_PASS}\",\"reality_priv\":\"${RPRIV}\",\"reality_pub\":\"${RPUB}\",\"reality_sid\":\"${RSID}\"}"
