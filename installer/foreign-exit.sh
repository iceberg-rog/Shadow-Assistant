#!/bin/bash
# ==========================================================================
# foreign-exit.sh  —  build a REAL foreign EXIT that matches the live fleet
# (native uv Marzban + xray 26.3.27, customer inbounds on 127.0.0.1, a
#  separate xray tunnel-in on :9443). NO Docker, and — deliberately — NO
#  OpenVPN/IPsec on the exit (those belong on the relay; running them here has
#  broken exit egress before).
#
# The exit's job: terminate the relay->exit REALITY tunnel (:9443) and the four
# customer inbounds (VLESS-REALITY/VMess/Trojan/SS on localhost), then egress
# (freedom). Customers reach these only THROUGH the relay's dokodemo+tunnel.
#
# Env (all optional except RELAY_IP):
#   RELAY_IP     the Iran relay IP (hosts table + sub prefix point back at it)   [required]
#   MIGRATE      1 => restore users+usage+days from /tmp/marzban-db.sqlite3
#   CUST_PRIV/CUST_PUB/CUST_SID   fleet customer VLESS-REALITY identity — pass these
#                so customer configs keep working across an exit swap. If unset, a
#                fresh customer keypair is generated (fine for a standalone test).
#   ADMIN_USER/ADMIN_PASS   panel admin (defaults to a fresh random pair)
#   SUB_PREFIX   subscription URL prefix (default https://RELAY_IP:2096)
#   PANEL_PORT   Marzban uvicorn port (default 39196 — the relay's sub-forward target)
#   WITH_L2TP    accepted for API compatibility but IGNORED on the exit (see above)
#
# Emits (last line):  FLEET_RESULT={"tun_uuid":..,"tun_pub":..,"tun_sid":..,..}
#   which the relay uses to repoint its tunnel at this new exit.
# ==========================================================================
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
RELAY_IP="${RELAY_IP:?set RELAY_IP=the Iran relay public IP}"
MIGRATE="${MIGRATE:-0}"
PANEL_PORT="${PANEL_PORT:-39196}"
SUB_PREFIX="${SUB_PREFIX:-https://${RELAY_IP}:2096}"
ADMIN_USER="${ADMIN_USER:-admin$(shuf -i 1000-9999 -n1 2>/dev/null || echo 7492)}"
ADMIN_PASS="${ADMIN_PASS:-$(openssl rand -base64 15 | tr -d '/+=' | cut -c1-16)}"
MZ=marzban
APP=/opt/marzban-app
VLIB=/var/lib/marzban
XC="$VLIB/xray-core"
echo ">> [1/6] exit build starting on ${SERVER_IP:-?}  (relay=$RELAY_IP migrate=$MIGRATE)"

# ---------- 1) base: swap + tools + uv ----------
swapon --show 2>/dev/null | grep -q /swapfile || {
  fallocate -l 2G /swapfile 2>/dev/null && chmod 600 /swapfile && mkswap /swapfile >/dev/null 2>&1 \
    && swapon /swapfile 2>/dev/null && grep -q /swapfile /etc/fstab 2>/dev/null || echo '/swapfile none swap sw 0 0' >> /etc/fstab; }
apt-get update -y >/dev/null 2>&1
apt-get install -y git curl unzip openssl >/dev/null 2>&1 || { echo "ERROR: apt install failed"; exit 1; }
if ! command -v uv >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/uv" ]; then
  curl -fsSL https://astral.sh/uv/install.sh | sh >/dev/null 2>&1
fi
export PATH="$HOME/.local/bin:$PATH"; UV="$(command -v uv || echo "$HOME/.local/bin/uv")"
"$UV" --version || { echo "ERROR: uv not available"; exit 1; }

# ---------- 2) Marzban (native, python 3.12 venv) ----------
echo ">> [2/6] Marzban (uv py3.12) + xray-core 26.3.27 ..."
cd /opt; rm -rf marzban-app; git clone --depth 1 https://github.com/Gozargah/Marzban.git marzban-app >/dev/null 2>&1 || { echo "ERROR: marzban clone failed"; exit 1; }
cd "$APP"
"$UV" venv --python 3.12 .venv >/dev/null 2>&1 || { echo "ERROR: venv create failed"; exit 1; }
"$UV" pip install --python .venv --no-cache -r requirements.txt grpcio grpcio-tools "setuptools<81" >/dev/null 2>&1 || { echo "ERROR: pip deps failed"; exit 1; }
.venv/bin/python -c "import pydantic_core,grpc,click,alembic,fastapi,uvicorn" 2>/dev/null || { echo "ERROR: dep import check failed"; exit 1; }

# xray-core 26.3.27  (stop the tunnel first so a REINSTALL can overwrite the binary)
systemctl stop xray-tunnel 2>/dev/null || true
mkdir -p "$XC"; cd "$XC"
if ! ./xray version 2>/dev/null | grep -q "26.3.27"; then
  curl -fsSL -o xray.zip https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip || { echo "ERROR: xray download failed"; exit 1; }
  python3 -m zipfile -e xray.zip . && rm -f xray.zip; chmod +x xray
fi
./xray version 2>&1 | head -1

# BBR
modprobe tcp_bbr 2>/dev/null || true
printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\nnet.ipv4.tcp_mtu_probing=1\n' > /etc/sysctl.d/99-bbr.conf
sysctl --system >/dev/null 2>&1 || true

# ---------- 3) keys: fresh TUNNEL keypair (per-exit) + customer identity ----------
echo ">> [3/6] generating tunnel keys + customer inbounds ..."
x25519() {  # echoes: "<priv> <pub>"  (robust to label wording across xray versions)
  local out; out="$("$XC/xray" x25519 2>/dev/null)"
  local priv pub
  priv=$(echo "$out" | grep -i 'private' | grep -oE '[A-Za-z0-9_/+-]{42,44}' | head -1)
  pub=$(echo "$out"  | grep -iv 'private' | grep -oE '[A-Za-z0-9_/+-]{42,44}' | head -1)
  echo "$priv $pub"
}
derive_pub() {  # echo the REALITY public key matching a given private key
  "$XC/xray" x25519 -i "$1" 2>/dev/null | grep -iv 'private' | grep -oE '[A-Za-z0-9_/+-]{42,44}' | head -1
}
read -r TUN_PRIV TUN_PUB < <(x25519)
[ -n "$TUN_PRIV" ] && [ -n "$TUN_PUB" ] || { echo "ERROR: tunnel key gen failed"; exit 1; }
TUN_UUID="$("$XC/xray" uuid)"
TUN_SID="$(openssl rand -hex 8)"

# customer VLESS-REALITY identity: reuse the fleet's if provided, else fresh.
# Marzban reads realitySettings.publicKey to build client subs, so we MUST set it.
if [ -n "${CUST_PRIV:-}" ] && [ -n "${CUST_SID:-}" ]; then
  CPRIV="$CUST_PRIV"; CSID="$CUST_SID"; CPUB="${CUST_PUB:-}"
  [ -z "$CPUB" ] && CPUB="$(derive_pub "$CPRIV")"
  echo "   customer identity: reusing fleet key (configs stay valid across swap)"
else
  read -r CPRIV CPUB < <(x25519); CSID="$(openssl rand -hex 8)"
  echo "   customer identity: FRESH (standalone test exit)"
fi
[ -n "$CPUB" ] || { echo "ERROR: could not determine customer REALITY public key"; exit 1; }

# self-signed cert for the Trojan inbound (clients use allowInsecure)
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=${SERVER_IP:-exit}" \
  -keyout "$VLIB/ssl_key.pem" -out "$VLIB/ssl_cert.pem" >/dev/null 2>&1

# ---------- 4) configs: customer inbounds (localhost) + tunnel-in (:9443) ----------
cat > "$VLIB/xray_config.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "VLESS_REALITY", "listen": "127.0.0.1", "port": 2443, "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "reality",
        "realitySettings": { "show": false, "dest": "www.cloudflare.com:443", "xver": 0, "serverNames": ["www.cloudflare.com"],
          "privateKey": "${CPRIV}", "publicKey": "${CPUB}", "shortIds": ["${CSID}"] } },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] } },
    { "tag": "VMESS_TCP", "listen": "127.0.0.1", "port": 2080, "protocol": "vmess",
      "settings": { "clients": [] }, "streamSettings": { "network": "tcp", "security": "none" },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] } },
    { "tag": "TROJAN_TLS", "listen": "127.0.0.1", "port": 2843, "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "tcp", "security": "tls",
        "tlsSettings": { "certificates": [{ "certificateFile": "$VLIB/ssl_cert.pem", "keyFile": "$VLIB/ssl_key.pem" }] } },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] } },
    { "tag": "SHADOWSOCKS", "listen": "127.0.0.1", "port": 2388, "protocol": "shadowsocks",
      "settings": { "clients": [], "network": "tcp,udp" }, "streamSettings": { "network": "tcp" },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] } }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "DIRECT" }, { "protocol": "blackhole", "tag": "BLOCK" } ]
}
EOF

cat > "$XC/tunnel.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "tunnel-in", "listen": "0.0.0.0", "port": 9443, "protocol": "vless",
      "settings": { "clients": [ { "id": "${TUN_UUID}" } ], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "reality",
        "realitySettings": { "show": false, "dest": "www.cloudflare.com:443", "xver": 0, "serverNames": ["www.cloudflare.com"],
          "privateKey": "${TUN_PRIV}", "shortIds": ["${TUN_SID}"] } } }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF

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
XRAY_SUBSCRIPTION_URL_PREFIX=${SUB_PREFIX}
EOF

# ---------- 5) database: migrate (restore + repoint hosts) or fresh ----------
echo ">> [5/6] database (migrate=$MIGRATE) ..."
cd "$APP"
if [ "$MIGRATE" = 1 ] && [ -f /tmp/marzban-db.sqlite3 ]; then
  install -m640 /tmp/marzban-db.sqlite3 "$VLIB/db.sqlite3"
  .venv/bin/python - "$RELAY_IP" <<'PY'
import sqlite3,sys
ip=sys.argv[1]; c=sqlite3.connect('/var/lib/marzban/db.sqlite3')
for tag,port in {'VLESS_REALITY':443,'VMESS_TCP':8080,'TROJAN_TLS':8443,'SHADOWSOCKS':8388}.items():
    c.execute("update hosts set address=?, port=? where inbound_tag=?", (ip, port, tag))
c.execute("update hosts set allowinsecure=1 where inbound_tag='TROJAN_TLS'")
c.commit()
print("   restored", c.execute("select count(*) from users").fetchone()[0], "users; hosts -> "+ip)
c.close()
PY
  .venv/bin/alembic upgrade head >/dev/null 2>&1 || true
else
  .venv/bin/alembic upgrade head >/dev/null 2>&1 || true
  printf '\n\n\n' | SUDO_USERNAME="$ADMIN_USER" MARZBAN_ADMIN_PASSWORD="$ADMIN_PASS" \
    .venv/bin/python marzban-cli.py admin create -u "$ADMIN_USER" --sudo >/dev/null 2>&1 || true
fi

# validate xray configs before starting
"$XC/xray" -test -c "$XC/tunnel.json"        >/dev/null 2>&1 || { echo "ERROR: tunnel.json invalid"; exit 1; }
"$XC/xray" -test -c "$VLIB/xray_config.json" >/dev/null 2>&1 || { echo "ERROR: xray_config.json invalid"; exit 1; }

# ---------- 6) services ----------
echo ">> [6/6] starting marzban + xray-tunnel ..."
cat > /etc/systemd/system/${MZ}.service <<EOF
[Unit]
Description=Marzban (uv python3.12)
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
cat > /etc/systemd/system/xray-tunnel.service <<EOF
[Unit]
Description=xray tunnel-in (relay -> exit)
After=network.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$XC/xray run -c $XC/tunnel.json
Restart=always
RestartSec=5
LimitNOFILE=1048576
Environment=XRAY_LOCATION_ASSET=$XC
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now xray-tunnel >/dev/null 2>&1
systemctl enable --now ${MZ} >/dev/null 2>&1

# firewall: only the tunnel (9443) + panel/sub port need to be reachable from the relay
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
  ufw allow 9443/tcp >/dev/null 2>&1 || true
  ufw allow ${PANEL_PORT}/tcp >/dev/null 2>&1 || true
fi

# wait + verify the customer inbounds and tunnel actually bound
ok=""
for i in $(seq 1 30); do
  code=$(curl -s -k -o /dev/null -w '%{http_code}' --max-time 6 "https://127.0.0.1:${PANEL_PORT}/dashboard/" || true)
  case "$code" in 200|307|308) ok=1; break;; esac
  sleep 2
done
for i in $(seq 1 10); do ss -tln 2>/dev/null | grep -qE '127.0.0.1:2443 ' && break; sleep 1; done
ss -tln 2>/dev/null | grep -qE '127.0.0.1:2443 ' || { echo "ERROR: customer inbound 2443 not listening (Marzban xray_config not loaded)"; exit 1; }
ss -tln 2>/dev/null | grep -qE ':9443 '        || { echo "ERROR: tunnel-in 9443 not listening"; exit 1; }

echo "   marzban=$(systemctl is-active ${MZ}) tunnel=$(systemctl is-active xray-tunnel) panel=${ok:-0}"
echo "   listening: $(ss -tln 2>/dev/null | grep -oE ':(2443|2080|2843|2388|9443|'"${PANEL_PORT}"') ' | tr -d ' :' | sort -u | tr '\n' ' ')"
echo ">> exit ready"
echo "FLEET_RESULT={\"tun_uuid\":\"${TUN_UUID}\",\"tun_pub\":\"${TUN_PUB}\",\"tun_sid\":\"${TUN_SID}\",\"panel_port\":\"${PANEL_PORT}\",\"admin_user\":\"${ADMIN_USER}\",\"admin_pass\":\"${ADMIN_PASS}\",\"cust_sid\":\"${CSID}\"}"
