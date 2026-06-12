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

# --- 2) AUTO-DETECT the best tunnel: Hysteria(QUIC) -> mKCP(plain UDP) -> REALITY-TCP ---
# Iran filters QUIC specifically (so Hysteria can connect then collapse), but many ISPs still
# pass plain UDP, and TLS-over-TCP to a clean IP is never protocol-dropped. We probe each tier
# with a real ~8MB sustained transfer and use the fastest that survives.
MODE="reality"   # safe default (TCP is never UDP-filtered)

probe_socks(){   # $1 = local socks port ; echoes bytes pulled through an ~8MB sustained transfer
  curl -s --max-time 15 -x socks5h://127.0.0.1:$1 -o /dev/null \
    -w '%{size_download}' "https://speed.cloudflare.com/__down?bytes=8000000" 2>/dev/null || echo 0
}

# Tier 1 — Hysteria2 (UDP/QUIC): fastest where the ISP allows a sustained QUIC flow.
if [ -n "${HY_AUTH:-}" ] && [ -n "${HY_OBFS:-}" ] && install_hysteria; then
  echo ">> probing Tier 1: Hysteria/QUIC -> ${EXIT_IP}:${HY_PORT} ..."
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
  for i in $(seq 1 12); do ss -tln 2>/dev/null | grep -q '127.0.0.1:1080' && break; sleep 1; done
  HB=0; ss -tln 2>/dev/null | grep -q '127.0.0.1:1080' && HB=$(probe_socks 1080)
  if [ "${HB:-0}" -gt 6500000 ]; then
    MODE="hysteria"; systemctl enable hysteria-client >/dev/null 2>&1
    echo ">> Tier 1 Hysteria WORKS (${HB} bytes sustained) — using the QUIC fast path."
  else
    systemctl disable --now hysteria-client >/dev/null 2>&1 || true
    echo ">> Tier 1 Hysteria filtered/unreliable (${HB} bytes) — trying mKCP."
  fi
fi

# Tier 2 — mKCP (plain non-QUIC UDP): survives QUIC-filtering ISPs that still pass plain UDP.
if [ "$MODE" = "reality" ] && [ -n "${MK_UUID:-}" ] && [ -n "${MK_SEED:-}" ]; then
  echo ">> probing Tier 2: mKCP/plain-UDP -> ${EXIT_IP}:${MK_PORT:-9445} ..."
  mkdir -p /usr/local/etc/xray
  cat > /usr/local/etc/xray/probe-mkcp.json <<EOF
{ "log": { "loglevel": "none" },
  "inbounds": [ { "listen": "127.0.0.1", "port": 1081, "protocol": "socks", "settings": { "udp": false } } ],
  "outbounds": [ { "protocol": "vless", "settings": { "vnext": [ { "address": "${EXIT_IP}", "port": ${MK_PORT:-9445}, "users": [ { "id": "${MK_UUID}", "encryption": "none" } ] } ] }, "streamSettings": { "network": "mkcp", "kcpSettings": { "mtu": 1350, "tti": 50, "uplinkCapacity": 100, "downlinkCapacity": 100, "congestion": true, "readBufferSize": 2, "writeBufferSize": 2, "header": { "type": "dtls" }, "seed": "${MK_SEED}" } } } ]
}
EOF
  setsid /usr/local/bin/xray run -c /usr/local/etc/xray/probe-mkcp.json >/dev/null 2>&1 </dev/null & MP=$!
  sleep 3
  MB=0; ss -tln 2>/dev/null | grep -q '127.0.0.1:1081' && MB=$(probe_socks 1081)
  kill "$MP" 2>/dev/null; pkill -f probe-mkcp.json 2>/dev/null; rm -f /usr/local/etc/xray/probe-mkcp.json
  if [ "${MB:-0}" -gt 6500000 ]; then
    MODE="mkcp"; echo ">> Tier 2 mKCP WORKS (${MB} bytes sustained) — using the plain-UDP fast path."
  else
    echo ">> Tier 2 mKCP filtered/unreliable (${MB} bytes) — falling back to REALITY-TCP."
  fi
fi
[ "$MODE" = "reality" ] && echo ">> Using Tier 3: REALITY-TCP (always works; TCP isn't UDP-filtered)."

# --- 3) relay xray config: dokodemo inbounds -> the chosen tunnel outbound ---
mkdir -p /usr/local/etc/xray
if [ "$MODE" = "hysteria" ]; then
  TUNNEL_OUT='{ "tag": "tunnel", "protocol": "socks", "settings": { "servers": [ { "address": "127.0.0.1", "port": 1080 } ] } }'
elif [ "$MODE" = "mkcp" ]; then
  TUNNEL_OUT='{ "tag": "tunnel", "protocol": "vless", "settings": { "vnext": [ { "address": "'"${EXIT_IP}"'", "port": '"${MK_PORT:-9445}"', "users": [ { "id": "'"${MK_UUID}"'", "encryption": "none" } ] } ] }, "streamSettings": { "network": "mkcp", "kcpSettings": { "mtu": 1350, "tti": 50, "uplinkCapacity": 100, "downlinkCapacity": 100, "congestion": true, "readBufferSize": 2, "writeBufferSize": 2, "header": { "type": "dtls" }, "seed": "'"${MK_SEED}"'" } } }'
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

# --- 7) failover monitor: if we landed on a fast UDP tier, install a watchdog that
#         auto-demotes to REALITY-TCP when that path collapses (Iran tightening QUIC/UDP) and
#         promotes back when it recovers. Probes SUSTAINED egress (not just connect) and
#         validates the target config before any restart, so it can only restore a broken
#         state, never disrupt a working one. REALITY-only relays need no watchdog. ---
MON="none"
if [ "$MODE" != "reality" ]; then
  cat > /usr/local/bin/fleet-monitor.sh <<EOF
#!/bin/bash
EXIT="${EXIT_IP}"
PRIMARY="${MODE}"
MK_UUID="${MK_UUID:-}"
MK_SEED="${MK_SEED:-}"
MK_PORT="${MK_PORT:-9445}"
TUN_UUID="${TUN_UUID}"
TUN_PUB="${TUN_PUB}"
TUN_SID="${TUN_SID}"
EOF
  cat >> /usr/local/bin/fleet-monitor.sh <<'MONEOF'
set -u
CFG=/usr/local/etc/xray/config.json
XRAY=/usr/local/bin/xray
S=/var/lib/fleet-monitor
FAIL_TH=3; OK_TH=3; COOLDOWN=600
mkdir -p "$S"
log(){ echo "$(date -u +%FT%TZ) $*" >> "$S/monitor.log"; }
current_tier(){ python3 -c "import json;c=json.load(open('$CFG'));o=[x for x in c['outbounds'] if x.get('tag')=='tunnel'][0];p=o.get('protocol');n=o.get('streamSettings',{}).get('network');print('hysteria' if p=='socks' else ('mkcp' if n=='mkcp' else 'reality'))" 2>/dev/null; }
probe_primary(){
  local sock ip ep pid=""
  if [ "$PRIMARY" = "hysteria" ]; then sock=1080
  else
    cat > "$S/probe.json" <<JSON
{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":19090,"protocol":"socks","settings":{"udp":false}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"$EXIT","port":$MK_PORT,"users":[{"id":"$MK_UUID","encryption":"none"}]}]},"streamSettings":{"network":"mkcp","kcpSettings":{"mtu":1350,"tti":50,"uplinkCapacity":100,"downlinkCapacity":100,"congestion":true,"readBufferSize":2,"writeBufferSize":2,"header":{"type":"dtls"},"seed":"$MK_SEED"}}}]}
JSON
    pkill -f "$S/probe.json" 2>/dev/null; sleep 1
    setsid "$XRAY" run -c "$S/probe.json" >/dev/null 2>&1 </dev/null & pid=$!; sleep 3; sock=19090
  fi
  local rc=1
  for ep in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    ip=$(curl -s --socks5 "127.0.0.1:$sock" --max-time 8 "$ep" 2>/dev/null | tr -d '[:space:]')
    [ "$ip" = "$EXIT" ] && { rc=0; break; }
  done
  [ -n "$pid" ] && { kill "$pid" 2>/dev/null; pkill -f "$S/probe.json" 2>/dev/null; }
  return $rc
}
set_tier(){
  cp "$CFG" "$CFG.monbak.$(date +%s)"
  MON_T="$1" MON_P="$PRIMARY" MEXIT="$EXIT" MMU="$MK_UUID" MMS="$MK_SEED" MMP="$MK_PORT" MTU="$TUN_UUID" MTP="$TUN_PUB" MTS="$TUN_SID" python3 - <<'PY'
import json,os
p="/usr/local/etc/xray/config.json"; c=json.load(open(p)); E=os.environ
t=E["MON_T"]; pr=E["MON_P"]
for ob in c["outbounds"]:
    if ob.get("tag")=="tunnel":
        if t=="primary" and pr=="hysteria":
            ob["protocol"]="socks"; ob["settings"]={"servers":[{"address":"127.0.0.1","port":1080}]}; ob.pop("streamSettings",None)
        elif t=="primary" and pr=="mkcp":
            ob["protocol"]="vless"; ob["settings"]={"vnext":[{"address":E["MEXIT"],"port":int(E["MMP"]),"users":[{"id":E["MMU"],"encryption":"none"}]}]}
            ob["streamSettings"]={"network":"mkcp","kcpSettings":{"mtu":1350,"tti":50,"uplinkCapacity":100,"downlinkCapacity":100,"congestion":True,"readBufferSize":2,"writeBufferSize":2,"header":{"type":"dtls"},"seed":E["MMS"]}}
        else:
            ob["protocol"]="vless"; ob["settings"]={"vnext":[{"address":E["MEXIT"],"port":9443,"users":[{"id":E["MTU"],"encryption":"none"}]}]}
            ob["streamSettings"]={"network":"tcp","security":"reality","realitySettings":{"serverName":"www.cloudflare.com","fingerprint":"chrome","publicKey":E["MTP"],"shortId":E["MTS"]}}
json.dump(c,open(p,"w"),indent=2)
PY
  if "$XRAY" -test -config "$CFG" >/dev/null 2>&1; then systemctl restart xray-relay; sleep 2; return 0
  else cp "$(ls -t $CFG.monbak.* | head -1)" "$CFG"; return 1; fi
}
now=$(date +%s); last=$(cat "$S/last_switch" 2>/dev/null||echo 0); in_cd=0; [ $((now-last)) -lt $COOLDOWN ] && in_cd=1
CUR=$(current_tier); [ -z "$CUR" ] && exit 0
if [ "$CUR" != "reality" ]; then
  if probe_primary; then echo 0 > "$S/fail"; log "OK $CUR healthy"
  else f=$(( $(cat "$S/fail" 2>/dev/null||echo 0)+1 )); echo "$f" > "$S/fail"; log "MISS $CUR ($f/$FAIL_TH)"
    if [ "$f" -ge "$FAIL_TH" ] && [ "$in_cd" = 0 ]; then set_tier reality && { log "SWITCH $CUR->reality (collapsed)"; echo 0 > "$S/fail"; date +%s > "$S/last_switch"; } || log "SWITCH-FAIL"; fi
  fi
else
  if probe_primary; then o=$(( $(cat "$S/ok" 2>/dev/null||echo 0)+1 )); echo "$o" > "$S/ok"; log "RECOVER $PRIMARY ($o/$OK_TH)"
    if [ "$o" -ge "$OK_TH" ] && [ "$in_cd" = 0 ]; then set_tier primary && { log "SWITCH reality->$PRIMARY (recovered)"; echo 0 > "$S/ok"; date +%s > "$S/last_switch"; }; fi
  else echo 0 > "$S/ok"; log "HOLD on reality"; fi
fi
MONEOF
  chmod +x /usr/local/bin/fleet-monitor.sh
  ( crontab -l 2>/dev/null | grep -v fleet-monitor; echo '*/2 * * * * /usr/local/bin/fleet-monitor.sh' ) | crontab -
  MON="active"
  echo "failover monitor installed (primary=${MODE} -> REALITY fallback; cron every 2 min)"
fi

echo "FLEET_RESULT={\"role\":\"iran-relay\",\"relay_ip\":\"${SERVER_IP}\",\"exit_ip\":\"${EXIT_IP}\",\"tunnel\":\"${MODE}\",\"forwarding\":\"${FWD}\",\"failover_monitor\":\"${MON}\",\"note\":\"Auto-selected ${MODE} tunnel (Hysteria>mKCP>REALITY ladder). All 4 protocols route through ${SERVER_IP}; Marzban Hosts auto-point customer configs here. Failover watchdog: ${MON}.\"}"
