#!/bin/bash
# ==========================================================================
# installer/repoint-exit.sh
# Repoint this Iran RELAY to a NEW foreign EXIT in one shot. Updates, on the
# relay:
#   1) the customer v2ray/xray tunnel outbound   (/usr/local/etc/xray/config.json)
#   2) the sub-forward target                    (/usr/local/bin/sub-forward.py)
#   3) the OpenVPN/L2TP VPN-stack tunnel outbound (/usr/local/etc/xray/config-ovpn.json)
#   4) the egress routing RETURN list            (/usr/local/sbin/ovpn-route-up.sh)
# then validates and restarts. Run whenever the exit is swapped (exits burn
# every few days). The new tunnel params come from the exit build (foreign.sh).
#
# Usage:
#   EXIT_IP=<new exit ip> TUN_UUID=<uuid> TUN_PUB=<reality pubkey> TUN_SID=<short id> \
#   [SUB_PORT=39196] [DRYRUN=1] bash installer/repoint-exit.sh
# ==========================================================================
set -euo pipefail
EXIT_IP="${EXIT_IP:?set EXIT_IP=the new exit IP}"
TUN_UUID="${TUN_UUID:?set TUN_UUID (new tunnel uuid, from the exit build)}"
TUN_PUB="${TUN_PUB:?set TUN_PUB (new tunnel REALITY public key)}"
TUN_SID="${TUN_SID:?set TUN_SID (new tunnel REALITY short id)}"
SUB_PORT="${SUB_PORT:-39196}"
DRYRUN="${DRYRUN:-0}"

RELAY_CFG=/usr/local/etc/xray/config.json
OVPN_CFG=/usr/local/etc/xray/config-ovpn.json
ALT_CFG=/usr/local/etc/xray/config-alt.json   # alt customer ports (2053/2083/2052/8880)

getaddr(){ python3 -c "import json,sys
try:c=json.load(open(sys.argv[1]))
except Exception:sys.exit(0)
print(next((o['settings']['vnext'][0]['address'] for o in c.get('outbounds',[]) if o.get('tag')=='tunnel'),''))" "$1" 2>/dev/null || true; }

OLD_EXIT=$(getaddr "$OVPN_CFG"); [ -z "$OLD_EXIT" ] && OLD_EXIT=$(getaddr "$RELAY_CFG")
echo ">> repoint relay: ${OLD_EXIT:-?} -> $EXIT_IP  (uuid ${TUN_UUID:0:8}..)"

repoint_tunnel(){  # $1 = xray config file with a 'tunnel' outbound
  [ -f "$1" ] || return 0
  python3 - "$1" <<PY
import json,sys
p=sys.argv[1]
try: c=json.load(open(p))
except Exception: sys.exit(0)
ch=False
for ob in c.get("outbounds",[]):
    if ob.get("tag")=="tunnel":
        v=ob["settings"]["vnext"][0]; v["address"]="$EXIT_IP"; v["port"]=9443
        v["users"][0]["id"]="$TUN_UUID"
        rs=ob["streamSettings"]["realitySettings"]; rs["publicKey"]="$TUN_PUB"; rs["shortId"]="$TUN_SID"
        ch=True
if ch:
    json.dump(c,open(p,"w"),indent=2); print("  updated",p)
PY
}

if [ "$DRYRUN" = 1 ]; then
  echo "(dry-run) would repoint customer tunnel + sub-forward + VPN-stack tunnel + routing to $EXIT_IP:9443"
  exit 0
fi

repoint_tunnel "$RELAY_CFG"
repoint_tunnel "$OVPN_CFG"
repoint_tunnel "$ALT_CFG"
if [ -f /usr/local/bin/sub-forward.py ]; then
  sed -i -E "s/TARGET[[:space:]]*=[[:space:]]*\([^)]*\)/TARGET=('$EXIT_IP',$SUB_PORT)/" /usr/local/bin/sub-forward.py && echo "  updated sub-forward -> $EXIT_IP:$SUB_PORT"
fi
if [ -n "$OLD_EXIT" ] && [ -f /usr/local/sbin/ovpn-route-up.sh ]; then
  sed -i "s#${OLD_EXIT}/32#${EXIT_IP}/32#g" /usr/local/sbin/ovpn-route-up.sh && echo "  updated routing RETURN list"
fi

echo ">> validating configs"
/usr/local/bin/xray -test -c "$RELAY_CFG" >/dev/null && echo "  relay config OK"
[ -f "$OVPN_CFG" ] && { /usr/local/bin/xray -test -c "$OVPN_CFG" >/dev/null && echo "  vpn-stack config OK"; }
[ -f "$ALT_CFG" ] && { /usr/local/bin/xray -test -c "$ALT_CFG" >/dev/null && echo "  alt-ports config OK"; }

echo ">> restarting (old exit is dead anyway; clients auto-reconnect to the new exit)"
systemctl restart xray-relay
systemctl restart xray-relay-alt 2>/dev/null || true
systemctl restart sub-forward 2>/dev/null || true
systemctl restart xray-ovpn 2>/dev/null || true
[ -f /usr/local/sbin/ovpn-route-up.sh ] && bash /usr/local/sbin/ovpn-route-up.sh 2>/dev/null || true
sleep 3

echo ">> DONE. relay=$(systemctl is-active xray-relay) vpn-ovpn=$(systemctl is-active xray-ovpn 2>/dev/null||echo n/a)"
timeout 6 bash -c "</dev/tcp/$EXIT_IP/9443" 2>/dev/null && echo ">> tunnel port $EXIT_IP:9443 reachable" || echo ">> WARNING: $EXIT_IP:9443 not reachable yet"
