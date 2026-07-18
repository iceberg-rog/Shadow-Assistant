#!/bin/bash
# ==========================================================================
# installer/restore-fleet.sh
# Restore a fleet-backup.tar.gz (from the panel's "Download fleet backup", or
# /opt/fleet-backups on the relay) onto a freshly installed server, so all
# users keep their consumed data + remaining days.
#
#   RELAY:  restores /opt/ovpnpanel/users.json  (OpenVPN/L2TP users + usage + expiry)
#   EXIT :  restores /var/lib/marzban/db.sqlite3 (v2ray users + usage + expiry)
#           and repoints the Marzban hosts back at the relay IP.
#
# Usage:
#   ROLE=relay BACKUP=fleet-backup.tar.gz bash installer/restore-fleet.sh
#   ROLE=exit  BACKUP=fleet-backup.tar.gz RELAY_IP=<relay ip> bash installer/restore-fleet.sh
# ==========================================================================
set -euo pipefail
ROLE="${ROLE:?set ROLE=relay or exit}"
BACKUP="${BACKUP:?set BACKUP=path to fleet-backup.tar.gz}"
[ -f "$BACKUP" ] || { echo "backup not found: $BACKUP"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
tar xzf "$BACKUP" -C "$TMP"

if [ "$ROLE" = relay ]; then
  [ -f "$TMP/users.json" ] || { echo "no users.json in backup"; exit 1; }
  mkdir -p /opt/ovpnpanel
  install -m600 "$TMP/users.json" /opt/ovpnpanel/users.json
  rm -f /run/vpn-acct-last.json
  systemctl restart vpn-accounting ovpn-panel 2>/dev/null || true
  echo ">> restored $(python3 -c "import json;print(len(json.load(open('/opt/ovpnpanel/users.json'))))") VPN users (with usage + expiry)"

elif [ "$ROLE" = exit ]; then
  RELAY_IP="${RELAY_IP:?set RELAY_IP so the Marzban hosts point back at the relay}"
  [ -f "$TMP/marzban-db.sqlite3" ] || { echo "no marzban-db.sqlite3 in backup"; exit 1; }
  MZ=marzban62; systemctl list-units --type=service 2>/dev/null | grep -q marzban62 || MZ=marzban
  systemctl stop "$MZ" 2>/dev/null || true
  install -m640 "$TMP/marzban-db.sqlite3" /var/lib/marzban/db.sqlite3
  python3 - "$RELAY_IP" <<'PY'
import sqlite3,sys
ip=sys.argv[1]; c=sqlite3.connect('/var/lib/marzban/db.sqlite3')
for tag,port in {'VLESS_REALITY':443,'VMESS_TCP':8080,'TROJAN_TLS':8443,'SHADOWSOCKS':8388}.items():
    c.execute("update hosts set address=?, port=? where inbound_tag=?", (ip, port, tag))
c.execute("update hosts set allowinsecure=1 where inbound_tag='TROJAN_TLS'")
c.commit()
print(">> restored", c.execute("select count(*) from users").fetchone()[0], "v2ray users; hosts -> "+ip)
PY
  systemctl start "$MZ" 2>/dev/null || true
else
  echo "ROLE must be 'relay' or 'exit'"; exit 1
fi
