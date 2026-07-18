# Fleet migration & backup

The fleet has two user databases, both carrying **users + consumed data + remaining days**:

| where | file | what |
|-------|------|------|
| **exit**  | `/var/lib/marzban/db.sqlite3` | v2ray customers (VLESS/VMess/Trojan/SS) |
| **relay** | `/opt/ovpnpanel/users.json`   | OpenVPN + L2TP users |

## Automatic backup (already running)

- The **exit** pushes its Marzban DB to the **relay** every 15 min over a locked-down
  SSH key (forced command, can only drop the backup file) → `/opt/fleet-backups/marzban-db.sqlite3`.
- The **relay** snapshots its own `users.json` every 15 min → `/opt/fleet-backups/users.json`.
- The panel serves the whole state as one file: **Panel → "Download fleet backup"**
  (`https://<relay>:2098/backup`) → `fleet-backup.tar.gz`.

So the state survives even a sudden exit burn. Keep an occasional copy of
`fleet-backup.tar.gz` off-server (one click) for the "both servers change" case.

## Changing the EXIT only (most common — exits burn every few days)

1. Build the new exit (native uv Marzban + xray 26.3.27 + tunnel-in :9443 +
   localhost customer inbounds) — `foreign-exit.sh` (also driven by the provisioning
   dashboard). It generates a fresh tunnel keypair and reuses the fleet's customer
   REALITY identity, so distributed customer configs keep working across the swap.
2. Restore the customers with their usage/expiry onto it:
   ```bash
   ROLE=exit BACKUP=fleet-backup.tar.gz RELAY_IP=<relay ip> bash installer/restore-fleet.sh
   ```
   (grab `fleet-backup.tar.gz` from the panel, or copy `/opt/fleet-backups/` off the relay)
3. Repoint the relay at the new exit (customer tunnel + sub-forward + VPN tunnel + routing):
   ```bash
   EXIT_IP=<new exit> TUN_UUID=<..> TUN_PUB=<..> TUN_SID=<..> bash installer/repoint-exit.sh
   ```
   The relay's OpenVPN/L2TP users are untouched (relay didn't change).

## Changing the RELAY only

1. Build the new relay: `iran.sh` then `vpn-stack/install.sh` (with the exit's tunnel params).
2. Restore the VPN users with usage/expiry:
   ```bash
   ROLE=relay BACKUP=fleet-backup.tar.gz bash installer/restore-fleet.sh
   ```

## Changing BOTH servers

Do the EXIT steps (build + `restore-fleet.sh ROLE=exit`) and the RELAY steps
(`iran.sh` + `vpn-stack/install.sh` + `restore-fleet.sh ROLE=relay`), then wire the
relay↔exit tunnel with the exit's fresh tunnel params. One `fleet-backup.tar.gz`
carries every account, its used data, and its remaining days across the move.
