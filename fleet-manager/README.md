# Fleet Manager

A single Windows `.exe` that provisions, migrates and monitors the VPN fleet —
so a swap no longer needs a shell session.

Build: `pyinstaller --onefile --name FleetManager --add-data "assets;assets" --collect-submodules paramiko app.py`
(`assets/` = a copy of `vpn-stack/` plus `installer/foreign-tunnel.sh`.)

- **core.py** — local SQLite state (servers / services / users / usage_log / events),
  SSH helpers, the app's own ed25519 key, and server-role probing.
  Role detection trusts geo when available (`countryCode == IR`); only when geo is
  blocked (typical inside Iran) does it fall back to "Iran-only sites answer fast".
- **engine.py** — the jobs: build a foreign exit (REALITY tunnel-in :9443), build an
  Iran relay (vpn-stack: OpenVPN + L2TP + panel), repoint, adopt an existing pair,
  push/pull users, and a six-point verification (tunnel, egress == exit IP, OpenVPN,
  panel, accounting, DNS).
- **app.py** — local web UI on 127.0.0.1 (dashboard + graphs, servers, build, users,
  migrate) with a live progress bar.

The DB is the source of truth: every account keeps its `used_bytes`, expiry and
device cap across a server replacement, including when the old box is already dead.
