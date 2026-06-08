# 🛰️ Fleet Panel

A small self-hosted dashboard to provision a fleet of proxy servers (anti-censorship
VPN nodes) from one place. You add a server (IP + SSH access + role), and the panel
SSHes in, installs the stack, tests it, and hands back the node's panel URL + admin
credentials.

- **Foreign role** → exit + [Marzban](https://github.com/Gozargah/Marzban) panel
  (VLESS + REALITY, auto self-signed TLS). **Working & tested.**
- **Iran role** → domestic relay that forwards to a foreign exit. **Work in progress.**

Auth to target servers is **SSH-key based**: the panel holds one Ed25519 keypair and
never stores root passwords (an optional one-time password is used only to install the
key, then discarded).

---

## Quick start

> Run this on a machine **outside Iran** (Docker Hub is geo-blocked from Iranian IPs —
> see *Known limitations*).

```bash
git clone <your-repo-url> fleet-panel && cd fleet-panel
cp .env.example .env
# edit .env and set a strong DASH_ADMIN_PASS + FLASK_SECRET
docker compose up -d --build
```

Open `http://<host>:8088/login` and log in with `DASH_ADMIN_PASS`.

## Using it

1. Open **🔑 Public Key** and copy the dashboard's public key. Add it to each target
   server (your VPS provider's *SSH Keys*, or `~/.ssh/authorized_keys`). You can also
   skip this and just type the root password once when adding the server — the panel
   installs its key and discards the password.
2. **➕ New Server** → pick role:
   - **Foreign (exit + panel)** — installs Docker + Marzban, generates REALITY keys and
     a TLS cert, brings the panel up, and returns its URL + admin user/pass.
   - **Iran (relay)** — installs the relay and points it at a foreign exit (set the
     exit IP). *Auto-tunnel linking is still being finalized.*
3. Watch the **live log**. On success the node shows `ready` plus the panel URL and
   admin credentials.

> Order matters: provision the **foreign exit first**, then the **Iran relay**.

---

## Layout

| Path | What |
|------|------|
| `app.py` | Flask dashboard (server list, add/provision, live log, key auth) |
| `installer/foreign.sh` | Foreign exit installer (Marzban + REALITY + TLS) |
| `installer/iran.sh` | Iran relay installer (WIP) |
| `Dockerfile`, `docker-compose.yml` | Containerized deploy |
| `data/` | Runtime state: SSH keypair, sqlite DB, logs — **never commit** |

## Security

- The dashboard holds the **private SSH key to your whole fleet**. Keep it behind a
  firewall / TLS / restricted access. Don't expose port 8088 to the open internet
  long-term.
- `data/` contains the private key and database — it's git-ignored. Don't commit it.
- Stored target credentials: none (key-based; one-time passwords are discarded).

## Known limitations

- **Iran Docker geo-block:** Iranian server IPs can't pull from Docker Hub (HTTP 403).
  Run the dashboard itself outside Iran. For Iran *relay* nodes the installer pulls
  Xray from GitHub releases instead of Docker.
- **Iran relay auto-tunnel** is not finished yet.
- Marzban panels use a **self-signed cert**, so browsers show a warning (proceed
  anyway). Point a domain at a node to switch to a real certificate.

## Disclaimer

For deploying onto **servers you own or are authorized to manage**. You are responsible
for complying with the laws and terms that apply to you.
