# 🛰️ Fleet Panel

A small self-hosted dashboard to provision a fleet of proxy servers (anti-censorship
VPN nodes) from one place. You add a server (IP + SSH access + role), and the panel
SSHes in, installs the stack, tests it, and hands back the node's panel URL + admin
credentials.

- **Foreign role** → exit + [Marzban](https://github.com/Gozargah/Marzban) panel with
  **four customer inbounds** — VLESS+REALITY (443), VMess (8080), Trojan+TLS (8443),
  Shadowsocks (8388) — kernel tuning (BBR + big UDP buffers), and **both** tunnel
  receivers: a **Hysteria2 server** (UDP 9444, the fast path) and a **REALITY-TCP
  receiver** (9443, the always-works fallback). **Working & tested.**
- **Iran role** → domestic relay that **auto-picks the best tunnel**. It captures each
  customer port and, after *probing* whether this ISP lets a sustained UDP flow survive,
  ships traffic to the exit over **Hysteria2** (UDP — beats per-flow TCP throttling, much
  faster) or falls back to a **VLESS+REALITY** TCP tunnel when UDP is filtered. Either way
  the hop looks like TLS to Cloudflare so *every* protocol passes DPI, and all four are
  auto-linked in Marzban so customer configs point at the relay IP. **Working & tested.**

Auth to target servers is **SSH-key based**: the panel holds one Ed25519 keypair and
never stores root passwords (an optional one-time password is used only to install the
key, then discarded).

---

## Quick start

Needs **Docker** (Docker Desktop on Windows/macOS, Docker Engine on Linux). The
launcher creates a `.env` with a random admin password on first run, builds the
image, starts the panel, and prints the login.

> Run this on a machine **outside Iran** (Docker Hub is geo-blocked from Iranian IPs —
> see *Known limitations*).

```bash
git clone https://github.com/iceberg-rog/Shadow-Assistant.git
cd Shadow-Assistant
```

**Windows** — double-click `run.bat`, or in PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File run.ps1
```

**Linux / macOS:**
```bash
chmod +x run.sh && ./run.sh
```

Either way the panel comes up at **http://localhost:8088/login**. The launcher prints
the admin password (also stored in `.env`).

Manual alternative (any OS): `cp .env.example .env`, edit it, then
`docker compose up -d --build`.

## Using it

1. Open **🔑 Public Key** and copy the dashboard's public key. Add it to each target
   server (your VPS provider's *SSH Keys*, or `~/.ssh/authorized_keys`). You can also
   skip this and just type the root password once when adding the server — the panel
   installs its key and discards the password.
2. **➕ New Server** → pick role:
   - **Foreign (exit + panel)** — installs Docker + Marzban, generates REALITY keys and
     a TLS cert, brings the panel up, and returns its URL + admin user/pass.
   - **Iran (relay)** — installs a transparent relay pointing at a foreign exit (set the
     exit IP), verifies forwarding, then auto-adds a Marzban Host so issued configs use
     the relay's fast domestic IP.
3. Watch the **live log**. On success the node shows `ready` plus the panel URL and
   admin credentials.

> Order matters: provision the **foreign exit first**, then the **Iran relay**.

---

## Layout

| Path | What |
|------|------|
| `app.py` | Flask dashboard (server list, add/provision, live log, key auth) |
| `installer/foreign.sh` | Foreign exit installer (Marzban + REALITY + TLS) |
| `installer/iran.sh` | Iran relay installer (transparent forward + Marzban auto-link) |
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
- Marzban panels use a **self-signed cert**, so browsers show a warning (proceed
  anyway). Point a domain at a node to switch to a real certificate.

## Disclaimer

For deploying onto **servers you own or are authorized to manage**. You are responsible
for complying with the laws and terms that apply to you.
