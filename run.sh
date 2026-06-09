#!/usr/bin/env bash
# Fleet Panel launcher (Linux / macOS)
# Checks prerequisites (git, docker, docker compose) and auto-installs missing ones,
# then starts the panel.
set -uo pipefail
cd "$(dirname "$0")"

SUDO=""
[ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

pkg_install() {
  if   command -v apt-get >/dev/null 2>&1; then $SUDO apt-get update -qq && $SUDO apt-get install -y "$@"
  elif command -v dnf     >/dev/null 2>&1; then $SUDO dnf install -y "$@"
  elif command -v yum     >/dev/null 2>&1; then $SUDO yum install -y "$@"
  elif command -v pacman  >/dev/null 2>&1; then $SUDO pacman -Sy --noconfirm "$@"
  elif command -v zypper  >/dev/null 2>&1; then $SUDO zypper install -y "$@"
  elif command -v apk     >/dev/null 2>&1; then $SUDO apk add "$@"
  elif command -v brew    >/dev/null 2>&1; then brew install "$@"
  else echo "No supported package manager found; install $* manually." ; return 1; fi
}

# ---- git ----
if ! command -v git >/dev/null 2>&1; then
  echo ">> git not found - installing..."; pkg_install git || true
fi

# ---- docker ----
if ! command -v docker >/dev/null 2>&1; then
  echo ">> docker not found - installing..."
  pkg_install docker.io || pkg_install docker || {
    echo ">> falling back to get.docker.com"; curl -fsSL https://get.docker.com | $SUDO sh; }
  $SUDO systemctl enable --now docker 2>/dev/null || true
  # let the current user talk to docker without sudo (takes effect next login)
  [ -n "$SUDO" ] && $SUDO usermod -aG docker "$USER" 2>/dev/null || true
fi

# ---- docker compose plugin ----
if ! docker compose version >/dev/null 2>&1; then
  echo ">> installing docker compose plugin..."
  pkg_install docker-compose-v2 || pkg_install docker-compose-plugin || true
fi

# ---- pick docker invocation (handle 'need sudo' until re-login) ----
DOCKER="docker"
if ! docker info >/dev/null 2>&1; then
  if [ -n "$SUDO" ] && $SUDO docker info >/dev/null 2>&1; then
    DOCKER="$SUDO docker"
  else
    echo "Docker daemon not reachable. Start it ('$SUDO systemctl start docker') or re-login, then re-run."
    exit 1
  fi
fi

# ---- first-run .env ----
if [ ! -f .env ]; then
  ADMIN=$(openssl rand -base64 12 2>/dev/null | tr -d '/+=' | cut -c1-16)
  SECRET=$(openssl rand -hex 16 2>/dev/null)
  printf 'DASH_ADMIN_PASS=%s\nFLASK_SECRET=%s\n' "$ADMIN" "$SECRET" > .env
  echo "Created .env  |  Dashboard password: $ADMIN"
fi

# ---- build + start ----
echo "Starting Fleet Panel (first build can take a few minutes)..."
$DOCKER compose up -d --build

# ---- verify ----
PASS=$(sed -n 's/^DASH_ADMIN_PASS=//p' .env)
up=""
for i in $(seq 1 20); do
  if curl -s -o /dev/null -w '%{http_code}' http://localhost:8088/login 2>/dev/null | grep -q 200; then up=1; break; fi
  sleep 2
done
echo
if [ -n "$up" ]; then
  echo "Fleet Panel is up:  http://localhost:8088/login"
  echo "Login password:     $PASS"
else
  echo "Container started but the panel did not answer yet."
  echo "Check logs:  $DOCKER compose logs -f"
  echo "Password (in .env): $PASS"
fi
