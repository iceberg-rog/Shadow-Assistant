#!/usr/bin/env bash
# Fleet Panel launcher (Linux / macOS)
set -euo pipefail
cd "$(dirname "$0")"

# 1) docker present?
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed. Install Docker, then re-run."; exit 1
fi
# 2) docker daemon running?
if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed but the daemon is NOT running."
  echo "Start Docker (e.g. 'sudo systemctl start docker' or open Docker Desktop), then re-run."
  exit 1
fi
# 3) compose plugin?
if ! docker compose version >/dev/null 2>&1; then
  echo "'docker compose' plugin not found. Install docker-compose-v2."; exit 1
fi

# 4) first-run .env
if [ ! -f .env ]; then
  ADMIN=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-16)
  SECRET=$(openssl rand -hex 16)
  printf 'DASH_ADMIN_PASS=%s\nFLASK_SECRET=%s\n' "$ADMIN" "$SECRET" > .env
  echo "Created .env  |  Dashboard password: $ADMIN"
fi

# 5) build + start
echo "Starting Fleet Panel (first build can take a few minutes)..."
docker compose up -d --build

# 6) verify it answers
PASS=$(sed -n 's/^DASH_ADMIN_PASS=//p' .env)
up=""
for i in $(seq 1 15); do
  if curl -s -o /dev/null -w '%{http_code}' http://localhost:8088/login 2>/dev/null | grep -q 200; then up=1; break; fi
  sleep 2
done
echo
if [ -n "$up" ]; then
  echo "Fleet Panel is up:  http://localhost:8088/login"
  echo "Login password:     $PASS"
else
  echo "Container started but the panel did not answer yet."
  echo "Check logs:  docker compose logs -f"
  echo "Password (in .env): $PASS"
fi
