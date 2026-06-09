#!/usr/bin/env bash
# Fleet Panel launcher (Linux / macOS)
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker not found. Install Docker, then re-run."; exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "'docker compose' plugin not found. Install docker-compose-v2."; exit 1
fi

if [ ! -f .env ]; then
  ADMIN=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-16)
  SECRET=$(openssl rand -hex 16)
  printf 'DASH_ADMIN_PASS=%s\nFLASK_SECRET=%s\n' "$ADMIN" "$SECRET" > .env
  echo "Created .env  |  Dashboard password: $ADMIN"
fi

echo "Starting Fleet Panel..."
docker compose up -d --build

PASS=$(sed -n 's/^DASH_ADMIN_PASS=//p' .env)
echo
echo "Fleet Panel is up:  http://localhost:8088/login"
echo "Login password:     $PASS"
