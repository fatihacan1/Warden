#!/bin/sh
# Prepares a Warden test server: finds the public IP, derives the sslip.io
# host name and writes .env with freshly generated secrets.
#
#   ./init.sh                      detect the public IP automatically
#   PUBLIC_IP=203.0.113.10 ./init.sh   use this IP instead
#   PUBLIC_HOST=auth.example.com ./init.sh   use your own domain instead
#   FORCE=1 ./init.sh              overwrite an existing .env (data stays encrypted with the OLD key!)
set -eu

cd "$(dirname "$0")"

if [ -f .env ] && [ "${FORCE:-}" != "1" ]; then
  echo ".env already exists. Keep it (the database is encrypted with its keys) or run FORCE=1 ./init.sh." >&2
  exit 1
fi

# --- random values ----------------------------------------------------------
# base64 of 32 random bytes; falls back to /dev/urandom when openssl is missing.
rand_b64() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32
  else
    head -c 32 /dev/urandom | base64
  fi
}
# URL safe token without padding.
rand_token() { rand_b64 | tr '+/' '-_' | tr -d '=\n'; }
rand_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16
  else
    head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# --- public address ---------------------------------------------------------
if [ -z "${PUBLIC_HOST:-}" ]; then
  ip="${PUBLIC_IP:-}"
  if [ -z "$ip" ]; then
    for url in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
      ip="$(curl -fsS --max-time 5 "$url" 2>/dev/null | tr -d ' \r\n' || true)"
      case "$ip" in
        *[!0-9.]* | "") ip="" ;;
        *) break ;;
      esac
    done
  fi
  if [ -z "$ip" ]; then
    echo "Could not detect the public IPv4 address. Run: PUBLIC_IP=<your ip> ./init.sh" >&2
    exit 1
  fi
  case "$ip" in
    *.*.*.*) ;;
    *) echo "'$ip' is not an IPv4 address." >&2; exit 1 ;;
  esac
  PUBLIC_HOST="$(echo "$ip" | tr '.' '-').sslip.io"
fi

pg_password="$(rand_hex)"

umask 077
cat > .env <<EOF
# Written by init.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Keep it private, never commit it.
# Back up ENCRYPTION_KEY: without it the encrypted data in the database is lost.

# Used by docker-compose.yml (Caddy certificate and Postgres container).
PUBLIC_HOST=${PUBLIC_HOST}
POSTGRES_PASSWORD=${pg_password}

# --- Warden ---
APP_ENV=production
LOG_FORMAT=json
HTTP_PUBLIC_URL=https://${PUBLIC_HOST}
HTTP_COOKIE_SECURE=true
# Only the Caddy container (fixed address 172.28.0.10 in docker-compose.yml) may set the client IP.
HTTP_TRUSTED_PROXIES=172.28.0.10/32

# sslmode=disable is fine only because Postgres sits on the private compose network.
# A remote or managed database needs sslmode=require.
DATABASE_URL=postgres://warden:${pg_password}@postgres:5432/warden?sslmode=disable
REDIS_URL=redis://redis:6379/0
RABBITMQ_URL=

ENCRYPTION_KEY=$(rand_b64)
ADMIN_TOKEN=$(rand_token)
# Acceptable only because docker-compose.yml binds the admin port to 127.0.0.1 and
# you reach it through an SSH tunnel over plain http://localhost. If you ever
# expose the admin UI over the network, serve it over HTTPS and set this to true.
ADMIN_COOKIE_SECURE=false

# No SMTP provider needed: emails are stored encrypted and shown in the admin
# UI under Inbox. Users do not receive them. See docs/test-server.md.
MAIL_DELIVERY=inbox

# Where your test app lives. Change these in the admin UI (Settings) later.
HTTP_CORS_ALLOWED_ORIGINS=http://localhost:3000
AUTH_ALLOWED_REDIRECT_URIS=http://localhost:3000/auth/callback
AUTH_VERIFY_EMAIL_URL=http://localhost:3000/verify-email?token={token}
AUTH_RESET_PASSWORD_URL=http://localhost:3000/reset-password?token={token}
EOF

echo "Wrote $(pwd)/.env"
echo
echo "  Public URL : https://${PUBLIC_HOST}"
echo "  Admin token: $(grep '^ADMIN_TOKEN=' .env | cut -d= -f2-)"
echo
echo "Next: docker compose up -d --build"
echo "Admin UI (from your computer): ssh -L 9090:127.0.0.1:9090 <user>@<server>  then http://localhost:9090"
