# Try Warden on a test server

No domain, no SMTP provider, about five minutes. You get a real HTTPS address, a private admin UI and an Inbox that shows every email Warden would send.

This is for testing. Users do not receive emails in this setup (see [Emails](#emails)). For real users use a domain and an SMTP provider: [production.md](production.md).

## On a fresh Ubuntu VPS

```bash
# 1. Docker
curl -fsSL https://get.docker.com | sh

# 2. Warden
git clone https://github.com/fatihacan1/warden.git
cd warden/deploy/test-server

# 3. Secrets and address (finds the server's public IP)
./init.sh

# 4. Start (first run builds the image, a couple of minutes)
docker compose up -d --build
```

`init.sh` prints your address, for example `https://203-0-113-10.sslip.io`, and the admin token. Caddy gets a Let's Encrypt certificate for that name on first start, which takes under a minute. Check with `curl https://203-0-113-10.sslip.io/healthz`.

Ports 80 and 443 must be open to the internet (a cloud firewall or security group counts). Nothing else is.

## Open the admin UI

The admin UI is not on the internet. It listens on `127.0.0.1:9090` of the server. From your computer:

```bash
ssh -L 9090:127.0.0.1:9090 user@your-server
```

Then open http://localhost:9090 and sign in with the admin token (it is `ADMIN_TOKEN` in `deploy/test-server/.env`).

## Emails

`MAIL_DELIVERY=inbox` is set for you. Warden does not send anything: every email (verification, password reset, security notices) is stored encrypted and listed under **Inbox** in the admin UI, with the one-time link ready to copy. A banner on every admin page reminds you.

Sign up through your app, open Inbox, click the verification link. Emails are kept for 7 days, at most 500.

**Want real delivery?** Pick one in `.env`, then `docker compose up -d`:

| Setting | Result |
| --- | --- |
| `MAIL_DELIVERY=direct` | Warden sends straight to the recipient's mail server on port 25, like Dokploy does. Works only if your host allows outbound port 25 (most clouds block it) and the mail will probably land in spam without SPF, DKIM and reverse DNS. Check what happens with `docker compose exec warden /warden mail-test you@example.com` |
| `MAIL_DELIVERY=smtp` plus `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` | Any SMTP provider. The reliable choice |

The inbox keeps working only in `inbox` mode. Switching to `direct` or `smtp` stops new emails from landing there.

## Point your app at it

Your app talks to `https://<ip-with-dashes>.sslip.io` (the token issuer, `/v1/...` API and JWKS). Add your app's origin and redirect URIs in the admin UI under **Settings**. The defaults in `.env` allow `http://localhost:3000`. A browser app on another origin needs `HTTP_CORS_ALLOWED_ORIGINS`.

## Security notes

- **sslip.io is a third-party DNS service.** It answers `203-0-113-10.sslip.io` with `203.0.113.10`. If it goes down or is hijacked, your name stops working or points elsewhere. Fine for tests.
- **The certificate is public.** Let's Encrypt logs every certificate in public Certificate Transparency logs, so the host name (which contains your IP) is discoverable. Do not treat the address as secret.
- **Users get no email in inbox mode.** Do not put real users on it. Anyone with the admin token can read every email, including reset links.
- **Admin stays private.** The UI is bound to localhost and reached through SSH. Do not publish port 9090, and keep the admin token secret.
- **Rate limits and lockouts** stay on, as in production. Sign-in and sign-up attempts per IP are limited.
- **Production checks still run.** Warden refuses to start with weak settings: HTTPS URL, secure cookies, generated secrets, and only the Caddy container may set client IPs (`HTTP_TRUSTED_PROXIES=172.28.0.0/24`).
- **Back up `.env`.** `ENCRYPTION_KEY` protects signing keys and the Inbox. Lose it and that data is unreadable.

Firewall with ufw (allow SSH first or you lock yourself out):

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80,443/tcp
sudo ufw allow 443/udp
sudo ufw enable
```

Docker publishes ports by editing iptables directly and can bypass ufw. That is why the compose file binds the admin port to `127.0.0.1` and publishes nothing for Postgres and Redis. Your cloud provider's firewall is the second line of defense.

## Update, stop, reset

```bash
git pull && docker compose up -d --build   # update
docker compose down                        # stop, keep data
docker compose down -v                     # stop and delete all data
```

If you delete the volumes, also delete `.env` and run `./init.sh` again, because the old encryption key no longer matches.

If the server's IP changes, run `FORCE=1 ./init.sh` and recreate the database (`docker compose down -v`). The address is the token issuer, so existing tokens stop working anyway.

## Plain `docker run`

One image, your own Postgres and Redis, no Caddy:

```bash
docker build -t warden:test .
docker run -d --name warden --restart unless-stopped \
  -p 8080:8080 -p 127.0.0.1:9090:9090 \
  -e APP_ENV=production \
  -e HTTP_PUBLIC_URL=https://203-0-113-10.sslip.io \
  -e HTTP_TRUSTED_PROXIES=<ip range of your TLS proxy> \
  -e DATABASE_URL='postgres://user:pass@db-host:5432/warden?sslmode=require' \
  -e REDIS_URL='redis://:pass@redis-host:6379/0' \
  -e ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  -e ADMIN_TOKEN="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')" \
  -e ADMIN_COOKIE_SECURE=false \
  -e MAIL_DELIVERY=inbox \
  warden:test
```

Production mode needs HTTPS in front (Caddy, nginx, a cloud load balancer). Without a TLS proxy use `APP_ENV=development`, which accepts `http://` URLs and uses the Inbox by default. Save the generated `ENCRYPTION_KEY`: a new one on restart cannot read the old data.

## Other Compose stacks

The repository's root `docker-compose.yml` is the development stack (adds RabbitMQ, S3 and Mailpit). Use `deploy/test-server` for anything reachable from the internet.

## Kubernetes

See [kubernetes.md](kubernetes.md). The same environment variables apply; `MAIL_DELIVERY=inbox` works there too.
