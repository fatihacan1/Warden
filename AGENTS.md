# AGENTS.md: Warden

Instructions for AI coding assistants that deploy Warden, connect apps and
services to it, or change this repository. For app code, also read the SDK's
[AGENTS.md](https://github.com/fatihacan1/warden-js/blob/main/AGENTS.md).

## What it is

Warden is a self-hosted authentication service (one Go binary plus PostgreSQL
and Redis). It signs users in, issues ES256 access tokens (`at+jwt`) that any
backend verifies offline with the JWKS, and issues service tokens for
service-to-service calls.

| Port | What | Exposure |
| --- | --- | --- |
| 8080 | Public API (`/v1/...`, JWKS, `/graphql`) | Behind your reverse proxy / ingress, HTTPS |
| 9090 | Admin UI, `/metrics`, admin API | **Private.** Never publish it to the internet; use an SSH tunnel, VPN or `kubectl port-forward` |
| 9091 | gRPC (optional) | Internal network only, TLS / mTLS in production |

## Pick the right credential

Most integration bugs are the wrong credential in the wrong place.

| Credential | Looks like | Where it lives | Use it for |
| --- | --- | --- | --- |
| Publishable key | `pk_live_...` | Frontend / mobile config, public | Identifies the app; bound to its origins |
| Secret key | `sk_live_...` | Backend env var only | Server API: create users, roles, disable, introspect |
| Service client | `svc_...` id + `wcs_...` secret | Backend env vars only | One service calling another (OAuth 2.0 client credentials) |
| User access token | JWT, `sub` = user id | Sent by the app as `Authorization: Bearer` | Your API learns who the user is |
| Service token | JWT, `sub` = `client:<id>`, `client_id`, `scope` | Obtained by the calling service | Your API learns which service is calling and with which scopes |
| Admin access token | `wat_...` | Automation / MCP config | Admin API and `warden mcp`, limited per resource |
| `ADMIN_TOKEN` | env var | Server env only | Signing in to the admin UI |

All of them are created in the admin UI (API keys, Service clients, Access
tokens). Ask the user for them; never invent or hard-code one.

## Deploying

| Situation | Use | Doc |
| --- | --- | --- |
| Local development | `make up` (Docker Compose, Mailpit catches email) | README, Quick start |
| Test server, no domain, no SMTP | `deploy/test-server/init.sh` (Caddy + sslip.io HTTPS, `MAIL_DELIVERY=inbox`) | [docs/test-server.md](docs/test-server.md) |
| One container, own Postgres/Redis | `docker run` with env vars | [docs/test-server.md](docs/test-server.md) |
| Production on VMs | Compose or the binary behind a TLS proxy | [docs/production.md](docs/production.md) |
| Kubernetes | `kubectl apply -k deploy/kubernetes/overlays/production` | [docs/kubernetes.md](docs/kubernetes.md) |
| Interactive first setup | `warden setup` (wizard writes `.env`) | README |

Email delivery (`MAIL_DELIVERY`):

- `smtp`: a real relay (`SMTP_HOST`, ...). Use this in production.
- `inbox`: nothing is sent, and emails appear under Inbox in the admin UI.
  This is for test servers without SMTP.
- `direct`: Warden sends to the recipient's MX on port 25. Most clouds block
  that port, and the mail usually lands in spam. Check with `warden mail-test <address>`.
- `log`: emails are only logged. This is for development.

Rules:

- `APP_ENV=production` refuses unsafe config (plain HTTP, dev secrets,
  wildcard CORS). Fix the config; do not switch to development to get past it.
- `HTTP_PUBLIC_URL` is the token issuer. Every service must verify against
  exactly this value.
- Set `HTTP_TRUSTED_PROXIES` to your proxy's addresses only, never a whole
  shared network, or clients can spoof their IP and dodge rate limits.
- Keep `ENCRYPTION_KEY` backed up. Rotate with `ENCRYPTION_PREVIOUS_KEYS` and
  `warden reencrypt`; never just replace it.
- Remote databases need `sslmode=require`.
- On Kubernetes, keep the NetworkPolicies. Pods that need the admin port or
  gRPC get the labels described in docs/kubernetes.md.

## Connecting apps and services

| Need | Do this |
| --- | --- |
| Sign users in from a web or mobile app | `warden-auth` with a publishable key (see the SDK AGENTS.md) |
| Protect your API (Node) | `warden-auth/server`: `warden.express({ roles })` |
| Protect your API (other languages) | Verify the JWT with the JWKS: ES256, `typ: at+jwt`, `iss` = `HTTP_PUBLIC_URL`, `aud` = `warden` ([docs/integration.md](docs/integration.md)) |
| Manage users from a backend | Server API `/v1/server/*` with a secret key |
| Service A calls service B | A uses a service client and B checks the scope. See below |
| React to sign-ups and other events | Webhooks (admin UI) or RabbitMQ events; deduplicate on `id` |
| Let an AI agent manage Warden | Admin access token + `warden mcp` |

### Service-to-service (OAuth 2.0 client credentials)

1. In the admin UI open Service clients, create a client for the **calling**
   service, and set the allowed audiences (receiving services, e.g.
   `payments-api`) and scopes (e.g. `payments:charge`). The secret is shown
   once.
2. The calling service runs `POST /v1/oauth/token` with
   `grant_type=client_credentials`, HTTP Basic `svc_...:wcs_...`, and
   `audience` and `scope`. In Node use `createServiceClient(...)`, which caches
   and renews the token. There is no refresh token: request a new token when
   this one expires.
3. The receiving service verifies the JWT with the JWKS, checks that `aud`
   contains **its own name**, and checks the `scope` claim. In Node use
   `warden.express({ scopes: ["payments:charge"] })`, with `audience` set to
   its own name.
4. Service tokens have no user. They are rejected by `/v1/me`, GraphQL and
   every user endpoint on purpose. Do not try to make one act as a user.
5. Rotate a secret in the admin UI. The old secret keeps working for a grace
   period, so you can deploy the new one without downtime.

Never use a user's token or a secret key (`sk_...`) for service-to-service
calls.

## Working on this repository

- Go 1.26, Fiber v3, pgx, goose migrations in `migrations/` (embedded; add a
  new numbered file, never edit an applied one).
- Gates before committing: `gofmt -l`, `go vet ./...`, `make lint`
  (staticcheck, gosec), `go test ./...`, and
  `go test -tags integration ./test/e2e/` against `make deps`.
- Errors go out as `domain.Error` values (`{"error":{"code":...}}`). Error
  codes are API. Do not change existing ones.
- New endpoints need `api/openapi.yaml`, the README table and, if they are
  user-facing, the SDK.
- Admin UI templates are in `internal/transport/admin/templates`. After a UI
  change, rebuild the container (`docker compose up -d --build warden`) and
  check it on :9090.
- Security-relevant code (tokens, sessions, password hashing, outbound
  requests) needs tests in `test/e2e/`, including the attack case.
