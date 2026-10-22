# Running Warden in production

## Go-live checklist

- [ ] `APP_ENV=production`, `LOG_FORMAT=json`
- [ ] Fresh secrets from `warden keygen`: `ENCRYPTION_KEY`, `ADMIN_TOKEN`, `GRPC_API_KEYS`. Store them in your secret manager and **back up `ENCRYPTION_KEY`**: without it, signing keys, TOTP seeds and provider secrets cannot be decrypted.
- [ ] `HTTP_PUBLIC_URL` is the public HTTPS URL; TLS terminates at your load balancer or ingress
- [ ] `HTTP_TRUSTED_PROXIES` lists the load balancer's address ranges, and `HTTP_PROXY_HEADER` matches what it sends (`X-Forwarded-For`, or `CF-Connecting-IP` behind Cloudflare)
- [ ] `HTTP_COOKIE_SECURE=true` (enforced)
- [ ] Ports 9090 (admin, metrics) and 9091 (gRPC) are **not** reachable from the internet
- [ ] Real SMTP relay configured (`SMTP_HOST`, port 587 with `SMTP_TLS_POLICY=mandatory`, or 465)
- [ ] `PASSWORD_CHECK_BREACHED=true` if the instance has outbound internet access
- [ ] Redirect URIs and CORS origins list only your production apps
- [ ] `GRPC_REFLECTION=false`
- [ ] Postgres backups and point-in-time recovery enabled
- [ ] Alerts on the metrics listed below

Warden validates most of this at startup and refuses to run with insecure settings.

## Deployment shape

```
             internet
                │ HTTPS
        ┌───────▼────────┐
        │ load balancer  │  (TLS, forwards X-Forwarded-For)
        └───────┬────────┘
                │ :8080
   ┌────────────┼────────────┐
   │ warden     │ warden     │  stateless replicas, 2+
   └─────┬──────┴─────┬──────┘
         │ private network: :9090 admin/metrics, :9091 gRPC
   ┌─────▼────┐  ┌────▼────┐  ┌──────────┐  ┌─────┐
   │ Postgres │  │  Redis  │  │ RabbitMQ │  │ S3  │
   └──────────┘  └─────────┘  └──────────┘  └─────┘
```

- Run at least two replicas. Any replica can serve any request; there is no sticky session.
- Migrations run automatically at startup under a Postgres advisory lock. To run them as a separate deploy step instead, set `DATABASE_AUTO_MIGRATE=false` and run `warden migrate`.
- Readiness: `GET /readyz` on port 8080 (Postgres and Redis). Liveness: `GET /healthz`. The container image also has `HEALTHCHECK` built in (`warden healthcheck`).
- On `SIGTERM` Warden stops accepting connections, finishes in-flight requests (up to `HTTP_SHUTDOWN_TIMEOUT`, 20 s) and exits. Give your orchestrator a longer termination grace period than that.

### Container image

```bash
docker build -t warden:1.0.0 --build-arg VERSION=1.0.0 .
docker run --env-file .env -p 8080:8080 warden:1.0.0
```

The image is distroless, about 65 MB, runs as a non-root user and contains only the static binary.

### Kubernetes notes

- Set memory requests/limits and `GOMEMLIMIT` to roughly 90% of the limit so the Go GC works before the kernel OOM killer does.
- Budget memory: about 30 MiB baseline + 19 MiB x `PASSWORD_MAX_CONCURRENT_HASHES` (default 2 x CPU). Four CPUs: about 200 MiB.
- Scale on CPU: password hashing dominates CPU, everything else is cheap.

## Sizing

| Resource | Guidance |
| --- | --- |
| Warden CPU | One Argon2id hash (19 MiB, t=2) takes about 20 ms of CPU on a modern core, so a core handles roughly 40-50 password sign-ins per second. Token refreshes and `/v1/me` calls are cheap (thousands per second) |
| Postgres | Small. One write per sign-in and refresh, PK and unique-index lookups only. Size `DATABASE_MAX_CONNS` x replicas below the server's `max_connections` |
| Redis | Small. Rate-limit counters, one-time tokens, revocation markers; every key has a TTL. Use `maxmemory-policy volatile-lru` |
| RabbitMQ | Optional. One message per auth event |

Your APIs verify tokens locally, so API traffic does not reach Warden at all.

## Managed services

| Need | Options |
| --- | --- |
| Postgres 14+ | AWS RDS/Aurora, Google Cloud SQL, Neon, Supabase, Crunchy Bridge |
| Redis 6.2+ | AWS ElastiCache, Upstash, Redis Cloud, Valkey |
| S3 | AWS S3, Cloudflare R2 (`S3_REGION=auto`), Backblaze B2, Garage, MinIO |
| SMTP | Amazon SES, Postmark, Resend, Mailgun, SendGrid |

For S3, leave `S3_ENDPOINT` empty for AWS. Set `S3_PUBLIC_BASE_URL` to serve avatars from a CDN or public bucket; otherwise Warden returns presigned URLs valid for `S3_PRESIGN_TTL`.

## Monitoring and alerts

Scrape `:9090/metrics`. Suggested alerts:

| Alert | Expression (PromQL) |
| --- | --- |
| Error rate | `sum(rate(warden_http_requests_total{status=~"5.."}[5m])) / sum(rate(warden_http_requests_total[5m])) > 0.02` |
| Load shedding | `rate(warden_http_shed_total[5m]) > 0` |
| Hasher saturated | `rate(warden_password_hash_rejected_total[5m]) > 0` (add CPU or replicas) |
| Credential stuffing | `sum(rate(warden_auth_events_total{event="sign_in",result=~"invalid|locked"}[5m])) > 5` |
| Stolen refresh tokens | `increase(warden_auth_events_total{event="refresh",result="reuse_detected"}[1h]) > 0` |
| Outbox stuck | `warden_outbox_pending > 1000` or `warden_outbox_dead > 0` |
| Latency | `histogram_quantile(0.95, sum by (le) (rate(warden_http_request_duration_seconds_bucket[5m]))) > 0.5` |

Set `SENTRY_DSN` to receive panics and unexpected errors.

## Operations

**Rotate the signing key** happens automatically every `TOKEN_KEY_ROTATION_INTERVAL` (30 days). Rotate immediately from the admin UI (Signing keys > Rotate now) if a key may have leaked. Old keys stay in the JWKS until tokens signed with them expire.

**Rotate `ADMIN_TOKEN`** by changing the variable and restarting. Existing admin sessions end immediately.

**Rotate gRPC API keys** by listing old and new keys together in `GRPC_API_KEYS`, moving clients to the new key, then removing the old one.

**Revoke a user everywhere**: admin UI > Users > Sign out everywhere, or gRPC `RevokeUserSessions`. Disabling an account also revokes all sessions.

**`ENCRYPTION_KEY` cannot be rotated in place** in this version. If it must change: re-enter provider secrets in the admin UI, rotate the signing key, and ask users with two-factor authentication to enroll again.

**Data retention**: expired sessions and delivered outbox events are deleted after 7 days, audit events after `AUTH_AUDIT_RETENTION` (90 days). Account deletion (`DELETE /v1/me`) removes the user, sessions, identities and avatar; audit entries keep only the user id.

## Backups and disaster recovery

Postgres holds everything durable: users, sessions, identities, signing keys, provider settings and the outbox. Back it up with point-in-time recovery. Redis holds only short-lived data; losing it signs nobody out, though pending email links and in-progress OAuth flows must be restarted.

Restoring Postgres to an earlier point brings back revoked sessions as of that time. After a restore, consider revoking all sessions (`UPDATE sessions SET revoked_at = now() WHERE revoked_at IS NULL`) so every user signs in again.
