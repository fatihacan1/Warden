# Running Warden in production

## Go-live checklist

- [ ] `APP_ENV=production`, `LOG_FORMAT=json`
- [ ] Fresh secrets from `warden setup` or `warden keygen`: `ENCRYPTION_KEY`, `ADMIN_TOKEN`, `GRPC_API_KEYS`. Store them in your secret manager and **back up `ENCRYPTION_KEY`**: without it, signing keys, TOTP seeds and provider secrets cannot be decrypted.
- [ ] `HTTP_PUBLIC_URL` is the public HTTPS URL; TLS terminates at your load balancer or ingress
- [ ] `HTTP_TRUSTED_PROXIES` lists the load balancer's address ranges, and `HTTP_PROXY_HEADER` matches what it sends (`X-Forwarded-For`, or `CF-Connecting-IP` behind Cloudflare)
- [ ] `HTTP_COOKIE_SECURE=true` (enforced)
- [ ] Ports 9090 (admin, metrics) and 9091 (gRPC) are **not** reachable from the internet
- [ ] Real SMTP relay configured (`SMTP_HOST`, port 587 with `SMTP_TLS_POLICY=mandatory`, or 465)
- [ ] `PASSWORD_CHECK_BREACHED=true` if the instance has outbound internet access
- [ ] Redirect URIs and CORS origins list only your production apps
- [ ] `GRPC_REFLECTION=false`
- [ ] gRPC traffic that leaves a trusted network uses TLS 1.3 and, ideally, mutual TLS (`GRPC_TLS_CERT_FILE`, `GRPC_TLS_KEY_FILE`, `GRPC_TLS_CLIENT_CA_FILE`); see [integration.md](integration.md#tls-and-mutual-tls)
- [ ] A publishable key per app (bound to its origins) and **Require a publishable key** turned on in Settings once every app sends one
- [ ] Secret keys only in backend secret stores; one per service so each can be revoked alone
- [ ] Webhook endpoints use `https://`; `WEBHOOK_ALLOW_PRIVATE_NETWORKS` stays unset (private targets blocked)
- [ ] If `GRAPHQL_ENABLED=true`: introspection is off by default in production; keep it that way
- [ ] Postgres backups and point-in-time recovery enabled
- [ ] Alerts on the metrics listed below

Warden validates most of this at startup and refuses to run with insecure settings.

Just testing on a server, with no domain or SMTP provider? See [test-server.md](test-server.md).

## Email delivery

Production sends through an SMTP provider (`SMTP_HOST`, the default mode). `MAIL_DELIVERY=inbox` (emails shown in the admin UI, users receive nothing) and `MAIL_DELIVERY=direct` (sent from the server on port 25, usually spam-filtered) exist for tests. Production never falls back to them: they must be chosen explicitly, and inbox mode shows a warning banner in the admin UI.

## Domain and HTTPS

Locally Warden runs on `http://localhost:8080`; that is what the callback URLs in the admin UI show. To go live:

1. **Pick a subdomain** for the auth service, for example `auth.yourapp.com`, and create a DNS `A` (and `AAAA`) record pointing at your server or load balancer.
2. **Terminate TLS in front of Warden.** The simplest option is [Caddy](https://caddyserver.com), which gets certificates automatically. A ready config is in [deploy/caddy/Caddyfile](../deploy/caddy/Caddyfile); replace the domain and run Caddy next to Warden on ports 80 and 443. Behind a cloud load balancer (AWS ALB, Cloudflare, Fly, Railway) use its TLS instead.
3. **Tell Warden its public address** in the environment and restart:

   ```env
   APP_ENV=production
   HTTP_PUBLIC_URL=https://auth.yourapp.com
   HTTP_TRUSTED_PROXIES=172.16.0.0/12   # the address range of Caddy or your load balancer
   HTTP_COOKIE_SECURE=true
   ```

   `HTTP_PUBLIC_URL` becomes the token issuer (`iss`), the JWKS address and the base of every OAuth callback URL. It is deliberately not editable in the admin UI: changing it invalidates every issued token.
4. **Register the new callback URLs.** Open the admin UI > Sign-in providers; each card now shows `https://auth.yourapp.com/v1/oauth/<provider>/callback`. Add it in each provider's console. Apple works only from this point, since it rejects localhost.
5. **Update your apps**: the issuer and JWKS URL in your backends, and the production redirect URIs and CORS origins in admin UI > Settings.

### Local and production side by side

Run two instances, each with its own `.env` and database: one on your machine (`APP_ENV=development`, localhost URL) and one on the server (`APP_ENV=production`, your domain). `APP_ENV` is what marks an instance as local or live; in production Warden refuses insecure settings such as plain HTTP.

Providers handle the two environments differently:

| Provider | Localhost callbacks | Recommendation |
| --- | --- | --- |
| Google | Allowed | One OAuth client can list both callback URLs |
| Discord | Allowed | One application can list both redirects |
| GitHub | Allowed | An OAuth App has a single callback URL: create one app for local, one for production |
| Apple | Not allowed (HTTPS only) | Test on a deployed instance, or through an HTTPS tunnel such as `cloudflared tunnel` with `HTTP_PUBLIC_URL` set to the tunnel URL |

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
- Migrations run automatically at startup under a Postgres advisory lock. To run them as a separate deploy step instead, set `DATABASE_AUTO_MIGRATE=false` and run `warden migrate` (the Kubernetes manifests do this in an init container).
- Readiness: `GET /readyz` on port 8080 (Postgres and Redis). Liveness: `GET /healthz`. The container image also has `HEALTHCHECK` built in (`warden healthcheck`).
- On `SIGTERM` Warden stops accepting connections, finishes in-flight requests (up to `HTTP_SHUTDOWN_TIMEOUT`, 20 s) and exits. Give your orchestrator a longer termination grace period than that.

### Container image

```bash
docker build -t warden:1.0.0 --build-arg VERSION=1.0.0 .
docker run --env-file .env -p 8080:8080 warden:1.0.0
```

The image is distroless, about 65 MB, runs as a non-root user and contains only the static binary.

### Kubernetes notes

Ready-made Kustomize manifests (restricted pod security, network policies, HPA, PDB, ingress, monitoring) are in [deploy/kubernetes](../deploy/kubernetes); see [kubernetes.md](kubernetes.md) for the guide.

- Set memory requests/limits and `GOMEMLIMIT` to roughly 90% of the limit so the Go GC works before the kernel OOM killer does.
- Budget memory: about 30 MiB baseline + 19 MiB x `PASSWORD_MAX_CONCURRENT_HASHES` (default 2 x CPU). Four CPUs: about 200 MiB.
- Scale on CPU: password hashing dominates CPU, everything else is cheap.
- Give the pod a `terminationGracePeriodSeconds` above `HTTP_SHUTDOWN_TIMEOUT` plus a short `preStop` delay, and never expose port 9090 through the ingress.

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

Warden exposes Prometheus metrics on the private admin port at `:9090/metrics`. Prometheus is the piece that collects them: it scrapes that URL every 15 seconds, stores the time series and evaluates alert rules; Grafana draws dashboards from it and Alertmanager sends the alerts.

The repository ships a ready setup:

| File | What it is |
| --- | --- |
| [deploy/prometheus/prometheus.yml](../deploy/prometheus/prometheus.yml) | Scrape config for the `warden` job |
| [deploy/prometheus/alerts.yml](../deploy/prometheus/alerts.yml) | Alert rules: down, 5xx rate, latency, load shedding, hasher saturation, outbox backlog and dead letters, refresh token reuse, credential stuffing |
| [deploy/grafana/](../deploy/grafana) | Datasource and a dashboard (traffic, latency, auth events, rate limits, deliveries, memory), provisioned automatically |

Locally: `docker compose --profile monitoring up -d`, then Prometheus at http://localhost:9092 and Grafana at http://localhost:3001 (`admin` / `admin`, change `GRAFANA_ADMIN_PASSWORD`). In production point your existing Prometheus (or Grafana Cloud, Datadog's OpenMetrics check, VictoriaMetrics) at every replica's `:9090/metrics` and load the same rule file. The key expressions:

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

**Rotate `ENCRYPTION_KEY`** without downtime:

1. Generate a new key (`warden keygen`). Set it as `ENCRYPTION_KEY` and move the old one to `ENCRYPTION_PREVIOUS_KEYS` (comma separated). `warden setup` does this for you when you replace the key.
2. Deploy. New data is sealed with the new key; old data stays readable because every ciphertext records which key sealed it.
3. Run `warden reencrypt` once. It rewrites signing keys, TOTP secrets, provider credentials, webhook secrets and queued emails under the new key, column by column, and is safe to run while Warden serves traffic.
4. Remove `ENCRYPTION_PREVIOUS_KEYS` and deploy again.

The same steps switch `ENCRYPTION_ALGORITHM` between `aes-256-gcm` and `xchacha20-poly1305`.

**Access tokens for automation and AI agents** (Developers > Access tokens) reach the admin API on the private admin port. Grant the least you can (read before write, one resource at a time), pick the shortest lifetime that works, pin long-lived ones to the IP of the machine that uses them, and revoke them when the job is done. Their use is in the audit log as `api.*` events with the token's name. An MCP client such as Claude runs `warden mcp` on a machine that can reach the admin port (VPN or SSH tunnel), never through the public internet in plain HTTP.

**Revoke an API key** on the API keys page. Publishable and secret keys stop working on every replica within 15 seconds. Use one key per app or service so a leak only needs one revocation.

**Data retention**: expired sessions and delivered outbox events are deleted after 7 days, audit events after `AUTH_AUDIT_RETENTION` (90 days). Account deletion (`DELETE /v1/me`) removes the user, sessions, identities and avatar; audit entries keep only the user id.

## Backups and disaster recovery

Postgres holds everything durable: users, sessions, identities, signing keys, provider settings and the outbox. Back it up with point-in-time recovery. Redis holds only short-lived data; losing it signs nobody out, though pending email links and in-progress OAuth flows must be restarted.

Restoring Postgres to an earlier point brings back revoked sessions as of that time. After a restore, consider revoking all sessions (`UPDATE sessions SET revoked_at = now() WHERE revoked_at IS NULL`) so every user signs in again.
