# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through GitHub's [private vulnerability reporting](https://github.com/fatihacan1/warden/security/advisories/new) for this repository.

Include the affected version or commit, a description of the issue and its impact, and steps to reproduce. You will receive an acknowledgement within 3 business days. Fixes are released as soon as practical, and reporters are credited unless they prefer otherwise.

## Supported versions

Security fixes go into the latest release. Run the newest version.

## What is in scope

The Warden service, its container image, the admin UI and the generated gRPC client. Issues in third-party dependencies are in scope when Warden uses the affected code path.

Out of scope: denial of service by volumetric traffic, findings that require a compromised host or leaked `ENCRYPTION_KEY` / `ADMIN_TOKEN`, missing hardening on the development `docker-compose.yml` stack, and the deliberately public development secrets in `.env.example` (Warden refuses to run with them in production).

## How Warden is tested

- Unit tests for every security-relevant package (token verification, password hashing, encryption, OAuth flows, rate limiting, configuration validation).
- An integration suite (`test/e2e`) that runs the full service against real Postgres, Redis and S3 and exercises abuse cases: forged and confused JWTs, refresh token replay, PKCE bypass, open redirects, pre-account takeover, CSRF on the admin UI, account enumeration and lockout.
- `govulncheck`, `gosec` and Semgrep in CI.

A summary of the threat model and mitigations is in the [README](README.md#security-model).
