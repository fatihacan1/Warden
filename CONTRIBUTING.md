# Contributing

Thanks for helping improve Warden.

## Setup

```bash
cp .env.example .env
docker compose up -d postgres redis rabbitmq garage garage-init mailpit
go run ./cmd/warden
```

## Before opening a pull request

```bash
gofmt -l ./cmd ./internal ./test     # must print nothing
go vet ./... && go vet -tags integration ./test/...
go test ./...
go test -tags integration -count=1 ./test/e2e/
```

CI also runs staticcheck, gosec, govulncheck and Semgrep.

## Guidelines

- Keep transports thin. Business rules belong in `internal/auth`, SQL in `internal/store`.
- Every security-relevant change needs a test, ideally an integration test in `test/e2e` that tries the attack.
- New configuration must be validated in `internal/config` and documented in `.env.example`. Prefer secure defaults; reject unsafe values instead of warning.
- New identity providers go in `internal/oauth` as one file with a `Definition`; the admin UI picks it up automatically.
- Schema changes are new files in `migrations/` (never edit an applied migration).
- After editing `api/proto`, run `buf generate` and commit the generated code.

Report security issues privately, see [SECURITY.md](SECURITY.md).
