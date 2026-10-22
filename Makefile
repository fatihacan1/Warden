VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/fatihacan1/warden/internal/observability.Version=$(VERSION)

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: env
env: ## Create .env from .env.example (does not overwrite)
	@test -f .env || cp .env.example .env

.PHONY: up
up: env ## Start the full stack (Warden + dependencies) in Docker
	docker compose up -d --build

.PHONY: deps
deps: env ## Start only the dependencies (run Warden with `make run`)
	docker compose up -d postgres redis rabbitmq garage garage-init mailpit garage-webui

.PHONY: down
down: ## Stop the stack (keeps data)
	docker compose down

.PHONY: run
run: ## Run Warden locally with .env
	go run ./cmd/warden serve

.PHONY: build
build: ## Build the binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/warden ./cmd/warden

.PHONY: image
image: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t warden:$(VERSION) .

.PHONY: test
test: ## Unit tests
	go test ./...

.PHONY: test-integration
test-integration: deps ## Integration tests against the compose stack
	go test -tags integration -count=1 ./test/e2e/

.PHONY: cover
cover: ## Unit test coverage report
	go test -coverprofile=coverage.out ./internal/...
	go tool cover -func=coverage.out | tail -1

.PHONY: lint
lint: ## go vet, staticcheck, gosec, govulncheck
	go vet ./...
	go vet -tags integration ./test/...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...
	go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -exclude-dir=pkg -exclude-generated ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: proto
proto: ## Regenerate gRPC code from api/proto
	buf lint
	buf generate

.PHONY: keygen
keygen: ## Print fresh secrets for .env
	go run ./cmd/warden keygen

.PHONY: loadtest
loadtest: ## Run the k6 load test against localhost:8080
	docker run --rm -i --network host -e BASE=http://localhost:8080 grafana/k6 run - < loadtest/auth.js
