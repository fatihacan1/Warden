# syntax=docker/dockerfile:1

# ---- build ----------------------------------------------------------------
FROM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags "-s -w -X github.com/fatihacan1/warden/internal/observability.Version=${VERSION}" \
    -o /out/warden ./cmd/warden

# ---- runtime --------------------------------------------------------------
# Distroless: no shell, no package manager, runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/warden /warden
USER nonroot:nonroot
EXPOSE 8080 9090 9091
HEALTHCHECK --interval=10s --timeout=4s --start-period=20s --retries=3 CMD ["/warden", "healthcheck"]
ENTRYPOINT ["/warden"]
CMD ["serve"]
