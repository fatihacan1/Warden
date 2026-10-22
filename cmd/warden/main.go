// Command warden runs the Warden authentication service.
//
//	warden serve            start the HTTP, admin and (optional) gRPC servers
//	warden migrate          apply database migrations and exit
//	warden migrate status   show migration status
//	warden keygen           print fresh random secrets for .env
//	warden healthcheck      exit 0 if the local HTTP server is healthy (Docker HEALTHCHECK)
//	warden version          print the version
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatihacan1/warden/internal/app"
	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/observability"
	"github.com/fatihacan1/warden/internal/platform/postgres"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		serve()
	case "migrate":
		migrate(len(os.Args) > 2 && os.Args[2] == "status")
	case "keygen":
		keygen()
	case "healthcheck":
		healthcheck()
	case "version", "--version", "-v":
		fmt.Println(observability.Version)
	case "help", "--help", "-h":
		fmt.Println("usage: warden [serve|migrate [status]|keygen|healthcheck|version]")
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
}

func load() *config.Config {
	if err := config.LoadDotEnv(".env"); err != nil {
		fmt.Fprintln(os.Stderr, "reading .env:", err)
		os.Exit(1)
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid configuration:")
		fmt.Fprintln(os.Stderr, " -", strings.ReplaceAll(err.Error(), "\n", "\n - "))
		os.Exit(1)
	}
	return cfg
}

func serve() {
	cfg := load()
	log := observability.NewLogger(cfg.LogLevel, cfg.LogFormat, cfg.ServiceName, cfg.Env)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.Build(ctx, cfg, log)
	if err != nil {
		app.Exit(log, err)
	}
	log.Info("warden started", "public_url", cfg.HTTP.PublicURL, "issuer", cfg.Token.Issuer,
		"admin_ui", cfg.Admin.Token != "", "grpc", cfg.GRPC.Enabled, "events", cfg.RabbitMQ.URL != "", "s3", cfg.S3.Enabled)
	if err := a.Run(ctx); err != nil {
		app.Exit(log, err)
	}
	log.Info("warden stopped")
}

func migrate(status bool) {
	cfg := load()
	log := observability.NewLogger(cfg.LogLevel, cfg.LogFormat, cfg.ServiceName, cfg.Env)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := postgres.Connect(ctx, cfg.Database)
	if err != nil {
		app.Exit(log, err)
	}
	defer pool.Close()
	if status {
		st, err := postgres.Status(ctx, pool)
		if err != nil {
			app.Exit(log, err)
		}
		for _, s := range st {
			fmt.Printf("%-8d %-10s %s\n", s.Source.Version, s.State, s.Source.Path)
		}
		return
	}
	if err := postgres.Migrate(ctx, pool, log); err != nil {
		app.Exit(log, err)
	}
	log.Info("migrations up to date")
}

func keygen() {
	random := func(n int) []byte {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		return b
	}
	fmt.Println("# Paste into your .env (never commit real values)")
	fmt.Printf("ENCRYPTION_KEY=%s\n", base64.StdEncoding.EncodeToString(random(32)))
	fmt.Printf("ADMIN_TOKEN=%s\n", base64.RawURLEncoding.EncodeToString(random(32)))
	fmt.Printf("GRPC_API_KEYS=%s\n", base64.RawURLEncoding.EncodeToString(random(32)))
	fmt.Println("# Garage (local S3) only:")
	fmt.Printf("GARAGE_RPC_SECRET=%s\n", hex.EncodeToString(random(32)))
}

// healthcheck lets distroless images (no curl/wget) define a HEALTHCHECK.
func healthcheck() {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz") // #nosec G704 -- loopback address from the operator's own config
	if err != nil || resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	_ = resp.Body.Close()
}
