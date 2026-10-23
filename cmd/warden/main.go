// Command warden runs the Warden authentication service.
//
//	warden serve            start the HTTP, admin and (optional) gRPC servers
//	warden setup            open the first-run wizard that tests connections and writes .env
//	warden migrate          apply database migrations and exit
//	warden migrate status   show migration status
//	warden reencrypt        re-encrypt stored secrets with the current ENCRYPTION_KEY
//	warden mcp              MCP server (stdio) for AI agents, using an access token
//	warden mail-test ADDR   send a test email with the current mail settings and print diagnostics
//	warden keygen           print fresh random secrets for .env
//	warden healthcheck      exit 0 if the local HTTP server is healthy (Docker HEALTHCHECK)
//	warden version          print the version
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatihacan1/warden/internal/app"
	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/mcp"
	"github.com/fatihacan1/warden/internal/observability"
	"github.com/fatihacan1/warden/internal/platform/postgres"
	"github.com/fatihacan1/warden/internal/setup"
	"github.com/fatihacan1/warden/internal/store"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		serve()
	case "setup":
		setupWizard(os.Args[2:])
	case "migrate":
		migrate(len(os.Args) > 2 && os.Args[2] == "status")
	case "reencrypt":
		reencrypt()
	case "mcp":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := mcp.Serve(ctx, os.Stdin, os.Stdout, mcp.FromEnv(observability.Version)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "mail-test":
		mailTest(os.Args[2:])
	case "keygen":
		keygen()
	case "healthcheck":
		healthcheck()
	case "version", "--version", "-v":
		fmt.Println(observability.Version)
	case "help", "--help", "-h":
		fmt.Println("usage: warden [serve|setup|migrate [status]|reencrypt|mcp|mail-test|keygen|healthcheck|version]")
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
		fmt.Fprintln(os.Stderr, "\nRun `warden setup` to create or fix the configuration in your browser.")
		os.Exit(1)
	}
	return cfg
}

func setupWizard(args []string) {
	flags := flag.NewFlagSet("setup", flag.ExitOnError)
	addr := flags.String("addr", "127.0.0.1:9095", "listen address (loopback only unless --allow-remote)")
	file := flags.String("env-file", ".env", "configuration file to write")
	remote := flags.Bool("allow-remote", false, "allow a non-loopback address, e.g. inside a container")
	_ = flags.Parse(args)
	log := observability.NewLogger("info", "text", "warden-setup", "setup")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := setup.Run(ctx, setup.Options{Addr: *addr, EnvFile: *file, AllowRemote: *remote, Log: log, Ready: func(u string) {
		fmt.Println("Warden setup is running. Open this link in your browser (it contains a one-time token):")
		fmt.Println()
		fmt.Println("  " + u)
		fmt.Println()
		fmt.Println("Press Ctrl+C to stop without saving.")
	}})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func reencrypt() {
	cfg := load()
	log := observability.NewLogger(cfg.LogLevel, cfg.LogFormat, cfg.ServiceName, cfg.Env)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	box, err := cfg.SecretBox()
	if err != nil {
		app.Exit(log, err)
	}
	pool, err := postgres.Connect(ctx, cfg.Database)
	if err != nil {
		app.Exit(log, err)
	}
	defer pool.Close()
	res, err := app.Reencrypt(ctx, store.New(pool), box)
	total := 0
	for _, r := range res {
		fmt.Printf("%-28s %d re-encrypted\n", r.Column, r.Changed)
		total += r.Changed
	}
	if err != nil {
		app.Exit(log, err)
	}
	fmt.Printf("\nDone: %d values now use the current key (%s).", total, box.Algorithm())
	if len(cfg.EncryptionPreviousKeys) > 0 {
		fmt.Print(" ENCRYPTION_PREVIOUS_KEYS can be removed once every replica runs with this configuration.")
	}
	fmt.Println()
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
