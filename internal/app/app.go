// Package app wires every component together and owns the process lifecycle:
// startup order, background workers and graceful shutdown.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"

	"github.com/fatihacan1/warden/internal/apikeys"
	"github.com/fatihacan1/warden/internal/auth"
	"github.com/fatihacan1/warden/internal/avatar"
	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/crypto/password"
	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/oauth"
	"github.com/fatihacan1/warden/internal/observability"
	"github.com/fatihacan1/warden/internal/platform/objectstore"
	"github.com/fatihacan1/warden/internal/platform/postgres"
	"github.com/fatihacan1/warden/internal/platform/rabbitmq"
	"github.com/fatihacan1/warden/internal/platform/redisx"
	"github.com/fatihacan1/warden/internal/ratelimit"
	"github.com/fatihacan1/warden/internal/settings"
	"github.com/fatihacan1/warden/internal/store"
	"github.com/fatihacan1/warden/internal/token"
	"github.com/fatihacan1/warden/internal/transport/admin"
	"github.com/fatihacan1/warden/internal/transport/grpcapi"
	"github.com/fatihacan1/warden/internal/transport/httpapi"
	"github.com/fatihacan1/warden/internal/webhooks"
)

// App is a fully wired Warden instance.
type App struct {
	Config    *config.Config
	Log       *slog.Logger
	Metrics   *observability.Metrics
	Pool      *pgxpool.Pool
	Redis     *redis.Client
	Store     *store.Store
	Keys      *token.KeyManager
	Tokens    *token.Issuer
	OAuth     *oauth.Registry
	Auth      *auth.Service
	Relay     *events.Relay
	HTTP      *httpapi.Server
	Admin     *admin.Server
	GRPC      *grpcapi.Server
	Publisher *rabbitmq.Publisher
	Objects   objectstore.Store
	Box       *secretbox.Box
	Settings  *settings.Manager
	APIKeys   *apikeys.Manager
	Webhooks  *webhooks.Manager
	Mail      *mailer.Library
	Renderer  *mailer.Renderer

	flushSentry func()
}

// Build connects to every dependency and constructs the servers. Nothing
// starts listening yet.
func Build(ctx context.Context, cfg *config.Config, log *slog.Logger) (*App, error) {
	a := &App{Config: cfg, Log: log, Metrics: observability.NewMetrics(), flushSentry: func() {}}

	if on, flush, err := observability.InitSentry(cfg.Sentry.DSN, cfg.Env, cfg.Sentry.TracesSampleRate); err != nil {
		log.Warn("sentry init failed", "err", err)
	} else if on {
		a.flushSentry = flush
		log.Info("sentry enabled")
	}

	box, err := cfg.SecretBox()
	if err != nil {
		return nil, err
	}
	a.Box = box

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if a.Pool, err = postgres.Connect(cctx, cfg.Database); err != nil {
		return nil, err
	}
	if cfg.Database.AutoMigrate {
		if err := postgres.Migrate(cctx, a.Pool, log); err != nil {
			a.Close()
			return nil, err
		}
	}
	if a.Redis, err = redisx.Connect(cctx, cfg.Redis); err != nil {
		a.Close()
		return nil, err
	}
	a.Store = store.New(a.Pool)
	a.Settings = settings.NewManager(cfg, a.Store, log)
	if err := a.Settings.Reload(cctx); err != nil {
		// Invalid or unreadable admin settings must not take the service down:
		// keep the environment defaults and surface the problem loudly.
		log.Error("runtime settings not applied, using environment defaults", "err", err)
	}

	a.APIKeys = apikeys.NewManager(a.Store, cfg.IsProduction(), log)
	if err := a.APIKeys.Reload(cctx); err != nil {
		a.Close()
		return nil, err
	}
	a.Webhooks = webhooks.NewManager(a.Store, box, log, webhooks.Options{
		Production: cfg.IsProduction(), AllowPrivate: cfg.WebhookPrivateNetworks(), Timeout: cfg.Webhook.Timeout,
	})
	if err := a.Webhooks.Reload(cctx); err != nil {
		a.Close()
		return nil, err
	}

	a.Keys = token.NewKeyManager(a.Store, box, cfg.Token.KeyRotationInterval, cfg.Token.AccessTTL, log)
	if err := a.Keys.Init(cctx); err != nil {
		a.Close()
		return nil, err
	}
	a.Tokens = token.NewIssuer(a.Keys, cfg.Token.Issuer, cfg.Token.Audience, cfg.Token.AccessTTL)

	a.Objects = objectstore.Disabled{}
	if cfg.S3.Enabled {
		s3, err := objectstore.NewS3(cctx, cfg.S3)
		if err != nil {
			a.Close()
			return nil, err
		}
		a.Objects = s3
	}

	var publisher events.Publisher
	if cfg.RabbitMQ.URL != "" {
		a.Publisher = rabbitmq.NewPublisher(cfg.RabbitMQ.URL, cfg.RabbitMQ.Exchange, log)
		if err := a.Publisher.Connect(); err != nil {
			// Not fatal: events are durable in the outbox and delivered later.
			log.Warn("rabbitmq unavailable at startup, events will be delivered when it is back", "err", err)
		}
		publisher = a.Publisher
	}

	renderer, err := mailer.NewRenderer(func() string { return a.Settings.Get().AppName }, func() string { return a.Settings.Get().DefaultLocale })
	if err != nil {
		a.Close()
		return nil, err
	}
	a.Renderer = renderer
	a.Mail = mailer.NewLibrary(a.Store, renderer, log)
	if err := a.Mail.Reload(cctx); err != nil {
		a.Close()
		return nil, err
	}
	var sender mailer.Sender = mailer.NewLog(log)
	if cfg.SMTP.Host != "" {
		sender = mailer.NewSMTP(cfg.SMTP)
	}
	a.Relay = events.NewRelay(a.Store, publisher, sender, renderer, box, log, a.Metrics).WithWebhooks(a.Webhooks)

	a.OAuth = oauth.NewRegistry(cfg.OAuth, cfg.HTTP.PublicURL, a.Store, box, oauth.NewHTTPClient(), log)
	if err := a.OAuth.Reload(cctx); err != nil {
		a.Close()
		return nil, err
	}

	rec := rateRecorder{a.Metrics}
	limiter := ratelimit.New(a.Redis, cfg.RateLimit.Enabled, cfg.RateLimit.FailOpen, log, rec)
	lockout := ratelimit.NewLockout(a.Redis, func() int { return a.Settings.Get().LockoutThreshold }, cfg.Auth.LockoutWindow, cfg.RateLimit.FailOpen, log)

	hasher := password.NewHasher(password.Params{
		Memory: cfg.Password.Argon2Memory, Iterations: cfg.Password.Argon2Iterations, Parallelism: cfg.Password.Argon2Parallelism,
	}, cfg.Password.MaxConcurrentHashes, cfg.Password.HashQueueTimeout, a.Metrics)
	breach := password.NewBreachChecker() // used only while the setting is on

	a.Auth = auth.New(auth.Deps{
		Config: cfg, Store: a.Store, Redis: a.Redis, Hasher: hasher, Breach: breach, Tokens: a.Tokens,
		Events: events.NewWriter(box, publisher != nil, a.Webhooks), Lockout: lockout, Box: box, OAuth: a.OAuth,
		Flow: oauth.NewFlow(a.Redis), Objects: a.Objects, Avatars: avatar.NewProcessor(), Metrics: a.Metrics, Log: log,
		Settings: a.Settings,
	})

	ready := a.readiness
	if a.HTTP, err = httpapi.New(httpapi.Deps{
		Config: cfg, Auth: a.Auth, Tokens: a.Tokens, Keys: a.Keys, OAuth: a.OAuth,
		Limiter: limiter, Metrics: a.Metrics, Log: log, Ready: ready, Settings: a.Settings, APIKeys: a.APIKeys,
	}); err != nil {
		a.Close()
		return nil, err
	}
	if a.Admin, err = admin.New(admin.Deps{
		Config: cfg, Auth: a.Auth, Store: a.Store, Redis: a.Redis, OAuth: a.OAuth, Keys: a.Keys,
		Limiter: limiter, Metrics: a.Metrics, Log: log, Ready: ready, Events: publisher != nil, Settings: a.Settings,
		APIKeys: a.APIKeys, Webhooks: a.Webhooks, Mail: a.Mail, Renderer: renderer, Sender: sender,
	}); err != nil {
		a.Close()
		return nil, err
	}
	if cfg.GRPC.Enabled {
		a.GRPC = grpcapi.New(a.Auth, a.Tokens, cfg.GRPC.APIKeys, cfg.GRPC.Reflection, log, a.Metrics)
	}
	return a, nil
}

type rateRecorder struct{ m *observability.Metrics }

func (r rateRecorder) RateLimited(policy string) { r.m.RateLimited.WithLabelValues(policy).Inc() }

// readiness checks hard dependencies. Optional ones (RabbitMQ, S3, SMTP) are
// reported but a failure does not make the instance unready: their work is
// queued in the outbox or degrades a single feature.
func (a *App) readiness(ctx context.Context) map[string]error {
	out := map[string]error{
		"postgres": a.Pool.Ping(ctx),
		"redis":    a.Redis.Ping(ctx).Err(),
	}
	return out
}

// Run starts servers and workers and blocks until ctx is cancelled, then
// shuts everything down gracefully.
func (a *App) Run(ctx context.Context) error {
	cfg := a.Config
	g, gctx := errgroup.WithContext(ctx)
	workers, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()

	serve := func(name, addr string, fn func() error) {
		g.Go(func() error {
			a.Log.Info("listening", "server", name, "addr", addr)
			if err := fn(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("%s server: %w", name, err)
			}
			return nil
		})
	}
	serve("http", cfg.HTTP.Addr, func() error { return a.HTTP.Listen(cfg.HTTP.Addr) })
	serve("admin", cfg.Admin.Addr, func() error { return a.Admin.Listen(cfg.Admin.Addr) })
	if a.GRPC != nil {
		serve("grpc", cfg.GRPC.Addr, func() error { return a.GRPC.Serve(cfg.GRPC.Addr) })
	}

	go a.Keys.Run(workers, 30*time.Second)
	go a.OAuth.Run(workers, 30*time.Second)
	go a.Settings.Run(workers, 15*time.Second)
	go a.APIKeys.Run(workers, 15*time.Second)
	go a.Webhooks.Run(workers, 15*time.Second)
	go a.Mail.Run(workers, 15*time.Second)
	go a.Relay.Run(workers)
	go a.cleanupLoop(workers)

	g.Go(func() error {
		<-gctx.Done()
		a.Log.Info("shutting down", "timeout", cfg.HTTP.ShutdownTimeout)
		sctx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
		defer cancel()
		// Stop taking new traffic first, let in-flight requests finish, then
		// stop workers so queued emails/events keep flowing until the end.
		if err := a.HTTP.Shutdown(sctx); err != nil {
			a.Log.Error("http shutdown", "err", err)
		}
		if a.GRPC != nil {
			a.GRPC.Shutdown(sctx)
		}
		if err := a.Admin.Shutdown(sctx); err != nil {
			a.Log.Error("admin shutdown", "err", err)
		}
		stopWorkers()
		return nil
	})
	err := g.Wait()
	a.Close()
	return err
}

// cleanupLoop prunes expired data hourly on a single replica.
func (a *App) cleanupLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		_, err := a.Store.TryAdvisoryLock(ctx, store.LockCleanup, func(ctx context.Context) error {
			now := time.Now()
			s, err := a.Store.DeleteExpiredSessions(ctx, now.Add(-7*24*time.Hour))
			if err != nil {
				return err
			}
			o, err := a.Store.DeleteProcessedOutbox(ctx, now.Add(-7*24*time.Hour))
			if err != nil {
				return err
			}
			au, err := a.Store.DeleteAuditBefore(ctx, now.Add(-a.Config.Auth.AuditRetention))
			if err != nil {
				return err
			}
			d, err := a.Store.DeleteStaleDevices(ctx, now.Add(-180*24*time.Hour))
			if err != nil {
				return err
			}
			a.Log.Info("cleanup finished", "sessions", s, "outbox", o, "audit", au, "devices", d)
			return nil
		})
		if err != nil && ctx.Err() == nil {
			a.Log.Error("cleanup failed", "err", err)
		}
	}
}

// Close releases connections. Safe to call on a partially built App.
func (a *App) Close() {
	if a.Publisher != nil {
		_ = a.Publisher.Close()
	}
	if a.Redis != nil {
		_ = a.Redis.Close()
	}
	if a.Pool != nil {
		a.Pool.Close()
	}
	if a.flushSentry != nil {
		a.flushSentry()
	}
}

// Exit logs a fatal startup error and exits non-zero.
func Exit(log *slog.Logger, err error) {
	log.Error("fatal", "err", err)
	os.Exit(1)
}
