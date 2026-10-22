// Package httpapi is the public REST API (Fiber v3).
package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"github.com/fatihacan1/warden/internal/auth"
	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/oauth"
	"github.com/fatihacan1/warden/internal/observability"
	"github.com/fatihacan1/warden/internal/ratelimit"
	"github.com/fatihacan1/warden/internal/settings"
	"github.com/fatihacan1/warden/internal/token"
)

// Readiness reports whether dependencies are healthy.
type Readiness func(ctx context.Context) map[string]error

// Deps are the collaborators of the HTTP server.
type Deps struct {
	Config   *config.Config
	Auth     *auth.Service
	Tokens   *token.Issuer
	Keys     *token.KeyManager
	OAuth    *oauth.Registry
	Limiter  *ratelimit.Limiter
	Metrics  *observability.Metrics
	Log      *slog.Logger
	Ready    Readiness
	Settings *settings.Manager
}

type Server struct {
	app      *fiber.App
	cfg      *config.Config
	auth     *auth.Service
	tokens   *token.Issuer
	keys     *token.KeyManager
	oauth    *oauth.Registry
	limiter  *ratelimit.Limiter
	metrics  *observability.Metrics
	log      *slog.Logger
	ready    Readiness
	settings *settings.Manager
}

const maxJSONBody = 64 << 10

// New builds the Fiber application with every route and middleware.
func New(d Deps) *Server {
	s := &Server{
		cfg: d.Config, auth: d.Auth, tokens: d.Tokens, keys: d.Keys, oauth: d.OAuth,
		limiter: d.Limiter, metrics: d.Metrics, log: d.Log, ready: d.Ready, settings: d.Settings,
	}
	trusted := len(d.Config.HTTP.TrustedProxies) > 0
	s.app = fiber.New(fiber.Config{
		AppName:            "warden",
		ServerHeader:       "",
		BodyLimit:          int(d.Config.S3.AvatarMaxBytes) + 256<<10,
		Concurrency:        d.Config.HTTP.MaxConnections,
		ReadTimeout:        d.Config.HTTP.ReadTimeout,
		WriteTimeout:       d.Config.HTTP.WriteTimeout,
		IdleTimeout:        d.Config.HTTP.IdleTimeout,
		ReadBufferSize:     16 << 10,
		TrustProxy:         trusted,
		TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: d.Config.HTTP.TrustedProxies},
		ProxyHeader:        d.Config.HTTP.ProxyHeader,
		EnableIPValidation: true,
		JSONEncoder:        json.Marshal,
		JSONDecoder:        json.Unmarshal,
		ErrorHandler:       s.errorHandler,
	})
	s.routes()
	return s
}

// App exposes the Fiber app (tests use app.Test).
func (s *Server) App() *fiber.App { return s.app }

func (s *Server) routes() {
	cfg := s.cfg
	a := s.app
	a.Use(requestid.New())
	a.Use(s.observe())
	a.Use(s.recoverer())
	a.Use(securityHeaders(cfg.IsProduction()))
	a.Use(s.shedLoad())
	a.Use(s.deadline())
	// Origins are read per request so they can be edited in the admin UI.
	a.Use(cors.New(cors.Config{
		AllowOriginsFunc: func(origin string) bool { return slices.Contains(s.settings.Get().CORSOrigins, origin) },
		AllowMethods:     []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type", "X-Auth-Mode", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID", "Retry-After"},
		AllowCredentials: true,
		MaxAge:           600,
	}))

	a.Get("/healthz", s.healthz)
	a.Get("/readyz", s.readyz)
	a.Get("/.well-known/jwks.json", s.jwks)
	a.Get("/.well-known/openid-configuration", s.discovery)

	global := s.rateLimit(ratelimit.Per("ip_global", cfg.RateLimit.GlobalPerMinute, time.Minute))
	strict := s.rateLimit(ratelimit.Per("ip_auth", cfg.RateLimit.AuthPerMinute, time.Minute))
	refresh := s.rateLimit(ratelimit.Per("ip_refresh", max(60, cfg.RateLimit.AuthPerMinute*2), time.Minute))
	email := s.rateLimit(ratelimit.Per("ip_email", 5, 15*time.Minute))

	v1 := a.Group("/v1", global, noStore)

	ab := v1.Group("/auth", jsonBody(maxJSONBody))
	ab.Get("/providers", s.providers)
	ab.Post("/signup", strict, s.signUp)
	ab.Post("/signin", strict, s.signIn)
	ab.Post("/mfa/verify", strict, s.verifyMFA)
	ab.Post("/refresh", refresh, s.refresh)
	ab.Post("/signout", s.signOut)
	ab.Post("/email/verify", strict, s.verifyEmail)
	ab.Post("/password/forgot", email, s.forgotPassword)
	ab.Post("/password/reset", strict, s.resetPassword)

	ob := v1.Group("/oauth")
	ob.Get("/:provider/authorize", strict, s.oauthAuthorize)
	ob.Get("/:provider/callback", strict, s.oauthCallback)
	ob.Post("/:provider/callback", strict, s.oauthCallback) // Apple form_post
	ob.Post("/token", jsonBody(maxJSONBody), strict, s.oauthToken)
	ob.Post("/:provider/native", jsonBody(maxJSONBody), strict, s.oauthNative)

	me := v1.Group("/me", s.requireAuth())
	me.Get("", s.getMe)
	me.Patch("", jsonBody(maxJSONBody), s.updateMe)
	me.Delete("", jsonBody(maxJSONBody), strict, s.deleteMe)
	me.Post("/password", jsonBody(maxJSONBody), strict, s.changePassword)
	me.Post("/email/resend", email, s.resendVerification)
	me.Put("/avatar", s.rateLimit(ratelimit.Per("ip_avatar", 10, time.Hour)), s.uploadAvatar)
	me.Delete("/avatar", s.deleteAvatar)
	me.Get("/sessions", s.listSessions)
	me.Delete("/sessions", s.revokeOtherSessions)
	me.Delete("/sessions/:id", s.revokeSession)
	me.Get("/identities", s.listIdentities)
	me.Delete("/identities/:provider", s.unlinkIdentity)
	me.Post("/mfa/totp/setup", jsonBody(maxJSONBody), s.totpSetup)
	me.Post("/mfa/totp/enable", jsonBody(maxJSONBody), strict, s.totpEnable)
	me.Post("/mfa/totp/disable", jsonBody(maxJSONBody), strict, s.totpDisable)
	me.Post("/mfa/recovery-codes", jsonBody(maxJSONBody), strict, s.regenerateRecoveryCodes)

	a.Use(func(fiber.Ctx) error { return fiber.ErrNotFound })
}

// Listen serves until Shutdown.
func (s *Server) Listen(addr string) error {
	return s.app.Listen(addr, fiber.ListenConfig{DisableStartupMessage: true})
}

// Shutdown stops accepting connections and waits for in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error { return s.app.ShutdownWithContext(ctx) }

// ---------------------------------------------------------------------------
// Health and discovery

func (s *Server) healthz(c fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok"})
}

func (s *Server) readyz(c fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(c.Context(), 2*time.Second)
	defer cancel()
	checks := s.ready(ctx)
	out := fiber.Map{}
	healthy := true
	for name, err := range checks {
		if err != nil {
			healthy = false
			out[name] = "unavailable"
			s.log.Warn("readiness check failed", "dependency", name, "err", err)
		} else {
			out[name] = "ok"
		}
	}
	status := fiber.StatusOK
	if !healthy {
		status = fiber.StatusServiceUnavailable
	}
	return c.Status(status).JSON(fiber.Map{"ready": healthy, "checks": out})
}

func (s *Server) jwks(c fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, "application/jwk-set+json")
	c.Set("Cache-Control", "public, max-age=300, stale-while-revalidate=60")
	c.Set("Access-Control-Allow-Origin", "*")
	return c.Send(s.keys.JWKS())
}

func (s *Server) discovery(c fiber.Ctx) error {
	base := s.cfg.HTTP.PublicURL
	c.Set("Cache-Control", "public, max-age=3600")
	c.Set("Access-Control-Allow-Origin", "*")
	return c.JSON(fiber.Map{
		"issuer":                                s.cfg.Token.Issuer,
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"token_endpoint":                        base + "/v1/oauth/token",
		"authorization_endpoint":                strings.TrimSuffix(base, "/") + "/v1/oauth/{provider}/authorize",
		"code_challenge_methods_supported":      []string{"S256"},
		"userinfo_endpoint":                     base + "/v1/me",
	})
}
