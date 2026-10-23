// Package admin serves the operator UI, Prometheus metrics and probes on a
// private port (ADMIN_ADDR). Never expose this port to the internet: reach it
// through a VPN, an SSH tunnel or your cluster network.
package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"

	"github.com/fatihacan1/warden/internal/accesstokens"
	"github.com/fatihacan1/warden/internal/apikeys"
	"github.com/fatihacan1/warden/internal/auth"
	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/i18n"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/oauth"
	"github.com/fatihacan1/warden/internal/oauthclients"
	"github.com/fatihacan1/warden/internal/observability"
	"github.com/fatihacan1/warden/internal/ratelimit"
	"github.com/fatihacan1/warden/internal/settings"
	"github.com/fatihacan1/warden/internal/store"
	"github.com/fatihacan1/warden/internal/token"
	"github.com/fatihacan1/warden/internal/webhooks"
)

//go:embed templates/*.html static/* static/providers/* static/flags/*
var assets embed.FS

// Deps are the collaborators of the admin server.
type Deps struct {
	Config   *config.Config
	Auth     *auth.Service
	Store    *store.Store
	Redis    *redis.Client
	OAuth    *oauth.Registry
	Keys     *token.KeyManager
	Limiter  *ratelimit.Limiter
	Metrics  *observability.Metrics
	Log      *slog.Logger
	Ready    func(ctx context.Context) map[string]error
	Events   bool
	Settings *settings.Manager
	APIKeys  *apikeys.Manager
	Webhooks *webhooks.Manager
	Mail     *mailer.Library
	Renderer *mailer.Renderer
	Sender   mailer.Sender

	AccessTokens *accesstokens.Manager
	Clients      *oauthclients.Manager
}

type Server struct {
	Deps
	app       *fiber.App
	pages     map[string]*template.Template
	tokenHash [32]byte
	enabled   bool
	assets    string // content hash for cache busting static files
	reference []refGroup
}

const (
	cookieName = "warden_admin"
	pageSize   = 50
)

func New(d Deps) (*Server, error) {
	s := &Server{Deps: d, enabled: d.Config.Admin.Token != ""}
	s.tokenHash = sha256.Sum256([]byte(d.Config.Admin.Token))
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	ref, err := buildReference()
	if err != nil {
		return nil, fmt.Errorf("admin: api/openapi.yaml: %w", err)
	}
	s.reference = ref
	h := sha256.New()
	for _, f := range []string{"static/admin.css", "static/admin.js"} {
		b, _ := assets.ReadFile(f)
		h.Write(b)
	}
	s.assets = hex.EncodeToString(h.Sum(nil))[:12]
	s.app = fiber.New(fiber.Config{
		AppName:      "warden-admin",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		BodyLimit:    256 << 10,
		ErrorHandler: s.errorHandler,
	})
	s.routes()
	return s, nil
}

func (s *Server) App() *fiber.App { return s.app }

// StaticFS exposes the admin stylesheet and icons (the setup wizard reuses them).
func StaticFS() fs.FS {
	sub, _ := fs.Sub(assets, "static")
	return sub
}

func (s *Server) Listen(addr string) error {
	return s.app.Listen(addr, fiber.ListenConfig{DisableStartupMessage: true})
}

func (s *Server) Shutdown(ctx context.Context) error { return s.app.ShutdownWithContext(ctx) }

func (s *Server) routes() {
	a := s.app
	a.Use(func(c fiber.Ctx) error {
		h := &c.Response().Header
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data: https: http:; frame-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		return c.Next()
	})
	a.Get("/healthz", func(c fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ok"}) })
	a.Get("/metrics", adaptor.HTTPHandler(promhttp.HandlerFor(s.Metrics.Registry, promhttp.HandlerOpts{EnableOpenMetrics: true})))
	static, _ := fs.Sub(assets, "static")
	a.Get("/admin/static/*", func(c fiber.Ctx) error {
		name := c.Params("*")
		b, err := fs.ReadFile(static, name)
		if err != nil || strings.Contains(name, "..") {
			return fiber.ErrNotFound
		}
		switch {
		case strings.HasSuffix(name, ".css"):
			c.Type("css")
		case strings.HasSuffix(name, ".js"):
			c.Type("js")
		case strings.HasSuffix(name, ".svg"):
			c.Set(fiber.HeaderContentType, "image/svg+xml")
		}
		c.Set("Cache-Control", "public, max-age=31536000, immutable") // URLs carry a content hash
		return c.Send(b)
	})

	if !s.enabled {
		a.Get("/", func(c fiber.Ctx) error {
			return c.Type("txt").SendString("Admin UI is disabled. Set ADMIN_TOKEN (32+ chars) to enable it. /metrics and /healthz are available.")
		})
		return
	}
	a.Use("/admin", s.ipAllowlist)
	a.Use("/api", s.ipAllowlist)
	s.apiRoutes(a.Group("/api/v1", s.apiAuth))
	a.Get("/", func(c fiber.Ctx) error { return c.Redirect().To("/admin") })
	a.Get("/admin/login", s.loginPage)
	a.Post("/admin/login", s.originCheck, s.login)

	g := a.Group("/admin", s.requireSession)
	g.Post("/logout", s.originCheck, s.csrf, s.logout)
	g.Get("", s.overview)
	g.Get("/settings", s.settingsPage)
	g.Post("/settings", s.originCheck, s.csrf, s.saveSettings)
	g.Post("/settings/reset", s.originCheck, s.csrf, s.resetSettings)
	g.Get("/providers", s.providersPage)
	g.Post("/providers/:name", s.originCheck, s.csrf, s.saveProvider)
	g.Post("/providers/:name/reset", s.originCheck, s.csrf, s.resetProvider)
	g.Get("/users", s.usersPage)
	g.Get("/users/:id", s.userPage)
	g.Post("/users/:id/disable", s.originCheck, s.csrf, s.disableUser)
	g.Post("/users/:id/enable", s.originCheck, s.csrf, s.enableUser)
	g.Post("/users/:id/revoke", s.originCheck, s.csrf, s.revokeUser)
	g.Post("/users/:id/roles", s.originCheck, s.csrf, s.rolesUser)
	g.Post("/users/:id/locale", s.originCheck, s.csrf, s.localeUser)
	g.Get("/keys", s.keysPage)
	g.Post("/keys/rotate", s.originCheck, s.csrf, s.rotateKeys)
	g.Get("/setup", s.setupPage)

	g.Get("/api-keys", s.apiKeysPage)
	g.Post("/api-keys", s.originCheck, s.csrf, s.createAPIKey)
	g.Get("/api-keys/:id", s.apiKeyPage)
	g.Post("/api-keys/:id", s.originCheck, s.csrf, s.updateAPIKey)
	g.Post("/api-keys/:id/revoke", s.originCheck, s.csrf, s.revokeAPIKey)

	g.Get("/webhooks", s.webhooksPage)
	g.Post("/webhooks", s.originCheck, s.csrf, s.createWebhook)
	g.Get("/webhooks/:id", s.webhookPage)
	g.Post("/webhooks/:id", s.originCheck, s.csrf, s.updateWebhook)
	g.Post("/webhooks/:id/test", s.originCheck, s.csrf, s.testWebhook)
	g.Post("/webhooks/:id/rotate", s.originCheck, s.csrf, s.rotateWebhookSecret)
	g.Post("/webhooks/:id/secret", s.originCheck, s.csrf, s.revealWebhookSecret)
	g.Post("/webhooks/:id/delete", s.originCheck, s.csrf, s.deleteWebhook)
	g.Post("/webhooks/:id/deliveries/:delivery/retry", s.originCheck, s.csrf, s.retryDelivery)

	g.Get("/emails", s.emailsPage)
	g.Get("/emails/:name", s.emailPage)
	g.Post("/emails/:name", s.originCheck, s.csrf, s.saveEmail)
	g.Post("/emails/:name/reset", s.originCheck, s.csrf, s.resetEmail)
	g.Get("/emails/:name/preview", s.previewEmail)
	g.Post("/emails/:name/preview", s.originCheck, s.csrf, s.previewEmail)
	g.Post("/emails/:name/test", s.originCheck, s.csrf, s.testEmail)

	g.Get("/access-tokens", s.accessTokensPage)
	g.Post("/access-tokens", s.originCheck, s.csrf, s.createAccessToken)
	g.Post("/access-tokens/:id/revoke", s.originCheck, s.csrf, s.revokeAccessToken)

	g.Get("/service-clients", s.serviceClientsPage)
	g.Post("/service-clients", s.originCheck, s.csrf, s.createServiceClient)
	g.Post("/service-clients/:id/rotate", s.originCheck, s.csrf, s.rotateServiceClient)
	g.Post("/service-clients/:id/revoke", s.originCheck, s.csrf, s.revokeServiceClient)

	g.Get("/docs", s.docsPage)
	g.Get("/openapi.yaml", s.openAPI)
}

// ---------------------------------------------------------------------------
// Templates

var funcs = template.FuncMap{
	"date": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			if v.IsZero() {
				return "-"
			}
			return v.UTC().Format("2006-01-02 15:04 UTC")
		case *time.Time:
			if v == nil {
				return "-"
			}
			return v.UTC().Format("2006-01-02 15:04 UTC")
		}
		return "-"
	},
	"ago": func(t time.Time) string {
		d := time.Since(t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return strconv.Itoa(int(d.Minutes())) + "m ago"
		case d < 48*time.Hour:
			return strconv.Itoa(int(d.Hours())) + "h ago"
		default:
			return strconv.Itoa(int(d.Hours()/24)) + "d ago"
		}
	},
	"join": strings.Join,
	"json": func(v any) string {
		b, _ := json.Marshal(v)
		return string(b)
	},
	"add":   func(a, b int) int { return a + b },
	"deref": func(t *time.Time) time.Time { return *t },
	"dict": func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	},
	"providerIcon": providerIcon,
	"sub":          func(a, b int) int { return a - b },
	"flag": func(code string) template.HTML {
		l := i18n.Lookup(code)
		return template.HTML(`<img class="flag" src="/admin/static/flags/` + l.Code + `.svg" alt="" width="18" height="12">`) // #nosec G203 -- fixed list of codes
	},
	"langName":  func(code string) string { return i18n.Lookup(code).Name },
	"device":    auth.DescribeDevice,
	"hasSuffix": strings.HasSuffix,
	"until": func(t time.Time) string {
		d := time.Until(t)
		switch {
		case d < time.Hour:
			return "in " + strconv.Itoa(max(1, int(d.Minutes()))) + "m"
		case d < 48*time.Hour:
			return "in " + strconv.Itoa(int(d.Hours())) + "h"
		default:
			return "in " + strconv.Itoa(int(d.Hours()/24)) + "d"
		}
	},
}

// providerIcon inlines a provider's brand mark (Simple Icons, CC0) so it can
// use currentColor and needs no extra request. Unknown providers get none.
func providerIcon(name string) template.HTML {
	b, err := assets.ReadFile("static/providers/" + name + ".svg")
	if err != nil {
		return ""
	}
	svg := strings.Replace(string(b), "<svg ", `<svg class="pv-icon pv-`+name+`" aria-hidden="true" focusable="false" fill="currentColor" `, 1)
	return template.HTML(svg) // #nosec G203 -- trusted file embedded at build time
}

func (s *Server) parseTemplates() error {
	s.pages = map[string]*template.Template{}
	entries, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimPrefix(e, "templates/"), ".html")
		if name == "layout" || strings.HasPrefix(name, "_") {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/_partials.html", e)
		if err != nil {
			return err
		}
		s.pages[name] = t
	}
	return nil
}

type view struct {
	Title   string
	Nav     string
	CSRF    string
	Flash   string
	Error   string
	Version string
	Env     string
	Assets  string
	Data    any
}

func (s *Server) render(c fiber.Ctx, status int, page, nav, title string, data any) error {
	t, ok := s.pages[page]
	if !ok {
		return errors.New("admin: unknown page " + page)
	}
	v := view{Title: title, Nav: nav, Data: data, Version: observability.Version, Env: s.Config.Env, Assets: s.assets,
		Flash: flashes[c.Query("ok")], Error: takeFlashError(c)}
	if sess, ok := c.Locals("admin_session").(*adminSession); ok {
		v.CSRF = sess.CSRF
	}
	c.Type("html", "utf-8")
	c.Status(status)
	return t.ExecuteTemplate(c.Response().BodyWriter(), "layout", v)
}

var flashes = map[string]string{
	"saved":          "Settings saved and applied.",
	"reset":          "Admin override removed. The provider now uses environment settings.",
	"disabled":       "User disabled and signed out everywhere.",
	"enabled":        "User enabled.",
	"revoked":        "All sessions revoked.",
	"roles":          "Roles updated. They apply on the user's next token refresh.",
	"rotated":        "Signing key rotated. Previous key stays published until its tokens expire.",
	"signedout":      "Signed out.",
	"keysaved":       "API key updated.",
	"tokenrevoked":   "Access token revoked. Requests with it are rejected immediately.",
	"clientrevoked":  "Service client revoked. It can no longer get tokens; tokens already issued expire on their own.",
	"keyrevoked":     "API key revoked. Requests using it are rejected immediately.",
	"webhooktest":    "Test event queued. It appears in the deliveries below within a few seconds.",
	"webhookdeleted": "Webhook deleted.",
	"retry":          "Delivery queued for another attempt.",
	"emailsaved":     "Template saved. New emails use it within 15 seconds on every replica.",
	"emailreset":     "Template reset to the built-in version.",
	"emailtest":      "Test email sent.",
	"settings":       "Settings saved. They apply to every replica within 15 seconds.",
	"settingsip":     "Settings saved. Your current address was added to the admin allowlist so you stay signed in.",
	"locale":         "Email language updated.",
	"envreset":       "Admin overrides removed. Environment values apply again.",
}

func (s *Server) errorHandler(c fiber.Ctx, err error) error {
	status := fiber.StatusInternalServerError
	msg := "Something went wrong."
	var fe *fiber.Error
	if de := domain.AsError(err); de != nil {
		status, msg = de.Status, de.Message
	} else if errors.As(err, &fe) {
		status, msg = fe.Code, fe.Message
	} else {
		s.Log.Error("admin error", "err", err, "path", c.Path())
	}
	c.Type("txt")
	return c.Status(status).SendString(msg)
}

// ---------------------------------------------------------------------------
// Session, CSRF and origin checks

type adminSession struct {
	CSRF    string    `json:"csrf"`
	Created time.Time `json:"created"`
	// TokenFP binds the session to the admin token: rotating ADMIN_TOKEN
	// immediately invalidates every existing admin session.
	TokenFP string `json:"tfp"`
	// Seen is the last request, for the idle timeout.
	Seen time.Time `json:"seen"`
	// IP the session was created from; recorded in the audit log.
	IP string `json:"ip"`
}

func (s *Server) tokenFingerprint() string { return randtoken.HashHex(string(s.tokenHash[:]))[:16] }

func sessionKey(cookie string) string { return "admin:sess:" + randtoken.HashHex(cookie) }

func (s *Server) requireSession(c fiber.Ctx) error {
	raw := c.Cookies(cookieName)
	if raw == "" || len(raw) > 128 {
		return c.Redirect().To("/admin/login")
	}
	b, err := s.Redis.Get(c.Context(), sessionKey(raw)).Bytes()
	if err != nil {
		return c.Redirect().To("/admin/login")
	}
	var sess adminSession
	if json.Unmarshal(b, &sess) != nil || subtle.ConstantTimeCompare([]byte(sess.TokenFP), []byte(s.tokenFingerprint())) != 1 {
		return c.Redirect().To("/admin/login")
	}
	// Idle timeout: a session left open on a shared or stolen machine ends on
	// its own. Absolute lifetime is the Redis TTL set at login.
	now := time.Now()
	if !sess.Seen.IsZero() && now.Sub(sess.Seen) > s.Config.Admin.SessionIdle {
		s.Redis.Del(c.Context(), sessionKey(raw))
		return c.Redirect().To("/admin/login?expired=1")
	}
	if now.Sub(sess.Seen) > time.Minute {
		sess.Seen = now
		if nb, err := json.Marshal(sess); err == nil {
			s.Redis.SetArgs(c.Context(), sessionKey(raw), nb, redis.SetArgs{KeepTTL: true})
		}
	}
	c.Locals("admin_session", &sess)
	return c.Next()
}

// originCheck rejects cross-site form posts (defense in depth next to the
// SameSite=Strict cookie and the CSRF token).
func (s *Server) originCheck(c fiber.Ctx) error {
	origin := c.Get(fiber.HeaderOrigin)
	if origin == "" {
		origin = c.Get(fiber.HeaderReferer)
	}
	if origin == "" {
		return c.Next() // non-browser client; the session cookie and CSRF token still apply
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host != string(c.Request().Host()) {
		return fiber.NewError(fiber.StatusForbidden, "Cross-origin request rejected.")
	}
	return c.Next()
}

func (s *Server) csrf(c fiber.Ctx) error {
	sess, _ := c.Locals("admin_session").(*adminSession)
	got := c.FormValue("_csrf")
	if sess == nil || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRF)) != 1 {
		return fiber.NewError(fiber.StatusForbidden, "Invalid or missing CSRF token. Reload the page and try again.")
	}
	return c.Next()
}

func (s *Server) loginPage(c fiber.Ctx) error {
	return s.render(c, fiber.StatusOK, "login", "", "Sign in", map[string]any{"Expired": c.Query("expired") == "1"})
}

func (s *Server) login(c fiber.Ctx) error {
	if d := s.Limiter.Allow(c.Context(), ratelimit.Per("admin_login", 10, 15*time.Minute), c.IP()); !d.Allowed {
		return s.render(c, fiber.StatusTooManyRequests, "login", "", "Sign in", map[string]string{"Error": "Too many attempts. Wait a few minutes."})
	}
	got := sha256.Sum256([]byte(c.FormValue("token")))
	if subtle.ConstantTimeCompare(got[:], s.tokenHash[:]) != 1 {
		s.Log.Warn("admin login failed", "ip", c.IP())
		s.audit(c, "admin.login_failed", nil)
		return s.render(c, fiber.StatusUnauthorized, "login", "", "Sign in", map[string]string{"Error": "That token is not valid."})
	}
	raw := randtoken.New(32)
	sess := adminSession{CSRF: randtoken.New(32), Created: time.Now(), TokenFP: s.tokenFingerprint(), Seen: time.Now(), IP: c.IP()}
	b, _ := json.Marshal(sess)
	if err := s.Redis.Set(c.Context(), sessionKey(raw), b, s.Config.Admin.SessionTTL).Err(); err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{
		Name: cookieName, Value: raw, Path: "/admin", HTTPOnly: true, SameSite: fiber.CookieSameSiteStrictMode,
		Secure: s.Config.AdminCookieSecure(), MaxAge: int(s.Config.Admin.SessionTTL.Seconds()),
	})
	s.audit(c, "admin.login", nil)
	return c.Redirect().Status(fiber.StatusSeeOther).To("/admin")
}

func (s *Server) logout(c fiber.Ctx) error {
	if raw := c.Cookies(cookieName); raw != "" {
		s.Redis.Del(c.Context(), sessionKey(raw))
	}
	c.Cookie(&fiber.Cookie{Name: cookieName, Value: "", Path: "/admin", MaxAge: -1, HTTPOnly: true, SameSite: fiber.CookieSameSiteStrictMode})
	return c.Redirect().Status(fiber.StatusSeeOther).To("/admin/login")
}

func (s *Server) audit(c fiber.Ctx, typ string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if err := s.Store.InsertAudit(context.WithoutCancel(c.Context()), store.AuditEvent{
		Type: typ, IP: c.IP(), UserAgent: c.Get(fiber.HeaderUserAgent), Metadata: data,
	}); err != nil {
		s.Log.Warn("admin audit failed", "err", err)
	}
}

func back(c fiber.Ctx, path, ok string) error {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return c.Redirect().Status(fiber.StatusSeeOther).To(path + sep + "ok=" + url.QueryEscape(ok))
}

// backErr carries the error message in a short-lived cookie rather than the
// URL, so nobody can craft an admin link that displays attacker text.
func backErr(c fiber.Ctx, path string, err error) error {
	msg := err.Error()
	if de := domain.AsError(err); de != nil {
		msg = de.Message
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	c.Cookie(&fiber.Cookie{Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(msg)), Path: "/admin",
		MaxAge: 60, HTTPOnly: true, SameSite: fiber.CookieSameSiteStrictMode})
	return c.Redirect().Status(fiber.StatusSeeOther).To(path)
}

const flashCookie = "warden_admin_flash"

func takeFlashError(c fiber.Ctx) string {
	raw := c.Cookies(flashCookie)
	if raw == "" {
		return ""
	}
	c.Cookie(&fiber.Cookie{Name: flashCookie, Value: "", Path: "/admin", MaxAge: -1, HTTPOnly: true, SameSite: fiber.CookieSameSiteStrictMode})
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) > 300 {
		return ""
	}
	return string(b)
}

func parseUserID(c fiber.Ctx) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return uuid.Nil, fiber.ErrNotFound
	}
	return id, nil
}
