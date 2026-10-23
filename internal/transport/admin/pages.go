package admin

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/i18n"
	"github.com/fatihacan1/warden/internal/oauth"
	"github.com/fatihacan1/warden/internal/settings"
	"github.com/fatihacan1/warden/internal/store"
)

func mailModeLabel(cfg *config.Config) string {
	switch cfg.MailDelivery() {
	case config.MailSMTP:
		return "SMTP via " + cfg.SMTP.Host
	case config.MailDirect:
		return "Direct from this server (test)"
	case config.MailInbox:
		return "Inbox, nothing is sent (test)"
	}
	return "Log (development)"
}

type depStatus struct {
	Name string
	OK   bool
}

type featureRow struct {
	Name, Value string
	On          bool
}

func (s *Server) overview(c fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(c.Context(), 3*time.Second)
	defer cancel()
	stats, err := s.Store.UserStats(ctx)
	if err != nil {
		return err
	}
	pending, dead, _ := s.Store.OutboxBacklog(ctx)
	var deps []depStatus
	for name, err := range s.Ready(ctx) {
		deps = append(deps, depStatus{Name: name, OK: err == nil})
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	var providers []string
	for _, d := range s.OAuth.Enabled() {
		providers = append(providers, d.DisplayName)
	}
	cfg := s.Config
	onOff := func(b bool) string {
		if b {
			return "On"
		}
		return "Off"
	}
	rt := s.Settings.Get()
	features := []featureRow{
		{"Sign-ups", onOff(rt.AllowSignup), rt.AllowSignup},
		{"Email verification required", onOff(rt.RequireEmailVerification), rt.RequireEmailVerification},
		{"Breached password check", onOff(rt.CheckBreachedPasswords), rt.CheckBreachedPasswords},
		{"Social providers", strings.Join(providers, ", "), len(providers) > 0},
		{"gRPC API", onOff(cfg.GRPC.Enabled), cfg.GRPC.Enabled},
		{"RabbitMQ events", onOff(s.Events), s.Events},
		{"S3 avatars", onOff(cfg.S3.Enabled), cfg.S3.Enabled},
		{"Mail delivery", mailModeLabel(cfg), cfg.MailDelivery() == config.MailSMTP},
		{"Sentry", onOff(cfg.Sentry.DSN != ""), cfg.Sentry.DSN != ""},
		{"GraphQL", onOff(cfg.GraphQL.Enabled), cfg.GraphQL.Enabled},
		{"Webhooks", strconv.Itoa(len(s.Webhooks.List())) + " endpoint(s)", len(s.Webhooks.List()) > 0},
		{"Publishable key required", onOff(rt.RequirePublishableKey), rt.RequirePublishableKey},
		{"Encryption", s.Config.EncryptionAlgorithm, true},
		{"Rate limiting", onOff(cfg.RateLimit.Enabled), cfg.RateLimit.Enabled},
	}
	recent, _ := s.Store.ListAudit(ctx, nil, 15)
	return s.render(c, fiber.StatusOK, "overview", "overview", "Overview", map[string]any{
		"Stats": stats, "OutboxPending": pending, "OutboxDead": dead, "Deps": deps, "Features": features,
		"PublicURL": cfg.HTTP.PublicURL, "KID": s.Keys.ActiveKID(), "KeySince": s.Keys.ActiveSince(), "Recent": recent,
	})
}

// ---------------------------------------------------------------------------
// Providers

func (s *Server) providersPage(c fiber.Ctx) error {
	pub := s.Config.HTTP.PublicURL
	local := false
	if u, err := url.Parse(pub); err == nil {
		h := u.Hostname()
		local = h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasSuffix(h, ".localhost")
	}
	return s.render(c, fiber.StatusOK, "providers", "providers", "Sign-in providers", map[string]any{
		"Providers": s.OAuth.Statuses(), "Redirects": s.Settings.Get().AllowedRedirectURIs,
		"PublicURL": pub, "Local": local, "HTTPS": strings.HasPrefix(pub, "https://"),
	})
}

func (s *Server) saveProvider(c fiber.Ctx) error {
	name := c.Params("name")
	def := s.OAuth.Definition(name)
	if def == nil {
		return fiber.ErrNotFound
	}
	values := map[string]string{}
	for _, f := range def.Fields {
		values[f.Key] = strings.TrimSpace(c.FormValue(f.Key))
	}
	enabled := c.FormValue("enabled") == "on"
	if err := s.OAuth.Save(c.Context(), name, enabled, values); err != nil {
		return backErr(c, "/admin/providers#"+name, err)
	}
	s.audit(c, "admin.provider_saved", map[string]any{"provider": name, "enabled": enabled})
	return back(c, "/admin/providers#"+name, "saved")
}

func (s *Server) resetProvider(c fiber.Ctx) error {
	name := c.Params("name")
	if err := s.OAuth.Reset(c.Context(), name); err != nil {
		return backErr(c, "/admin/providers", err)
	}
	s.audit(c, "admin.provider_reset", map[string]any{"provider": name})
	return back(c, "/admin/providers#"+name, "reset")
}

// ---------------------------------------------------------------------------
// Users

func (s *Server) usersPage(c fiber.Ctx) error {
	q := strings.TrimSpace(c.Query("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	page, _ := strconv.Atoi(c.Query("page", "1"))
	page = min(max(page, 1), 100000)
	users, total, err := s.Store.ListUsers(c.Context(), q, pageSize, (page-1)*pageSize)
	if err != nil {
		return err
	}
	pages := max(1, (total+pageSize-1)/pageSize)
	if page > pages {
		// Out of range (bookmarked page, users deleted): go to the last page.
		return c.Redirect().To("/admin/users?q=" + url.QueryEscape(q) + "&page=" + strconv.Itoa(pages))
	}
	first := (page-1)*pageSize + 1
	if total == 0 {
		first = 0
	}
	return s.render(c, fiber.StatusOK, "users", "users", "Users", map[string]any{
		"Users": users, "Total": total, "Query": q, "Page": page, "Pages": pages,
		"HasPrev": page > 1, "HasNext": page < pages, "Window": pageWindow(page, pages),
		"From": first, "To": (page-1)*pageSize + len(users), "Default": s.Settings.Get().DefaultLocale,
	})
}

// pageWindow lists the page numbers around the current one; 0 is a gap.
func pageWindow(page, pages int) []int {
	var out []int
	for p := 1; p <= pages; p++ {
		if p == 1 || p == pages || (p >= page-2 && p <= page+2) {
			out = append(out, p)
		} else if len(out) > 0 && out[len(out)-1] != 0 {
			out = append(out, 0)
		}
	}
	return out
}

func (s *Server) userPage(c fiber.Ctx) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	u, err := s.Store.GetUserByID(c.Context(), id)
	if errors.Is(err, domain.ErrNotFound) {
		return fiber.ErrNotFound
	}
	if err != nil {
		return err
	}
	sessions, _ := s.Store.ListActiveSessions(c.Context(), id)
	identities, _ := s.Store.ListIdentities(c.Context(), id)
	audit, _ := s.Store.ListAudit(c.Context(), &id, 30)
	codes, _ := s.Store.CountUnusedRecoveryCodes(c.Context(), id)
	return s.render(c, fiber.StatusOK, "user", "users", u.Email, map[string]any{
		"User": u, "Sessions": sessions, "Identities": identities, "Audit": audit, "RecoveryCodes": codes,
		"AvatarURL": s.Auth.AvatarURL(c.Context(), u), "Locales": i18n.Locales, "Default": s.Settings.Get().DefaultLocale,
	})
}

func (s *Server) userAction(c fiber.Ctx, fn func(id uuid.UUID) error, auditType, ok string) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	path := "/admin/users/" + id.String()
	if err := fn(id); err != nil {
		return backErr(c, path, err)
	}
	s.audit(c, auditType, map[string]any{"user_id": id})
	return back(c, path, ok)
}

func (s *Server) disableUser(c fiber.Ctx) error {
	return s.userAction(c, func(id uuid.UUID) error { return s.Auth.SetDisabled(c.Context(), id, true, "admin_ui") },
		"admin.user_disable", "disabled")
}

func (s *Server) enableUser(c fiber.Ctx) error {
	return s.userAction(c, func(id uuid.UUID) error { return s.Auth.SetDisabled(c.Context(), id, false, "admin_ui") },
		"admin.user_enable", "enabled")
}

func (s *Server) revokeUser(c fiber.Ctx) error {
	return s.userAction(c, func(id uuid.UUID) error {
		_, err := s.Auth.RevokeAllSessions(c.Context(), id, uuid.Nil, domain.RevokeAdmin, domain.RequestMeta{IP: c.IP()})
		return err
	}, "admin.sessions_revoke", "revoked")
}

func (s *Server) localeUser(c fiber.Ctx) error {
	return s.userAction(c, func(id uuid.UUID) error {
		_, err := s.Auth.SetLocale(c.Context(), id, c.FormValue("locale"))
		return err
	}, "admin.locale_set", "locale")
}

func (s *Server) rolesUser(c fiber.Ctx) error {
	var roles []string
	for _, r := range strings.Split(c.FormValue("roles"), ",") {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" {
			roles = append(roles, r)
		}
	}
	return s.userAction(c, func(id uuid.UUID) error { return s.Auth.SetRoles(c.Context(), id, roles, "admin_ui") },
		"admin.roles_set", "roles")
}

// ---------------------------------------------------------------------------
// Keys and setup

func (s *Server) keysPage(c fiber.Ctx) error {
	rows, err := s.Store.ListSigningKeys(c.Context(), time.Now().Add(-s.Config.Token.AccessTTL-10*time.Minute))
	if err != nil {
		return err
	}
	return s.render(c, fiber.StatusOK, "keys", "keys", "Signing keys", map[string]any{
		"Keys": rows, "Active": s.Keys.ActiveKID(), "JWKS": s.Config.HTTP.PublicURL + "/.well-known/jwks.json",
		"Rotation": s.Config.Token.KeyRotationInterval, "AccessTTL": s.Config.Token.AccessTTL,
	})
}

func (s *Server) rotateKeys(c fiber.Ctx) error {
	if err := s.Keys.Rotate(c.Context()); err != nil {
		return backErr(c, "/admin/keys", err)
	}
	s.audit(c, "admin.keys_rotated", map[string]any{"kid": s.Keys.ActiveKID()})
	return back(c, "/admin/keys", "rotated")
}

func (s *Server) setupPage(c fiber.Ctx) error {
	cfg := s.Config
	var enabled []*oauth.Definition = s.OAuth.Enabled()
	return s.render(c, fiber.StatusOK, "setup", "setup", "Integrate", map[string]any{
		"PublicURL": cfg.HTTP.PublicURL, "Issuer": cfg.Token.Issuer, "Audience": strings.Join(cfg.Token.Audience, ","),
		"JWKS": cfg.HTTP.PublicURL + "/.well-known/jwks.json", "Redirects": s.Settings.Get().AllowedRedirectURIs,
		"Providers": enabled, "GRPC": cfg.GRPC.Enabled, "GRPCAddr": cfg.GRPC.Addr, "Exchange": cfg.RabbitMQ.Exchange,
		"Events": s.Events, "CORS": s.Settings.Get().CORSOrigins,
	})
}

var _ = store.AuditEvent{}

// ---------------------------------------------------------------------------
// Runtime settings

func (s *Server) settingsPage(c fiber.Ctx) error {
	over, since := s.Settings.Overridden()
	return s.render(c, fiber.StatusOK, "settings", "settings", "Settings", map[string]any{
		"S": s.Settings.Get(), "Overridden": over, "Since": since, "Env": s.Settings.Env(),
		"Production": s.Config.IsProduction(), "Locales": i18n.Locales, "MyIP": c.IP(),
		"AllowlistForcedOff": s.Config.Admin.IPAllowlistDisabled,
	})
}

func lines(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' })
}

func (s *Server) saveSettings(c fiber.Ctx) error {
	atoi := func(k string) int {
		n, err := strconv.Atoi(strings.TrimSpace(c.FormValue(k)))
		if err != nil {
			return -1
		}
		return n
	}
	r := settings.Runtime{
		AllowSignup:              c.FormValue("allow_signup") == "on",
		RequireEmailVerification: c.FormValue("require_email_verification") == "on",
		CheckBreachedPasswords:   c.FormValue("check_breached_passwords") == "on",
		PasswordMinLength:        atoi("password_min_length"),
		LockoutThreshold:         atoi("lockout_threshold"),
		AppName:                  c.FormValue("app_name"),
		VerifyEmailURL:           c.FormValue("verify_email_url"),
		ResetPasswordURL:         c.FormValue("reset_password_url"),
		AllowedRedirectURIs:      lines(c.FormValue("allowed_redirect_uris")),
		CORSOrigins:              lines(c.FormValue("cors_origins")),
		RequirePublishableKey:    c.FormValue("require_publishable_key") == "on",
		DefaultLocale:            c.FormValue("default_locale"),
		NotifyNewDevice:          c.FormValue("notify_new_device") == "on",
		NotifyAccountLocked:      c.FormValue("notify_account_locked") == "on",
		AdminIPAllowlist:         c.FormValue("admin_ip_allowlist") == "on",
		AdminAllowedIPs:          lines(c.FormValue("admin_allowed_ips")),
	}
	var addedIP bool
	r.AdminAllowedIPs, addedIP = withCurrentIP(r.AdminIPAllowlist, r.AdminAllowedIPs, c.IP())
	if r.RequirePublishableKey && !s.APIKeys.HasPublishable() {
		return backErr(c, "/admin/settings", domain.ErrValidation.WithMessage("Create a publishable key on the API keys page before requiring one, or every app is locked out."))
	}
	if err := s.Settings.Save(c.Context(), r); err != nil {
		return backErr(c, "/admin/settings", err)
	}
	s.audit(c, "admin.settings_saved", map[string]any{
		"allow_signup": r.AllowSignup, "require_email_verification": r.RequireEmailVerification,
		"check_breached_passwords": r.CheckBreachedPasswords, "require_publishable_key": r.RequirePublishableKey,
		"admin_ip_allowlist": r.AdminIPAllowlist, "admin_allowed_ips": r.AdminAllowedIPs, "default_locale": r.DefaultLocale,
		"notify_new_device": r.NotifyNewDevice, "notify_account_locked": r.NotifyAccountLocked,
	})
	if addedIP {
		return back(c, "/admin/settings", "settingsip")
	}
	return back(c, "/admin/settings", "settings")
}

func (s *Server) resetSettings(c fiber.Ctx) error {
	if err := s.Settings.Reset(c.Context()); err != nil {
		return backErr(c, "/admin/settings", err)
	}
	s.audit(c, "admin.settings_reset", nil)
	return back(c, "/admin/settings", "envreset")
}
