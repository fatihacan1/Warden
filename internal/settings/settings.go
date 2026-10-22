// Package settings holds the feature toggles and policies that can be changed
// at runtime from the admin UI, without a restart.
//
// Environment variables provide the defaults. Settings saved in the admin UI
// override them as a whole and can be reset to fall back to the environment.
// Infrastructure (database, Redis, S3, SMTP, keys) deliberately stays in the
// environment: it holds secrets and cannot change without a restart.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/i18n"
)

// Runtime are the editable settings.
type Runtime struct {
	AllowSignup              bool     `json:"allow_signup"`
	RequireEmailVerification bool     `json:"require_email_verification"`
	CheckBreachedPasswords   bool     `json:"check_breached_passwords"`
	PasswordMinLength        int      `json:"password_min_length"`
	LockoutThreshold         int      `json:"lockout_threshold"`
	AppName                  string   `json:"app_name"`
	VerifyEmailURL           string   `json:"verify_email_url"`
	ResetPasswordURL         string   `json:"reset_password_url"`
	AllowedRedirectURIs      []string `json:"allowed_redirect_uris"`
	CORSOrigins              []string `json:"cors_origins"`
	RequirePublishableKey    bool     `json:"require_publishable_key"`
	DefaultLocale            string   `json:"default_locale"`
	NotifyNewDevice          bool     `json:"notify_new_device"`
	NotifyAccountLocked      bool     `json:"notify_account_locked"`
	// AdminIPAllowlist restricts the admin UI to AdminAllowedIPs.
	AdminIPAllowlist bool     `json:"admin_ip_allowlist"`
	AdminAllowedIPs  []string `json:"admin_allowed_ips"`
}

// Store persists the admin overrides.
type Store interface {
	GetRuntimeSettings(ctx context.Context) ([]byte, time.Time, error)
	SaveRuntimeSettings(ctx context.Context, data []byte) error
	DeleteRuntimeSettings(ctx context.Context) error
}

type state struct {
	current    *Runtime
	overridden bool
	updatedAt  time.Time
}

// Manager serves the current settings to every request (lock-free reads) and
// reloads them periodically so changes made on one replica reach the others.
type Manager struct {
	env        Runtime
	production bool
	store      Store
	log        *slog.Logger
	st         atomic.Pointer[state]
}

// FromConfig extracts the environment defaults.
func FromConfig(c *config.Config) Runtime {
	return Runtime{
		AllowSignup:              c.Auth.AllowSignup,
		RequireEmailVerification: c.Auth.RequireEmailVerification,
		CheckBreachedPasswords:   c.Password.CheckBreached,
		PasswordMinLength:        c.Password.MinLength,
		LockoutThreshold:         c.Auth.LockoutThreshold,
		AppName:                  c.Auth.AppName,
		VerifyEmailURL:           c.Auth.VerifyEmailURL,
		ResetPasswordURL:         c.Auth.ResetPasswordURL,
		AllowedRedirectURIs:      slices.Clone(c.Auth.AllowedRedirectURIs),
		CORSOrigins:              slices.Clone(c.HTTP.CORSOrigins),
		RequirePublishableKey:    c.Auth.RequirePublishableKey,
		DefaultLocale:            c.Auth.DefaultLocale,
		NotifyNewDevice:          c.Auth.NotifyNewDevice,
		NotifyAccountLocked:      c.Auth.NotifyAccountLocked,
		AdminIPAllowlist:         len(c.Admin.AllowedIPs) > 0,
		AdminAllowedIPs:          slices.Clone(c.Admin.AllowedIPs),
	}
}

func NewManager(c *config.Config, st Store, log *slog.Logger) *Manager {
	m := &Manager{env: FromConfig(c), production: c.IsProduction(), store: st, log: log}
	env := m.env
	m.st.Store(&state{current: &env})
	return m
}

// NewStatic returns a Manager that always serves r (tests).
func NewStatic(r Runtime) *Manager {
	m := &Manager{env: r}
	m.st.Store(&state{current: &r})
	return m
}

// Get returns the current settings. The returned value must not be modified.
func (m *Manager) Get() *Runtime { return m.st.Load().current }

// Overridden reports whether admin settings are active, and since when.
func (m *Manager) Overridden() (bool, time.Time) {
	s := m.st.Load()
	return s.overridden, s.updatedAt
}

// Env returns the environment defaults.
func (m *Manager) Env() Runtime { return m.env }

// Reload reads the admin overrides from the database.
func (m *Manager) Reload(ctx context.Context) error {
	if m.store == nil {
		return nil
	}
	data, at, err := m.store.GetRuntimeSettings(ctx)
	if errors.Is(err, domain.ErrNotFound) {
		env := m.env
		m.st.Store(&state{current: &env})
		return nil
	}
	if err != nil {
		return err
	}
	r := m.env // fields missing from older saved JSON keep env values
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("settings: decode: %w", err)
	}
	if err := r.Validate(m.production); err != nil {
		// Never apply invalid settings; keep serving the previous ones.
		return fmt.Errorf("settings: stored settings are invalid: %w", err)
	}
	m.st.Store(&state{current: &r, overridden: true, updatedAt: at})
	return nil
}

// Run reloads periodically until ctx is cancelled.
func (m *Manager) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Reload(ctx); err != nil {
				m.log.Error("runtime settings reload failed", "err", err)
			}
		}
	}
}

// Save validates and stores new settings, then applies them immediately.
func (m *Manager) Save(ctx context.Context, r Runtime) error {
	r.normalize()
	if err := r.Validate(m.production); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := m.store.SaveRuntimeSettings(ctx, data); err != nil {
		return err
	}
	return m.Reload(ctx)
}

// Reset removes the admin overrides; environment values apply again.
func (m *Manager) Reset(ctx context.Context) error {
	if err := m.store.DeleteRuntimeSettings(ctx); err != nil {
		return err
	}
	return m.Reload(ctx)
}

func (r *Runtime) normalize() {
	r.AppName = strings.TrimSpace(r.AppName)
	r.VerifyEmailURL = strings.TrimSpace(r.VerifyEmailURL)
	r.ResetPasswordURL = strings.TrimSpace(r.ResetPasswordURL)
	r.AllowedRedirectURIs = cleanList(r.AllowedRedirectURIs)
	origins := make([]string, 0, len(r.CORSOrigins))
	for _, o := range r.CORSOrigins {
		origins = append(origins, strings.TrimRight(strings.TrimSpace(o), "/"))
	}
	r.CORSOrigins = cleanList(origins)
	r.AdminAllowedIPs = cleanList(r.AdminAllowedIPs)
	r.DefaultLocale = strings.ToLower(strings.TrimSpace(r.DefaultLocale))
}

func cleanList(in []string) []string {
	out := []string{}
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// Validate applies the same safety rules as the environment configuration.
func (r *Runtime) Validate(production bool) error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if r.PasswordMinLength < 8 || r.PasswordMinLength > 64 {
		add("Minimum password length must be between 8 and 64.")
	}
	if r.LockoutThreshold < 3 || r.LockoutThreshold > 100 {
		add("Lockout threshold must be between 3 and 100 failed attempts.")
	}
	if r.AppName == "" || len(r.AppName) > 60 {
		add("App name must be 1 to 60 characters.")
	}
	for _, t := range []string{r.VerifyEmailURL, r.ResetPasswordURL} {
		u, err := url.Parse(strings.ReplaceAll(t, "{token}", "x"))
		if err != nil || !strings.Contains(t, "{token}") || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			add("Email link templates must be absolute http(s) URLs containing {token}: %q", t)
		} else if production && u.Scheme != "https" {
			add("Email link templates must use https in production: %q", t)
		}
	}
	if len(r.AllowedRedirectURIs) > 50 || len(r.CORSOrigins) > 50 {
		add("At most 50 redirect URIs and 50 CORS origins.")
	}
	for _, raw := range r.AllowedRedirectURIs {
		u, err := url.Parse(raw)
		switch {
		case err != nil || u.Scheme == "" || u.Fragment != "" || u.User != nil:
			add("Invalid redirect URI: %q", raw)
		case strings.EqualFold(u.Scheme, "javascript") || strings.EqualFold(u.Scheme, "data"):
			add("Redirect URI scheme not allowed: %q", raw)
		case production && u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1":
			add("Redirect URIs must use https in production: %q", raw)
		}
	}
	for _, o := range r.CORSOrigins {
		u, err := url.Parse(o)
		if o == "*" || strings.EqualFold(o, "null") || err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			add("CORS origins must be exact origins like https://app.example.com (no *, paths or null): %q", o)
		}
	}
	if r.DefaultLocale != "" && !i18n.Supported(r.DefaultLocale) {
		add("Default email language %q is not supported.", r.DefaultLocale)
	}
	if len(r.AdminAllowedIPs) > 100 {
		add("At most 100 admin IP entries.")
	}
	for _, p := range r.AdminAllowedIPs {
		if _, _, err := net.ParseCIDR(p); err != nil && net.ParseIP(p) == nil {
			add("Admin allowlist entries must be IPs or CIDR ranges like 203.0.113.7 or 10.0.0.0/8: %q", p)
		}
	}
	if r.AdminIPAllowlist && len(r.AdminAllowedIPs) == 0 {
		add("Add at least one IP before turning on the admin IP allowlist.")
	}
	return errors.Join(errs...)
}
