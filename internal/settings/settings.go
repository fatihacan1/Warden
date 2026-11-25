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

	"github.com/fatihacan1/warden/internal/captcha"
	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/i18n"
)

// Values of Runtime.EmailPolicy.
const (
	EmailPolicyAny   = "any"
	EmailPolicyKnown = "known"
)

// Runtime are the editable settings.
type Runtime struct {
	AllowSignup              bool     `json:"allow_signup"`
	RequireWorkEmail         bool     `json:"require_work_email"`
	WorkEmailExtraBlocked    []string `json:"work_email_extra_blocked"`
	WorkEmailAllowed         []string `json:"work_email_allowed"`
	EmailPolicy              string   `json:"email_policy"`
	EmailAllowCompanies      bool     `json:"email_allow_companies"`
	EmailAllowSchools        bool     `json:"email_allow_schools"`
	EmailAllowedDomains      []string `json:"email_allowed_domains"`
	EmailBlockedDomains      []string `json:"email_blocked_domains"`
	RequireEmailVerification bool     `json:"require_email_verification"`
	HideExistingAccounts     bool     `json:"hide_existing_accounts"`
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

	// Cloudflare Turnstile bot protection.
	TurnstileEnabled bool   `json:"turnstile_enabled"`
	TurnstileSiteKey string `json:"turnstile_site_key"`
	// TurnstileSecretKey is never serialized with the settings: it is stored
	// encrypted (see storedRuntime) and never returned by any API. Saving
	// with an empty value keeps the current secret.
	TurnstileSecretKey   string   `json:"-"`
	TurnstileHostnames   []string `json:"turnstile_hostnames"`
	TurnstileSignup      bool     `json:"turnstile_signup"`
	TurnstileForgot      bool     `json:"turnstile_password_forgot"`
	TurnstileResend      bool     `json:"turnstile_email_resend"`
	TurnstileSignIn      string   `json:"turnstile_signin"`
	TurnstileSignInAfter int      `json:"turnstile_signin_after"`
}

// Turnstile returns the bot protection part of the settings.
func (r *Runtime) Turnstile() captcha.Settings {
	return captcha.Settings{
		Enabled: r.TurnstileEnabled, SecretKey: r.TurnstileSecretKey, SiteKey: r.TurnstileSiteKey,
		Hostnames: r.TurnstileHostnames, SignInMode: r.TurnstileSignIn, SignInAfter: r.TurnstileSignInAfter,
	}
}

// TurnstileSecretHint shows the last characters of the secret so admins can
// tell which key is configured without revealing it.
func (r *Runtime) TurnstileSecretHint() string {
	k := r.TurnstileSecretKey
	switch {
	case k == "":
		return ""
	case captcha.IsTestSecret(k):
		return "Cloudflare test key"
	case len(k) <= 12:
		return "set"
	}
	return "\u2026" + k[len(k)-4:]
}

// storedRuntime is the database form: the Turnstile secret is sealed with
// ENCRYPTION_KEY under SecretLabel.
type storedRuntime struct {
	Runtime
	TurnstileSecretEnc []byte `json:"turnstile_secret_enc,omitempty"`
}

// SecretLabel binds the sealed Turnstile secret to its purpose.
const SecretLabel = "settings:turnstile_secret"

// Sealer encrypts secrets at rest (secretbox.Box).
type Sealer interface {
	Seal(plaintext []byte, label string) ([]byte, error)
	Open(ciphertext []byte, label string) ([]byte, error)
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
	box        Sealer
	log        *slog.Logger
	st         atomic.Pointer[state]
}

// FromConfig extracts the environment defaults.
func FromConfig(c *config.Config) Runtime {
	return Runtime{
		AllowSignup:              c.Auth.AllowSignup,
		RequireWorkEmail:         c.Auth.RequireWorkEmail,
		WorkEmailExtraBlocked:    slices.Clone(c.Auth.WorkEmailExtraBlocked),
		WorkEmailAllowed:         slices.Clone(c.Auth.WorkEmailAllowed),
		EmailPolicy:              c.Auth.EmailPolicy,
		EmailAllowCompanies:      c.Auth.EmailAllowCompanies,
		EmailAllowSchools:        c.Auth.EmailAllowSchools,
		EmailAllowedDomains:      slices.Clone(c.Auth.EmailAllowedDomains),
		EmailBlockedDomains:      slices.Clone(c.Auth.EmailBlockedDomains),
		RequireEmailVerification: c.Auth.RequireEmailVerification,
		HideExistingAccounts:     c.Auth.HideExistingAccounts,
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
		TurnstileEnabled:         c.Auth.TurnstileSecretKey != "",
		TurnstileSiteKey:         c.Auth.TurnstileSiteKey,
		TurnstileSecretKey:       c.Auth.TurnstileSecretKey,
		TurnstileHostnames:       captcha.NormalizeHostnames(c.Auth.TurnstileHostnames),
		TurnstileSignup:          c.Auth.TurnstileSignup,
		TurnstileForgot:          c.Auth.TurnstileForgot,
		TurnstileResend:          c.Auth.TurnstileResend,
		TurnstileSignIn:          c.Auth.TurnstileSignIn,
		TurnstileSignInAfter:     c.Auth.TurnstileSignInAfter,
	}
}

// NewManager serves the settings. box encrypts the Turnstile secret saved
// from the admin UI; without it such a secret cannot be saved or loaded.
func NewManager(c *config.Config, st Store, box Sealer, log *slog.Logger) *Manager {
	m := &Manager{env: FromConfig(c), production: c.IsProduction(), store: st, box: box, log: log}
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
	sr := storedRuntime{Runtime: m.env} // fields missing from older saved JSON keep env values
	r := &sr.Runtime
	// Unmarshal can reuse slice storage, so keep environment defaults isolated.
	r.WorkEmailExtraBlocked = slices.Clone(m.env.WorkEmailExtraBlocked)
	r.WorkEmailAllowed = slices.Clone(m.env.WorkEmailAllowed)
	r.EmailAllowedDomains = slices.Clone(m.env.EmailAllowedDomains)
	r.EmailBlockedDomains = slices.Clone(m.env.EmailBlockedDomains)
	r.AllowedRedirectURIs = slices.Clone(m.env.AllowedRedirectURIs)
	r.CORSOrigins = slices.Clone(m.env.CORSOrigins)
	r.AdminAllowedIPs = slices.Clone(m.env.AdminAllowedIPs)
	r.TurnstileHostnames = slices.Clone(m.env.TurnstileHostnames)
	if err := json.Unmarshal(data, &sr); err != nil {
		return fmt.Errorf("settings: decode: %w", err)
	}
	if len(sr.TurnstileSecretEnc) > 0 {
		if m.box == nil {
			return errors.New("settings: cannot decrypt the Turnstile secret without ENCRYPTION_KEY")
		}
		pt, err := m.box.Open(sr.TurnstileSecretEnc, SecretLabel)
		if err != nil {
			return fmt.Errorf("settings: decrypt Turnstile secret: %w", err)
		}
		r.TurnstileSecretKey = string(pt)
	}
	if err := r.Validate(m.production); err != nil {
		// Never apply invalid settings; keep serving the previous ones.
		return fmt.Errorf("settings: stored settings are invalid: %w", err)
	}
	m.st.Store(&state{current: r, overridden: true, updatedAt: at})
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
//
// An empty TurnstileSecretKey keeps the secret currently in effect (no API
// returns it, so callers cannot echo it back). SaveClearingTurnstileSecret
// removes it.
func (m *Manager) Save(ctx context.Context, r Runtime) error {
	return m.save(ctx, r, false)
}

// SaveClearingTurnstileSecret saves r and removes the Turnstile secret saved
// in the database; AUTH_TURNSTILE_SECRET_KEY, if set, applies again.
func (m *Manager) SaveClearingTurnstileSecret(ctx context.Context, r Runtime) error {
	return m.save(ctx, r, true)
}

func (m *Manager) save(ctx context.Context, r Runtime, clearSecret bool) error {
	r.normalize()
	switch {
	case clearSecret:
		// Without a saved secret the environment value applies again.
		r.TurnstileSecretKey = m.env.TurnstileSecretKey
	case r.TurnstileSecretKey == "":
		r.TurnstileSecretKey = m.Get().TurnstileSecretKey
	}
	if err := r.Validate(m.production); err != nil {
		return err
	}
	sr := storedRuntime{Runtime: r}
	// Only a secret that differs from the environment is stored, so a later
	// change of AUTH_TURNSTILE_SECRET_KEY still applies.
	if r.TurnstileSecretKey != "" && r.TurnstileSecretKey != m.env.TurnstileSecretKey {
		if m.box == nil {
			return errors.New("an encryption key is required to store the Turnstile secret")
		}
		enc, err := m.box.Seal([]byte(r.TurnstileSecretKey), SecretLabel)
		if err != nil {
			return err
		}
		sr.TurnstileSecretEnc = enc
	}
	data, err := json.Marshal(sr)
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
	r.WorkEmailExtraBlocked = cleanList(r.WorkEmailExtraBlocked)
	r.WorkEmailAllowed = cleanList(r.WorkEmailAllowed)
	r.EmailPolicy = strings.ToLower(strings.TrimSpace(r.EmailPolicy))
	if r.EmailPolicy == "" {
		r.EmailPolicy = EmailPolicyAny
	}
	r.EmailAllowedDomains = cleanList(r.EmailAllowedDomains)
	r.EmailBlockedDomains = cleanList(r.EmailBlockedDomains)
	r.AdminAllowedIPs = cleanList(r.AdminAllowedIPs)
	r.DefaultLocale = strings.ToLower(strings.TrimSpace(r.DefaultLocale))
	r.TurnstileSiteKey = strings.TrimSpace(r.TurnstileSiteKey)
	r.TurnstileSecretKey = strings.TrimSpace(r.TurnstileSecretKey)
	r.TurnstileHostnames = captcha.NormalizeHostnames(r.TurnstileHostnames)
	r.TurnstileSignIn = strings.ToLower(strings.TrimSpace(r.TurnstileSignIn))
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
	switch r.EmailPolicy {
	case "", EmailPolicyAny:
	case EmailPolicyKnown:
		if r.RequireWorkEmail {
			add("Choose either \"Known email providers only\" or \"Require work email\": together nobody could sign up.")
		}
	default:
		add("Email policy must be any or known.")
	}
	if len(r.EmailAllowedDomains) > 500 || len(r.EmailBlockedDomains) > 500 {
		add("At most 500 allowed and 500 blocked email domains.")
	}
	if r.HideExistingAccounts && !r.RequireEmailVerification {
		add("Hiding existing accounts needs email verification: without it sign-up signs people in and gives the answer away.")
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
	errs = append(errs, r.Turnstile().Validate(production, false)...)
	return errors.Join(errs...)
}
