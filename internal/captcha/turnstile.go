// Package captcha verifies Cloudflare Turnstile tokens on the server.
//
// The browser solves the Turnstile widget and sends the resulting token with
// the request; Warden then asks Cloudflare's siteverify endpoint whether the
// token is genuine, unused, issued for one of our hostnames and for the
// expected action. The secret key never leaves the server.
//
// Verification fails closed: when Cloudflare cannot be reached or answers
// with something unexpected, the request is rejected (captcha_unavailable).
package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/fatihacan1/warden/internal/domain"
)

// SiteverifyURL is Cloudflare's verification endpoint.
const SiteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// HeaderName is the request header carrying the token.
const HeaderName = "CF-Turnstile-Response"

// Actions expected from the widget (data-action) per protected endpoint.
const (
	ActionSignup  = "signup"
	ActionSignIn  = "signin"
	ActionForgot  = "password_forgot"
	ActionResend  = "email_resend"
	maxTokenLen   = 2048 // Cloudflare documents tokens up to 2048 characters
	maxSecretLen  = 256
	maxBodyBytes  = 64 << 10
	maxHostnames  = 50
	defaultWait   = 5 * time.Second
	minTokenLen   = 20
	maxSiteKeyLen = 256
)

// Sign-in modes.
const (
	SignInOff           = "off"
	SignInAfterFailures = "after_failures"
	SignInAlways        = "always"
)

// testSecrets are Cloudflare's dummy secret keys. They accept the dummy token
// (XXXX.DUMMY.TOKEN.XXXX) and report hostname example.com, so hostname and
// action checks are skipped for them. They are refused in production.
var testSecrets = []string{
	"1x0000000000000000000000000000000AA", // always passes
	"2x0000000000000000000000000000000AA", // always fails
	"3x0000000000000000000000000000000AA", // yields "token already spent"
}

// IsTestSecret reports whether secret is one of Cloudflare's dummy keys.
func IsTestSecret(secret string) bool { return slices.Contains(testSecrets, secret) }

// Verifier calls siteverify.
type Verifier struct {
	client *http.Client
	url    string
	log    *slog.Logger
}

// New returns a Verifier with a short timeout. Redirects are never followed.
func New(log *slog.Logger) *Verifier {
	return NewWithURL(log, SiteverifyURL, nil)
}

// NewWithURL points the verifier at another endpoint (tests only).
func NewWithURL(log *slog.Logger, endpoint string, client *http.Client) *Verifier {
	if client == nil {
		client = &http.Client{Timeout: defaultWait}
	}
	cp := *client
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Verifier{client: &cp, url: endpoint, log: log}
}

// Check describes one verification.
type Check struct {
	Secret    string
	Token     string
	RemoteIP  string
	Action    string   // expected action
	Hostnames []string // accepted hostnames; empty accepts any (development only)
}

type siteverifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
}

// Verify returns nil when the token is valid, or one of
// domain.ErrCaptchaRequired, ErrCaptchaFailed, ErrCaptchaUnavailable.
func (v *Verifier) Verify(ctx context.Context, c Check) error {
	token := strings.TrimSpace(c.Token)
	if token == "" {
		return domain.ErrCaptchaRequired
	}
	if len(token) > maxTokenLen || len(token) < minTokenLen || !printableASCII(token) {
		return domain.ErrCaptchaFailed
	}
	if c.Secret == "" {
		v.log.Error("turnstile is enabled without a secret key")
		return domain.ErrCaptchaUnavailable
	}

	form := url.Values{"secret": {c.Secret}, "response": {token}}
	if ip := net.ParseIP(c.RemoteIP); ip != nil {
		form.Set("remoteip", ip.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, strings.NewReader(form.Encode()))
	if err != nil {
		return domain.ErrCaptchaUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		v.log.Warn("turnstile siteverify unreachable", "err", redact(err, c.Secret))
		return domain.ErrCaptchaUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		v.log.Warn("turnstile siteverify returned an error status", "status", resp.StatusCode)
		return domain.ErrCaptchaUnavailable
	}
	var out siteverifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&out); err != nil {
		v.log.Warn("turnstile siteverify returned invalid JSON", "err", err)
		return domain.ErrCaptchaUnavailable
	}

	if !out.Success {
		for _, code := range out.ErrorCodes {
			switch code {
			case "missing-input-secret", "invalid-input-secret":
				v.log.Error("turnstile secret key rejected by Cloudflare; check the secret key in Settings", "code", code)
				return domain.ErrCaptchaUnavailable
			case "internal-error":
				v.log.Warn("turnstile siteverify internal error")
				return domain.ErrCaptchaUnavailable
			}
		}
		return domain.ErrCaptchaFailed
	}
	if IsTestSecret(c.Secret) {
		return nil
	}
	if len(c.Hostnames) > 0 && !slices.Contains(c.Hostnames, strings.ToLower(out.Hostname)) {
		v.log.Warn("turnstile token issued for another hostname", "hostname", out.Hostname)
		return domain.ErrCaptchaFailed
	}
	if c.Action != "" && out.Action != c.Action {
		v.log.Warn("turnstile token issued for another action", "expected", c.Action, "action", out.Action)
		return domain.ErrCaptchaFailed
	}
	return nil
}

// redact keeps the secret out of logs (url.Error never contains the body,
// but stay defensive).
func redact(err error, secret string) string {
	s := err.Error()
	if secret != "" {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	return s
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

var hostnameRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Settings is the configuration shared by the environment and the admin UI.
type Settings struct {
	Enabled     bool
	SecretKey   string
	SiteKey     string
	Hostnames   []string
	SignInMode  string
	SignInAfter int
}

// Validate returns human readable problems; envNames switches the wording to
// environment variable names.
func (s Settings) Validate(production, envNames bool) []error {
	var errs []error
	name := func(env, ui string) string {
		if envNames {
			return env
		}
		return ui
	}
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if len(s.SecretKey) > maxSecretLen || !printableASCII(s.SecretKey) && s.SecretKey != "" {
		add("%s is not a valid key.", name("AUTH_TURNSTILE_SECRET_KEY", "Turnstile secret key"))
	}
	if len(s.SiteKey) > maxSiteKeyLen || !printableASCII(s.SiteKey) && s.SiteKey != "" {
		add("%s is not a valid key.", name("AUTH_TURNSTILE_SITE_KEY", "Turnstile site key"))
	}
	if len(s.Hostnames) > maxHostnames {
		add("At most %d Turnstile hostnames.", maxHostnames)
	}
	for _, h := range s.Hostnames {
		if len(h) > 253 || !hostnameRE.MatchString(h) {
			add("%s must be plain hostnames like app.example.com (no scheme, port or path): %q", name("AUTH_TURNSTILE_HOSTNAMES", "Turnstile hostnames"), h)
		}
	}
	if !s.Enabled {
		return errs
	}
	switch s.SignInMode {
	case SignInOff, SignInAfterFailures, SignInAlways:
	default:
		add("%s must be off, after_failures or always.", name("AUTH_TURNSTILE_SIGNIN", "Turnstile sign-in mode"))
	}
	if s.SignInAfter < 1 || s.SignInAfter > 20 {
		add("%s must be between 1 and 20.", name("AUTH_TURNSTILE_SIGNIN_AFTER", "Turnstile failed sign-ins before the check"))
	}
	if s.SecretKey == "" {
		add("%s is required when Turnstile is on.", name("AUTH_TURNSTILE_SECRET_KEY", "Turnstile secret key"))
	}
	if s.SiteKey == "" {
		add("%s is required when Turnstile is on (the frontend needs it to render the widget).", name("AUTH_TURNSTILE_SITE_KEY", "Turnstile site key"))
	}
	if production {
		if IsTestSecret(s.SecretKey) {
			add("%s is a Cloudflare test key; it must not be used in production.", name("AUTH_TURNSTILE_SECRET_KEY", "Turnstile secret key"))
		}
		if len(s.Hostnames) == 0 {
			add("%s must list your site's hostnames in production.", name("AUTH_TURNSTILE_HOSTNAMES", "Turnstile hostnames"))
		}
	}
	return errs
}

// NormalizeHostnames lowercases, trims and de-duplicates hostnames.
func NormalizeHostnames(in []string) []string {
	out := []string{}
	for _, h := range in {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}
