// Package config loads and validates Warden's runtime configuration.
//
// All configuration comes from environment variables (12-factor). A .env file
// is loaded for local development when present, but real environment variables
// always win.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the root configuration object.
type Config struct {
	Env         string `env:"APP_ENV" envDefault:"development"`
	ServiceName string `env:"SERVICE_NAME" envDefault:"warden"`
	LogLevel    string `env:"LOG_LEVEL" envDefault:"info"`
	LogFormat   string `env:"LOG_FORMAT" envDefault:"json"`

	// EncryptionKey is a base64 encoded 32 byte key used to encrypt secrets at
	// rest (signing keys, TOTP secrets, provider credentials, queued emails).
	EncryptionKey string `env:"ENCRYPTION_KEY,required"`

	HTTP      HTTPConfig      `envPrefix:"HTTP_"`
	Admin     AdminConfig     `envPrefix:"ADMIN_"`
	GRPC      GRPCConfig      `envPrefix:"GRPC_"`
	Database  DatabaseConfig  `envPrefix:"DATABASE_"`
	Redis     RedisConfig     `envPrefix:"REDIS_"`
	S3        S3Config        `envPrefix:"S3_"`
	RabbitMQ  RabbitMQConfig  `envPrefix:"RABBITMQ_"`
	SMTP      SMTPConfig      `envPrefix:"SMTP_"`
	Token     TokenConfig     `envPrefix:"TOKEN_"`
	Auth      AuthConfig      `envPrefix:"AUTH_"`
	Password  PasswordConfig  `envPrefix:"PASSWORD_"`
	RateLimit RateLimitConfig `envPrefix:"RATE_LIMIT_"`
	OAuth     OAuthConfig     `envPrefix:"OAUTH_"`
	Sentry    SentryConfig    `envPrefix:"SENTRY_"`
}

type HTTPConfig struct {
	Addr string `env:"ADDR" envDefault:":8080"`
	// PublicURL is the externally reachable base URL of this service. It is used
	// as the token issuer and to build OAuth callback URLs.
	PublicURL      string        `env:"PUBLIC_URL" envDefault:"http://localhost:8080"`
	ReadTimeout    time.Duration `env:"READ_TIMEOUT" envDefault:"10s"`
	WriteTimeout   time.Duration `env:"WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout    time.Duration `env:"IDLE_TIMEOUT" envDefault:"60s"`
	RequestTimeout time.Duration `env:"REQUEST_TIMEOUT" envDefault:"10s"`
	// MaxInFlight caps concurrently processed requests. Excess requests are shed
	// with 503 instead of queueing until the process runs out of memory.
	MaxInFlight     int           `env:"MAX_IN_FLIGHT" envDefault:"2000"`
	MaxConnections  int           `env:"MAX_CONNECTIONS" envDefault:"20000"`
	TrustedProxies  []string      `env:"TRUSTED_PROXIES" envSeparator:","`
	ProxyHeader     string        `env:"PROXY_HEADER" envDefault:"X-Forwarded-For"`
	CORSOrigins     []string      `env:"CORS_ALLOWED_ORIGINS" envSeparator:","`
	CookieDomain    string        `env:"COOKIE_DOMAIN"`
	CookieSecure    bool          `env:"COOKIE_SECURE" envDefault:"true"`
	CookieSameSite  string        `env:"COOKIE_SAME_SITE" envDefault:"Lax"`
	RefreshCookie   string        `env:"REFRESH_COOKIE_NAME" envDefault:"warden_refresh"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"20s"`
}

type AdminConfig struct {
	// Addr serves the admin UI, /metrics and probes. Never expose it publicly.
	Addr string `env:"ADDR" envDefault:":9090"`
	// Token enables the admin UI. Leave empty to disable the UI entirely.
	Token      string        `env:"TOKEN"`
	SessionTTL time.Duration `env:"SESSION_TTL" envDefault:"8h"`
	// CookieSecure: "true", "false" or empty (= true only in production).
	CookieSecure string `env:"COOKIE_SECURE"`
}

type GRPCConfig struct {
	Enabled    bool     `env:"ENABLED" envDefault:"false"`
	Addr       string   `env:"ADDR" envDefault:":9091"`
	APIKeys    []string `env:"API_KEYS" envSeparator:","`
	Reflection bool     `env:"REFLECTION" envDefault:"false"`
}

type DatabaseConfig struct {
	URL              string        `env:"URL,required"`
	MaxConns         int32         `env:"MAX_CONNS" envDefault:"20"`
	MinConns         int32         `env:"MIN_CONNS" envDefault:"2"`
	MaxConnLifetime  time.Duration `env:"MAX_CONN_LIFETIME" envDefault:"1h"`
	MaxConnIdleTime  time.Duration `env:"MAX_CONN_IDLE_TIME" envDefault:"15m"`
	StatementTimeout time.Duration `env:"STATEMENT_TIMEOUT" envDefault:"5s"`
	AutoMigrate      bool          `env:"AUTO_MIGRATE" envDefault:"true"`
}

type RedisConfig struct {
	URL          string        `env:"URL" envDefault:"redis://localhost:6379/0"`
	PoolSize     int           `env:"POOL_SIZE" envDefault:"0"`
	DialTimeout  time.Duration `env:"DIAL_TIMEOUT" envDefault:"3s"`
	ReadTimeout  time.Duration `env:"READ_TIMEOUT" envDefault:"1s"`
	WriteTimeout time.Duration `env:"WRITE_TIMEOUT" envDefault:"1s"`
}

type S3Config struct {
	Enabled         bool   `env:"ENABLED" envDefault:"false"`
	Endpoint        string `env:"ENDPOINT"`
	Region          string `env:"REGION" envDefault:"us-east-1"`
	Bucket          string `env:"BUCKET"`
	AccessKeyID     string `env:"ACCESS_KEY_ID"`
	SecretAccessKey string `env:"SECRET_ACCESS_KEY"`
	UsePathStyle    bool   `env:"USE_PATH_STYLE" envDefault:"true"`
	// PublicBaseURL serves objects from a CDN/public bucket. When empty, short
	// lived presigned URLs are returned instead.
	PublicBaseURL  string        `env:"PUBLIC_BASE_URL"`
	PresignTTL     time.Duration `env:"PRESIGN_TTL" envDefault:"1h"`
	AvatarMaxBytes int64         `env:"AVATAR_MAX_BYTES" envDefault:"2097152"`
}

type RabbitMQConfig struct {
	// URL enables event publishing when set, e.g. amqp://user:pass@host:5672/.
	URL      string `env:"URL"`
	Exchange string `env:"EXCHANGE" envDefault:"warden.events"`
}

type SMTPConfig struct {
	// Host enables SMTP delivery. When empty emails are written to the log
	// (development only).
	Host      string `env:"HOST"`
	Port      int    `env:"PORT" envDefault:"587"`
	Username  string `env:"USERNAME"`
	Password  string `env:"PASSWORD"`
	From      string `env:"FROM" envDefault:"Warden <no-reply@localhost>"`
	TLSPolicy string `env:"TLS_POLICY" envDefault:"mandatory"`
}

type TokenConfig struct {
	// Issuer defaults to HTTP_PUBLIC_URL.
	Issuer   string   `env:"ISSUER"`
	Audience []string `env:"AUDIENCE" envSeparator:"," envDefault:"warden"`
	// AccessTTL is the lifetime of access JWTs. Keep it short: they cannot be
	// revoked without an online check.
	AccessTTL time.Duration `env:"ACCESS_TTL" envDefault:"15m"`
	// RefreshTTL is the sliding idle timeout of a session.
	RefreshTTL time.Duration `env:"REFRESH_TTL" envDefault:"720h"`
	// SessionMaxAge is the absolute lifetime of a session, regardless of use.
	SessionMaxAge time.Duration `env:"SESSION_MAX_AGE" envDefault:"2160h"`
	// RefreshReuseGrace tolerates a client retrying a refresh whose response was
	// lost. Reuse after this window revokes the whole session.
	RefreshReuseGrace time.Duration `env:"REFRESH_REUSE_GRACE" envDefault:"10s"`
	// KeyRotationInterval automatically rotates the signing key. 0 disables.
	KeyRotationInterval time.Duration `env:"KEY_ROTATION_INTERVAL" envDefault:"720h"`
}

type AuthConfig struct {
	AppName                  string        `env:"APP_NAME" envDefault:"Warden"`
	AllowSignup              bool          `env:"ALLOW_SIGNUP" envDefault:"true"`
	RequireEmailVerification bool          `env:"REQUIRE_EMAIL_VERIFICATION" envDefault:"false"`
	EmailVerificationTTL     time.Duration `env:"EMAIL_VERIFICATION_TTL" envDefault:"24h"`
	PasswordResetTTL         time.Duration `env:"PASSWORD_RESET_TTL" envDefault:"30m"`
	// URL templates used in emails. {token} is replaced with the token.
	VerifyEmailURL   string `env:"VERIFY_EMAIL_URL" envDefault:"http://localhost:3000/verify-email?token={token}"`
	ResetPasswordURL string `env:"RESET_PASSWORD_URL" envDefault:"http://localhost:3000/reset-password?token={token}"`
	// AllowedRedirectURIs is the exact-match allowlist for OAuth redirects back
	// to your apps (web URLs or mobile custom schemes like myapp://auth).
	AllowedRedirectURIs []string      `env:"ALLOWED_REDIRECT_URIS" envSeparator:","`
	LockoutThreshold    int           `env:"LOCKOUT_THRESHOLD" envDefault:"10"`
	LockoutWindow       time.Duration `env:"LOCKOUT_WINDOW" envDefault:"15m"`
	RecentAuthWindow    time.Duration `env:"RECENT_AUTH_WINDOW" envDefault:"15m"`
	AuditRetention      time.Duration `env:"AUDIT_RETENTION" envDefault:"2160h"`
}

type PasswordConfig struct {
	MinLength     int  `env:"MIN_LENGTH" envDefault:"8"`
	MaxLength     int  `env:"MAX_LENGTH" envDefault:"128"`
	CheckBreached bool `env:"CHECK_BREACHED" envDefault:"false"`
	// Argon2id parameters. Defaults follow the OWASP Password Storage Cheat Sheet.
	Argon2Memory      uint32 `env:"ARGON2_MEMORY_KIB" envDefault:"19456"`
	Argon2Iterations  uint32 `env:"ARGON2_ITERATIONS" envDefault:"2"`
	Argon2Parallelism uint8  `env:"ARGON2_PARALLELISM" envDefault:"1"`
	// MaxConcurrentHashes bounds memory used by hashing (each hash allocates
	// Argon2Memory). 0 means 2 x GOMAXPROCS.
	MaxConcurrentHashes int           `env:"MAX_CONCURRENT_HASHES" envDefault:"0"`
	HashQueueTimeout    time.Duration `env:"HASH_QUEUE_TIMEOUT" envDefault:"3s"`
}

type RateLimitConfig struct {
	Enabled bool `env:"ENABLED" envDefault:"true"`
	// FailOpen keeps the service available when Redis is unreachable.
	FailOpen bool `env:"FAIL_OPEN" envDefault:"true"`
	// Requests per minute per client IP across the whole public API.
	GlobalPerMinute int `env:"GLOBAL_PER_MINUTE" envDefault:"600"`
	// Requests per minute per client IP on credential endpoints.
	AuthPerMinute int `env:"AUTH_PER_MINUTE" envDefault:"30"`
}

type ProviderEnv struct {
	Enabled      bool   `env:"ENABLED" envDefault:"false"`
	ClientID     string `env:"CLIENT_ID"`
	ClientSecret string `env:"CLIENT_SECRET"`
	// NativeClientIDs are extra audiences accepted for native (mobile) ID token
	// sign-in, e.g. iOS/Android client IDs or Apple bundle IDs.
	NativeClientIDs []string `env:"NATIVE_CLIENT_IDS" envSeparator:","`
	TeamID          string   `env:"TEAM_ID"`
	KeyID           string   `env:"KEY_ID"`
	PrivateKey      string   `env:"PRIVATE_KEY"`
}

type OAuthConfig struct {
	Google  ProviderEnv `envPrefix:"GOOGLE_"`
	Apple   ProviderEnv `envPrefix:"APPLE_"`
	Discord ProviderEnv `envPrefix:"DISCORD_"`
	GitHub  ProviderEnv `envPrefix:"GITHUB_"`
}

type SentryConfig struct {
	DSN              string  `env:"DSN"`
	TracesSampleRate float64 `env:"TRACES_SAMPLE_RATE" envDefault:"0"`
}

// Load parses the configuration from the environment and validates it.
func Load() (*Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) normalize() {
	c.HTTP.PublicURL = strings.TrimRight(c.HTTP.PublicURL, "/")
	if c.Token.Issuer == "" {
		c.Token.Issuer = c.HTTP.PublicURL
	}
	c.OAuth.Apple.PrivateKey = strings.ReplaceAll(c.OAuth.Apple.PrivateKey, `\n`, "\n")
}

// AdminCookieSecure reports whether the admin session cookie needs HTTPS.
func (c *Config) AdminCookieSecure() bool {
	switch strings.ToLower(c.Admin.CookieSecure) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return c.IsProduction()
	}
}

// IsProduction reports whether the service runs with production hardening.
func (c *Config) IsProduction() bool { return c.Env == "production" }

// EncryptionKeyBytes decodes ENCRYPTION_KEY.
func (c *Config) EncryptionKeyBytes() ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(c.EncryptionKey)
	if err != nil {
		key, err = base64.RawURLEncoding.DecodeString(c.EncryptionKey)
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("ENCRYPTION_KEY must be 32 random bytes, base64 encoded (generate with: warden keygen)")
	}
	return key, nil
}

// Validate rejects insecure or inconsistent configuration early, at startup.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	switch c.Env {
	case "development", "production", "test":
	default:
		add("APP_ENV must be development, production or test")
	}
	if _, err := c.EncryptionKeyBytes(); err != nil {
		errs = append(errs, err)
	}
	if c.IsProduction() {
		for _, v := range append([]string{c.EncryptionKey, c.Admin.Token}, c.GRPC.APIKeys...) {
			if _, public := exampleSecrets[v]; public {
				add("a secret from .env.example is in use; generate your own with `warden keygen`")
				break
			}
		}
	}
	if u, err := url.Parse(c.HTTP.PublicURL); err != nil || u.Scheme == "" || u.Host == "" {
		add("HTTP_PUBLIC_URL must be an absolute URL")
	} else if c.IsProduction() && u.Scheme != "https" {
		add("HTTP_PUBLIC_URL must use https in production")
	}
	switch strings.ToLower(c.HTTP.CookieSameSite) {
	case "lax", "strict", "none":
	default:
		add("HTTP_COOKIE_SAME_SITE must be Lax, Strict or None")
	}
	if strings.EqualFold(c.HTTP.CookieSameSite, "none") && !c.HTTP.CookieSecure {
		add("HTTP_COOKIE_SAME_SITE=None requires HTTP_COOKIE_SECURE=true")
	}
	if c.IsProduction() && !c.HTTP.CookieSecure {
		add("HTTP_COOKIE_SECURE must be true in production")
	}
	for _, o := range c.HTTP.CORSOrigins {
		if o == "*" {
			add("HTTP_CORS_ALLOWED_ORIGINS must not contain '*': credentials are allowed, list origins explicitly")
		}
	}
	if c.HTTP.MaxInFlight < 1 {
		add("HTTP_MAX_IN_FLIGHT must be positive")
	}
	if c.Admin.Token != "" && len(c.Admin.Token) < 32 {
		add("ADMIN_TOKEN must be at least 32 characters")
	}
	if c.GRPC.Enabled {
		if len(c.GRPC.APIKeys) == 0 {
			add("GRPC_API_KEYS is required when GRPC_ENABLED=true")
		}
		for _, k := range c.GRPC.APIKeys {
			if len(k) < 32 {
				add("each GRPC_API_KEYS entry must be at least 32 characters")
				break
			}
		}
	}
	if c.S3.Enabled && (c.S3.Bucket == "" || c.S3.AccessKeyID == "" || c.S3.SecretAccessKey == "") {
		add("S3_BUCKET, S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY are required when S3_ENABLED=true")
	}
	if c.S3.AvatarMaxBytes < 1024 || c.S3.AvatarMaxBytes > 20<<20 {
		add("S3_AVATAR_MAX_BYTES must be between 1KiB and 20MiB")
	}
	if c.IsProduction() && c.SMTP.Host == "" {
		add("SMTP_HOST is required in production (emails would only be logged)")
	}
	switch c.SMTP.TLSPolicy {
	case "mandatory", "opportunistic", "none":
	default:
		add("SMTP_TLS_POLICY must be mandatory, opportunistic or none")
	}
	if c.Token.AccessTTL < time.Minute || c.Token.AccessTTL > 24*time.Hour {
		add("TOKEN_ACCESS_TTL must be between 1m and 24h")
	}
	if c.Token.RefreshTTL < c.Token.AccessTTL {
		add("TOKEN_REFRESH_TTL must be longer than TOKEN_ACCESS_TTL")
	}
	if c.Token.SessionMaxAge < c.Token.RefreshTTL {
		add("TOKEN_SESSION_MAX_AGE must be >= TOKEN_REFRESH_TTL")
	}
	if c.Token.RefreshReuseGrace < 0 || c.Token.RefreshReuseGrace > time.Minute {
		add("TOKEN_REFRESH_REUSE_GRACE must be between 0 and 1m")
	}
	if len(c.Token.Audience) == 0 {
		add("TOKEN_AUDIENCE must not be empty")
	}
	if c.Password.MinLength < 8 {
		add("PASSWORD_MIN_LENGTH must be at least 8 (NIST SP 800-63B)")
	}
	if c.Password.MaxLength < 64 || c.Password.MaxLength > 1024 {
		add("PASSWORD_MAX_LENGTH must be between 64 and 1024")
	}
	if c.Password.Argon2Memory < 7168 || c.Password.Argon2Iterations < 1 || c.Password.Argon2Parallelism < 1 {
		add("Argon2 parameters are below the OWASP minimums")
	}
	for _, raw := range c.Auth.AllowedRedirectURIs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Fragment != "" {
			add("AUTH_ALLOWED_REDIRECT_URIS contains an invalid URI: %q", raw)
			continue
		}
		if c.IsProduction() && u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
			add("AUTH_ALLOWED_REDIRECT_URIS must use https in production: %q", raw)
		}
	}
	for _, tmpl := range []string{c.Auth.VerifyEmailURL, c.Auth.ResetPasswordURL} {
		if !strings.Contains(tmpl, "{token}") {
			add("email URL templates must contain {token}: %q", tmpl)
		}
	}
	if c.Auth.LockoutThreshold < 3 {
		add("AUTH_LOCKOUT_THRESHOLD must be at least 3")
	}
	if c.RateLimit.AuthPerMinute < 1 || c.RateLimit.GlobalPerMinute < 1 {
		add("RATE_LIMIT_* values must be positive")
	}
	// Zero or negative durations must never silently mean "forever" or "off".
	// A TTL of 0 would create Redis keys that never expire.
	durations := []struct {
		name     string
		v        time.Duration
		min, max time.Duration
	}{
		{"HTTP_REQUEST_TIMEOUT", c.HTTP.RequestTimeout, time.Second, 5 * time.Minute},
		{"HTTP_READ_TIMEOUT", c.HTTP.ReadTimeout, time.Second, 5 * time.Minute},
		{"HTTP_WRITE_TIMEOUT", c.HTTP.WriteTimeout, time.Second, 5 * time.Minute},
		{"HTTP_IDLE_TIMEOUT", c.HTTP.IdleTimeout, time.Second, time.Hour},
		{"ADMIN_SESSION_TTL", c.Admin.SessionTTL, 5 * time.Minute, 7 * 24 * time.Hour},
		{"DATABASE_STATEMENT_TIMEOUT", c.Database.StatementTimeout, 100 * time.Millisecond, 5 * time.Minute},
		{"S3_PRESIGN_TTL", c.S3.PresignTTL, time.Minute, 7 * 24 * time.Hour},
		{"AUTH_EMAIL_VERIFICATION_TTL", c.Auth.EmailVerificationTTL, 5 * time.Minute, 7 * 24 * time.Hour},
		{"AUTH_PASSWORD_RESET_TTL", c.Auth.PasswordResetTTL, 5 * time.Minute, 24 * time.Hour},
		{"AUTH_LOCKOUT_WINDOW", c.Auth.LockoutWindow, time.Minute, 24 * time.Hour},
		{"AUTH_RECENT_AUTH_WINDOW", c.Auth.RecentAuthWindow, time.Minute, 24 * time.Hour},
		{"AUTH_AUDIT_RETENTION", c.Auth.AuditRetention, 24 * time.Hour, 10 * 365 * 24 * time.Hour},
	}
	for _, d := range durations {
		if d.v < d.min || d.v > d.max {
			add("%s must be between %s and %s (got %s)", d.name, d.min, d.max, d.v)
		}
	}
	if c.Token.KeyRotationInterval < 0 || (c.Token.KeyRotationInterval > 0 && c.Token.KeyRotationInterval < time.Hour) {
		add("TOKEN_KEY_ROTATION_INTERVAL must be 0 (disabled) or at least 1h")
	}
	if u, err := url.Parse(c.Token.Issuer); err != nil || u.Scheme == "" || u.Host == "" {
		add("TOKEN_ISSUER must be an absolute URL (got %q)", c.Token.Issuer)
	}
	for _, p := range c.HTTP.TrustedProxies {
		if _, _, err := net.ParseCIDR(p); err != nil && net.ParseIP(p) == nil {
			add("HTTP_TRUSTED_PROXIES contains %q, which is not an IP or CIDR", p)
		}
		if c.IsProduction() && (p == "0.0.0.0/0" || p == "::/0") {
			add("HTTP_TRUSTED_PROXIES must list your load balancer ranges, not %s: trusting everyone lets clients spoof their IP and bypass rate limits", p)
		}
	}
	for _, o := range c.HTTP.CORSOrigins {
		if strings.EqualFold(o, "null") {
			add("HTTP_CORS_ALLOWED_ORIGINS must not contain \"null\"")
		}
	}
	if c.Sentry.TracesSampleRate < 0 || c.Sentry.TracesSampleRate > 1 {
		add("SENTRY_TRACES_SAMPLE_RATE must be between 0 and 1")
	}
	return errors.Join(errs...)
}

// exampleSecrets are the public development values shipped in .env.example.
var exampleSecrets = map[string]struct{}{
	"fgloS3l1dQSZBolGg9UkqXDB2GgMFtQPzFe5L7X+MHQ=": {},
	"Y4Wzth-iNodchOnhoX8j23NH-VCCf-jj3B4irfQUso4":  {},
	"_82LBvOVYDrKY9_c-zCgE8GDx2g_2gvI9D82PVYXP9k":  {},
}
