package setup

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// field is one environment variable the wizard asks for.
type field struct {
	Key         string
	Label       string
	Help        string
	Kind        string // text, secret, bool, select, list
	Options     []option
	Default     string
	Generate    string // "key" (32 bytes, base64) or "token" (32 bytes, base64url)
	Placeholder string
}

type option struct{ Value, Label, Help string }

// section groups fields; Check names the connection test it offers.
type section struct {
	ID     string
	Title  string
	Lede   string
	Check  string
	Fields []field
}

// Defaults are the public development values of the local Docker Compose
// stack (also in .env.example); production validation rejects them where it
// matters.
//
// #nosec G101 -- documented development defaults, not real credentials
var sections = []section{
	{ID: "instance", Title: "Instance", Lede: "Where this Warden runs and what users see.", Fields: []field{
		{Key: "APP_ENV", Label: "Environment", Kind: "select", Default: "development", Options: []option{
			{"development", "Development", "Local machine. Relaxed checks, readable logs."},
			{"production", "Production", "Requires HTTPS and real secrets. Refuses unsafe settings."},
		}},
		{Key: "HTTP_PUBLIC_URL", Label: "Public URL", Default: "http://localhost:8080",
			Help: "How apps reach this instance. Also the token issuer and the base of OAuth callbacks. https://auth.yourapp.com in production."},
		{Key: "AUTH_APP_NAME", Label: "App name", Default: "Warden", Help: "Shown in emails and authenticator apps."},
	}},
	{ID: "database", Title: "PostgreSQL", Lede: "Users, sessions and settings. Required.", Check: "postgres", Fields: []field{
		{Key: "DATABASE_URL", Label: "Connection URL", Kind: "secret", Default: "postgres://warden:warden@localhost:5432/warden?sslmode=disable",
			Help: "postgres://user:password@host:5432/db?sslmode=require. The user needs to create tables (migrations run at start)."},
	}},
	{ID: "redis", Title: "Redis", Lede: "Rate limits, one-time codes and the revocation list. Required.", Check: "redis", Fields: []field{
		{Key: "REDIS_URL", Label: "Connection URL", Kind: "secret", Default: "redis://localhost:6379/0", Help: "redis://:password@host:6379/0, or rediss:// for TLS."},
	}},
	{ID: "email", Title: "Email", Lede: "Verification and password reset emails. Pick how they leave Warden. The SMTP fields below only matter for SMTP.", Check: "smtp", Fields: []field{
		{Key: "MAIL_DELIVERY", Label: "Delivery", Kind: "select", Default: "smtp", Options: []option{
			{"smtp", "SMTP provider", "Postmark, SES, Resend, Mailgun or your own server. The right choice for real users."},
			{"inbox", "Admin Inbox (testing)", "Nothing is sent. Emails are stored encrypted and shown in the admin UI under Inbox. No SMTP provider, no domain needed, but users receive nothing."},
			{"direct", "Send from this server (testing)", "Warden delivers straight to the recipient's mail server on port 25. Needs no provider, but many hosts block port 25 and the mail usually lands in spam."},
		}},
		{Key: "SMTP_HOST", Label: "SMTP host", Default: "localhost", Placeholder: "smtp.postmarkapp.com"},
		{Key: "SMTP_PORT", Label: "Port", Default: "1025", Help: "587 (STARTTLS) or 465 (TLS) for most providers; 1025 for Mailpit."},
		{Key: "SMTP_USERNAME", Label: "Username"},
		{Key: "SMTP_PASSWORD", Label: "Password", Kind: "secret"},
		{Key: "SMTP_FROM", Label: "From", Default: "Warden <no-reply@example.com>"},
		{Key: "SMTP_TLS_POLICY", Label: "TLS", Kind: "select", Default: "none", Options: []option{
			{"mandatory", "Mandatory", "Refuse to send without TLS. Use this with real providers."},
			{"opportunistic", "Opportunistic", "Use TLS when offered."},
			{"none", "None", "Local test servers like Mailpit only."},
		}},
	}},
	{ID: "storage", Title: "Profile photos (S3)", Lede: "Any S3 compatible storage: AWS S3, Cloudflare R2, Backblaze B2, MinIO, Garage. Optional.", Check: "s3", Fields: []field{
		{Key: "S3_ENABLED", Label: "Store profile photos", Kind: "bool", Default: "true"},
		{Key: "S3_ENDPOINT", Label: "Endpoint", Default: "http://localhost:3900", Help: "Empty for AWS S3."},
		{Key: "S3_REGION", Label: "Region", Default: "garage", Help: "us-east-1 for AWS, auto for R2."},
		{Key: "S3_BUCKET", Label: "Bucket", Default: "warden"},
		{Key: "S3_ACCESS_KEY_ID", Label: "Access key ID", Default: "GK31c2f218a2e44f485b94239e"},
		{Key: "S3_SECRET_ACCESS_KEY", Label: "Secret access key", Kind: "secret", Default: "b892c0665f0ada8a4755dae98baa3b133590e11dae3bcc1f9d769d67f16c3835"},
		{Key: "S3_USE_PATH_STYLE", Label: "Path-style URLs", Kind: "bool", Default: "true", Help: "On for MinIO, Garage and most self-hosted stores."},
		{Key: "S3_PUBLIC_BASE_URL", Label: "Public base URL", Help: "CDN or public bucket URL. Empty = short-lived signed URLs."},
	}},
	{ID: "events", Title: "Events (RabbitMQ)", Lede: "Publishes user.created and other events to a topic exchange. Optional: webhooks work without it.", Check: "rabbitmq", Fields: []field{
		{Key: "RABBITMQ_URL", Label: "Connection URL", Kind: "secret", Default: "amqp://warden:warden@localhost:5672/", Help: "Empty disables publishing."},
	}},
	{ID: "encryption", Title: "Encryption at rest", Lede: "Signing keys, TOTP secrets, provider credentials, webhook secrets and queued emails are encrypted before they reach the database.", Fields: []field{
		{Key: "ENCRYPTION_ALGORITHM", Label: "Algorithm", Kind: "select", Default: "aes-256-gcm", Options: []option{
			{"aes-256-gcm", "AES-256-GCM", "The default. Hardware accelerated on every modern server CPU."},
			{"xchacha20-poly1305", "XChaCha20-Poly1305", "Constant time without AES instructions (some ARM and older CPUs), 192-bit random nonces."},
		}, Help: "Both are authenticated encryption with 256-bit keys. Changing it later is safe: old data stays readable and `warden reencrypt` converts it."},
		{Key: "ENCRYPTION_KEY", Label: "Encryption key", Kind: "secret", Generate: "key",
			Help: "32 random bytes. Back it up: without it encrypted data cannot be recovered. Replacing it here keeps the old key as a previous key so nothing breaks."},
	}},
	{ID: "access", Title: "Access", Lede: "Who can manage this instance and which APIs are on.", Fields: []field{
		{Key: "ADMIN_TOKEN", Label: "Admin token", Kind: "secret", Generate: "token", Help: "Signs you in to the admin UI on the private port (9090)."},
		{Key: "GRPC_ENABLED", Label: "gRPC API for internal services", Kind: "bool", Default: "true"},
		{Key: "GRPC_API_KEYS", Label: "gRPC API key", Kind: "secret", Generate: "token", Help: "Sent as x-api-key by your services. Comma separate several."},
		{Key: "GRAPHQL_ENABLED", Label: "GraphQL endpoint (POST /graphql)", Kind: "bool", Default: "false", Help: "Account queries and mutations. Depth and size limited; introspection off in production."},
	}},
	{ID: "apps", Title: "Your apps", Lede: "Editable later in the admin UI, without a restart.", Fields: []field{
		{Key: "HTTP_CORS_ALLOWED_ORIGINS", Label: "Web app origins (CORS)", Kind: "list", Default: "http://localhost:3000", Help: "Comma separated, exact origins. Mobile apps need nothing here."},
		{Key: "AUTH_ALLOWED_REDIRECT_URIS", Label: "Social sign-in redirect URIs", Kind: "list", Default: "http://localhost:3000/auth/callback,myapp://auth/callback"},
		{Key: "AUTH_VERIFY_EMAIL_URL", Label: "Verify email page", Default: "http://localhost:3000/verify-email?token={token}"},
		{Key: "AUTH_RESET_PASSWORD_URL", Label: "Reset password page", Default: "http://localhost:3000/reset-password?token={token}"},
		{Key: "HTTP_TRUSTED_PROXIES", Label: "Trusted proxies", Kind: "list", Help: "Your load balancer's IP ranges, so client IPs and rate limits are right. Empty when nothing sits in front."},
	}},
}

// managed lists every key the wizard writes, including derived ones.
func managed() map[string]bool {
	m := map[string]bool{"HTTP_COOKIE_SECURE": true, "LOG_FORMAT": true, "GRPC_REFLECTION": true, "ENCRYPTION_PREVIOUS_KEYS": true}
	for _, s := range sections {
		for _, f := range s.Fields {
			m[f.Key] = true
		}
	}
	return m
}

func generate(kind string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("setup: " + err.Error())
	}
	if kind == "key" {
		return base64.StdEncoding.EncodeToString(b)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// quote writes a value so both Warden's loader and Docker Compose read it
// back unchanged.
func quote(v string) string {
	if v == "" || !strings.ContainsAny(v, " #\"'\t") {
		return v
	}
	if !strings.Contains(v, "'") {
		return "'" + v + "'"
	}
	return `"` + strings.ReplaceAll(v, `"`, `'`) + `"`
}

// render produces the .env file: managed sections first, then any other
// variables from the previous file, unchanged.
func render(vals map[string]string, previous map[string]string, order []string) string {
	var b strings.Builder
	b.WriteString("# Warden configuration, written by `warden setup`.\n")
	b.WriteString("# Real environment variables override this file. Keep it out of git.\n")
	b.WriteString("# Every option is documented in .env.example.\n")
	for _, s := range sections {
		b.WriteString("\n# --- " + s.Title + " ")
		b.WriteString(strings.Repeat("-", max(3, 72-len(s.Title))) + "\n")
		for _, f := range s.Fields {
			b.WriteString(f.Key + "=" + quote(vals[f.Key]) + "\n")
			if f.Key == "ENCRYPTION_KEY" && vals["ENCRYPTION_PREVIOUS_KEYS"] != "" {
				b.WriteString("# Retired keys, only used to read old data. Run `warden reencrypt`, then remove them.\n")
				b.WriteString("ENCRYPTION_PREVIOUS_KEYS=" + quote(vals["ENCRYPTION_PREVIOUS_KEYS"]) + "\n")
			}
		}
		if s.ID == "instance" {
			b.WriteString("HTTP_COOKIE_SECURE=" + vals["HTTP_COOKIE_SECURE"] + "\n")
			b.WriteString("LOG_FORMAT=" + vals["LOG_FORMAT"] + "\n")
		}
		if s.ID == "access" {
			b.WriteString("GRPC_REFLECTION=" + vals["GRPC_REFLECTION"] + "\n")
		}
	}
	m := managed()
	var rest []string
	for _, k := range order {
		if !m[k] {
			rest = append(rest, k+"="+quote(previous[k]))
		}
	}
	if len(rest) > 0 {
		b.WriteString("\n# --- Kept from the previous .env " + strings.Repeat("-", 40) + "\n")
		b.WriteString(strings.Join(rest, "\n") + "\n")
	}
	return b.String()
}
