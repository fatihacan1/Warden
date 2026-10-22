package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=") // 32 bytes
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost/db")
}

func TestLoadDefaults(t *testing.T) {
	baseEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token.Issuer != "http://localhost:8080" {
		t.Fatalf("issuer should default to public url, got %q", cfg.Token.Issuer)
	}
	if cfg.Password.Argon2Memory != 19456 || cfg.Token.AccessTTL.Minutes() != 15 {
		t.Fatal("unexpected defaults")
	}
	if cfg.AdminCookieSecure() {
		t.Fatal("admin cookie should not require https in development by default")
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"short encryption key":     {"ENCRYPTION_KEY": "c2hvcnQ="},
		"wildcard cors":            {"HTTP_CORS_ALLOWED_ORIGINS": "*"},
		"short admin token":        {"ADMIN_TOKEN": "too-short"},
		"grpc without keys":        {"GRPC_ENABLED": "true"},
		"weak min password":        {"PASSWORD_MIN_LENGTH": "4"},
		"bad redirect uri":         {"AUTH_ALLOWED_REDIRECT_URIS": "not a uri"},
		"redirect with fragment":   {"AUTH_ALLOWED_REDIRECT_URIS": "https://a.example.com/cb#x"},
		"template without token":   {"AUTH_VERIFY_EMAIL_URL": "https://app/verify"},
		"samesite none insecure":   {"HTTP_COOKIE_SAME_SITE": "None", "HTTP_COOKIE_SECURE": "false"},
		"argon below owasp":        {"PASSWORD_ARGON2_MEMORY_KIB": "1024"},
		"refresh shorter than ttl": {"TOKEN_REFRESH_TTL": "1m"},
		"zero verification ttl":    {"AUTH_EMAIL_VERIFICATION_TTL": "0s"},
		"zero audit retention":     {"AUTH_AUDIT_RETENTION": "0s"},
		"zero statement timeout":   {"DATABASE_STATEMENT_TIMEOUT": "0s"},
		"negative key rotation":    {"TOKEN_KEY_ROTATION_INTERVAL": "-1h"},
		"null cors origin":         {"HTTP_CORS_ALLOWED_ORIGINS": "null"},
		"comment as issuer":        {"TOKEN_ISSUER": "# defaults to HTTP_PUBLIC_URL"},
		"comment as proxy":         {"HTTP_TRUSTED_PROXIES": "10.0.0.0/8 (my lb)"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			baseEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestProductionHardening(t *testing.T) {
	baseEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("HTTP_PUBLIC_URL", "http://auth.example.com")
	t.Setenv("HTTP_COOKIE_SECURE", "false")
	_, err := Load()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"https in production", "HTTP_COOKIE_SECURE", "SMTP_HOST"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestProductionRejectsExampleSecrets(t *testing.T) {
	baseEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("HTTP_PUBLIC_URL", "https://auth.example.com")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("ENCRYPTION_KEY", "fgloS3l1dQSZBolGg9UkqXDB2GgMFtQPzFe5L7X+MHQ=")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), ".env.example") {
		t.Fatalf("expected example secret rejection, got %v", err)
	}
	t.Setenv("ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if _, err := Load(); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
}

func TestDotEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "# comment\nWARDEN_T_A=plain\nWARDEN_T_B=\"quoted value\"\nWARDEN_T_C=val # trailing\nWARDEN_T_D=   # only a comment\nexport WARDEN_T_E=exported\nWARDEN_T_F=from-file\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_T_F", "from-env")
	for _, k := range []string{"WARDEN_T_A", "WARDEN_T_B", "WARDEN_T_C", "WARDEN_T_D", "WARDEN_T_E"} {
		os.Unsetenv(k)
		t.Cleanup(func() { os.Unsetenv(k) })
	}
	if err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"WARDEN_T_A": "plain", "WARDEN_T_B": "quoted value", "WARDEN_T_C": "val",
		"WARDEN_T_D": "", "WARDEN_T_E": "exported", "WARDEN_T_F": "from-env",
	}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if err := LoadDotEnv(filepath.Join(dir, "missing")); err != nil {
		t.Fatal("missing file must not be an error")
	}
}
