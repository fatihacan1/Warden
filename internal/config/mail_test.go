package config

import "testing"

func prodEnv(t *testing.T) {
	t.Helper()
	baseEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("HTTP_PUBLIC_URL", "https://203-0-113-10.sslip.io")
	t.Setenv("HTTP_COOKIE_SECURE", "true")
	t.Setenv("HTTP_TRUSTED_PROXIES", "172.28.0.0/16")
	t.Setenv("ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
}

func TestMailDeliveryDefaults(t *testing.T) {
	cases := []struct {
		env, smtp, mode, want string
	}{
		{"development", "", "", "inbox"},
		{"development", "smtp.example.com", "", "smtp"},
		{"test", "", "", "log"},
		{"development", "", "log", "log"},
		{"development", "smtp.example.com", "direct", "direct"},
		{"development", "", " INBOX ", "inbox"},
	}
	for _, c := range cases {
		baseEnv(t)
		t.Setenv("APP_ENV", c.env)
		t.Setenv("SMTP_HOST", c.smtp)
		t.Setenv("MAIL_DELIVERY", c.mode)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		if got := cfg.MailDelivery(); got != c.want {
			t.Errorf("%+v: got %q, want %q", c, got, c.want)
		}
	}
}

func TestProductionMailModes(t *testing.T) {
	cases := []struct {
		name, smtp, mode string
		ok               bool
	}{
		{"no mail setup at all is refused", "", "", false},
		{"smtp host", "smtp.example.com", "", true},
		{"explicit inbox", "", "inbox", true},
		{"explicit direct", "", "direct", true},
		{"log is refused", "", "log", false},
		{"smtp mode without host", "", "smtp", false},
		{"unknown mode", "", "carrier-pigeon", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prodEnv(t)
			t.Setenv("SMTP_HOST", c.smtp)
			t.Setenv("MAIL_DELIVERY", c.mode)
			_, err := Load()
			if (err == nil) != c.ok {
				t.Fatalf("ok=%v, err=%v", c.ok, err)
			}
		})
	}
}

func TestMailHeloName(t *testing.T) {
	baseEnv(t)
	t.Setenv("HTTP_PUBLIC_URL", "https://auth.example.com:8443")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.MailHeloName(); got != "auth.example.com" {
		t.Fatalf("got %q", got)
	}
	cfg.Mail.HeloName = "mail.example.com"
	if got := cfg.MailHeloName(); got != "mail.example.com" {
		t.Fatalf("got %q", got)
	}
}
