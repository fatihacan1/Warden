package captcha

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fatihacan1/warden/internal/domain"
)

const (
	goodToken  = "0.valid-token-from-the-widget-xxxxxxxxxxxxxxxx"
	realSecret = "0x4AAAAAAAreal-secret-key-for-tests"
)

type fake struct {
	calls  atomic.Int32
	status int
	body   string
	check  func(r *http.Request)
}

func (f *fake) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if f.check != nil {
			f.check(r)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func verify(t *testing.T, f *fake, c Check) error {
	t.Helper()
	srv := f.server(t)
	return NewWithURL(nil, srv.URL, srv.Client()).Verify(context.Background(), c)
}

func baseCheck() Check {
	return Check{Secret: realSecret, Token: goodToken, RemoteIP: "203.0.113.9", Action: ActionSignup, Hostnames: []string{"app.example.com"}}
}

func TestVerifySuccessSendsSecretTokenAndIP(t *testing.T) {
	f := &fake{status: 200, body: `{"success":true,"hostname":"app.example.com","action":"signup"}`}
	f.check = func(r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if r.PostForm.Get("secret") != realSecret || r.PostForm.Get("response") != goodToken || r.PostForm.Get("remoteip") != "203.0.113.9" {
			t.Errorf("unexpected form: %v", r.PostForm)
		}
	}
	if err := verify(t, f, baseCheck()); err != nil {
		t.Fatalf("want success, got %v", err)
	}
}

func TestVerifyRejections(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		mutate func(*Check)
		want   *domain.Error
		calls  int32
	}{
		{"missing token", 200, `{"success":true}`, func(c *Check) { c.Token = "  " }, domain.ErrCaptchaRequired, 0},
		{"oversized token", 200, `{"success":true}`, func(c *Check) { c.Token = strings.Repeat("a", 2049) }, domain.ErrCaptchaFailed, 0},
		{"too short token", 200, `{"success":true}`, func(c *Check) { c.Token = "abc" }, domain.ErrCaptchaFailed, 0},
		{"control chars in token", 200, `{"success":true}`, func(c *Check) { c.Token = goodToken + "\r\nX-Injected: 1" }, domain.ErrCaptchaFailed, 0},
		{"no secret configured", 200, `{"success":true}`, func(c *Check) { c.Secret = "" }, domain.ErrCaptchaUnavailable, 0},
		{"cloudflare says invalid", 200, `{"success":false,"error-codes":["invalid-input-response"]}`, nil, domain.ErrCaptchaFailed, 1},
		{"token reused or expired", 200, `{"success":false,"error-codes":["timeout-or-duplicate"]}`, nil, domain.ErrCaptchaFailed, 1},
		{"failure without codes", 200, `{"success":false}`, nil, domain.ErrCaptchaFailed, 1},
		{"secret rejected", 200, `{"success":false,"error-codes":["invalid-input-secret"]}`, nil, domain.ErrCaptchaUnavailable, 1},
		{"cloudflare internal error", 200, `{"success":false,"error-codes":["internal-error"]}`, nil, domain.ErrCaptchaUnavailable, 1},
		{"http 500", 500, `oops`, nil, domain.ErrCaptchaUnavailable, 1},
		{"redirect not followed", 302, ``, nil, domain.ErrCaptchaUnavailable, 1},
		{"invalid json", 200, `<html>`, nil, domain.ErrCaptchaUnavailable, 1},
		{"token for another site", 200, `{"success":true,"hostname":"evil.example.net","action":"signup"}`, nil, domain.ErrCaptchaFailed, 1},
		{"hostname suffix trick", 200, `{"success":true,"hostname":"app.example.com.evil.net","action":"signup"}`, nil, domain.ErrCaptchaFailed, 1},
		{"token for another action", 200, `{"success":true,"hostname":"app.example.com","action":"signin"}`, nil, domain.ErrCaptchaFailed, 1},
		{"token without action", 200, `{"success":true,"hostname":"app.example.com","action":""}`, nil, domain.ErrCaptchaFailed, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fake{status: tc.status, body: tc.body}
			c := baseCheck()
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			err := verify(t, f, c)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want.Code, err)
			}
			if got := f.calls.Load(); got != tc.calls {
				t.Fatalf("siteverify called %d times, want %d", got, tc.calls)
			}
		})
	}
}

func TestVerifyHostnameIsCaseInsensitive(t *testing.T) {
	f := &fake{status: 200, body: `{"success":true,"hostname":"APP.Example.com","action":"signup"}`}
	if err := verify(t, f, baseCheck()); err != nil {
		t.Fatalf("want success, got %v", err)
	}
}

func TestVerifyTestSecretSkipsHostnameAndAction(t *testing.T) {
	f := &fake{status: 200, body: `{"success":true,"hostname":"example.com","action":""}`}
	c := baseCheck()
	c.Secret = "1x0000000000000000000000000000000AA"
	if err := verify(t, f, c); err != nil {
		t.Fatalf("test secret should pass locally, got %v", err)
	}
	// The test secret still needs Cloudflare to say success.
	f = &fake{status: 200, body: `{"success":false,"error-codes":["invalid-input-response"]}`}
	c.Secret = "2x0000000000000000000000000000000AA"
	if err := verify(t, f, c); !errors.Is(err, domain.ErrCaptchaFailed) {
		t.Fatalf("want captcha_failed, got %v", err)
	}
}

func TestVerifyUnreachableFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	err := NewWithURL(nil, url, nil).Verify(context.Background(), baseCheck())
	if !errors.Is(err, domain.ErrCaptchaUnavailable) {
		t.Fatalf("want captcha_unavailable, got %v", err)
	}
}

func TestVerifyTimeoutFailsClosed(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	t.Cleanup(func() { close(block); srv.Close() })
	v := NewWithURL(nil, srv.URL, &http.Client{Timeout: 100 * time.Millisecond})
	start := time.Now()
	if err := v.Verify(context.Background(), baseCheck()); !errors.Is(err, domain.ErrCaptchaUnavailable) {
		t.Fatalf("want captcha_unavailable, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("verification did not time out")
	}
}

func TestVerifyIgnoresInvalidRemoteIP(t *testing.T) {
	f := &fake{status: 200, body: `{"success":true,"hostname":"app.example.com","action":"signup"}`}
	f.check = func(r *http.Request) {
		if _, ok := r.PostForm["remoteip"]; ok {
			t.Errorf("invalid remote ip forwarded: %q", r.PostForm.Get("remoteip"))
		}
	}
	c := baseCheck()
	c.RemoteIP = "not-an-ip&secret=x"
	if err := verify(t, f, c); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsValidate(t *testing.T) {
	ok := Settings{Enabled: true, SecretKey: realSecret, SiteKey: "0x4AAAAAAAsite", Hostnames: []string{"app.example.com"}, SignInMode: SignInAfterFailures, SignInAfter: 3}
	if errs := ok.Validate(true, false); len(errs) != 0 {
		t.Fatalf("valid settings rejected: %v", errs)
	}
	off := Settings{}
	if errs := off.Validate(true, false); len(errs) != 0 {
		t.Fatalf("disabled settings rejected: %v", errs)
	}
	bad := []struct {
		name   string
		mutate func(*Settings)
		prod   bool
	}{
		{"no secret", func(s *Settings) { s.SecretKey = "" }, false},
		{"no site key", func(s *Settings) { s.SiteKey = "" }, false},
		{"bad mode", func(s *Settings) { s.SignInMode = "sometimes" }, false},
		{"after zero", func(s *Settings) { s.SignInAfter = 0 }, false},
		{"after too big", func(s *Settings) { s.SignInAfter = 21 }, false},
		{"hostname with scheme", func(s *Settings) { s.Hostnames = []string{"https://app.example.com"} }, false},
		{"hostname with port", func(s *Settings) { s.Hostnames = []string{"app.example.com:443"} }, false},
		{"hostname wildcard", func(s *Settings) { s.Hostnames = []string{"*.example.com"} }, false},
		{"test secret in production", func(s *Settings) { s.SecretKey = "1x0000000000000000000000000000000AA" }, true},
		{"no hostnames in production", func(s *Settings) { s.Hostnames = nil }, true},
		{"secret with newline", func(s *Settings) { s.SecretKey = "abc\ndef" }, false},
	}
	for _, tc := range bad {
		s := ok
		s.Hostnames = []string{"app.example.com"}
		tc.mutate(&s)
		if errs := s.Validate(tc.prod, false); len(errs) == 0 {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	dev := ok
	dev.SecretKey = "1x0000000000000000000000000000000AA"
	dev.Hostnames = nil
	if errs := dev.Validate(false, false); len(errs) != 0 {
		t.Fatalf("test secret should be fine outside production: %v", errs)
	}
}

func TestNormalizeHostnames(t *testing.T) {
	got := NormalizeHostnames([]string{" App.Example.com. ", "app.example.com", "", "www.example.com"})
	if len(got) != 2 || got[0] != "app.example.com" || got[1] != "www.example.com" {
		t.Fatalf("got %v", got)
	}
}
