//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fatihacan1/warden/internal/captcha"
	"github.com/fatihacan1/warden/internal/settings"
)

const (
	tsSecret = "0x4AAAAAAA-e2e-turnstile-secret-key"
	tsSite   = "0x4AAAAAAA-e2e-site-key"
)

// fakeSiteverify imitates Cloudflare: tokens look like
// "tok-<action>-<hostname>-<nonce>" and can be used once.
type fakeSiteverify struct {
	mu      sync.Mutex
	used    map[string]bool
	secrets []string
	ips     []string
	calls   int
}

func (f *fakeSiteverify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.secrets = append(f.secrets, r.PostForm.Get("secret"))
	f.ips = append(f.ips, r.PostForm.Get("remoteip"))
	w.Header().Set("Content-Type", "application/json")
	tok := r.PostForm.Get("response")
	parts := strings.SplitN(tok, "-", 4)
	switch {
	case r.PostForm.Get("secret") != tsSecret:
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error-codes": []string{"invalid-input-secret"}})
	case len(parts) != 4 || parts[0] != "tok":
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}})
	case f.used[tok]:
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error-codes": []string{"timeout-or-duplicate"}})
	default:
		f.used[tok] = true
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "action": parts[1], "hostname": parts[2]})
	}
}

func token(action, host string) string {
	return "tok-" + action + "-" + host + "-" + randIP()
}

// withTurnstile turns bot protection on against a fake Cloudflare and
// restores everything afterwards.
func withTurnstile(t *testing.T, mutate func(r *settings.Runtime)) *fakeSiteverify {
	t.Helper()
	ctx := context.Background()
	original := *A.Settings.Get()
	wasOverridden, _ := A.Settings.Overridden()
	fake := &fakeSiteverify{used: map[string]bool{}}
	srv := httptest.NewServer(fake)
	A.HTTP.SetCaptchaVerifier(captcha.NewWithURL(nil, srv.URL, srv.Client()))
	t.Cleanup(func() {
		srv.Close()
		A.HTTP.SetCaptchaVerifier(captcha.New(nil))
		var err error
		if wasOverridden {
			err = A.Settings.SaveClearingTurnstileSecret(ctx, original)
		} else {
			err = A.Settings.Reset(ctx)
		}
		if err != nil {
			t.Error(err)
		}
	})
	r := original
	r.AllowSignup = true
	r.TurnstileEnabled = true
	r.TurnstileSiteKey = tsSite
	r.TurnstileSecretKey = tsSecret
	r.TurnstileHostnames = []string{"app.example.com"}
	r.TurnstileSignup, r.TurnstileForgot, r.TurnstileResend = true, true, true
	r.TurnstileSignIn = captcha.SignInAfterFailures
	r.TurnstileSignInAfter = 2
	if mutate != nil {
		mutate(&r)
	}
	if err := A.Settings.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
	return fake
}

func (c *client) withToken(tok string) *client {
	cp := *c
	cp.headers = map[string]string{}
	for k, v := range c.headers {
		cp.headers[k] = v
	}
	cp.headers[captcha.HeaderName] = tok
	return &cp
}

func TestTurnstileSignup(t *testing.T) {
	fake := withTurnstile(t, nil)
	c := newClient(t)
	body := func() map[string]string { return map[string]string{"email": randEmail(), "password": pw} }

	if r := c.do("POST", "/v1/auth/signup", body(), ""); r.Status != 400 || r.errCode(t) != "captcha_required" {
		t.Fatalf("no token: %d %s", r.Status, r.Body)
	}
	if r := c.withToken("garbage-token-that-cloudflare-rejects").do("POST", "/v1/auth/signup", body(), ""); r.Status != 403 || r.errCode(t) != "captcha_failed" {
		t.Fatalf("bad token: %d %s", r.Status, r.Body)
	}
	// Attack: a token solved on the attacker's own site.
	if r := c.withToken(token("signup", "evil.example.net")).do("POST", "/v1/auth/signup", body(), ""); r.Status != 403 || r.errCode(t) != "captcha_failed" {
		t.Fatalf("foreign hostname: %d %s", r.Status, r.Body)
	}
	// Attack: a token solved for a cheaper action reused for sign-up.
	if r := c.withToken(token("password_forgot", "app.example.com")).do("POST", "/v1/auth/signup", body(), ""); r.Status != 403 || r.errCode(t) != "captcha_failed" {
		t.Fatalf("wrong action: %d %s", r.Status, r.Body)
	}
	good := token("signup", "app.example.com")
	if r := c.withToken(good).do("POST", "/v1/auth/signup", body(), ""); r.Status != 201 {
		t.Fatalf("valid token: %d %s", r.Status, r.Body)
	}
	// Attack: replaying a spent token.
	if r := c.withToken(good).do("POST", "/v1/auth/signup", body(), ""); r.Status != 403 || r.errCode(t) != "captcha_failed" {
		t.Fatalf("replayed token: %d %s", r.Status, r.Body)
	}
	// Body field works too.
	b := body()
	b["turnstile_token"] = token("signup", "app.example.com")
	if r := c.do("POST", "/v1/auth/signup", b, ""); r.Status != 201 {
		t.Fatalf("body token: %d %s", r.Status, r.Body)
	}
	// The server, not the client, holds the secret, and forwards the real client IP.
	fake.mu.Lock()
	for i, s := range fake.secrets {
		if s != tsSecret {
			t.Errorf("call %d used secret %q", i, s)
		}
	}
	if last := fake.ips[len(fake.ips)-1]; last != c.ip {
		t.Errorf("remoteip %q, want %q", last, c.ip)
	}
	fake.mu.Unlock()
}

func TestTurnstileProvidersExposeOnlyPublicKey(t *testing.T) {
	withTurnstile(t, nil)
	r := newClient(t).do("GET", "/v1/auth/providers", nil, "")
	if r.Status != 200 {
		t.Fatalf("providers: %d", r.Status)
	}
	if strings.Contains(string(r.Body), tsSecret) || strings.Contains(string(r.Body), "secret") {
		t.Fatalf("secret leaked: %s", r.Body)
	}
	bot, _ := r.json(t)["captcha"].(map[string]any)
	if bot["provider"] != "turnstile" || bot["site_key"] != tsSite || bot["signin"] != "after_failures" || bot["signin_after"] != float64(2) {
		t.Fatalf("captcha config: %v", bot)
	}
}

func TestTurnstileDisabledPerEndpoint(t *testing.T) {
	withTurnstile(t, func(r *settings.Runtime) { r.TurnstileSignup = false })
	c := newClient(t)
	if r := c.do("POST", "/v1/auth/signup", map[string]string{"email": randEmail(), "password": pw}, ""); r.Status != 201 {
		t.Fatalf("sign-up check off: %d %s", r.Status, r.Body)
	}
	if r := c.do("POST", "/v1/auth/password/forgot", map[string]string{"email": randEmail()}, ""); r.Status != 400 || r.errCode(t) != "captcha_required" {
		t.Fatalf("forgot still protected: %d %s", r.Status, r.Body)
	}
}

func TestTurnstileForgotAndResend(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	tk := c.signUp(email, pw)
	withTurnstile(t, nil)

	if r := c.do("POST", "/v1/auth/password/forgot", map[string]string{"email": email}, ""); r.Status != 400 || r.errCode(t) != "captcha_required" {
		t.Fatalf("forgot without token: %d %s", r.Status, r.Body)
	}
	if r := c.withToken(token("password_forgot", "app.example.com")).do("POST", "/v1/auth/password/forgot", map[string]string{"email": email}, ""); r.Status != 202 {
		t.Fatalf("forgot with token: %d %s", r.Status, r.Body)
	}
	if r := c.do("POST", "/v1/me/email/resend", nil, tk.Access); r.Status != 400 || r.errCode(t) != "captcha_required" {
		t.Fatalf("resend without token: %d %s", r.Status, r.Body)
	}
	if r := c.withToken(token("signup", "app.example.com")).do("POST", "/v1/me/email/resend", nil, tk.Access); r.Status != 403 {
		t.Fatalf("resend with wrong action: %d %s", r.Status, r.Body)
	}
	if r := c.withToken(token("email_resend", "app.example.com")).do("POST", "/v1/me/email/resend", nil, tk.Access); r.Status != 202 {
		t.Fatalf("resend with token: %d %s", r.Status, r.Body)
	}
}

func TestTurnstileSignInAfterFailures(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	c.signUp(email, pw)
	fresh := newClient(t)
	e2 := randEmail()
	fresh.signUp(e2, pw)
	withTurnstile(t, nil) // after 2 failures

	signIn := func(cl *client, email, password string) resp {
		return cl.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": password}, "")
	}
	if r := signIn(c, email, pw); r.Status != 200 {
		t.Fatalf("clean sign-in should not need a check: %d %s", r.Status, r.Body)
	}
	for i := 0; i < 2; i++ {
		if r := signIn(c, email, "wrong password "+randIP()); r.Status != 401 {
			t.Fatalf("failure %d: %d %s", i, r.Status, r.Body)
		}
	}
	// Even the right password now needs the check (no free guesses).
	if r := signIn(c, email, pw); r.Status != 400 || r.errCode(t) != "captcha_required" {
		t.Fatalf("after failures: %d %s", r.Status, r.Body)
	}
	// From another IP the account counter still applies.
	other := newClient(t)
	if r := signIn(other, email, pw); r.Status != 400 || r.errCode(t) != "captcha_required" {
		t.Fatalf("account counter from another IP: %d %s", r.Status, r.Body)
	}
	// From the same IP, other accounts need it too (password spraying).
	if r := signIn(c, randEmail(), "whatever password"); r.Status != 400 || r.errCode(t) != "captcha_required" {
		t.Fatalf("ip counter: %d %s", r.Status, r.Body)
	}
	if r := signIn(c.withToken(token("signup", "app.example.com")), email, pw); r.Status != 403 {
		t.Fatalf("wrong action accepted: %d %s", r.Status, r.Body)
	}
	if r := signIn(c.withToken(token("signin", "app.example.com")), email, pw); r.Status != 200 {
		t.Fatalf("with token: %d %s", r.Status, r.Body)
	}
	// A fresh client and account need no check.
	if r := signIn(fresh, e2, pw); r.Status != 200 {
		t.Fatalf("fresh: %d %s", r.Status, r.Body)
	}
}

func TestTurnstileSignInModes(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	c.signUp(email, pw)
	signIn := func(cl *client) resp {
		return cl.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, "")
	}

	t.Run("always", func(t *testing.T) {
		withTurnstile(t, func(r *settings.Runtime) { r.TurnstileSignIn = captcha.SignInAlways })
		if r := signIn(c); r.Status != 400 || r.errCode(t) != "captcha_required" {
			t.Fatalf("always without token: %d %s", r.Status, r.Body)
		}
		if r := signIn(c.withToken(token("signin", "app.example.com"))); r.Status != 200 {
			t.Fatalf("always with token: %d %s", r.Status, r.Body)
		}
	})
	t.Run("off", func(t *testing.T) {
		withTurnstile(t, func(r *settings.Runtime) { r.TurnstileSignIn = captcha.SignInOff })
		cl := newClient(t)
		for i := 0; i < 3; i++ {
			cl.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": "nope nope nope"}, "")
		}
		if r := signIn(cl); r.Status != 200 {
			t.Fatalf("off: %d %s", r.Status, r.Body)
		}
	})
}

func TestTurnstileFailsClosed(t *testing.T) {
	withTurnstile(t, nil)
	srv := httptest.NewServer(http.NotFoundHandler())
	dead := srv.URL
	srv.Close()
	A.HTTP.SetCaptchaVerifier(captcha.NewWithURL(nil, dead, nil))
	c := newClient(t)
	r := c.withToken(token("signup", "app.example.com")).do("POST", "/v1/auth/signup", map[string]string{"email": randEmail(), "password": pw}, "")
	if r.Status != 503 || r.errCode(t) != "captcha_unavailable" {
		t.Fatalf("unreachable Cloudflare: %d %s", r.Status, r.Body)
	}
}

func TestTurnstileCORSAllowsHeader(t *testing.T) {
	req, _ := http.NewRequest("OPTIONS", "http://warden.test/v1/auth/signup", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type,cf-turnstile-response")
	r := newClient(t).raw(req)
	if !strings.Contains(strings.ToLower(r.Header.Get("Access-Control-Allow-Headers")), "cf-turnstile-response") {
		t.Fatalf("preflight: %d %v", r.Status, r.Header)
	}
}

func TestTurnstileSettingsAreAdminUIOnly(t *testing.T) {
	withTurnstile(t, nil)
	a := adminLogin(t)
	tok := a.createToken("Turnstile probe", "1h", map[string]string{"settings": "write"}, "")
	if st, body := apiDo(t, "PATCH", "/settings", tok, map[string]any{"turnstile_enabled": false}, nil); st != 403 {
		t.Fatalf("token turned off bot protection: %d %v", st, body)
	}
	st, body := apiDo(t, "GET", "/settings", tok, nil, nil)
	raw, _ := json.Marshal(body)
	if st != 200 || strings.Contains(string(raw), tsSecret) || strings.Contains(string(raw), "turnstile_secret") {
		t.Fatalf("settings API leaks the secret: %d %s", st, raw)
	}
	// Changing an unrelated setting keeps the secret and protection on.
	if st, body := apiDo(t, "PATCH", "/settings", tok, map[string]any{"app_name": "Acme"}, nil); st != 200 {
		t.Fatalf("patch: %d %v", st, body)
	}
	if !A.Settings.Get().TurnstileEnabled || A.Settings.Get().TurnstileSecretKey != tsSecret {
		t.Fatal("unrelated patch dropped Turnstile")
	}
	// The secret is stored encrypted.
	var data string
	if err := A.Store.Pool().QueryRow(context.Background(), `SELECT data::text FROM runtime_settings`).Scan(&data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(data, tsSecret) {
		t.Fatal("secret stored in plaintext")
	}
	// The admin page never renders it.
	_, page := adminDo(t, "GET", "/admin/settings", a.cookie, nil, nil)
	if strings.Contains(page, tsSecret) {
		t.Fatal("admin page renders the secret")
	}
}
