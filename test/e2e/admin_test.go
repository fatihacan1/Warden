//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type adminClient struct {
	t      *testing.T
	cookie string
	csrf   string
}

func adminDo(t *testing.T, method, path, cookie string, form url.Values, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, "http://admin.test"+path, body)
	req.Host = "admin.test"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.Header.Set("Cookie", "warden_admin="+cookie)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := A.Admin.App().Test(req, fiberTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

var csrfRe = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)

func adminLogin(t *testing.T) *adminClient {
	t.Helper()
	// Every test logs in from the same address; reset the login rate limit so
	// the number of admin tests is not capped by it (TestAdminAuth covers it).
	if keys, _ := A.Redis.Keys(context.Background(), "rate:admin_login:*").Result(); len(keys) > 0 {
		A.Redis.Del(context.Background(), keys...)
	}
	res, _ := adminDo(t, "POST", "/admin/login", "", url.Values{"token": {adminToken}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("admin login: %d", res.StatusCode)
	}
	var cookie string
	for _, c := range res.Cookies() {
		if c.Name == "warden_admin" {
			cookie = c.Value
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatal("admin cookie must be HttpOnly and SameSite=Strict")
			}
		}
	}
	_, page := adminDo(t, "GET", "/admin", cookie, nil, nil)
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no csrf token on page")
	}
	return &adminClient{t: t, cookie: cookie, csrf: m[1]}
}

func TestAdminAuth(t *testing.T) {
	if res, _ := adminDo(t, "GET", "/admin", "", nil, nil); res.StatusCode != 303 && res.StatusCode != 302 {
		t.Fatalf("unauthenticated admin access: %d", res.StatusCode)
	}
	if res, _ := adminDo(t, "GET", "/admin", "forged-session", nil, nil); res.StatusCode != 303 && res.StatusCode != 302 {
		t.Fatal("forged session accepted")
	}
	if res, body := adminDo(t, "POST", "/admin/login", "", url.Values{"token": {"wrong"}}, nil); res.StatusCode != 401 || !strings.Contains(body, "not valid") {
		t.Fatalf("wrong token: %d", res.StatusCode)
	}
	// Metrics stay available for scrapers.
	if res, body := adminDo(t, "GET", "/metrics", "", nil, nil); res.StatusCode != 200 || !strings.Contains(body, "warden_http_in_flight_requests") {
		t.Fatalf("metrics: %d", res.StatusCode)
	}
}

func TestAdminCSRFAndOrigin(t *testing.T) {
	a := adminLogin(t)
	c := newClient(t)
	tk := c.signUp(randEmail(), pw)
	path := "/admin/users/" + tk.UserID + "/disable"

	if res, _ := adminDo(t, "POST", path, a.cookie, url.Values{}, nil); res.StatusCode != 403 {
		t.Fatalf("POST without CSRF token: %d", res.StatusCode)
	}
	if res, _ := adminDo(t, "POST", path, a.cookie, url.Values{"_csrf": {"wrong"}}, nil); res.StatusCode != 403 {
		t.Fatalf("POST with wrong CSRF token: %d", res.StatusCode)
	}
	if res, _ := adminDo(t, "POST", path, a.cookie, url.Values{"_csrf": {a.csrf}}, map[string]string{"Origin": "https://evil.example.com"}); res.StatusCode != 403 {
		t.Fatalf("cross-origin POST: %d", res.StatusCode)
	}
	if c.do("GET", "/v1/me", nil, tk.Access).Status != 200 {
		t.Fatal("a rejected admin request had an effect")
	}
	res, _ := adminDo(t, "POST", path, a.cookie, url.Values{"_csrf": {a.csrf}}, map[string]string{"Origin": "http://admin.test"})
	if res.StatusCode != 303 {
		t.Fatalf("valid admin action: %d", res.StatusCode)
	}
	if c.do("GET", "/v1/me", nil, tk.Access).Status != 401 {
		t.Fatal("disabled user still active")
	}
}

func TestAdminProviderToggle(t *testing.T) {
	a := adminLogin(t)
	form := url.Values{"_csrf": {a.csrf}, "enabled": {"on"}, "client_id": {"gh-client"}, "client_secret": {"gh-secret-value"}}
	res, _ := adminDo(t, "POST", "/admin/providers/github", a.cookie, form, nil)
	if res.StatusCode != 303 || hasFlashError(res) {
		t.Fatalf("enable github: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	c := newClient(t)
	if body := string(c.do("GET", "/v1/auth/providers", nil, "").Body); !strings.Contains(body, `"github"`) {
		t.Fatalf("github not listed after enabling: %s", body)
	}
	_, page := adminDo(t, "GET", "/admin/providers", a.cookie, nil, nil)
	if strings.Contains(page, "gh-secret-value") {
		t.Fatal("provider secret rendered back into the admin page")
	}
	// Enabling with a missing secret is rejected with a message.
	res, _ = adminDo(t, "POST", "/admin/providers/discord", a.cookie, url.Values{"_csrf": {a.csrf}, "enabled": {"on"}, "client_id": {"x"}}, nil)
	if !hasFlashError(res) {
		t.Fatal("invalid provider settings accepted")
	}
	// Turn it back off.
	adminDo(t, "POST", "/admin/providers/github", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)
	if body := string(c.do("GET", "/v1/auth/providers", nil, "").Body); strings.Contains(body, `"github"`) {
		t.Fatal("github still listed after disabling")
	}
}

func TestAdminPagesRender(t *testing.T) {
	a := adminLogin(t)
	tk := newClient(t).signUp(randEmail(), pw)
	for _, p := range []string{"/admin", "/admin/settings", "/admin/providers", "/admin/users", "/admin/users?q=example", "/admin/users/" + tk.UserID, "/admin/keys", "/admin/setup",
		"/admin/api-keys", "/admin/webhooks", "/admin/emails", "/admin/emails/verify_email", "/admin/emails/layout", "/admin/docs", "/admin/access-tokens", "/admin/inbox"} {
		res, body := adminDo(t, "GET", p, a.cookie, nil, nil)
		if res.StatusCode != 200 || !strings.Contains(body, "</html>") {
			t.Errorf("%s: %d", p, res.StatusCode)
		}
		if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
			t.Errorf("%s: weak CSP %q", p, csp)
		}
	}
	// Reflected input is escaped.
	_, body := adminDo(t, "GET", "/admin/users?q=%3Cscript%3Ealert(1)%3C/script%3E", a.cookie, nil, nil)
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("search query reflected without escaping")
	}
	_, body = adminDo(t, "GET", "/admin?err=%3Cimg%20src=x%20onerror=alert(1)%3E", a.cookie, nil, nil)
	if strings.Contains(body, "<img src=x") {
		t.Fatal("error message reflected without escaping")
	}
}

func hasFlashError(res *http.Response) bool {
	for _, c := range res.Cookies() {
		if c.Name == "warden_admin_flash" && c.Value != "" {
			return true
		}
	}
	return false
}

func TestAdminSessionDiesWithTokenRotation(t *testing.T) {
	a := adminLogin(t)
	// Simulate a different ADMIN_TOKEN by changing the stored fingerprint.
	if _, page := adminDo(t, "GET", "/admin", a.cookie, nil, nil); !strings.Contains(page, "Overview") {
		t.Fatal("session should work")
	}
	keys, _ := A.Redis.Keys(context.Background(), "admin:sess:*").Result()
	for _, k := range keys {
		A.Redis.Set(context.Background(), k, `{"csrf":"x","tfp":"old-token"}`, time.Minute)
	}
	if res, _ := adminDo(t, "GET", "/admin", a.cookie, nil, nil); res.StatusCode != 303 && res.StatusCode != 302 {
		t.Fatalf("session issued for another admin token still valid: %d", res.StatusCode)
	}
}

func TestAdminRuntimeSettings(t *testing.T) {
	a := adminLogin(t)
	c := newClient(t)
	cur := A.Settings.Get()
	form := url.Values{
		"_csrf": {a.csrf}, "password_min_length": {"12"}, "lockout_threshold": {"5"}, "app_name": {"Northwind"},
		"verify_email_url": {cur.VerifyEmailURL}, "reset_password_url": {cur.ResetPasswordURL},
		"allowed_redirect_uris": {strings.Join(cur.AllowedRedirectURIs, "\n")},
		"cors_origins":          {"https://app.example.com\nhttps://admin.example.com"},
		// allow_signup omitted = switched off
	}
	res, _ := adminDo(t, "POST", "/admin/settings", a.cookie, form, nil)
	if res.StatusCode != 303 || hasFlashError(res) {
		t.Fatalf("save settings: %d", res.StatusCode)
	}
	defer adminDo(t, "POST", "/admin/settings/reset", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)

	if r := c.do("POST", "/v1/auth/signup", map[string]string{"email": randEmail(), "password": pw}, ""); r.errCode(t) != "signup_disabled" {
		t.Fatalf("sign-ups should be off immediately: %s", r.Body)
	}
	body := c.do("GET", "/v1/auth/providers", nil, "").json(t)
	if body["signup_enabled"] != false || body["password_min_length"] != float64(12) {
		t.Fatalf("providers endpoint does not reflect settings: %v", body)
	}
	// New CORS origin is live without a restart.
	req, _ := http.NewRequest("OPTIONS", "http://warden.test/v1/auth/signin", nil)
	req.Header.Set("Origin", "https://admin.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	if got := c.raw(req).Header.Get("Access-Control-Allow-Origin"); got != "https://admin.example.com" {
		t.Fatalf("new CORS origin not applied: %q", got)
	}
	// Unsafe values are refused and change nothing.
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("cors_origins", "*")
	bad.Set("allow_signup", "on")
	res, _ = adminDo(t, "POST", "/admin/settings", a.cookie, bad, nil)
	if !hasFlashError(res) || A.Settings.Get().AllowSignup {
		t.Fatal("wildcard CORS accepted")
	}
	// Reset restores environment values.
	adminDo(t, "POST", "/admin/settings/reset", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)
	if c.do("POST", "/v1/auth/signup", map[string]string{"email": randEmail(), "password": pw}, "").Status != 201 {
		t.Fatal("sign-ups not restored after reset")
	}
}

func TestAdminIdleTimeout(t *testing.T) {
	a := adminLogin(t)
	keys, _ := A.Redis.Keys(context.Background(), "admin:sess:*").Result()
	for _, k := range keys {
		raw, _ := A.Redis.Get(context.Background(), k).Bytes()
		var sess map[string]any
		_ = json.Unmarshal(raw, &sess)
		sess["seen"] = time.Now().Add(-2 * time.Hour)
		b, _ := json.Marshal(sess)
		A.Redis.Set(context.Background(), k, b, time.Hour)
	}
	res, _ := adminDo(t, "GET", "/admin", a.cookie, nil, nil)
	if res.StatusCode != 303 && res.StatusCode != 302 || !strings.Contains(res.Header.Get("Location"), "expired=1") {
		t.Fatalf("idle session still valid: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}
