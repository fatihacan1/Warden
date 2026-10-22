//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatihacan1/warden/internal/app"
	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/webhooks"
)

var revealRe = regexp.MustCompile(`<code>((?:sk|pk)_test_[A-Za-z0-9_-]{20,}|whsec_(?:[A-Za-z0-9+/=]|&#43;){20,})</code>`)

// adminReveal follows a show-once redirect and returns the revealed value.
func (a *adminClient) reveal(res *http.Response) string {
	a.t.Helper()
	loc := res.Header.Get("Location")
	if res.StatusCode != 303 || !strings.Contains(loc, "reveal=") {
		a.t.Fatalf("expected a reveal redirect, got %d %q", res.StatusCode, loc)
	}
	_, page := adminDo(a.t, "GET", loc, a.cookie, nil, nil)
	m := revealRe.FindStringSubmatch(page)
	if m == nil {
		a.t.Fatalf("no revealed value on page (%s): %.400s", loc, page)
	}
	// Show-once: a second visit shows nothing.
	if _, again := adminDo(a.t, "GET", loc, a.cookie, nil, nil); revealRe.MatchString(again) {
		a.t.Fatal("secret shown twice")
	}
	// html/template writes "+" as "&#43;"; browsers show it as "+".
	return html.UnescapeString(m[1])
}

func (a *adminClient) createKey(kind, name, origins string) string {
	a.t.Helper()
	res, _ := adminDo(a.t, "POST", "/admin/api-keys", a.cookie, url.Values{"_csrf": {a.csrf}, "kind": {kind}, "name": {name}, "origins": {origins}}, nil)
	if hasFlashError(res) {
		a.t.Fatalf("create %s key failed", kind)
	}
	return a.reveal(res)
}

func TestServerAPIWithSecretKey(t *testing.T) {
	a := adminLogin(t)
	sk := a.createKey("secret", "Billing service", "")
	if !strings.HasPrefix(sk, "sk_test_") {
		t.Fatalf("unexpected secret key %q", sk)
	}
	_, page := adminDo(t, "GET", "/admin/api-keys", a.cookie, nil, nil)
	if strings.Contains(page, sk) {
		t.Fatal("secret key rendered on the keys page after creation")
	}

	c := newClient(t)
	email := randEmail()
	r := c.do("POST", "/v1/server/users", map[string]any{"email": email, "password": pw, "name": "Ada", "roles": []string{"admin"}, "email_verified": true}, sk)
	if r.Status != 201 {
		t.Fatalf("create user: %d %s", r.Status, r.Body)
	}
	u := r.json(t)
	id := u["id"].(string)
	if u["email_verified"] != true || u["roles"].([]any)[0] != "admin" {
		t.Fatalf("created user: %v", u)
	}
	if r := c.do("POST", "/v1/server/users", map[string]any{"email": email}, sk); r.errCode(t) != "email_taken" {
		t.Fatalf("duplicate email: %s", r.Body)
	}
	if r := c.do("GET", "/v1/server/users?email="+url.QueryEscape(strings.ToUpper(email)), nil, sk); r.Status != 200 || r.json(t)["id"] != id {
		t.Fatalf("find by email: %s", r.Body)
	}

	// The created user can sign in, and roles are in the token.
	tk := parseTokens(t, c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, ""))
	r = c.do("POST", "/v1/server/tokens/verify", map[string]any{"token": tk.Access}, sk)
	if v := r.json(t); v["active"] != true || v["user_id"] != id {
		t.Fatalf("verify token: %s", r.Body)
	}

	// Role change shows up in an online check right away.
	if r := c.do("PATCH", "/v1/server/users/"+id, map[string]any{"roles": []string{"admin", "billing"}, "name": "Ada L."}, sk); r.Status != 200 || r.json(t)["name"] != "Ada L." {
		t.Fatalf("update user: %d %s", r.Status, r.Body)
	}
	v := c.do("POST", "/v1/server/tokens/verify", map[string]any{"token": tk.Access, "check_session": true}, sk).json(t)
	if roles, _ := v["roles"].([]any); len(roles) != 2 {
		t.Fatalf("online check should return current roles: %v", v)
	}
	if r := c.do("DELETE", "/v1/server/users/"+id+"/sessions", nil, sk); r.json(t)["revoked"] != float64(1) {
		t.Fatalf("revoke sessions: %s", r.Body)
	}
	if v := c.do("POST", "/v1/server/tokens/verify", map[string]any{"token": tk.Access}, sk).json(t); v["active"] != false {
		t.Fatalf("revoked session still active: %v", v)
	}

	// Rejections: no key, wrong key, an access token, a publishable key, a browser.
	for name, auth := range map[string]string{"none": "", "wrong": "sk_test_wrongwrongwrongwrongwrong", "access token": tk.Access} {
		if r := c.do("GET", "/v1/server/users/"+id, nil, auth); r.Status != 401 || r.errCode(t) != "invalid_secret_key" {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	browser := newClient(t)
	browser.headers["Origin"] = "https://app.example.com"
	if r := browser.do("GET", "/v1/server/users/"+id, nil, sk); r.errCode(t) != "secret_key_in_browser" {
		t.Fatalf("secret key accepted from a browser: %s", r.Body)
	}

	// Revoked keys stop working immediately.
	keyID := ""
	for _, k := range A.APIKeys.List() {
		if k.Name == "Billing service" && k.Active() {
			keyID = k.ID.String()
		}
	}
	adminDo(t, "POST", "/admin/api-keys/"+keyID+"/revoke", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)
	if r := c.do("GET", "/v1/server/users/"+id, nil, sk); r.Status != 401 {
		t.Fatal("revoked secret key still accepted")
	}
}

func TestPublishableKeys(t *testing.T) {
	a := adminLogin(t)
	pk := a.createKey("publishable", "Web app", "https://pk-app.example.com")

	c := newClient(t)
	c.headers["X-Warden-Key"] = pk
	c.headers["Origin"] = "https://pk-app.example.com"
	if r := c.do("GET", "/v1/auth/providers", nil, ""); r.Status != 200 || r.Header.Get("Access-Control-Allow-Origin") != "https://pk-app.example.com" {
		t.Fatalf("publishable key from its origin: %d acao=%q", r.Status, r.Header.Get("Access-Control-Allow-Origin"))
	}
	// The key's origin passes CORS preflight without being in Settings.
	req, _ := http.NewRequest("OPTIONS", "http://warden.test/v1/auth/signin", nil)
	req.Header.Set("Origin", "https://pk-app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "x-warden-key,content-type")
	if got := c.raw(req).Header.Get("Access-Control-Allow-Origin"); got != "https://pk-app.example.com" {
		t.Fatalf("preflight for a key origin: %q", got)
	}

	evil := newClient(t)
	evil.headers["X-Warden-Key"] = pk
	evil.headers["Origin"] = "https://evil.example.com"
	if r := evil.do("GET", "/v1/auth/providers", nil, ""); r.errCode(t) != "origin_not_allowed" {
		t.Fatalf("key used from another origin: %s", r.Body)
	}
	bogus := newClient(t)
	bogus.headers["X-Warden-Key"] = "pk_test_doesnotexist000000000000"
	if r := bogus.do("GET", "/v1/auth/providers", nil, ""); r.errCode(t) != "invalid_publishable_key" {
		t.Fatalf("unknown key accepted: %s", r.Body)
	}

	// Enforce keys: calls without one are rejected, calls with one pass.
	cur := A.Settings.Get()
	form := url.Values{
		"_csrf": {a.csrf}, "allow_signup": {"on"}, "password_min_length": {"8"}, "lockout_threshold": {"5"}, "app_name": {"Warden"},
		"verify_email_url": {cur.VerifyEmailURL}, "reset_password_url": {cur.ResetPasswordURL},
		"allowed_redirect_uris": {strings.Join(cur.AllowedRedirectURIs, "\n")}, "cors_origins": {strings.Join(cur.CORSOrigins, "\n")},
		"require_publishable_key": {"on"},
	}
	if res, _ := adminDo(t, "POST", "/admin/settings", a.cookie, form, nil); hasFlashError(res) {
		t.Fatal("could not require publishable keys")
	}
	defer adminDo(t, "POST", "/admin/settings/reset", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)
	if r := newClient(t).do("GET", "/v1/auth/providers", nil, ""); r.errCode(t) != "invalid_publishable_key" {
		t.Fatalf("keyless request accepted while keys are required: %s", r.Body)
	}
	if r := c.do("GET", "/v1/auth/providers", nil, ""); r.Status != 200 {
		t.Fatalf("keyed request rejected: %s", r.Body)
	}
	// Discovery and JWKS stay public: other services must always reach them.
	if r := newClient(t).do("GET", "/.well-known/jwks.json", nil, ""); r.Status != 200 {
		t.Fatal("JWKS requires a publishable key")
	}
}

func gql(c *client, auth, query string, vars map[string]any) resp {
	c.t.Helper()
	return c.do("POST", "/graphql", map[string]any{"query": query, "variables": vars}, auth)
}

func gqlErrCode(t *testing.T, r resp) string {
	t.Helper()
	errs, _ := r.json(t)["errors"].([]any)
	if len(errs) == 0 {
		return ""
	}
	ext, _ := errs[0].(map[string]any)["extensions"].(map[string]any)
	code, _ := ext["code"].(string)
	return code
}

func TestGraphQL(t *testing.T) {
	c := newClient(t)
	tk := c.signUp(randEmail(), pw)

	r := gql(c, tk.Access, `{ me { id name roles } sessions { id current } providers { password } }`, nil)
	data, _ := r.json(t)["data"].(map[string]any)
	if r.Status != 200 || data == nil || data["me"].(map[string]any)["id"] != tk.UserID {
		t.Fatalf("me query: %s", r.Body)
	}
	if s := data["sessions"].([]any); len(s) != 1 || s[0].(map[string]any)["current"] != true {
		t.Fatalf("sessions: %v", s)
	}

	r = gql(c, tk.Access, `mutation($n: String!) { updateProfile(name: $n) { name } }`, map[string]any{"n": "Grace"})
	if !strings.Contains(string(r.Body), `"Grace"`) {
		t.Fatalf("mutation: %s", r.Body)
	}

	// Anonymous: public fields only.
	if r := gql(c, "", `{ providers { signupEnabled } }`, nil); r.Status != 200 || strings.Contains(string(r.Body), "errors") {
		t.Fatalf("anonymous providers: %s", r.Body)
	}
	if r := gql(c, "", `{ me { id } }`, nil); gqlErrCode(t, r) != "unauthorized" {
		t.Fatalf("anonymous me: %s", r.Body)
	}
	// Server-only fields need a secret key, not a user token.
	if r := gql(c, tk.Access, `{ user(id: "`+tk.UserID+`") { email } }`, nil); gqlErrCode(t, r) != "invalid_secret_key" {
		t.Fatalf("user() with an access token: %s", r.Body)
	}
	sk := adminLogin(t).createKey("secret", "GraphQL test", "")
	if r := gql(c, sk, `{ user(id: "`+tk.UserID+`") { id } }`, nil); !strings.Contains(string(r.Body), tk.UserID) {
		t.Fatalf("user() with a secret key: %s", r.Body)
	}

	// Abuse limits.
	nested := "{ __schema { types { fields { type { ofType { ofType { ofType { ofType { name } } } } } } } } }"
	if r := gql(c, tk.Access, nested, nil); !strings.Contains(string(r.Body), "errors") {
		t.Fatalf("deep query accepted: %s", r.Body)
	}
	if r := gql(c, tk.Access, "{ me { id } }"+strings.Repeat(" ", 9000), nil); !strings.Contains(string(r.Body), "errors") {
		t.Fatalf("oversized query accepted: %d", r.Status)
	}
	batch, _ := http.NewRequest("POST", "http://warden.test/graphql", strings.NewReader(`[{"query":"{ me { id } }"}]`))
	batch.Header.Set("Content-Type", "application/json")
	if r := c.raw(batch); r.Status != 422 {
		t.Fatalf("batched request: %d", r.Status)
	}
	if r := c.do("GET", "/graphql?query={me{id}}", nil, tk.Access); r.Status != 404 && r.Status != 405 {
		t.Fatalf("GET /graphql must not be served: %d", r.Status)
	}
	form, _ := http.NewRequest("POST", "http://warden.test/graphql", strings.NewReader(`query={me{id}}`))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if r := c.raw(form); r.Status != 415 {
		t.Fatalf("form-encoded GraphQL (CSRF vector) accepted: %d", r.Status)
	}
}

type receiver struct {
	mu     sync.Mutex
	status int
	got    []http.Header
	bodies [][]byte
}

func (rc *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.got = append(rc.got, r.Header.Clone())
	rc.bodies = append(rc.bodies, b)
	w.WriteHeader(rc.status)
}

func (rc *receiver) count() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.bodies)
}

func drainUntil(t *testing.T, cond func() bool) {
	t.Helper()
	for range 40 {
		relay.Tick(context.Background())
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not reached while draining the outbox")
}

func TestWebhooks(t *testing.T) {
	rc := &receiver{status: 204}
	srv := httptest.NewServer(rc)
	defer srv.Close()

	a := adminLogin(t)
	form := url.Values{"_csrf": {a.csrf}, "url": {srv.URL + "/hooks"}, "event_user.created": {"on"}, "event_user.updated": {"on"}}
	res, _ := adminDo(t, "POST", "/admin/webhooks", a.cookie, form, nil)
	if hasFlashError(res) {
		t.Fatal("create webhook failed")
	}
	secret := a.reveal(res)
	var hookID string
	for _, w := range A.Webhooks.List() {
		if w.URL == srv.URL+"/hooks" {
			hookID = w.ID.String()
		}
	}
	defer adminDo(t, "POST", "/admin/webhooks/"+hookID+"/delete", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)

	c := newClient(t)
	tk := c.signUp(randEmail(), pw)
	drainUntil(t, func() bool { return rc.count() >= 1 })

	rc.mu.Lock()
	h, body := rc.got[0], rc.bodies[0]
	rc.mu.Unlock()
	if !webhooks.Verify(secret, h.Get("webhook-id"), h.Get("webhook-timestamp"), h.Get("webhook-signature"), body, 5*time.Minute, time.Now()) {
		t.Fatalf("signature does not verify: %v", h)
	}
	var evt map[string]any
	_ = json.Unmarshal(body, &evt)
	if evt["type"] != "user.created" || evt["user_id"] != tk.UserID || evt["id"] != h.Get("webhook-id") {
		t.Fatalf("unexpected event %s", body)
	}
	// Tampered bodies and old timestamps fail verification.
	if webhooks.Verify(secret, h.Get("webhook-id"), h.Get("webhook-timestamp"), h.Get("webhook-signature"), append(body, ' '), 5*time.Minute, time.Now()) {
		t.Fatal("tampered body verified")
	}
	if webhooks.Verify(secret, h.Get("webhook-id"), h.Get("webhook-timestamp"), h.Get("webhook-signature"), body, 5*time.Minute, time.Now().Add(10*time.Minute)) {
		t.Fatal("replayed request verified")
	}

	// Unsubscribed events are not sent; subscribed ones are.
	c.do("PATCH", "/v1/me", map[string]string{"name": "Renamed"}, tk.Access)
	drainUntil(t, func() bool { return rc.count() >= 2 })
	rc.mu.Lock()
	second := string(rc.bodies[1])
	rc.mu.Unlock()
	if !strings.Contains(second, `"user.updated"`) {
		t.Fatalf("second delivery: %s", second)
	}

	// A failing receiver is retried; the admin page shows it.
	rc.mu.Lock()
	rc.status = 500
	rc.mu.Unlock()
	adminDo(t, "POST", "/admin/webhooks/"+hookID+"/test", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)
	drainUntil(t, func() bool { return rc.count() >= 3 })
	_, page := adminDo(t, "GET", "/admin/webhooks/"+hookID, a.cookie, nil, nil)
	if !strings.Contains(page, "Retrying") || !strings.Contains(page, "webhook.test") {
		t.Fatal("failed delivery not shown as retrying")
	}

	// SSRF guard: metadata and private addresses are refused in production
	// mode even when the URL looks public.
	m := webhooks.NewManager(A.Store, A.Box, nil, webhooks.Options{Production: true, Timeout: time.Second})
	if _, _, err := m.Create(context.Background(), webhooks.Input{URL: "https://169.254.169.254/latest", Enabled: true}); err == nil {
		t.Fatal("link-local webhook target accepted in production")
	}
	if _, _, err := m.Create(context.Background(), webhooks.Input{URL: "http://api.example.com/hook", Enabled: true}); err == nil {
		t.Fatal("plain http webhook accepted in production")
	}
}

func TestEmailTemplates(t *testing.T) {
	a := adminLogin(t)
	src, _ := A.Renderer.Default("verify_email", "en")
	form := url.Values{"_csrf": {a.csrf}, "subject": {"Welcome aboard, confirm {{.AppName}}"},
		"html": {strings.Replace(src.HTML, "Confirm your email address", "Custom verify heading", 1)}, "text": {src.Text + "\nCustom footer"}}
	res, _ := adminDo(t, "POST", "/admin/emails/verify_email", a.cookie, form, nil)
	if res.StatusCode != 303 || hasFlashError(res) {
		t.Fatalf("save template: %d", res.StatusCode)
	}
	defer adminDo(t, "POST", "/admin/emails/verify_email/reset", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)

	email := randEmail()
	newClient(t).signUp(email, pw)
	tokenFor(t, email, "verify-email")
	mails.mu.Lock()
	var got string
	for _, m := range mails.msgs {
		if m.To == email {
			got = m.Subject + "\n" + m.HTML + "\n" + m.Text
		}
	}
	mails.mu.Unlock()
	if !strings.Contains(got, "Welcome aboard, confirm Warden") || !strings.Contains(got, "Custom verify heading") || !strings.Contains(got, "Custom footer") {
		t.Fatalf("custom template not used:\n%s", got)
	}

	// Preview is framed same-origin only and sandboxed.
	res, body := adminDo(t, "GET", "/admin/emails/verify_email/preview", a.cookie, nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "Custom verify heading") || !strings.Contains(res.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("preview: %d csp=%q", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}
	// Broken templates are refused and the saved one keeps working.
	bad := url.Values{"_csrf": {a.csrf}, "subject": {"x"}, "html": {"{{if}}"}, "text": {"x"}}
	if res, _ := adminDo(t, "POST", "/admin/emails/verify_email", a.cookie, bad, nil); !hasFlashError(res) {
		t.Fatal("broken template accepted")
	}
	if s, _ := A.Renderer.Effective("verify_email", "en"); !strings.Contains(s.HTML, "Custom verify heading") {
		t.Fatal("a rejected save replaced the template")
	}
}

// Rotating ENCRYPTION_KEY (and the algorithm) keeps everything readable, and
// reencrypt moves every stored secret to the new key.
func TestReencryptAfterKeyRotation(t *testing.T) {
	ctx := context.Background()
	oldKey, _ := A.Config.EncryptionKeyBytes()
	newKey := randBytes(32)

	// Make sure every encrypted column has data: MFA, a webhook, a provider.
	c := newClient(t)
	tk := c.signUp(randEmail(), pw)
	c.do("POST", "/v1/me/mfa/totp/setup", nil, tk.Access)
	if _, _, err := A.Webhooks.Create(ctx, webhooks.Input{URL: "https://hooks.example.com/rotate", Enabled: false}); err != nil {
		t.Fatal(err)
	}

	rotated, err := secretbox.NewKeyring(secretbox.XChaCha20Poly1305, newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.Reencrypt(ctx, A.Store, rotated)
	if err != nil {
		t.Fatal(err)
	}
	changed := map[string]int{}
	for _, r := range res {
		changed[r.Column] = r.Changed
	}
	if changed["signing_keys.private_key"] == 0 || changed["webhooks.secret"] == 0 || changed["provider_settings.config"] == 0 {
		t.Fatalf("nothing re-encrypted: %v", changed)
	}
	// Idempotent: a second run has nothing left to do.
	again, _ := app.Reencrypt(ctx, A.Store, rotated)
	for _, r := range again {
		if r.Changed != 0 {
			t.Fatalf("%s re-encrypted twice", r.Column)
		}
	}
	// Only the new key is needed now.
	newOnly, _ := secretbox.NewKeyring(secretbox.XChaCha20Poly1305, newKey)
	rows, _ := A.Store.ListSigningKeys(ctx, time.Now().Add(-time.Hour))
	for _, r := range rows {
		if _, err := newOnly.Open(r.PrivateKey, "signing-key:"+r.KID); err != nil {
			t.Fatalf("signing key %s not readable with the new key alone", r.KID)
		}
	}

	// Put everything back so the rest of the suite keeps working.
	back, _ := secretbox.NewKeyring(secretbox.AES256GCM, oldKey, newKey)
	if _, err := app.Reencrypt(ctx, A.Store, back); err != nil {
		t.Fatal(err)
	}
	if err := A.Keys.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if r := c.do("GET", "/v1/me", nil, tk.Access); r.Status != 200 {
		t.Fatalf("service broken after rotating back: %d", r.Status)
	}
}

// Node.js fetch (undici) sends Sec-Fetch-Mode: cors on every request; that
// must not be mistaken for a browser.
func TestServerAPIAcceptsNodeFetchHeaders(t *testing.T) {
	sk := adminLogin(t).createKey("secret", "Node backend", "")
	c := newClient(t)
	c.headers["Sec-Fetch-Mode"] = "cors"
	if r := c.do("GET", "/v1/server/users?email="+url.QueryEscape(randEmail()), nil, sk); r.Status != 404 {
		t.Fatalf("server API from Node fetch: %d %s", r.Status, r.Body)
	}
}
