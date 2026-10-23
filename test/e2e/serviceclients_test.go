//go:build integration

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	clientIDRe     = regexp.MustCompile(`<code>(svc_[A-Za-z0-9_-]+)</code>`)
	clientSecretRe = regexp.MustCompile(`<code>(wcs_[A-Za-z0-9_-]+)</code>`)
)

type svc struct {
	ID       uuid.UUID
	ClientID string
	Secret   string
}

func (a *adminClient) revealClient(res *http.Response) (clientID, secret string) {
	a.t.Helper()
	loc := res.Header.Get("Location")
	if res.StatusCode != 303 || !strings.Contains(loc, "reveal=") {
		a.t.Fatalf("expected a reveal redirect, got %d %q", res.StatusCode, loc)
	}
	_, page := adminDo(a.t, "GET", loc, a.cookie, nil, nil)
	ci, cs := clientIDRe.FindStringSubmatch(page), clientSecretRe.FindStringSubmatch(page)
	if ci == nil || cs == nil {
		a.t.Fatalf("no client id or secret on page: %.300s", page)
	}
	if _, again := adminDo(a.t, "GET", loc, a.cookie, nil, nil); clientSecretRe.MatchString(again) {
		a.t.Fatal("secret shown twice")
	}
	return ci[1], cs[1]
}

func (a *adminClient) createServiceClient(name, scopes, audiences, ttl string) svc {
	a.t.Helper()
	res, _ := adminDo(a.t, "POST", "/admin/service-clients", a.cookie,
		url.Values{"_csrf": {a.csrf}, "name": {name}, "scopes": {scopes}, "audiences": {audiences}, "ttl": {ttl}}, nil)
	if hasFlashError(res) {
		a.t.Fatalf("create service client %q failed", name)
	}
	id, secret := a.revealClient(res)
	list, err := A.Clients.List(context.Background())
	if err != nil {
		a.t.Fatal(err)
	}
	for _, c := range list {
		if c.ClientID == id {
			return svc{ID: c.ID, ClientID: id, Secret: secret}
		}
	}
	a.t.Fatal("client not stored")
	return svc{}
}

func (a *adminClient) rotateClient(s svc, grace string) string {
	a.t.Helper()
	res, _ := adminDo(a.t, "POST", "/admin/service-clients/"+s.ID.String()+"/rotate", a.cookie, url.Values{"_csrf": {a.csrf}, "grace": {grace}}, nil)
	if hasFlashError(res) {
		a.t.Fatal("rotate failed")
	}
	id, secret := a.revealClient(res)
	if id != s.ClientID {
		a.t.Fatal("client id changed on rotation")
	}
	return secret
}

// tokenRequest posts to /v1/oauth/token as a form, the way RFC 6749 clients do.
func tokenRequest(c *client, form url.Values, basicID, basicSecret string) resp {
	c.t.Helper()
	req, _ := http.NewRequest("POST", "http://warden.test/v1/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", c.ip)
	if basicID != "" || basicSecret != "" {
		req.SetBasicAuth(url.QueryEscape(basicID), url.QueryEscape(basicSecret))
	}
	return c.raw(req)
}

func grant(extra url.Values) url.Values {
	v := url.Values{"grant_type": {"client_credentials"}}
	for k, vals := range extra {
		v[k] = vals
	}
	return v
}

func oauthErr(t *testing.T, r resp) string {
	t.Helper()
	s, _ := r.json(t)["error"].(string)
	return s
}

// jwksKey fetches the signing key with this kid from the public JWKS.
func jwksKey(t *testing.T, kid string) *ecdsa.PublicKey {
	t.Helper()
	var set struct {
		Keys []struct{ Kid, Crv, X, Y string }
	}
	r := newClient(t).do("GET", "/.well-known/jwks.json", nil, "")
	if err := json.Unmarshal(r.Body, &set); err != nil {
		t.Fatal(err)
	}
	for _, k := range set.Keys {
		if k.Kid != kid {
			continue
		}
		x, _ := base64.RawURLEncoding.DecodeString(k.X)
		y, _ := base64.RawURLEncoding.DecodeString(k.Y)
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	}
	t.Fatalf("kid %s not in JWKS", kid)
	return nil
}

func TestClientCredentialsGrant(t *testing.T) {
	a := adminLogin(t)
	s := a.createServiceClient("orders-worker", "orders:read orders:write\nreports:read", "orders-api\ne2e-api", "15")
	c := newClient(t)

	// client_secret_basic, defaults: every scope, first audience.
	r := tokenRequest(c, grant(nil), s.ClientID, s.Secret)
	if r.Status != 200 {
		t.Fatalf("basic auth: %d %s", r.Status, r.Body)
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("token response must not be cacheable")
	}
	body := r.json(t)
	if body["token_type"] != "Bearer" || body["expires_in"].(float64) < 890 || body["expires_in"].(float64) > 900 || body["refresh_token"] != nil {
		t.Fatalf("response %v", body)
	}
	if body["scope"] != "orders:read orders:write reports:read" {
		t.Fatalf("scope %v", body["scope"])
	}
	access := body["access_token"].(string)

	// Offline verification with the public JWKS only.
	var claims struct {
		jwt.RegisteredClaims
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
		SID      string `json:"sid"`
		Email    string `json:"email"`
	}
	tok, err := jwt.ParseWithClaims(access, &claims, func(tk *jwt.Token) (any, error) {
		if tk.Header["typ"] != "at+jwt" {
			t.Fatalf("typ %v", tk.Header["typ"])
		}
		return jwksKey(t, tk.Header["kid"].(string)), nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(A.Config.Token.Issuer), jwt.WithAudience("orders-api"))
	if err != nil || !tok.Valid {
		t.Fatalf("offline verification: %v", err)
	}
	if claims.Subject != "client:"+s.ClientID || claims.ClientID != s.ClientID || claims.ID == "" || claims.SID != "" || claims.Email != "" ||
		claims.Scope != "orders:read orders:write reports:read" {
		t.Fatalf("claims %+v", claims)
	}

	// client_secret_post, a scope subset, a chosen audience and RFC 8707 "resource".
	r = tokenRequest(c, grant(url.Values{"client_id": {s.ClientID}, "client_secret": {s.Secret}, "scope": {"orders:read"}, "audience": {"e2e-api"}}), "", "")
	if r.Status != 200 || r.json(t)["scope"] != "orders:read" {
		t.Fatalf("post auth: %d %s", r.Status, r.Body)
	}
	r = tokenRequest(c, grant(url.Values{"resource": {"e2e-api"}}), s.ClientID, s.Secret)
	if r.Status != 200 {
		t.Fatalf("resource: %d %s", r.Status, r.Body)
	}
	// JSON body works too.
	jr := c.do("POST", "/v1/oauth/token", map[string]any{"grant_type": "client_credentials", "client_id": s.ClientID, "client_secret": s.Secret, "scope": "reports:read"}, "")
	if jr.Status != 200 || jr.json(t)["scope"] != "reports:read" {
		t.Fatalf("json body: %d %s", jr.Status, jr.Body)
	}

	// The audit log records issuance.
	events, _ := A.Store.ListAudit(context.Background(), nil, 200)
	found := false
	for _, e := range events {
		if e.Type == "oauth.client_token_issued" && e.Metadata["client_id"] == s.ClientID {
			found = true
		}
	}
	if !found {
		t.Fatal("no audit entry for the issued token")
	}

	// Discovery advertises the grant.
	d := c.do("GET", "/.well-known/openid-configuration", nil, "").json(t)
	if g, _ := d["grant_types_supported"].([]any); len(g) == 0 || g[0] != "client_credentials" {
		t.Fatalf("discovery %v", d)
	}
}

func TestClientCredentialsErrors(t *testing.T) {
	a := adminLogin(t)
	s := a.createServiceClient("errors-svc", "a:read", "", "5")
	c := newClient(t)

	// Wrong secret, unknown client and missing credentials look the same.
	var bodies []string
	for _, tc := range []struct{ id, secret string }{
		{s.ClientID, "wcs_wrong"}, {"svc_unknown", s.Secret}, {"svc_unknown", "wcs_wrong"},
	} {
		r := tokenRequest(c, grant(nil), tc.id, tc.secret)
		if r.Status != 401 || oauthErr(t, r) != "invalid_client" || !strings.HasPrefix(r.Header.Get("WWW-Authenticate"), "Basic") {
			t.Fatalf("%v: %d %s %q", tc, r.Status, r.Body, r.Header.Get("WWW-Authenticate"))
		}
		bodies = append(bodies, string(r.Body))
	}
	if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatalf("errors differ: %v", bodies)
	}
	if r := tokenRequest(c, grant(nil), "", ""); r.Status != 401 || oauthErr(t, r) != "invalid_client" {
		t.Fatalf("no credentials: %d %s", r.Status, r.Body)
	}
	if r := tokenRequest(c, grant(url.Values{"client_id": {s.ClientID}, "client_secret": {"nope"}}), "", ""); r.Status != 401 || r.Header.Get("WWW-Authenticate") != "" {
		t.Fatalf("post with wrong secret: %d %q", r.Status, r.Header.Get("WWW-Authenticate"))
	}
	// Two authentication methods at once is a malformed request.
	if r := tokenRequest(c, grant(url.Values{"client_id": {s.ClientID}, "client_secret": {s.Secret}}), s.ClientID, s.Secret); r.Status != 400 || oauthErr(t, r) != "invalid_request" {
		t.Fatalf("two methods: %d %s", r.Status, r.Body)
	}

	// Scope and audience outside the allow lists.
	r := tokenRequest(c, grant(url.Values{"scope": {"a:read admin"}}), s.ClientID, s.Secret)
	if r.Status != 400 || oauthErr(t, r) != "invalid_scope" {
		t.Fatalf("scope: %d %s", r.Status, r.Body)
	}
	r = tokenRequest(c, grant(url.Values{"audience": {"billing-api"}}), s.ClientID, s.Secret)
	if r.Status != 400 || oauthErr(t, r) != "invalid_target" {
		t.Fatalf("audience: %d %s", r.Status, r.Body)
	}
	r = tokenRequest(c, grant(url.Values{"resource": {"https://evil.example"}}), s.ClientID, s.Secret)
	if r.Status != 400 || oauthErr(t, r) != "invalid_target" {
		t.Fatalf("resource: %d %s", r.Status, r.Body)
	}
	// Unknown grant types, and forms are not accepted for the login code exchange.
	if r := tokenRequest(c, url.Values{"grant_type": {"password"}, "username": {"x"}}, s.ClientID, s.Secret); r.Status != 400 || oauthErr(t, r) != "unsupported_grant_type" {
		t.Fatalf("password grant: %d %s", r.Status, r.Body)
	}
	if r := tokenRequest(c, url.Values{"code": {"x"}}, "", ""); r.Status != 415 {
		t.Fatalf("form login code exchange: %d %s", r.Status, r.Body)
	}
	// The login code exchange still works as before (invalid code, JSON).
	if r := c.do("POST", "/v1/oauth/token", map[string]string{"code": "bogus", "code_verifier": strings.Repeat("a", 43), "redirect_uri": "https://app.example.com/callback"}, ""); r.Status == 200 || r.Status == 415 || r.Status >= 500 {
		t.Fatalf("login code exchange: %d %s", r.Status, r.Body)
	}

	// A revoked client is refused like an unknown one.
	adminRes, _ := adminDo(t, "POST", "/admin/service-clients/"+s.ID.String()+"/revoke", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)
	if adminRes.StatusCode != 303 {
		t.Fatalf("revoke: %d", adminRes.StatusCode)
	}
	if r := tokenRequest(c, grant(nil), s.ClientID, s.Secret); r.Status != 401 || oauthErr(t, r) != "invalid_client" {
		t.Fatalf("revoked client: %d %s", r.Status, r.Body)
	}
}

func TestServiceTokensAreNotUserTokens(t *testing.T) {
	a := adminLogin(t)
	s := a.createServiceClient("machine-svc", "orders:read", "e2e-api", "15")
	c := newClient(t)
	r := tokenRequest(c, grant(nil), s.ClientID, s.Secret)
	if r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	access := r.json(t)["access_token"].(string)

	// Every user endpoint refuses it.
	for _, p := range []struct{ method, path string }{
		{"GET", "/v1/me"}, {"GET", "/v1/me/sessions"}, {"GET", "/v1/me/identities"}, {"DELETE", "/v1/me/sessions"},
	} {
		if r := c.do(p.method, p.path, nil, access); r.Status != 401 || r.errCode(t) != "invalid_token" {
			t.Fatalf("%s %s with a service token: %d %s", p.method, p.path, r.Status, r.Body)
		}
	}
	if r := c.do("PATCH", "/v1/me", map[string]string{"name": "x"}, access); r.Status != 401 {
		t.Fatalf("PATCH /v1/me: %d", r.Status)
	}
	// GraphQL as well.
	if r := gql(c, access, `{ me { id } }`, nil); r.Status == 200 && !strings.Contains(string(r.Body), "errors") {
		t.Fatalf("graphql me with a service token: %s", r.Body)
	} else if strings.Contains(string(r.Body), `"id"`) {
		t.Fatalf("graphql leaked data: %s", r.Body)
	}
	if r := gql(c, access, `{ sessions { id } }`, nil); strings.Contains(string(r.Body), `"id"`) {
		t.Fatalf("graphql sessions: %s", r.Body)
	}
	// Signing out with it must not touch any session.
	if r := c.do("POST", "/v1/auth/signout", nil, access); r.Status >= 500 {
		t.Fatalf("signout: %d", r.Status)
	}

	// Introspection understands it: active, client and scope, no user.
	sk := a.createKey("secret", "introspect", "")
	v := c.do("POST", "/v1/server/tokens/verify", map[string]any{"token": access}, sk).json(t)
	if v["active"] != true || v["client_id"] != s.ClientID || v["scope"] != "orders:read" || v["token_type"] != "service" || v["user_id"] != nil || v["session_id"] != nil {
		t.Fatalf("introspection: %v", v)
	}
	if aud, _ := v["aud"].([]any); len(aud) != 1 || aud[0] != "e2e-api" {
		t.Fatalf("aud %v", v["aud"])
	}
	// A user token never looks like a service token.
	u := c.signUp(randEmail(), pw)
	uv := c.do("POST", "/v1/server/tokens/verify", map[string]any{"token": u.Access}, sk).json(t)
	if uv["active"] != true || uv["client_id"] != nil || uv["user_id"] != u.UserID {
		t.Fatalf("user introspection: %v", uv)
	}

	// Revoking the client makes introspection answer inactive at once, even
	// though the JWT itself has not expired.
	res, _ := adminDo(t, "POST", "/admin/service-clients/"+s.ID.String()+"/revoke", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("revoke: %d", res.StatusCode)
	}
	v = c.do("POST", "/v1/server/tokens/verify", map[string]any{"token": access}, sk).json(t)
	if v["active"] != false || v["reason"] != "client_revoked" {
		t.Fatalf("after revoke: %v", v)
	}
}

func TestClientSecretRotationGracePeriod(t *testing.T) {
	a := adminLogin(t)
	s := a.createServiceClient("rotating-svc", "x", "", "15")
	c := newClient(t)
	ok := func(secret string) bool {
		return tokenRequest(c, grant(nil), s.ClientID, secret).Status == 200
	}

	next := a.rotateClient(s, "1h")
	if next == s.Secret || !strings.HasPrefix(next, "wcs_") {
		t.Fatal("rotation must produce a new secret")
	}
	if !ok(next) || !ok(s.Secret) {
		t.Fatal("both secrets must work during the grace period")
	}
	_, page := adminDo(t, "GET", "/admin/service-clients", a.cookie, nil, nil)
	if !strings.Contains(page, "Old secret valid") {
		t.Fatal("the UI should show that the old secret is still valid")
	}

	// Rotating again with no grace ends every earlier secret at once.
	third := a.rotateClient(s, "0")
	if ok(s.Secret) || ok(next) || !ok(third) {
		t.Fatal("grace 0 must retire the previous secrets")
	}

	// Grace that runs out: shorten it in the database and see it expire.
	fourth := a.rotateClient(s, "24h")
	if !ok(third) || !ok(fourth) {
		t.Fatal("grace period")
	}
	if _, err := A.Pool.Exec(context.Background(), `UPDATE oauth_clients SET prev_secret_expires_at = now() - interval '1 second' WHERE id = $1`, s.ID); err != nil {
		t.Fatal(err)
	}
	if ok(third) || !ok(fourth) {
		t.Fatal("the old secret must stop working when the grace period ends")
	}
}

func TestClientCredentialsRateLimit(t *testing.T) {
	a := adminLogin(t)
	s := a.createServiceClient("noisy-svc", "x", "", "15")
	c := newClient(t)
	limit := A.Config.RateLimit.ClientTokenPerMinute
	var limited bool
	for i := 0; i < limit+10; i++ {
		r := tokenRequest(c, grant(nil), s.ClientID, s.Secret)
		if r.Status == 429 {
			limited = true
			if r.Header.Get("Retry-After") == "" {
				t.Fatal("missing Retry-After")
			}
			break
		}
		if r.Status != 200 {
			t.Fatalf("request %d: %d %s", i, r.Status, r.Body)
		}
	}
	if !limited {
		t.Fatalf("no rate limit after %d requests", limit+10)
	}
	// Another client is not affected, even from the same address.
	other := a.createServiceClient("quiet-svc", "x", "", "15")
	if r := tokenRequest(newClient(t), grant(nil), other.ClientID, other.Secret); r.Status != 200 {
		t.Fatalf("other client: %d %s", r.Status, r.Body)
	}
	// Strangers cannot burn a client's budget: failed attempts do not count.
	victim := a.createServiceClient("victim-svc", "x", "", "15")
	attacker := newClient(t)
	for range 20 {
		tokenRequest(attacker, grant(nil), victim.ClientID, "wcs_guess")
	}
	if r := tokenRequest(newClient(t), grant(nil), victim.ClientID, victim.Secret); r.Status != 200 {
		t.Fatalf("victim locked out: %d %s", r.Status, r.Body)
	}
}

func TestServiceClientsAdminPage(t *testing.T) {
	a := adminLogin(t)
	if res, page := adminDo(t, "GET", "/admin/service-clients", a.cookie, nil, nil); res.StatusCode != 200 || !strings.Contains(page, "Service clients") {
		t.Fatalf("page: %d", res.StatusCode)
	}
	// Validation errors come back as a flash, nothing is created.
	before, _ := A.Clients.List(context.Background())
	res, _ := adminDo(t, "POST", "/admin/service-clients", a.cookie, url.Values{"_csrf": {a.csrf}, "name": {""}, "ttl": {"15"}}, nil)
	if !hasFlashError(res) {
		t.Fatal("empty name should be rejected")
	}
	res, _ = adminDo(t, "POST", "/admin/service-clients", a.cookie, url.Values{"_csrf": {a.csrf}, "name": {"x"}, "ttl": {"15"}, "scopes": {`bad"scope`}}, nil)
	if !hasFlashError(res) {
		t.Fatal("bad scope should be rejected")
	}
	after, _ := A.Clients.List(context.Background())
	if len(after) != len(before) {
		t.Fatal("invalid clients were created")
	}
	// CSRF is enforced.
	res, _ = adminDo(t, "POST", "/admin/service-clients", a.cookie, url.Values{"name": {"x"}, "ttl": {"15"}}, nil)
	if res.StatusCode == 303 && !hasFlashError(res) && strings.Contains(res.Header.Get("Location"), "reveal") {
		t.Fatal("created without CSRF token")
	}
}
