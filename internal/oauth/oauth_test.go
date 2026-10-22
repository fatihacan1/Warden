package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/store"
)

// ---------------------------------------------------------------------------
// ID token verification against a fake JWKS endpoint.

type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, kid: "test-kid"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		b64 := base64.RawURLEncoding
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": f.kid, "alg": "RS256", "use": "sig",
			"n": b64.EncodeToString(key.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func baseClaims(nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": "https://accounts.google.com", "aud": "web-client", "sub": "1234",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"email": "u@example.com", "email_verified": true, "nonce": nonce,
	}
}

func TestIDTokenVerifier(t *testing.T) {
	idp := newFakeIdP(t)
	v := newIDTokenVerifier(idp.srv.URL, googleIssuers, []string{"web-client", "ios-client"}, idp.srv.Client())
	ctx := context.Background()

	// Valid token.
	_, c, err := v.verify(ctx, idp.sign(t, baseClaims("n1")), "n1", true)
	if err != nil || c.Email != "u@example.com" || !truthy(c.EmailVerified) {
		t.Fatalf("valid token rejected: %v", err)
	}

	// Second issuer spelling and native audience.
	cl := baseClaims("n1")
	cl["iss"], cl["aud"] = "accounts.google.com", "ios-client"
	if _, _, err := v.verify(ctx, idp.sign(t, cl), "n1", true); err != nil {
		t.Fatalf("alternate issuer/native audience rejected: %v", err)
	}

	// Apple style hashed nonce.
	sum := sha256.Sum256([]byte("raw-nonce"))
	if _, _, err := v.verify(ctx, idp.sign(t, baseClaims(hex.EncodeToString(sum[:]))), "raw-nonce", true); err != nil {
		t.Fatalf("hashed nonce rejected: %v", err)
	}

	bad := map[string]func(jwt.MapClaims){
		"wrong audience": func(c jwt.MapClaims) { c["aud"] = "someone-else" },
		"wrong issuer":   func(c jwt.MapClaims) { c["iss"] = "https://evil.example.com" },
		"expired":        func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"wrong nonce":    func(c jwt.MapClaims) { c["nonce"] = "other" },
		"missing nonce":  func(c jwt.MapClaims) { delete(c, "nonce") },
	}
	for name, mutate := range bad {
		cl := baseClaims("n1")
		mutate(cl)
		if _, _, err := v.verify(ctx, idp.sign(t, cl), "n1", true); !errors.Is(err, ErrInvalidIDToken) {
			t.Errorf("%s: expected ErrInvalidIDToken, got %v", name, err)
		}
	}

	// Token signed by a different key.
	other := newFakeIdP(t)
	if _, _, err := v.verify(ctx, other.sign(t, baseClaims("n1")), "n1", true); err == nil {
		t.Error("token from foreign key accepted")
	}
}

// ---------------------------------------------------------------------------
// Code exchange flows against a fake OAuth server.

func fakeOAuthServer(t *testing.T, routes map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/token" {
			_ = r.ParseForm()
			if r.Form.Get("code") != "good-code" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
		} else if r.Header.Get("Authorization") != "Bearer at-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGitHubUsesOnlyPrimaryVerifiedEmail(t *testing.T) {
	srv := fakeOAuthServer(t, map[string]any{
		"/token": map[string]any{"access_token": "at-123", "token_type": "bearer"},
		"/user":  map[string]any{"id": 42, "login": "octo", "name": ""},
		"/user/emails": []map[string]any{
			{"email": "unverified@example.com", "primary": false, "verified": false},
			{"email": "primary@example.com", "primary": true, "verified": true},
		},
	})
	p, err := newGitHub(Settings{Values: map[string]string{KeyClientID: "id", KeyClientSecret: "secret"}}, Deps{CallbackURL: "https://cb", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	gh := p.(*github)
	gh.conf.Endpoint = oauth2.Endpoint{AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}
	gh.apiBase = srv.URL

	id, err := gh.Exchange(context.Background(), "good-code", strings.Repeat("v", 43), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "42" || id.Email != "primary@example.com" || !id.EmailVerified || id.Name != "octo" {
		t.Fatalf("unexpected identity %+v", id)
	}
	if _, err := gh.Exchange(context.Background(), "bad-code", strings.Repeat("v", 43), "", nil); err == nil {
		t.Fatal("invalid code accepted")
	}
}

func TestDiscordUnverifiedEmailIsNotTrusted(t *testing.T) {
	srv := fakeOAuthServer(t, map[string]any{
		"/token":     map[string]any{"access_token": "at-123", "token_type": "bearer"},
		"/users/@me": map[string]any{"id": "99", "username": "gamer", "email": "g@example.com", "verified": false, "avatar": "abc"},
	})
	p, _ := newDiscord(Settings{Values: map[string]string{KeyClientID: "id", KeyClientSecret: "secret"}}, Deps{HTTPClient: srv.Client()})
	d := p.(*discord)
	d.conf.Endpoint = oauth2.Endpoint{TokenURL: srv.URL + "/token", AuthStyle: oauth2.AuthStyleInHeader}
	d.apiBase = srv.URL
	id, err := d.Exchange(context.Background(), "good-code", strings.Repeat("v", 43), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if id.EmailVerified {
		t.Fatal("unverified Discord email must not be marked verified")
	}
	if id.AvatarURL != "https://cdn.discordapp.com/avatars/99/abc.png" {
		t.Fatalf("avatar %q", id.AvatarURL)
	}
}

func testP8(t *testing.T) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestAppleClientSecret(t *testing.T) {
	p8 := testP8(t)
	p, err := newApple(Settings{Values: map[string]string{
		KeyClientID: "com.example.web", KeyTeamID: "TEAM123", KeyKeyID: "KEY123",
		KeyPrivateKey: strings.ReplaceAll(p8, "\n", `\n`), // escaped form from env files
	}}, Deps{CallbackURL: "https://auth.example.com/v1/oauth/apple/callback", HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	a := p.(*apple)
	secret, err := a.clientSecret()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Parse(secret, func(*jwt.Token) (any, error) { return &a.key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(appleIssuer), jwt.WithIssuer("TEAM123"))
	if err != nil {
		t.Fatal(err)
	}
	if tok.Header["kid"] != "KEY123" {
		t.Fatal("kid header missing")
	}
	if sub, _ := tok.Claims.GetSubject(); sub != "com.example.web" {
		t.Fatalf("sub %q", sub)
	}
	u, _ := url.Parse(a.AuthURL("st", "nn", ""))
	if u.Query().Get("response_mode") != "form_post" || u.Query().Get("nonce") != "nn" {
		t.Fatalf("auth url %s", u)
	}
	if _, err := newApple(Settings{Values: map[string]string{KeyClientID: "a", KeyTeamID: "b", KeyKeyID: "c", KeyPrivateKey: "garbage"}}, Deps{}); err == nil {
		t.Fatal("invalid key accepted")
	}
}

// ---------------------------------------------------------------------------
// Registry: env + admin overrides, secrets preserved, validation.

type memSettings struct {
	mu   sync.Mutex
	rows map[string]store.ProviderSettingRow
}

func (m *memSettings) ListProviderSettings(context.Context) ([]store.ProviderSettingRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.ProviderSettingRow
	for _, r := range m.rows {
		out = append(out, r)
	}
	return out, nil
}

func (m *memSettings) UpsertProviderSetting(_ context.Context, r store.ProviderSettingRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[r.Provider] = r
	return nil
}

func (m *memSettings) DeleteProviderSetting(_ context.Context, p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, p)
	return nil
}

func TestRegistry(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, _ := secretbox.New(key)
	st := &memSettings{rows: map[string]store.ProviderSettingRow{}}
	cfg := config.OAuthConfig{GitHub: config.ProviderEnv{Enabled: true, ClientID: "env-id", ClientSecret: "env-secret"}}
	r := NewRegistry(cfg, "https://auth.example.com", st, box, http.DefaultClient, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	if err := r.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("github"); !ok {
		t.Fatal("env-enabled provider missing")
	}
	if _, ok := r.Get("google"); ok {
		t.Fatal("disabled provider present")
	}

	// Enabling without required fields fails validation.
	if err := r.Save(ctx, "discord", true, map[string]string{KeyClientID: "x"}); err == nil {
		t.Fatal("expected validation error")
	}
	// Valid save enables it.
	if err := r.Save(ctx, "discord", true, map[string]string{KeyClientID: "d-id", KeyClientSecret: "d-secret"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("discord"); !ok {
		t.Fatal("discord should be active")
	}
	// Saving again with an empty secret keeps the stored secret.
	if err := r.Save(ctx, "discord", true, map[string]string{KeyClientID: "d-id-2", KeyClientSecret: ""}); err != nil {
		t.Fatal(err)
	}
	for _, s := range r.Statuses() {
		if s.Def.Name == "discord" {
			if s.Values[KeyClientID] != "d-id-2" || !s.SecretSet[KeyClientSecret] || s.Source != SourceAdmin {
				t.Fatalf("unexpected status %+v", s)
			}
			if _, leaked := s.Values[KeyClientSecret]; leaked {
				t.Fatal("secret value exposed in status")
			}
		}
	}
	// Stored config is encrypted.
	if strings.Contains(string(st.rows["discord"].Config), "d-secret") {
		t.Fatal("provider secret stored in plaintext")
	}
	// Admin override can disable an env-enabled provider; reset restores it.
	if err := r.Save(ctx, "github", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("github"); ok {
		t.Fatal("github should be disabled by admin override")
	}
	if err := r.Reset(ctx, "github"); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("github"); !ok {
		t.Fatal("github should fall back to env settings")
	}
}

// ---------------------------------------------------------------------------
// Flow storage and helpers.

func TestFlowSingleUse(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	f := NewFlow(rdb)
	ctx := context.Background()

	key, err := f.SaveState(ctx, State{Provider: "google", RedirectURI: "myapp://cb"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.TakeState(ctx, key)
	if err != nil || st.Provider != "google" {
		t.Fatalf("take state: %v", err)
	}
	if _, err := f.TakeState(ctx, key); !errors.Is(err, ErrFlowNotFound) {
		t.Fatal("state must be single use")
	}

	code, _ := f.SaveCode(ctx, LoginCode{UserID: "u1"})
	mr.FastForward(61 * time.Second)
	if _, err := f.TakeCode(ctx, code); !errors.Is(err, ErrFlowNotFound) {
		t.Fatal("login code must expire after 60s")
	}
	code, _ = f.SaveCode(ctx, LoginCode{UserID: "u1"})
	if _, err := f.TakeCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	if _, err := f.TakeCode(ctx, code); !errors.Is(err, ErrFlowNotFound) {
		t.Fatal("login code must be single use")
	}

	ok, _ := f.UseNonce(ctx, "apple", "n", time.Minute)
	again, _ := f.UseNonce(ctx, "apple", "n", time.Minute)
	if !ok || again {
		t.Fatal("nonce replay not detected")
	}
}

func TestPKCE(t *testing.T) {
	// RFC 7636 Appendix B test vector.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !VerifyPKCE(verifier, challenge) {
		t.Fatal("RFC 7636 vector failed")
	}
	if VerifyPKCE("short", challenge) || VerifyPKCE(verifier, "wrong") || VerifyPKCE(verifier+"x", challenge) {
		t.Fatal("invalid PKCE accepted")
	}
}

func TestRedirectAllowed(t *testing.T) {
	allowed := []string{"https://app.example.com/auth/callback", "myapp://auth"}
	ok := []string{"https://app.example.com/auth/callback", "myapp://auth"}
	bad := []string{
		"", "https://app.example.com/auth/callback/../evil", "https://app.example.com/auth/callback?x=1",
		"https://app.example.com.evil.com/auth/callback", "https://user@app.example.com/auth/callback",
		"https://app.example.com/auth/callback#frag", "myapp://auth.evil", "javascript:alert(1)",
	}
	for _, u := range ok {
		if !RedirectAllowed(allowed, u) {
			t.Errorf("%q should be allowed", u)
		}
	}
	for _, u := range bad {
		if RedirectAllowed(allowed, u) {
			t.Errorf("%q must be rejected", u)
		}
	}
}

func TestAppendQuery(t *testing.T) {
	got := AppendQuery("myapp://auth?x=1", map[string]string{"code": "a b", "state": ""})
	if got != "myapp://auth?code=a+b&x=1" {
		t.Fatalf("got %q", got)
	}
}
