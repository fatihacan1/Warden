//go:build integration

// Package e2e runs Warden in-process against real PostgreSQL, Redis and S3
// (the docker compose stack) and exercises it through its public interfaces.
//
//	docker compose up -d postgres redis garage garage-init
//	go test -tags integration ./test/e2e/ -count=1
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/fatihacan1/warden/internal/app"
	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/oauth"
)

var (
	A        *app.App
	grpcAddr string
	mails    = &mailbox{}
	relay    *events.Relay
	fakeIdP  = &fakeProvider{identities: map[string]*oauth.Identity{}}
)

const (
	adminToken = "e2e-admin-token-0123456789abcdef0123456789"
	grpcKey    = "e2e-grpc-key-0123456789abcdef0123456789abcd"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx := context.Background()
	adminURL := env("WARDEN_TEST_POSTGRES", "postgres://warden:warden@localhost:5432/postgres?sslmode=disable")
	dbName := "warden_e2e_" + hex.EncodeToString(randBytes(4))
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		fmt.Println("e2e: postgres unavailable, start docker compose first:", err)
		return 1
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		fmt.Println("e2e: create database:", err)
		return 1
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "DROP DATABASE "+dbName+" WITH (FORCE)")
		conn.Close(context.Background())
	}()
	u, _ := url.Parse(adminURL)
	u.Path = "/" + dbName

	redisURL := env("WARDEN_TEST_REDIS", "redis://localhost:6379/15")
	ro, _ := redis.ParseURL(redisURL)
	rc := redis.NewClient(ro)
	_ = rc.FlushDB(ctx).Err()
	_ = rc.Close()

	settings := map[string]string{
		"APP_ENV":                         "test",
		"LOG_LEVEL":                       "error",
		"ENCRYPTION_KEY":                  "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		"DATABASE_URL":                    u.String(),
		"REDIS_URL":                       redisURL,
		"HTTP_PUBLIC_URL":                 "http://warden.test",
		"HTTP_COOKIE_SECURE":              "false",
		"HTTP_TRUSTED_PROXIES":            "0.0.0.0/0,::/0", // lets each test pick its client IP via X-Forwarded-For
		"HTTP_CORS_ALLOWED_ORIGINS":       "https://app.example.com",
		"ADMIN_TOKEN":                     adminToken,
		"GRPC_ENABLED":                    "true",
		"GRPC_API_KEYS":                   grpcKey,
		"TOKEN_AUDIENCE":                  "e2e-api",
		"TOKEN_REFRESH_REUSE_GRACE":       "2s",
		"AUTH_ALLOWED_REDIRECT_URIS":      "https://app.example.com/callback,myapp://auth",
		"AUTH_LOCKOUT_THRESHOLD":          "5",
		"RATE_LIMIT_AUTH_PER_MINUTE":      "200",
		"RATE_LIMIT_GLOBAL_PER_MINUTE":    "5000",
		"PASSWORD_ARGON2_MEMORY_KIB":      "8192", // faster tests; still above the OWASP floor of 7 MiB
		"PASSWORD_ARGON2_ITERATIONS":      "1",
		"S3_ENABLED":                      env("WARDEN_TEST_S3", "true"),
		"S3_ENDPOINT":                     "http://localhost:3900",
		"S3_REGION":                       "garage",
		"S3_BUCKET":                       "warden",
		"S3_ACCESS_KEY_ID":                "GK31c2f218a2e44f485b94239e",
		"S3_SECRET_ACCESS_KEY":            "b892c0665f0ada8a4755dae98baa3b133590e11dae3bcc1f9d769d67f16c3835",
		"RABBITMQ_URL":                    "",
		"SMTP_HOST":                       "",
		"OAUTH_GOOGLE_ENABLED":            "false",
		"AUTH_REQUIRE_EMAIL_VERIFICATION": "false",
	}
	for k, v := range settings {
		os.Setenv(k, v)
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Println("e2e: config:", err)
		return 1
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	A, err = app.Build(ctx, cfg, log)
	if err != nil {
		fmt.Println("e2e: build:", err)
		return 1
	}
	defer A.Close()

	// A fake identity provider exercises the full browser OAuth flow.
	A.OAuth.Register(&oauth.Definition{Name: "fake", DisplayName: "Fake", Fields: []oauth.Field{{Key: "client_id", Required: true}},
		New: func(oauth.Settings, oauth.Deps) (oauth.Provider, error) { return fakeIdP, nil }})
	if err := A.OAuth.Save(ctx, "fake", true, map[string]string{"client_id": "x"}); err != nil {
		fmt.Println("e2e: register fake provider:", err)
		return 1
	}

	renderer, _ := mailer.NewRenderer(func() string { return "Warden" })
	relay = events.NewRelay(A.Store, nil, mails, renderer, A.Box, log, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println(err)
		return 1
	}
	grpcAddr = ln.Addr().String()
	go func() { _ = A.GRPC.ServeListener(ln) }()
	defer A.GRPC.Shutdown(ctx)

	return m.Run()
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randEmail() string { return "u" + hex.EncodeToString(randBytes(5)) + "@example.com" }

func randIP() string {
	b := randBytes(3)
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

// ---------------------------------------------------------------------------
// HTTP client over fiber's in-memory transport.

type client struct {
	t       *testing.T
	ip      string
	headers map[string]string
}

func newClient(t *testing.T) *client {
	return &client{t: t, ip: randIP(), headers: map[string]string{}}
}

type resp struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("invalid json (%d): %s", r.Status, r.Body)
	}
	return m
}

func (r resp) errCode(t *testing.T) string {
	t.Helper()
	e, _ := r.json(t)["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

func (c *client) do(method, path string, body any, auth string) resp {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://warden.test"+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	req.Header.Set("X-Forwarded-For", c.ip)
	req.Header.Set("User-Agent", "e2e-test")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	return c.raw(req)
}

func (c *client) raw(req *http.Request) resp {
	c.t.Helper()
	res, err := A.HTTP.App().Test(req, fiberTestConfig)
	if err != nil {
		c.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{Status: res.StatusCode, Header: res.Header, Body: b}
}

type tokens struct {
	Access, Refresh, UserID string
}

func (c *client) signUp(email, password string) tokens {
	c.t.Helper()
	r := c.do("POST", "/v1/auth/signup", map[string]string{"email": email, "password": password, "name": "Test User"}, "")
	if r.Status != 201 {
		c.t.Fatalf("signup: %d %s", r.Status, r.Body)
	}
	return parseTokens(c.t, r)
}

func parseTokens(t *testing.T, r resp) tokens {
	t.Helper()
	m := r.json(t)
	tk, ok := m["tokens"].(map[string]any)
	if !ok {
		t.Fatalf("no tokens in response: %s", r.Body)
	}
	user, _ := m["user"].(map[string]any)
	rt, _ := tk["refresh_token"].(string)
	return tokens{Access: tk["access_token"].(string), Refresh: rt, UserID: user["id"].(string)}
}

// ---------------------------------------------------------------------------
// Mail capture.

type mailbox struct {
	mu   sync.Mutex
	msgs []mailer.Message
}

func (m *mailbox) Send(_ context.Context, msg mailer.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, msg)
	return nil
}

// tokenFor drains the outbox and returns the token from the latest email to
// "to" whose link contains marker.
func tokenFor(t *testing.T, to, marker string) string {
	t.Helper()
	for range 20 {
		relay.Tick(context.Background())
		mails.mu.Lock()
		for i := len(mails.msgs) - 1; i >= 0; i-- {
			m := mails.msgs[i]
			if m.To != to || !strings.Contains(m.Text, marker) {
				continue
			}
			i := strings.Index(m.Text, "token=")
			tok := m.Text[i+len("token="):]
			if j := strings.IndexAny(tok, " \n\r"); j >= 0 {
				tok = tok[:j]
			}
			mails.mu.Unlock()
			tok, _ = url.QueryUnescape(tok)
			return tok
		}
		mails.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no %q email for %s", marker, to)
	return ""
}

// ---------------------------------------------------------------------------
// Fake OAuth provider.

type fakeProvider struct {
	mu         sync.Mutex
	identities map[string]*oauth.Identity // code -> identity
}

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) AuthURL(state, nonce, verifier string) string {
	return "https://idp.example.com/authorize?state=" + url.QueryEscape(state)
}

func (f *fakeProvider) Exchange(_ context.Context, code, _, _ string, _ url.Values) (*oauth.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.identities[code]
	if !ok {
		return nil, fmt.Errorf("bad code")
	}
	return id, nil
}

func (f *fakeProvider) set(code string, id *oauth.Identity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identities[code] = id
}
