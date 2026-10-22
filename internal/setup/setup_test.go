package setup

import (
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatihacan1/warden/internal/config"
)

func newTestServer(t *testing.T, envFile string) *server {
	t.Helper()
	prev, order, err := config.ReadDotEnv(envFile)
	if err != nil {
		t.Fatal(err)
	}
	page := template.Must(template.New("").Funcs(template.FuncMap{
		"value": func(vals map[string]string, k string) string { return vals[k] },
		"isset": func(vals map[string]string, k string) bool { return vals[k] != "" },
	}).ParseFS(assets, "templates/*.html"))
	return &server{opt: Options{EnvFile: envFile}, token: "tok-123", page: page, previous: prev, order: order, done: make(chan struct{})}
}

func do(t *testing.T, h http.Handler, method, target string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	req.Host = "127.0.0.1:9095"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGuard(t *testing.T) {
	s := newTestServer(t, filepath.Join(t.TempDir(), ".env"))
	h := s.routes()
	if rec := do(t, h, "GET", "/", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/?token=wrong", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	rec := do(t, h, "GET", "/?token=tok-123", nil, nil)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Set-Cookie"), "HttpOnly") {
		t.Fatalf("token exchange: %d %v", rec.Code, rec.Header())
	}
	cookie := map[string]string{"Cookie": cookieName + "=tok-123"}
	if rec := do(t, h, "GET", "/", nil, cookie); rec.Code != 200 || !strings.Contains(rec.Body.String(), "ENCRYPTION_KEY") {
		t.Fatalf("form: %d", rec.Code)
	}
	// DNS rebinding: a foreign Host header is refused even with the cookie.
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "attacker.example.com"
	req.Header.Set("Cookie", cookieName+"=tok-123")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign host: %d", rec.Code)
	}
	// Cross-site posts are refused.
	hdr := map[string]string{"Cookie": cookieName + "=tok-123", "Origin": "https://evil.example.com"}
	if rec := do(t, h, "POST", "/generate/key", url.Values{}, hdr); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site post: %d", rec.Code)
	}
}

func TestReviewValidatesAndSaveKeepsOldKey(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	oldKey := generate("key")
	if err := os.WriteFile(envFile, []byte("ENCRYPTION_KEY="+oldKey+"\nCUSTOM_FLAG='keep me'\nAPP_ENV=development\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, envFile)
	h := s.routes()
	cookie := map[string]string{"Cookie": cookieName + "=tok-123"}

	form := url.Values{}
	for k, v := range s.defaults() {
		form.Set(k, v)
	}
	form.Set("S3_ENABLED", "on")
	form.Set("ADMIN_TOKEN", "short")
	if rec := do(t, h, "POST", "/review", form, cookie); !strings.Contains(rec.Body.String(), "ADMIN_TOKEN must be at least 32 characters") {
		t.Fatalf("invalid config not reported:\n%s", rec.Body.String())
	}

	newKey := generate("key")
	form.Set("ADMIN_TOKEN", generate("token"))
	form.Set("ENCRYPTION_KEY", newKey)
	form.Set("ENCRYPTION_ALGORITHM", "xchacha20-poly1305")
	form.Set("HTTP_CORS_ALLOWED_ORIGINS", "https://a.example.com,\n https://b.example.com")
	rec := do(t, h, "POST", "/review", form, cookie)
	if !strings.Contains(rec.Body.String(), "Write .env") {
		t.Fatalf("valid config not accepted:\n%s", rec.Body.String())
	}
	if rec := do(t, h, "POST", "/save", url.Values{}, cookie); rec.Code != 200 {
		t.Fatalf("save: %d", rec.Code)
	}

	vars, _, err := config.ReadDotEnv(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if vars["ENCRYPTION_KEY"] != newKey || vars["ENCRYPTION_PREVIOUS_KEYS"] != oldKey {
		t.Fatalf("key rotation not recorded: %v", vars)
	}
	if vars["CUSTOM_FLAG"] != "keep me" || vars["HTTP_CORS_ALLOWED_ORIGINS"] != "https://a.example.com,https://b.example.com" {
		t.Fatalf("values not preserved: %v", vars)
	}
	// The written file must load with the real validator.
	if _, err := config.LoadFrom(vars); err != nil {
		t.Fatalf("written .env does not load: %v", err)
	}
	backups, _ := filepath.Glob(envFile + ".bak-*")
	if len(backups) != 1 {
		t.Fatal("previous file not backed up")
	}
	if info, _ := os.Stat(envFile); info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf(".env is readable by others: %v", info.Mode())
	}
}

func TestQuoteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	vals := map[string]string{"A": "Warden <no-reply@example.com>", "B": "has # hash", "C": "plain", "D": "it's"}
	var b strings.Builder
	for k, v := range vals {
		b.WriteString(k + "=" + quote(v) + "\n")
	}
	p := filepath.Join(dir, "x.env")
	_ = os.WriteFile(p, []byte(b.String()), 0o600)
	got, _, err := config.ReadDotEnv(p)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range vals {
		if got[k] != v {
			t.Errorf("%s: wrote %q, read %q", k, v, got[k])
		}
	}
}

// Browsers turn Origin into "null" on form posts under Referrer-Policy:
// no-referrer, which would make every form submission fail the origin check.
func TestFormPostsKeepTheirOrigin(t *testing.T) {
	s := newTestServer(t, filepath.Join(t.TempDir(), ".env"))
	rec := do(t, s.routes(), "GET", "/", nil, map[string]string{"Cookie": cookieName + "=tok-123"})
	if p := rec.Header().Get("Referrer-Policy"); p == "no-referrer" || p == "" {
		t.Fatalf("Referrer-Policy %q breaks same-origin form posts", p)
	}
	hdr := map[string]string{"Cookie": cookieName + "=tok-123", "Origin": "http://127.0.0.1:9095"}
	if rec := do(t, s.routes(), "POST", "/generate/token", url.Values{}, hdr); rec.Code != 200 {
		t.Fatalf("same-origin post: %d", rec.Code)
	}
}
