//go:build integration

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/settings"
)

// inbox drains the outbox and returns every message sent to addr so far.
func inbox(addr string) []mailer.Message {
	for range 5 {
		if relay.Tick(context.Background()) == 0 {
			break
		}
	}
	mails.mu.Lock()
	defer mails.mu.Unlock()
	var out []mailer.Message
	for _, m := range mails.msgs {
		if m.To == addr {
			out = append(out, m)
		}
	}
	return out
}

func countSubject(msgs []mailer.Message, part string) int {
	n := 0
	for _, m := range msgs {
		if strings.Contains(m.Subject, part) {
			n++
		}
	}
	return n
}

func TestUserLanguage(t *testing.T) {
	c := newClient(t)
	c.headers["Accept-Language"] = "tr-TR,tr;q=0.9,en;q=0.8"
	email := randEmail()
	tk := c.signUp(email, pw)
	if me := c.do("GET", "/v1/me", nil, tk.Access).json(t); me["locale"] != "tr" {
		t.Fatalf("locale from Accept-Language: %v", me["locale"])
	}
	if n := countSubject(inbox(email), "E-posta adresinizi doğrulayın"); n != 1 {
		t.Fatalf("verification email not in Turkish: %+v", inbox(email))
	}

	if r := c.do("PATCH", "/v1/me", map[string]string{"locale": "en-US"}, tk.Access); r.json(t)["locale"] != "en" {
		t.Fatalf("set locale: %s", r.Body)
	}
	c.do("POST", "/v1/me/email/resend", nil, tk.Access)
	if n := countSubject(inbox(email), "Verify your email address"); n != 1 {
		t.Fatal("email after switching to English is not in English")
	}
	if r := c.do("PATCH", "/v1/me", map[string]string{"locale": "klingon"}, tk.Access); r.Status != 422 {
		t.Fatalf("unsupported locale accepted: %d", r.Status)
	}
	// Explicit locale on sign-up wins over the browser.
	c2 := newClient(t)
	c2.headers["Accept-Language"] = "tr"
	r := c2.do("POST", "/v1/auth/signup", map[string]string{"email": randEmail(), "password": pw, "locale": "en"}, "")
	if u, _ := r.json(t)["user"].(map[string]any); u["locale"] != "en" {
		t.Fatalf("explicit locale ignored: %s", r.Body)
	}
}

func TestNewDeviceNotice(t *testing.T) {
	email := randEmail()
	first := newClient(t)
	first.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
	first.signUp(email, pw)
	signIn := func(c *client) tokens {
		t.Helper()
		return parseTokens(t, c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, ""))
	}
	signIn(first) // same device again
	if n := countSubject(inbox(email), "New sign-in"); n != 0 {
		t.Fatalf("known device triggered %d notices", n)
	}

	phone := newClient(t)
	phone.headers["User-Agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
	phoneTokens := signIn(phone)
	msgs := inbox(email)
	if n := countSubject(msgs, "New sign-in from Safari on iOS"); n != 1 {
		t.Fatalf("new device notices: %d", countSubject(msgs, "New sign-in"))
	}
	signIn(phone) // a second sign-in from the same phone is not new
	if n := countSubject(inbox(email), "New sign-in"); n != 1 {
		t.Fatalf("repeat sign-in notified again: %d", n)
	}

	var text string
	for _, m := range msgs {
		if strings.Contains(m.Subject, "New sign-in") {
			text = m.Text
		}
	}
	i := strings.Index(text, "/v1/auth/sessions/end?token=")
	if i < 0 || !strings.Contains(text, phone.ip) {
		t.Fatalf("notice lacks the sign-out link or IP:\n%s", text)
	}
	tok := strings.Fields(text[i+len("/v1/auth/sessions/end?token="):])[0]

	// Opening the link (or a mail scanner doing it) changes nothing.
	page := first.do("GET", "/v1/auth/sessions/end?token="+url.QueryEscape(tok), nil, "")
	if page.Status != 200 || !strings.Contains(string(page.Body), "<form") {
		t.Fatalf("confirmation page: %d", page.Status)
	}
	if first.do("GET", "/v1/me", nil, phoneTokens.Access).Status != 200 {
		t.Fatal("GET on the link revoked the session")
	}
	confirm := func() resp {
		req, _ := http.NewRequest("POST", "http://warden.test/v1/auth/sessions/end", strings.NewReader(url.Values{"token": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return first.raw(req)
	}
	if r := confirm(); r.Status != 200 {
		t.Fatalf("confirm: %d %s", r.Status, r.Body)
	}
	if first.do("GET", "/v1/me", nil, phoneTokens.Access).Status != 401 {
		t.Fatal("reported session still active")
	}
	if r := confirm(); r.Status != 400 {
		t.Fatalf("link reusable: %d", r.Status)
	}
}

func TestAccountLockedNotice(t *testing.T) {
	email := randEmail()
	c := newClient(t)
	c.signUp(email, pw)
	for range 7 {
		c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": "wrong password!"}, "")
	}
	if n := countSubject(inbox(email), "Sign-in paused"); n != 1 {
		t.Fatalf("lockout notices: %d (want exactly 1)", n)
	}
}

func TestAdminIPAllowlist(t *testing.T) {
	a := adminLogin(t)
	defer A.Settings.Reset(context.Background())
	cur := A.Settings.Get()
	form := url.Values{
		"_csrf": {a.csrf}, "allow_signup": {"on"}, "password_min_length": {"8"}, "lockout_threshold": {"5"}, "app_name": {"Warden"},
		"verify_email_url": {cur.VerifyEmailURL}, "reset_password_url": {cur.ResetPasswordURL}, "default_locale": {"en"},
		"allowed_redirect_uris": {strings.Join(cur.AllowedRedirectURIs, "\n")}, "cors_origins": {strings.Join(cur.CORSOrigins, "\n")},
		"admin_ip_allowlist": {"on"}, "admin_allowed_ips": {"198.51.100.0/24"},
	}
	res, _ := adminDo(t, "POST", "/admin/settings", a.cookie, form, nil)
	if hasFlashError(res) || !strings.Contains(res.Header.Get("Location"), "settingsip") {
		t.Fatalf("enabling the allowlist: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if r, _ := adminDo(t, "GET", "/admin", a.cookie, nil, nil); r.StatusCode != 200 {
		t.Fatalf("admin locked out after enabling the allowlist: %d", r.StatusCode)
	}
	if len(A.Settings.Get().AdminAllowedIPs) != 2 {
		t.Fatalf("current address not added: %v", A.Settings.Get().AdminAllowedIPs)
	}

	// Someone else's list: this address is refused, metrics stay reachable.
	rt := *A.Settings.Get()
	rt.AdminAllowedIPs = []string{"198.51.100.0/24"}
	if err := A.Settings.Save(context.Background(), settings.Runtime(rt)); err != nil {
		t.Fatal(err)
	}
	if r, body := adminDo(t, "GET", "/admin/login", "", nil, nil); r.StatusCode != 403 || !strings.Contains(body, "ADMIN_IP_ALLOWLIST_DISABLED") {
		t.Fatalf("outside address: %d", r.StatusCode)
	}
	if r, _ := adminDo(t, "GET", "/metrics", "", nil, nil); r.StatusCode != 200 {
		t.Fatal("metrics blocked by the admin allowlist")
	}
}

func TestUsersPagination(t *testing.T) {
	a := adminLogin(t)
	tag := "pg" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	for i := range 55 {
		u := &domain.User{ID: uuid.Must(uuid.NewV7()), Email: fmt.Sprintf("%s-%02d@example.com", tag, i), Roles: []string{}}
		if err := A.Store.CreateUser(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	_, p1 := adminDo(t, "GET", "/admin/users?q="+tag, a.cookie, nil, nil)
	_, p2 := adminDo(t, "GET", "/admin/users?q="+tag+"&page=2", a.cookie, nil, nil)
	if strings.Count(p1, tag+"-") != 50 || strings.Count(p2, tag+"-") != 5 {
		t.Fatalf("page sizes: %d and %d", strings.Count(p1, tag+"-"), strings.Count(p2, tag+"-"))
	}
	if !strings.Contains(p2, "51–55") || !strings.Contains(p1, `aria-current="page"`) {
		t.Fatal("pager labels missing")
	}
	if r, _ := adminDo(t, "GET", "/admin/users?q="+tag+"&page=99", a.cookie, nil, nil); r.StatusCode != 303 && r.StatusCode != 302 ||
		!strings.Contains(r.Header.Get("Location"), "page=2") {
		t.Fatalf("out of range page: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	_ = time.Second
}
