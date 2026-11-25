//go:build integration

package e2e

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/fatihacan1/warden/internal/oauth"
	"github.com/fatihacan1/warden/internal/settings"
)

func withSettings(t *testing.T, change func(*settings.Runtime)) {
	t.Helper()
	ctx := context.Background()
	original := *A.Settings.Get()
	t.Cleanup(func() {
		if err := A.Settings.Save(ctx, original); err != nil {
			t.Error(err)
		}
	})
	r := original
	change(&r)
	if err := A.Settings.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
}

func TestKnownEmailPolicy(t *testing.T) {
	c := newClient(t)
	signup := func(email string) resp {
		return c.do("POST", "/v1/auth/signup", map[string]string{"email": email, "password": pw}, "")
	}
	before := randEmail() // example.com, opened while anything goes
	if r := signup(before); r.Status != 201 {
		t.Fatalf("open: %d %s", r.Status, r.Body)
	}
	withSettings(t, func(r *settings.Runtime) {
		r.EmailPolicy = settings.EmailPolicyKnown
		r.EmailAllowSchools = true
		r.EmailAllowedDomains = []string{"partner.test"}
	})
	for email, want := range map[string]int{
		"k" + randIP() + "@gmail.com":           201,
		"k" + randIP() + "@outlook.com.tr":      201,
		"k" + randIP() + "@itu.edu.tr":          201,
		"k" + randIP() + "@mail.partner.test":   201,
		"k" + randIP() + "@mailinator.com":      422,
		"k" + randIP() + "@x.mailinator.com":    422,
		"k" + randIP() + "@something.xyz":       422,
		"k" + randIP() + "@gmail.com.evil.test": 422,
		randEmail():                             422,
	} {
		r := signup(email)
		if r.Status != want {
			t.Errorf("%s: %d %s", email, r.Status, r.Body)
		}
		if r.Status == 422 && r.errCode(t) != "email_not_accepted" {
			t.Errorf("%s: %s", email, r.Body)
		}
	}
	if r := c.do("POST", "/v1/auth/signin", map[string]string{"email": before, "password": pw}, ""); r.Status != 200 {
		t.Fatalf("existing users must keep signing in: %d %s", r.Status, r.Body)
	}
	if got := c.do("GET", "/v1/auth/providers", nil, "").json(t)["email_policy"]; got != "known" {
		t.Fatalf("public setting: %v", got)
	}
	_, challenge := pkcePair()
	back := oauthLogin(t, c, &oauth.Identity{Provider: "fake", Subject: "pol-" + randIP(), Email: "s" + randIP() + "@mailinator.com", EmailVerified: true}, "myapp://auth", challenge)
	if back.Query().Get("error") != "email_not_accepted" {
		t.Fatalf("social sign-up: %s", back)
	}
}

func TestContradictingSettingsAreRefused(t *testing.T) {
	for name, change := range map[string]func(*settings.Runtime){
		"known and work":      func(r *settings.Runtime) { r.EmailPolicy = "known"; r.RequireWorkEmail = true },
		"unknown policy":      func(r *settings.Runtime) { r.EmailPolicy = "some" },
		"hide without verify": func(r *settings.Runtime) { r.HideExistingAccounts = true; r.RequireEmailVerification = false },
	} {
		r := *A.Settings.Get()
		change(&r)
		if err := A.Settings.Save(context.Background(), r); err == nil {
			t.Error(name, "was saved")
		}
	}
}

func TestExistingAccountsAreHidden(t *testing.T) {
	c := newClient(t)
	taken := randEmail()
	if r := c.do("POST", "/v1/auth/signup", map[string]string{"email": taken, "password": pw, "name": "Owner"}, ""); r.Status != 201 {
		t.Fatal(r.Status, string(r.Body))
	}
	if r := c.do("POST", "/v1/auth/signup", map[string]string{"email": taken, "password": pw}, ""); r.Status != 409 {
		t.Fatalf("off by default: %d", r.Status)
	}
	withSettings(t, func(r *settings.Runtime) { r.RequireEmailVerification = true; r.HideExistingAccounts = true })

	other := "another correct horse battery"
	fresh := c.do("POST", "/v1/auth/signup", map[string]string{"email": randEmail(), "password": other, "name": "Same"}, "")
	again := c.do("POST", "/v1/auth/signup", map[string]string{"email": strings.ToUpper(taken), "password": other, "name": "Same"}, "")
	if fresh.Status != 201 || again.Status != fresh.Status {
		t.Fatalf("status: %d %d %s", fresh.Status, again.Status, again.Body)
	}
	a, b := fresh.json(t), again.json(t)
	if keys(a) != keys(b) || a["status"] != b["status"] || a["status"] != "verification_required" {
		t.Fatalf("answers differ:\n%s\n%s", fresh.Body, again.Body)
	}
	ua, ub := a["user"].(map[string]any), b["user"].(map[string]any)
	if keys(ua) != keys(ub) || b["tokens"] != nil {
		t.Fatalf("users differ:\n%s\n%s", fresh.Body, again.Body)
	}
	for _, k := range []string{"name", "email_verified", "roles", "locale", "mfa_enabled", "has_password", "avatar_url", "last_sign_in_at"} {
		if !reflect.DeepEqual(ua[k], ub[k]) {
			t.Errorf("%s differs: %v %v", k, ua[k], ub[k])
		}
	}

	// the password the stranger chose opens nothing, the owner's still does after confirming through the mail
	if r := c.do("POST", "/v1/auth/signin", map[string]string{"email": taken, "password": other}, ""); r.Status != 401 {
		t.Fatalf("stranger's password: %d %s", r.Status, r.Body)
	}
	tok := tokenFor(t, taken, "reset-password")
	const chosen = "owner chooses a new one 77"
	if r := c.do("POST", "/v1/auth/password/reset", map[string]string{"token": tok, "password": chosen}, ""); r.Status >= 300 {
		t.Fatalf("link in the notice: %d %s", r.Status, r.Body)
	}
	if r := c.do("POST", "/v1/auth/signin", map[string]string{"email": taken, "password": chosen}, ""); r.Status != 200 {
		t.Fatalf("owner: %d %s", r.Status, r.Body)
	}
	if r := c.do("POST", "/v1/auth/signin", map[string]string{"email": taken, "password": pw}, ""); r.Status != 401 {
		t.Fatalf("the password of whoever registered first must be gone: %d", r.Status)
	}
}

func keys(m map[string]any) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return strings.Join(out, ",")
}
