//go:build integration

package e2e

import (
	"context"
	"testing"

	"github.com/fatihacan1/warden/internal/oauth"
)

func TestWorkEmailSignup(t *testing.T) {
	ctx := context.Background()
	original := *A.Settings.Get()
	defer func() {
		if err := A.Settings.Save(ctx, original); err != nil {
			t.Error(err)
		}
	}()
	set := func(enabled bool, allowed []string) {
		r := original
		r.AllowSignup = true
		r.RequireWorkEmail = enabled
		r.WorkEmailAllowed = allowed
		if err := A.Settings.Save(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	c := newClient(t)
	email := "u" + randIP() + "@gmail.com"
	signup := func(email string) resp {
		return c.do("POST", "/v1/auth/signup", map[string]string{"email": email, "password": pw}, "")
	}
	set(false, nil)
	if r := signup(email); r.Status != 201 {
		t.Fatalf("disabled: %d %s", r.Status, r.Body)
	}
	set(true, nil)
	if r := signup("new" + randIP() + "@gmail.com"); r.Status != 422 || r.errCode(t) != "work_email_required" {
		t.Fatalf("blocked: %d %s", r.Status, r.Body)
	}
	if r := signup(randEmail()); r.Status != 201 {
		t.Fatalf("company: %d %s", r.Status, r.Body)
	}
	if r := c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, ""); r.Status != 200 {
		t.Fatalf("existing login: %d %s", r.Status, r.Body)
	}
	if got := c.do("GET", "/v1/auth/providers", nil, "").json(t)["require_work_email"]; got != true {
		t.Fatalf("public setting: %v", got)
	}
	_, challenge := pkcePair()
	back := oauthLogin(t, c, &oauth.Identity{Provider: "fake", Subject: "work-" + randIP(), Email: "social" + randIP() + "@gmail.com", EmailVerified: true}, "myapp://auth", challenge)
	if back.Query().Get("error") != "work_email_required" {
		t.Fatalf("social signup: %s", back)
	}
	set(true, []string{"gmail.com"})
	if r := signup("allowed" + randIP() + "@gmail.com"); r.Status != 201 {
		t.Fatalf("allowed: %d %s", r.Status, r.Body)
	}
}
