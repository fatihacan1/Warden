//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/fatihacan1/warden/internal/oauth"
	wardenv1 "github.com/fatihacan1/warden/pkg/api/wardenv1"
)

var fiberTestConfig = fiber.TestConfig{Timeout: 20 * time.Second, FailOnTimeout: true}

const pw = "correct horse battery staple"

func TestPasswordLifecycle(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	tk := c.signUp(email, pw)

	me := c.do("GET", "/v1/me", nil, tk.Access)
	if me.Status != 200 || me.json(t)["email"] != email {
		t.Fatalf("me: %d %s", me.Status, me.Body)
	}

	// Sign-in normalizes email case and whitespace.
	r := c.do("POST", "/v1/auth/signin", map[string]string{"email": "  " + strings.ToUpper(email) + " ", "password": pw}, "")
	if r.Status != 200 {
		t.Fatalf("signin: %d %s", r.Status, r.Body)
	}

	// Profile update.
	r = c.do("PATCH", "/v1/me", map[string]string{"name": "  New Name  "}, tk.Access)
	if r.Status != 200 || r.json(t)["name"] != "New Name" {
		t.Fatalf("update: %d %s", r.Status, r.Body)
	}

	// Change password signs out other sessions but keeps the current one.
	other := parseTokens(t, c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, ""))
	r = c.do("POST", "/v1/me/password", map[string]string{"current_password": "wrong password!!", "new_password": "another strong passphrase"}, tk.Access)
	if r.Status != 401 {
		t.Fatalf("wrong current password accepted: %d", r.Status)
	}
	r = c.do("POST", "/v1/me/password", map[string]string{"current_password": pw, "new_password": "another strong passphrase"}, tk.Access)
	if r.Status != 204 {
		t.Fatalf("change password: %d %s", r.Status, r.Body)
	}
	if c.do("GET", "/v1/me", nil, other.Access).Status != 401 {
		t.Fatal("other session's access token must be revoked after password change")
	}
	if c.do("GET", "/v1/me", nil, tk.Access).Status != 200 {
		t.Fatal("current session must survive password change")
	}
	if c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, "").Status != 401 {
		t.Fatal("old password still works")
	}

	// Sign out revokes the session.
	if r := c.do("POST", "/v1/auth/signout", map[string]string{"refresh_token": tk.Refresh}, ""); r.Status != 204 {
		t.Fatalf("signout: %d", r.Status)
	}
	if c.do("GET", "/v1/me", nil, tk.Access).Status != 401 {
		t.Fatal("access token valid after sign out")
	}
	if r := c.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": tk.Refresh}, ""); r.Status != 401 {
		t.Fatal("refresh token valid after sign out")
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	c := newClient(t)
	tk := c.signUp(randEmail(), pw)

	r1 := c.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": tk.Refresh}, "")
	if r1.Status != 200 {
		t.Fatalf("refresh: %d %s", r1.Status, r1.Body)
	}
	t1 := parseTokens(t, r1)
	if t1.Refresh == tk.Refresh {
		t.Fatal("refresh token was not rotated")
	}

	// A retry with the previous token inside the grace window succeeds once
	// (lost response) ...
	r2 := c.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": tk.Refresh}, "")
	if r2.Status != 200 {
		t.Fatalf("grace retry: %d %s", r2.Status, r2.Body)
	}
	t2 := parseTokens(t, r2)

	// ... but replaying it after the window is treated as theft: the whole
	// session is revoked, including the newest tokens.
	time.Sleep(2500 * time.Millisecond)
	if r := c.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": tk.Refresh}, ""); r.Status != 401 {
		t.Fatalf("reuse after grace accepted: %d", r.Status)
	}
	if r := c.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": t2.Refresh}, ""); r.Status != 401 {
		t.Fatal("token family must be revoked after reuse")
	}
	if c.do("GET", "/v1/me", nil, t2.Access).Status != 401 {
		t.Fatal("access token of a revoked session must be rejected")
	}
}

func TestConcurrentRefreshNeverForks(t *testing.T) {
	c := newClient(t)
	tk := c.signUp(randEmail(), pw)
	var wg sync.WaitGroup
	results := make(chan int, 10)
	for range 10 {
		wg.Go(func() {
			results <- c.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": tk.Refresh}, "").Status
		})
	}
	wg.Wait()
	close(results)
	ok := 0
	for s := range results {
		if s == 200 {
			ok++
		} else if s != 401 {
			t.Fatalf("unexpected status %d", s)
		}
	}
	if ok == 0 {
		t.Fatal("no concurrent refresh succeeded")
	}
	var active int
	_ = A.Pool.QueryRow(context.Background(), `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, tk.UserID).Scan(&active)
	if active != 1 {
		t.Fatalf("concurrent refreshes must not create extra sessions, active=%d", active)
	}
}

func TestNoAccountEnumeration(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	c.signUp(email, pw)

	wrongPw := c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": "not the password"}, "")
	unknown := c.do("POST", "/v1/auth/signin", map[string]string{"email": randEmail(), "password": "not the password"}, "")
	if wrongPw.Status != unknown.Status || wrongPw.errCode(t) != unknown.errCode(t) {
		t.Fatalf("responses differ: %d/%s vs %d/%s", wrongPw.Status, wrongPw.errCode(t), unknown.Status, unknown.errCode(t))
	}
	f1 := c.do("POST", "/v1/auth/password/forgot", map[string]string{"email": email}, "")
	f2 := newClient(t).do("POST", "/v1/auth/password/forgot", map[string]string{"email": randEmail()}, "")
	if f1.Status != 202 || f2.Status != 202 || !bytes.Equal(f1.Body, f2.Body) {
		t.Fatalf("forgot password reveals account existence: %s / %s", f1.Body, f2.Body)
	}
}

func TestAccountLockout(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	c.signUp(email, pw)
	for i := range 5 {
		// Different IPs: lockout is per account, not per source.
		cl := newClient(t)
		if r := cl.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": fmt.Sprintf("guess-%d-xxxx", i)}, ""); r.Status != 401 {
			t.Fatalf("attempt %d: %d", i, r.Status)
		}
	}
	r := c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, "")
	if r.Status != 429 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("expected lockout with Retry-After even for the right password, got %d", r.Status)
	}
}

func TestIPRateLimit(t *testing.T) {
	c := newClient(t)
	limited := false
	for range 7 {
		r := c.do("POST", "/v1/auth/password/forgot", map[string]string{"email": randEmail()}, "")
		if r.Status == 429 {
			limited = true
			if r.Header.Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
		}
	}
	if !limited {
		t.Fatal("forgot-password endpoint is not rate limited per IP")
	}
}

func TestEmailVerificationAndPasswordReset(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	tk := c.signUp(email, pw)

	tok := tokenFor(t, email, "verify-email")
	if r := c.do("POST", "/v1/auth/email/verify", map[string]string{"token": tok}, ""); r.Status != 200 {
		t.Fatalf("verify: %d %s", r.Status, r.Body)
	}
	if r := c.do("POST", "/v1/auth/email/verify", map[string]string{"token": tok}, ""); r.Status != 401 {
		t.Fatal("verification token is reusable")
	}
	if me := c.do("GET", "/v1/me", nil, tk.Access).json(t); me["email_verified"] != true {
		t.Fatal("email not marked verified")
	}

	if r := c.do("POST", "/v1/auth/password/forgot", map[string]string{"email": email}, ""); r.Status != 202 {
		t.Fatal(r.Status)
	}
	reset := tokenFor(t, email, "reset-password")
	// Weak password is rejected without burning the link.
	if r := c.do("POST", "/v1/auth/password/reset", map[string]string{"token": reset, "password": "password"}, ""); r.Status != 422 {
		t.Fatalf("weak password accepted: %d", r.Status)
	}
	if r := c.do("POST", "/v1/auth/password/reset", map[string]string{"token": reset, "password": "a brand new passphrase"}, ""); r.Status != 200 {
		t.Fatalf("reset: %d %s", r.Status, r.Body)
	}
	if r := c.do("POST", "/v1/auth/password/reset", map[string]string{"token": reset, "password": "yet another passphrase"}, ""); r.Status != 401 {
		t.Fatal("reset link is reusable")
	}
	if c.do("GET", "/v1/me", nil, tk.Access).Status != 401 {
		t.Fatal("sessions must be revoked after a password reset")
	}
	if c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": "a brand new passphrase"}, "").Status != 200 {
		t.Fatal("cannot sign in with the new password")
	}
}

func TestResetLinkDiesWhenPasswordChanges(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	tk := c.signUp(email, pw)
	c.do("POST", "/v1/auth/password/forgot", map[string]string{"email": email}, "")
	reset := tokenFor(t, email, "reset-password")
	if r := c.do("POST", "/v1/me/password", map[string]string{"current_password": pw, "new_password": "changed in the meantime"}, tk.Access); r.Status != 204 {
		t.Fatal(r.Status)
	}
	if r := c.do("POST", "/v1/auth/password/reset", map[string]string{"token": reset, "password": "attacker chosen passphrase"}, ""); r.Status != 401 {
		t.Fatalf("stale reset link still works after a password change: %d", r.Status)
	}
}

func TestTOTPMFA(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	tk := c.signUp(email, pw)

	setup := c.do("POST", "/v1/me/mfa/totp/setup", nil, tk.Access).json(t)
	secret := setup["secret"].(string)
	if !strings.HasPrefix(setup["otpauth_url"].(string), "otpauth://totp/") {
		t.Fatal("bad otpauth url")
	}
	code := func(at time.Time) string {
		s, _ := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		return s
	}
	if r := c.do("POST", "/v1/me/mfa/totp/enable", map[string]string{"code": "000000"}, tk.Access); r.Status != 401 {
		t.Fatalf("wrong enable code accepted: %d", r.Status)
	}
	en := c.do("POST", "/v1/me/mfa/totp/enable", map[string]string{"code": code(time.Now())}, tk.Access)
	if en.Status != 200 {
		t.Fatalf("enable: %d %s", en.Status, en.Body)
	}
	rc := en.json(t)["recovery_codes"].([]any)
	if len(rc) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(rc))
	}

	// Password alone is no longer enough.
	r := c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, "")
	m := r.json(t)
	if m["status"] != "mfa_required" || m["tokens"] != nil {
		t.Fatalf("expected mfa_required without tokens: %s", r.Body)
	}
	mfaToken := m["mfa_token"].(string)

	// The code used at enrollment is single use (same 30s step).
	if r := c.do("POST", "/v1/auth/mfa/verify", map[string]string{"mfa_token": mfaToken, "code": code(time.Now())}, ""); r.Status != 401 {
		t.Fatalf("TOTP replay within the same step accepted: %d", r.Status)
	}
	// Next step's code (clock drift tolerance) works.
	ok := c.do("POST", "/v1/auth/mfa/verify", map[string]string{"mfa_token": mfaToken, "code": code(time.Now().Add(30 * time.Second))}, "")
	if ok.Status != 200 {
		t.Fatalf("mfa verify: %d %s", ok.Status, ok.Body)
	}
	amr := ok.json(t)["tokens"].(map[string]any)
	_ = amr
	// The MFA token cannot be reused.
	if r := c.do("POST", "/v1/auth/mfa/verify", map[string]string{"mfa_token": mfaToken, "code": code(time.Now().Add(60 * time.Second))}, ""); r.Status != 401 {
		t.Fatal("mfa token reusable")
	}

	// Recovery code works exactly once.
	m = c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, "").json(t)
	recovery := rc[0].(string)
	if r := c.do("POST", "/v1/auth/mfa/verify", map[string]string{"mfa_token": m["mfa_token"].(string), "code": strings.ToUpper(recovery)}, ""); r.Status != 200 {
		t.Fatalf("recovery code rejected: %d %s", r.Status, r.Body)
	}
	m = c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, "").json(t)
	if r := c.do("POST", "/v1/auth/mfa/verify", map[string]string{"mfa_token": m["mfa_token"].(string), "code": recovery}, ""); r.Status != 401 {
		t.Fatal("recovery code reusable")
	}

	// Brute force of the challenge is capped.
	m = c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, "").json(t)
	tokenForBrute := m["mfa_token"].(string)
	last := 0
	for i := range 7 {
		last = c.do("POST", "/v1/auth/mfa/verify", map[string]string{"mfa_token": tokenForBrute, "code": fmt.Sprintf("%06d", i)}, "").Status
	}
	if last != 401 && last != 429 {
		t.Fatalf("unexpected status after brute force: %d", last)
	}
	// TOTP secret is encrypted at rest.
	var raw []byte
	_ = A.Pool.QueryRow(context.Background(), `SELECT totp_secret FROM users WHERE id = $1`, tk.UserID).Scan(&raw)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("TOTP secret stored in plaintext")
	}
}

func pkcePair() (verifier, challenge string) {
	verifier = base64.RawURLEncoding.EncodeToString(randBytes(32))
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// oauthLogin runs the complete browser flow against the fake provider and
// returns the final redirect URL received by the app.
func oauthLogin(t *testing.T, c *client, id *oauth.Identity, redirect, challenge string) *url.URL {
	t.Helper()
	q := url.Values{"redirect_uri": {redirect}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"app-state-1"}}
	r := c.do("GET", "/v1/oauth/fake/authorize?"+q.Encode(), nil, "")
	if r.Status != 302 {
		t.Fatalf("authorize: %d %s", r.Status, r.Body)
	}
	idp, _ := url.Parse(r.Header.Get("Location"))
	state := idp.Query().Get("state")
	code := "idp-code-" + randIP()
	fakeIdP.set(code, id)
	cb := c.do("GET", "/v1/oauth/fake/callback?"+url.Values{"state": {state}, "code": {code}}.Encode(), nil, "")
	if cb.Status != 303 {
		t.Fatalf("callback: %d %s", cb.Status, cb.Body)
	}
	back, _ := url.Parse(cb.Header.Get("Location"))
	return back
}

func TestOAuthBrowserFlowWithPKCE(t *testing.T) {
	c := newClient(t)
	verifier, challenge := pkcePair()
	email := randEmail()
	sub := "sub-" + randIP()
	back := oauthLogin(t, c, &oauth.Identity{Provider: "fake", Subject: sub, Email: email, EmailVerified: true, Name: "OAuth User"}, "myapp://auth", challenge)
	if back.Scheme != "myapp" || back.Query().Get("state") != "app-state-1" || back.Query().Get("code") == "" {
		t.Fatalf("bad redirect back to app: %s", back)
	}
	code := back.Query().Get("code")

	// Intercepting app without the verifier cannot redeem the code.
	other, _ := pkcePair()
	if r := c.do("POST", "/v1/oauth/token", map[string]string{"code": code, "code_verifier": other, "redirect_uri": "myapp://auth"}, ""); r.Status != 401 {
		t.Fatalf("code redeemed without the right verifier: %d", r.Status)
	}
	// The failed attempt burned the code (single use).
	if r := c.do("POST", "/v1/oauth/token", map[string]string{"code": code, "code_verifier": verifier, "redirect_uri": "myapp://auth"}, ""); r.Status != 401 {
		t.Fatal("login code reusable after a failed redemption")
	}

	back = oauthLogin(t, c, &oauth.Identity{Provider: "fake", Subject: sub, Email: email, EmailVerified: true}, "myapp://auth", challenge)
	r := c.do("POST", "/v1/oauth/token", map[string]string{"code": back.Query().Get("code"), "code_verifier": verifier, "redirect_uri": "myapp://auth"}, "")
	if r.Status != 200 {
		t.Fatalf("token exchange: %d %s", r.Status, r.Body)
	}
	tk := parseTokens(t, r)
	me := c.do("GET", "/v1/me", nil, tk.Access).json(t)
	if me["email"] != email || me["email_verified"] != true || me["has_password"] != false {
		t.Fatalf("unexpected user %v", me)
	}
	ids := c.do("GET", "/v1/me/identities", nil, tk.Access).json(t)["identities"].([]any)
	if len(ids) != 1 {
		t.Fatalf("expected one identity, got %v", ids)
	}
	// Removing the only credential is refused.
	if r := c.do("DELETE", "/v1/me/identities/fake", nil, tk.Access); r.Status != 409 {
		t.Fatalf("last credential unlinked: %d", r.Status)
	}
}

func TestOAuthRejectsOpenRedirectAndMissingPKCE(t *testing.T) {
	c := newClient(t)
	_, challenge := pkcePair()
	for _, redirect := range []string{"https://evil.example.com/callback", "https://app.example.com/callback/../x", "myapp://auth.evil", ""} {
		q := url.Values{"redirect_uri": {redirect}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
		if r := c.do("GET", "/v1/oauth/fake/authorize?"+q.Encode(), nil, ""); r.Status != 400 {
			t.Errorf("redirect %q accepted: %d", redirect, r.Status)
		}
	}
	q := url.Values{"redirect_uri": {"myapp://auth"}, "code_challenge_method": {"plain"}, "code_challenge": {"abc"}}
	if r := c.do("GET", "/v1/oauth/fake/authorize?"+q.Encode(), nil, ""); r.Status != 422 {
		t.Fatalf("missing/plain PKCE accepted: %d", r.Status)
	}
	// Forged or replayed state is refused without redirecting anywhere.
	if r := c.do("GET", "/v1/oauth/fake/callback?state=forged&code=x", nil, ""); r.Status != 401 || r.Header.Get("Location") != "" {
		t.Fatalf("forged state: %d %s", r.Status, r.Header.Get("Location"))
	}
	if r := c.do("GET", "/v1/oauth/nope/authorize?redirect_uri=myapp://auth", nil, ""); r.Status != 404 {
		t.Fatalf("unknown provider: %d", r.Status)
	}
}

// Pre-account takeover: an attacker registers the victim's email with a
// password (never verifies it). When the victim later signs in with a
// provider that verified the email, the attacker's password must be wiped
// and the attacker's sessions revoked.
func TestOAuthPreAccountTakeoverProtection(t *testing.T) {
	attacker := newClient(t)
	victimEmail := randEmail()
	atk := attacker.signUp(victimEmail, "attacker password 123")

	victim := newClient(t)
	verifier, challenge := pkcePair()
	back := oauthLogin(t, victim, &oauth.Identity{Provider: "fake", Subject: "victim-" + randIP(), Email: victimEmail, EmailVerified: true}, "myapp://auth", challenge)
	r := victim.do("POST", "/v1/oauth/token", map[string]string{"code": back.Query().Get("code"), "code_verifier": verifier, "redirect_uri": "myapp://auth"}, "")
	if r.Status != 200 {
		t.Fatalf("victim sign-in: %d %s", r.Status, r.Body)
	}
	if attacker.do("POST", "/v1/auth/signin", map[string]string{"email": victimEmail, "password": "attacker password 123"}, "").Status != 401 {
		t.Fatal("attacker's password survived account linking")
	}
	if attacker.do("GET", "/v1/me", nil, atk.Access).Status != 401 {
		t.Fatal("attacker's session survived account linking")
	}
}

func TestOAuthUnverifiedEmailDoesNotLink(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	c.signUp(email, pw)
	tok := tokenFor(t, email, "verify-email")
	c.do("POST", "/v1/auth/email/verify", map[string]string{"token": tok}, "")

	_, challenge := pkcePair()
	back := oauthLogin(t, newClient(t), &oauth.Identity{Provider: "fake", Subject: "x-" + randIP(), Email: email, EmailVerified: false}, "myapp://auth", challenge)
	if back.Query().Get("error") != "email_taken" || back.Query().Get("code") != "" {
		t.Fatalf("unverified provider email must not link to an existing account: %s", back)
	}
}

func TestDisabledAccount(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	tk := c.signUp(email, pw)
	id := mustUUID(t, tk.UserID)
	if err := A.Auth.SetDisabled(context.Background(), id, true, "test"); err != nil {
		t.Fatal(err)
	}
	if c.do("GET", "/v1/me", nil, tk.Access).Status != 401 {
		t.Fatal("disabled user's access token still accepted")
	}
	if r := c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, ""); r.errCode(t) != "account_disabled" {
		t.Fatalf("expected account_disabled, got %s", r.Body)
	}
	if r := c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": "wrong password"}, ""); r.errCode(t) != "invalid_credentials" {
		t.Fatal("disabled state must only be revealed after a correct password")
	}
}

func TestAvatarUpload(t *testing.T) {
	if A.Config.S3.Enabled == false {
		t.Skip("S3 disabled")
	}
	c := newClient(t)
	tk := c.signUp(randEmail(), pw)

	img := image.NewRGBA(image.Rect(0, 0, 300, 200))
	for x := range 300 {
		img.Set(x, 100, color.RGBA{R: 200, A: 255})
	}
	var pngBuf bytes.Buffer
	_ = png.Encode(&pngBuf, img)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "me.png")
	_, _ = fw.Write(pngBuf.Bytes())
	_ = mw.Close()
	req, _ := http.NewRequest("PUT", "http://warden.test/v1/me/avatar", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+tk.Access)
	req.Header.Set("X-Forwarded-For", c.ip)
	r := c.raw(req)
	if r.Status != 200 {
		t.Fatalf("upload: %d %s", r.Status, r.Body)
	}
	avatarURL, _ := r.json(t)["avatar_url"].(string)
	if avatarURL == "" {
		t.Fatal("no avatar url")
	}
	res, err := http.Get(avatarURL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, err := jpeg.Decode(res.Body)
	if err != nil {
		t.Fatalf("stored avatar is not a JPEG: %v", err)
	}
	if got.Bounds().Dx() != 512 {
		t.Fatalf("avatar not normalized: %v", got.Bounds())
	}

	// Non-images are rejected.
	req, _ = http.NewRequest("PUT", "http://warden.test/v1/me/avatar", strings.NewReader("<svg onload=alert(1)>"))
	req.Header.Set("Authorization", "Bearer "+tk.Access)
	req.Header.Set("X-Forwarded-For", c.ip)
	if r := c.raw(req); r.Status != 415 {
		t.Fatalf("svg/html accepted as avatar: %d", r.Status)
	}
}

func TestDeleteAccount(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	tk := c.signUp(email, pw)
	if r := c.do("DELETE", "/v1/me", map[string]string{"password": "wrong"}, tk.Access); r.Status != 401 {
		t.Fatalf("deleted with wrong password: %d", r.Status)
	}
	if r := c.do("DELETE", "/v1/me", map[string]string{"password": pw}, tk.Access); r.Status != 204 {
		t.Fatalf("delete: %d %s", r.Status, r.Body)
	}
	if c.do("GET", "/v1/me", nil, tk.Access).Status != 401 {
		t.Fatal("token valid after account deletion")
	}
	if c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, "").Status != 401 {
		t.Fatal("deleted account can sign in")
	}
}

func TestSessionsAPI(t *testing.T) {
	c := newClient(t)
	email := randEmail()
	tk := c.signUp(email, pw)
	other := parseTokens(t, c.do("POST", "/v1/auth/signin", map[string]string{"email": email, "password": pw}, ""))
	list := c.do("GET", "/v1/me/sessions", nil, tk.Access).json(t)["sessions"].([]any)
	if len(list) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(list))
	}
	// A user cannot revoke someone else's session.
	stranger := newClient(t).signUp(randEmail(), pw)
	var foreignSID string
	for _, s := range list {
		if m := s.(map[string]any); m["current"] == false {
			foreignSID = m["id"].(string)
		}
	}
	c.do("DELETE", "/v1/me/sessions/"+foreignSID, nil, stranger.Access)
	if c.do("GET", "/v1/me", nil, other.Access).Status != 200 {
		t.Fatal("a stranger revoked another user's session")
	}
	if r := c.do("DELETE", "/v1/me/sessions", nil, tk.Access); r.Status != 200 {
		t.Fatal(r.Status)
	}
	if c.do("GET", "/v1/me", nil, other.Access).Status != 401 {
		t.Fatal("other session survived 'sign out other devices'")
	}
}

func TestCookieMode(t *testing.T) {
	c := newClient(t)
	c.headers["X-Auth-Mode"] = "cookie"
	r := c.do("POST", "/v1/auth/signup", map[string]string{"email": randEmail(), "password": pw}, "")
	if r.Status != 201 {
		t.Fatal(r.Status)
	}
	if tk := r.json(t)["tokens"].(map[string]any); tk["refresh_token"] != nil {
		t.Fatal("refresh token leaked into the body in cookie mode")
	}
	ck := r.Header.Get("Set-Cookie")
	if lc := strings.ToLower(ck); !strings.Contains(ck, "warden_refresh=") || !strings.Contains(lc, "httponly") || !strings.Contains(lc, "path=/v1/auth") || !strings.Contains(lc, "samesite=lax") {
		t.Fatalf("bad refresh cookie: %s", ck)
	}
	val := strings.SplitN(strings.SplitN(ck, ";", 2)[0], "=", 2)[1]

	// Cookie alone (no X-Auth-Mode header, as a cross-site form would send) is ignored.
	req, _ := http.NewRequest("POST", "http://warden.test/v1/auth/refresh", nil)
	req.Header.Set("Cookie", "warden_refresh="+val)
	req.Header.Set("X-Forwarded-For", c.ip)
	if r := c.raw(req); r.Status != 401 {
		t.Fatalf("cookie used without the CSRF header: %d", r.Status)
	}
	req, _ = http.NewRequest("POST", "http://warden.test/v1/auth/refresh", nil)
	req.Header.Set("Cookie", "warden_refresh="+val)
	req.Header.Set("X-Auth-Mode", "cookie")
	req.Header.Set("X-Forwarded-For", c.ip)
	if r := c.raw(req); r.Status != 200 {
		t.Fatalf("cookie refresh: %d %s", r.Status, r.Body)
	}
}

func TestSecurityHeadersAndCORS(t *testing.T) {
	c := newClient(t)
	r := c.do("GET", "/healthz", nil, "")
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy"} {
		if r.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	tk := c.signUp(randEmail(), pw)
	if cc := c.do("GET", "/v1/me", nil, tk.Access).Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("authenticated response cacheable: %q", cc)
	}
	pre := func(origin string) string {
		req, _ := http.NewRequest("OPTIONS", "http://warden.test/v1/auth/signin", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("X-Forwarded-For", c.ip)
		return c.raw(req).Header.Get("Access-Control-Allow-Origin")
	}
	if got := pre("https://app.example.com"); got != "https://app.example.com" {
		t.Errorf("allowed origin not echoed: %q", got)
	}
	if got := pre("https://evil.example.com"); got != "" {
		t.Errorf("foreign origin allowed: %q", got)
	}
}

func TestMalformedInput(t *testing.T) {
	c := newClient(t)
	cases := []struct {
		body   string
		status int
	}{
		{`{"email":`, 422},
		{`[]`, 422},
		{`{"email":"not-an-email","password":"correct horse battery"}`, 422},
		{`{"email":"a@b.co","password":"short"}`, 422},
		{`{"email":"a@b.co","password":"` + strings.Repeat("x", 2000) + `"}`, 422},
		{`{"email":"` + strings.Repeat("a", 300) + `@x.com","password":"correct horse battery"}`, 422},
		{`{"email":"a\u0000@b.co","password":"correct horse battery"}`, 422},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest("POST", "http://warden.test/v1/auth/signup", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", c.ip)
		if r := c.raw(req); r.Status != tc.status {
			t.Errorf("%.40s: got %d want %d (%s)", tc.body, r.Status, tc.status, r.Body)
		}
	}
	big := `{"email":"a@b.co","password":"` + strings.Repeat("x", 100<<10) + `"}`
	req, _ := http.NewRequest("POST", "http://warden.test/v1/auth/signup", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", c.ip)
	if r := c.raw(req); r.Status != 413 {
		t.Errorf("oversized JSON body: %d", r.Status)
	}
	for _, h := range []string{"Bearer", "Bearer x.y.z", "Basic abc", "Bearer " + strings.Repeat("a", 10000)} {
		req, _ := http.NewRequest("GET", "http://warden.test/v1/me", nil)
		req.Header.Set("Authorization", h)
		req.Header.Set("X-Forwarded-For", c.ip)
		if r := c.raw(req); r.Status != 401 {
			t.Errorf("auth header %.20q: %d", h, r.Status)
		}
	}
}

func TestGRPC(t *testing.T) {
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cl := wardenv1.NewAuthServiceClient(conn)
	ctx := context.Background()

	if _, err := cl.GetUser(ctx, &wardenv1.GetUserRequest{UserId: "x"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing api key: %v", err)
	}
	bad := metadata.AppendToOutgoingContext(ctx, "x-api-key", "wrong")
	if _, err := cl.GetUser(bad, &wardenv1.GetUserRequest{UserId: "x"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong api key: %v", err)
	}
	authed := metadata.AppendToOutgoingContext(ctx, "x-api-key", grpcKey)

	c := newClient(t)
	tk := c.signUp(randEmail(), pw)
	v, err := cl.VerifyAccessToken(authed, &wardenv1.VerifyAccessTokenRequest{AccessToken: tk.Access, CheckSession: true})
	if err != nil || !v.Valid || v.UserId != tk.UserID {
		t.Fatalf("verify: %v %v", v, err)
	}
	if _, err := cl.SetUserRoles(authed, &wardenv1.SetUserRolesRequest{UserId: tk.UserID, Roles: []string{"admin", "editor"}}); err != nil {
		t.Fatal(err)
	}
	u, err := cl.GetUser(authed, &wardenv1.GetUserRequest{UserId: tk.UserID})
	if err != nil || len(u.User.Roles) != 2 {
		t.Fatalf("get user: %v %v", u, err)
	}
	if _, err := cl.SetUserRoles(authed, &wardenv1.SetUserRolesRequest{UserId: tk.UserID, Roles: []string{"Bad Role!"}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid role accepted: %v", err)
	}
	// New roles appear in refreshed tokens.
	r := parseTokens(t, c.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": tk.Refresh}, ""))
	v, _ = cl.VerifyAccessToken(authed, &wardenv1.VerifyAccessTokenRequest{AccessToken: r.Access})
	if len(v.Roles) != 2 {
		t.Fatalf("roles not in refreshed token: %v", v.Roles)
	}
	rv, err := cl.RevokeUserSessions(authed, &wardenv1.RevokeUserSessionsRequest{UserId: tk.UserID})
	if err != nil || rv.Revoked < 1 {
		t.Fatalf("revoke: %v %v", rv, err)
	}
	v, _ = cl.VerifyAccessToken(authed, &wardenv1.VerifyAccessTokenRequest{AccessToken: r.Access, CheckSession: true})
	if v.Valid || v.Reason != "session_revoked" {
		t.Fatalf("revoked session still valid: %v", v)
	}
	v, _ = cl.VerifyAccessToken(authed, &wardenv1.VerifyAccessTokenRequest{AccessToken: "garbage"})
	if v.Valid {
		t.Fatal("garbage token valid")
	}
}
