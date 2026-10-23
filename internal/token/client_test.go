package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestClientTokens(t *testing.T) {
	iss, _ := newTestIssuer(t)
	raw, exp, err := iss.IssueClient(ClientSubject{ClientID: "svc_abc", Scopes: []string{"orders:read", "orders:write"}, Audience: []string{"orders-api"}, TTL: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(exp) > 10*time.Minute {
		t.Fatalf("exp %v", exp)
	}
	claims, err := iss.VerifyAny(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !claims.IsMachine() || claims.Subject != "client:svc_abc" || claims.ClientID != "svc_abc" || claims.Scope != "orders:read orders:write" {
		t.Fatalf("claims %+v", claims)
	}
	if len(claims.Scopes()) != 2 || claims.SessionID != "" || claims.Email != "" || len(claims.Roles) != 0 {
		t.Fatalf("machine token carries user data: %+v", claims)
	}
	if _, err := claims.UserID(); err == nil {
		t.Fatal("client subject must not parse as a user id")
	}
	if _, err := iss.Verify(raw); err == nil {
		t.Fatal("Verify must reject service tokens")
	}
	// A user token is not a machine token.
	user, _, _ := iss.Issue(subject())
	uc, err := iss.Verify(user)
	if err != nil || uc.IsMachine() {
		t.Fatalf("user token: %v %v", uc, err)
	}
}

func TestClientTokenValidation(t *testing.T) {
	iss, _ := newTestIssuer(t)
	for _, s := range []ClientSubject{
		{Audience: []string{"a"}, TTL: time.Minute},
		{ClientID: "x", TTL: time.Minute},
		{ClientID: "x", Audience: []string{"a"}},
	} {
		if _, _, err := iss.IssueClient(s); err == nil {
			t.Fatalf("%+v should be refused", s)
		}
	}
	// A token with a client_id but also a session (a confused token) is refused.
	key := iss.keys.active()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://auth.example.com", Subject: "client:x", Audience: []string{"a"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)), IssuedAt: jwt.NewNumericDate(time.Now())},
		ClientID: "x", SessionID: uuid.NewString(),
	})
	tok.Header["kid"], tok.Header["typ"] = key.kid, AccessTokenType
	signed, err := tok.SignedString(key.private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Verify(signed); err == nil {
		t.Fatal("client token with a session must be refused")
	}
}
