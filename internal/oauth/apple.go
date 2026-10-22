package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func appleDefinition() *Definition {
	return &Definition{
		Name:           "apple",
		DisplayName:    "Apple",
		DocsURL:        "https://developer.apple.com/documentation/sign_in_with_apple",
		ConsoleURL:     "https://developer.apple.com/account/resources/identifiers/list/serviceId",
		SupportsNative: true,
		CallbackField:  "Identifiers > Services ID > Sign in with Apple > Return URLs",
		Fields: []Field{
			{Key: KeyClientID, Label: "Services ID", Required: true, Help: "The Services ID (e.g. com.example.web) configured with the callback URL above as Return URL."},
			{Key: KeyTeamID, Label: "Team ID", Required: true},
			{Key: KeyKeyID, Label: "Key ID", Required: true, Help: "ID of the Sign in with Apple private key."},
			{Key: KeyPrivateKey, Label: "Private key (.p8)", Secret: true, Required: true, Multiline: true, Help: "Paste the full contents of the AuthKey_XXXX.p8 file."},
			{Key: KeyNativeClientIDs, Label: "App bundle IDs", Help: "Optional, comma separated. Bundle IDs accepted for native Sign in with Apple on iOS."},
		},
		New: newApple,
	}
}

// #nosec G101 -- public OAuth endpoint URLs, not credentials
var appleEndpoint = oauth2.Endpoint{
	AuthURL:   "https://appleid.apple.com/auth/authorize",
	TokenURL:  "https://appleid.apple.com/auth/token",
	AuthStyle: oauth2.AuthStyleInParams,
}

const (
	appleIssuer = "https://appleid.apple.com"
	appleJWKS   = "https://appleid.apple.com/auth/keys"
)

type apple struct {
	clientID string
	teamID   string
	keyID    string
	key      *ecdsa.PrivateKey
	endpoint oauth2.Endpoint
	verifier *idTokenVerifier
	deps     Deps
	now      func() time.Time
}

func newApple(s Settings, d Deps) (Provider, error) {
	if err := requireFields(s, KeyClientID, KeyTeamID, KeyKeyID, KeyPrivateKey); err != nil {
		return nil, err
	}
	key, err := parseAppleKey(s.Get(KeyPrivateKey))
	if err != nil {
		return nil, err
	}
	audiences := append([]string{s.Get(KeyClientID)}, s.List(KeyNativeClientIDs)...)
	return &apple{
		clientID: s.Get(KeyClientID),
		teamID:   s.Get(KeyTeamID),
		keyID:    s.Get(KeyKeyID),
		key:      key,
		endpoint: appleEndpoint,
		verifier: newIDTokenVerifier(appleJWKS, []string{appleIssuer}, audiences, d.HTTPClient),
		deps:     d,
		now:      time.Now,
	}, nil
}

func parseAppleKey(p8 string) (*ecdsa.PrivateKey, error) {
	p8 = strings.ReplaceAll(p8, `\n`, "\n")
	block, _ := pem.Decode([]byte(p8))
	if block == nil {
		return nil, errors.New("apple: private key is not PEM encoded")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apple: parse private key: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apple: private key must be an EC (P-256) key")
	}
	return ec, nil
}

func (a *apple) Name() string { return "apple" }

func (a *apple) config(secret string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: secret,
		Endpoint:     a.endpoint,
		RedirectURL:  a.deps.CallbackURL,
		Scopes:       []string{"name", "email"},
	}
}

// AuthURL uses response_mode=form_post (required by Apple when requesting
// name/email), so the callback arrives as a cross-site POST. That is why
// Warden keeps flow state server-side instead of in cookies.
func (a *apple) AuthURL(state, nonce, _ string) string {
	return a.config("").AuthCodeURL(state,
		oauth2.SetAuthURLParam("response_mode", "form_post"),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
}

// clientSecret builds the ES256 JWT Apple uses instead of a static secret.
func (a *apple) clientSecret() (string, error) {
	now := a.now()
	t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    a.teamID,
		Subject:   a.clientID,
		Audience:  jwt.ClaimStrings{appleIssuer},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	})
	t.Header["kid"] = a.keyID
	return t.SignedString(a.key)
}

type appleUser struct {
	Name struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name"`
}

func (a *apple) Exchange(ctx context.Context, code, _, nonce string, form url.Values) (*Identity, error) {
	secret, err := a.clientSecret()
	if err != nil {
		return nil, fmt.Errorf("apple: client secret: %w", err)
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.deps.HTTPClient)
	tok, err := a.config(secret).Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("apple: exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("apple: token response has no id_token")
	}
	id, err := a.identity(ctx, raw, nonce)
	if err != nil {
		return nil, err
	}
	// Apple sends the user's name only on the very first authorization, as a
	// JSON form field next to the code. It is unauthenticated, so it is only
	// used as a display name, never for identification.
	if u := form.Get("user"); u != "" && len(u) < 4096 {
		var au appleUser
		if json.Unmarshal([]byte(u), &au) == nil {
			id.Name = strings.TrimSpace(au.Name.FirstName + " " + au.Name.LastName)
		}
	}
	return id, nil
}

func (a *apple) VerifyIDToken(ctx context.Context, raw, nonce string) (*Identity, error) {
	return a.identity(ctx, raw, nonce)
}

func (a *apple) identity(ctx context.Context, raw, nonce string) (*Identity, error) {
	tok, c, err := a.verifier.verify(ctx, raw, nonce, true)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Provider:      "apple",
		Subject:       tok.Subject,
		Email:         c.Email,
		EmailVerified: truthy(c.EmailVerified),
	}, nil
}
