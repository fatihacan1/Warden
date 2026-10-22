package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"golang.org/x/oauth2"
)

func googleDefinition() *Definition {
	return &Definition{
		Name:            "google",
		DisplayName:     "Google",
		DocsURL:         "https://developers.google.com/identity/protocols/oauth2/web-server",
		ConsoleURL:      "https://console.cloud.google.com/apis/credentials",
		SupportsNative:  true,
		AllowsLocalhost: true,
		CallbackField:   "Credentials > OAuth client > Authorized redirect URIs",
		Fields: []Field{
			{Key: KeyClientID, Label: "Web client ID", Required: true, Help: "OAuth client of type \"Web application\". Add the callback URL above as an authorized redirect URI."},
			{Key: KeyClientSecret, Label: "Web client secret", Secret: true, Required: true},
			{Key: KeyNativeClientIDs, Label: "Native client IDs", Help: "Optional, comma separated. iOS/Android client IDs accepted as ID token audiences for native sign-in."},
		},
		New: newGoogle,
	}
}

type google struct {
	conf     *oauth2.Config
	verifier *idTokenVerifier
	deps     Deps
}

// #nosec G101 -- public OAuth endpoint URLs, not credentials
var googleEndpoint = oauth2.Endpoint{
	AuthURL:   "https://accounts.google.com/o/oauth2/v2/auth",
	TokenURL:  "https://oauth2.googleapis.com/token",
	AuthStyle: oauth2.AuthStyleInParams,
}

const googleJWKS = "https://www.googleapis.com/oauth2/v3/certs"

var googleIssuers = []string{"https://accounts.google.com", "accounts.google.com"}

func newGoogle(s Settings, d Deps) (Provider, error) {
	if err := requireFields(s, KeyClientID, KeyClientSecret); err != nil {
		return nil, err
	}
	audiences := append([]string{s.Get(KeyClientID)}, s.List(KeyNativeClientIDs)...)
	return &google{
		conf: &oauth2.Config{
			ClientID:     s.Get(KeyClientID),
			ClientSecret: s.Get(KeyClientSecret),
			Endpoint:     googleEndpoint,
			RedirectURL:  d.CallbackURL,
			Scopes:       []string{"openid", "email", "profile"},
		},
		verifier: newIDTokenVerifier(googleJWKS, googleIssuers, audiences, d.HTTPClient),
		deps:     d,
	}, nil
}

func (g *google) Name() string { return "google" }

func (g *google) AuthURL(state, nonce, verifier string) string {
	return g.conf.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("prompt", "select_account"),
	)
}

func (g *google) Exchange(ctx context.Context, code, verifier, nonce string, _ url.Values) (*Identity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.deps.HTTPClient)
	tok, err := g.conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("google: exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("google: token response has no id_token")
	}
	return g.identity(ctx, raw, nonce, true)
}

func (g *google) VerifyIDToken(ctx context.Context, raw, nonce string) (*Identity, error) {
	return g.identity(ctx, raw, nonce, true)
}

func (g *google) identity(ctx context.Context, raw, nonce string, nonceRequired bool) (*Identity, error) {
	tok, c, err := g.verifier.verify(ctx, raw, nonce, nonceRequired)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Provider:      "google",
		Subject:       tok.Subject,
		Email:         c.Email,
		EmailVerified: truthy(c.EmailVerified),
		Name:          c.Name,
		AvatarURL:     c.Picture,
	}, nil
}
