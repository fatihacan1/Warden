package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"github.com/coreos/go-oidc/v3/oidc"
)

// idTokenVerifier validates OIDC ID tokens against a provider's JWKS. The key
// set is cached and refreshed by go-oidc when an unknown kid appears.
type idTokenVerifier struct {
	issuers   []string
	audiences []string
	verifier  *oidc.IDTokenVerifier
}

func newIDTokenVerifier(jwksURL string, issuers, audiences []string, client *http.Client) *idTokenVerifier {
	ctx := oidc.ClientContext(context.Background(), client)
	keySet := oidc.NewRemoteKeySet(ctx, jwksURL)
	v := oidc.NewVerifier(issuers[0], keySet, &oidc.Config{
		SkipClientIDCheck:    true, // checked below against several allowed audiences
		SkipIssuerCheck:      true, // checked below: Google uses two issuer spellings
		SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256},
	})
	return &idTokenVerifier{issuers: issuers, audiences: audiences, verifier: v}
}

type standardClaims struct {
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"` // bool (Google) or "true" (Apple)
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// verify checks signature, expiry, issuer, audience and nonce. When
// nonceHashed is true the token nonce may also be hex(sha256(nonce)), which
// is how native Sign in with Apple embeds it.
func (v *idTokenVerifier) verify(ctx context.Context, raw, nonce string, nonceRequired bool) (*oidc.IDToken, *standardClaims, error) {
	tok, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidIDToken, err)
	}
	if !slices.Contains(v.issuers, tok.Issuer) {
		return nil, nil, fmt.Errorf("%w: unexpected issuer %q", ErrInvalidIDToken, tok.Issuer)
	}
	if !slices.ContainsFunc(tok.Audience, func(a string) bool { return slices.Contains(v.audiences, a) }) {
		return nil, nil, fmt.Errorf("%w: audience not allowed", ErrInvalidIDToken)
	}
	if nonceRequired || tok.Nonce != "" {
		if nonce == "" || !nonceMatches(tok.Nonce, nonce) {
			return nil, nil, fmt.Errorf("%w: nonce mismatch", ErrInvalidIDToken)
		}
	}
	var c standardClaims
	if err := tok.Claims(&c); err != nil {
		return nil, nil, fmt.Errorf("%w: claims: %v", ErrInvalidIDToken, err)
	}
	return tok, &c, nil
}

func nonceMatches(tokenNonce, supplied string) bool {
	if tokenNonce == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(tokenNonce), []byte(supplied)) == 1 {
		return true
	}
	sum := sha256.Sum256([]byte(supplied))
	return subtle.ConstantTimeCompare([]byte(tokenNonce), []byte(hex.EncodeToString(sum[:]))) == 1
}

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		b, _ := strconv.ParseBool(t)
		return b
	}
	return false
}
