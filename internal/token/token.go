// Package token issues and verifies access tokens (JWT, ES256) and manages
// the signing key lifecycle (generation, rotation, JWKS publication).
//
// ES256 was chosen over RS256 (smaller tokens, faster signing) and over EdDSA
// (universally supported by JWT libraries in every language, including
// Node's jose/jsonwebtoken and mobile SDKs).
package token

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessTokenType is the JWT "typ" header for access tokens (RFC 9068). It
// stops an ID token or any other JWT signed by the same key from being
// accepted as an access token.
const AccessTokenType = "at+jwt"

// Claims are the access token claims.
type Claims struct {
	jwt.RegisteredClaims
	SessionID     string   `json:"sid"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified"`
	Roles         []string `json:"roles,omitempty"`
	AMR           []string `json:"amr,omitempty"`
}

// Subject is the parsed user id.
func (c *Claims) UserID() (uuid.UUID, error) { return uuid.Parse(c.Subject) }

// SID is the parsed session id.
func (c *Claims) SID() (uuid.UUID, error) { return uuid.Parse(c.SessionID) }

// Issuer signs access tokens with the active key and verifies them against
// every published key.
type Issuer struct {
	keys     *KeyManager
	issuer   string
	audience []string
	ttl      time.Duration
	now      func() time.Time
}

func NewIssuer(keys *KeyManager, issuer string, audience []string, ttl time.Duration) *Issuer {
	return &Issuer{keys: keys, issuer: issuer, audience: audience, ttl: ttl, now: time.Now}
}

// TTL returns the access token lifetime.
func (i *Issuer) TTL() time.Duration { return i.ttl }

// Subject describes who the token is for.
type Subject struct {
	UserID        uuid.UUID
	SessionID     uuid.UUID
	Email         string
	EmailVerified bool
	Roles         []string
	AMR           []string
}

// Issue signs a new access token.
func (i *Issuer) Issue(s Subject) (string, time.Time, error) {
	key := i.keys.active()
	if key == nil {
		return "", time.Time{}, errors.New("token: no active signing key")
	}
	now := i.now()
	exp := now.Add(i.ttl)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   s.UserID.String(),
			Audience:  i.audience,
			ExpiresAt: jwt.NewNumericDate(exp),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		SessionID:     s.SessionID.String(),
		Email:         s.Email,
		EmailVerified: s.EmailVerified,
		Roles:         s.Roles,
		AMR:           s.AMR,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = key.kid
	t.Header["typ"] = AccessTokenType
	signed, err := t.SignedString(key.private)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token: sign: %w", err)
	}
	return signed, exp, nil
}

// ErrInvalid is returned for any token that fails verification.
var ErrInvalid = errors.New("token: invalid")

// Verify parses and fully validates an access token.
func (i *Issuer) Verify(raw string) (*Claims, error) {
	var claims Claims
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(i.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(i.now),
	)
	_, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != AccessTokenType {
			return nil, errors.New("unexpected token type")
		}
		kid, _ := t.Header["kid"].(string)
		pub := i.keys.publicKey(kid)
		if pub == nil {
			return nil, errors.New("unknown key id")
		}
		return pub, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !audienceMatches(claims.Audience, i.audience) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalid)
	}
	if claims.Subject == "" || claims.SessionID == "" {
		return nil, fmt.Errorf("%w: missing subject", ErrInvalid)
	}
	return &claims, nil
}

func audienceMatches(got jwt.ClaimStrings, want []string) bool {
	for _, a := range got {
		if slices.Contains(want, a) {
			return true
		}
	}
	return false
}
