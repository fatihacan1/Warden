package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/fatihacan1/warden/internal/crypto/randtoken"
)

// The browser flow, end to end:
//
//  1. App opens  GET /v1/oauth/{provider}/authorize?redirect_uri=..&code_challenge=..&state=..
//     (code_challenge is the app's own PKCE challenge, S256).
//  2. Warden stores a server-side State (provider PKCE verifier, nonce, the
//     app's redirect/challenge) under a random key and redirects to the IdP.
//  3. The IdP calls back /v1/oauth/{provider}/callback. Warden consumes the
//     State exactly once (GETDEL), exchanges the code, resolves the user.
//  4. Warden redirects to redirect_uri?code=<login code>&state=<app state>.
//     The login code is single use, valid for 60s, and bound to the app's
//     PKCE challenge.
//  5. App calls POST /v1/oauth/token {code, code_verifier, redirect_uri} and
//     receives tokens. An attacker who intercepts the redirect (e.g. a
//     malicious app claiming the same custom URL scheme) cannot redeem the
//     code without the verifier.

// State is stored server-side between authorize and callback.
type State struct {
	Provider      string `json:"p"`
	RedirectURI   string `json:"r"`
	ClientState   string `json:"s"`
	CodeChallenge string `json:"c"`
	Nonce         string `json:"n"`
	Verifier      string `json:"v"`
}

// LoginCode is the short-lived code handed to the app after the callback.
type LoginCode struct {
	UserID        string   `json:"u"`
	Provider      string   `json:"p"`
	RedirectURI   string   `json:"r"`
	CodeChallenge string   `json:"c"`
	AMR           []string `json:"a"`
}

// ErrFlowNotFound means the state/code is unknown, expired or already used.
var ErrFlowNotFound = errors.New("oauth: flow not found or expired")

type Flow struct {
	rdb      *redis.Client
	stateTTL time.Duration
	codeTTL  time.Duration
}

func NewFlow(rdb *redis.Client) *Flow {
	return &Flow{rdb: rdb, stateTTL: 10 * time.Minute, codeTTL: 60 * time.Second}
}

func (f *Flow) SaveState(ctx context.Context, st State) (string, error) {
	key := randtoken.New(32)
	b, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	if err := f.rdb.Set(ctx, "oauth:state:"+randtoken.HashHex(key), b, f.stateTTL).Err(); err != nil {
		return "", err
	}
	return key, nil
}

// TakeState returns and deletes the state (single use).
func (f *Flow) TakeState(ctx context.Context, key string) (*State, error) {
	if key == "" || len(key) > 128 {
		return nil, ErrFlowNotFound
	}
	b, err := f.rdb.GetDel(ctx, "oauth:state:"+randtoken.HashHex(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrFlowNotFound
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (f *Flow) SaveCode(ctx context.Context, lc LoginCode) (string, error) {
	code := randtoken.New(32)
	b, err := json.Marshal(lc)
	if err != nil {
		return "", err
	}
	if err := f.rdb.Set(ctx, "oauth:code:"+randtoken.HashHex(code), b, f.codeTTL).Err(); err != nil {
		return "", err
	}
	return code, nil
}

// TakeCode returns and deletes a login code (single use).
func (f *Flow) TakeCode(ctx context.Context, code string) (*LoginCode, error) {
	if code == "" || len(code) > 128 {
		return nil, ErrFlowNotFound
	}
	b, err := f.rdb.GetDel(ctx, "oauth:code:"+randtoken.HashHex(code)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrFlowNotFound
	}
	if err != nil {
		return nil, err
	}
	var lc LoginCode
	if err := json.Unmarshal(b, &lc); err != nil {
		return nil, err
	}
	return &lc, nil
}

// UseNonce records a native sign-in nonce; it returns false if the nonce was
// already used (ID token replay).
func (f *Flow) UseNonce(ctx context.Context, provider, nonce string, ttl time.Duration) (bool, error) {
	return f.rdb.SetNX(ctx, "oauth:nonce:"+provider+":"+randtoken.HashHex(nonce), 1, ttl).Result()
}

// VerifyPKCE checks an S256 code_verifier against its challenge (RFC 7636).
func VerifyPKCE(verifier, challenge string) bool {
	if !ValidPKCEValue(verifier) || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// ValidPKCEValue checks RFC 7636 length and charset (also valid for S256
// challenges, which are 43 chars of base64url).
func ValidPKCEValue(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~'
		if !ok {
			return false
		}
	}
	return true
}

// RedirectAllowed reports whether uri exactly matches an allowlisted URI.
// Exact matching (no prefixes, no wildcards) is what OAuth 2.1 requires; it
// rules out open redirects through path or query tricks.
func RedirectAllowed(allowed []string, uri string) bool {
	if uri == "" || len(uri) > 2048 {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return slices.Contains(allowed, uri)
}

// AppendQuery adds parameters to a redirect URI, preserving existing ones.
func AppendQuery(uri string, params map[string]string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
