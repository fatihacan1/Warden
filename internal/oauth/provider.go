// Package oauth implements social sign-in (Google, Apple, Discord, GitHub)
// behind a single Provider interface.
//
// Adding a provider means adding one file with a Definition: the admin UI
// renders its settings form from Definition.Fields automatically.
package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Identity is the normalized result of a successful external sign-in.
type Identity struct {
	Provider      string
	Subject       string // stable, provider scoped user id
	Email         string
	EmailVerified bool
	Name          string
	AvatarURL     string
}

// Provider performs the browser redirect flow (authorization code).
type Provider interface {
	Name() string
	// AuthURL returns the provider consent URL.
	AuthURL(state, nonce, pkceVerifier string) string
	// Exchange trades the authorization code for a verified identity. form
	// carries extra callback parameters (Apple posts the user's name there).
	Exchange(ctx context.Context, code, pkceVerifier, nonce string, form url.Values) (*Identity, error)
}

// NativeVerifier verifies ID tokens obtained by native mobile SDKs (Sign in
// with Apple on iOS, Google Sign-In / Credential Manager on Android & iOS).
type NativeVerifier interface {
	VerifyIDToken(ctx context.Context, rawIDToken, nonce string) (*Identity, error)
}

// Field describes one setting in the admin UI.
type Field struct {
	Key       string
	Label     string
	Help      string
	Secret    bool
	Required  bool
	Multiline bool
}

// Settings are the effective values for one provider.
type Settings struct {
	Enabled bool
	Values  map[string]string
}

// Get returns a trimmed value.
func (s Settings) Get(key string) string { return strings.TrimSpace(s.Values[key]) }

// List returns a comma separated value as a slice.
func (s Settings) List(key string) []string {
	var out []string
	for _, v := range strings.Split(s.Values[key], ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Deps are shared dependencies handed to provider constructors.
type Deps struct {
	CallbackURL string // https://auth.example.com/v1/oauth/<name>/callback
	HTTPClient  *http.Client
}

// Definition registers a provider kind.
type Definition struct {
	Name           string
	DisplayName    string
	DocsURL        string
	ConsoleURL     string
	SupportsNative bool
	Fields         []Field
	New            func(s Settings, d Deps) (Provider, error)
}

// Common setting keys.
const (
	KeyClientID        = "client_id"
	KeyClientSecret    = "client_secret"
	KeyNativeClientIDs = "native_client_ids"
	KeyTeamID          = "team_id"
	KeyKeyID           = "key_id"
	KeyPrivateKey      = "private_key"
)

// Definitions lists every supported provider, in display order.
func Definitions() []*Definition {
	return []*Definition{googleDefinition(), appleDefinition(), githubDefinition(), discordDefinition()}
}

// ErrInvalidIDToken is returned when an ID token fails verification.
var ErrInvalidIDToken = errors.New("oauth: invalid id token")

func requireFields(s Settings, keys ...string) error {
	var missing []string
	for _, k := range keys {
		if s.Get(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return errors.New("missing required settings: " + strings.Join(missing, ", "))
	}
	return nil
}

// newHTTPClient is used for every call to identity providers: bounded time,
// no unbounded redirects.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// NewHTTPClient exposes the hardened client for wiring.
func NewHTTPClient() *http.Client { return newHTTPClient() }
