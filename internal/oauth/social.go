package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/oauth2"
)

// ---------------------------------------------------------------------------
// Discord

func discordDefinition() *Definition {
	return &Definition{
		Name:            "discord",
		DisplayName:     "Discord",
		DocsURL:         "https://discord.com/developers/docs/topics/oauth2",
		ConsoleURL:      "https://discord.com/developers/applications",
		AllowsLocalhost: true,
		CallbackField:   "OAuth2 > Redirects",
		Fields: []Field{
			{Key: KeyClientID, Label: "Client ID", Required: true, Help: "From the OAuth2 page of your Discord application. Add the callback URL above as a redirect."},
			{Key: KeyClientSecret, Label: "Client secret", Secret: true, Required: true},
		},
		New: newDiscord,
	}
}

type discord struct {
	conf    *oauth2.Config
	apiBase string
	deps    Deps
}

func newDiscord(s Settings, d Deps) (Provider, error) {
	if err := requireFields(s, KeyClientID, KeyClientSecret); err != nil {
		return nil, err
	}
	return &discord{
		conf: &oauth2.Config{
			ClientID:     s.Get(KeyClientID),
			ClientSecret: s.Get(KeyClientSecret),
			Endpoint: oauth2.Endpoint{ // #nosec G101 -- public endpoint URLs
				AuthURL:   "https://discord.com/oauth2/authorize",
				TokenURL:  "https://discord.com/api/oauth2/token",
				AuthStyle: oauth2.AuthStyleInHeader,
			},
			RedirectURL: d.CallbackURL,
			Scopes:      []string{"identify", "email"},
		},
		apiBase: "https://discord.com/api",
		deps:    d,
	}, nil
}

func (p *discord) Name() string { return "discord" }

func (p *discord) AuthURL(state, _, verifier string) string {
	return p.conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("prompt", "consent"))
}

type discordUser struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	GlobalName string `json:"global_name"`
	Email      string `json:"email"`
	Verified   bool   `json:"verified"`
	Avatar     string `json:"avatar"`
}

func (p *discord) Exchange(ctx context.Context, code, verifier, _ string, _ url.Values) (*Identity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.deps.HTTPClient)
	tok, err := p.conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("discord: exchange: %w", err)
	}
	var u discordUser
	if err := getJSON(ctx, p.deps.HTTPClient, p.apiBase+"/users/@me", tok.AccessToken, &u); err != nil {
		return nil, fmt.Errorf("discord: user: %w", err)
	}
	if u.ID == "" {
		return nil, fmt.Errorf("discord: empty user id")
	}
	name := u.GlobalName
	if name == "" {
		name = u.Username
	}
	id := &Identity{Provider: "discord", Subject: u.ID, Email: u.Email, EmailVerified: u.Verified && u.Email != "", Name: name}
	if u.Avatar != "" {
		id.AvatarURL = "https://cdn.discordapp.com/avatars/" + url.PathEscape(u.ID) + "/" + url.PathEscape(u.Avatar) + ".png"
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// GitHub

func githubDefinition() *Definition {
	return &Definition{
		Name:            "github",
		DisplayName:     "GitHub",
		DocsURL:         "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps",
		ConsoleURL:      "https://github.com/settings/developers",
		AllowsLocalhost: true,
		CallbackField:   "OAuth App > Authorization callback URL",
		Fields: []Field{
			{Key: KeyClientID, Label: "Client ID", Required: true, Help: "From an OAuth App. Set the callback URL above as the Authorization callback URL."},
			{Key: KeyClientSecret, Label: "Client secret", Secret: true, Required: true},
		},
		New: newGitHub,
	}
}

type github struct {
	conf    *oauth2.Config
	apiBase string
	deps    Deps
}

func newGitHub(s Settings, d Deps) (Provider, error) {
	if err := requireFields(s, KeyClientID, KeyClientSecret); err != nil {
		return nil, err
	}
	return &github{
		conf: &oauth2.Config{
			ClientID:     s.Get(KeyClientID),
			ClientSecret: s.Get(KeyClientSecret),
			Endpoint: oauth2.Endpoint{ // #nosec G101 -- public endpoint URLs
				AuthURL:   "https://github.com/login/oauth/authorize",
				TokenURL:  "https://github.com/login/oauth/access_token",
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL: d.CallbackURL,
			Scopes:      []string{"read:user", "user:email"},
		},
		apiBase: "https://api.github.com",
		deps:    d,
	}, nil
}

func (p *github) Name() string { return "github" }

func (p *github) AuthURL(state, _, verifier string) string {
	return p.conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (p *github) Exchange(ctx context.Context, code, verifier, _ string, _ url.Values) (*Identity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.deps.HTTPClient)
	tok, err := p.conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("github: exchange: %w", err)
	}
	var u githubUser
	if err := getJSON(ctx, p.deps.HTTPClient, p.apiBase+"/user", tok.AccessToken, &u); err != nil {
		return nil, fmt.Errorf("github: user: %w", err)
	}
	if u.ID == 0 {
		return nil, fmt.Errorf("github: empty user id")
	}
	var emails []githubEmail
	if err := getJSON(ctx, p.deps.HTTPClient, p.apiBase+"/user/emails", tok.AccessToken, &emails); err != nil {
		return nil, fmt.Errorf("github: emails: %w", err)
	}
	id := &Identity{Provider: "github", Subject: strconv.FormatInt(u.ID, 10), Name: u.Name, AvatarURL: u.AvatarURL}
	if id.Name == "" {
		id.Name = u.Login
	}
	// Only the primary *verified* address is trusted for account linking.
	for _, e := range emails {
		if e.Primary && e.Verified {
			id.Email, id.EmailVerified = e.Email, true
			break
		}
	}
	return id, nil
}

// ---------------------------------------------------------------------------

// getJSON fetches a JSON document with a bearer token and a 1 MiB cap.
func getJSON(ctx context.Context, client *http.Client, endpoint, accessToken string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "warden-auth")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
