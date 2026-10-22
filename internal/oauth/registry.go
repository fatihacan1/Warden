package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/store"
)

// SettingsStore persists admin-managed provider settings.
type SettingsStore interface {
	ListProviderSettings(ctx context.Context) ([]store.ProviderSettingRow, error)
	UpsertProviderSetting(ctx context.Context, r store.ProviderSettingRow) error
	DeleteProviderSetting(ctx context.Context, provider string) error
}

// Source tells where a provider's effective settings come from.
type Source string

const (
	SourceNone  Source = "none"
	SourceEnv   Source = "env"
	SourceAdmin Source = "admin"
)

// Status is a provider's state as shown in the admin UI. Secret values are
// never included, only whether they are set.
type Status struct {
	Def         *Definition
	Enabled     bool
	Active      bool // enabled and constructed successfully
	Source      Source
	Error       string
	CallbackURL string
	Values      map[string]string // non-secret values
	SecretSet   map[string]bool
}

type snapshot struct {
	providers map[string]Provider
	statuses  []Status
}

// Registry holds the live provider set. Settings saved in the admin UI
// override environment variables; deleting them falls back to the env.
type Registry struct {
	defs      []*Definition
	env       map[string]Settings
	store     SettingsStore
	box       *secretbox.Box
	publicURL string
	client    *http.Client
	log       *slog.Logger
	current   atomic.Pointer[snapshot]
}

func NewRegistry(cfg config.OAuthConfig, publicURL string, st SettingsStore, box *secretbox.Box, client *http.Client, log *slog.Logger) *Registry {
	return &Registry{
		defs:      Definitions(),
		env:       envSettings(cfg),
		store:     st,
		box:       box,
		publicURL: publicURL,
		client:    client,
		log:       log,
	}
}

func envSettings(cfg config.OAuthConfig) map[string]Settings {
	conv := func(p config.ProviderEnv) Settings {
		natives := ""
		for i, n := range p.NativeClientIDs {
			if i > 0 {
				natives += ","
			}
			natives += n
		}
		return Settings{Enabled: p.Enabled, Values: map[string]string{
			KeyClientID: p.ClientID, KeyClientSecret: p.ClientSecret, KeyNativeClientIDs: natives,
			KeyTeamID: p.TeamID, KeyKeyID: p.KeyID, KeyPrivateKey: p.PrivateKey,
		}}
	}
	return map[string]Settings{
		"google": conv(cfg.Google), "apple": conv(cfg.Apple), "discord": conv(cfg.Discord), "github": conv(cfg.GitHub),
	}
}

// Register adds a custom provider definition (call before Reload). It is the
// extension point for providers Warden does not ship, and is used by tests.
func (r *Registry) Register(def *Definition) {
	r.defs = append(r.defs, def)
}

// CallbackURL returns the redirect URI to register with the provider.
func (r *Registry) CallbackURL(name string) string {
	return r.publicURL + "/v1/oauth/" + name + "/callback"
}

func (r *Registry) label(name string) string { return "provider:" + name }

func (r *Registry) loadDB(ctx context.Context) (map[string]Settings, error) {
	rows, err := r.store.ListProviderSettings(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Settings, len(rows))
	for _, row := range rows {
		plain, err := r.box.Open(row.Config, r.label(row.Provider))
		if err != nil {
			return nil, fmt.Errorf("decrypt %s settings: %w", row.Provider, err)
		}
		values := map[string]string{}
		if err := json.Unmarshal(plain, &values); err != nil {
			return nil, fmt.Errorf("decode %s settings: %w", row.Provider, err)
		}
		out[row.Provider] = Settings{Enabled: row.Enabled, Values: values}
	}
	return out, nil
}

// Reload rebuilds the provider set from env + database.
func (r *Registry) Reload(ctx context.Context) error {
	db, err := r.loadDB(ctx)
	if err != nil {
		return err
	}
	snap := &snapshot{providers: map[string]Provider{}}
	for _, def := range r.defs {
		st := Status{Def: def, Source: SourceNone, CallbackURL: r.CallbackURL(def.Name),
			Values: map[string]string{}, SecretSet: map[string]bool{}}
		s, ok := db[def.Name]
		switch {
		case ok:
			st.Source = SourceAdmin
		case r.env[def.Name].Enabled || hasAnyValue(r.env[def.Name]):
			s, st.Source = r.env[def.Name], SourceEnv
		}
		if s.Values == nil {
			s.Values = map[string]string{}
		}
		for _, f := range def.Fields {
			if f.Secret {
				st.SecretSet[f.Key] = s.Get(f.Key) != ""
			} else {
				st.Values[f.Key] = s.Get(f.Key)
			}
		}
		st.Enabled = s.Enabled
		if s.Enabled {
			p, err := def.New(s, Deps{CallbackURL: st.CallbackURL, HTTPClient: r.client})
			if err != nil {
				st.Error = err.Error()
				r.log.Error("identity provider misconfigured", "provider", def.Name, "err", err)
			} else {
				snap.providers[def.Name] = p
				st.Active = true
			}
		}
		snap.statuses = append(snap.statuses, st)
	}
	r.current.Store(snap)
	return nil
}

func hasAnyValue(s Settings) bool {
	for _, v := range s.Values {
		if v != "" {
			return true
		}
	}
	return false
}

// Run reloads periodically so admin changes made on another replica apply
// everywhere.
func (r *Registry) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Reload(ctx); err != nil {
				r.log.Error("identity provider reload failed", "err", err)
			}
		}
	}
}

// Get returns an enabled provider.
func (r *Registry) Get(name string) (Provider, bool) {
	snap := r.current.Load()
	if snap == nil {
		return nil, false
	}
	p, ok := snap.providers[name]
	return p, ok
}

// Enabled lists active providers in display order.
func (r *Registry) Enabled() []*Definition {
	snap := r.current.Load()
	if snap == nil {
		return nil
	}
	var out []*Definition
	for _, st := range snap.statuses {
		if st.Active {
			out = append(out, st.Def)
		}
	}
	return out
}

// Statuses returns every provider's status for the admin UI.
func (r *Registry) Statuses() []Status {
	if snap := r.current.Load(); snap != nil {
		return snap.statuses
	}
	return nil
}

// Definition returns a provider definition by name.
func (r *Registry) Definition(name string) *Definition {
	for _, d := range r.defs {
		if d.Name == name {
			return d
		}
	}
	return nil
}

// Save stores admin settings. Empty secret fields keep their current value,
// so secrets never have to be sent back to the browser. When enabling, the
// settings are validated by constructing the provider first.
func (r *Registry) Save(ctx context.Context, name string, enabled bool, submitted map[string]string) error {
	def := r.Definition(name)
	if def == nil {
		return fmt.Errorf("unknown provider %q", name)
	}
	current := map[string]string{}
	db, err := r.loadDB(ctx)
	if err != nil {
		return err
	}
	if s, ok := db[name]; ok {
		maps.Copy(current, s.Values)
	} else {
		maps.Copy(current, r.env[name].Values)
	}
	values := map[string]string{}
	for _, f := range def.Fields {
		v, ok := submitted[f.Key]
		if f.Secret && v == "" {
			v = current[f.Key]
		} else if !ok {
			v = current[f.Key]
		}
		if len(v) > 16<<10 {
			return fmt.Errorf("%s is too long", f.Label)
		}
		values[f.Key] = v
	}
	s := Settings{Enabled: enabled, Values: values}
	if enabled {
		if _, err := def.New(s, Deps{CallbackURL: r.CallbackURL(name), HTTPClient: r.client}); err != nil {
			return err
		}
	}
	plain, err := json.Marshal(values)
	if err != nil {
		return err
	}
	sealed, err := r.box.Seal(plain, r.label(name))
	if err != nil {
		return err
	}
	if err := r.store.UpsertProviderSetting(ctx, store.ProviderSettingRow{Provider: name, Enabled: enabled, Config: sealed}); err != nil {
		return err
	}
	return r.Reload(ctx)
}

// Reset removes admin overrides so the provider falls back to env settings.
func (r *Registry) Reset(ctx context.Context, name string) error {
	if r.Definition(name) == nil {
		return fmt.Errorf("unknown provider %q", name)
	}
	if err := r.store.DeleteProviderSetting(ctx, name); err != nil {
		return err
	}
	return r.Reload(ctx)
}
