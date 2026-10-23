// Package accesstokens issues the scoped, expiring tokens that automation
// and AI agents use to manage an instance through the admin API.
//
// Design, in the spirit of RevenueCat's API keys:
//
//   - Permissions per resource, each none, read or write (write includes
//     read). Nothing is granted by default.
//   - Every token expires: 1 hour, 1 day, 1 week, 30 or 90 days. There is no
//     "never", so a forgotten token cannot live forever.
//   - Optional IP ranges per token.
//   - Shown once, stored as SHA-256, checked against the database on every
//     request so revocation is immediate on every replica.
//   - Tokens cannot mint tokens and cannot change admin access settings, so a
//     leaked token cannot escalate or lock you out.
package accesstokens

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/store"
)

// Prefix starts every token, so secret scanners (GitHub, gitleaks) and
// humans can recognize one.
const Prefix = "wat_"

// Levels.
const (
	None  = ""
	Read  = "read"
	Write = "write"
)

// Resource is something a token can be granted access to.
type Resource struct {
	Key   string
	Title string
	Read  string // what read allows ("" = no read level)
	Write string // what write allows ("" = no write level)
}

// Resources lists every grantable resource, in UI order.
var Resources = []Resource{
	{"users", "Users", "List and search users, see sessions, linked accounts and their security log", "Create users, change name, roles, language, disable or enable, sign out everywhere"},
	{"email_templates", "Email templates", "Templates in every language, with previews", "Edit and reset templates"},
	{"settings", "Settings", "Feature toggles and policies", "Change them; admin access settings stay in the UI"},
	{"webhooks", "Webhooks", "List endpoints and deliveries", "Create, change, test and delete endpoints"},
	{"api_keys", "API keys", "List publishable and secret keys (never their values)", "Create and revoke keys"},
	{"providers", "Sign-in providers", "See which providers are on and their callback URLs (never secrets)", ""},
	{"audit", "Audit log", "The security and admin audit log", ""},
	{"stats", "Statistics", "User counts, sessions, outbox health", ""},
}

// Durations a token can be created for.
var Durations = []struct {
	Key   string
	Label string
	D     time.Duration
}{
	{"1h", "1 hour", time.Hour},
	{"1d", "1 day", 24 * time.Hour},
	{"7d", "1 week", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour},
	{"90d", "90 days", 90 * 24 * time.Hour},
}

// Token is an access token without its secret.
type Token struct {
	ID            uuid.UUID
	Name          string
	Hint          string
	Scopes        map[string]string
	AllowedIPs    []string
	ExpiresAt     time.Time
	CreatedAt     time.Time
	CreatedFromIP string
	LastUsedAt    *time.Time
	LastUsedIP    string
	RevokedAt     *time.Time
}

// Status is active, expired or revoked.
func (t *Token) Status(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case !now.Before(t.ExpiresAt):
		return "expired"
	}
	return "active"
}

// Allows reports whether the token grants level on resource.
func (t *Token) Allows(resource, level string) bool {
	got := t.Scopes[resource]
	return got == Write || (level == Read && got == Read)
}

// ScopeList renders scopes as "users:write" strings, for display and logs.
func (t *Token) ScopeList() []string {
	var out []string
	for _, r := range Resources {
		if l := t.Scopes[r.Key]; l != None {
			out = append(out, r.Key+":"+l)
		}
	}
	return out
}

func fromRow(r *store.AccessTokenRow) *Token {
	return &Token{ID: r.ID, Name: r.Name, Hint: r.Hint, Scopes: r.Scopes, AllowedIPs: r.AllowedIPs, ExpiresAt: r.ExpiresAt,
		CreatedAt: r.CreatedAt, CreatedFromIP: r.CreatedFromIP, LastUsedAt: r.LastUsedAt, LastUsedIP: r.LastUsedIP, RevokedAt: r.RevokedAt}
}

// Store persists tokens.
type Store interface {
	ListAccessTokens(ctx context.Context) ([]*store.AccessTokenRow, error)
	GetAccessTokenByHash(ctx context.Context, hash []byte) (*store.AccessTokenRow, error)
	CreateAccessToken(ctx context.Context, r *store.AccessTokenRow) error
	RevokeAccessToken(ctx context.Context, id uuid.UUID) error
	TouchAccessToken(ctx context.Context, id uuid.UUID, ip string) error
}

type Manager struct {
	store   Store
	log     *slog.Logger
	now     func() time.Time
	touched sync.Map
}

func NewManager(st Store, log *slog.Logger) *Manager {
	return &Manager{store: st, log: log, now: time.Now}
}

// List returns recent tokens, active first.
func (m *Manager) List(ctx context.Context) ([]*Token, error) {
	rows, err := m.store.ListAccessTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Token, 0, len(rows))
	for _, r := range rows {
		out = append(out, fromRow(r))
	}
	return out, nil
}

// Input is a new token request.
type Input struct {
	Name       string
	Duration   string            // one of Durations[].Key
	Scopes     map[string]string // resource -> read|write
	AllowedIPs []string
	CreatedBy  string // IP of the admin creating it
}

// Create issues a token and returns its value, which is never shown again.
func (m *Manager) Create(ctx context.Context, in Input) (string, *Token, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 80 {
		return "", nil, domain.ErrValidation.WithMessage("Name the token (1 to 80 characters), for example \"Claude: email templates\".")
	}
	var ttl time.Duration
	for _, d := range Durations {
		if d.Key == in.Duration {
			ttl = d.D
		}
	}
	if ttl == 0 {
		return "", nil, domain.ErrValidation.WithMessage("Choose how long the token is valid: 1 hour, 1 day, 1 week, 30 or 90 days.")
	}
	scopes := map[string]string{}
	for _, r := range Resources {
		switch l := in.Scopes[r.Key]; {
		case l == None:
		case l == Read && r.Read != "", l == Write && r.Write != "":
			scopes[r.Key] = l
		default:
			return "", nil, domain.ErrValidation.WithMessage("Invalid permission for " + r.Title + ".")
		}
	}
	for k := range in.Scopes {
		if !slices.ContainsFunc(Resources, func(r Resource) bool { return r.Key == k }) {
			return "", nil, domain.ErrValidation.WithMessage("Unknown permission " + k + ".")
		}
	}
	if len(scopes) == 0 {
		return "", nil, domain.ErrValidation.WithMessage("Grant at least one permission. Start with read access and add write only where needed.")
	}
	ips := []string{}
	for _, ip := range in.AllowedIPs {
		if ip = strings.TrimSpace(ip); ip == "" || slices.Contains(ips, ip) {
			continue
		}
		if _, _, err := net.ParseCIDR(ip); err != nil && net.ParseIP(ip) == nil {
			return "", nil, domain.ErrValidation.WithMessage("Allowed IPs must be addresses or CIDR ranges: " + ip)
		}
		ips = append(ips, ip)
	}
	raw := Prefix + randtoken.New(32)
	sum := sha256.Sum256([]byte(raw))
	row := &store.AccessTokenRow{ID: uuid.Must(uuid.NewV7()), Name: in.Name, TokenHash: sum[:], Hint: raw[:len(Prefix)+4] + "…" + raw[len(raw)-4:],
		Scopes: scopes, AllowedIPs: ips, ExpiresAt: m.now().Add(ttl), CreatedFromIP: in.CreatedBy}
	if err := m.store.CreateAccessToken(ctx, row); err != nil {
		return "", nil, err
	}
	return raw, fromRow(row), nil
}

// Revoke disables a token immediately.
func (m *Manager) Revoke(ctx context.Context, id uuid.UUID) error {
	return m.store.RevokeAccessToken(ctx, id)
}

// Errors returned by Authenticate. Messages are safe to show the caller.
var (
	ErrInvalid   = errors.New("invalid access token")
	ErrExpired   = errors.New("access token expired")
	ErrRevoked   = errors.New("access token revoked")
	ErrIPBlocked = errors.New("access token not allowed from this address")
)

// Authenticate checks a presented token against the database.
func (m *Manager) Authenticate(ctx context.Context, raw, ip string) (*Token, error) {
	if !strings.HasPrefix(raw, Prefix) || len(raw) > 128 {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256([]byte(raw))
	row, err := m.store.GetAccessTokenByHash(ctx, sum[:])
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	t := fromRow(row)
	switch t.Status(m.now()) {
	case "revoked":
		return nil, ErrRevoked
	case "expired":
		return nil, ErrExpired
	}
	if len(t.AllowedIPs) > 0 && !ipIn(ip, t.AllowedIPs) {
		return nil, ErrIPBlocked
	}
	m.touch(t, ip)
	return t, nil
}

func (m *Manager) touch(t *Token, ip string) {
	now := m.now()
	if last, ok := m.touched.Load(t.ID); ok && now.Sub(last.(time.Time)) < 30*time.Second {
		return
	}
	m.touched.Store(t.ID, now)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.store.TouchAccessToken(ctx, t.ID, ip); err != nil {
			m.log.Warn("access token touch failed", "err", err)
		}
	}()
}

func ipIn(ip string, entries []string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, e := range entries {
		if _, n, err := net.ParseCIDR(e); err == nil && n.Contains(addr) {
			return true
		}
		if other := net.ParseIP(e); other != nil && other.Equal(addr) {
			return true
		}
	}
	return false
}
