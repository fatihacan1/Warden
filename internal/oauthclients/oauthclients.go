// Package oauthclients manages the service clients that use the OAuth 2.0
// client credentials grant (RFC 6749 section 4.4) to get short-lived access
// tokens for service-to-service calls.
//
// Design, in the spirit of internal/accesstokens:
//
//   - The client secret is 256 random bits, shown once and stored as SHA-256.
//   - A client may only request scopes and audiences from its allow lists.
//   - Rotation keeps the previous secret valid for a grace period, so a fleet
//     of services can roll to the new secret without downtime.
//   - State is read from the database on every authentication, so revoking a
//     client takes effect on every replica at once. Access tokens already
//     issued stay valid until they expire (at most one hour).
package oauthclients

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
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

const (
	// IDPrefix starts every client id, SecretPrefix every secret, so secret
	// scanners and humans can recognize them.
	IDPrefix     = "svc_"
	SecretPrefix = "wcs_"

	DefaultTTL = 15 * time.Minute
	MinTTL     = time.Minute
	MaxTTL     = time.Hour
	// MaxGrace bounds how long a rotated-out secret may stay valid.
	MaxGrace = 7 * 24 * time.Hour

	maxScopes    = 50
	maxScopeLen  = 64
	maxAudiences = 20
	maxAudLen    = 200
)

// GraceOptions are the rotation grace periods the UI offers.
var GraceOptions = []struct {
	Key   string
	Label string
	D     time.Duration
}{
	{"0", "Revoke the old secret now", 0},
	{"1h", "Keep the old secret for 1 hour", time.Hour},
	{"24h", "Keep the old secret for 24 hours", 24 * time.Hour},
}

// Client is a service client without its secret.
type Client struct {
	ID                  uuid.UUID
	Name                string
	ClientID            string
	SecretHint          string
	PrevSecretExpiresAt *time.Time
	AllowedScopes       []string
	AllowedAudiences    []string
	TTL                 time.Duration
	CreatedAt           time.Time
	SecretRotatedAt     *time.Time
	LastUsedAt          *time.Time
	RevokedAt           *time.Time
}

// TTLMinutes is the access token lifetime in whole minutes.
func (c *Client) TTLMinutes() int { return int(c.TTL / time.Minute) }

// Status is active or revoked.
func (c *Client) Status() string {
	if c.RevokedAt != nil {
		return "revoked"
	}
	return "active"
}

// PrevSecretActive reports whether a rotated-out secret still works.
func (c *Client) PrevSecretActive(now time.Time) bool {
	return c.RevokedAt == nil && c.PrevSecretExpiresAt != nil && now.Before(*c.PrevSecretExpiresAt)
}

func fromRow(r *store.OAuthClientRow) *Client {
	return &Client{ID: r.ID, Name: r.Name, ClientID: r.ClientID, SecretHint: r.SecretHint, PrevSecretExpiresAt: r.PrevSecretExpiresAt,
		AllowedScopes: r.AllowedScopes, AllowedAudiences: r.AllowedAudiences, TTL: time.Duration(r.TokenTTLSeconds) * time.Second,
		CreatedAt: r.CreatedAt, SecretRotatedAt: r.SecretRotatedAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt}
}

// Store persists clients.
type Store interface {
	ListOAuthClients(ctx context.Context) ([]*store.OAuthClientRow, error)
	GetOAuthClient(ctx context.Context, id uuid.UUID) (*store.OAuthClientRow, error)
	GetOAuthClientByClientID(ctx context.Context, clientID string) (*store.OAuthClientRow, error)
	CreateOAuthClient(ctx context.Context, r *store.OAuthClientRow) error
	RotateOAuthClientSecret(ctx context.Context, id uuid.UUID, hash []byte, hint string, grace time.Duration) error
	RevokeOAuthClient(ctx context.Context, id uuid.UUID) error
	TouchOAuthClient(ctx context.Context, id uuid.UUID) error
}

type Manager struct {
	store           Store
	log             *slog.Logger
	defaultAudience []string
	now             func() time.Time
	touched         sync.Map
}

// NewManager builds a manager. defaultAudience is used for clients created
// without an explicit audience list (normally TOKEN_AUDIENCE).
func NewManager(st Store, defaultAudience []string, log *slog.Logger) *Manager {
	return &Manager{store: st, log: log, defaultAudience: defaultAudience, now: time.Now}
}

// DefaultAudience is what a new client is allowed when none is given.
func (m *Manager) DefaultAudience() []string { return slices.Clone(m.defaultAudience) }

// List returns clients, active first.
func (m *Manager) List(ctx context.Context) ([]*Client, error) {
	rows, err := m.store.ListOAuthClients(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Client, 0, len(rows))
	for _, r := range rows {
		out = append(out, fromRow(r))
	}
	return out, nil
}

// Get returns one client by its internal id.
func (m *Manager) Get(ctx context.Context, id uuid.UUID) (*Client, error) {
	r, err := m.store.GetOAuthClient(ctx, id)
	if err != nil {
		return nil, err
	}
	return fromRow(r), nil
}

// Active returns the client with this public client id if it exists and is
// not revoked. Introspection uses it to refuse tokens of revoked clients.
func (m *Manager) Active(ctx context.Context, clientID string) (*Client, error) {
	r, err := m.store.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if r.RevokedAt != nil {
		return nil, ErrInvalidClient
	}
	return fromRow(r), nil
}

// Input is a new client.
type Input struct {
	Name      string
	Scopes    []string
	Audiences []string
	TTL       time.Duration // 0 = DefaultTTL
}

// ValidScope reports whether s is a legal scope token (RFC 6749 section 3.3):
// printable ASCII without space, double quote or backslash.
func ValidScope(s string) bool {
	if s == "" || len(s) > maxScopeLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < 0x21 || b > 0x7e || b == '"' || b == '\\' {
			return false
		}
	}
	return true
}

func cleanList(in []string, max, maxLen int, what string, valid func(string) bool) ([]string, error) {
	out := []string{}
	for _, v := range in {
		if v = strings.TrimSpace(v); v == "" || slices.Contains(out, v) {
			continue
		}
		if len(v) > maxLen || !valid(v) {
			return nil, domain.ErrValidation.WithMessage("Invalid " + what + ": " + v)
		}
		out = append(out, v)
	}
	if len(out) > max {
		return nil, domain.ErrValidation.WithMessage("Too many " + what + "s.")
	}
	return out, nil
}

func validAudience(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f })
}

// SplitList splits a comma, space or newline separated form value.
func SplitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}

// Create makes a client and returns its secret, which is never shown again.
func (m *Manager) Create(ctx context.Context, in Input) (string, *Client, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 80 {
		return "", nil, domain.ErrValidation.WithMessage("Name the client (1 to 80 characters), for example \"billing-service\".")
	}
	scopes, err := cleanList(in.Scopes, maxScopes, maxScopeLen, "scope", ValidScope)
	if err != nil {
		return "", nil, err
	}
	auds, err := cleanList(in.Audiences, maxAudiences, maxAudLen, "audience", validAudience)
	if err != nil {
		return "", nil, err
	}
	if len(auds) == 0 {
		auds = m.DefaultAudience()
	}
	if len(auds) == 0 {
		return "", nil, domain.ErrValidation.WithMessage("Give the client at least one audience.")
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < MinTTL || ttl > MaxTTL {
		return "", nil, domain.ErrValidation.WithMessage("Token lifetime must be between 1 minute and 1 hour.")
	}
	secret := SecretPrefix + randtoken.New(32)
	row := &store.OAuthClientRow{
		ID: uuid.Must(uuid.NewV7()), Name: in.Name, ClientID: IDPrefix + randtoken.New(12),
		SecretHash: hashSecret(secret), SecretHint: hint(secret), AllowedScopes: scopes, AllowedAudiences: auds,
		TokenTTLSeconds: int(ttl / time.Second),
	}
	if err := m.store.CreateOAuthClient(ctx, row); err != nil {
		return "", nil, err
	}
	return secret, fromRow(row), nil
}

// Rotate installs a new secret and returns it. With grace > 0 the previous
// secret keeps working for that long, so deployments can roll over.
func (m *Manager) Rotate(ctx context.Context, id uuid.UUID, grace time.Duration) (string, error) {
	if grace < 0 || grace > MaxGrace {
		return "", domain.ErrValidation.WithMessage("Grace period must be between 0 and 7 days.")
	}
	secret := SecretPrefix + randtoken.New(32)
	if err := m.store.RotateOAuthClientSecret(ctx, id, hashSecret(secret), hint(secret), grace); err != nil {
		return "", err
	}
	return secret, nil
}

// Revoke disables a client immediately.
func (m *Manager) Revoke(ctx context.Context, id uuid.UUID) error {
	return m.store.RevokeOAuthClient(ctx, id)
}

func hashSecret(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func hint(secret string) string { return secret[:len(SecretPrefix)+3] + "…" + secret[len(secret)-3:] }

// Errors returned by Authenticate and Resolve. They map to the RFC 6749
// section 5.2 error codes.
var (
	// ErrInvalidClient covers unknown client, wrong secret and revoked
	// client alike, so callers cannot tell them apart.
	ErrInvalidClient = errors.New("invalid client")
	ErrInvalidScope  = errors.New("invalid scope")
	// ErrInvalidTarget is the RFC 8707 error for a disallowed audience.
	ErrInvalidTarget = errors.New("invalid target")
)

// dummyHash is compared against when the client does not exist, so lookups
// of unknown clients cost the same as wrong secrets.
var dummyHash = hashSecret("warden-unknown-client")

// Authenticate checks client credentials. Every failure is ErrInvalidClient;
// any other error is an infrastructure problem.
func (m *Manager) Authenticate(ctx context.Context, clientID, secret string) (*Client, error) {
	var row *store.OAuthClientRow
	if len(clientID) <= 64 && len(secret) <= 256 {
		var err error
		row, err = m.store.GetOAuthClientByClientID(ctx, clientID)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return nil, err
		}
	}
	cur, prev := dummyHash, make([]byte, sha256.Size)
	var prevValid bool
	if row != nil {
		cur = row.SecretHash
		if row.PrevSecretHash != nil && row.PrevSecretExpiresAt != nil && m.now().Before(*row.PrevSecretExpiresAt) {
			prev, prevValid = row.PrevSecretHash, true
		}
	}
	got := hashSecret(secret)
	okCur := subtle.ConstantTimeCompare(got, cur)
	okPrev := subtle.ConstantTimeCompare(got, prev)
	if row == nil || row.RevokedAt != nil || (okCur&1)|(okPrev&1&b2i(prevValid)) != 1 {
		return nil, ErrInvalidClient
	}
	c := fromRow(row)
	m.touch(c)
	return c, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Resolve applies the client's allow lists to a request. scope is the
// space-separated request value ("" = every allowed scope); audiences is the
// "audience"/"resource" request values ("" = the client's first audience).
func (c *Client) Resolve(scope string, audiences []string) (scopes, aud []string, err error) {
	if fields := strings.Fields(scope); len(fields) > 0 {
		for _, s := range fields {
			if !ValidScope(s) || !slices.Contains(c.AllowedScopes, s) {
				return nil, nil, ErrInvalidScope
			}
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
	} else {
		scopes = slices.Clone(c.AllowedScopes)
	}
	for _, a := range audiences {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		if !slices.Contains(c.AllowedAudiences, a) {
			return nil, nil, ErrInvalidTarget
		}
		if !slices.Contains(aud, a) {
			aud = append(aud, a)
		}
	}
	if len(aud) == 0 {
		if len(c.AllowedAudiences) == 0 {
			return nil, nil, ErrInvalidTarget
		}
		aud = []string{c.AllowedAudiences[0]}
	}
	return scopes, aud, nil
}

func (m *Manager) touch(c *Client) {
	now := m.now()
	if last, ok := m.touched.Load(c.ID); ok && now.Sub(last.(time.Time)) < 30*time.Second {
		return
	}
	m.touched.Store(c.ID, now)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.store.TouchOAuthClient(ctx, c.ID); err != nil {
			m.log.Warn("oauth client touch failed", "err", err)
		}
	}()
}
