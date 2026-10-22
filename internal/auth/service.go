// Package auth contains Warden's business logic: sign-up, sign-in, sessions,
// refresh token rotation, email verification, password reset, MFA, social
// sign-in and account management. Transports (HTTP, gRPC, admin) are thin
// layers on top of Service.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/fatihacan1/warden/internal/avatar"
	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/crypto/password"
	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/oauth"
	"github.com/fatihacan1/warden/internal/observability"
	"github.com/fatihacan1/warden/internal/platform/objectstore"
	"github.com/fatihacan1/warden/internal/ratelimit"
	"github.com/fatihacan1/warden/internal/settings"
	"github.com/fatihacan1/warden/internal/store"
	"github.com/fatihacan1/warden/internal/token"
)

// Deps are the collaborators of Service.
type Deps struct {
	Config   *config.Config
	Store    *store.Store
	Redis    *redis.Client
	Hasher   *password.Hasher
	Breach   *password.BreachChecker // nil disables the breach check
	Tokens   *token.Issuer
	Events   *events.Writer
	Lockout  *ratelimit.Lockout
	Box      *secretbox.Box
	OAuth    *oauth.Registry
	Flow     *oauth.Flow
	Objects  objectstore.Store
	Avatars  *avatar.Processor
	Metrics  *observability.Metrics
	Log      *slog.Logger
	Settings *settings.Manager
}

// Service implements every authentication use case.
type Service struct {
	Deps
	cfg *config.Config
}

func New(d Deps) *Service {
	return &Service{Deps: d, cfg: d.Config}
}

// TokenPair is returned on every successful authentication.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	SessionID    string    `json:"session_id"`
}

// Result is the outcome of a sign-up / sign-in step.
type Result struct {
	User                 *domain.User
	Tokens               *TokenPair
	MFARequired          bool
	MFAToken             string
	VerificationRequired bool
	NewUser              bool
}

// ---------------------------------------------------------------------------
// Helpers shared by the use cases.

func normalizeEmail(raw string) (string, bool) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if len(e) < 3 || len(e) > 254 || strings.ContainsAny(e, " \t\r\n<>\"'") {
		return "", false
	}
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e {
		return "", false
	}
	local, host, ok := strings.Cut(e, "@")
	if !ok || local == "" || len(local) > 64 || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return "", false
	}
	return e, true
}

func cleanName(n string) string {
	n = strings.TrimSpace(strings.ToValidUTF8(n, ""))
	n = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, n)
	if utf8.RuneCountInString(n) > 100 {
		n = string([]rune(n)[:100])
	}
	return n
}

// lockoutKey avoids storing raw emails in Redis.
func lockoutKey(kind, id string) string { return kind + ":" + randtoken.HashHex(id) }

func (s *Service) metric(event, result string) {
	if s.Metrics != nil {
		s.Metrics.Auth(event, result)
	}
}

// audit records a security event. Failures are logged, never returned: the
// audit trail must not take authentication down.
func (s *Service) audit(ctx context.Context, userID uuid.UUID, typ string, meta domain.RequestMeta, data map[string]any) {
	e := store.AuditEvent{Type: typ, IP: meta.IP, UserAgent: meta.UserAgent, Metadata: data}
	if userID != uuid.Nil {
		e.UserID = &userID
	}
	if err := s.Store.InsertAudit(context.WithoutCancel(ctx), e); err != nil {
		s.Log.Warn("audit write failed", "type", typ, "err", err)
	}
}

// checkNewPassword applies the password policy and the optional breach check.
func (s *Service) checkNewPassword(ctx context.Context, pw, email string) error {
	policy := password.Policy{MinLength: s.Settings.Get().PasswordMinLength, MaxLength: s.cfg.Password.MaxLength}
	if p := policy.Problem(pw, email); p != "" {
		return domain.ErrWeakPassword.WithMessage(p).WithFields(map[string]string{"password": p})
	}
	if s.Breach != nil && s.Settings.Get().CheckBreachedPasswords {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		breached, err := s.Breach.Breached(cctx, pw)
		if err != nil {
			s.Log.Warn("breached password check unavailable (fail open)", "err", err)
		} else if breached {
			return domain.ErrBreachedPassword
		}
	}
	return nil
}

func (s *Service) hash(ctx context.Context, pw string) (string, error) {
	h, err := s.Hasher.Hash(ctx, pw)
	if errors.Is(err, password.ErrBusy) {
		return "", domain.ErrServerBusy.WithRetryAfter(2 * time.Second)
	}
	return h, err
}

// issueSession creates a session row inside tx and signs an access token.
func (s *Service) issueSession(ctx context.Context, tx *store.Store, u *domain.User, amr []string, meta domain.RequestMeta) (*TokenPair, error) {
	now := time.Now()
	refresh := randtoken.New(32)
	sess := &domain.Session{
		ID:                uuid.Must(uuid.NewV7()),
		UserID:            u.ID,
		RefreshHash:       randtoken.Hash(refresh),
		AMR:               amr,
		UserAgent:         meta.UserAgent,
		IP:                meta.IP,
		CreatedAt:         now,
		ExpiresAt:         now.Add(s.cfg.Token.RefreshTTL),
		AbsoluteExpiresAt: now.Add(s.cfg.Token.SessionMaxAge),
	}
	if err := tx.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	if err := tx.TouchSignIn(ctx, u.ID); err != nil {
		return nil, err
	}
	if err := s.Events.Event(ctx, tx, events.UserSignedIn, u.ID, map[string]any{"session_id": sess.ID, "amr": amr}); err != nil {
		return nil, err
	}
	pair, err := s.accessToken(u, sess.ID, amr)
	if err != nil {
		return nil, err
	}
	pair.RefreshToken = refresh
	return pair, nil
}

func (s *Service) accessToken(u *domain.User, sid uuid.UUID, amr []string) (*TokenPair, error) {
	raw, exp, err := s.Tokens.Issue(token.Subject{
		UserID: u.ID, SessionID: sid, Email: u.Email, EmailVerified: u.EmailVerified(), Roles: u.Roles, AMR: amr,
	})
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken: raw, TokenType: "Bearer", ExpiresAt: exp,
		ExpiresIn: int(time.Until(exp).Round(time.Second).Seconds()), SessionID: sid.String(),
	}, nil
}

// startSession runs the final sign-in step for a verified user: MFA challenge
// if enabled, otherwise a new session.
func (s *Service) startSession(ctx context.Context, u *domain.User, amr []string, meta domain.RequestMeta) (*Result, error) {
	if u.MFAEnabled() {
		tok, err := s.createMFAChallenge(ctx, u.ID, amr)
		if err != nil {
			return nil, err
		}
		return &Result{User: u, MFARequired: true, MFAToken: tok}, nil
	}
	var pair *TokenPair
	err := s.Store.InTx(ctx, func(tx *store.Store) error {
		var err error
		pair, err = s.issueSession(ctx, tx, u, amr, meta)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &Result{User: u, Tokens: pair}, nil
}

// markRevoked publishes revoked session ids to Redis so online checks
// (gRPC VerifyAccessToken, /v1/me) reject their access tokens immediately.
func (s *Service) markRevoked(ctx context.Context, ids ...uuid.UUID) {
	if len(ids) == 0 {
		return
	}
	ttl := s.cfg.Token.AccessTTL + time.Minute
	pipe := s.Redis.Pipeline()
	for _, id := range ids {
		pipe.Set(ctx, "revoked:sid:"+id.String(), 1, ttl)
	}
	if _, err := pipe.Exec(context.WithoutCancel(ctx)); err != nil {
		s.Log.Warn("failed to publish session revocation", "err", err)
	}
}

// SessionRevoked is a fast check against the Redis revocation list. It fails
// open (returns false) when Redis is unavailable: access tokens are short
// lived and their signature is still verified.
func (s *Service) SessionRevoked(ctx context.Context, sid uuid.UUID) bool {
	n, err := s.Redis.Exists(ctx, "revoked:sid:"+sid.String()).Result()
	if err != nil {
		s.Log.Warn("revocation check unavailable", "err", err)
		return false
	}
	return n > 0
}

// SessionActive is the authoritative (database) session check.
func (s *Service) SessionActive(ctx context.Context, sid uuid.UUID) (bool, error) {
	if s.SessionRevoked(ctx, sid) {
		return false, nil
	}
	sess, err := s.Store.GetSession(ctx, sid)
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return sess.Active(time.Now()), nil
}

// revokeAll revokes every session of a user except keep and records it.
func (s *Service) revokeAll(ctx context.Context, tx *store.Store, userID, keep uuid.UUID, reason string) ([]uuid.UUID, error) {
	ids, err := tx.RevokeUserSessions(ctx, userID, keep, reason)
	if err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		if err := s.Events.Event(ctx, tx, events.SessionRevoked, userID, map[string]any{"session_ids": ids, "reason": reason}); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// putJSON / takeJSON store short-lived one-time records in Redis.
func (s *Service) putJSON(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Redis.Set(ctx, key, b, ttl).Err()
}

func (s *Service) takeJSON(ctx context.Context, key string, v any) error {
	b, err := s.Redis.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return domain.ErrInvalidToken
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		h := int(d / time.Hour)
		if h == 1 {
			return "1 hour"
		}
		return strconv.Itoa(h) + " hours"
	default:
		m := int(d / time.Minute)
		if m == 1 {
			return "1 minute"
		}
		return strconv.Itoa(m) + " minutes"
	}
}
