package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/crypto/password"
	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/store"
)

// SignUpInput is the sign-up request.
type SignUpInput struct {
	Email    string
	Password string
	Name     string
}

// SignUp creates a password account.
func (s *Service) SignUp(ctx context.Context, in SignUpInput, meta domain.RequestMeta) (*Result, error) {
	if !s.Settings.Get().AllowSignup {
		return nil, domain.ErrSignupDisabled
	}
	email, ok := normalizeEmail(in.Email)
	if !ok {
		return nil, domain.ErrValidation.WithFields(map[string]string{"email": "Enter a valid email address."})
	}
	if err := s.checkNewPassword(ctx, in.Password, email); err != nil {
		return nil, err
	}
	hash, err := s.hash(ctx, in.Password)
	if err != nil {
		return nil, err
	}
	u := &domain.User{ID: uuid.Must(uuid.NewV7()), Email: email, PasswordHash: hash, Name: cleanName(in.Name), Roles: []string{}}

	var pair *TokenPair
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		if err := s.Events.Event(ctx, tx, events.UserCreated, u.ID, map[string]any{"email": u.Email, "method": "password"}); err != nil {
			return err
		}
		if err := s.queueVerificationEmail(ctx, tx, u); err != nil {
			return err
		}
		if s.Settings.Get().RequireEmailVerification {
			return nil
		}
		pair, err = s.issueSession(ctx, tx, u, []string{domain.AMRPassword}, meta)
		return err
	})
	if err != nil {
		if errors.Is(err, domain.ErrEmailTaken) {
			s.metric("sign_up", "email_taken")
		}
		return nil, err
	}
	s.metric("sign_up", "success")
	s.audit(ctx, u.ID, "user.sign_up", meta, map[string]any{"method": "password"})
	return &Result{User: u, Tokens: pair, NewUser: true, VerificationRequired: pair == nil}, nil
}

// SignIn authenticates with email + password.
//
// Every failure path returns the same error and spends the same Argon2 cost,
// so neither the response nor its timing reveals whether an email exists.
func (s *Service) SignIn(ctx context.Context, rawEmail, pw string, meta domain.RequestMeta) (*Result, error) {
	email, ok := normalizeEmail(rawEmail)
	if !ok || pw == "" || len(pw) > s.cfg.Password.MaxLength {
		s.metric("sign_in", "invalid")
		return nil, domain.ErrInvalidCredentials
	}
	lk := lockoutKey("pwd", email)
	if retry := s.Lockout.Check(ctx, lk); retry > 0 {
		s.metric("sign_in", "locked")
		return nil, domain.ErrRateLimited.WithMessage("Too many failed attempts. Please try again later.").WithRetryAfter(retry)
	}

	u, err := s.Store.GetUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	if u == nil || !u.HasPassword() {
		if err := s.Hasher.DummyVerify(ctx, pw); errors.Is(err, password.ErrBusy) {
			return nil, domain.ErrServerBusy.WithRetryAfter(2 * time.Second)
		}
		s.Lockout.Fail(ctx, lk)
		s.metric("sign_in", "invalid")
		s.audit(ctx, uuid.Nil, "user.sign_in_failed", meta, map[string]any{"reason": "unknown_account"})
		return nil, domain.ErrInvalidCredentials
	}

	match, rehash, err := s.Hasher.Verify(ctx, pw, u.PasswordHash)
	if errors.Is(err, password.ErrBusy) {
		return nil, domain.ErrServerBusy.WithRetryAfter(2 * time.Second)
	}
	if err != nil {
		return nil, err
	}
	if !match {
		n := s.Lockout.Fail(ctx, lk)
		s.metric("sign_in", "invalid")
		s.audit(ctx, u.ID, "user.sign_in_failed", meta, map[string]any{"reason": "bad_password", "failures": n})
		return nil, domain.ErrInvalidCredentials
	}
	s.Lockout.Reset(ctx, lk)

	// Only reveal account state once the password is proven.
	if u.Disabled() {
		s.metric("sign_in", "disabled")
		return nil, domain.ErrAccountDisabled
	}
	if s.Settings.Get().RequireEmailVerification && !u.EmailVerified() {
		s.metric("sign_in", "unverified")
		return nil, domain.ErrEmailNotVerified
	}
	if rehash {
		if h, err := s.Hasher.Hash(ctx, pw); err == nil {
			if err := s.Store.SetPasswordHash(ctx, u.ID, h); err != nil {
				s.Log.Warn("password rehash failed", "err", err)
			}
		}
	}

	res, err := s.startSession(ctx, u, []string{domain.AMRPassword}, meta)
	if err != nil {
		return nil, err
	}
	if res.MFARequired {
		s.metric("sign_in", "mfa_required")
	} else {
		s.metric("sign_in", "success")
		s.audit(ctx, u.ID, "user.sign_in", meta, map[string]any{"method": "password"})
	}
	return res, nil
}

// Refresh rotates a refresh token and returns a new token pair.
//
// Each refresh token is single use. Presenting an already rotated token
// outside the grace window means it was copied: the whole session (token
// family) is revoked, logging out both the attacker and the victim, who then
// signs in again (RFC 9700 section 4.14.2).
func (s *Service) Refresh(ctx context.Context, raw string, meta domain.RequestMeta) (*Result, error) {
	if raw == "" || len(raw) > 256 {
		return nil, domain.ErrInvalidToken
	}
	hash := randtoken.Hash(raw)
	for range 2 {
		sess, matchedPrev, err := s.Store.FindSessionByRefreshHash(ctx, hash)
		if errors.Is(err, domain.ErrNotFound) {
			s.metric("refresh", "invalid")
			return nil, domain.ErrInvalidToken
		}
		if err != nil {
			return nil, err
		}
		now := time.Now()
		if !sess.Active(now) {
			s.metric("refresh", "inactive")
			return nil, domain.ErrInvalidToken
		}
		prev, resetRotated := sess.RefreshHash, true
		if matchedPrev {
			if sess.RotatedAt == nil || now.Sub(*sess.RotatedAt) > s.cfg.Token.RefreshReuseGrace {
				s.handleReuse(ctx, sess, meta)
				return nil, domain.ErrInvalidToken
			}
			// Lost-response retry within the grace window: rotate again from
			// the previous token without extending the window.
			prev, resetRotated = sess.PrevRefreshHash, false
		}

		u, err := s.Store.GetUserByID(ctx, sess.UserID)
		if err != nil {
			return nil, err
		}
		if u.Disabled() {
			return nil, domain.ErrAccountDisabled
		}

		next := randtoken.New(32)
		ok, err := s.Store.RotateRefreshToken(ctx, sess.ID, sess.RefreshHash, prev, randtoken.Hash(next),
			now.Add(s.cfg.Token.RefreshTTL), meta.IP, meta.UserAgent, resetRotated)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue // concurrent rotation; re-read and decide again
		}
		pair, err := s.accessToken(u, sess.ID, sess.AMR)
		if err != nil {
			return nil, err
		}
		pair.RefreshToken = next
		s.metric("refresh", "success")
		return &Result{User: u, Tokens: pair}, nil
	}
	s.metric("refresh", "conflict")
	return nil, domain.ErrInvalidToken
}

func (s *Service) handleReuse(ctx context.Context, sess *domain.Session, meta domain.RequestMeta) {
	s.metric("refresh", "reuse_detected")
	s.Log.Warn("refresh token reuse detected, revoking session", "user_id", sess.UserID, "session_id", sess.ID, "ip", meta.IP)
	err := s.Store.InTx(ctx, func(tx *store.Store) error {
		revoked, err := tx.RevokeSession(ctx, sess.UserID, sess.ID, domain.RevokeReuseDetected)
		if err != nil || !revoked {
			return err
		}
		return s.Events.Event(ctx, tx, events.SessionRevoked, sess.UserID,
			map[string]any{"session_ids": []uuid.UUID{sess.ID}, "reason": domain.RevokeReuseDetected})
	})
	if err != nil {
		s.Log.Error("revoke after reuse failed", "err", err)
	}
	s.markRevoked(ctx, sess.ID)
	s.audit(ctx, sess.UserID, "session.refresh_reuse_detected", meta, map[string]any{"session_id": sess.ID})
}

// SignOut revokes the session identified by a refresh token. Unknown tokens
// are ignored (sign-out is idempotent).
func (s *Service) SignOut(ctx context.Context, raw string, meta domain.RequestMeta) error {
	if raw == "" || len(raw) > 256 {
		return nil
	}
	sess, _, err := s.Store.FindSessionByRefreshHash(ctx, randtoken.Hash(raw))
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.RevokeSession(ctx, sess.UserID, sess.ID, domain.RevokeSignOut, meta)
}

// RevokeSession revokes one session of a user.
func (s *Service) RevokeSession(ctx context.Context, userID, sid uuid.UUID, reason string, meta domain.RequestMeta) error {
	var revoked bool
	err := s.Store.InTx(ctx, func(tx *store.Store) error {
		var err error
		revoked, err = tx.RevokeSession(ctx, userID, sid, reason)
		if err != nil || !revoked {
			return err
		}
		return s.Events.Event(ctx, tx, events.SessionRevoked, userID, map[string]any{"session_ids": []uuid.UUID{sid}, "reason": reason})
	})
	if err != nil {
		return err
	}
	if revoked {
		s.markRevoked(ctx, sid)
		s.audit(ctx, userID, "session.revoked", meta, map[string]any{"session_id": sid, "reason": reason})
	}
	return nil
}

// RevokeAllSessions revokes every session of a user except keep.
func (s *Service) RevokeAllSessions(ctx context.Context, userID, keep uuid.UUID, reason string, meta domain.RequestMeta) (int, error) {
	var ids []uuid.UUID
	err := s.Store.InTx(ctx, func(tx *store.Store) error {
		var err error
		ids, err = s.revokeAll(ctx, tx, userID, keep, reason)
		return err
	})
	if err != nil {
		return 0, err
	}
	s.markRevoked(ctx, ids...)
	if len(ids) > 0 {
		s.audit(ctx, userID, "session.revoked_all", meta, map[string]any{"count": len(ids), "reason": reason})
	}
	return len(ids), nil
}
