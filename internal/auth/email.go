package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/i18n"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/store"
)

type emailTokenRecord struct {
	UserID string `json:"u"`
	Email  string `json:"e"`
	// PasswordFingerprint invalidates outstanding reset links as soon as the
	// password changes by any means.
	PasswordFingerprint string `json:"p,omitempty"`
}

func link(tmpl, token string) string {
	return strings.ReplaceAll(tmpl, "{token}", url.QueryEscape(token))
}

func passwordFingerprint(hash string) string {
	sum := sha256.Sum256([]byte("pwfp:" + hash))
	return hex.EncodeToString(sum[:8])
}

func (s *Service) queueVerificationEmail(ctx context.Context, tx *store.Store, u *domain.User) error {
	if u.Email == "" || u.EmailVerified() {
		return nil
	}
	tok := randtoken.New(32)
	if err := s.putJSON(ctx, "ev:"+randtoken.HashHex(tok), emailTokenRecord{UserID: u.ID.String(), Email: u.Email},
		s.cfg.Auth.EmailVerificationTTL); err != nil {
		return err
	}
	return s.Events.Email(ctx, tx, u.Email, s.locale(u), mailer.TemplateVerifyEmail, map[string]string{
		"Link":      link(s.Settings.Get().VerifyEmailURL, tok),
		"ExpiresIn": i18n.Duration(s.cfg.Auth.EmailVerificationTTL, s.locale(u)),
	})
}

// ResendVerification sends a new verification email to the signed-in user.
func (s *Service) ResendVerification(ctx context.Context, userID uuid.UUID) error {
	u, err := s.Store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.EmailVerified() || u.Email == "" {
		return nil
	}
	return s.Store.InTx(ctx, func(tx *store.Store) error { return s.queueVerificationEmail(ctx, tx, u) })
}

// VerifyEmail consumes a verification token.
func (s *Service) VerifyEmail(ctx context.Context, tok string, meta domain.RequestMeta) error {
	if tok == "" || len(tok) > 128 {
		return domain.ErrInvalidToken
	}
	var rec emailTokenRecord
	if err := s.takeJSON(ctx, "ev:"+randtoken.HashHex(tok), &rec); err != nil {
		return err
	}
	uid, err := uuid.Parse(rec.UserID)
	if err != nil {
		return domain.ErrInvalidToken
	}
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		u, err := tx.GetUserByIDForUpdate(ctx, uid)
		if err != nil {
			return err
		}
		// The email may have changed since the link was sent.
		if u.Email != rec.Email {
			return domain.ErrInvalidToken
		}
		if u.EmailVerified() {
			return nil
		}
		if err := tx.MarkEmailVerified(ctx, uid, time.Now()); err != nil {
			return err
		}
		return s.Events.Event(ctx, tx, events.UserEmailVerified, uid, map[string]any{"email": u.Email})
	})
	if errors.Is(err, domain.ErrNotFound) {
		return domain.ErrInvalidToken
	}
	if err == nil {
		s.audit(ctx, uid, "user.email_verified", meta, nil)
	}
	return err
}

// ForgotPassword emails a reset link. It always succeeds from the caller's
// point of view so it cannot be used to discover registered emails.
func (s *Service) ForgotPassword(ctx context.Context, rawEmail string, meta domain.RequestMeta) error {
	email, ok := normalizeEmail(rawEmail)
	if !ok {
		return nil
	}
	u, err := s.Store.GetUserByEmail(ctx, email)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if u.Disabled() {
		return nil
	}
	tok := randtoken.New(32)
	rec := emailTokenRecord{UserID: u.ID.String(), Email: u.Email, PasswordFingerprint: passwordFingerprint(u.PasswordHash)}
	if err := s.putJSON(ctx, "pr:"+randtoken.HashHex(tok), rec, s.cfg.Auth.PasswordResetTTL); err != nil {
		return err
	}
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		return s.Events.Email(ctx, tx, u.Email, s.locale(u), mailer.TemplateResetPassword, map[string]string{
			"Link":      link(s.Settings.Get().ResetPasswordURL, tok),
			"ExpiresIn": i18n.Duration(s.cfg.Auth.PasswordResetTTL, s.locale(u)),
		})
	})
	if err == nil {
		s.audit(ctx, u.ID, "user.password_reset_requested", meta, nil)
	}
	return err
}

// ResetPassword sets a new password with a reset token and signs out every
// session. Proving control of the inbox also verifies the email address.
func (s *Service) ResetPassword(ctx context.Context, tok, newPassword string, meta domain.RequestMeta) error {
	if tok == "" || len(tok) > 128 {
		return domain.ErrInvalidToken
	}
	key := "pr:" + randtoken.HashHex(tok)
	// Peek first so a weak password does not burn the link.
	var rec emailTokenRecord
	raw, err := s.Redis.Get(ctx, key).Bytes()
	if err != nil {
		return domain.ErrInvalidToken
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return domain.ErrInvalidToken
	}
	uid, err := uuid.Parse(rec.UserID)
	if err != nil {
		return domain.ErrInvalidToken
	}
	if err := s.checkNewPassword(ctx, newPassword, rec.Email); err != nil {
		return err
	}
	hash, err := s.hash(ctx, newPassword)
	if err != nil {
		return err
	}
	if err := s.takeJSON(ctx, key, &rec); err != nil { // consume (single use)
		return err
	}

	var revoked []uuid.UUID
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		u, err := tx.GetUserByIDForUpdate(ctx, uid)
		if err != nil {
			return err
		}
		fp := passwordFingerprint(u.PasswordHash)
		if u.Email != rec.Email || subtle.ConstantTimeCompare([]byte(fp), []byte(rec.PasswordFingerprint)) != 1 || u.Disabled() {
			return domain.ErrInvalidToken
		}
		if err := tx.SetPasswordHash(ctx, uid, hash); err != nil {
			return err
		}
		if !u.EmailVerified() {
			if err := tx.MarkEmailVerified(ctx, uid, time.Now()); err != nil {
				return err
			}
		}
		if revoked, err = s.revokeAll(ctx, tx, uid, uuid.Nil, domain.RevokePasswordReset); err != nil {
			return err
		}
		if err := s.Events.Event(ctx, tx, events.UserPasswordChange, uid, map[string]any{"via": "reset"}); err != nil {
			return err
		}
		return s.Events.Email(ctx, tx, u.Email, s.locale(u), mailer.TemplatePasswordChanged, map[string]string{"When": i18n.Time(time.Now(), s.locale(u))})
	})
	if errors.Is(err, domain.ErrNotFound) {
		return domain.ErrInvalidToken
	}
	if err != nil {
		return err
	}
	s.markRevoked(ctx, revoked...)
	s.Lockout.Reset(ctx, lockoutKey("pwd", rec.Email))
	s.audit(ctx, uid, "user.password_reset", meta, nil)
	return nil
}
