package auth

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/avatar"
	"github.com/fatihacan1/warden/internal/crypto/password"
	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/i18n"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/platform/objectstore"
	"github.com/fatihacan1/warden/internal/store"
)

// GetUser returns a user by id.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.Store.GetUserByID(ctx, id)
}

// AvatarURL resolves a stored avatar key to a URL ("" when none).
func (s *Service) AvatarURL(ctx context.Context, u *domain.User) string {
	if u.AvatarKey == "" {
		return ""
	}
	url, err := s.Objects.URL(ctx, u.AvatarKey)
	if err != nil {
		return ""
	}
	return url
}

// UpdateProfile changes mutable profile fields.
func (s *Service) UpdateProfile(ctx context.Context, userID uuid.UUID, name string) (*domain.User, error) {
	name = cleanName(name)
	err := s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.UpdateUserProfile(ctx, userID, name); err != nil {
			return err
		}
		return s.Events.Event(ctx, tx, events.UserUpdated, userID, map[string]any{"fields": []string{"name"}})
	})
	if err != nil {
		return nil, err
	}
	return s.Store.GetUserByID(ctx, userID)
}

// requireRecentAuth enforces step-up for sensitive changes on accounts that
// have no password to confirm with (social-only accounts).
func (s *Service) requireRecentAuth(ctx context.Context, userID, sid uuid.UUID) error {
	sess, err := s.Store.GetSession(ctx, sid)
	if err != nil || sess.UserID != userID {
		return domain.ErrReauthRequired
	}
	if time.Since(sess.CreatedAt) > s.cfg.Auth.RecentAuthWindow {
		return domain.ErrReauthRequired
	}
	return nil
}

func (s *Service) confirmIdentity(ctx context.Context, u *domain.User, sid uuid.UUID, currentPassword string) error {
	if !u.HasPassword() {
		return s.requireRecentAuth(ctx, u.ID, sid)
	}
	lk := lockoutKey("pwd", u.ID.String())
	if retry := s.Lockout.Check(ctx, lk); retry > 0 {
		return domain.ErrRateLimited.WithRetryAfter(retry)
	}
	ok, _, err := s.Hasher.Verify(ctx, currentPassword, u.PasswordHash)
	if errors.Is(err, password.ErrBusy) {
		return domain.ErrServerBusy.WithRetryAfter(2 * time.Second)
	}
	if err != nil {
		return err
	}
	if !ok {
		s.Lockout.Fail(ctx, lk)
		return domain.ErrInvalidCredentials.WithMessage("The current password is incorrect.").
			WithFields(map[string]string{"current_password": "Incorrect password."})
	}
	return nil
}

// ChangePassword sets a new password (or the first password for social-only
// accounts) and signs out every other session.
func (s *Service) ChangePassword(ctx context.Context, userID, sid uuid.UUID, current, next string, meta domain.RequestMeta) error {
	u, err := s.Store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.confirmIdentity(ctx, u, sid, current); err != nil {
		return err
	}
	if err := s.checkNewPassword(ctx, next, u.Email); err != nil {
		return err
	}
	hash, err := s.hash(ctx, next)
	if err != nil {
		return err
	}
	var revoked []uuid.UUID
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.SetPasswordHash(ctx, userID, hash); err != nil {
			return err
		}
		if revoked, err = s.revokeAll(ctx, tx, userID, sid, domain.RevokePasswordChange); err != nil {
			return err
		}
		if err := s.Events.Event(ctx, tx, events.UserPasswordChange, userID, map[string]any{"via": "change"}); err != nil {
			return err
		}
		return s.Events.Email(ctx, tx, u.Email, s.locale(u), mailer.TemplatePasswordChanged, map[string]string{"When": i18n.Time(time.Now(), s.locale(u))})
	})
	if err != nil {
		return err
	}
	s.markRevoked(ctx, revoked...)
	s.audit(ctx, userID, "user.password_changed", meta, nil)
	return nil
}

// DeleteAccount permanently deletes the user and everything linked to it.
func (s *Service) DeleteAccount(ctx context.Context, userID, sid uuid.UUID, currentPassword string, meta domain.RequestMeta) error {
	u, err := s.Store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.confirmIdentity(ctx, u, sid, currentPassword); err != nil {
		return err
	}
	sessions, err := s.Store.ListActiveSessions(ctx, userID)
	if err != nil {
		return err
	}
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.DeleteUser(ctx, userID); err != nil {
			return err
		}
		return s.Events.Event(ctx, tx, events.UserDeleted, userID, nil)
	})
	if err != nil {
		return err
	}
	ids := make([]uuid.UUID, 0, len(sessions))
	for _, sess := range sessions {
		ids = append(ids, sess.ID)
	}
	s.markRevoked(ctx, ids...)
	if u.AvatarKey != "" {
		if err := s.Objects.Delete(context.WithoutCancel(ctx), u.AvatarKey); err != nil {
			s.Log.Warn("avatar delete failed", "key", u.AvatarKey, "err", err)
		}
	}
	s.audit(ctx, userID, "user.deleted", meta, nil)
	return nil
}

// ListSessions returns the user's active sessions.
func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	return s.Store.ListActiveSessions(ctx, userID)
}

// ListIdentities returns linked social accounts.
func (s *Service) ListIdentities(ctx context.Context, userID uuid.UUID) ([]*domain.Identity, error) {
	return s.Store.ListIdentities(ctx, userID)
}

// UnlinkIdentity removes a social login, unless it is the last way in.
func (s *Service) UnlinkIdentity(ctx context.Context, userID uuid.UUID, provider string, meta domain.RequestMeta) error {
	err := s.Store.InTx(ctx, func(tx *store.Store) error {
		u, err := tx.GetUserByIDForUpdate(ctx, userID)
		if err != nil {
			return err
		}
		ids, err := tx.ListIdentities(ctx, userID)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(ids, func(i *domain.Identity) bool { return i.Provider == provider }) {
			return domain.ErrNotFound
		}
		if !u.HasPassword() && len(ids) <= 1 {
			return domain.ErrLastCredential
		}
		if err := tx.DeleteIdentity(ctx, userID, provider); err != nil {
			return err
		}
		return s.Events.Event(ctx, tx, events.IdentityUnlinked, userID, map[string]any{"provider": provider})
	})
	if err == nil {
		s.audit(ctx, userID, "identity.unlinked", meta, map[string]any{"provider": provider})
	}
	return err
}

// UploadAvatar validates, normalizes and stores a new profile picture.
func (s *Service) UploadAvatar(ctx context.Context, userID uuid.UUID, data []byte) (*domain.User, error) {
	if _, ok := s.Objects.(objectstore.Disabled); ok {
		return nil, domain.ErrFeatureDisabled.WithMessage("Avatar uploads require S3 storage.")
	}
	if int64(len(data)) > s.cfg.S3.AvatarMaxBytes {
		return nil, domain.ErrPayloadTooLarge
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	img, err := s.Avatars.Process(pctx, data)
	switch {
	case errors.Is(err, avatar.ErrUnsupported):
		return nil, domain.ErrUnsupportedMedia.WithMessage("Upload a JPEG, PNG, GIF or WebP image.")
	case errors.Is(err, avatar.ErrTooLarge):
		return nil, domain.ErrPayloadTooLarge.WithMessage("Image dimensions are too large.")
	case errors.Is(err, avatar.ErrBusy):
		return nil, domain.ErrServerBusy.WithRetryAfter(2 * time.Second)
	case err != nil:
		return nil, err
	}
	u, err := s.Store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	key := "avatars/" + userID.String() + "/" + randtoken.New(12) + ".jpg"
	if err := s.Objects.Put(ctx, key, "image/jpeg", img); err != nil {
		return nil, domain.ErrServiceUnavailable
	}
	if err := s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.UpdateUserAvatar(ctx, userID, key); err != nil {
			return err
		}
		return s.Events.Event(ctx, tx, events.UserUpdated, userID, map[string]any{"fields": []string{"avatar"}})
	}); err != nil {
		_ = s.Objects.Delete(context.WithoutCancel(ctx), key)
		return nil, err
	}
	if u.AvatarKey != "" {
		if err := s.Objects.Delete(context.WithoutCancel(ctx), u.AvatarKey); err != nil {
			s.Log.Warn("old avatar delete failed", "key", u.AvatarKey, "err", err)
		}
	}
	u.AvatarKey = key
	return u, nil
}

// DeleteAvatar removes the profile picture.
func (s *Service) DeleteAvatar(ctx context.Context, userID uuid.UUID) error {
	u, err := s.Store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.AvatarKey == "" {
		return nil
	}
	if err := s.Store.UpdateUserAvatar(ctx, userID, ""); err != nil {
		return err
	}
	if err := s.Objects.Delete(ctx, u.AvatarKey); err != nil {
		s.Log.Warn("avatar delete failed", "key", u.AvatarKey, "err", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Administrative operations (admin UI and gRPC).

// SetDisabled disables or re-enables an account. Disabling revokes every
// session immediately.
func (s *Service) SetDisabled(ctx context.Context, userID uuid.UUID, disabled bool, actor string) error {
	var revoked []uuid.UUID
	err := s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.SetDisabled(ctx, userID, disabled); err != nil {
			return err
		}
		evt := events.UserEnabled
		if disabled {
			evt = events.UserDisabled
			var err error
			if revoked, err = s.revokeAll(ctx, tx, userID, uuid.Nil, domain.RevokeAccountDisabled); err != nil {
				return err
			}
		}
		return s.Events.Event(ctx, tx, evt, userID, map[string]any{"actor": actor})
	})
	if err != nil {
		return err
	}
	s.markRevoked(ctx, revoked...)
	s.audit(ctx, userID, map[bool]string{true: "admin.user_disabled", false: "admin.user_enabled"}[disabled],
		domain.RequestMeta{}, map[string]any{"actor": actor})
	return nil
}

var roleRe = regexp.MustCompile(`^[a-z][a-z0-9_:.-]{0,63}$`)

func cleanRoles(roles []string) ([]string, error) {
	clean := make([]string, 0, len(roles))
	for _, r := range roles {
		if !roleRe.MatchString(r) {
			return nil, domain.ErrValidation.WithMessage("Roles must be lowercase identifiers (a-z, 0-9, _ : . -).")
		}
		if !slices.Contains(clean, r) {
			clean = append(clean, r)
		}
	}
	if len(clean) > 32 {
		return nil, domain.ErrValidation.WithMessage("Too many roles.")
	}
	return clean, nil
}

// SetRoles replaces a user's roles. Roles appear in access tokens; changes
// apply on the next token refresh.
func (s *Service) SetRoles(ctx context.Context, userID uuid.UUID, roles []string, actor string) error {
	clean, err := cleanRoles(roles)
	if err != nil {
		return err
	}
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.SetRoles(ctx, userID, clean); err != nil {
			return err
		}
		return s.Events.Event(ctx, tx, events.UserUpdated, userID, map[string]any{"fields": []string{"roles"}, "roles": clean, "actor": actor})
	})
	if err == nil {
		s.audit(ctx, userID, "admin.roles_changed", domain.RequestMeta{}, map[string]any{"roles": clean, "actor": actor})
	}
	return err
}

// CreateUserInput is a user created by a backend (server API, gRPC) rather
// than by the user signing up.
type CreateUserInput struct {
	Email         string
	Password      string // optional: without one the user signs in socially or resets it
	Name          string
	Roles         []string
	EmailVerified bool
	Locale        string
}

// CreateUser creates an account on behalf of an operator. It ignores the
// sign-up toggle (that only governs self-service sign-up) but applies the
// password policy.
func (s *Service) CreateUser(ctx context.Context, in CreateUserInput, actor string, meta domain.RequestMeta) (*domain.User, error) {
	email, ok := normalizeEmail(in.Email)
	if !ok {
		return nil, domain.ErrValidation.WithFields(map[string]string{"email": "Enter a valid email address."})
	}
	roles, err := cleanRoles(in.Roles)
	if err != nil {
		return nil, err
	}
	u := &domain.User{ID: uuid.Must(uuid.NewV7()), Email: email, Name: cleanName(in.Name), Roles: roles, Locale: firstLocale(in.Locale)}
	if in.Password != "" {
		if err := s.checkNewPassword(ctx, in.Password, email); err != nil {
			return nil, err
		}
		if u.PasswordHash, err = s.hash(ctx, in.Password); err != nil {
			return nil, err
		}
	}
	if in.EmailVerified {
		now := time.Now()
		u.EmailVerifiedAt = &now
	}
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		if err := s.Events.Event(ctx, tx, events.UserCreated, u.ID, map[string]any{"email": u.Email, "method": "server", "actor": actor}); err != nil {
			return err
		}
		if !in.EmailVerified && u.HasPassword() {
			return s.queueVerificationEmail(ctx, tx, u)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, u.ID, "admin.user_created", meta, map[string]any{"actor": actor, "roles": roles})
	return s.Store.GetUserByID(ctx, u.ID)
}

// AdminUpdateProfile changes a user's name on behalf of an operator.
func (s *Service) AdminUpdateProfile(ctx context.Context, userID uuid.UUID, name, actor string) (*domain.User, error) {
	u, err := s.UpdateProfile(ctx, userID, name)
	if err == nil {
		s.audit(ctx, userID, "admin.profile_changed", domain.RequestMeta{}, map[string]any{"actor": actor})
	}
	return u, err
}

// FindUserByEmail returns the user with this email.
func (s *Service) FindUserByEmail(ctx context.Context, rawEmail string) (*domain.User, error) {
	email, ok := normalizeEmail(rawEmail)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return s.Store.GetUserByEmail(ctx, email)
}
