package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fatihacan1/warden/internal/domain"
)

const userColumns = `id, email, email_verified_at, password_hash, name, avatar_key, roles, locale,
	totp_secret, totp_enabled_at, totp_last_step, disabled_at, last_sign_in_at, created_at, updated_at`

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	var email, pwHash, avatar *string
	err := row.Scan(&u.ID, &email, &u.EmailVerifiedAt, &pwHash, &u.Name, &avatar, &u.Roles, &u.Locale,
		&u.TOTPSecret, &u.TOTPEnabledAt, &u.TOTPLastStep, &u.DisabledAt, &u.LastSignInAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	u.Email, u.PasswordHash, u.AvatarKey = deref(email), deref(pwHash), deref(avatar)
	if u.Roles == nil {
		u.Roles = []string{}
	}
	return &u, nil
}

// CreateUser inserts a user. Returns domain.ErrEmailTaken on duplicates.
func (s *Store) CreateUser(ctx context.Context, u *domain.User) error {
	if u.Roles == nil {
		u.Roles = []string{}
	}
	err := s.db.QueryRow(ctx, `
		INSERT INTO users (id, email, email_verified_at, password_hash, name, avatar_key, roles, locale)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, updated_at`,
		u.ID, nullable(u.Email), u.EmailVerifiedAt, nullable(u.PasswordHash), u.Name, nullable(u.AvatarKey), u.Roles, u.Locale,
	).Scan(&u.CreatedAt, &u.UpdatedAt)
	return mapErr(err)
}

func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// GetUserByIDForUpdate locks the row for the rest of the transaction.
func (s *Store) GetUserByIDForUpdate(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1 FOR UPDATE`, id))
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, strings.ToLower(email)))
}

func (s *Store) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]*domain.User, error) {
	rows, err := s.db.Query(ctx, `SELECT `+userColumns+` FROM users WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ListUsers returns a page of users, newest first, optionally filtered by an
// email/name substring. It is used by the admin UI.
func (s *Store) ListUsers(ctx context.Context, query string, limit, offset int) ([]*domain.User, int, error) {
	where, args := "", []any{}
	if q := strings.TrimSpace(query); q != "" {
		like := "%" + escapeLike(strings.ToLower(q)) + "%"
		args = append(args, like)
		where = `WHERE email LIKE $1 OR lower(name) LIKE $1 OR id::text = $2`
		args = append(args, q)
	}
	var total int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	n := len(args)
	rows, err := s.db.Query(ctx, `SELECT `+userColumns+` FROM users `+where+
		` ORDER BY created_at DESC LIMIT $`+itoa(n-1)+` OFFSET $`+itoa(n), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

func (s *Store) UpdateUserProfile(ctx context.Context, id uuid.UUID, name string) error {
	return execOne(ctx, s.db, `UPDATE users SET name = $2, updated_at = now() WHERE id = $1`, id, name)
}

func (s *Store) UpdateUserLocale(ctx context.Context, id uuid.UUID, locale string) error {
	return execOne(ctx, s.db, `UPDATE users SET locale = $2, updated_at = now() WHERE id = $1`, id, locale)
}

// SeenDevice records a sign-in from a device and reports whether the device
// is new for this user.
func (s *Store) SeenDevice(ctx context.Context, userID uuid.UUID, fingerprint []byte, label string) (bool, error) {
	var inserted bool
	err := s.db.QueryRow(ctx, `
		INSERT INTO user_devices (user_id, fingerprint, label) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, fingerprint) DO UPDATE SET last_seen = now(), label = EXCLUDED.label
		RETURNING (xmax = 0)`, userID, fingerprint, cleanText(label, 120)).Scan(&inserted)
	return inserted, mapErr(err)
}

// HasDevices reports whether any device is recorded for the user.
func (s *Store) HasDevices(ctx context.Context, userID uuid.UUID) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_devices WHERE user_id = $1)`, userID).Scan(&ok)
	return ok, err
}

// DeleteStaleDevices forgets devices unused since before; signing in from
// them again counts as a new device.
func (s *Store) DeleteStaleDevices(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM user_devices WHERE last_seen < $1`, before)
	return tag.RowsAffected(), err
}

func (s *Store) UpdateUserAvatar(ctx context.Context, id uuid.UUID, key string) error {
	return execOne(ctx, s.db, `UPDATE users SET avatar_key = $2, updated_at = now() WHERE id = $1`, id, nullable(key))
}

func (s *Store) SetPasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	return execOne(ctx, s.db, `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, id, nullable(hash))
}

func (s *Store) MarkEmailVerified(ctx context.Context, id uuid.UUID, at time.Time) error {
	return execOne(ctx, s.db, `UPDATE users SET email_verified_at = COALESCE(email_verified_at, $2), updated_at = now() WHERE id = $1`, id, at)
}

func (s *Store) SetRoles(ctx context.Context, id uuid.UUID, roles []string) error {
	return execOne(ctx, s.db, `UPDATE users SET roles = $2, updated_at = now() WHERE id = $1`, id, roles)
}

func (s *Store) SetDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	return execOne(ctx, s.db, `
		UPDATE users SET disabled_at = CASE WHEN $2 THEN COALESCE(disabled_at, now()) ELSE NULL END,
		updated_at = now() WHERE id = $1`, id, disabled)
}

func (s *Store) TouchSignIn(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET last_sign_in_at = now() WHERE id = $1`, id)
	return err
}

// EnableTOTP stores the encrypted secret and marks MFA as enabled.
func (s *Store) EnableTOTP(ctx context.Context, id uuid.UUID, secret []byte, step int64) error {
	return execOne(ctx, s.db, `
		UPDATE users SET totp_secret = $2, totp_enabled_at = now(), totp_last_step = $3, updated_at = now()
		WHERE id = $1 AND totp_enabled_at IS NULL`, id, secret, step)
}

func (s *Store) DisableTOTP(ctx context.Context, id uuid.UUID) error {
	if err := execOne(ctx, s.db, `
		UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = 0, updated_at = now()
		WHERE id = $1`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, id)
	return err
}

// AdvanceTOTPStep records the last accepted time step. It only succeeds when
// step is newer than the stored one, which makes every code single-use even
// across concurrent requests.
func (s *Store) AdvanceTOTPStep(ctx context.Context, id uuid.UUID, step int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2`, id, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, id uuid.UUID, hashes [][]byte) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO recovery_codes (user_id, code_hash) SELECT $1, unnest($2::bytea[])`, id, hashes)
	return err
}

// UseRecoveryCode atomically consumes a recovery code.
func (s *Store) UseRecoveryCode(ctx context.Context, id uuid.UUID, hash []byte) (bool, error) {
	tag, err := s.db.Exec(ctx, `
		UPDATE recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`, id, hash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, id uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL`, id).Scan(&n)
	return n, err
}

func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.db, `DELETE FROM users WHERE id = $1`, id)
}

// UserStats powers the admin dashboard.
type UserStats struct {
	Total, Verified, MFA, Disabled, NewLast24h, ActiveSessions int
}

func (s *Store) UserStats(ctx context.Context) (UserStats, error) {
	var st UserStats
	err := s.db.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE email_verified_at IS NOT NULL),
		       count(*) FILTER (WHERE totp_enabled_at IS NOT NULL),
		       count(*) FILTER (WHERE disabled_at IS NOT NULL),
		       count(*) FILTER (WHERE created_at > now() - interval '24 hours'),
		       (SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now())
		FROM users`).Scan(&st.Total, &st.Verified, &st.MFA, &st.Disabled, &st.NewLast24h, &st.ActiveSessions)
	return st, err
}

func execOne(ctx context.Context, db DBTX, sql string, args ...any) error {
	tag, err := db.Exec(ctx, sql, args...)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
