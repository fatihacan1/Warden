package domain

import (
	"slices"
	"time"

	"github.com/google/uuid"
)

// User is an account. Email is empty for identities that did not share one.
type User struct {
	ID              uuid.UUID
	Email           string
	EmailVerifiedAt *time.Time
	PasswordHash    string
	Name            string
	AvatarKey       string
	Roles           []string
	TOTPSecret      []byte // encrypted at rest
	TOTPEnabledAt   *time.Time
	TOTPLastStep    int64
	DisabledAt      *time.Time
	LastSignInAt    *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (u *User) EmailVerified() bool { return u.EmailVerifiedAt != nil }
func (u *User) HasPassword() bool   { return u.PasswordHash != "" }
func (u *User) MFAEnabled() bool    { return u.TOTPEnabledAt != nil }
func (u *User) Disabled() bool      { return u.DisabledAt != nil }
func (u *User) HasRole(r string) bool {
	return slices.Contains(u.Roles, r)
}

// Identity links a user to an external identity provider account.
type Identity struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Provider   string
	Subject    string
	Email      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// Session is a refresh-token family: one signed-in device.
type Session struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	RefreshHash       []byte
	PrevRefreshHash   []byte
	RotatedAt         *time.Time
	AMR               []string
	UserAgent         string
	IP                string
	CreatedAt         time.Time
	LastUsedAt        time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	RevokeReason      string
}

// Active reports whether the session can still be refreshed at time now.
func (s *Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt) && now.Before(s.AbsoluteExpiresAt)
}

// RequestMeta describes the client that issued a request; it is recorded on
// sessions and audit events.
type RequestMeta struct {
	IP        string
	UserAgent string
	RequestID string
}

// Authentication methods (RFC 8176 "amr" values where they exist).
const (
	AMRPassword = "pwd"
	AMRMFA      = "mfa"
	AMROTP      = "otp"
)

// AMROAuth returns the amr value for a federated sign-in.
func AMROAuth(provider string) string { return "oauth:" + provider }

// Session revoke reasons.
const (
	RevokeSignOut         = "sign_out"
	RevokeUser            = "revoked_by_user"
	RevokeAdmin           = "revoked_by_admin"
	RevokeReuseDetected   = "refresh_token_reuse"
	RevokePasswordReset   = "password_reset"
	RevokePasswordChange  = "password_changed"
	RevokeAccountDisabled = "account_disabled"
	RevokeAccountLinked   = "account_linked"
)
