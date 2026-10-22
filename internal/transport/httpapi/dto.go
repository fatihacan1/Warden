package httpapi

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/fatihacan1/warden/internal/auth"
	"github.com/fatihacan1/warden/internal/domain"
)

// UserView is the public representation of a user.
type UserView struct {
	ID            string     `json:"id"`
	Email         string     `json:"email,omitempty"`
	EmailVerified bool       `json:"email_verified"`
	Name          string     `json:"name"`
	AvatarURL     string     `json:"avatar_url,omitempty"`
	Roles         []string   `json:"roles"`
	Locale        string     `json:"locale"`
	MFAEnabled    bool       `json:"mfa_enabled"`
	HasPassword   bool       `json:"has_password"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSignInAt  *time.Time `json:"last_sign_in_at,omitempty"`
}

func (s *Server) userView(ctx context.Context, u *domain.User) UserView {
	return UserView{
		ID: u.ID.String(), Email: u.Email, EmailVerified: u.EmailVerified(), Name: u.Name,
		AvatarURL: s.auth.AvatarURL(ctx, u), Roles: u.Roles, Locale: u.Locale, MFAEnabled: u.MFAEnabled(),
		HasPassword: u.HasPassword(), CreatedAt: u.CreatedAt, LastSignInAt: u.LastSignInAt,
	}
}

// AuthResponse is returned by sign-up, sign-in, MFA, refresh and OAuth.
type AuthResponse struct {
	Status   string          `json:"status"` // "authenticated" | "mfa_required" | "verification_required"
	User     *UserView       `json:"user,omitempty"`
	Tokens   *auth.TokenPair `json:"tokens,omitempty"`
	MFAToken string          `json:"mfa_token,omitempty"`
	NewUser  bool            `json:"new_user,omitempty"`
}

// cookieMode reports whether the client asked for the refresh token in an
// HttpOnly cookie instead of the body (recommended for browser apps).
func cookieMode(c fiber.Ctx) bool {
	return c.Get("X-Auth-Mode") == "cookie"
}

func (s *Server) respondAuth(c fiber.Ctx, status int, r *auth.Result) error {
	resp := AuthResponse{NewUser: r.NewUser}
	switch {
	case r.MFARequired:
		resp.Status, resp.MFAToken = "mfa_required", r.MFAToken
	case r.Tokens == nil:
		resp.Status = "verification_required"
	default:
		resp.Status = "authenticated"
		pair := *r.Tokens
		if cookieMode(c) {
			s.setRefreshCookie(c, pair.RefreshToken)
			pair.RefreshToken = ""
		}
		resp.Tokens = &pair
	}
	if r.User != nil {
		v := s.userView(c.Context(), r.User)
		resp.User = &v
	}
	return c.Status(status).JSON(resp)
}

func (s *Server) setRefreshCookie(c fiber.Ctx, value string) {
	c.Cookie(&fiber.Cookie{
		Name:     s.cfg.HTTP.RefreshCookie,
		Value:    value,
		Path:     "/v1/auth",
		Domain:   s.cfg.HTTP.CookieDomain,
		MaxAge:   int(s.cfg.Token.RefreshTTL.Seconds()),
		Secure:   s.cfg.HTTP.CookieSecure,
		HTTPOnly: true,
		SameSite: s.cfg.HTTP.CookieSameSite,
	})
}

func (s *Server) clearRefreshCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name: s.cfg.HTTP.RefreshCookie, Value: "", Path: "/v1/auth", Domain: s.cfg.HTTP.CookieDomain,
		MaxAge: -1, Expires: time.Unix(0, 0), Secure: s.cfg.HTTP.CookieSecure, HTTPOnly: true, SameSite: s.cfg.HTTP.CookieSameSite,
	})
}

// decode parses a JSON body. An empty body decodes to the zero value.
func decode(c fiber.Ctx, v any) error {
	body := c.Body()
	if len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return domain.ErrValidation.WithMessage("Malformed JSON body.")
	}
	return nil
}

type SessionView struct {
	ID         string    `json:"id"`
	Current    bool      `json:"current"`
	UserAgent  string    `json:"user_agent"`
	IP         string    `json:"ip"`
	AMR        []string  `json:"amr"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type IdentityView struct {
	Provider   string     `json:"provider"`
	Email      string     `json:"email,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}
