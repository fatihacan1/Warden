package httpapi

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/apikeys"
	"github.com/fatihacan1/warden/internal/auth"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/ratelimit"
)

// The server API (/v1/server) is for your backends. It is authenticated with
// a secret key (Authorization: Bearer sk_live_...) created in the admin UI,
// and refuses any request that looks like it comes from a browser.

const localAPIKey ctxKey = 100

// publishableKey identifies the calling app. A key that is bound to origins
// only works from those origins. Without a key the request is allowed unless
// the admin requires one.
func (s *Server) publishableKey() fiber.Handler {
	return func(c fiber.Ctx) error {
		p := c.Path()
		// Provider redirects cannot carry headers; the server API uses secret keys.
		if strings.HasPrefix(p, "/v1/server/") || p == "/v1/server" || strings.HasSuffix(p, "/callback") {
			return c.Next()
		}
		raw := c.Get("X-Warden-Key")
		if raw == "" && strings.HasSuffix(p, "/authorize") {
			raw = c.Query("client_key") // browser navigation: no custom headers
		}
		if raw == "" {
			if s.settings.Get().RequirePublishableKey {
				return domain.ErrPublishableKey
			}
			return c.Next()
		}
		k := s.apiKeys.Lookup(raw, apikeys.Publishable)
		if k == nil {
			return domain.ErrPublishableKey
		}
		if !k.AllowsOrigin(c.Get(fiber.HeaderOrigin)) {
			return domain.ErrOriginNotAllowed
		}
		c.Locals(localAPIKey, k)
		return c.Next()
	}
}

// requireSecretKey authenticates the server API.
func (s *Server) requireSecretKey() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Browsers always send Origin on cross-origin fetches. Sec-Fetch-* is
		// not a signal: Node's fetch sends Sec-Fetch-Mode too.
		if c.Get(fiber.HeaderOrigin) != "" {
			return domain.ErrSecretKeyInBrowser
		}
		raw, ok := bearer(c.Get(fiber.HeaderAuthorization))
		if !ok || !strings.HasPrefix(raw, "sk_") {
			c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="warden-server"`)
			return domain.ErrSecretKey
		}
		k := s.apiKeys.Lookup(raw, apikeys.Secret)
		if k == nil {
			c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="warden-server", error="invalid_token"`)
			return domain.ErrSecretKey
		}
		if d := s.limiter.Allow(c.Context(), ratelimit.Per("secret_key", 6000, time.Minute), k.ID.String()); !d.Allowed {
			return domain.ErrRateLimited.WithRetryAfter(d.RetryAfter)
		}
		c.Locals(localAPIKey, k)
		return c.Next()
	}
}

func actor(c fiber.Ctx) string {
	if k, ok := c.Locals(localAPIKey).(*apikeys.Key); ok {
		return "api_key:" + k.Name
	}
	return "server_api"
}

func (s *Server) serverRoutes(g fiber.Router) {
	g.Post("/users", s.serverCreateUser)
	g.Get("/users", s.serverFindUser)
	g.Get("/users/:id", s.serverGetUser)
	g.Patch("/users/:id", s.serverUpdateUser)
	g.Delete("/users/:id/sessions", s.serverRevokeSessions)
	g.Post("/tokens/verify", s.serverVerifyToken)
}

func (s *Server) serverCreateUser(c fiber.Ctx) error {
	var in struct {
		Email         string   `json:"email"`
		Password      string   `json:"password"`
		Name          string   `json:"name"`
		Roles         []string `json:"roles"`
		EmailVerified bool     `json:"email_verified"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	u, err := s.auth.CreateUser(c.Context(), auth.CreateUserInput{
		Email: in.Email, Password: in.Password, Name: in.Name, Roles: in.Roles, EmailVerified: in.EmailVerified,
	}, actor(c), meta(c))
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(s.serverUserView(c, u))
}

// ServerUserView adds operator-only fields to UserView.
type ServerUserView struct {
	UserView
	Disabled  bool      `json:"disabled"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Server) serverUserView(c fiber.Ctx, u *domain.User) ServerUserView {
	return ServerUserView{UserView: s.userView(c.Context(), u), Disabled: u.Disabled(), UpdatedAt: u.UpdatedAt}
}

func pathUserID(c fiber.Ctx) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return uuid.Nil, domain.ErrNotFound
	}
	return id, nil
}

func (s *Server) serverGetUser(c fiber.Ctx) error {
	id, err := pathUserID(c)
	if err != nil {
		return err
	}
	u, err := s.auth.GetUser(c.Context(), id)
	if err != nil {
		return err
	}
	return c.JSON(s.serverUserView(c, u))
}

func (s *Server) serverFindUser(c fiber.Ctx) error {
	email := c.Query("email")
	if email == "" {
		return domain.ErrValidation.WithMessage("Pass ?email= to look a user up, or GET /v1/server/users/{id}.")
	}
	u, err := s.auth.FindUserByEmail(c.Context(), email)
	if err != nil {
		return err
	}
	return c.JSON(s.serverUserView(c, u))
}

func (s *Server) serverUpdateUser(c fiber.Ctx) error {
	id, err := pathUserID(c)
	if err != nil {
		return err
	}
	var in struct {
		Name     *string   `json:"name"`
		Roles    *[]string `json:"roles"`
		Disabled *bool     `json:"disabled"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	if _, err := s.auth.GetUser(c.Context(), id); err != nil {
		return err
	}
	if in.Name != nil {
		if _, err := s.auth.AdminUpdateProfile(c.Context(), id, *in.Name, actor(c)); err != nil {
			return err
		}
	}
	if in.Roles != nil {
		if err := s.auth.SetRoles(c.Context(), id, *in.Roles, actor(c)); err != nil {
			return err
		}
	}
	if in.Disabled != nil {
		if err := s.auth.SetDisabled(c.Context(), id, *in.Disabled, actor(c)); err != nil {
			return err
		}
	}
	return s.serverGetUser(c)
}

func (s *Server) serverRevokeSessions(c fiber.Ctx) error {
	id, err := pathUserID(c)
	if err != nil {
		return err
	}
	n, err := s.auth.RevokeAllSessions(c.Context(), id, uuid.Nil, domain.RevokeAdmin, meta(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"revoked": n})
}

// serverVerifyToken is token introspection for backends that cannot verify
// JWTs themselves, or that need an online check against revoked sessions.
func (s *Server) serverVerifyToken(c fiber.Ctx) error {
	var in struct {
		Token        string `json:"token"`
		CheckSession bool   `json:"check_session"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	inactive := func(reason string) error { return c.JSON(fiber.Map{"active": false, "reason": reason}) }
	claims, err := s.tokens.Verify(in.Token)
	if err != nil {
		return inactive("invalid_token")
	}
	uid, err1 := claims.UserID()
	sid, err2 := claims.SID()
	if err1 != nil || err2 != nil {
		return inactive("invalid_token")
	}
	if in.CheckSession {
		ok, err := s.auth.SessionActive(c.Context(), sid)
		if err != nil {
			return err
		}
		if !ok {
			return inactive("session_revoked")
		}
	} else if s.auth.SessionRevoked(c.Context(), sid) {
		return inactive("session_revoked")
	}
	out := fiber.Map{
		"active": true, "user_id": uid.String(), "session_id": sid.String(), "roles": claims.Roles, "amr": claims.AMR,
		"email": claims.Email, "email_verified": claims.EmailVerified, "expires_at": claims.ExpiresAt.Time,
	}
	if in.CheckSession {
		u, err := s.auth.GetUser(c.Context(), uid)
		if err != nil || u.Disabled() {
			return inactive("user_disabled")
		}
		// Current roles, not the ones frozen into the token.
		out["roles"] = u.Roles
	}
	return c.JSON(out)
}
