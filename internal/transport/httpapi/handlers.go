package httpapi

import (
	"html"
	"io"
	"net/url"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/auth"
	"github.com/fatihacan1/warden/internal/domain"
)

// ---------------------------------------------------------------------------
// Credentials

func (s *Server) providers(c fiber.Ctx) error {
	type provider struct {
		Name         string `json:"name"`
		DisplayName  string `json:"display_name"`
		AuthorizeURL string `json:"authorize_url"`
		Native       bool   `json:"native"`
	}
	out := []provider{}
	for _, d := range s.oauth.Enabled() {
		out = append(out, provider{
			Name: d.Name, DisplayName: d.DisplayName, Native: d.SupportsNative,
			AuthorizeURL: s.cfg.HTTP.PublicURL + "/v1/oauth/" + d.Name + "/authorize",
		})
	}
	rt := s.settings.Get()
	c.Set("Cache-Control", "public, max-age=60")
	return c.JSON(fiber.Map{
		"password":                    true,
		"signup_enabled":              rt.AllowSignup,
		"email_verification_required": rt.RequireEmailVerification,
		"password_min_length":         rt.PasswordMinLength,
		"providers":                   out,
	})
}

func (s *Server) signUp(c fiber.Ctx) error {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
		Locale   string `json:"locale"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	res, err := s.auth.SignUp(c.Context(), auth.SignUpInput{Email: in.Email, Password: in.Password, Name: in.Name, Locale: in.Locale}, meta(c))
	if err != nil {
		return err
	}
	return s.respondAuth(c, fiber.StatusCreated, res)
}

func (s *Server) signIn(c fiber.Ctx) error {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	res, err := s.auth.SignIn(c.Context(), in.Email, in.Password, meta(c))
	if err != nil {
		return err
	}
	return s.respondAuth(c, fiber.StatusOK, res)
}

func (s *Server) verifyMFA(c fiber.Ctx) error {
	var in struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	res, err := s.auth.VerifyMFA(c.Context(), in.MFAToken, in.Code, meta(c))
	if err != nil {
		return err
	}
	return s.respondAuth(c, fiber.StatusOK, res)
}

// refreshToken reads the token from the body, or from the HttpOnly cookie
// when the client opted into cookie mode (the custom header requirement is
// the CSRF defense for the cookie).
func (s *Server) refreshToken(c fiber.Ctx) (string, error) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decode(c, &in); err != nil {
		return "", err
	}
	if in.RefreshToken == "" && cookieMode(c) {
		in.RefreshToken = c.Cookies(s.cfg.HTTP.RefreshCookie)
	}
	return in.RefreshToken, nil
}

func (s *Server) refresh(c fiber.Ctx) error {
	raw, err := s.refreshToken(c)
	if err != nil {
		return err
	}
	res, err := s.auth.Refresh(c.Context(), raw, meta(c))
	if err != nil {
		if cookieMode(c) && domain.AsError(err) != nil && domain.AsError(err).Code == domain.ErrInvalidToken.Code {
			s.clearRefreshCookie(c)
		}
		return err
	}
	return s.respondAuth(c, fiber.StatusOK, res)
}

func (s *Server) signOut(c fiber.Ctx) error {
	raw, err := s.refreshToken(c)
	if err != nil {
		return err
	}
	if raw != "" {
		if err := s.auth.SignOut(c.Context(), raw, meta(c)); err != nil {
			return err
		}
	} else if h, ok := bearer(c.Get(fiber.HeaderAuthorization)); ok {
		if claims, err := s.tokens.Verify(h); err == nil && !claims.IsMachine() {
			uid, _ := claims.UserID()
			sid, _ := claims.SID()
			if err := s.auth.RevokeSession(c.Context(), uid, sid, domain.RevokeSignOut, meta(c)); err != nil {
				return err
			}
		}
	}
	if cookieMode(c) {
		s.clearRefreshCookie(c)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (s *Server) verifyEmail(c fiber.Ctx) error {
	var in struct {
		Token string `json:"token"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	if err := s.auth.VerifyEmail(c.Context(), in.Token, meta(c)); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"verified": true})
}

func (s *Server) forgotPassword(c fiber.Ctx) error {
	var in struct {
		Email string `json:"email"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	if err := s.auth.ForgotPassword(c.Context(), in.Email, meta(c)); err != nil {
		s.log.Error("forgot password failed", "err", err) // never reveal to the client
	}
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"message": "If an account exists for that email, a reset link has been sent.",
	})
}

func (s *Server) resetPassword(c fiber.Ctx) error {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	if err := s.auth.ResetPassword(c.Context(), in.Token, in.Password, meta(c)); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"reset": true})
}

// ---------------------------------------------------------------------------
// OAuth

func (s *Server) oauthAuthorize(c fiber.Ctx) error {
	u, err := s.auth.AuthorizeURL(c.Context(), auth.AuthorizeInput{
		Provider:      c.Params("provider"),
		RedirectURI:   c.Query("redirect_uri"),
		State:         c.Query("state"),
		CodeChallenge: c.Query("code_challenge"),
		Method:        c.Query("code_challenge_method", "S256"),
	})
	if err != nil {
		return err
	}
	return c.Redirect().Status(fiber.StatusFound).To(u)
}

func (s *Server) oauthCallback(c fiber.Ctx) error {
	params := url.Values{}
	for k, v := range c.Queries() {
		params.Set(k, v)
	}
	if c.Method() == fiber.MethodPost {
		form, err := url.ParseQuery(string(c.Body()))
		if err == nil {
			for k, v := range form {
				params[k] = v
			}
		}
	}
	res, err := s.auth.HandleCallback(c.Context(), c.Params("provider"), params, meta(c))
	if err != nil {
		if de := domain.AsError(err); de != nil {
			c.Set("Cache-Control", "no-store")
			return c.Status(de.Status).Type("html").SendString(errorPage(de.Message))
		}
		return err
	}
	// 303 turns Apple's POST callback into a GET on the app.
	return c.Redirect().Status(fiber.StatusSeeOther).To(res.RedirectURL)
}

func (s *Server) oauthToken(c fiber.Ctx) error {
	var in struct {
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
		RedirectURI  string `json:"redirect_uri"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	res, err := s.auth.ExchangeLoginCode(c.Context(), in.Code, in.CodeVerifier, in.RedirectURI, meta(c))
	if err != nil {
		return err
	}
	return s.respondAuth(c, fiber.StatusOK, res)
}

func (s *Server) oauthNative(c fiber.Ctx) error {
	var in struct {
		IDToken string `json:"id_token"`
		Nonce   string `json:"nonce"`
		Name    string `json:"name"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	res, err := s.auth.SignInWithIDToken(c.Context(), c.Params("provider"), in.IDToken, in.Nonce, in.Name, meta(c))
	if err != nil {
		return err
	}
	status := fiber.StatusOK
	if res.NewUser {
		status = fiber.StatusCreated
	}
	return s.respondAuth(c, status, res)
}

// errorPage is shown when a callback cannot be tied to a trusted redirect.
func errorPage(msg string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign-in failed</title></head>` +
		`<body style="font-family:system-ui,sans-serif;max-width:480px;margin:15vh auto;padding:0 16px;color:#1d1d1b">` +
		`<h1 style="font-size:20px">Sign-in failed</h1><p>` + html.EscapeString(msg) + `</p><p>You can close this window and try again.</p></body></html>`
}

// ---------------------------------------------------------------------------
// Current user

func (s *Server) getMe(c fiber.Ctx) error {
	u, err := s.auth.GetUser(c.Context(), userID(c))
	if err != nil {
		if domain.AsError(err) != nil && domain.AsError(err).Code == domain.ErrNotFound.Code {
			return domain.ErrInvalidToken
		}
		return err
	}
	if u.Disabled() {
		return domain.ErrAccountDisabled
	}
	return c.JSON(s.userView(c.Context(), u))
}

func (s *Server) updateMe(c fiber.Ctx) error {
	var in struct {
		Name   *string `json:"name"`
		Locale *string `json:"locale"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	if in.Locale != nil {
		if _, err := s.auth.SetLocale(c.Context(), userID(c), *in.Locale); err != nil {
			return err
		}
	}
	if in.Name == nil {
		return s.getMe(c)
	}
	u, err := s.auth.UpdateProfile(c.Context(), userID(c), *in.Name)
	if err != nil {
		return err
	}
	return c.JSON(s.userView(c.Context(), u))
}

func (s *Server) deleteMe(c fiber.Ctx) error {
	var in struct {
		Password string `json:"password"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	if err := s.auth.DeleteAccount(c.Context(), userID(c), sessionID(c), in.Password, meta(c)); err != nil {
		return err
	}
	s.clearRefreshCookie(c)
	return c.SendStatus(fiber.StatusNoContent)
}

func (s *Server) changePassword(c fiber.Ctx) error {
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decode(c, &in); err != nil {
		return err
	}
	if err := s.auth.ChangePassword(c.Context(), userID(c), sessionID(c), in.CurrentPassword, in.NewPassword, meta(c)); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (s *Server) resendVerification(c fiber.Ctx) error {
	if err := s.auth.ResendVerification(c.Context(), userID(c)); err != nil {
		return err
	}
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"sent": true})
}

func (s *Server) uploadAvatar(c fiber.Ctx) error {
	var data []byte
	if fh, err := c.FormFile("file"); err == nil {
		if fh.Size > s.cfg.S3.AvatarMaxBytes {
			return domain.ErrPayloadTooLarge
		}
		f, err := fh.Open()
		if err != nil {
			return domain.ErrValidation.WithMessage("Could not read the uploaded file.")
		}
		defer f.Close()
		data, err = io.ReadAll(io.LimitReader(f, s.cfg.S3.AvatarMaxBytes+1))
		if err != nil {
			return domain.ErrValidation.WithMessage("Could not read the uploaded file.")
		}
	} else {
		data = c.Body() // raw image body
	}
	if len(data) == 0 {
		return domain.ErrValidation.WithMessage("Send the image as multipart field \"file\" or as the raw request body.")
	}
	u, err := s.auth.UploadAvatar(c.Context(), userID(c), data)
	if err != nil {
		return err
	}
	return c.JSON(s.userView(c.Context(), u))
}

func (s *Server) deleteAvatar(c fiber.Ctx) error {
	if err := s.auth.DeleteAvatar(c.Context(), userID(c)); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (s *Server) listSessions(c fiber.Ctx) error {
	sessions, err := s.auth.ListSessions(c.Context(), userID(c))
	if err != nil {
		return err
	}
	current := sessionID(c)
	out := make([]SessionView, 0, len(sessions))
	for _, x := range sessions {
		out = append(out, SessionView{
			ID: x.ID.String(), Current: x.ID == current, UserAgent: x.UserAgent, IP: x.IP, AMR: x.AMR,
			CreatedAt: x.CreatedAt, LastUsedAt: x.LastUsedAt, ExpiresAt: x.ExpiresAt,
		})
	}
	return c.JSON(fiber.Map{"sessions": out})
}

func (s *Server) revokeSession(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return domain.ErrNotFound
	}
	if err := s.auth.RevokeSession(c.Context(), userID(c), id, domain.RevokeUser, meta(c)); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (s *Server) revokeOtherSessions(c fiber.Ctx) error {
	n, err := s.auth.RevokeAllSessions(c.Context(), userID(c), sessionID(c), domain.RevokeUser, meta(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"revoked": n})
}

func (s *Server) listIdentities(c fiber.Ctx) error {
	ids, err := s.auth.ListIdentities(c.Context(), userID(c))
	if err != nil {
		return err
	}
	out := make([]IdentityView, 0, len(ids))
	for _, i := range ids {
		out = append(out, IdentityView{Provider: i.Provider, Email: i.Email, CreatedAt: i.CreatedAt, LastUsedAt: i.LastUsedAt})
	}
	return c.JSON(fiber.Map{"identities": out})
}

func (s *Server) unlinkIdentity(c fiber.Ctx) error {
	if err := s.auth.UnlinkIdentity(c.Context(), userID(c), c.Params("provider"), meta(c)); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (s *Server) totpSetup(c fiber.Ctx) error {
	setup, err := s.auth.StartTOTPSetup(c.Context(), userID(c))
	if err != nil {
		return err
	}
	return c.JSON(setup)
}

type codeInput struct {
	Code string `json:"code"`
}

func (s *Server) totpEnable(c fiber.Ctx) error {
	var in codeInput
	if err := decode(c, &in); err != nil {
		return err
	}
	codes, err := s.auth.EnableTOTP(c.Context(), userID(c), in.Code, meta(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"enabled": true, "recovery_codes": codes})
}

func (s *Server) totpDisable(c fiber.Ctx) error {
	var in codeInput
	if err := decode(c, &in); err != nil {
		return err
	}
	if err := s.auth.DisableTOTP(c.Context(), userID(c), in.Code, meta(c)); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"enabled": false})
}

func (s *Server) regenerateRecoveryCodes(c fiber.Ctx) error {
	var in codeInput
	if err := decode(c, &in); err != nil {
		return err
	}
	codes, err := s.auth.RegenerateRecoveryCodes(c.Context(), userID(c), in.Code, meta(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"recovery_codes": codes})
}
