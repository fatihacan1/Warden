package httpapi

import (
	"github.com/gofiber/fiber/v3"

	"github.com/fatihacan1/warden/internal/captcha"
	"github.com/fatihacan1/warden/internal/domain"
)

// SetCaptchaVerifier replaces the Turnstile verifier (tests point it at a
// fake siteverify endpoint). Call it before serving requests.
func (s *Server) SetCaptchaVerifier(v *captcha.Verifier) { s.captcha = v }

// captchaToken reads the Turnstile token from the CF-Turnstile-Response
// header, falling back to the turnstile_token body field.
func captchaToken(c fiber.Ctx, bodyToken string) string {
	if h := c.Get(captcha.HeaderName); h != "" {
		return h
	}
	return bodyToken
}

// requireCaptcha verifies the Turnstile token when bot protection is on for
// action. Verification always happens here, on the server, with the secret
// key; the browser only ever sees the public site key.
func (s *Server) requireCaptcha(c fiber.Ctx, action, bodyToken string) error {
	rt := s.settings.Get()
	if !rt.TurnstileEnabled {
		return nil
	}
	var on bool
	switch action {
	case captcha.ActionSignup:
		on = rt.TurnstileSignup
	case captcha.ActionForgot:
		on = rt.TurnstileForgot
	case captcha.ActionResend:
		on = rt.TurnstileResend
	case captcha.ActionSignIn:
		on = rt.TurnstileSignIn == captcha.SignInAlways
	}
	if !on {
		return nil
	}
	return s.verifyCaptcha(c, action, bodyToken)
}

// requireSignInCaptcha applies the sign-in mode: never, always, or once the
// account or the client IP has reached the configured number of failures.
func (s *Server) requireSignInCaptcha(c fiber.Ctx, email, bodyToken string) error {
	rt := s.settings.Get()
	if !rt.TurnstileEnabled {
		return nil
	}
	switch rt.TurnstileSignIn {
	case captcha.SignInAlways:
		return s.verifyCaptcha(c, captcha.ActionSignIn, bodyToken)
	case captcha.SignInAfterFailures:
		n, err := s.auth.SignInFailures(c.Context(), email, meta(c))
		if err != nil {
			// Without the counter we cannot tell; ask for the check rather
			// than let unlimited guesses through.
			s.log.Warn("sign-in failure counter unavailable, requiring turnstile", "err", err)
		} else if n < rt.TurnstileSignInAfter {
			return nil
		}
		return s.verifyCaptcha(c, captcha.ActionSignIn, bodyToken)
	default:
		return nil
	}
}

func (s *Server) verifyCaptcha(c fiber.Ctx, action, bodyToken string) error {
	rt := s.settings.Get()
	if s.captcha == nil {
		return domain.ErrCaptchaUnavailable
	}
	err := s.captcha.Verify(c.Context(), captcha.Check{
		Secret: rt.TurnstileSecretKey, Token: captchaToken(c, bodyToken), RemoteIP: c.IP(),
		Action: action, Hostnames: rt.TurnstileHostnames,
	})
	if s.metrics != nil {
		result := "success"
		if de := domain.AsError(err); de != nil {
			result = de.Code
		}
		s.metrics.Auth("captcha_"+action, result)
	}
	return err
}
