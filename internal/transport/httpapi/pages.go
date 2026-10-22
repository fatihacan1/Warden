package httpapi

import (
	"html"

	"github.com/gofiber/fiber/v3"

	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/i18n"
)

// Small HTML pages for links that arrive by email. They are the only HTML the
// public API serves, so they get their own strict CSP: inline styles only,
// forms back to this origin, nothing else.

var pageText = map[string]map[string]string{
	"en": {
		"confirm_title": "Sign out that device?",
		"confirm_body":  "This ends the session that was reported in the email. Anyone using it is signed out right away.",
		"confirm_btn":   "Sign out that device",
		"done_title":    "The device was signed out",
		"done_body":     "If you did not make that sign-in, change your password now and turn on two-factor authentication.",
		"bad_title":     "This link no longer works",
		"bad_body":      "It was already used or has expired. You can review and sign out devices from your account settings.",
	},
	"tr": {
		"confirm_title": "O cihazın oturumu kapatılsın mı?",
		"confirm_body":  "E-postada bildirilen oturum sonlandırılır. O cihazı kullanan kişinin oturumu hemen kapanır.",
		"confirm_btn":   "O cihazın oturumunu kapat",
		"done_title":    "Cihazın oturumu kapatıldı",
		"done_body":     "O girişi siz yapmadıysanız şifrenizi hemen değiştirin ve iki adımlı doğrulamayı açın.",
		"bad_title":     "Bu bağlantı artık geçerli değil",
		"bad_body":      "Daha önce kullanılmış ya da süresi dolmuş. Cihazlarınızı hesap ayarlarından görüp kapatabilirsiniz.",
	},
}

func (s *Server) page(c fiber.Ctx, status int, title, body, form string) error {
	loc := i18n.FromAcceptLanguage(c.Get(fiber.HeaderAcceptLanguage))
	if loc == "" {
		loc = s.settings.Get().DefaultLocale
	}
	c.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	c.Set("Cache-Control", "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	c.Type("html", "utf-8")
	return c.Status(status).SendString(`<!doctype html><html lang="` + html.EscapeString(loc) + `"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>` + html.EscapeString(title) + `</title></head>` +
		`<body style="font:16px/1.55 system-ui,-apple-system,'Segoe UI',sans-serif;max-width:460px;margin:12vh auto;padding:0 20px;color:#1d1d1b">` +
		`<p style="font-weight:600;margin:0 0 24px">` + html.EscapeString(s.settings.Get().AppName) + `</p>` +
		`<h1 style="font-size:22px;margin:0 0 12px">` + html.EscapeString(title) + `</h1><p>` + html.EscapeString(body) + `</p>` + form + `</body></html>`)
}

func (s *Server) text(c fiber.Ctx, key string) string {
	loc := i18n.FromAcceptLanguage(c.Get(fiber.HeaderAcceptLanguage))
	if _, ok := pageText[loc]; !ok {
		loc = s.settings.Get().DefaultLocale
	}
	if v, ok := pageText[loc][key]; ok {
		return v
	}
	return pageText["en"][key]
}

// endSessionPage asks for confirmation: mail scanners follow links, so a GET
// must never revoke anything.
func (s *Server) endSessionPage(c fiber.Ctx) error {
	tok := c.Query("token")
	if tok == "" || len(tok) > 128 {
		return s.page(c, fiber.StatusBadRequest, s.text(c, "bad_title"), s.text(c, "bad_body"), "")
	}
	form := `<form method="post" action="/v1/auth/sessions/end"><input type="hidden" name="token" value="` + html.EscapeString(tok) + `">` +
		`<button type="submit" style="font:inherit;font-weight:600;background:#b42318;color:#fff;border:0;border-radius:6px;padding:12px 18px;cursor:pointer">` +
		html.EscapeString(s.text(c, "confirm_btn")) + `</button></form>`
	return s.page(c, fiber.StatusOK, s.text(c, "confirm_title"), s.text(c, "confirm_body"), form)
}

func (s *Server) endSession(c fiber.Ctx) error {
	if err := s.auth.EndSessionFromEmail(c.Context(), c.FormValue("token"), meta(c)); err != nil {
		if de := domain.AsError(err); de != nil && de.Code == domain.ErrInvalidToken.Code {
			return s.page(c, fiber.StatusBadRequest, s.text(c, "bad_title"), s.text(c, "bad_body"), "")
		}
		return err
	}
	return s.page(c, fiber.StatusOK, s.text(c, "done_title"), s.text(c, "done_body"), "")
}
