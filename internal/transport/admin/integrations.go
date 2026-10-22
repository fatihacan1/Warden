package admin

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/fatihacan1/warden/api"
	"github.com/fatihacan1/warden/internal/apikeys"
	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/i18n"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/webhooks"
)

// ---------------------------------------------------------------------------
// Show-once values (new secret keys, webhook secrets)
//
// The value is parked in Redis for a few minutes and the browser is
// redirected to ?reveal=<id>, which reads and deletes it. Secrets therefore
// never appear in URLs, logs or the browser history, and reloading the page
// does not show them again.

func (s *Server) stash(c fiber.Ctx, v map[string]string) (string, error) {
	id := randtoken.New(18)
	b, _ := json.Marshal(v)
	return id, s.Redis.Set(c.Context(), "admin:reveal:"+randtoken.HashHex(id), b, 5*time.Minute).Err()
}

func (s *Server) unstash(c fiber.Ctx) map[string]string {
	id := c.Query("reveal")
	if id == "" || len(id) > 64 {
		return nil
	}
	b, err := s.Redis.GetDel(c.Context(), "admin:reveal:"+randtoken.HashHex(id)).Bytes()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			s.Log.Warn("reveal lookup failed", "err", err)
		}
		return nil
	}
	var v map[string]string
	_ = json.Unmarshal(b, &v)
	return v
}

func (s *Server) reveal(c fiber.Ctx, path string, v map[string]string) error {
	id, err := s.stash(c, v)
	if err != nil {
		return backErr(c, path, err)
	}
	return c.Redirect().Status(fiber.StatusSeeOther).To(path + "?reveal=" + id)
}

// ---------------------------------------------------------------------------
// API keys

func (s *Server) apiKeysPage(c fiber.Ctx) error {
	return s.render(c, fiber.StatusOK, "apikeys", "apikeys", "API keys", map[string]any{
		"Keys": s.APIKeys.List(), "Reveal": s.unstash(c), "Required": s.Settings.Get().RequirePublishableKey,
		"PKPrefix": s.APIKeys.Prefix(apikeys.Publishable), "SKPrefix": s.APIKeys.Prefix(apikeys.Secret),
		"PublicURL": s.Config.HTTP.PublicURL,
	})
}

func (s *Server) createAPIKey(c fiber.Ctx) error {
	kind := apikeys.Kind(c.FormValue("kind"))
	raw, k, err := s.APIKeys.Create(c.Context(), kind, c.FormValue("name"), lines(c.FormValue("origins")))
	if err != nil {
		return backErr(c, "/admin/api-keys", err)
	}
	s.audit(c, "admin.api_key_created", map[string]any{"key_id": k.ID, "kind": kind, "name": k.Name})
	return s.reveal(c, "/admin/api-keys", map[string]string{"Kind": string(kind), "Name": k.Name, "Value": raw})
}

func (s *Server) updateAPIKey(c fiber.Ctx) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	if err := s.APIKeys.Update(c.Context(), id, c.FormValue("name"), lines(c.FormValue("origins"))); err != nil {
		return backErr(c, "/admin/api-keys", err)
	}
	s.audit(c, "admin.api_key_updated", map[string]any{"key_id": id})
	return back(c, "/admin/api-keys", "keysaved")
}

func (s *Server) revokeAPIKey(c fiber.Ctx) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	if err := s.APIKeys.Revoke(c.Context(), id); err != nil {
		return backErr(c, "/admin/api-keys", err)
	}
	s.audit(c, "admin.api_key_revoked", map[string]any{"key_id": id})
	return back(c, "/admin/api-keys", "keyrevoked")
}

// ---------------------------------------------------------------------------
// Webhooks

func webhookInput(c fiber.Ctx) webhooks.Input {
	var evs []string
	if c.FormValue("all_events") != "on" {
		for _, e := range events.Types {
			if c.FormValue("event_"+e) == "on" {
				evs = append(evs, e)
			}
		}
	}
	return webhooks.Input{URL: c.FormValue("url"), Description: c.FormValue("description"), Events: evs, Enabled: c.FormValue("enabled") == "on"}
}

func (s *Server) webhooksPage(c fiber.Ctx) error {
	return s.render(c, fiber.StatusOK, "webhooks", "webhooks", "Webhooks", map[string]any{
		"Webhooks": s.Webhooks.List(), "Events": events.Types, "Private": s.Config.WebhookPrivateNetworks(),
		"Defaults": map[string]bool{events.UserCreated: true, events.UserUpdated: true},
	})
}

func (s *Server) createWebhook(c fiber.Ctx) error {
	in := webhookInput(c)
	if c.FormValue("all_events") != "on" && len(in.Events) == 0 {
		return backErr(c, "/admin/webhooks", domain.ErrValidation.WithMessage("Pick at least one event, or choose \"All events\"."))
	}
	in.Enabled = true
	w, secret, err := s.Webhooks.Create(c.Context(), in)
	if err != nil {
		return backErr(c, "/admin/webhooks", err)
	}
	s.audit(c, "admin.webhook_created", map[string]any{"webhook_id": w.ID, "url": w.URL})
	return s.reveal(c, "/admin/webhooks/"+w.ID.String(), map[string]string{"Secret": secret})
}

type deliveryView struct {
	ID        int64
	Type      string
	EventID   string
	Status    string
	Attempts  int
	LastError string
	CreatedAt time.Time
	Next      time.Time
}

func (s *Server) webhookPage(c fiber.Ctx) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	w := s.Webhooks.Get(id)
	if w == nil {
		return fiber.ErrNotFound
	}
	rows, err := s.Store.ListDeliveries(c.Context(), w.Topic(), 30)
	if err != nil {
		return err
	}
	var list []deliveryView
	for _, d := range rows {
		var env events.Envelope
		_ = json.Unmarshal(d.Payload, &env)
		v := deliveryView{ID: d.ID, Type: env.Type, EventID: env.ID, Attempts: d.Attempts, LastError: d.LastError, CreatedAt: d.CreatedAt, Next: d.NextAttempt}
		switch {
		case d.ProcessedAt != nil:
			v.Status = "delivered"
		case d.FailedAt != nil:
			v.Status = "failed"
		case d.Attempts > 0:
			v.Status = "retrying"
		default:
			v.Status = "pending"
		}
		list = append(list, v)
	}
	reveal := s.unstash(c)
	return s.render(c, fiber.StatusOK, "webhook", "webhooks", "Webhook", map[string]any{
		"W": w, "Events": events.Types, "Deliveries": list, "Reveal": reveal, "Wanted": wantedSet(w),
	})
}

func wantedSet(w *webhooks.Webhook) map[string]bool {
	m := map[string]bool{}
	for _, e := range w.Events {
		m[e] = true
	}
	return m
}

func (s *Server) webhookAction(c fiber.Ctx, fn func(id uuid.UUID) error, auditType, ok string) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	path := "/admin/webhooks/" + id.String()
	if err := fn(id); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return fiber.ErrNotFound
		}
		return backErr(c, path, err)
	}
	s.audit(c, auditType, map[string]any{"webhook_id": id})
	return back(c, path, ok)
}

func (s *Server) updateWebhook(c fiber.Ctx) error {
	return s.webhookAction(c, func(id uuid.UUID) error {
		in := webhookInput(c)
		if c.FormValue("all_events") != "on" && len(in.Events) == 0 {
			return domain.ErrValidation.WithMessage("Pick at least one event, or choose \"All events\".")
		}
		return s.Webhooks.Update(c.Context(), id, in)
	}, "admin.webhook_updated", "saved")
}

func (s *Server) testWebhook(c fiber.Ctx) error {
	return s.webhookAction(c, func(id uuid.UUID) error {
		w := s.Webhooks.Get(id)
		if w == nil {
			return domain.ErrNotFound
		}
		body, err := events.NewEnvelope(webhooks.TestEvent, uuid.Nil, map[string]any{"message": "Test event sent from the Warden admin UI."})
		if err != nil {
			return err
		}
		return s.Store.EnqueueOutbox(c.Context(), w.Topic(), body)
	}, "admin.webhook_tested", "webhooktest")
}

func (s *Server) rotateWebhookSecret(c fiber.Ctx) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	secret, err := s.Webhooks.RotateSecret(c.Context(), id)
	if err != nil {
		return backErr(c, "/admin/webhooks/"+id.String(), err)
	}
	s.audit(c, "admin.webhook_secret_rotated", map[string]any{"webhook_id": id})
	return s.reveal(c, "/admin/webhooks/"+id.String(), map[string]string{"Secret": secret})
}

func (s *Server) revealWebhookSecret(c fiber.Ctx) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	secret, err := s.Webhooks.Secret(id)
	if err != nil {
		return backErr(c, "/admin/webhooks/"+id.String(), err)
	}
	s.audit(c, "admin.webhook_secret_viewed", map[string]any{"webhook_id": id})
	return s.reveal(c, "/admin/webhooks/"+id.String(), map[string]string{"Secret": secret})
}

func (s *Server) deleteWebhook(c fiber.Ctx) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	if err := s.Webhooks.Delete(c.Context(), id); err != nil {
		return backErr(c, "/admin/webhooks/"+id.String(), err)
	}
	s.audit(c, "admin.webhook_deleted", map[string]any{"webhook_id": id})
	return back(c, "/admin/webhooks", "webhookdeleted")
}

func (s *Server) retryDelivery(c fiber.Ctx) error {
	return s.webhookAction(c, func(id uuid.UUID) error {
		did, err := strconv.ParseInt(c.Params("delivery"), 10, 64)
		if err != nil {
			return domain.ErrNotFound
		}
		return s.Store.RetryDelivery(c.Context(), webhooks.TopicPrefix+id.String(), did)
	}, "admin.webhook_retry", "retry")
}

// ---------------------------------------------------------------------------
// Email templates

type emailRow struct {
	mailer.Info
	Langs []emailLang
}

type emailLang struct {
	i18n.Locale
	Customized bool
	UpdatedAt  time.Time
}

func (s *Server) emailLangs(name string) []emailLang {
	var out []emailLang
	for _, l := range i18n.Locales {
		_, custom := s.Mail.Override(name, l.Code)
		out = append(out, emailLang{Locale: l, Customized: custom, UpdatedAt: s.Mail.UpdatedAt(name, l.Code)})
	}
	return out
}

func (s *Server) emailsPage(c fiber.Ctx) error {
	rows := []emailRow{{Info: *layoutInfo(), Langs: s.emailLangs(mailer.LayoutName)}}
	for _, t := range mailer.Templates {
		rows = append(rows, emailRow{Info: t, Langs: s.emailLangs(t.Name)})
	}
	return s.render(c, fiber.StatusOK, "emails", "emails", "Emails", map[string]any{
		"Templates": rows, "SMTP": s.Config.SMTP.Host != "", "From": s.Config.SMTP.From,
		"Default": i18n.Lookup(s.Renderer.Locale("")), "Locales": i18n.Locales,
	})
}

func layoutInfo() *mailer.Info {
	return &mailer.Info{Name: mailer.LayoutName, Title: "Layout", Description: "The frame around every HTML email: header, footer and colors.",
		Vars: map[string]string{}}
}

func emailInfo(name string) (*mailer.Info, bool) {
	if name == mailer.LayoutName {
		return layoutInfo(), true
	}
	i := mailer.Lookup(name)
	return i, i != nil
}

// emailLocale reads ?lang= (or the form field) and falls back to the default.
func (s *Server) emailLocale(c fiber.Ctx) string {
	l := c.Query("lang")
	if c.Method() == fiber.MethodPost && c.FormValue("lang") != "" {
		l = c.FormValue("lang")
	}
	return s.Renderer.Locale(l)
}

func emailPath(name, locale string) string { return "/admin/emails/" + name + "?lang=" + locale }

func (s *Server) emailPage(c fiber.Ctx) error {
	info, ok := emailInfo(c.Params("name"))
	if !ok {
		return fiber.ErrNotFound
	}
	loc := s.emailLocale(c)
	src, _ := s.Renderer.Effective(info.Name, loc)
	_, custom := s.Mail.Override(info.Name, loc)
	return s.render(c, fiber.StatusOK, "email", "emails", info.Title, map[string]any{
		"Info": info, "Src": src, "Custom": custom, "Layout": info.Name == mailer.LayoutName, "SMTP": s.Config.SMTP.Host != "",
		"Lang": i18n.Lookup(loc), "Langs": s.emailLangs(info.Name),
	})
}

func emailSource(c fiber.Ctx) mailer.Source {
	return mailer.Source{Subject: c.FormValue("subject"), HTML: c.FormValue("html"), Text: c.FormValue("text")}
}

func (s *Server) saveEmail(c fiber.Ctx) error {
	info, ok := emailInfo(c.Params("name"))
	if !ok {
		return fiber.ErrNotFound
	}
	loc := s.emailLocale(c)
	path := emailPath(info.Name, loc)
	if err := s.Mail.Save(c.Context(), info.Name, loc, emailSource(c)); err != nil {
		return backErr(c, path, err)
	}
	s.audit(c, "admin.email_template_saved", map[string]any{"template": info.Name, "locale": loc})
	return back(c, path, "emailsaved")
}

func (s *Server) resetEmail(c fiber.Ctx) error {
	info, ok := emailInfo(c.Params("name"))
	if !ok {
		return fiber.ErrNotFound
	}
	loc := s.emailLocale(c)
	if err := s.Mail.Reset(c.Context(), info.Name, loc); err != nil {
		return backErr(c, emailPath(info.Name, loc), err)
	}
	s.audit(c, "admin.email_template_reset", map[string]any{"template": info.Name, "locale": loc})
	return back(c, emailPath(info.Name, loc), "emailreset")
}

// previewEmail renders into the preview frame: the saved version on GET, the
// submitted (unsaved) version on POST.
func (s *Server) previewEmail(c fiber.Ctx) error {
	info, ok := emailInfo(c.Params("name"))
	if !ok {
		return fiber.ErrNotFound
	}
	loc := s.emailLocale(c)
	src, _ := s.Renderer.Effective(info.Name, loc)
	if c.Method() == fiber.MethodPost {
		src = emailSource(c)
	}
	view := "html"
	if c.Query("view") == "text" {
		view = "text"
	}
	msg, err := s.Mail.Preview(info.Name, loc, src)
	// The frame is sandboxed (no scripts, no forms, no same-origin access).
	c.Set("X-Frame-Options", "SAMEORIGIN")
	c.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; frame-ancestors 'self'; sandbox")
	if err != nil {
		c.Type("html", "utf-8")
		return c.Status(fiber.StatusUnprocessableEntity).SendString(`<p style="font:14px system-ui;color:#b42318;padding:16px">` +
			html.EscapeString(err.Error()) + `</p>`)
	}
	if view == "text" {
		c.Type("html", "utf-8")
		return c.SendString(`<pre style="font:13px/1.5 ui-monospace,monospace;white-space:pre-wrap;padding:16px;margin:0">Subject: ` +
			html.EscapeString(msg.Subject) + "\n\n" + html.EscapeString(msg.Text) + `</pre>`)
	}
	c.Type("html", "utf-8")
	return c.SendString(msg.HTML)
}

func (s *Server) testEmail(c fiber.Ctx) error {
	info, ok := emailInfo(c.Params("name"))
	if !ok {
		return fiber.ErrNotFound
	}
	loc := s.emailLocale(c)
	path := emailPath(info.Name, loc)
	addr, err := mail.ParseAddress(strings.TrimSpace(c.FormValue("to")))
	if err != nil {
		return backErr(c, path, domain.ErrValidation.WithMessage("Enter the email address to send the test to."))
	}
	src, _ := s.Renderer.Effective(info.Name, loc)
	msg, err := s.Mail.Preview(info.Name, loc, src)
	if err != nil {
		return backErr(c, path, err)
	}
	msg.To = addr.Address
	msg.Subject = "[Test] " + msg.Subject
	ctx, cancel := context.WithTimeout(c.Context(), 20*time.Second)
	defer cancel()
	if err := s.Sender.Send(ctx, msg); err != nil {
		s.Log.Warn("test email failed", "err", err)
		return backErr(c, path, errors.New("Sending failed: "+err.Error()))
	}
	s.audit(c, "admin.email_test_sent", map[string]any{"template": info.Name})
	return back(c, path, "emailtest")
}

// ---------------------------------------------------------------------------
// Documentation

func (s *Server) docsPage(c fiber.Ctx) error {
	cfg := s.Config
	var pk string
	for _, k := range s.APIKeys.List() {
		if k.Kind == apikeys.Publishable && k.Active() {
			pk = k.Hint
			break
		}
	}
	return s.render(c, fiber.StatusOK, "docs", "docs", "API docs", map[string]any{
		"PublicURL": cfg.HTTP.PublicURL, "Issuer": cfg.Token.Issuer, "Audience": strings.Join(cfg.Token.Audience, ","),
		"JWKS": cfg.HTTP.PublicURL + "/.well-known/jwks.json", "PK": pk, "GraphQL": cfg.GraphQL.Enabled,
		"Reference": s.reference,
	})
}

func (s *Server) openAPI(c fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, "application/yaml; charset=utf-8")
	if c.Query("download") != "" {
		c.Set(fiber.HeaderContentDisposition, `attachment; filename="warden-openapi.yaml"`)
	}
	return c.Send(api.OpenAPI)
}
