package admin

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/accesstokens"
	"github.com/fatihacan1/warden/internal/apikeys"
	"github.com/fatihacan1/warden/internal/auth"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/i18n"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/ratelimit"
	"github.com/fatihacan1/warden/internal/settings"
	"github.com/fatihacan1/warden/internal/store"
	"github.com/fatihacan1/warden/internal/webhooks"
)

// The admin API (/api/v1 on the admin port) is what automation and AI agents
// use to manage an instance. It is authenticated with access tokens created
// in the admin UI (Developers > Access tokens), each limited to the
// resources and levels it was granted.
//
//   - Same private port and IP allowlist as the admin UI.
//   - Bearer tokens only; requests from a browser (Origin header) are refused,
//     so no page can drive it with an admin's cookies or a pasted token.
//   - 300 requests per minute per token.
//   - Every write is in the audit log with the token's name and id.
//   - No endpoint creates access tokens or changes admin access settings.

const localToken = "access_token"

func apiError(c fiber.Ctx, status int, code, msg string) error {
	c.Set("Cache-Control", "no-store")
	return c.Status(status).JSON(fiber.Map{"error": fiber.Map{"code": code, "message": msg}})
}

func (s *Server) apiAuth(c fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	if c.Get(fiber.HeaderOrigin) != "" {
		return apiError(c, fiber.StatusForbidden, "browser_request", "The admin API does not accept requests from browsers.")
	}
	raw, _ := strings.CutPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	if raw == "" {
		c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="warden-admin"`)
		return apiError(c, fiber.StatusUnauthorized, "unauthorized", "Send an access token: Authorization: Bearer wat_...")
	}
	t, err := s.AccessTokens.Authenticate(c.Context(), strings.TrimSpace(raw), c.IP())
	if err != nil {
		code, status := "invalid_token", fiber.StatusUnauthorized
		switch {
		case errors.Is(err, accesstokens.ErrExpired):
			code = "token_expired"
		case errors.Is(err, accesstokens.ErrRevoked):
			code = "token_revoked"
		case errors.Is(err, accesstokens.ErrIPBlocked):
			code, status = "ip_not_allowed", fiber.StatusForbidden
		case !errors.Is(err, accesstokens.ErrInvalid):
			s.Log.Error("access token check failed", "err", err)
			return apiError(c, fiber.StatusServiceUnavailable, "service_unavailable", "Try again shortly.")
		}
		s.Log.Warn("admin api: rejected token", "reason", code, "ip", c.IP())
		return apiError(c, status, code, err.Error())
	}
	if d := s.Limiter.Allow(c.Context(), ratelimit.Per("access_token", 300, time.Minute), t.ID.String()); !d.Allowed {
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(d.RetryAfter.Seconds())+1))
		return apiError(c, fiber.StatusTooManyRequests, "rate_limited", "Too many requests for this token.")
	}
	c.Locals(localToken, t)
	return c.Next()
}

type apiHandler func(c fiber.Ctx, t *accesstokens.Token) (any, error)

// api wraps a handler with a permission check and JSON error mapping. status
// is used for successful responses.
func (s *Server) api(resource, level string, status int, h apiHandler) fiber.Handler {
	return func(c fiber.Ctx) error {
		t, _ := c.Locals(localToken).(*accesstokens.Token)
		if t == nil || !t.Allows(resource, level) {
			return apiError(c, fiber.StatusForbidden, "insufficient_scope", "This token needs "+resource+":"+level+".")
		}
		out, err := h(c, t)
		if err != nil {
			var de *domain.Error
			var fe *fiber.Error
			switch {
			case errors.As(err, &de):
				body := fiber.Map{"code": de.Code, "message": de.Message}
				if len(de.Fields) > 0 {
					body["fields"] = de.Fields
				}
				return c.Status(de.Status).JSON(fiber.Map{"error": body})
			case errors.As(err, &fe):
				return apiError(c, fe.Code, "error", fe.Message)
			}
			s.Log.Error("admin api failed", "err", err, "path", c.Path())
			return apiError(c, fiber.StatusInternalServerError, "internal_error", "Something went wrong.")
		}
		if out == nil {
			return c.SendStatus(fiber.StatusNoContent)
		}
		return c.Status(status).JSON(out)
	}
}

// apiAudit records a write made with a token.
func (s *Server) apiAudit(c fiber.Ctx, t *accesstokens.Token, typ string, userID *uuid.UUID, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["token_id"], data["token_name"] = t.ID, t.Name
	if err := s.Store.InsertAudit(context.WithoutCancel(c.Context()), store.AuditEvent{
		UserID: userID, Type: "api." + typ, IP: c.IP(), UserAgent: c.Get(fiber.HeaderUserAgent), Metadata: data,
	}); err != nil {
		s.Log.Warn("admin api audit failed", "err", err)
	}
}

func decodeJSON(c fiber.Ctx, v any) error {
	if len(c.Body()) == 0 {
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(c.Get(fiber.HeaderContentType)), fiber.MIMEApplicationJSON) {
		return domain.ErrUnsupportedMedia.WithMessage("Content-Type must be application/json.")
	}
	dec := json.NewDecoder(strings.NewReader(string(c.Body())))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return domain.ErrValidation.WithMessage("Invalid JSON: " + err.Error())
	}
	return nil
}

func (s *Server) apiRoutes(g fiber.Router) {
	g.Get("/token", func(c fiber.Ctx) error {
		t := c.Locals(localToken).(*accesstokens.Token)
		return c.JSON(fiber.Map{"id": t.ID, "name": t.Name, "scopes": t.ScopeList(), "expires_at": t.ExpiresAt})
	})

	g.Get("/stats", s.api("stats", accesstokens.Read, 200, s.apiStats))

	g.Get("/users", s.api("users", accesstokens.Read, 200, s.apiListUsers))
	g.Get("/users/:id", s.api("users", accesstokens.Read, 200, s.apiGetUser))
	g.Post("/users", s.api("users", accesstokens.Write, 201, s.apiCreateUser))
	g.Patch("/users/:id", s.api("users", accesstokens.Write, 200, s.apiUpdateUser))
	g.Delete("/users/:id/sessions", s.api("users", accesstokens.Write, 200, s.apiRevokeUserSessions))

	g.Get("/settings", s.api("settings", accesstokens.Read, 200, s.apiGetSettings))
	g.Patch("/settings", s.api("settings", accesstokens.Write, 200, s.apiPatchSettings))

	g.Get("/email-templates", s.api("email_templates", accesstokens.Read, 200, s.apiListTemplates))
	g.Get("/email-templates/:name", s.api("email_templates", accesstokens.Read, 200, s.apiGetTemplate))
	g.Post("/email-templates/:name/preview", s.api("email_templates", accesstokens.Read, 200, s.apiPreviewTemplate))
	g.Put("/email-templates/:name", s.api("email_templates", accesstokens.Write, 200, s.apiSaveTemplate))
	g.Delete("/email-templates/:name", s.api("email_templates", accesstokens.Write, 200, s.apiResetTemplate))

	g.Get("/webhooks", s.api("webhooks", accesstokens.Read, 200, s.apiListWebhooks))
	g.Get("/webhooks/:id/deliveries", s.api("webhooks", accesstokens.Read, 200, s.apiWebhookDeliveries))
	g.Post("/webhooks", s.api("webhooks", accesstokens.Write, 201, s.apiCreateWebhook))
	g.Patch("/webhooks/:id", s.api("webhooks", accesstokens.Write, 200, s.apiUpdateWebhook))
	g.Delete("/webhooks/:id", s.api("webhooks", accesstokens.Write, 200, s.apiDeleteWebhook))
	g.Post("/webhooks/:id/test", s.api("webhooks", accesstokens.Write, 202, s.apiTestWebhook))

	g.Get("/api-keys", s.api("api_keys", accesstokens.Read, 200, s.apiListAPIKeys))
	g.Post("/api-keys", s.api("api_keys", accesstokens.Write, 201, s.apiCreateAPIKey))
	g.Delete("/api-keys/:id", s.api("api_keys", accesstokens.Write, 200, s.apiRevokeAPIKey))

	g.Get("/providers", s.api("providers", accesstokens.Read, 200, s.apiProviders))
	g.Get("/audit", s.api("audit", accesstokens.Read, 200, s.apiAuditLog))

	g.Use(func(c fiber.Ctx) error {
		return apiError(c, fiber.StatusNotFound, "not_found", "No such endpoint. See /admin/docs#admin-api.")
	})
}

// ---------------------------------------------------------------------------
// Stats, users

func (s *Server) apiStats(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	st, err := s.Store.UserStats(c.Context())
	if err != nil {
		return nil, err
	}
	pending, dead, _ := s.Store.OutboxBacklog(c.Context())
	return fiber.Map{"users": st.Total, "verified": st.Verified, "mfa": st.MFA, "disabled": st.Disabled,
		"new_last_24h": st.NewLast24h, "active_sessions": st.ActiveSessions, "outbox_pending": pending, "outbox_dead": dead}, nil
}

type apiUser struct {
	ID            string     `json:"id"`
	Email         string     `json:"email,omitempty"`
	EmailVerified bool       `json:"email_verified"`
	Name          string     `json:"name"`
	Roles         []string   `json:"roles"`
	Locale        string     `json:"locale"`
	MFAEnabled    bool       `json:"mfa_enabled"`
	HasPassword   bool       `json:"has_password"`
	Disabled      bool       `json:"disabled"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSignInAt  *time.Time `json:"last_sign_in_at,omitempty"`
}

func toAPIUser(u *domain.User) apiUser {
	return apiUser{ID: u.ID.String(), Email: u.Email, EmailVerified: u.EmailVerified(), Name: u.Name, Roles: u.Roles, Locale: u.Locale,
		MFAEnabled: u.MFAEnabled(), HasPassword: u.HasPassword(), Disabled: u.Disabled(), CreatedAt: u.CreatedAt, LastSignInAt: u.LastSignInAt}
}

func (s *Server) apiListUsers(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	q := strings.TrimSpace(c.Query("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	page, _ := strconv.Atoi(c.Query("page", "1"))
	per, _ := strconv.Atoi(c.Query("per_page", "50"))
	page, per = min(max(page, 1), 100000), min(max(per, 1), 200)
	users, total, err := s.Store.ListUsers(c.Context(), q, per, (page-1)*per)
	if err != nil {
		return nil, err
	}
	out := make([]apiUser, 0, len(users))
	for _, u := range users {
		out = append(out, toAPIUser(u))
	}
	return fiber.Map{"users": out, "total": total, "page": page, "per_page": per}, nil
}

func apiUserID(c fiber.Ctx) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return uuid.Nil, domain.ErrNotFound
	}
	return id, nil
}

func (s *Server) apiGetUser(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	id, err := apiUserID(c)
	if err != nil {
		return nil, err
	}
	u, err := s.Store.GetUserByID(c.Context(), id)
	if err != nil {
		return nil, err
	}
	sessions, _ := s.Store.ListActiveSessions(c.Context(), id)
	identities, _ := s.Store.ListIdentities(c.Context(), id)
	auditLog, _ := s.Store.ListAudit(c.Context(), &id, 30)
	type sess struct {
		ID         string    `json:"id"`
		Device     string    `json:"device"`
		IP         string    `json:"ip"`
		AMR        []string  `json:"amr"`
		LastUsedAt time.Time `json:"last_used_at"`
	}
	type ident struct {
		Provider string `json:"provider"`
		Email    string `json:"email,omitempty"`
	}
	type event struct {
		Type      string         `json:"type"`
		IP        string         `json:"ip"`
		Metadata  map[string]any `json:"metadata"`
		CreatedAt time.Time      `json:"created_at"`
	}
	out := fiber.Map{"user": toAPIUser(u), "sessions": []sess{}, "identities": []ident{}, "audit": []event{}}
	var ss []sess
	for _, x := range sessions {
		ss = append(ss, sess{ID: x.ID.String(), Device: auth.DescribeDevice(x.UserAgent), IP: x.IP, AMR: x.AMR, LastUsedAt: x.LastUsedAt})
	}
	var ii []ident
	for _, x := range identities {
		ii = append(ii, ident{Provider: x.Provider, Email: x.Email})
	}
	var ee []event
	for _, x := range auditLog {
		ee = append(ee, event{Type: x.Type, IP: x.IP, Metadata: x.Metadata, CreatedAt: x.CreatedAt})
	}
	if ss != nil {
		out["sessions"] = ss
	}
	if ii != nil {
		out["identities"] = ii
	}
	if ee != nil {
		out["audit"] = ee
	}
	return out, nil
}

func (s *Server) apiCreateUser(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	var in struct {
		Email         string   `json:"email"`
		Password      string   `json:"password"`
		Name          string   `json:"name"`
		Roles         []string `json:"roles"`
		EmailVerified bool     `json:"email_verified"`
		Locale        string   `json:"locale"`
	}
	if err := decodeJSON(c, &in); err != nil {
		return nil, err
	}
	u, err := s.Auth.CreateUser(c.Context(), auth.CreateUserInput{Email: in.Email, Password: in.Password, Name: in.Name, Roles: in.Roles,
		EmailVerified: in.EmailVerified, Locale: in.Locale}, "access_token:"+t.Name, domain.RequestMeta{IP: c.IP()})
	if err != nil {
		return nil, err
	}
	s.apiAudit(c, t, "user_created", &u.ID, nil)
	return toAPIUser(u), nil
}

func (s *Server) apiUpdateUser(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	id, err := apiUserID(c)
	if err != nil {
		return nil, err
	}
	var in struct {
		Name     *string   `json:"name"`
		Roles    *[]string `json:"roles"`
		Disabled *bool     `json:"disabled"`
		Locale   *string   `json:"locale"`
	}
	if err := decodeJSON(c, &in); err != nil {
		return nil, err
	}
	if _, err := s.Store.GetUserByID(c.Context(), id); err != nil {
		return nil, err
	}
	actor := "access_token:" + t.Name
	changed := []string{}
	if in.Name != nil {
		if _, err := s.Auth.AdminUpdateProfile(c.Context(), id, *in.Name, actor); err != nil {
			return nil, err
		}
		changed = append(changed, "name")
	}
	if in.Roles != nil {
		if err := s.Auth.SetRoles(c.Context(), id, *in.Roles, actor); err != nil {
			return nil, err
		}
		changed = append(changed, "roles")
	}
	if in.Locale != nil {
		if _, err := s.Auth.SetLocale(c.Context(), id, *in.Locale); err != nil {
			return nil, err
		}
		changed = append(changed, "locale")
	}
	if in.Disabled != nil {
		if err := s.Auth.SetDisabled(c.Context(), id, *in.Disabled, actor); err != nil {
			return nil, err
		}
		changed = append(changed, "disabled")
	}
	s.apiAudit(c, t, "user_updated", &id, map[string]any{"fields": changed})
	u, err := s.Store.GetUserByID(c.Context(), id)
	if err != nil {
		return nil, err
	}
	return toAPIUser(u), nil
}

func (s *Server) apiRevokeUserSessions(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	id, err := apiUserID(c)
	if err != nil {
		return nil, err
	}
	n, err := s.Auth.RevokeAllSessions(c.Context(), id, uuid.Nil, domain.RevokeAdmin, domain.RequestMeta{IP: c.IP()})
	if err != nil {
		return nil, err
	}
	s.apiAudit(c, t, "sessions_revoked", &id, map[string]any{"count": n})
	return fiber.Map{"revoked": n}, nil
}

// ---------------------------------------------------------------------------
// Settings

// adminOnlySettings can only be changed in the admin UI: a token must never
// be able to lock admins out or widen its own reach.
var adminOnlySettings = []string{"admin_ip_allowlist", "admin_allowed_ips"}

func (s *Server) apiGetSettings(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	over, since := s.Settings.Overridden()
	return fiber.Map{"settings": s.Settings.Get(), "overridden": over, "updated_at": since}, nil
}

func (s *Server) apiPatchSettings(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	var patch map[string]json.RawMessage
	if err := decodeJSON(c, &patch); err != nil {
		return nil, err
	}
	cur, err := json.Marshal(s.Settings.Get())
	if err != nil {
		return nil, err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(cur, &merged); err != nil {
		return nil, err
	}
	var keys []string
	for k, v := range patch {
		for _, blocked := range adminOnlySettings {
			if k == blocked {
				return nil, domain.ErrForbidden.WithMessage(k + " can only be changed in the admin UI.")
			}
		}
		if _, ok := merged[k]; !ok {
			return nil, domain.ErrValidation.WithMessage("Unknown setting " + k + ".")
		}
		merged[k] = v
		keys = append(keys, k)
	}
	b, _ := json.Marshal(merged)
	var next settings.Runtime
	if err := json.Unmarshal(b, &next); err != nil {
		return nil, domain.ErrValidation.WithMessage("Invalid value: " + err.Error())
	}
	if next.RequirePublishableKey && !s.APIKeys.HasPublishable() {
		return nil, domain.ErrValidation.WithMessage("Create a publishable key before requiring one, or every app is locked out.")
	}
	if err := s.Settings.Save(c.Context(), next); err != nil {
		if de := domain.AsError(err); de != nil {
			return nil, err
		}
		return nil, domain.ErrValidation.WithMessage(err.Error())
	}
	s.apiAudit(c, t, "settings_changed", nil, map[string]any{"fields": keys})
	return s.apiGetSettings(c, t)
}

// ---------------------------------------------------------------------------
// Email templates

func (s *Server) apiTemplateLocale(c fiber.Ctx) (string, error) {
	l := c.Query("lang")
	if l != "" && i18n.Normalize(l) == "" {
		return "", domain.ErrValidation.WithMessage("Unsupported language " + l + ".")
	}
	return s.Renderer.Locale(l), nil
}

func (s *Server) apiListTemplates(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	type lang struct {
		Locale     string     `json:"locale"`
		Customized bool       `json:"customized"`
		UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	}
	type tpl struct {
		Name        string            `json:"name"`
		Title       string            `json:"title"`
		Description string            `json:"description"`
		Variables   map[string]string `json:"variables"`
		Languages   []lang            `json:"languages"`
	}
	list := append([]mailer.Info{*layoutInfo()}, mailer.Templates...)
	out := []tpl{}
	for _, t := range list {
		row := tpl{Name: t.Name, Title: t.Title, Description: t.Description, Variables: t.Vars}
		for _, l := range s.emailLangs(t.Name) {
			x := lang{Locale: l.Code, Customized: l.Customized}
			if l.Customized {
				at := l.UpdatedAt
				x.UpdatedAt = &at
			}
			row.Languages = append(row.Languages, x)
		}
		out = append(out, row)
	}
	return fiber.Map{"templates": out, "default_locale": s.Renderer.Locale("")}, nil
}

func (s *Server) apiGetTemplate(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	info, ok := emailInfo(c.Params("name"))
	if !ok {
		return nil, domain.ErrNotFound
	}
	loc, err := s.apiTemplateLocale(c)
	if err != nil {
		return nil, err
	}
	src, _ := s.Renderer.Effective(info.Name, loc)
	_, custom := s.Mail.Override(info.Name, loc)
	return fiber.Map{"name": info.Name, "locale": loc, "customized": custom, "subject": src.Subject, "html": src.HTML, "text": src.Text,
		"variables": info.Vars, "sample": mailer.SampleFor(info, loc)}, nil
}

type templateBody struct {
	Subject *string `json:"subject"`
	HTML    *string `json:"html"`
	Text    *string `json:"text"`
}

// merge applies the given fields to the effective source, so callers can
// change only the subject, for example.
func merge(src mailer.Source, b templateBody) mailer.Source {
	if b.Subject != nil {
		src.Subject = *b.Subject
	}
	if b.HTML != nil {
		src.HTML = *b.HTML
	}
	if b.Text != nil {
		src.Text = *b.Text
	}
	return src
}

func (s *Server) apiPreviewTemplate(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	info, ok := emailInfo(c.Params("name"))
	if !ok {
		return nil, domain.ErrNotFound
	}
	loc, err := s.apiTemplateLocale(c)
	if err != nil {
		return nil, err
	}
	var in templateBody
	if err := decodeJSON(c, &in); err != nil {
		return nil, err
	}
	src, _ := s.Renderer.Effective(info.Name, loc)
	msg, err := s.Mail.Preview(info.Name, loc, merge(src, in))
	if err != nil {
		if de := domain.AsError(err); de != nil {
			return nil, err
		}
		return nil, domain.ErrValidation.WithMessage(err.Error())
	}
	return fiber.Map{"subject": msg.Subject, "html": msg.HTML, "text": msg.Text}, nil
}

func (s *Server) apiSaveTemplate(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	info, ok := emailInfo(c.Params("name"))
	if !ok {
		return nil, domain.ErrNotFound
	}
	loc, err := s.apiTemplateLocale(c)
	if err != nil {
		return nil, err
	}
	var in templateBody
	if err := decodeJSON(c, &in); err != nil {
		return nil, err
	}
	src, _ := s.Renderer.Effective(info.Name, loc)
	if err := s.Mail.Save(c.Context(), info.Name, loc, merge(src, in)); err != nil {
		return nil, err
	}
	s.apiAudit(c, t, "email_template_saved", nil, map[string]any{"template": info.Name, "locale": loc})
	return s.apiGetTemplate(c, t)
}

func (s *Server) apiResetTemplate(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	info, ok := emailInfo(c.Params("name"))
	if !ok {
		return nil, domain.ErrNotFound
	}
	loc, err := s.apiTemplateLocale(c)
	if err != nil {
		return nil, err
	}
	if err := s.Mail.Reset(c.Context(), info.Name, loc); err != nil {
		return nil, err
	}
	s.apiAudit(c, t, "email_template_reset", nil, map[string]any{"template": info.Name, "locale": loc})
	return s.apiGetTemplate(c, t)
}

// ---------------------------------------------------------------------------
// Webhooks

type apiWebhook struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	Description string    `json:"description"`
	Events      []string  `json:"events"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	Secret      string    `json:"secret,omitempty"`
}

func toAPIWebhook(w *webhooks.Webhook) apiWebhook {
	ev := w.Events
	if ev == nil {
		ev = []string{}
	}
	return apiWebhook{ID: w.ID.String(), URL: w.URL, Description: w.Description, Events: ev, Enabled: w.Enabled, CreatedAt: w.CreatedAt}
}

func (s *Server) apiListWebhooks(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	out := []apiWebhook{}
	for _, w := range s.Webhooks.List() {
		out = append(out, toAPIWebhook(w))
	}
	return fiber.Map{"webhooks": out, "events": events.Types}, nil
}

func (s *Server) apiWebhook(c fiber.Ctx) (*webhooks.Webhook, error) {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return nil, domain.ErrNotFound
	}
	w := s.Webhooks.Get(id)
	if w == nil {
		return nil, domain.ErrNotFound
	}
	return w, nil
}

func (s *Server) apiWebhookDeliveries(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	w, err := s.apiWebhook(c)
	if err != nil {
		return nil, err
	}
	rows, err := s.Store.ListDeliveries(c.Context(), w.Topic(), 50)
	if err != nil {
		return nil, err
	}
	type delivery struct {
		ID        int64      `json:"id"`
		Type      string     `json:"type"`
		EventID   string     `json:"event_id"`
		Attempts  int        `json:"attempts"`
		LastError string     `json:"last_error,omitempty"`
		CreatedAt time.Time  `json:"created_at"`
		Delivered *time.Time `json:"delivered_at,omitempty"`
		Failed    *time.Time `json:"failed_at,omitempty"`
	}
	out := []delivery{}
	for _, d := range rows {
		var env events.Envelope
		_ = json.Unmarshal(d.Payload, &env)
		out = append(out, delivery{ID: d.ID, Type: env.Type, EventID: env.ID, Attempts: d.Attempts, LastError: d.LastError,
			CreatedAt: d.CreatedAt, Delivered: d.ProcessedAt, Failed: d.FailedAt})
	}
	return fiber.Map{"deliveries": out}, nil
}

type webhookBody struct {
	URL         *string   `json:"url"`
	Description *string   `json:"description"`
	Events      *[]string `json:"events"`
	Enabled     *bool     `json:"enabled"`
}

func (b webhookBody) apply(in webhooks.Input) webhooks.Input {
	if b.URL != nil {
		in.URL = *b.URL
	}
	if b.Description != nil {
		in.Description = *b.Description
	}
	if b.Events != nil {
		in.Events = *b.Events
	}
	if b.Enabled != nil {
		in.Enabled = *b.Enabled
	}
	return in
}

func (s *Server) apiCreateWebhook(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	var in webhookBody
	if err := decodeJSON(c, &in); err != nil {
		return nil, err
	}
	w, secret, err := s.Webhooks.Create(c.Context(), in.apply(webhooks.Input{Enabled: true}))
	if err != nil {
		return nil, err
	}
	s.apiAudit(c, t, "webhook_created", nil, map[string]any{"webhook_id": w.ID, "url": w.URL})
	out := toAPIWebhook(w)
	out.Secret = secret // shown once
	return out, nil
}

func (s *Server) apiUpdateWebhook(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	w, err := s.apiWebhook(c)
	if err != nil {
		return nil, err
	}
	var in webhookBody
	if err := decodeJSON(c, &in); err != nil {
		return nil, err
	}
	cur := webhooks.Input{URL: w.URL, Description: w.Description, Events: w.Events, Enabled: w.Enabled}
	if err := s.Webhooks.Update(c.Context(), w.ID, in.apply(cur)); err != nil {
		return nil, err
	}
	s.apiAudit(c, t, "webhook_updated", nil, map[string]any{"webhook_id": w.ID})
	return toAPIWebhook(s.Webhooks.Get(w.ID)), nil
}

func (s *Server) apiDeleteWebhook(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	w, err := s.apiWebhook(c)
	if err != nil {
		return nil, err
	}
	if err := s.Webhooks.Delete(c.Context(), w.ID); err != nil {
		return nil, err
	}
	s.apiAudit(c, t, "webhook_deleted", nil, map[string]any{"webhook_id": w.ID})
	return fiber.Map{"deleted": true}, nil
}

func (s *Server) apiTestWebhook(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	w, err := s.apiWebhook(c)
	if err != nil {
		return nil, err
	}
	body, err := events.NewEnvelope(webhooks.TestEvent, uuid.Nil, map[string]any{"message": "Test event sent through the admin API."})
	if err != nil {
		return nil, err
	}
	if err := s.Store.EnqueueOutbox(c.Context(), w.Topic(), body); err != nil {
		return nil, err
	}
	s.apiAudit(c, t, "webhook_tested", nil, map[string]any{"webhook_id": w.ID})
	return fiber.Map{"queued": true}, nil
}

// ---------------------------------------------------------------------------
// API keys, providers, audit

type apiKeyView struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	Name           string     `json:"name"`
	Hint           string     `json:"hint"`
	AllowedOrigins []string   `json:"allowed_origins"`
	Active         bool       `json:"active"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	Value          string     `json:"value,omitempty"`
}

func toAPIKey(k *apikeys.Key) apiKeyView {
	o := k.AllowedOrigins
	if o == nil {
		o = []string{}
	}
	return apiKeyView{ID: k.ID.String(), Kind: string(k.Kind), Name: k.Name, Hint: k.Hint, AllowedOrigins: o, Active: k.Active(),
		CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt}
}

func (s *Server) apiListAPIKeys(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	out := []apiKeyView{}
	for _, k := range s.APIKeys.List() {
		out = append(out, toAPIKey(k))
	}
	return fiber.Map{"api_keys": out}, nil
}

func (s *Server) apiCreateAPIKey(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	var in struct {
		Kind           string   `json:"kind"`
		Name           string   `json:"name"`
		AllowedOrigins []string `json:"allowed_origins"`
	}
	if err := decodeJSON(c, &in); err != nil {
		return nil, err
	}
	raw, k, err := s.APIKeys.Create(c.Context(), apikeys.Kind(in.Kind), in.Name, in.AllowedOrigins)
	if err != nil {
		return nil, err
	}
	s.apiAudit(c, t, "api_key_created", nil, map[string]any{"key_id": k.ID, "kind": k.Kind, "name": k.Name})
	out := toAPIKey(k)
	out.Value = raw // shown once
	return out, nil
}

func (s *Server) apiRevokeAPIKey(c fiber.Ctx, t *accesstokens.Token) (any, error) {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return nil, domain.ErrNotFound
	}
	if err := s.APIKeys.Revoke(c.Context(), id); err != nil {
		return nil, err
	}
	s.apiAudit(c, t, "api_key_revoked", nil, map[string]any{"key_id": id})
	return fiber.Map{"revoked": true}, nil
}

func (s *Server) apiProviders(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	type provider struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Enabled     bool   `json:"enabled"`
		Active      bool   `json:"active"`
		Source      string `json:"source"`
		CallbackURL string `json:"callback_url"`
		Error       string `json:"error,omitempty"`
	}
	out := []provider{}
	for _, st := range s.OAuth.Statuses() {
		out = append(out, provider{Name: st.Def.Name, DisplayName: st.Def.DisplayName, Enabled: st.Enabled, Active: st.Active,
			Source: string(st.Source), CallbackURL: st.CallbackURL, Error: st.Error})
	}
	return fiber.Map{"providers": out}, nil
}

func (s *Server) apiAuditLog(c fiber.Ctx, _ *accesstokens.Token) (any, error) {
	limit, _ := strconv.Atoi(c.Query("limit", "50"))
	limit = min(max(limit, 1), 500)
	var uid *uuid.UUID
	if v := c.Query("user_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, domain.ErrValidation.WithMessage("user_id must be a UUID.")
		}
		uid = &id
	}
	rows, err := s.Store.ListAudit(c.Context(), uid, limit)
	if err != nil {
		return nil, err
	}
	type event struct {
		Type      string         `json:"type"`
		UserID    *uuid.UUID     `json:"user_id,omitempty"`
		IP        string         `json:"ip"`
		Metadata  map[string]any `json:"metadata"`
		CreatedAt time.Time      `json:"created_at"`
	}
	out := []event{}
	for _, e := range rows {
		out = append(out, event{Type: e.Type, UserID: e.UserID, IP: e.IP, Metadata: e.Metadata, CreatedAt: e.CreatedAt})
	}
	return fiber.Map{"events": out}, nil
}
