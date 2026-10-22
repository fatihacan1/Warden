// Package mailer renders and delivers transactional emails.
//
// Built-in templates ship with the binary. Each one can be overridden from
// the admin UI (subject, HTML and plain text), as can the shared HTML layout.
// Overrides are validated by rendering them with sample data before they are
// saved, so a broken template never reaches the delivery queue.
package mailer

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/wneessen/go-mail"

	"github.com/fatihacan1/warden/internal/config"
)

// Message is a rendered email.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Sender delivers messages.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Template names.
const (
	TemplateVerifyEmail     = "verify_email"
	TemplateResetPassword   = "reset_password"
	TemplatePasswordChanged = "password_changed"
	TemplateMFAChanged      = "mfa_changed"
	// LayoutName is the shared HTML frame. It must define "layout_start" and
	// "layout_end"; templates call them with {{template "layout_start" .}}.
	LayoutName = "layout"
)

// Info describes a template for the admin UI.
type Info struct {
	Name        string
	Title       string
	Description string
	// Vars are the .Data fields the template receives.
	Vars map[string]string
	// Sample is used for previews and validation.
	Sample map[string]string
}

// Templates lists every built-in template.
var Templates = []Info{
	{TemplateVerifyEmail, "Verify email", "Sent after sign-up and when a user asks for a new verification link.",
		map[string]string{"Link": "One-time verification link", "ExpiresIn": "How long the link works, e.g. 24 hours"},
		map[string]string{"Link": "https://app.example.com/verify-email?token=sample-token", "ExpiresIn": "24 hours"}},
	{TemplateResetPassword, "Reset password", "Sent when a user asks to reset a forgotten password.",
		map[string]string{"Link": "One-time reset link", "ExpiresIn": "How long the link works, e.g. 30 minutes"},
		map[string]string{"Link": "https://app.example.com/reset-password?token=sample-token", "ExpiresIn": "30 minutes"}},
	{TemplatePasswordChanged, "Password changed", "Security notice after a password change or reset.",
		map[string]string{"When": "Date and time of the change (UTC)"},
		map[string]string{"When": "Thu, 22 Oct 2026 10:00:00 UTC"}},
	{TemplateMFAChanged, "Two-factor changed", "Security notice when two-factor authentication is turned on or off.",
		map[string]string{"Action": "enabled or disabled", "When": "Date and time of the change (UTC)"},
		map[string]string{"Action": "enabled", "When": "Thu, 22 Oct 2026 10:00:00 UTC"}},
}

// Lookup returns the Info of a template, or nil.
func Lookup(name string) *Info {
	for i := range Templates {
		if Templates[i].Name == name {
			return &Templates[i]
		}
	}
	return nil
}

// #nosec G101 -- template names, not credentials
var defaultSubjects = map[string]string{
	TemplateVerifyEmail:     "{{.AppName}}: Verify your email address",
	TemplateResetPassword:   "{{.AppName}}: Reset your password",
	TemplatePasswordChanged: "{{.AppName}}: Your password was changed",
	TemplateMFAChanged:      "{{.AppName}}: Your two-factor authentication settings changed",
}

//go:embed templates/*
var templateFS embed.FS

// Source is the editable form of a template. For the layout only HTML is used.
type Source struct {
	Subject string
	HTML    string
	Text    string
}

// Overrides supplies templates saved in the admin UI.
type Overrides interface {
	Override(name string) (Source, bool)
}

// Renderer turns a template name + data into a Message.
type Renderer struct {
	appName   func() string
	defaults  map[string]Source
	overrides Overrides
}

// NewRenderer creates a renderer; appName is read on every render so it can
// change at runtime.
func NewRenderer(appName func() string) (*Renderer, error) {
	r := &Renderer{appName: appName, defaults: map[string]Source{}}
	layout, err := templateFS.ReadFile("templates/_layout.html")
	if err != nil {
		return nil, err
	}
	r.defaults[LayoutName] = Source{HTML: string(layout)}
	for _, t := range Templates {
		h, err := templateFS.ReadFile("templates/" + t.Name + ".html")
		if err != nil {
			return nil, err
		}
		txt, err := templateFS.ReadFile("templates/" + t.Name + ".txt")
		if err != nil {
			return nil, err
		}
		r.defaults[t.Name] = Source{Subject: defaultSubjects[t.Name], HTML: string(h), Text: string(txt)}
	}
	// Built-in templates must always render; fail at startup if not.
	for _, t := range Templates {
		if _, err := r.Render("check@example.com", t.Name, t.Sample); err != nil {
			return nil, fmt.Errorf("mailer: built-in template %s: %w", t.Name, err)
		}
	}
	return r, nil
}

// WithOverrides makes the renderer use templates saved in the admin UI.
func (r *Renderer) WithOverrides(o Overrides) *Renderer {
	r.overrides = o
	return r
}

// Default returns the built-in source of a template.
func (r *Renderer) Default(name string) (Source, bool) {
	s, ok := r.defaults[name]
	return s, ok
}

// Effective returns the source in use: the override if any, else the default.
func (r *Renderer) Effective(name string) (Source, bool) {
	if r.overrides != nil {
		if s, ok := r.overrides.Override(name); ok {
			return s, true
		}
	}
	return r.Default(name)
}

// Render builds a message with the effective templates. data is exposed to
// templates as .Data.
func (r *Renderer) Render(to, name string, data map[string]string) (Message, error) {
	src, ok := r.Effective(name)
	if !ok || name == LayoutName {
		return Message{}, fmt.Errorf("mailer: unknown template %q", name)
	}
	layout, _ := r.Effective(LayoutName)
	return r.RenderSource(to, src, layout.HTML, data)
}

// RenderSource renders an arbitrary source with layout (previews, validation).
func (r *Renderer) RenderSource(to string, src Source, layout string, data map[string]string) (Message, error) {
	if data == nil {
		data = map[string]string{}
	}
	app := r.appName()
	view := map[string]any{"AppName": app, "Data": data, "Year": time.Now().Year()}

	subject, err := execText("subject", src.Subject, view)
	if err != nil {
		return Message{}, fmt.Errorf("subject: %w", err)
	}
	subject = strings.Join(strings.Fields(subject), " ") // no header injection via newlines
	if subject == "" {
		return Message{}, errors.New("subject: renders to an empty line")
	}
	text, err := execText("text", src.Text, view)
	if err != nil {
		return Message{}, fmt.Errorf("plain text: %w", err)
	}
	h, err := htmltemplate.New("layout").Option("missingkey=zero").Parse(layout)
	if err != nil {
		return Message{}, fmt.Errorf("layout: %w", err)
	}
	if _, err := h.New("body").Parse(src.HTML); err != nil {
		return Message{}, fmt.Errorf("HTML: %w", err)
	}
	var html bytes.Buffer
	if err := h.ExecuteTemplate(&html, "body", view); err != nil {
		return Message{}, fmt.Errorf("HTML: %w", err)
	}
	return Message{To: to, Subject: subject, Text: text, HTML: html.String()}, nil
}

func execText(name, src string, view any) (string, error) {
	t, err := texttemplate.New(name).Option("missingkey=zero").Parse(src)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, view); err != nil {
		return "", err
	}
	return b.String(), nil
}

// SMTP delivers through an SMTP relay (SES, Postmark, Resend, Mailgun, ...).
type SMTP struct {
	cfg  config.SMTPConfig
	from string
}

func NewSMTP(cfg config.SMTPConfig) *SMTP { return &SMTP{cfg: cfg, from: cfg.From} }

func (s *SMTP) Send(ctx context.Context, m Message) error {
	msg := mail.NewMsg()
	if err := msg.From(s.from); err != nil {
		return fmt.Errorf("mailer: from: %w", err)
	}
	if err := msg.To(m.To); err != nil {
		return fmt.Errorf("mailer: to: %w", err)
	}
	msg.Subject(m.Subject)
	msg.SetBodyString(mail.TypeTextPlain, m.Text)
	msg.AddAlternativeString(mail.TypeTextHTML, m.HTML)
	client, err := NewClient(s.cfg)
	if err != nil {
		return err
	}
	return client.DialAndSendWithContext(ctx, msg)
}

// NewClient builds an SMTP client from the configuration (also used by the
// setup wizard to test credentials).
func NewClient(cfg config.SMTPConfig) (*mail.Client, error) {
	policy := mail.TLSMandatory
	switch cfg.TLSPolicy {
	case "opportunistic":
		policy = mail.TLSOpportunistic
	case "none":
		policy = mail.NoTLS
	}
	opts := []mail.Option{mail.WithPort(cfg.Port), mail.WithTLSPolicy(policy), mail.WithTimeout(15 * time.Second)}
	if cfg.Port == 465 {
		opts = append(opts, mail.WithSSL()) // implicit TLS (SMTPS)
	}
	if cfg.Username != "" {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(cfg.Username), mail.WithPassword(cfg.Password))
	}
	client, err := mail.NewClient(cfg.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("mailer: client: %w", err)
	}
	return client, nil
}

// Log writes emails to the log instead of sending them. Development only:
// the log contains one-time links.
type Log struct{ log *slog.Logger }

func NewLog(log *slog.Logger) *Log { return &Log{log: log} }

func (l *Log) Send(_ context.Context, m Message) error {
	l.log.Warn("SMTP not configured, email written to log (development only)",
		"to", m.To, "subject", m.Subject, "body", strings.TrimSpace(m.Text))
	return nil
}
