// Package mailer renders and delivers transactional emails.
package mailer

import (
	"bytes"
	"context"
	"embed"
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
)

var subjects = map[string]string{
	TemplateVerifyEmail:     "Verify your email address",
	TemplateResetPassword:   "Reset your password",
	TemplatePasswordChanged: "Your password was changed",
	TemplateMFAChanged:      "Your two-factor authentication settings changed",
}

//go:embed templates/*
var templateFS embed.FS

// Renderer turns a template name + data into a Message.
type Renderer struct {
	appName func() string
	html    *htmltemplate.Template
	text    *texttemplate.Template
}

// NewRenderer creates a renderer; appName is read on every render so it can
// change at runtime.
func NewRenderer(appName func() string) (*Renderer, error) {
	h, err := htmltemplate.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	t, err := texttemplate.ParseFS(templateFS, "templates/*.txt")
	if err != nil {
		return nil, err
	}
	return &Renderer{appName: appName, html: h, text: t}, nil
}

// Render builds a message. data is exposed to templates as .Data.
func (r *Renderer) Render(to, name string, data map[string]string) (Message, error) {
	subject, ok := subjects[name]
	if !ok {
		return Message{}, fmt.Errorf("mailer: unknown template %q", name)
	}
	app := r.appName()
	view := map[string]any{"AppName": app, "Data": data, "Year": time.Now().Year()}
	var text, html bytes.Buffer
	if err := r.text.ExecuteTemplate(&text, name+".txt", view); err != nil {
		return Message{}, err
	}
	if err := r.html.ExecuteTemplate(&html, name+".html", view); err != nil {
		return Message{}, err
	}
	return Message{To: to, Subject: app + ": " + subject, Text: text.String(), HTML: html.String()}, nil
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

	policy := mail.TLSMandatory
	switch s.cfg.TLSPolicy {
	case "opportunistic":
		policy = mail.TLSOpportunistic
	case "none":
		policy = mail.NoTLS
	}
	opts := []mail.Option{mail.WithPort(s.cfg.Port), mail.WithTLSPolicy(policy), mail.WithTimeout(15 * time.Second)}
	if s.cfg.Port == 465 {
		opts = append(opts, mail.WithSSL()) // implicit TLS (SMTPS)
	}
	if s.cfg.Username != "" {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(s.cfg.Username), mail.WithPassword(s.cfg.Password))
	}
	client, err := mail.NewClient(s.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("mailer: client: %w", err)
	}
	return client.DialAndSendWithContext(ctx, msg)
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
