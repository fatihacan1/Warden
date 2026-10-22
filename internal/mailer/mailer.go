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
	"github.com/fatihacan1/warden/internal/i18n"
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
	TemplateNewDevice       = "new_device"
	TemplateAccountLocked   = "account_locked"
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
	{TemplateNewDevice, "New device sign-in", "Security notice the first time an account signs in from a device it has not used before. Turn it off in Settings.",
		map[string]string{"Device": "Browser and OS, e.g. Chrome on Windows", "IP": "IP address of the sign-in", "Location": "Country, when a proxy like Cloudflare reports it (may be empty)",
			"Method": "How they signed in: Password, Google, ...", "When": "Date and time (UTC)", "SignOutLink": "Link that ends that session (may be empty)"},
		map[string]string{"Device": "Chrome on Windows", "IP": "203.0.113.24", "Location": "TR", "Method": "Password", "When": "Thu, 22 Oct 2026 10:00 UTC",
			"SignOutLink": "https://auth.example.com/v1/auth/sessions/end?token=sample"}},
	{TemplateAccountLocked, "Account locked", "Security notice when too many wrong passwords pause password sign-in. Sent once per lockout. Turn it off in Settings.",
		map[string]string{"Attempts": "Number of failed attempts", "Duration": "How long sign-in is paused", "IP": "IP address of the last attempt", "When": "Date and time (UTC)"},
		map[string]string{"Attempts": "10", "Duration": "15 minutes", "IP": "203.0.113.24", "When": "Thu, 22 Oct 2026 10:00 UTC"}},
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
var defaultSubjects = map[string]map[string]string{
	"en": {
		TemplateVerifyEmail:     "{{.AppName}}: Verify your email address",
		TemplateResetPassword:   "{{.AppName}}: Reset your password",
		TemplatePasswordChanged: "{{.AppName}}: Your password was changed",
		TemplateMFAChanged:      "{{.AppName}}: Your two-factor authentication settings changed",
		TemplateNewDevice:       "{{.AppName}}: New sign-in from {{.Data.Device}}",
		TemplateAccountLocked:   "{{.AppName}}: Sign-in paused after failed attempts",
	},
	"tr": {
		TemplateVerifyEmail:     "{{.AppName}}: E-posta adresinizi doğrulayın",
		TemplateResetPassword:   "{{.AppName}}: Şifrenizi sıfırlayın",
		TemplatePasswordChanged: "{{.AppName}}: Şifreniz değiştirildi",
		TemplateMFAChanged:      "{{.AppName}}: İki adımlı doğrulama ayarlarınız değişti",
		TemplateNewDevice:       "{{.AppName}}: {{.Data.Device}} cihazından yeni giriş",
		TemplateAccountLocked:   "{{.AppName}}: Başarısız denemeler nedeniyle giriş durduruldu",
	},
}

//go:embed templates/*/*.html templates/*/*.txt
var templateFS embed.FS

// Source is the editable form of a template. For the layout only HTML is used.
type Source struct {
	Subject string
	HTML    string
	Text    string
}

// Overrides supplies templates saved in the admin UI.
type Overrides interface {
	Override(name, locale string) (Source, bool)
}

// Renderer turns a template name + data into a Message.
type Renderer struct {
	appName   func() string
	locale    func() string // instance default language
	defaults  map[string]map[string]Source
	overrides Overrides
}

// NewRenderer creates a renderer; appName and defaultLocale are read on every
// render so they can change at runtime.
func NewRenderer(appName func() string, defaultLocale func() string) (*Renderer, error) {
	if defaultLocale == nil {
		defaultLocale = func() string { return i18n.Default }
	}
	r := &Renderer{appName: appName, locale: defaultLocale, defaults: map[string]map[string]Source{}}
	for _, loc := range i18n.Locales {
		dir := "templates/" + loc.Code + "/"
		set := map[string]Source{}
		layout, err := templateFS.ReadFile(dir + "_layout.html")
		if err != nil {
			return nil, err
		}
		set[LayoutName] = Source{HTML: string(layout)}
		for _, t := range Templates {
			h, err := templateFS.ReadFile(dir + t.Name + ".html")
			if err != nil {
				return nil, err
			}
			txt, err := templateFS.ReadFile(dir + t.Name + ".txt")
			if err != nil {
				return nil, err
			}
			set[t.Name] = Source{Subject: defaultSubjects[loc.Code][t.Name], HTML: string(h), Text: string(txt)}
		}
		r.defaults[loc.Code] = set
	}
	// Built-in templates must always render; fail at startup if not.
	for _, loc := range i18n.Locales {
		for _, t := range Templates {
			if _, err := r.Render("check@example.com", t.Name, loc.Code, t.Sample); err != nil {
				return nil, fmt.Errorf("mailer: built-in template %s (%s): %w", t.Name, loc.Code, err)
			}
		}
	}
	return r, nil
}

// Locale resolves the language to send in: the requested one when supported,
// else the instance default.
func (r *Renderer) Locale(requested string) string {
	if l := i18n.Normalize(requested); l != "" {
		return l
	}
	if l := i18n.Normalize(r.locale()); l != "" {
		return l
	}
	return i18n.Default
}

// WithOverrides makes the renderer use templates saved in the admin UI.
func (r *Renderer) WithOverrides(o Overrides) *Renderer {
	r.overrides = o
	return r
}

// Default returns the built-in source of a template in a language.
func (r *Renderer) Default(name, locale string) (Source, bool) {
	s, ok := r.defaults[r.Locale(locale)][name]
	return s, ok
}

// Effective returns the source in use for a language: the override saved in
// the admin UI if any, else the built-in one.
func (r *Renderer) Effective(name, locale string) (Source, bool) {
	locale = r.Locale(locale)
	if r.overrides != nil {
		if s, ok := r.overrides.Override(name, locale); ok {
			return s, true
		}
	}
	return r.Default(name, locale)
}

// Render builds a message with the effective templates in the recipient's
// language ("" = instance default). data is exposed to templates as .Data.
func (r *Renderer) Render(to, name, locale string, data map[string]string) (Message, error) {
	src, ok := r.Effective(name, locale)
	if !ok || name == LayoutName {
		return Message{}, fmt.Errorf("mailer: unknown template %q", name)
	}
	layout, _ := r.Effective(LayoutName, locale)
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

// localSamples replace English sample values in previews of other languages.
var localSamples = map[string]map[string]string{
	"tr": {"ExpiresIn": "24 saat", "Duration": "15 dakika", "When": "22 Ekim 2026 10:00 UTC", "Method": "Şifre", "Action": "enabled"},
}

// SampleFor returns preview data for a template in a language.
func SampleFor(info *Info, locale string) map[string]string {
	out := map[string]string{}
	for k, v := range info.Sample {
		out[k] = v
		if l, ok := localSamples[locale][k]; ok {
			out[k] = l
		}
	}
	return out
}
