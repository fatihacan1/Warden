package config

import "net/url"

// Mail delivery modes (MAIL_DELIVERY).
const (
	// MailSMTP sends through an SMTP relay (SMTP_HOST). The production choice.
	MailSMTP = "smtp"
	// MailInbox stores emails encrypted and shows them in the admin Inbox.
	// Nothing leaves the server: for testing only.
	MailInbox = "inbox"
	// MailDirect delivers straight to the recipient's mail server on port 25.
	MailDirect = "direct"
	// MailLog writes emails to the log (bodies included). Development only.
	MailLog = "log"
)

// MailConfig selects how emails leave Warden.
type MailConfig struct {
	// Delivery is smtp, inbox, direct or log. Empty picks smtp when SMTP_HOST is
	// set and otherwise inbox in development (log in test). Production never
	// falls back: inbox, direct and log need to be chosen explicitly.
	Delivery string `env:"DELIVERY"`
	// HeloName is the host name announced to mail servers in direct mode.
	// Defaults to the host of HTTP_PUBLIC_URL.
	HeloName string `env:"HELO_NAME"`
	// InboxMax is how many emails the admin Inbox keeps.
	InboxMax int `env:"INBOX_MAX" envDefault:"500"`
}

// MailHeloName is the host name direct delivery announces: MAIL_HELO_NAME, else
// the host of HTTP_PUBLIC_URL.
func (c *Config) MailHeloName() string {
	if c.Mail.HeloName != "" {
		return c.Mail.HeloName
	}
	if u, err := url.Parse(c.HTTP.PublicURL); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "localhost"
}

// MailDelivery returns the effective delivery mode.
func (c *Config) MailDelivery() string {
	if d := c.Mail.Delivery; d != "" {
		return d
	}
	switch {
	case c.SMTP.Host != "":
		return MailSMTP
	case c.Env == "development":
		return MailInbox
	case c.Env == "test":
		return MailLog
	}
	return MailSMTP // production: validation then asks for SMTP_HOST
}
