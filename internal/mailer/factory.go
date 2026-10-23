package mailer

import (
	"log/slog"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/crypto/secretbox"
)

// NewSender builds the sender for MAIL_DELIVERY. st may be nil when the Inbox
// is not needed (the mail-test command).
func NewSender(cfg *config.Config, st InboxStore, box *secretbox.Box, log *slog.Logger) Sender {
	switch cfg.MailDelivery() {
	case config.MailSMTP:
		return NewSMTP(cfg.SMTP)
	case config.MailDirect:
		return NewDirect(cfg.SMTP.From, cfg.MailHeloName())
	case config.MailInbox:
		if st != nil {
			return NewInbox(st, box, cfg.Mail.InboxMax)
		}
	}
	return NewLog(log)
}
