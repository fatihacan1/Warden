package admin

import (
	"html"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/mailer"
)

// inboxRow is one line of the Inbox list.
type inboxRow struct {
	mailer.InboxItem
	Broken bool
}

// inboxPage lists the emails kept by MAIL_DELIVERY=inbox.
func (s *Server) inboxPage(c fiber.Ctx) error {
	rows, err := s.Store.ListInbox(c.Context(), 200, 0)
	if err != nil {
		return err
	}
	total, err := s.Store.CountInbox(c.Context())
	if err != nil {
		return err
	}
	items := make([]inboxRow, 0, len(rows))
	for _, r := range rows {
		it, err := mailer.OpenInboxMeta(s.Box, r)
		items = append(items, inboxRow{InboxItem: it, Broken: err != nil})
	}
	return s.render(c, fiber.StatusOK, "inbox", "inbox", "Inbox", map[string]any{
		"Items": items, "Total": total, "Active": s.Config.MailDelivery() == config.MailInbox,
		"Mode": s.Config.MailDelivery(), "Max": s.Config.Mail.InboxMax, "Days": int(mailer.InboxRetention.Hours() / 24),
		"Production": s.Config.IsProduction(),
	})
}

var linkRe = regexp.MustCompile(`https?://[^\s<>"'()]+`)

// emailLinks returns the distinct links of a message, which is what a tester
// needs to click (verification and reset links).
func emailLinks(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range linkRe.FindAllString(text, -1) {
		l = strings.TrimRight(l, ".,;")
		if !seen[l] && len(out) < 10 {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

func (s *Server) inboxItem(c fiber.Ctx) (mailer.InboxItem, error) {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return mailer.InboxItem{}, fiber.ErrNotFound
	}
	row, err := s.Store.GetInboxMessage(c.Context(), id)
	if err != nil {
		return mailer.InboxItem{}, fiber.ErrNotFound
	}
	it, err := mailer.OpenInbox(s.Box, *row)
	if err != nil {
		s.Log.Warn("inbox entry unreadable", "id", id, "err", err)
		return it, fiber.NewError(fiber.StatusUnprocessableEntity, "This email cannot be decrypted. The encryption key was probably changed.")
	}
	return it, nil
}

func (s *Server) inboxMessagePage(c fiber.Ctx) error {
	it, err := s.inboxItem(c)
	if err != nil {
		return err
	}
	return s.render(c, fiber.StatusOK, "inbox_message", "inbox", it.Subject, map[string]any{
		"Item": it, "Links": emailLinks(it.Text),
	})
}

// inboxPreview renders the HTML part for the sandboxed frame.
func (s *Server) inboxPreview(c fiber.Ctx) error {
	it, err := s.inboxItem(c)
	if err != nil {
		return err
	}
	// Same sandbox as the template preview, and stricter: no remote content at
	// all except images, no scripts, forms or same-origin access.
	c.Set("X-Frame-Options", "SAMEORIGIN")
	c.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'; sandbox")
	c.Type("html", "utf-8")
	if c.Query("view") == "text" {
		return c.SendString(`<pre style="font:13px/1.5 ui-monospace,monospace;white-space:pre-wrap;padding:16px;margin:0">Subject: ` +
			html.EscapeString(it.Subject) + "\n\n" + html.EscapeString(it.Text) + `</pre>`)
	}
	return c.SendString(it.HTML)
}

func (s *Server) deleteInboxMessage(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.ErrNotFound
	}
	if err := s.Store.DeleteInboxMessage(c.Context(), id); err != nil {
		return backErr(c, "/admin/inbox", err)
	}
	return back(c, "/admin/inbox", "inboxdeleted")
}

func (s *Server) clearInbox(c fiber.Ctx) error {
	n, err := s.Store.DeleteAllInbox(c.Context())
	if err != nil {
		return err
	}
	s.audit(c, "admin.inbox_cleared", map[string]any{"count": n})
	return back(c, "/admin/inbox", "inboxcleared")
}
