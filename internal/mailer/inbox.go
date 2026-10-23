package mailer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/store"
)

// InboxRetention is how long the admin Inbox keeps an email.
const InboxRetention = 7 * 24 * time.Hour

// InboxStore is the persistence of the Inbox.
type InboxStore interface {
	AddInboxMessage(ctx context.Context, r *store.InboxRow) error
	PruneInbox(ctx context.Context, keep int, cutoff time.Time) (int64, error)
}

// Inbox keeps emails on the server, encrypted, instead of sending them. The
// admin UI lists them. Meant for test servers without an SMTP provider: the
// recipient never gets anything.
type Inbox struct {
	store InboxStore
	box   *secretbox.Box
	max   int
}

func NewInbox(st InboxStore, box *secretbox.Box, max int) *Inbox {
	return &Inbox{store: st, box: box, max: max}
}

type inboxMeta struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
}

type inboxBody struct {
	Text string `json:"text"`
	HTML string `json:"html"`
}

// Labels bind a ciphertext to its row, so sealed values cannot be swapped.
func inboxLabel(kind string, id uuid.UUID) string { return "inbox:" + kind + ":" + id.String() }

func (i *Inbox) Send(ctx context.Context, m Message) error {
	id := uuid.New()
	meta, err := i.seal(inboxMeta{To: m.To, Subject: m.Subject}, inboxLabel("meta", id))
	if err != nil {
		return err
	}
	body, err := i.seal(inboxBody{Text: m.Text, HTML: m.HTML}, inboxLabel("body", id))
	if err != nil {
		return err
	}
	if err := i.store.AddInboxMessage(ctx, &store.InboxRow{ID: id, Meta: meta, Body: body}); err != nil {
		return fmt.Errorf("mailer: inbox: %w", err)
	}
	// Best effort: the hourly cleanup also enforces the limits.
	_, _ = i.store.PruneInbox(ctx, i.max, time.Now().Add(-InboxRetention))
	return nil
}

func (i *Inbox) seal(v any, label string) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return i.box.Seal(raw, label)
}

// InboxItem is a decrypted Inbox entry. Text and HTML are empty in listings.
type InboxItem struct {
	ID        uuid.UUID
	CreatedAt time.Time
	To        string
	Subject   string
	Text      string
	HTML      string
}

// OpenInboxMeta decrypts the recipient and subject of a listed row.
func OpenInboxMeta(box *secretbox.Box, r store.InboxRow) (InboxItem, error) {
	var meta inboxMeta
	raw, err := box.Open(r.Meta, inboxLabel("meta", r.ID))
	if err == nil {
		err = json.Unmarshal(raw, &meta)
	}
	if err != nil {
		return InboxItem{ID: r.ID, CreatedAt: r.CreatedAt}, fmt.Errorf("mailer: inbox entry cannot be decrypted (was the encryption key changed?): %w", err)
	}
	return InboxItem{ID: r.ID, CreatedAt: r.CreatedAt, To: meta.To, Subject: meta.Subject}, nil
}

// OpenInbox decrypts a full row.
func OpenInbox(box *secretbox.Box, r store.InboxRow) (InboxItem, error) {
	it, err := OpenInboxMeta(box, r)
	if err != nil {
		return it, err
	}
	var body inboxBody
	raw, err := box.Open(r.Body, inboxLabel("body", r.ID))
	if err == nil {
		err = json.Unmarshal(raw, &body)
	}
	if err != nil {
		return it, fmt.Errorf("mailer: inbox entry cannot be decrypted: %w", err)
	}
	it.Text, it.HTML = body.Text, body.HTML
	return it, nil
}
