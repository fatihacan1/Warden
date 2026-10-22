// Package events implements the transactional outbox.
//
// State changes and the events/emails they cause are committed atomically:
// either both are written or neither is. A background relay then delivers
// them at-least-once (consumers must be idempotent, use the event id).
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/store"
)

// Event types published to RabbitMQ (routing keys).
const (
	UserCreated        = "user.created"
	UserUpdated        = "user.updated"
	UserDeleted        = "user.deleted"
	UserEmailVerified  = "user.email_verified"
	UserPasswordChange = "user.password_changed"
	UserSignedIn       = "user.signed_in"
	UserDisabled       = "user.disabled"
	UserEnabled        = "user.enabled"
	UserMFAEnabled     = "user.mfa_enabled"
	UserMFADisabled    = "user.mfa_disabled"
	IdentityLinked     = "identity.linked"
	IdentityUnlinked   = "identity.unlinked"
	SessionRevoked     = "session.revoked"
)

// EmailTopic marks outbox rows delivered by the mailer, not RabbitMQ.
const EmailTopic = "email.send"

// Envelope is the JSON body of every published event.
type Envelope struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	OccurredAt time.Time `json:"occurred_at"`
	UserID     string    `json:"user_id,omitempty"`
	Data       any       `json:"data,omitempty"`
}

// EmailJob is an encrypted outbox payload for the mailer.
type EmailJob struct {
	To       string            `json:"to"`
	Template string            `json:"template"`
	Data     map[string]string `json:"data"`
}

// Writer enqueues events and emails inside the caller's transaction.
type Writer struct {
	box           *secretbox.Box
	eventsEnabled bool
}

func NewWriter(box *secretbox.Box, eventsEnabled bool) *Writer {
	return &Writer{box: box, eventsEnabled: eventsEnabled}
}

// Event enqueues a domain event. It is a no-op when no broker is configured.
func (w *Writer) Event(ctx context.Context, tx *store.Store, typ string, userID uuid.UUID, data any) error {
	if !w.eventsEnabled {
		return nil
	}
	env := Envelope{ID: uuid.Must(uuid.NewV7()).String(), Type: typ, OccurredAt: time.Now().UTC(), Data: data}
	if userID != uuid.Nil {
		env.UserID = userID.String()
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("events: marshal: %w", err)
	}
	return tx.EnqueueOutbox(ctx, typ, body)
}

// Email enqueues a transactional email. The payload contains one-time links,
// so it is encrypted at rest and deleted after delivery.
func (w *Writer) Email(ctx context.Context, tx *store.Store, to, template string, data map[string]string) error {
	if strings.TrimSpace(to) == "" {
		return nil
	}
	body, err := json.Marshal(EmailJob{To: to, Template: template, Data: data})
	if err != nil {
		return err
	}
	sealed, err := w.box.Seal(body, EmailTopic)
	if err != nil {
		return err
	}
	return tx.EnqueueOutbox(ctx, EmailTopic, sealed)
}
