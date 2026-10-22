package events

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/store"
)

type fakeStore struct {
	mu        sync.Mutex
	queue     []store.OutboxMessage
	completed map[int64]bool // id -> deleted
	retried   map[int64]bool // id -> dead
}

func (f *fakeStore) ClaimOutbox(context.Context, int, time.Duration) ([]store.OutboxMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := f.queue
	f.queue = nil
	for i := range q {
		q[i].Attempts++
	}
	return q, nil
}

func (f *fakeStore) CompleteOutbox(_ context.Context, id int64, del bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completed[id] = del
	return nil
}

func (f *fakeStore) RetryOutbox(_ context.Context, id int64, _ time.Time, _ string, dead bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retried[id] = dead
	return nil
}

func (f *fakeStore) OutboxBacklog(context.Context) (int, int, error) { return 0, 0, nil }

type fakePublisher struct {
	mu   sync.Mutex
	got  []string
	fail bool
}

func (p *fakePublisher) Publish(_ context.Context, topic, _ string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errors.New("broker down")
	}
	p.got = append(p.got, topic)
	return nil
}

type fakeSender struct {
	mu   sync.Mutex
	sent []mailer.Message
}

func (s *fakeSender) Send(_ context.Context, m mailer.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, m)
	return nil
}

func setup(t *testing.T) (*fakeStore, *fakePublisher, *fakeSender, *Relay, *secretbox.Box) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, _ := secretbox.New(key)
	st := &fakeStore{completed: map[int64]bool{}, retried: map[int64]bool{}}
	pub := &fakePublisher{}
	snd := &fakeSender{}
	r, err := mailer.NewRenderer(func() string { return "Test" })
	if err != nil {
		t.Fatal(err)
	}
	relay := NewRelay(st, pub, snd, r, box, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	return st, pub, snd, relay, box
}

func TestRelayDeliversEventsAndEmails(t *testing.T) {
	st, pub, snd, relay, box := setup(t)
	env, _ := json.Marshal(Envelope{ID: "e1", Type: UserCreated})
	job, _ := json.Marshal(EmailJob{To: "a@b.co", Template: mailer.TemplateVerifyEmail, Data: map[string]string{"Link": "https://x", "ExpiresIn": "1h"}})
	sealed, _ := box.Seal(job, EmailTopic)
	st.queue = []store.OutboxMessage{{ID: 1, Topic: UserCreated, Payload: env}, {ID: 2, Topic: EmailTopic, Payload: sealed}}

	if n := relay.Tick(context.Background()); n != 2 {
		t.Fatalf("claimed %d", n)
	}
	if len(pub.got) != 1 || pub.got[0] != UserCreated {
		t.Fatalf("published %v", pub.got)
	}
	if len(snd.sent) != 1 || snd.sent[0].To != "a@b.co" {
		t.Fatalf("sent %v", snd.sent)
	}
	if del, ok := st.completed[1]; !ok || del {
		t.Fatal("event should be marked processed, not deleted")
	}
	if del, ok := st.completed[2]; !ok || !del {
		t.Fatal("email payload (contains one-time link) must be deleted after delivery")
	}
}

func TestRelayRetriesAndDeadLetters(t *testing.T) {
	st, pub, _, relay, _ := setup(t)
	pub.fail = true
	env, _ := json.Marshal(Envelope{ID: "e1"})
	st.queue = []store.OutboxMessage{
		{ID: 1, Topic: UserCreated, Payload: env, Attempts: 0},
		{ID: 2, Topic: EmailTopic, Payload: []byte("tampered")},
	}
	relay.Tick(context.Background())
	if dead, ok := st.retried[1]; !ok || dead {
		t.Fatalf("transient failure should be retried, not dead-lettered (dead=%v ok=%v)", dead, ok)
	}
	if dead := st.retried[2]; !dead {
		t.Fatal("undecryptable payload is a permanent error and must be dead-lettered immediately")
	}
}

func TestBackoff(t *testing.T) {
	if backoff(1) != 2*time.Second || backoff(3) != 8*time.Second {
		t.Fatal("unexpected backoff")
	}
	if backoff(100) != time.Hour {
		t.Fatal("backoff must be capped at 1h")
	}
}
