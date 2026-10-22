package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/observability"
	"github.com/fatihacan1/warden/internal/store"
)

// Publisher delivers events to a broker.
type Publisher interface {
	Publish(ctx context.Context, topic, messageID string, body []byte) error
}

// RelayStore is the persistence the relay needs.
type RelayStore interface {
	ClaimOutbox(ctx context.Context, limit int, lease time.Duration) ([]store.OutboxMessage, error)
	CompleteOutbox(ctx context.Context, id int64, deletePayload bool) error
	RetryOutbox(ctx context.Context, id int64, next time.Time, lastErr string, dead bool) error
	OutboxBacklog(ctx context.Context) (pending, failed int, err error)
}

// Relay delivers outbox messages with exponential backoff.
type Relay struct {
	store       RelayStore
	publisher   Publisher // nil when events are disabled
	sender      mailer.Sender
	renderer    *mailer.Renderer
	box         *secretbox.Box
	log         *slog.Logger
	metrics     *observability.Metrics
	batch       int
	maxAttempts int
	poll        time.Duration
	workers     int
}

func NewRelay(st RelayStore, pub Publisher, sender mailer.Sender, renderer *mailer.Renderer, box *secretbox.Box,
	log *slog.Logger, metrics *observability.Metrics) *Relay {
	return &Relay{
		store: st, publisher: pub, sender: sender, renderer: renderer, box: box, log: log, metrics: metrics,
		batch: 50, maxAttempts: 15, poll: time.Second, workers: 8,
	}
}

// Run polls until ctx is cancelled.
func (r *Relay) Run(ctx context.Context) {
	t := time.NewTicker(r.poll)
	defer t.Stop()
	gauge := time.NewTicker(15 * time.Second)
	defer gauge.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-gauge.C:
			if p, f, err := r.store.OutboxBacklog(ctx); err == nil && r.metrics != nil {
				r.metrics.OutboxPending.Set(float64(p))
				r.metrics.OutboxFailed.Set(float64(f))
			}
		case <-t.C:
			// Drain quickly when there is a backlog, otherwise wait for the tick.
			for ctx.Err() == nil {
				n := r.Tick(ctx)
				if n < r.batch {
					break
				}
			}
		}
	}
}

// Tick processes one batch and returns how many messages were claimed.
func (r *Relay) Tick(ctx context.Context) int {
	msgs, err := r.store.ClaimOutbox(ctx, r.batch, time.Minute)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Error("outbox claim failed", "err", err)
		}
		return 0
	}
	sem := make(chan struct{}, r.workers)
	var wg sync.WaitGroup
	for _, m := range msgs {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			r.deliver(ctx, m)
		})
	}
	wg.Wait()
	return len(msgs)
}

func (r *Relay) deliver(ctx context.Context, m store.OutboxMessage) {
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("outbox delivery panicked", "id", m.ID, "topic", m.Topic, "panic", fmt.Sprint(p))
			_ = r.store.RetryOutbox(context.WithoutCancel(ctx), m.ID, time.Now(), "panic", true)
		}
	}()
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	kind := "event"
	isEmail := m.Topic == EmailTopic
	if isEmail {
		kind = "email"
	}
	err := r.dispatch(dctx, m, isEmail)
	if err == nil {
		r.count(kind, "ok")
		if err := r.store.CompleteOutbox(context.WithoutCancel(ctx), m.ID, isEmail); err != nil {
			r.log.Error("outbox complete failed", "id", m.ID, "err", err)
		}
		return
	}
	var perm permanentError
	dead := m.Attempts >= r.maxAttempts || errors.As(err, &perm)
	next := time.Now().Add(backoff(m.Attempts))
	r.count(kind, "error")
	r.log.Warn("outbox delivery failed", "id", m.ID, "topic", m.Topic, "attempt", m.Attempts, "dead", dead, "err", err)
	if err := r.store.RetryOutbox(context.WithoutCancel(ctx), m.ID, next, err.Error(), dead); err != nil {
		r.log.Error("outbox retry update failed", "id", m.ID, "err", err)
	}
}

type permanentError struct{ error }

func (r *Relay) dispatch(ctx context.Context, m store.OutboxMessage, isEmail bool) error {
	if !isEmail {
		if r.publisher == nil {
			return nil // events disabled after being enqueued: drop
		}
		var env Envelope
		if err := json.Unmarshal(m.Payload, &env); err != nil {
			return permanentError{fmt.Errorf("decode event: %w", err)}
		}
		return r.publisher.Publish(ctx, m.Topic, env.ID, m.Payload)
	}
	plain, err := r.box.Open(m.Payload, EmailTopic)
	if err != nil {
		return permanentError{fmt.Errorf("decrypt email: %w", err)}
	}
	var job EmailJob
	if err := json.Unmarshal(plain, &job); err != nil {
		return permanentError{fmt.Errorf("decode email: %w", err)}
	}
	msg, err := r.renderer.Render(job.To, job.Template, job.Data)
	if err != nil {
		return permanentError{err}
	}
	return r.sender.Send(ctx, msg)
}

func (r *Relay) count(kind, result string) {
	if r.metrics != nil {
		r.metrics.OutboxSent.WithLabelValues(kind, result).Inc()
	}
}

// backoff: 2s, 4s, 8s ... capped at 1h.
func backoff(attempt int) time.Duration {
	d := time.Duration(math.Pow(2, float64(min(attempt, 12)))) * time.Second
	return min(d, time.Hour)
}
