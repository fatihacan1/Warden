// Package webhooks delivers domain events to HTTP endpoints configured in the
// admin UI.
//
// Each event is written to the transactional outbox once per matching
// endpoint (topic "webhook:<id>"), so every endpoint has its own retries and a
// slow or broken receiver never delays the others or RabbitMQ.
//
// Requests follow the Standard Webhooks specification
// (https://www.standardwebhooks.com): headers webhook-id, webhook-timestamp
// and webhook-signature = "v1," + base64(HMAC-SHA256(secret,
// id + "." + timestamp + "." + body)). Receivers verify the signature and
// reject timestamps older than a few minutes, which stops replays.
package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/store"
)

// TopicPrefix marks outbox rows that are webhook deliveries.
const TopicPrefix = events.WebhookTopicPrefix

// TestEvent is sent by the "Send test event" button.
const TestEvent = "webhook.test"

// Webhook is an endpoint without its secret.
type Webhook struct {
	ID          uuid.UUID
	URL         string
	Description string
	Events      []string // empty = every event
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	secret      []byte // encrypted
}

// Wants reports whether the endpoint subscribes to an event type.
func (w *Webhook) Wants(typ string) bool {
	return w.Enabled && (len(w.Events) == 0 || slices.Contains(w.Events, typ))
}

// Topic is the outbox topic of this endpoint's deliveries.
func (w *Webhook) Topic() string { return TopicPrefix + w.ID.String() }

// Store persists endpoints.
type Store interface {
	ListWebhooks(ctx context.Context) ([]store.WebhookRow, error)
	CreateWebhook(ctx context.Context, r *store.WebhookRow) error
	UpdateWebhook(ctx context.Context, r *store.WebhookRow) error
	SetWebhookSecret(ctx context.Context, id uuid.UUID, secret []byte) error
	DeleteWebhook(ctx context.Context, id uuid.UUID) error
}

// Manager keeps the endpoint list in memory, reloads it periodically and
// delivers queued requests.
type Manager struct {
	store        Store
	box          *secretbox.Box
	log          *slog.Logger
	production   bool
	allowPrivate bool
	client       *http.Client
	list         atomic.Pointer[[]*Webhook]
}

// Options configure delivery.
type Options struct {
	Production bool
	// AllowPrivate permits loopback and private network targets.
	AllowPrivate bool
	Timeout      time.Duration
}

func NewManager(st Store, box *secretbox.Box, log *slog.Logger, opt Options) *Manager {
	m := &Manager{store: st, box: box, log: log, production: opt.Production, allowPrivate: opt.AllowPrivate}
	m.client = newClient(opt.Timeout, opt.AllowPrivate)
	empty := []*Webhook{}
	m.list.Store(&empty)
	return m
}

func label(id uuid.UUID) string { return "webhook:" + id.String() }

// Reload reads every endpoint from the database.
func (m *Manager) Reload(ctx context.Context) error {
	rows, err := m.store.ListWebhooks(ctx)
	if err != nil {
		return err
	}
	list := make([]*Webhook, 0, len(rows))
	for _, r := range rows {
		list = append(list, &Webhook{ID: r.ID, URL: r.URL, Description: r.Description, Events: r.Events, Enabled: r.Enabled,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, secret: r.Secret})
	}
	m.list.Store(&list)
	return nil
}

// Run reloads until ctx is cancelled.
func (m *Manager) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Reload(ctx); err != nil && ctx.Err() == nil {
				m.log.Error("webhooks reload failed", "err", err)
			}
		}
	}
}

// List returns every endpoint.
func (m *Manager) List() []*Webhook { return *m.list.Load() }

// Get returns an endpoint by id, or nil.
func (m *Manager) Get(id uuid.UUID) *Webhook {
	for _, w := range m.List() {
		if w.ID == id {
			return w
		}
	}
	return nil
}

// Targets implements events.Fanout: the outbox topics an event goes to.
func (m *Manager) Targets(typ string) []string {
	var out []string
	for _, w := range m.List() {
		if w.Wants(typ) {
			out = append(out, w.Topic())
		}
	}
	return out
}

// Input is what the admin UI submits.
type Input struct {
	URL         string
	Description string
	Events      []string
	Enabled     bool
}

func (m *Manager) validate(in *Input) error {
	in.URL = strings.TrimSpace(in.URL)
	in.Description = strings.TrimSpace(in.Description)
	u, err := url.Parse(in.URL)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || len(in.URL) > 2048:
		return domain.ErrValidation.WithMessage("Enter an absolute http(s) URL without credentials, for example https://api.example.com/webhooks/warden.")
	case m.production && u.Scheme != "https":
		return domain.ErrValidation.WithMessage("Webhook URLs must use https in production.")
	case u.Fragment != "":
		return domain.ErrValidation.WithMessage("Webhook URLs cannot contain a #fragment.")
	}
	if !m.allowPrivate {
		if ip := net.ParseIP(u.Hostname()); (ip != nil && !publicIP(ip)) || strings.EqualFold(u.Hostname(), "localhost") {
			return domain.ErrValidation.WithMessage("Private and loopback addresses are blocked (WEBHOOK_ALLOW_PRIVATE_NETWORKS=false).")
		}
	}
	if utf8.RuneCountInString(in.Description) > 200 {
		return domain.ErrValidation.WithMessage("Keep the description under 200 characters.")
	}
	clean := []string{}
	for _, e := range in.Events {
		if e = strings.TrimSpace(e); e == "" || slices.Contains(clean, e) {
			continue
		}
		if !slices.Contains(events.Types, e) {
			return domain.ErrValidation.WithMessage(fmt.Sprintf("Unknown event %q.", e))
		}
		clean = append(clean, e)
	}
	in.Events = clean
	return nil
}

// NewSecret returns a Standard Webhooks signing secret ("whsec_" + base64).
func NewSecret() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("webhooks: " + err.Error())
	}
	return "whsec_" + base64.StdEncoding.EncodeToString(b)
}

// Create adds an endpoint and returns its signing secret.
func (m *Manager) Create(ctx context.Context, in Input) (*Webhook, string, error) {
	if err := m.validate(&in); err != nil {
		return nil, "", err
	}
	if len(m.List()) >= 20 {
		return nil, "", domain.ErrValidation.WithMessage("At most 20 webhook endpoints.")
	}
	id := uuid.Must(uuid.NewV7())
	secret := NewSecret()
	sealed, err := m.box.Seal([]byte(secret), label(id))
	if err != nil {
		return nil, "", err
	}
	row := &store.WebhookRow{ID: id, URL: in.URL, Description: in.Description, Events: in.Events, Enabled: in.Enabled, Secret: sealed}
	if err := m.store.CreateWebhook(ctx, row); err != nil {
		return nil, "", err
	}
	if err := m.Reload(ctx); err != nil {
		return nil, "", err
	}
	return m.Get(id), secret, nil
}

// Update changes an endpoint's URL, description, events and state.
func (m *Manager) Update(ctx context.Context, id uuid.UUID, in Input) error {
	if m.Get(id) == nil {
		return domain.ErrNotFound
	}
	if err := m.validate(&in); err != nil {
		return err
	}
	if err := m.store.UpdateWebhook(ctx, &store.WebhookRow{ID: id, URL: in.URL, Description: in.Description, Events: in.Events, Enabled: in.Enabled}); err != nil {
		return err
	}
	return m.Reload(ctx)
}

// RotateSecret replaces the signing secret and returns the new one.
func (m *Manager) RotateSecret(ctx context.Context, id uuid.UUID) (string, error) {
	if m.Get(id) == nil {
		return "", domain.ErrNotFound
	}
	secret := NewSecret()
	sealed, err := m.box.Seal([]byte(secret), label(id))
	if err != nil {
		return "", err
	}
	if err := m.store.SetWebhookSecret(ctx, id, sealed); err != nil {
		return "", err
	}
	return secret, m.Reload(ctx)
}

// Secret decrypts an endpoint's signing secret (shown again on request).
func (m *Manager) Secret(id uuid.UUID) (string, error) {
	w := m.Get(id)
	if w == nil {
		return "", domain.ErrNotFound
	}
	b, err := m.box.Open(w.secret, label(id))
	return string(b), err
}

// Delete removes an endpoint and its pending deliveries.
func (m *Manager) Delete(ctx context.Context, id uuid.UUID) error {
	if err := m.store.DeleteWebhook(ctx, id); err != nil {
		return err
	}
	return m.Reload(ctx)
}

// ---------------------------------------------------------------------------
// Delivery

// ErrGone is returned when the receiver answered 410: delivery stops.
var ErrGone = errors.New("webhook endpoint answered 410 Gone")

// Deliver implements events.WebhookDeliverer. It returns nil when the
// endpoint no longer exists or is disabled: there is nobody to deliver to.
func (m *Manager) Deliver(ctx context.Context, topic, msgID string, body []byte) error {
	id, err := uuid.Parse(strings.TrimPrefix(topic, TopicPrefix))
	if err != nil {
		return nil
	}
	w := m.Get(id)
	if w == nil || !w.Enabled {
		return nil
	}
	secret, err := m.Secret(id)
	if err != nil {
		return fmt.Errorf("webhook secret: %w", err)
	}
	ts := time.Now().Unix()
	sig, err := Sign(secret, msgID, ts, body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Warden-Webhooks/1")
	req.Header.Set("webhook-id", msgID)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", sig)
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusGone:
		return events.Permanent(ErrGone)
	}
	return fmt.Errorf("receiver answered %d: %s", resp.StatusCode, strings.TrimSpace(strings.ToValidUTF8(string(snippet), "")))
}

// Sign computes the webhook-signature header value.
func Sign(secret, msgID string, ts int64, body []byte) (string, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return "", errors.New("webhooks: malformed secret")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msgID + "." + strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Verify checks a signature the way receivers should: constant time, any of
// the space separated signatures, timestamp within tolerance.
func Verify(secret, msgID, timestamp, signatures string, body []byte, tolerance time.Duration, now time.Time) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return false
	}
	want, err := Sign(secret, msgID, ts, body)
	if err != nil {
		return false
	}
	for _, s := range strings.Fields(signatures) {
		if hmac.Equal([]byte(s), []byte(want)) {
			return true
		}
	}
	return false
}

// newClient returns an HTTP client that never follows redirects and, unless
// allowPrivate, refuses to connect to non-public addresses. The check runs on
// the resolved IP at connect time, so DNS rebinding cannot bypass it.
func newClient(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !allowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || !publicIP(ip) {
				return fmt.Errorf("webhook target %s is not a public address", host)
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func publicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// 100.64.0.0/10 (carrier-grade NAT) and 0.0.0.0/8 are not public either.
	if v4 := ip.To4(); v4 != nil && (v4[0] == 0 || (v4[0] == 100 && v4[1]&0xc0 == 64)) {
		return false
	}
	return true
}
