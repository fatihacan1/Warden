// Package observability wires structured logging, Prometheus metrics and
// Sentry error reporting.
package observability

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Version is set at build time with -ldflags "-X ...observability.Version=v1.2.3".
var Version = "dev"

// NewLogger returns a JSON (production) or text (local) logger.
func NewLogger(level, format, service, env string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(h).With("service", service, "env", env, "version", Version)
}

// Metrics holds every Prometheus collector exposed on the admin port.
type Metrics struct {
	Registry *prometheus.Registry

	HTTPRequests  *prometheus.CounterVec
	HTTPDuration  *prometheus.HistogramVec
	HTTPInFlight  prometheus.Gauge
	HTTPShed      prometheus.Counter
	GRPCRequests  *prometheus.CounterVec
	AuthEvents    *prometheus.CounterVec
	RateLimited   *prometheus.CounterVec
	HashWait      prometheus.Histogram
	HashDuration  prometheus.Histogram
	HashRejected  prometheus.Counter
	OutboxPending prometheus.Gauge
	OutboxFailed  prometheus.Gauge
	OutboxSent    *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_http_requests_total", Help: "HTTP requests by route and status.",
		}, []string{"method", "route", "status"}),
		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "warden_http_request_duration_seconds", Help: "HTTP request latency.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"method", "route"}),
		HTTPInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "warden_http_in_flight_requests", Help: "Requests currently being served.",
		}),
		HTTPShed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "warden_http_shed_total", Help: "Requests rejected by load shedding.",
		}),
		GRPCRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_grpc_requests_total", Help: "gRPC requests by method and code.",
		}, []string{"method", "code"}),
		AuthEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_auth_events_total", Help: "Authentication events (sign_in, sign_up, refresh, ...) by result.",
		}, []string{"event", "result"}),
		RateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_rate_limited_total", Help: "Requests rejected by rate limiting, by policy.",
		}, []string{"policy"}),
		HashWait: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "warden_password_hash_wait_seconds", Help: "Time spent waiting for a hashing slot.",
			Buckets: []float64{.001, .005, .01, .05, .1, .25, .5, 1, 2, 3},
		}),
		HashDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "warden_password_hash_duration_seconds", Help: "Argon2id compute time.",
			Buckets: []float64{.01, .025, .05, .1, .2, .4, .8, 1.6},
		}),
		HashRejected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "warden_password_hash_rejected_total", Help: "Hash requests rejected because the hasher was saturated.",
		}),
		OutboxPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "warden_outbox_pending", Help: "Outbox messages waiting for delivery.",
		}),
		OutboxFailed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "warden_outbox_dead", Help: "Outbox messages that exhausted their retries.",
		}),
		OutboxSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_outbox_delivered_total", Help: "Outbox deliveries by kind and result.",
		}, []string{"kind", "result"}),
	}
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.HTTPRequests, m.HTTPDuration, m.HTTPInFlight, m.HTTPShed, m.GRPCRequests, m.AuthEvents,
		m.RateLimited, m.HashWait, m.HashDuration, m.HashRejected, m.OutboxPending, m.OutboxFailed, m.OutboxSent,
	)
	return m
}

// ObserveHash implements password.Observer.
func (m *Metrics) ObserveHash(wait, compute time.Duration) {
	m.HashWait.Observe(wait.Seconds())
	m.HashDuration.Observe(compute.Seconds())
}

// ObserveRejected implements password.Observer.
func (m *Metrics) ObserveRejected() { m.HashRejected.Inc() }

// Auth records an authentication event.
func (m *Metrics) Auth(event, result string) { m.AuthEvents.WithLabelValues(event, result).Inc() }

// InitSentry enables Sentry when dsn is set. The returned function flushes
// buffered events and must be called on shutdown.
func InitSentry(dsn, env string, tracesSampleRate float64) (bool, func(), error) {
	if dsn == "" {
		return false, func() {}, nil
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Environment:      env,
		Release:          "warden@" + Version,
		EnableTracing:    tracesSampleRate > 0,
		TracesSampleRate: tracesSampleRate,
		AttachStacktrace: true,
		BeforeSend: func(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
			scrub(event)
			return event
		},
	})
	if err != nil {
		return false, func() {}, err
	}
	return true, func() { sentry.Flush(3 * time.Second) }, nil
}

// scrub removes credentials from events before they leave the process.
func scrub(e *sentry.Event) {
	if e.Request == nil {
		return
	}
	e.Request.Cookies = ""
	e.Request.Data = ""
	for k := range e.Request.Headers {
		switch strings.ToLower(k) {
		case "authorization", "cookie", "x-api-key", "set-cookie":
			e.Request.Headers[k] = "[redacted]"
		}
	}
	e.Request.QueryString = ""
}

// CaptureError reports an unexpected error to Sentry (no-op when disabled).
func CaptureError(ctx context.Context, err error, tags map[string]string) {
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}
	if hub.Client() == nil {
		return
	}
	hub.WithScope(func(scope *sentry.Scope) {
		for k, v := range tags {
			scope.SetTag(k, v)
		}
		hub.CaptureException(err)
	})
}

// CapturePanic reports a recovered panic.
func CapturePanic(ctx context.Context, recovered any, tags map[string]string) {
	hub := sentry.CurrentHub()
	if hub.Client() == nil {
		return
	}
	hub.WithScope(func(scope *sentry.Scope) {
		for k, v := range tags {
			scope.SetTag(k, v)
		}
		hub.RecoverWithContext(ctx, recovered)
	})
}
