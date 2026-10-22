package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/observability"
	"github.com/fatihacan1/warden/internal/ratelimit"
)

type ctxKey int

const (
	localClaims ctxKey = iota
	localUserID
	localSessionID
)

// observe logs every request and records Prometheus metrics. It must run
// after requestid and before everything else.
func (s *Server) observe() fiber.Handler {
	return func(c fiber.Ctx) error {
		start := time.Now()
		s.metrics.HTTPInFlight.Inc()
		err := c.Next()
		s.metrics.HTTPInFlight.Dec()
		if err != nil {
			// Render the error now so the logged/metric status is the real one.
			if herr := s.errorHandler(c, err); herr != nil {
				s.log.Error("error handler failed", "err", herr)
			}
		}
		status := c.Response().StatusCode()
		route := c.Route().Path
		if status == fiber.StatusNotFound && route == "/" {
			route = "unmatched"
		}
		elapsed := time.Since(start)
		s.metrics.HTTPRequests.WithLabelValues(c.Method(), route, strconv.Itoa(status)).Inc()
		s.metrics.HTTPDuration.WithLabelValues(c.Method(), route).Observe(elapsed.Seconds())

		level := slog.LevelInfo
		switch {
		case status >= 500:
			level = slog.LevelError
		case status >= 400:
			level = slog.LevelWarn
		}
		if route == "/healthz" || route == "/readyz" {
			level = slog.LevelDebug
		}
		s.log.Log(c.Context(), level, "http request",
			"method", c.Method(), "route", route, "status", status,
			"duration_ms", elapsed.Milliseconds(), "ip", c.IP(),
			"request_id", requestid.FromContext(c), "bytes", len(c.Response().Body()))
		return nil
	}
}

// recoverer converts panics into 500s and reports them to Sentry.
func (s *Server) recoverer() fiber.Handler {
	return func(c fiber.Ctx) (err error) {
		defer func() {
			if r := recover(); r != nil {
				observability.CapturePanic(c.Context(), r, map[string]string{"route": c.Route().Path, "request_id": requestid.FromContext(c)})
				s.log.Error("panic recovered", "panic", fmt.Sprint(r), "route", c.Route().Path)
				err = domain.ErrInternal
			}
		}()
		return c.Next()
	}
}

// shedLoad rejects work above MaxInFlight with 503 instead of letting latency
// and memory grow without bound. Probes are exempt.
func (s *Server) shedLoad() fiber.Handler {
	var inFlight atomic.Int64
	limit := int64(s.cfg.HTTP.MaxInFlight)
	return func(c fiber.Ctx) error {
		p := c.Path()
		if p == "/healthz" || p == "/readyz" {
			return c.Next()
		}
		if inFlight.Add(1) > limit {
			inFlight.Add(-1)
			s.metrics.HTTPShed.Inc()
			return domain.ErrServerBusy.WithRetryAfter(time.Second)
		}
		defer inFlight.Add(-1)
		return c.Next()
	}
}

// deadline bounds the total time a handler may spend on downstream calls.
func (s *Server) deadline() fiber.Handler {
	return func(c fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.HTTP.RequestTimeout)
		defer cancel()
		c.SetContext(ctx)
		err := c.Next()
		if err == nil && errors.Is(ctx.Err(), context.DeadlineExceeded) && c.Response().StatusCode() >= 500 {
			return domain.ErrServiceUnavailable
		}
		return err
	}
}

// securityHeaders applies strict headers suitable for a JSON API.
func securityHeaders(hsts bool) fiber.Handler {
	return func(c fiber.Ctx) error {
		h := &c.Response().Header
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-site")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		return c.Next()
	}
}

// noStore forbids caching of responses that may contain tokens.
func noStore(c fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	c.Set("Pragma", "no-cache")
	return c.Next()
}

// rateLimit applies a per-IP policy.
func (s *Server) rateLimit(p ratelimit.Policy) fiber.Handler {
	return func(c fiber.Ctx) error {
		d := s.limiter.Allow(c.Context(), p, c.IP())
		if !d.Allowed {
			return domain.ErrRateLimited.WithRetryAfter(d.RetryAfter)
		}
		return c.Next()
	}
}

// jsonBody requires a JSON content type on bodies and a small size. Requiring
// application/json also blocks classic cross-site form CSRF: browsers cannot
// send it cross-origin without a CORS preflight.
func jsonBody(maxBytes int) fiber.Handler {
	return func(c fiber.Ctx) error {
		if c.Method() == fiber.MethodGet || c.Method() == fiber.MethodHead || c.Method() == fiber.MethodOptions {
			return c.Next()
		}
		if len(c.Body()) > maxBytes {
			return domain.ErrPayloadTooLarge
		}
		if len(c.Body()) > 0 {
			ct := strings.ToLower(c.Get(fiber.HeaderContentType))
			if !strings.HasPrefix(ct, fiber.MIMEApplicationJSON) {
				return domain.ErrUnsupportedMedia.WithMessage("Content-Type must be application/json.")
			}
		}
		return c.Next()
	}
}

// requireAuth validates the bearer access token and rejects revoked sessions.
func (s *Server) requireAuth() fiber.Handler {
	return func(c fiber.Ctx) error {
		raw, ok := bearer(c.Get(fiber.HeaderAuthorization))
		if !ok {
			c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="warden"`)
			return domain.ErrUnauthorized
		}
		claims, err := s.tokens.Verify(raw)
		if err != nil {
			c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="warden", error="invalid_token"`)
			return domain.ErrInvalidToken
		}
		uid, err1 := claims.UserID()
		sid, err2 := claims.SID()
		if err1 != nil || err2 != nil {
			return domain.ErrInvalidToken
		}
		if s.auth.SessionRevoked(c.Context(), sid) {
			c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="warden", error="invalid_token"`)
			return domain.ErrInvalidToken
		}
		c.Locals(localClaims, claims)
		c.Locals(localUserID, uid)
		c.Locals(localSessionID, sid)
		return c.Next()
	}
}

func bearer(h string) (string, bool) {
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	t := strings.TrimSpace(h[len(prefix):])
	return t, t != "" && len(t) < 8192
}

func userID(c fiber.Ctx) uuid.UUID {
	id, _ := c.Locals(localUserID).(uuid.UUID)
	return id
}

func sessionID(c fiber.Ctx) uuid.UUID {
	id, _ := c.Locals(localSessionID).(uuid.UUID)
	return id
}

func meta(c fiber.Ctx) domain.RequestMeta {
	return domain.RequestMeta{IP: c.IP(), UserAgent: c.Get(fiber.HeaderUserAgent), RequestID: requestid.FromContext(c)}
}
