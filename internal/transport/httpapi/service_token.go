package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/oauthclients"
	"github.com/fatihacan1/warden/internal/ratelimit"
	"github.com/fatihacan1/warden/internal/store"
	"github.com/fatihacan1/warden/internal/token"
)

// The OAuth 2.0 client credentials grant (RFC 6749 section 4.4) on
// POST /v1/oauth/token. Services authenticate with HTTP Basic
// (client_secret_basic) or body parameters (client_secret_post) and get a
// short-lived JWT that anyone can verify offline with the JWKS.

const (
	grantClientCredentials        = "client_credentials"
	localTokenParams       ctxKey = 101
)

// tokenParams returns the parameters of a token request, from a form body
// (the RFC format) or a JSON object. The result is cached per request.
func tokenParams(c fiber.Ctx) (url.Values, error) {
	if v, ok := c.Locals(localTokenParams).(url.Values); ok {
		return v, nil
	}
	out := url.Values{}
	body := c.Body()
	ct := strings.ToLower(c.Get(fiber.HeaderContentType))
	switch {
	case len(body) == 0:
	case strings.HasPrefix(ct, fiber.MIMEApplicationForm):
		v, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		out = v
	case strings.HasPrefix(ct, fiber.MIMEApplicationJSON):
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, err
		}
		for k, v := range m {
			switch t := v.(type) {
			case string:
				out.Add(k, t)
			case []any:
				for _, e := range t {
					if s, ok := e.(string); ok {
						out.Add(k, s)
					}
				}
			}
		}
	default:
		return nil, errors.New("unsupported content type")
	}
	c.Locals(localTokenParams, out)
	return out, nil
}

// isClientCredentials reports whether the request is a client credentials
// grant, so publishable-key checks (which are for end-user apps) skip it.
func isClientCredentials(c fiber.Ctx) bool {
	p, err := tokenParams(c)
	return err == nil && p.Get("grant_type") == grantClientCredentials
}

// tokenBody limits the size of a token request. The content type is checked
// per grant in tokenEndpoint: only the client credentials grant may use form
// encoding, so a cross-site form cannot reach the login code exchange.
func tokenBody(maxBytes int) fiber.Handler {
	return func(c fiber.Ctx) error {
		if len(c.Body()) > maxBytes {
			return domain.ErrPayloadTooLarge
		}
		return c.Next()
	}
}

// tokenEndpoint serves POST /v1/oauth/token: the client credentials grant
// when grant_type=client_credentials, otherwise the login code exchange.
func (s *Server) tokenEndpoint(strict ratelimit.Policy) fiber.Handler {
	return func(c fiber.Ctx) error {
		if isClientCredentials(c) {
			return s.clientCredentials(c)
		}
		if p, err := tokenParams(c); err == nil && p.Get("grant_type") != "" {
			return oauthError(c, fiber.StatusBadRequest, "unsupported_grant_type", "Only grant_type=client_credentials is supported here.")
		}
		if len(c.Body()) > 0 && !strings.HasPrefix(strings.ToLower(c.Get(fiber.HeaderContentType)), fiber.MIMEApplicationJSON) {
			return domain.ErrUnsupportedMedia.WithMessage("Content-Type must be application/json.")
		}
		if d := s.limiter.Allow(c.Context(), strict, c.IP()); !d.Allowed {
			return domain.ErrRateLimited.WithRetryAfter(d.RetryAfter)
		}
		return s.oauthToken(c)
	}
}

// oauthError renders an RFC 6749 section 5.2 error.
func oauthError(c fiber.Ctx, status int, code, desc string) error {
	c.Set("Cache-Control", "no-store")
	c.Set("Pragma", "no-cache")
	return c.Status(status).JSON(fiber.Map{"error": code, "error_description": desc})
}

func invalidClient(c fiber.Ctx, basic bool) error {
	if basic {
		c.Set(fiber.HeaderWWWAuthenticate, `Basic realm="warden", charset="UTF-8"`)
	}
	return oauthError(c, fiber.StatusUnauthorized, "invalid_client", "Client authentication failed.")
}

// basicCredentials parses client_secret_basic (RFC 6749 section 2.3.1).
func basicCredentials(h string) (id, secret string, present, ok bool) {
	const prefix = "basic "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false, false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return "", "", true, false
	}
	i, s, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", true, false
	}
	// Both parts are form-urlencoded before encoding; many clients skip that.
	if v, err := url.QueryUnescape(i); err == nil {
		i = v
	}
	if v, err := url.QueryUnescape(s); err == nil {
		s = v
	}
	return i, s, true, true
}

func (s *Server) clientCredentials(c fiber.Ctx) error {
	ctx := c.Context()
	params, err := tokenParams(c)
	if err != nil {
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "Malformed request body.")
	}
	if d := s.limiter.Allow(ctx, ratelimit.Per("ip_client_token", s.cfg.RateLimit.ClientTokenIPPerMinute, time.Minute), c.IP()); !d.Allowed {
		return domain.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}

	id, secret, viaHeader, headerOK := basicCredentials(c.Get(fiber.HeaderAuthorization))
	bodyID, bodySecret := params.Get("client_id"), params.Get("client_secret")
	switch {
	case viaHeader && !headerOK:
		return invalidClient(c, true)
	case viaHeader && (bodySecret != "" || (bodyID != "" && bodyID != id)):
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "Use one client authentication method per request.")
	case !viaHeader:
		id, secret = bodyID, bodySecret
	}
	if id == "" || secret == "" {
		return invalidClient(c, viaHeader)
	}

	client, err := s.clients.Authenticate(ctx, id, secret)
	if errors.Is(err, oauthclients.ErrInvalidClient) {
		s.auditClient(ctx, c, "oauth.client_auth_failed", map[string]any{"client_id": truncate(id, 64)})
		return invalidClient(c, viaHeader)
	}
	if err != nil {
		return err
	}
	// Per client limit, after authentication so that strangers cannot burn
	// another service's budget.
	if d := s.limiter.Allow(ctx, ratelimit.Per("client_token", s.cfg.RateLimit.ClientTokenPerMinute, time.Minute), client.ClientID); !d.Allowed {
		return domain.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}

	audiences := append(append([]string{}, params["audience"]...), params["resource"]...) // RFC 8707 "resource"
	scopes, aud, err := client.Resolve(params.Get("scope"), audiences)
	switch {
	case errors.Is(err, oauthclients.ErrInvalidScope):
		s.auditClient(ctx, c, "oauth.client_token_denied", map[string]any{"client_id": client.ClientID, "reason": "invalid_scope"})
		return oauthError(c, fiber.StatusBadRequest, "invalid_scope", "The requested scope is not allowed for this client.")
	case errors.Is(err, oauthclients.ErrInvalidTarget):
		s.auditClient(ctx, c, "oauth.client_token_denied", map[string]any{"client_id": client.ClientID, "reason": "invalid_target"})
		return oauthError(c, fiber.StatusBadRequest, "invalid_target", "The requested audience is not allowed for this client.")
	case err != nil:
		return err
	}

	raw, exp, err := s.tokens.IssueClient(token.ClientSubject{ClientID: client.ClientID, Scopes: scopes, Audience: aud, TTL: client.TTL})
	if err != nil {
		return err
	}
	s.auditClient(ctx, c, "oauth.client_token_issued", map[string]any{
		"client_id": client.ClientID, "scope": strings.Join(scopes, " "), "audience": aud,
	})
	return c.JSON(fiber.Map{
		"access_token": raw,
		"token_type":   "Bearer",
		"expires_in":   int(math.Ceil(time.Until(exp).Seconds())),
		"scope":        strings.Join(scopes, " "),
	})
}

func (s *Server) auditClient(ctx context.Context, c fiber.Ctx, typ string, data map[string]any) {
	m := meta(c)
	if err := s.auth.Store.InsertAudit(context.WithoutCancel(ctx), store.AuditEvent{Type: typ, IP: m.IP, UserAgent: m.UserAgent, Metadata: data}); err != nil {
		s.log.Warn("audit write failed", "type", typ, "err", err)
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// serviceTokenView is the introspection answer for a machine token, or
// ok=false when its client is revoked or gone.
func (s *Server) serviceTokenView(ctx context.Context, claims *token.Claims) (view fiber.Map, ok bool, err error) {
	cl, err := s.clients.Active(ctx, claims.ClientID)
	if err != nil {
		if errors.Is(err, oauthclients.ErrInvalidClient) || errors.Is(err, domain.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return fiber.Map{
		"active": true, "token_type": "service", "sub": claims.Subject, "client_id": claims.ClientID, "client_name": cl.Name,
		"scope": claims.Scope, "aud": []string(claims.Audience), "expires_at": claims.ExpiresAt.Time,
	}, true, nil
}
