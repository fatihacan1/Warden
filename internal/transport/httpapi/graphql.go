package httpapi

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	graphql "github.com/graph-gophers/graphql-go"

	"github.com/fatihacan1/warden/internal/apikeys"
	"github.com/fatihacan1/warden/internal/domain"
)

// GraphQL exposes the account API (the same operations as /v1/me) plus a few
// server-only fields for secret keys. Sign-in, refresh and sign-out stay on
// REST, where cookies and token rotation are handled.
//
// Hardening: POST with application/json only (no GET, so no CSRF through
// simple requests and no caching), one operation per request, bounded query
// length, depth, parallelism and fragment overlap checks, introspection off in
// production, and resolver errors reduced to Warden's error codes.

// GraphQLSchema is the schema served at POST /graphql.
const GraphQLSchema = `
schema {
  query: Query
  mutation: Mutation
}

type Query {
  "The signed-in user. Requires an access token."
  me: User!
  "Active sessions (devices) of the signed-in user."
  sessions: [Session!]!
  "Social accounts linked to the signed-in user."
  identities: [Identity!]!
  "Sign-in methods enabled on this instance. No authentication needed."
  providers: Providers!
  "Any user by id. Requires a secret key (server only)."
  user(id: ID!): User
}

type Mutation {
  "Change the signed-in user's display name and/or email language (en, tr; empty = default)."
  updateProfile(name: String, locale: String): User!
  "Sign out one device of the signed-in user."
  revokeSession(id: ID!): Boolean!
  "Sign out every other device; returns how many were signed out."
  revokeOtherSessions: Int!
  "Unlink a social account from the signed-in user."
  unlinkIdentity(provider: String!): Boolean!
  "Replace a user's roles. Requires a secret key (server only)."
  setUserRoles(id: ID!, roles: [String!]!): User!
}

type User {
  id: ID!
  email: String
  emailVerified: Boolean!
  name: String!
  avatarUrl: String
  roles: [String!]!
  "Email language; empty = instance default"
  locale: String!
  mfaEnabled: Boolean!
  hasPassword: Boolean!
  "RFC 3339"
  createdAt: String!
  lastSignInAt: String
}

type Session {
  id: ID!
  current: Boolean!
  userAgent: String!
  ip: String!
  amr: [String!]!
  createdAt: String!
  lastUsedAt: String!
  expiresAt: String!
}

type Identity {
  provider: String!
  email: String
  createdAt: String!
  lastUsedAt: String
}

type Providers {
  password: Boolean!
  signupEnabled: Boolean!
  emailVerificationRequired: Boolean!
  passwordMinLength: Int!
  social: [Provider!]!
}

type Provider {
  name: String!
  displayName: String!
  native: Boolean!
}
`

func (s *Server) buildGraphQL() error {
	opts := []graphql.SchemaOpt{
		graphql.UseFieldResolvers(),
		graphql.MaxDepth(s.cfg.GraphQL.MaxDepth),
		graphql.MaxQueryLength(s.cfg.GraphQL.MaxQueryLength),
		graphql.MaxParallelism(8),
		graphql.OverlapValidationLimit(500),
		graphql.Logger(gqlLogger{s}),
	}
	if !s.cfg.GraphQLIntrospection() {
		opts = append(opts, graphql.RestrictIntrospection(func(context.Context) bool { return false }))
	}
	schema, err := graphql.ParseSchema(GraphQLSchema, &gqlRoot{s: s}, opts...)
	if err != nil {
		return err
	}
	s.gql = schema
	return nil
}

type gqlLogger struct{ s *Server }

func (l gqlLogger) LogPanic(_ context.Context, value any) {
	l.s.log.Error("graphql resolver panicked", "panic", value)
}

type principalKey struct{}

type principal struct {
	userID    uuid.UUID
	sessionID uuid.UUID
	secret    *apikeys.Key
}

// graphqlHandler serves POST /graphql.
func (s *Server) graphqlHandler(c fiber.Ctx) error {
	var req struct {
		Query         string         `json:"query"`
		OperationName string         `json:"operationName"`
		Variables     map[string]any `json:"variables"`
	}
	body := c.Body()
	if len(body) > 0 && body[0] == '[' {
		return domain.ErrValidation.WithMessage("Batched GraphQL requests are not supported; send one operation per request.")
	}
	if err := decode(c, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Query) == "" {
		return domain.ErrValidation.WithMessage("Send {\"query\": \"...\"} as JSON.")
	}
	var p principal
	if h := c.Get(fiber.HeaderAuthorization); h != "" {
		raw, ok := bearer(h)
		if !ok {
			return domain.ErrUnauthorized
		}
		if strings.HasPrefix(raw, "sk_") {
			if c.Get(fiber.HeaderOrigin) != "" {
				return domain.ErrSecretKeyInBrowser
			}
			if p.secret = s.apiKeys.Lookup(raw, apikeys.Secret); p.secret == nil {
				return domain.ErrSecretKey
			}
		} else {
			claims, err := s.tokens.Verify(raw)
			if err != nil {
				return domain.ErrInvalidToken
			}
			uid, err1 := claims.UserID()
			sid, err2 := claims.SID()
			if err1 != nil || err2 != nil || s.auth.SessionRevoked(c.Context(), sid) {
				return domain.ErrInvalidToken
			}
			p.userID, p.sessionID = uid, sid
		}
	}
	ctx := context.WithValue(c.Context(), principalKey{}, p)
	ctx = context.WithValue(ctx, metaKey{}, meta(c))
	resp := s.gql.Exec(ctx, req.Query, req.OperationName, req.Variables)
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSONCharsetUTF8)
	out, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return c.Send(out)
}

type metaKey struct{}

// gqlError carries a Warden error code into the GraphQL "extensions".
type gqlError struct{ de *domain.Error }

func (e gqlError) Error() string { return e.de.Message }
func (e gqlError) Extensions() map[string]any {
	ext := map[string]any{"code": e.de.Code}
	if len(e.de.Fields) > 0 {
		ext["fields"] = e.de.Fields
	}
	return ext
}

type gqlRoot struct{ s *Server }

func (r *gqlRoot) fail(ctx context.Context, err error) error {
	if de := domain.AsError(err); de != nil {
		return gqlError{de}
	}
	r.s.log.Error("graphql resolver failed", "err", err)
	return gqlError{domain.ErrInternal}
}

func (r *gqlRoot) user(ctx context.Context) (principal, error) {
	p, _ := ctx.Value(principalKey{}).(principal)
	if p.userID == uuid.Nil {
		return p, gqlError{domain.ErrUnauthorized}
	}
	return p, nil
}

func (r *gqlRoot) server(ctx context.Context) error {
	if p, _ := ctx.Value(principalKey{}).(principal); p.secret == nil {
		return gqlError{domain.ErrSecretKey}
	}
	return nil
}

func reqMeta(ctx context.Context) domain.RequestMeta {
	m, _ := ctx.Value(metaKey{}).(domain.RequestMeta)
	return m
}

type gqlUser struct {
	ID            graphql.ID
	Email         *string
	EmailVerified bool
	Name          string
	AvatarURL     *string
	Roles         []string
	Locale        string
	MFAEnabled    bool
	HasPassword   bool
	CreatedAt     string
	LastSignInAt  *string
}

func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func optionalTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	v := rfc3339(*t)
	return &v
}

func (r *gqlRoot) toUser(ctx context.Context, u *domain.User) *gqlUser {
	return &gqlUser{
		ID: graphql.ID(u.ID.String()), Email: optional(u.Email), EmailVerified: u.EmailVerified(), Name: u.Name,
		AvatarURL: optional(r.s.auth.AvatarURL(ctx, u)), Roles: u.Roles, Locale: u.Locale, MFAEnabled: u.MFAEnabled(),
		HasPassword: u.HasPassword(), CreatedAt: rfc3339(u.CreatedAt), LastSignInAt: optionalTime(u.LastSignInAt),
	}
}

func (r *gqlRoot) Me(ctx context.Context) (*gqlUser, error) {
	p, err := r.user(ctx)
	if err != nil {
		return nil, err
	}
	u, err := r.s.auth.GetUser(ctx, p.userID)
	if err != nil {
		return nil, r.fail(ctx, err)
	}
	if u.Disabled() {
		return nil, gqlError{domain.ErrAccountDisabled}
	}
	return r.toUser(ctx, u), nil
}

type gqlSession struct {
	ID         graphql.ID
	Current    bool
	UserAgent  string
	IP         string
	AMR        []string
	CreatedAt  string
	LastUsedAt string
	ExpiresAt  string
}

func (r *gqlRoot) Sessions(ctx context.Context) ([]*gqlSession, error) {
	p, err := r.user(ctx)
	if err != nil {
		return nil, err
	}
	list, err := r.s.auth.ListSessions(ctx, p.userID)
	if err != nil {
		return nil, r.fail(ctx, err)
	}
	out := make([]*gqlSession, 0, len(list))
	for _, x := range list {
		out = append(out, &gqlSession{ID: graphql.ID(x.ID.String()), Current: x.ID == p.sessionID, UserAgent: x.UserAgent,
			IP: x.IP, AMR: x.AMR, CreatedAt: rfc3339(x.CreatedAt), LastUsedAt: rfc3339(x.LastUsedAt), ExpiresAt: rfc3339(x.ExpiresAt)})
	}
	return out, nil
}

type gqlIdentity struct {
	Provider   string
	Email      *string
	CreatedAt  string
	LastUsedAt *string
}

func (r *gqlRoot) Identities(ctx context.Context) ([]*gqlIdentity, error) {
	p, err := r.user(ctx)
	if err != nil {
		return nil, err
	}
	list, err := r.s.auth.ListIdentities(ctx, p.userID)
	if err != nil {
		return nil, r.fail(ctx, err)
	}
	out := make([]*gqlIdentity, 0, len(list))
	for _, i := range list {
		out = append(out, &gqlIdentity{Provider: i.Provider, Email: optional(i.Email), CreatedAt: rfc3339(i.CreatedAt), LastUsedAt: optionalTime(i.LastUsedAt)})
	}
	return out, nil
}

type gqlProvider struct {
	Name        string
	DisplayName string
	Native      bool
}

type gqlProviders struct {
	Password                  bool
	SignupEnabled             bool
	EmailVerificationRequired bool
	PasswordMinLength         int32
	Social                    []*gqlProvider
}

func (r *gqlRoot) Providers() *gqlProviders {
	rt := r.s.settings.Get()
	out := &gqlProviders{Password: true, SignupEnabled: rt.AllowSignup, EmailVerificationRequired: rt.RequireEmailVerification,
		PasswordMinLength: int32(min(rt.PasswordMinLength, 64)), // #nosec G115 -- validated to 8..64
		Social:            []*gqlProvider{},
	}
	for _, d := range r.s.oauth.Enabled() {
		out.Social = append(out.Social, &gqlProvider{Name: d.Name, DisplayName: d.DisplayName, Native: d.SupportsNative})
	}
	return out
}

func (r *gqlRoot) User(ctx context.Context, args struct{ ID graphql.ID }) (*gqlUser, error) {
	if err := r.server(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(string(args.ID))
	if err != nil {
		return nil, nil
	}
	u, err := r.s.auth.GetUser(ctx, id)
	if de := domain.AsError(err); de != nil && de.Code == domain.ErrNotFound.Code {
		return nil, nil
	}
	if err != nil {
		return nil, r.fail(ctx, err)
	}
	return r.toUser(ctx, u), nil
}

func (r *gqlRoot) UpdateProfile(ctx context.Context, args struct {
	Name   *string
	Locale *string
}) (*gqlUser, error) {
	p, err := r.user(ctx)
	if err != nil {
		return nil, err
	}
	if args.Locale != nil {
		if _, err := r.s.auth.SetLocale(ctx, p.userID, *args.Locale); err != nil {
			return nil, r.fail(ctx, err)
		}
	}
	if args.Name != nil {
		if _, err := r.s.auth.UpdateProfile(ctx, p.userID, *args.Name); err != nil {
			return nil, r.fail(ctx, err)
		}
	}
	u, err := r.s.auth.GetUser(ctx, p.userID)
	if err != nil {
		return nil, r.fail(ctx, err)
	}
	return r.toUser(ctx, u), nil
}

func (r *gqlRoot) RevokeSession(ctx context.Context, args struct{ ID graphql.ID }) (bool, error) {
	p, err := r.user(ctx)
	if err != nil {
		return false, err
	}
	id, err := uuid.Parse(string(args.ID))
	if err != nil {
		return false, gqlError{domain.ErrNotFound}
	}
	if err := r.s.auth.RevokeSession(ctx, p.userID, id, domain.RevokeUser, reqMeta(ctx)); err != nil {
		return false, r.fail(ctx, err)
	}
	return true, nil
}

func (r *gqlRoot) RevokeOtherSessions(ctx context.Context) (int32, error) {
	p, err := r.user(ctx)
	if err != nil {
		return 0, err
	}
	n, err := r.s.auth.RevokeAllSessions(ctx, p.userID, p.sessionID, domain.RevokeUser, reqMeta(ctx))
	if err != nil {
		return 0, r.fail(ctx, err)
	}
	return int32(min(n, math.MaxInt32)), nil // #nosec G115 -- clamped
}

func (r *gqlRoot) UnlinkIdentity(ctx context.Context, args struct{ Provider string }) (bool, error) {
	p, err := r.user(ctx)
	if err != nil {
		return false, err
	}
	if err := r.s.auth.UnlinkIdentity(ctx, p.userID, args.Provider, reqMeta(ctx)); err != nil {
		return false, r.fail(ctx, err)
	}
	return true, nil
}

func (r *gqlRoot) SetUserRoles(ctx context.Context, args struct {
	ID    graphql.ID
	Roles []string
}) (*gqlUser, error) {
	if err := r.server(ctx); err != nil {
		return nil, err
	}
	p, _ := ctx.Value(principalKey{}).(principal)
	id, err := uuid.Parse(string(args.ID))
	if err != nil {
		return nil, gqlError{domain.ErrNotFound}
	}
	if err := r.s.auth.SetRoles(ctx, id, args.Roles, "api_key:"+p.secret.Name); err != nil {
		return nil, r.fail(ctx, err)
	}
	u, err := r.s.auth.GetUser(ctx, id)
	if err != nil {
		return nil, r.fail(ctx, err)
	}
	return r.toUser(ctx, u), nil
}
