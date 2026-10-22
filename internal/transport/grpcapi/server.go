// Package grpcapi is the internal service-to-service gRPC API.
package grpcapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fatihacan1/warden/internal/auth"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/observability"
	"github.com/fatihacan1/warden/internal/token"
	wardenv1 "github.com/fatihacan1/warden/pkg/api/wardenv1"
)

// Server implements wardenv1.AuthServiceServer.
type Server struct {
	wardenv1.UnimplementedAuthServiceServer
	auth    *auth.Service
	tokens  *token.Issuer
	log     *slog.Logger
	metrics *observability.Metrics
	keys    [][32]byte // SHA-256 of accepted API keys
	grpc    *grpc.Server
	health  *health.Server
}

func New(a *auth.Service, tokens *token.Issuer, apiKeys []string, reflect bool, log *slog.Logger, m *observability.Metrics) *Server {
	s := &Server{auth: a, tokens: tokens, log: log, metrics: m}
	for _, k := range apiKeys {
		s.keys = append(s.keys, sha256.Sum256([]byte(k)))
	}
	s.grpc = grpc.NewServer(
		grpc.ChainUnaryInterceptor(s.recoverer, s.observe, s.authenticate),
		grpc.MaxRecvMsgSize(1<<20),
		grpc.MaxConcurrentStreams(1000),
		grpc.ConnectionTimeout(5*time.Second),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 5 * time.Minute, Time: time.Minute, Timeout: 20 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 15 * time.Second, PermitWithoutStream: true}),
	)
	wardenv1.RegisterAuthServiceServer(s.grpc, s)
	s.health = health.NewServer()
	healthpb.RegisterHealthServer(s.grpc, s.health)
	s.health.SetServingStatus("warden.v1.AuthService", healthpb.HealthCheckResponse_SERVING)
	if reflect {
		reflection.Register(s.grpc)
	}
	return s
}

func (s *Server) Serve(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.grpc.Serve(ln)
}

// ServeListener serves on an existing listener (tests, socket activation).
func (s *Server) ServeListener(ln net.Listener) error { return s.grpc.Serve(ln) }

// Shutdown drains in-flight RPCs, forcing a stop when ctx expires.
func (s *Server) Shutdown(ctx context.Context) {
	s.health.Shutdown()
	done := make(chan struct{})
	go func() { s.grpc.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		s.grpc.Stop()
	}
}

// ---------------------------------------------------------------------------
// Interceptors

func (s *Server) authenticate(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	if strings.HasPrefix(info.FullMethod, "/grpc.health.v1.Health/") {
		return next(ctx, req)
	}
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get("x-api-key")
	if len(vals) != 1 || !s.validKey(vals[0]) {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid api key")
	}
	return next(ctx, req)
}

// validKey compares hashes in constant time against every configured key.
func (s *Server) validKey(k string) bool {
	h := sha256.Sum256([]byte(k))
	ok := 0
	for i := range s.keys {
		ok |= subtle.ConstantTimeCompare(h[:], s.keys[i][:])
	}
	return ok == 1
}

func (s *Server) observe(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := next(ctx, req)
	code := status.Code(err)
	s.metrics.GRPCRequests.WithLabelValues(info.FullMethod, code.String()).Inc()
	level := slog.LevelInfo
	if code != codes.OK {
		level = slog.LevelWarn
	}
	if code == codes.Internal || code == codes.Unknown {
		level = slog.LevelError
	}
	s.log.Log(ctx, level, "grpc request", "method", info.FullMethod, "code", code.String(), "duration_ms", time.Since(start).Milliseconds())
	return resp, err
}

func (s *Server) recoverer(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			observability.CapturePanic(ctx, r, map[string]string{"grpc_method": info.FullMethod})
			s.log.Error("grpc panic recovered", "panic", fmt.Sprint(r), "method", info.FullMethod)
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	return next(ctx, req)
}

// toStatus maps domain errors to gRPC codes.
func toStatus(err error) error {
	if err == nil {
		return nil
	}
	de := domain.AsError(err)
	if de == nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return status.Error(codes.DeadlineExceeded, "deadline exceeded")
		}
		return status.Error(codes.Internal, "internal error")
	}
	code := codes.Unknown
	switch {
	case de.Status == 400 || de.Status == 422:
		code = codes.InvalidArgument
	case de.Status == 401:
		code = codes.Unauthenticated
	case de.Status == 403:
		code = codes.PermissionDenied
	case de.Status == 404:
		code = codes.NotFound
	case de.Status == 409:
		code = codes.AlreadyExists
	case de.Status == 429:
		code = codes.ResourceExhausted
	case de.Status == 503:
		code = codes.Unavailable
	case de.Status >= 500:
		code = codes.Internal
	}
	return status.Error(code, de.Message)
}

func parseID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// RPCs

func (s *Server) VerifyAccessToken(ctx context.Context, req *wardenv1.VerifyAccessTokenRequest) (*wardenv1.VerifyAccessTokenResponse, error) {
	claims, err := s.tokens.Verify(req.GetAccessToken())
	if err != nil {
		return &wardenv1.VerifyAccessTokenResponse{Valid: false, Reason: "invalid_token"}, nil
	}
	sid, err := claims.SID()
	if err != nil {
		return &wardenv1.VerifyAccessTokenResponse{Valid: false, Reason: "invalid_token"}, nil
	}
	if req.GetCheckSession() {
		active, err := s.auth.SessionActive(ctx, sid)
		if err != nil {
			return nil, status.Error(codes.Unavailable, "session check unavailable")
		}
		if !active {
			return &wardenv1.VerifyAccessTokenResponse{Valid: false, Reason: "session_revoked"}, nil
		}
	} else if s.auth.SessionRevoked(ctx, sid) {
		return &wardenv1.VerifyAccessTokenResponse{Valid: false, Reason: "session_revoked"}, nil
	}
	resp := &wardenv1.VerifyAccessTokenResponse{
		Valid: true, UserId: claims.Subject, SessionId: claims.SessionID, Email: claims.Email,
		EmailVerified: claims.EmailVerified, Roles: claims.Roles, Amr: claims.AMR,
	}
	if claims.ExpiresAt != nil {
		resp.ExpiresAt = timestamppb.New(claims.ExpiresAt.Time)
	}
	return resp, nil
}

func (s *Server) GetUser(ctx context.Context, req *wardenv1.GetUserRequest) (*wardenv1.GetUserResponse, error) {
	id, err := parseID(req.GetUserId())
	if err != nil {
		return nil, err
	}
	u, err := s.auth.GetUser(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	return &wardenv1.GetUserResponse{User: s.userProto(ctx, u)}, nil
}

func (s *Server) GetUsers(ctx context.Context, req *wardenv1.GetUsersRequest) (*wardenv1.GetUsersResponse, error) {
	if len(req.GetUserIds()) > 100 {
		return nil, status.Error(codes.InvalidArgument, "at most 100 user_ids per call")
	}
	ids := make([]uuid.UUID, 0, len(req.GetUserIds()))
	for _, raw := range req.GetUserIds() {
		id, err := parseID(raw)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	users, err := s.auth.Store.GetUsersByIDs(ctx, ids)
	if err != nil {
		return nil, toStatus(err)
	}
	out := &wardenv1.GetUsersResponse{}
	for _, u := range users {
		out.Users = append(out.Users, s.userProto(ctx, u))
	}
	return out, nil
}

func (s *Server) SetUserRoles(ctx context.Context, req *wardenv1.SetUserRolesRequest) (*wardenv1.SetUserRolesResponse, error) {
	id, err := parseID(req.GetUserId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.SetRoles(ctx, id, req.GetRoles(), "grpc"); err != nil {
		return nil, toStatus(err)
	}
	return &wardenv1.SetUserRolesResponse{}, nil
}

func (s *Server) SetUserDisabled(ctx context.Context, req *wardenv1.SetUserDisabledRequest) (*wardenv1.SetUserDisabledResponse, error) {
	id, err := parseID(req.GetUserId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.SetDisabled(ctx, id, req.GetDisabled(), "grpc"); err != nil {
		return nil, toStatus(err)
	}
	return &wardenv1.SetUserDisabledResponse{}, nil
}

func (s *Server) RevokeUserSessions(ctx context.Context, req *wardenv1.RevokeUserSessionsRequest) (*wardenv1.RevokeUserSessionsResponse, error) {
	id, err := parseID(req.GetUserId())
	if err != nil {
		return nil, err
	}
	n, err := s.auth.RevokeAllSessions(ctx, id, uuid.Nil, domain.RevokeAdmin, domain.RequestMeta{})
	if err != nil {
		return nil, toStatus(err)
	}
	return &wardenv1.RevokeUserSessionsResponse{Revoked: int32(min(n, math.MaxInt32))}, nil // #nosec G115 -- clamped
}

func (s *Server) userProto(ctx context.Context, u *domain.User) *wardenv1.User {
	p := &wardenv1.User{
		Id: u.ID.String(), Email: u.Email, EmailVerified: u.EmailVerified(), Name: u.Name,
		AvatarUrl: s.auth.AvatarURL(ctx, u), Roles: u.Roles, MfaEnabled: u.MFAEnabled(),
		Disabled: u.Disabled(), CreatedAt: timestamppb.New(u.CreatedAt),
	}
	if u.LastSignInAt != nil {
		p.LastSignInAt = timestamppb.New(*u.LastSignInAt)
	}
	return p
}
