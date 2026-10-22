// Package domain holds Warden's core types and the error vocabulary shared by
// every transport (HTTP, gRPC, admin UI).
package domain

import (
	"errors"
	"net/http"
	"time"
)

// Error is a client-safe error with a stable machine readable code. Messages
// must never contain secrets or reveal whether an account exists.
type Error struct {
	Code       string
	Message    string
	Status     int
	Fields     map[string]string
	RetryAfter time.Duration
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Is makes errors.Is match on the code, so wrapped or decorated copies of a
// sentinel (e.g. with RetryAfter set) still compare equal.
func (e *Error) Is(target error) bool {
	var t *Error
	if errors.As(target, &t) {
		return t.Code == e.Code
	}
	return false
}

// WithFields returns a copy carrying per-field validation messages.
func (e *Error) WithFields(fields map[string]string) *Error {
	cp := *e
	cp.Fields = fields
	return &cp
}

// WithRetryAfter returns a copy carrying a Retry-After hint.
func (e *Error) WithRetryAfter(d time.Duration) *Error {
	cp := *e
	cp.RetryAfter = d
	return &cp
}

// WithMessage returns a copy with a different human readable message.
func (e *Error) WithMessage(msg string) *Error {
	cp := *e
	cp.Message = msg
	return &cp
}

func newErr(code string, status int, msg string) *Error {
	return &Error{Code: code, Status: status, Message: msg}
}

var (
	ErrValidation         = newErr("validation_failed", http.StatusUnprocessableEntity, "The request is invalid.")
	ErrInvalidCredentials = newErr("invalid_credentials", http.StatusUnauthorized, "Invalid email or password.")
	ErrUnauthorized       = newErr("unauthorized", http.StatusUnauthorized, "Authentication is required.")
	ErrInvalidToken       = newErr("invalid_token", http.StatusUnauthorized, "The token is invalid or has expired.")
	ErrInvalidMFACode     = newErr("invalid_mfa_code", http.StatusUnauthorized, "The verification code is invalid.")
	ErrForbidden          = newErr("forbidden", http.StatusForbidden, "You are not allowed to perform this action.")
	ErrAccountDisabled    = newErr("account_disabled", http.StatusForbidden, "This account has been disabled.")
	ErrEmailNotVerified   = newErr("email_not_verified", http.StatusForbidden, "Please verify your email address first.")
	ErrReauthRequired     = newErr("reauthentication_required", http.StatusForbidden, "Please sign in again to continue.")
	ErrSignupDisabled     = newErr("signup_disabled", http.StatusForbidden, "Sign-ups are currently disabled.")
	ErrNotFound           = newErr("not_found", http.StatusNotFound, "The resource was not found.")
	ErrProviderDisabled   = newErr("provider_not_enabled", http.StatusNotFound, "This sign-in method is not enabled.")
	ErrEmailTaken         = newErr("email_taken", http.StatusConflict, "That email address is already in use.")
	ErrConflict           = newErr("conflict", http.StatusConflict, "The request conflicts with the current state.")
	ErrLastCredential     = newErr("last_credential", http.StatusConflict, "You cannot remove your only sign-in method.")
	ErrMFAAlreadyEnabled  = newErr("mfa_already_enabled", http.StatusConflict, "Two-factor authentication is already enabled.")
	ErrMFANotEnabled      = newErr("mfa_not_enabled", http.StatusConflict, "Two-factor authentication is not enabled.")
	ErrWeakPassword       = newErr("weak_password", http.StatusUnprocessableEntity, "The password does not meet the requirements.")
	ErrBreachedPassword   = newErr("breached_password", http.StatusUnprocessableEntity, "This password has appeared in a data breach. Please choose another one.")
	ErrInvalidRedirect    = newErr("invalid_redirect_uri", http.StatusBadRequest, "The redirect_uri is not allowed.")
	ErrOAuthFailed        = newErr("oauth_failed", http.StatusBadGateway, "The identity provider could not complete the sign-in.")
	ErrPayloadTooLarge    = newErr("payload_too_large", http.StatusRequestEntityTooLarge, "The request body is too large.")
	ErrUnsupportedMedia   = newErr("unsupported_media_type", http.StatusUnsupportedMediaType, "The file type is not supported.")
	ErrRateLimited        = newErr("rate_limited", http.StatusTooManyRequests, "Too many requests. Please try again later.")
	ErrFeatureDisabled    = newErr("feature_disabled", http.StatusNotImplemented, "This feature is not enabled on this server.")
	ErrServerBusy         = newErr("server_busy", http.StatusServiceUnavailable, "The server is busy. Please retry shortly.")
	ErrServiceUnavailable = newErr("service_unavailable", http.StatusServiceUnavailable, "A dependency is unavailable. Please retry shortly.")
	ErrInternal           = newErr("internal_error", http.StatusInternalServerError, "An unexpected error occurred.")
)

// AsError extracts a *Error from err, or nil when err is not client-safe.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}
