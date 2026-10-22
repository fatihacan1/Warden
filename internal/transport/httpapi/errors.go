package httpapi

import (
	"errors"
	"math"
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/observability"
)

// ErrorBody is the JSON shape of every error response.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code      string            `json:"code"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
}

// errorHandler maps errors to responses. Unknown errors become a generic 500
// (details are logged and sent to Sentry, never to the client).
func (s *Server) errorHandler(c fiber.Ctx, err error) error {
	de := domain.AsError(err)
	if de == nil {
		var fe *fiber.Error
		if errors.As(err, &fe) {
			de = &domain.Error{Code: fiberCode(fe.Code), Message: fe.Message, Status: fe.Code}
		} else {
			de = domain.ErrInternal
			s.log.Error("unhandled error", "err", err, "route", c.Route().Path, "request_id", requestid.FromContext(c))
			observability.CaptureError(c.Context(), err, map[string]string{"route": c.Route().Path, "request_id": requestid.FromContext(c)})
		}
	}
	if de.RetryAfter > 0 {
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(math.Ceil(de.RetryAfter.Seconds()))))
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(de.Status).JSON(ErrorBody{Error: ErrorDetail{
		Code: de.Code, Message: de.Message, Fields: de.Fields, RequestID: requestid.FromContext(c),
	}})
}

func fiberCode(status int) string {
	switch status {
	case fiber.StatusNotFound:
		return "not_found"
	case fiber.StatusMethodNotAllowed:
		return "method_not_allowed"
	case fiber.StatusRequestEntityTooLarge:
		return "payload_too_large"
	case fiber.StatusBadRequest:
		return "bad_request"
	case fiber.StatusRequestTimeout:
		return "request_timeout"
	default:
		if status >= 500 {
			return "internal_error"
		}
		return "http_error"
	}
}
