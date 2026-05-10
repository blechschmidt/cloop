// Package apierror defines a structured error type and wire format used by
// cloop's HTTP servers (pkg/ui and pkg/apiserver).
//
// The package exposes:
//
//   - APIError: a typed error with a stable string Code, a human-readable
//     Message, an HTTPStatus, and an optional Details map.
//   - A registry of well-known error codes (INVALID_INPUT, NOT_FOUND,
//     RATE_LIMITED, INTERNAL, …) that callers should reuse instead of
//     inventing new strings. Codes are part of the API contract; renaming
//     one is a breaking change.
//   - WriteError, a helper that renders any error as the canonical JSON
//     response body, mapping plain errors and pkg/statedb sentinels to a
//     sensible default code/status.
//
// Wire format:
//
//	{
//	  "error": {
//	    "code":    "NOT_FOUND",
//	    "message": "task 42 does not exist",
//	    "details": { "task_id": 42 }   // optional, omitted if empty
//	  }
//	}
//
// The top-level "error" envelope keeps the body distinguishable from a
// successful payload at a glance and leaves room for additional metadata
// (request id, etc.) without breaking existing clients.
package apierror

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Code is a stable, machine-readable identifier for a class of API errors.
// Codes are part of the public API contract — never rename one; add a new
// constant if you need finer granularity. The wire form is the bare string
// value (e.g. "INVALID_INPUT").
type Code string

const (
	// CodeInvalidInput indicates the client sent a malformed request: bad
	// JSON, missing required fields, out-of-range numeric values, an
	// unparseable path parameter, etc. Maps to HTTP 400.
	CodeInvalidInput Code = "INVALID_INPUT"

	// CodeUnauthorized indicates the request is missing or carries invalid
	// credentials (bearer token). Maps to HTTP 401.
	CodeUnauthorized Code = "UNAUTHORIZED"

	// CodeForbidden indicates the caller is authenticated but not allowed
	// to perform the requested action. Maps to HTTP 403.
	CodeForbidden Code = "FORBIDDEN"

	// CodeNotFound indicates the requested resource (project, task,
	// artifact, …) does not exist. Maps to HTTP 404.
	CodeNotFound Code = "NOT_FOUND"

	// CodeMethodNotAllowed indicates the resource exists but the HTTP
	// method is not supported on it. Maps to HTTP 405.
	CodeMethodNotAllowed Code = "METHOD_NOT_ALLOWED"

	// CodeConflict indicates a state-machine or optimistic-concurrency
	// conflict: the resource is in a state incompatible with the request,
	// or the caller's plan version is stale. Maps to HTTP 409.
	CodeConflict Code = "CONFLICT"

	// CodePayloadTooLarge indicates the request body exceeded the
	// configured cap (MaxBytesReader). Maps to HTTP 413.
	CodePayloadTooLarge Code = "PAYLOAD_TOO_LARGE"

	// CodeRateLimited indicates the per-IP rate limit was exceeded. Maps
	// to HTTP 429. Servers should set Retry-After alongside this error.
	CodeRateLimited Code = "RATE_LIMITED"

	// CodeInternal indicates an unexpected server-side failure. Maps to
	// HTTP 500. Use sparingly; prefer a specific code when one fits.
	CodeInternal Code = "INTERNAL"

	// CodeUnavailable indicates a transient backend failure: SQLite
	// reported "database is locked" beyond the busy_timeout, an upstream
	// dependency is down, etc. Maps to HTTP 503. Callers may retry.
	CodeUnavailable Code = "UNAVAILABLE"
)

// defaultStatus returns the HTTP status code that pairs with a given Code.
// Used by APIError.statusOrDefault and WriteError when an explicit status
// has not been set on the error.
func defaultStatus(c Code) int {
	switch c {
	case CodeInvalidInput:
		return http.StatusBadRequest
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeForbidden:
		return http.StatusForbidden
	case CodeNotFound:
		return http.StatusNotFound
	case CodeMethodNotAllowed:
		return http.StatusMethodNotAllowed
	case CodeConflict:
		return http.StatusConflict
	case CodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeUnavailable:
		return http.StatusServiceUnavailable
	case CodeInternal:
		return http.StatusInternalServerError
	}
	// Unknown code — treat as internal so a forgotten registration does not
	// silently downgrade a real failure to a 200.
	return http.StatusInternalServerError
}

// APIError is the canonical error type returned by cloop HTTP handlers.
//
// APIError implements the error interface so it composes naturally with
// errors.Is / errors.As. Two APIErrors with the same Code are reported as
// equal by Is — handlers can therefore test for `apierror.IsCode(err,
// apierror.CodeNotFound)` without caring about the exact message.
type APIError struct {
	// Code is a stable machine-readable identifier. Required.
	Code Code `json:"code"`

	// Message is a human-readable explanation. Should be specific enough
	// for an operator reading logs but must not leak secrets, internal
	// paths, or stack traces.
	Message string `json:"message"`

	// HTTPStatus is the HTTP status code to send. Zero means "use the
	// default for Code". Setting a non-zero value is useful for codes
	// like CodeInternal whose default may be too coarse for a specific
	// failure mode.
	HTTPStatus int `json:"-"`

	// Details carries optional structured context (e.g. validation
	// failures, the offending field, the task id involved). Nil/empty
	// maps are omitted from the wire response.
	Details map[string]any `json:"details,omitempty"`

	// cause keeps the underlying error for errors.Unwrap support. Unset
	// when an APIError is constructed by hand.
	cause error
}

// Error implements the error interface. Format: "CODE: message".
func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Message
}

// Unwrap returns the underlying error, if any. Allows errors.Is / errors.As
// to traverse APIError → cause chains created by WrapError.
func (e *APIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is matches another error against this APIError. Two APIErrors are equal
// when their Codes match. This lets callers write `errors.Is(err,
// apierror.New(apierror.CodeNotFound, ""))` without caring about message
// contents.
func (e *APIError) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	other, ok := target.(*APIError)
	if !ok {
		return false
	}
	return e.Code == other.Code
}

// statusOrDefault returns HTTPStatus, falling back to defaultStatus(Code)
// when unset. Used by WriteError before serialising the response.
func (e *APIError) statusOrDefault() int {
	if e == nil {
		return http.StatusInternalServerError
	}
	if e.HTTPStatus > 0 {
		return e.HTTPStatus
	}
	return defaultStatus(e.Code)
}

// New constructs an APIError with the given code and message. HTTPStatus is
// left zero so it picks up the code's default; callers needing a specific
// status should set it on the returned value.
func New(code Code, message string) *APIError {
	return &APIError{Code: code, Message: message}
}

// Newf is New with fmt.Sprintf-style formatting. Avoids importing fmt at
// every call site for the common "build a one-line message" pattern.
func Newf(code Code, format string, args ...any) *APIError {
	return &APIError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// WithDetails returns a copy of e with the provided detail fields merged
// in. Existing keys are overwritten. Nil-safe.
func (e *APIError) WithDetails(kv map[string]any) *APIError {
	if e == nil {
		return nil
	}
	if len(kv) == 0 {
		return e
	}
	out := *e
	if out.Details == nil {
		out.Details = make(map[string]any, len(kv))
	} else {
		// Copy to avoid mutating a shared map captured by an earlier caller.
		copied := make(map[string]any, len(out.Details)+len(kv))
		for k, v := range out.Details {
			copied[k] = v
		}
		out.Details = copied
	}
	for k, v := range kv {
		out.Details[k] = v
	}
	return &out
}

// WithStatus returns a copy of e with HTTPStatus overridden.
func (e *APIError) WithStatus(status int) *APIError {
	if e == nil {
		return nil
	}
	out := *e
	out.HTTPStatus = status
	return &out
}

// WithCause returns a copy of e wrapping cause. The cause becomes the
// errors.Unwrap target so errors.Is / errors.As can traverse to it.
func (e *APIError) WithCause(cause error) *APIError {
	if e == nil {
		return nil
	}
	out := *e
	out.cause = cause
	return &out
}

// FromError returns an *APIError that best represents err for an HTTP
// response. The mapping rules, in order of precedence:
//
//  1. nil → nil.
//  2. err already is an *APIError → returned unchanged.
//  3. errors.Is matches a pkg/statedb sentinel → mapped to the
//     corresponding code (NOT_FOUND, CONFLICT, UNAVAILABLE, INTERNAL).
//  4. http.MaxBytesError → CodePayloadTooLarge.
//  5. Anything else → CodeInternal wrapping err as the cause.
//
// Use this from a handler when you have an arbitrary error and want to
// hand it straight to WriteError without writing a switch yourself.
func FromError(err error) *APIError {
	if err == nil {
		return nil
	}
	var ae *APIError
	if errors.As(err, &ae) {
		return ae
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return New(CodePayloadTooLarge, "request body too large").WithCause(err)
	}
	switch {
	case errors.Is(err, statedb.ErrTaskNotFound), errors.Is(err, statedb.ErrProjectNotFound):
		return New(CodeNotFound, err.Error()).WithCause(err)
	case errors.Is(err, statedb.ErrStaleVersion):
		return New(CodeConflict, err.Error()).WithCause(err)
	case errors.Is(err, statedb.ErrDBLocked):
		return New(CodeUnavailable, err.Error()).WithCause(err)
	case errors.Is(err, statedb.ErrSchemaMismatch):
		return New(CodeInternal, err.Error()).WithCause(err)
	}
	return New(CodeInternal, err.Error()).WithCause(err)
}

// FromHTTPStatus returns the Code that pairs with an HTTP status. Used by
// the legacy `jsonErr(w, message, status)` helpers in pkg/ui and
// pkg/apiserver as they migrate to structured codes — handlers that
// already know the precise status (e.g. from statedb.HTTPStatus) can
// forward through this helper without losing semantic information.
//
// Statuses outside the small set we use intentionally fall through to
// CodeInternal: an unknown status almost certainly indicates a server-side
// failure, and labelling it as such is safer than silently inventing a
// new code.
func FromHTTPStatus(status int) Code {
	switch status {
	case http.StatusBadRequest:
		return CodeInvalidInput
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusMethodNotAllowed:
		return CodeMethodNotAllowed
	case http.StatusConflict:
		return CodeConflict
	case http.StatusRequestEntityTooLarge:
		return CodePayloadTooLarge
	case http.StatusTooManyRequests:
		return CodeRateLimited
	case http.StatusServiceUnavailable:
		return CodeUnavailable
	default:
		return CodeInternal
	}
}

// WriteStatus is a convenience wrapper for the legacy `jsonErr(w, message,
// status)` call shape. It maps status to a Code via FromHTTPStatus, then
// writes the structured response. Existing handlers can therefore migrate
// in two phases: first switch to WriteStatus to land the wire-format
// change project-wide, then iteratively replace the call with an explicit
// Code to make the intent visible in the source.
func WriteStatus(w http.ResponseWriter, message string, status int) {
	WriteError(w, &APIError{
		Code:       FromHTTPStatus(status),
		Message:    message,
		HTTPStatus: status,
	})
}

// IsCode reports whether err (or any error wrapped by err) carries an
// APIError whose Code matches the given code.
func IsCode(err error, code Code) bool {
	if err == nil {
		return false
	}
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Code == code
}

// envelope is the JSON wire shape: {"error": APIError}. Kept separate so
// the public APIError struct stays clean for code that builds errors
// programmatically.
type envelope struct {
	Error *APIError `json:"error"`
}

// WriteError serialises e as the canonical JSON error body and writes the
// associated HTTP status. nil e is treated as a generic internal error so
// handlers can pass through a fresh helper return without nil-checking.
//
// The Content-Type is set to application/json. Header writes happen before
// the body, so callers must not write to w themselves before invoking this
// helper. Errors writing the body are intentionally swallowed — the status
// has already been sent and there is nothing meaningful to do.
func WriteError(w http.ResponseWriter, e *APIError) {
	if e == nil {
		e = New(CodeInternal, "unknown error")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.statusOrDefault())
	_ = json.NewEncoder(w).Encode(envelope{Error: e})
}

// Write is a convenience wrapper that builds an APIError from a code and
// message and writes it. Equivalent to WriteError(w, New(code, message))
// but reads more naturally at the call site:
//
//	apierror.Write(w, apierror.CodeInvalidInput, "title is required")
func Write(w http.ResponseWriter, code Code, message string) {
	WriteError(w, New(code, message))
}

// WriteFromError accepts any error, runs it through FromError, and writes
// the result. nil err is a no-op so callers can use it in idiomatic
//
//	if err != nil { apierror.WriteFromError(w, err); return }
//
// blocks without an extra layer of helpers.
func WriteFromError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	WriteError(w, FromError(err))
}

