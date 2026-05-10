package apierror

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestCodeStability locks in the wire string of every well-known code.
// These strings are part of the API contract — clients pattern-match on
// them — so a rename should fail this test loudly. Add a new constant
// and a new line here when introducing a code; never edit an existing
// line.
func TestCodeStability(t *testing.T) {
	t.Parallel()

	cases := []struct {
		code Code
		want string
	}{
		{CodeInvalidInput, "INVALID_INPUT"},
		{CodeUnauthorized, "UNAUTHORIZED"},
		{CodeForbidden, "FORBIDDEN"},
		{CodeNotFound, "NOT_FOUND"},
		{CodeMethodNotAllowed, "METHOD_NOT_ALLOWED"},
		{CodeConflict, "CONFLICT"},
		{CodePayloadTooLarge, "PAYLOAD_TOO_LARGE"},
		{CodeRateLimited, "RATE_LIMITED"},
		{CodeInternal, "INTERNAL"},
		{CodeUnavailable, "UNAVAILABLE"},
	}
	for _, tc := range cases {
		if string(tc.code) != tc.want {
			t.Errorf("code drift: got %q, want %q — wire format is part of the API contract", string(tc.code), tc.want)
		}
	}
}

// TestDefaultStatusMapping verifies every code maps to the documented HTTP
// status. Like TestCodeStability, the mapping is a wire contract.
func TestDefaultStatusMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		code   Code
		status int
	}{
		{CodeInvalidInput, http.StatusBadRequest},
		{CodeUnauthorized, http.StatusUnauthorized},
		{CodeForbidden, http.StatusForbidden},
		{CodeNotFound, http.StatusNotFound},
		{CodeMethodNotAllowed, http.StatusMethodNotAllowed},
		{CodeConflict, http.StatusConflict},
		{CodePayloadTooLarge, http.StatusRequestEntityTooLarge},
		{CodeRateLimited, http.StatusTooManyRequests},
		{CodeUnavailable, http.StatusServiceUnavailable},
		{CodeInternal, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		if got := defaultStatus(tc.code); got != tc.status {
			t.Errorf("defaultStatus(%q) = %d, want %d", tc.code, got, tc.status)
		}
	}

	// An unknown code must NOT silently downgrade to 200; we want a
	// 500 so the misuse is visible in production.
	if got := defaultStatus(Code("GIBBERISH")); got != http.StatusInternalServerError {
		t.Errorf("defaultStatus on unknown code = %d, want 500", got)
	}
}

// TestErrorAndUnwrap covers the error-interface plumbing.
func TestErrorAndUnwrap(t *testing.T) {
	t.Parallel()

	// Nil receiver is safe — handlers may bubble up a zero-value pointer.
	var nilErr *APIError
	if nilErr.Error() != "<nil>" {
		t.Errorf("nil APIError.Error() = %q, want %q", nilErr.Error(), "<nil>")
	}

	e := New(CodeNotFound, "task 42 missing")
	if got := e.Error(); got != "NOT_FOUND: task 42 missing" {
		t.Errorf("Error() = %q, want %q", got, "NOT_FOUND: task 42 missing")
	}

	// Empty message: Error() must still be human-readable.
	bare := New(CodeInternal, "")
	if got := bare.Error(); got != "INTERNAL" {
		t.Errorf("bare.Error() = %q, want %q", got, "INTERNAL")
	}

	// Unwrap chains to the original cause.
	cause := errors.New("disk full")
	wrapped := New(CodeInternal, "save failed").WithCause(cause)
	if !errors.Is(wrapped, cause) {
		t.Errorf("errors.Is should walk to the underlying cause")
	}
}

// TestIsMatchesByCode ensures errors.Is treats two APIErrors as equal when
// their codes match, regardless of the message. This is the contract
// callers rely on for the IsCode helper and for code-based branching.
func TestIsMatchesByCode(t *testing.T) {
	t.Parallel()

	a := New(CodeNotFound, "task 1")
	b := New(CodeNotFound, "task 2")
	if !errors.Is(a, b) {
		t.Errorf("two CodeNotFound errors should match under errors.Is")
	}

	c := New(CodeConflict, "task 1")
	if errors.Is(a, c) {
		t.Errorf("different codes must not match under errors.Is")
	}

	// IsCode helper variant.
	if !IsCode(a, CodeNotFound) {
		t.Errorf("IsCode should return true for matching code")
	}
	if IsCode(a, CodeConflict) {
		t.Errorf("IsCode should return false for non-matching code")
	}
	if IsCode(nil, CodeNotFound) {
		t.Errorf("IsCode(nil, …) must be false")
	}
	if IsCode(errors.New("plain"), CodeNotFound) {
		t.Errorf("IsCode on non-APIError must be false")
	}
}

// TestFromErrorMapping verifies the error→APIError translation table.
// Each branch is checked separately so a regression points straight at
// the broken case rather than a confusing combined assertion.
func TestFromErrorMapping(t *testing.T) {
	t.Parallel()

	if FromError(nil) != nil {
		t.Errorf("FromError(nil) must return nil")
	}

	// Pass-through: an existing APIError is returned unchanged.
	src := New(CodeRateLimited, "slow down")
	if got := FromError(src); got != src {
		t.Errorf("FromError(*APIError) should return the same pointer")
	}

	// Wrapped APIError surfaces via errors.As.
	wrapped := fmt.Errorf("orchestrator: %w", New(CodeConflict, "stale"))
	got := FromError(wrapped)
	if got == nil || got.Code != CodeConflict {
		t.Errorf("wrapped APIError should be unwrapped; got %+v", got)
	}

	// statedb sentinels.
	cases := []struct {
		name     string
		err      error
		wantCode Code
	}{
		{"task not found", statedb.ErrTaskNotFound, CodeNotFound},
		{"project not found", statedb.ErrProjectNotFound, CodeNotFound},
		{"stale version", statedb.ErrStaleVersion, CodeConflict},
		{"db locked", statedb.ErrDBLocked, CodeUnavailable},
		{"schema mismatch", statedb.ErrSchemaMismatch, CodeInternal},
		{"unknown", errors.New("boom"), CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ae := FromError(tc.err)
			if ae == nil {
				t.Fatalf("FromError returned nil for %v", tc.err)
			}
			if ae.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", ae.Code, tc.wantCode)
			}
			// Cause must be preserved so errors.Is keeps working.
			if !errors.Is(ae, tc.err) {
				t.Errorf("cause not preserved for %v", tc.err)
			}
		})
	}

	// MaxBytesError → PAYLOAD_TOO_LARGE.
	mbe := &http.MaxBytesError{Limit: 1024}
	ae := FromError(mbe)
	if ae == nil || ae.Code != CodePayloadTooLarge {
		t.Errorf("MaxBytesError should map to PAYLOAD_TOO_LARGE; got %+v", ae)
	}
}

// TestWriteErrorWireFormat asserts the exact JSON shape of the response
// body. The shape is what every API consumer sees — locking it in here
// prevents accidental rename of envelope keys.
func TestWriteErrorWireFormat(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteError(rec, New(CodeNotFound, "task 7 missing").
		WithDetails(map[string]any{"task_id": float64(7)}))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}

	var body envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Error == nil {
		t.Fatalf("response missing 'error' envelope key")
	}
	if body.Error.Code != CodeNotFound {
		t.Errorf("decoded code = %q, want NOT_FOUND", body.Error.Code)
	}
	if body.Error.Message != "task 7 missing" {
		t.Errorf("decoded message = %q, want 'task 7 missing'", body.Error.Message)
	}
	if got := body.Error.Details["task_id"]; got != float64(7) {
		t.Errorf("details[task_id] = %v, want 7", got)
	}

	// Empty details must be omitted from the wire (omitempty).
	rec2 := httptest.NewRecorder()
	WriteError(rec2, New(CodeInternal, "boom"))
	if strings.Contains(rec2.Body.String(), `"details"`) {
		t.Errorf("empty details should be omitted; body = %s", rec2.Body.String())
	}
}

// TestWriteErrorNilSafe ensures handlers that pass through a nil error
// pointer get a generic 500 rather than a panic.
func TestWriteErrorNilSafe(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteError(rec, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("nil APIError must yield 500; got %d", rec.Code)
	}

	var body envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("nil-error response is not valid JSON: %v", err)
	}
	if body.Error == nil || body.Error.Code != CodeInternal {
		t.Errorf("nil-error response should carry INTERNAL code; got %+v", body.Error)
	}
}

// TestWriteFromErrorAndWrite covers the convenience wrappers.
func TestWriteFromErrorAndWrite(t *testing.T) {
	t.Parallel()

	// nil err is a no-op.
	rec := httptest.NewRecorder()
	WriteFromError(rec, nil)
	if rec.Body.Len() != 0 || rec.Code != http.StatusOK {
		t.Errorf("WriteFromError(nil) should write nothing; got code=%d body=%q", rec.Code, rec.Body.String())
	}

	// statedb sentinel routes through FromError.
	rec = httptest.NewRecorder()
	WriteFromError(rec, statedb.ErrDBLocked)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("ErrDBLocked must yield 503; got %d", rec.Code)
	}
	var body envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body.Error == nil || body.Error.Code != CodeUnavailable {
		t.Errorf("expected UNAVAILABLE code; got %+v", body.Error)
	}

	// Write helper.
	rec = httptest.NewRecorder()
	Write(rec, CodeInvalidInput, "title required")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Write must use code default; got %d", rec.Code)
	}
}

// TestWithStatusOverride confirms the explicit status overrides the
// per-code default.
func TestWithStatusOverride(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	// Internal code paired with 502 (Bad Gateway) — atypical but valid.
	WriteError(rec, New(CodeInternal, "upstream down").WithStatus(http.StatusBadGateway))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("WithStatus override ignored; got %d, want 502", rec.Code)
	}
}

// TestWithDetailsImmutable verifies WithDetails copies the underlying map
// instead of mutating shared state. A handler returning a frozen base
// error from a package-level var must not see its details polluted by an
// unrelated request.
func TestWithDetailsImmutable(t *testing.T) {
	t.Parallel()

	base := New(CodeNotFound, "task missing").WithDetails(map[string]any{"k": "v"})
	other := base.WithDetails(map[string]any{"x": 1})

	if _, ok := base.Details["x"]; ok {
		t.Errorf("WithDetails mutated the base error's map")
	}
	if other.Details["k"] != "v" || other.Details["x"] != 1 {
		t.Errorf("WithDetails dropped or failed to merge keys: %+v", other.Details)
	}
}

// TestFromHTTPStatus exercises the legacy-status → code adapter. Every
// case here is a wire commitment for the migration from `jsonErr(w, msg,
// status)` to structured codes — same status must always produce the
// same code.
func TestFromHTTPStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		status int
		code   Code
	}{
		{http.StatusBadRequest, CodeInvalidInput},
		{http.StatusUnauthorized, CodeUnauthorized},
		{http.StatusForbidden, CodeForbidden},
		{http.StatusNotFound, CodeNotFound},
		{http.StatusMethodNotAllowed, CodeMethodNotAllowed},
		{http.StatusConflict, CodeConflict},
		{http.StatusRequestEntityTooLarge, CodePayloadTooLarge},
		{http.StatusTooManyRequests, CodeRateLimited},
		{http.StatusServiceUnavailable, CodeUnavailable},
		{http.StatusInternalServerError, CodeInternal},
		{http.StatusBadGateway, CodeInternal},        // unknown → internal
		{http.StatusGatewayTimeout, CodeInternal},    // unknown → internal
		{http.StatusUnprocessableEntity, CodeInternal}, // unknown → internal
	}
	for _, tc := range cases {
		got := FromHTTPStatus(tc.status)
		if got != tc.code {
			t.Errorf("FromHTTPStatus(%d) = %q, want %q", tc.status, got, tc.code)
		}
	}
}

// TestWriteStatusPreservesStatus locks in the bridge helper: WriteStatus
// must emit exactly the status the caller asked for, regardless of what
// the code's default would have been. This matters for handlers that
// pipe statedb.HTTPStatus through (which can return 503 for a code whose
// default would be 500).
func TestWriteStatusPreservesStatus(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteStatus(rec, "boom", http.StatusServiceUnavailable)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}

	var body envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body.Error.Code != CodeUnavailable {
		t.Errorf("code = %q, want UNAVAILABLE", body.Error.Code)
	}
	if body.Error.Message != "boom" {
		t.Errorf("message = %q, want boom", body.Error.Message)
	}
}

// TestFromErrorWithWrappedSentinel asserts that a sentinel buried under
// fmt.Errorf("%w", …) still surfaces the right code. This exercises the
// real handler path where pkg/state wraps the driver error before bubbling.
func TestFromErrorWithWrappedSentinel(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("save: %w", statedb.ErrTaskNotFound)
	ae := FromError(wrapped)
	if ae == nil || ae.Code != CodeNotFound {
		t.Errorf("wrapped sentinel should yield NOT_FOUND; got %+v", ae)
	}
}
