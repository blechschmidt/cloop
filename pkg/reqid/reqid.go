// Package reqid provides request-scoped correlation IDs that flow through
// HTTP middleware, the orchestrator, and provider calls so that every log
// line, audit entry, and error can be tied back to one logical operation.
//
// A request ID is a short opaque string. It is meant to be cheap to generate,
// safe to log, and human-readable in tracebacks. It is NOT a security
// credential — collisions are extremely unlikely (~96 bits of entropy) but
// not cryptographically guaranteed.
//
// Lifecycle:
//
//   - HTTP middleware (pkg/ui/server.go, pkg/apiserver/server.go) reads the
//     incoming X-Request-ID header, validates it, falls back to Generate()
//     when missing or malformed, then attaches the ID to r.Context() via
//     WithContext and echoes it on the response via the X-Request-ID header.
//   - The orchestrator generates an ID at the entry of each task execution
//     and injects it into the task context so every provider call inherits
//     the ID without further plumbing.
//   - Providers (anthropic, openai, ollama, claudecode) and the retry/breaker
//     wrappers read the ID via FromContext and include it in their structured
//     log lines and error wrapping.
//
// Empty string ("") is the canonical absence value: helpers return "" when
// no ID is bound and accept "" as a no-op when injecting.
package reqid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// HeaderName is the canonical HTTP header carrying the request ID into and
// out of the cloop UI / API servers. It matches the de-facto standard used
// by AWS, GCP, and most reverse proxies.
const HeaderName = "X-Request-ID"

// MaxLength bounds the length of an externally-supplied request ID. IDs
// longer than this are rejected and a fresh ID is generated instead. The
// cap prevents log injection (an attacker stuffing kilobytes into a header)
// and keeps log lines readable.
const MaxLength = 128

// Length is the byte length of a generated request ID before hex encoding,
// yielding a 24-character hex string (96 bits of entropy). Short enough to
// fit comfortably in log lines, long enough that collisions are negligible
// for any plausible cloop workload.
const Length = 12

// LogKey is the structured-log attribute name under which the request ID
// is emitted. Callers that bind a logger via logger.With should use this
// constant so downstream log aggregators can index a single canonical key.
const LogKey = "request_id"

type contextKey struct{}

// ctxKey is the unexported context key used by WithContext / FromContext.
// Using a struct{} type prevents collisions with string-keyed values that
// other packages might inject into the same context.
var ctxKey contextKey

// Generate returns a fresh random request ID. It uses crypto/rand for a
// uniform, unguessable distribution; if the syscall fails (extremely rare —
// e.g. /dev/urandom unreadable in a locked-down chroot) it falls back to a
// deterministic placeholder so callers never see an empty ID. The placeholder
// is distinguishable in logs but does not expose the failure mode to the
// network.
func Generate() string {
	buf := make([]byte, Length)
	if _, err := rand.Read(buf); err != nil {
		// Fall back to a stable placeholder. This path should never be hit
		// in practice; if it is, the operator has a bigger problem than
		// duplicate request IDs.
		return "reqid-fallback"
	}
	return hex.EncodeToString(buf)
}

// WithContext returns a copy of ctx that carries id. When id is empty the
// original ctx is returned unchanged so callers can chain WithContext into
// an HTTP handler without checking for the empty case at every call site.
func WithContext(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKey, id)
}

// FromContext returns the request ID bound to ctx, or "" when none is
// present. Callers MUST treat "" as "no ID known" and either omit the
// request_id attribute from their log line or generate one on the spot —
// they MUST NOT log "" as a literal value.
func FromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(ctxKey).(string)
	return v
}

// IsValid reports whether id is plausibly a valid request ID: non-empty,
// shorter than MaxLength, and made up only of printable ASCII without
// whitespace or control characters. The function is permissive on purpose —
// any client-supplied ID that meets the format constraints is honoured for
// trace continuity, not just IDs produced by Generate.
func IsValid(id string) bool {
	if id == "" || len(id) > MaxLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		// Printable ASCII excluding space (0x20) and DEL (0x7F).
		if c <= 0x20 || c >= 0x7F {
			return false
		}
	}
	return true
}

// FromRequest extracts the request ID from r's X-Request-ID header,
// returning ("", false) when the header is missing or fails IsValid. The
// boolean lets callers distinguish "no header" from "header was rejected"
// for logging purposes.
func FromRequest(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	raw := strings.TrimSpace(r.Header.Get(HeaderName))
	if raw == "" {
		return "", false
	}
	if !IsValid(raw) {
		return "", false
	}
	return raw, true
}

// EnsureContext returns a context that carries a request ID, generating
// one when ctx does not yet have one. The returned ID is the canonical
// value the caller should attach to log lines for the rest of the request.
//
// Use this at boundaries where request-ID propagation may not have been
// performed (background jobs, CLI entry points, retries spawned without
// the parent context). Do not use it inside middleware that already
// handles header parsing — middleware should call FromRequest first so it
// can echo the original ID back on the response.
func EnsureContext(ctx context.Context) (context.Context, string) {
	if id := FromContext(ctx); id != "" {
		return ctx, id
	}
	id := Generate()
	return WithContext(ctx, id), id
}
