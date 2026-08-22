// Package statedb — typed sentinel errors.
//
// HTTP handlers, the orchestrator, and CLI commands need to distinguish a
// handful of well-known failure modes from a generic "something went wrong".
// The Go convention is to expose package-level sentinel errors and have
// callers use errors.Is to test against them. This file is the authoritative
// list for cloop's relational data layer.
//
// HTTP mapping (used by pkg/ui and pkg/apiserver via HTTPStatus below):
//
//	ErrTaskNotFound    → 404 Not Found
//	ErrProjectNotFound → 404 Not Found
//	ErrStaleVersion    → 409 Conflict
//	ErrDBLocked        → 503 Service Unavailable
//	ErrSchemaMismatch  → 500 Internal Server Error
//
// All these errors are safe targets for errors.Is. Internal helpers wrap
// driver errors with %w so the sentinel survives across package boundaries.
package statedb

import (
	"errors"
	"net/http"
	"strings"
)

// Sentinel errors. Add to this list — do not rename or reuse.
var (
	// ErrTaskNotFound indicates the requested task ID does not exist in the
	// project plan. Returned by lookup helpers in pkg/state and pkg/statedb.
	ErrTaskNotFound = errors.New("statedb: task not found")

	// ErrProjectNotFound indicates the working directory has no cloop project
	// (no state.db, no migratable state.json). Returned by state.Load.
	ErrProjectNotFound = errors.New("statedb: project not found")

	// ErrStaleVersion indicates an optimistic-concurrency check failed: the
	// caller's plan version no longer matches the on-disk version. Callers
	// should re-load and re-apply.
	ErrStaleVersion = errors.New("statedb: stale plan version")

	// ErrDBLocked indicates SQLite returned a busy/locked error that the
	// busy_timeout did not absorb (extreme contention or a long-running
	// writer in another process). Callers may retry the operation.
	ErrDBLocked = errors.New("statedb: database busy")

	// ErrSchemaMismatch indicates the on-disk schema is not what this binary
	// expects (corruption, partial migration, or a future binary's database
	// opened by an older one). Manual intervention is usually required.
	ErrSchemaMismatch = errors.New("statedb: schema mismatch")

	// ErrExecutorNotFound indicates the requested execution backend is not
	// registered in the executors table. Callers must treat this as fatal
	// for the operation rather than falling back to host execution — see
	// pkg/executor's fail-closed resolution policy.
	ErrExecutorNotFound = errors.New("statedb: executor not found")

	// ErrBrokerSecretNotFound indicates no broker_secrets row has the
	// requested ID. Like ErrExecutorNotFound this is fatal for the
	// operation: a caller must never substitute a different credential for
	// one it could not find.
	ErrBrokerSecretNotFound = errors.New("statedb: broker secret not found")

	// ErrBrokerGrantNotFound indicates no broker_grants row has the
	// requested ID.
	ErrBrokerGrantNotFound = errors.New("statedb: broker grant not found")

	// ErrEgressGrantNotFound indicates no egress_grants row has the
	// requested ID. Like the broker sentinels this is fatal for the
	// operation: a caller must never fall back to a different egress policy
	// than the one it asked for.
	ErrEgressGrantNotFound = errors.New("statedb: egress grant not found")

	// ErrExecutorHealthNotFound indicates the executor has no health record:
	// the scheduler has never probed it. Callers must not read this as
	// "healthy" — an unobserved executor is unknown, not ready.
	ErrExecutorHealthNotFound = errors.New("statedb: executor health not found")

	// ErrExecutorSessionNotFound indicates no executor_sessions row has the
	// requested ID.
	ErrExecutorSessionNotFound = errors.New("statedb: executor session not found")

	// ErrExecutorSessionClaimLost indicates a conditional requeue matched no
	// row: another supervisor already claimed the session, or it is no longer
	// running. This is the exactly-once signal, and it is a distinct error
	// because "someone else is failing this over" must never be retried as if
	// it were a transient fault — doing so is how the same work ends up
	// running twice.
	ErrExecutorSessionClaimLost = errors.New("statedb: executor session claim lost")

	// ErrAPITokenNotFound indicates no api_tokens row has the requested ID.
	//
	// On the verification path this is an ordinary outcome, not a fault: it
	// is what a forged or already-purged token id looks like. Callers must
	// answer it exactly as they answer a bad secret — an unauthenticated
	// caller must not be able to use the difference to learn which token ids
	// exist.
	ErrAPITokenNotFound = errors.New("statedb: api token not found")
)

// classifyDriverErr inspects a raw error returned by the modernc.org/sqlite
// driver and wraps it in one of the typed sentinels above when the message
// matches a known failure mode. The original error is preserved via %w so
// callers can still call err.Error() for full driver context.
//
// Driver string-matching is unavoidable here — modernc.org/sqlite does not
// expose stable error code constants for these conditions — but it is
// confined to this single function so call sites only ever see typed
// errors.
func classifyDriverErr(err error) error {
	if err == nil {
		return nil
	}
	// Don't re-wrap errors that already carry one of our sentinels.
	if errors.Is(err, ErrDBLocked) ||
		errors.Is(err, ErrSchemaMismatch) ||
		errors.Is(err, ErrTaskNotFound) ||
		errors.Is(err, ErrProjectNotFound) ||
		errors.Is(err, ErrStaleVersion) ||
		errors.Is(err, ErrExecutorNotFound) {
		return err
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "database is locked"),
		strings.Contains(lower, "database table is locked"),
		strings.Contains(lower, "sqlite_busy"),
		strings.Contains(lower, "busy"):
		return wrap(ErrDBLocked, err)
	case strings.Contains(lower, "no such table"),
		strings.Contains(lower, "no such column"),
		strings.Contains(lower, "malformed"),
		strings.Contains(lower, "schema"):
		return wrap(ErrSchemaMismatch, err)
	}
	return err
}

// wrap returns an error whose Is target is sentinel and whose Error message
// exposes the underlying driver detail.
func wrap(sentinel, inner error) error {
	return &wrappedErr{sentinel: sentinel, inner: inner}
}

type wrappedErr struct {
	sentinel error
	inner    error
}

func (w *wrappedErr) Error() string { return w.sentinel.Error() + ": " + w.inner.Error() }
func (w *wrappedErr) Unwrap() error { return w.inner }
func (w *wrappedErr) Is(target error) bool {
	return target == w.sentinel || errors.Is(w.inner, target)
}

// HTTPStatus returns the HTTP status code that best represents err for an
// API response. Unknown errors map to 500. Use this from any HTTP handler
// to keep status-code logic out of individual call sites.
//
//	if err != nil {
//	    jsonErr(w, err.Error(), statedb.HTTPStatus(err))
//	    return
//	}
func HTTPStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrTaskNotFound), errors.Is(err, ErrProjectNotFound),
		errors.Is(err, ErrExecutorNotFound), errors.Is(err, ErrAPITokenNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrStaleVersion):
		return http.StatusConflict
	case errors.Is(err, ErrDBLocked):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrSchemaMismatch):
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}
