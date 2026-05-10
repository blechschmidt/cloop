package statedb

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// TestSentinels_AreDistinct guards against accidental copy-paste sharing
// between the five public sentinels. A future refactor that, say, set
// ErrTaskNotFound = ErrProjectNotFound would silently change HTTP semantics
// for half the API surface — this test makes that error a compile-time
// red flag.
func TestSentinels_AreDistinct(t *testing.T) {
	all := []error{
		ErrTaskNotFound,
		ErrProjectNotFound,
		ErrStaleVersion,
		ErrDBLocked,
		ErrSchemaMismatch,
	}
	for i := range all {
		for j := range all {
			if i == j {
				continue
			}
			if errors.Is(all[i], all[j]) {
				t.Errorf("sentinels %v and %v are not distinct (errors.Is returned true)",
					all[i], all[j])
			}
		}
	}
}

// TestHTTPStatus_Mapping locks in the contract that pkg/ui and pkg/apiserver
// rely on. Changing any of these mappings is a wire-level API break for the
// Web UI and any external client of cloop's REST API.
func TestHTTPStatus_Mapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil → 200", nil, http.StatusOK},
		{"task-not-found → 404", ErrTaskNotFound, http.StatusNotFound},
		{"project-not-found → 404", ErrProjectNotFound, http.StatusNotFound},
		{"stale-version → 409", ErrStaleVersion, http.StatusConflict},
		{"db-locked → 503", ErrDBLocked, http.StatusServiceUnavailable},
		{"schema-mismatch → 500", ErrSchemaMismatch, http.StatusInternalServerError},
		{"unknown → 500", errors.New("boom"), http.StatusInternalServerError},

		// Wrapped errors must round-trip through errors.Is.
		{"wrapped task-not-found", fmt.Errorf("lookup id=42: %w", ErrTaskNotFound), http.StatusNotFound},
		{"wrapped db-locked", fmt.Errorf("save state: %w", ErrDBLocked), http.StatusServiceUnavailable},

		// Doubly-wrapped (e.g. statedb wraps the driver error which is then
		// further wrapped by an outer fmt.Errorf at the call site).
		{"double-wrapped",
			fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", ErrStaleVersion)),
			http.StatusConflict},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := HTTPStatus(tc.err); got != tc.want {
				t.Errorf("HTTPStatus(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestClassifyDriverErr_BusyVariants verifies all the busy/locked phrasings
// the modernc.org/sqlite driver emits get classified as ErrDBLocked. These
// strings come straight from observed driver output — adding new variants
// here is the right place to extend the classifier.
func TestClassifyDriverErr_BusyVariants(t *testing.T) {
	variants := []string{
		"database is locked",
		"database table is locked: plan_tasks",
		"SQLITE_BUSY: cannot start a transaction",
		"some other busy condition",
	}
	for _, msg := range variants {
		got := classifyDriverErr(errors.New(msg))
		if !errors.Is(got, ErrDBLocked) {
			t.Errorf("classifyDriverErr(%q) did not wrap ErrDBLocked; got %v", msg, got)
		}
		// The driver detail must survive: callers should still see the
		// raw message in logs and HTTP error bodies.
		if got.Error() == ErrDBLocked.Error() {
			t.Errorf("classifyDriverErr(%q) lost the driver-detail message", msg)
		}
	}
}

// TestClassifyDriverErr_SchemaVariants covers the ErrSchemaMismatch path —
// "no such table" / "no such column" / "malformed" shouldn't surface as a
// generic 500 when they could be a partial-migration or corrupt-DB signal.
func TestClassifyDriverErr_SchemaVariants(t *testing.T) {
	variants := []string{
		"no such table: plan_tasks",
		"no such column: cost_id",
		"file is not a database (malformed)",
	}
	for _, msg := range variants {
		got := classifyDriverErr(errors.New(msg))
		if !errors.Is(got, ErrSchemaMismatch) {
			t.Errorf("classifyDriverErr(%q) did not wrap ErrSchemaMismatch; got %v", msg, got)
		}
	}
}

// TestClassifyDriverErr_NilPassthrough ensures a nil error stays nil — the
// function is called liberally inside helpers, so a nil-in/non-nil-out bug
// would silently fail every successful operation.
func TestClassifyDriverErr_NilPassthrough(t *testing.T) {
	if got := classifyDriverErr(nil); got != nil {
		t.Errorf("classifyDriverErr(nil) = %v, want nil", got)
	}
}

// TestClassifyDriverErr_PreservesSentinel ensures we don't double-wrap an
// error that already carries one of our sentinels. Important because
// classifyDriverErr is called at every layer that returns from SQL.
func TestClassifyDriverErr_PreservesSentinel(t *testing.T) {
	already := fmt.Errorf("upstream: %w", ErrTaskNotFound)
	got := classifyDriverErr(already)
	if got != already {
		t.Errorf("classifyDriverErr re-wrapped a sentinel-bearing error; got %v, want unchanged", got)
	}
}
