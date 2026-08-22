package apiserver

// The readiness half of Task 20170 for `cloop serve`.
//
// `cloop serve` is the other way a control plane gets hosted, and it had the
// same gap as `cloop ui`: it registered only the localprocess driver, and its
// /readyz asked only about SQLite. A strict-mode deployment therefore reported
// itself ready while every POST /run it accepted could only be answered with a
// host-execution refusal.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// initReadyzStateDB creates a usable state store so the SQLite gate passes
// and the executor gate is the only thing left that can fail.
func initReadyzStateDB(t *testing.T, workDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(workDir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	db, err := statedb.Open(state.StateDBPath(workDir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("statedb.Close: %v", err)
	}
}

// enterStrictMode flips the process-global policy and undoes both of its
// effects. ApplyHostExecutionPolicy evicts the localprocess driver, and
// registerBuiltinExecutors is behind a sync.Once, so restoring the flag alone
// would leave every later test in this package without a host executor.
func enterStrictMode(t *testing.T) {
	t.Helper()
	prev := executor.SetAllowHostExecution(false)
	t.Cleanup(func() {
		executor.SetAllowHostExecution(prev)
		if prev {
			_ = localprocess.Ensure(executor.DefaultRegistry)
		}
	})
	executor.ApplyHostExecutionPolicy(false)
}

func probeReadyz(t *testing.T, s *Server) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	s.handleReadyz(rr, req)

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("/readyz: invalid JSON: %v (body=%s)", err, rr.Body.String())
	}
	return rr.Code, body
}

// TestReadyz_StrictModeWithNoIsolatingExecutor is the regression test: a
// strict-mode API server with nothing isolating registered must fail its
// readiness gate rather than accept traffic it can only refuse.
func TestReadyz_StrictModeWithNoIsolatingExecutor(t *testing.T) {
	wd := t.TempDir()
	initReadyzStateDB(t, wd)
	s := New(wd, 0, "")
	enterStrictMode(t)

	if len(executor.IsolatedIDs()) > 0 {
		t.Skip("another test left an isolating executor in the default registry")
	}

	code, body := probeReadyz(t, s)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz: want 503, got %d (body=%v)", code, body)
	}
	if got, _ := body["check"].(string); got != "executors" {
		t.Errorf("/readyz: want check=executors, got %v", body["check"])
	}
	if rem, _ := body["remediation"].(string); rem == "" {
		t.Error("/readyz: not-ready body must carry a remediation")
	}
	if reason, _ := body["reason"].(string); !strings.Contains(reason, "strict mode") {
		t.Errorf("/readyz: want a reason naming strict mode, got %q", body["reason"])
	}
}

// TestReadyz_PermissiveModeUnaffected: the gate must never fire for the
// ordinary single-machine `cloop serve`.
func TestReadyz_PermissiveModeUnaffected(t *testing.T) {
	wd := t.TempDir()
	initReadyzStateDB(t, wd)
	s := New(wd, 0, "")
	prev := executor.SetAllowHostExecution(true)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })

	code, body := probeReadyz(t, s)
	if code != http.StatusOK {
		t.Fatalf("/readyz: want 200 in permissive mode, got %d (body=%v)", code, body)
	}
	if got := body["status"]; got != "ready" {
		t.Errorf("/readyz: want status=ready, got %v", got)
	}
}
