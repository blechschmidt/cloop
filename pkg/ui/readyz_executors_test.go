package ui

// End-to-end cover for the readiness half of Task 20170.
//
// The unit tests in pkg/executor/reconcile pin down the verdict; these pin
// down that the HTTP probe actually asks for it. That distinction matters
// because the bug being fixed was not a wrong verdict — it was a probe that
// never consulted the execution path at all, so a hub that could only answer
// runs with 409 passed its readiness gate and a Kubernetes rollout went green.
//
// These tests are deliberately not parallel: the host-execution policy is a
// process-global switch, and a t.Parallel sibling reading it mid-flip would
// flake.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
)

// enterStrictMode flips the process-global no-host-execution policy for one
// test and undoes both of its effects afterwards.
//
// Restoring the flag is not enough. ApplyHostExecutionPolicy also *evicts*
// the localprocess driver from the default registry, and registerBuiltin-
// Executors is guarded by a sync.Once — so without re-registering it here,
// the first strict-mode test in this package would silently leave every
// later test running against a registry with no host executor.
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

// probeReadyz runs the readiness probe through the real handler chain and
// returns the status code and decoded body.
func probeReadyz(t *testing.T, s *Server) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("/readyz: invalid JSON: %v (body=%s)", err, rr.Body.String())
	}
	return rr.Code, body
}

// TestReadyz_StrictModeWithNoIsolatingExecutorIsNotReady is the regression
// test: a hub in strict mode with nothing isolating registered must fail
// readiness, and must say what to do about it.
func TestReadyz_StrictModeWithNoIsolatingExecutorIsNotReady(t *testing.T) {
	wd := t.TempDir()
	initStateDB(t, wd)
	s := New(wd, 0, "")

	// Reproduce "allow_host_process: false with no isolating executor
	// configured" — the exact shape of a hub deployed from the Helm chart
	// before this task, which came up with zero usable executors.
	enterStrictMode(t)

	if len(executor.IsolatedIDs()) > 0 {
		t.Skip("another test left an isolating executor in the default registry")
	}

	code, body := probeReadyz(t, s)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz: want 503 when strict mode has no isolating executor, got %d (body=%v)", code, body)
	}
	if got := body["status"]; got != "not_ready" {
		t.Errorf("/readyz: want status=not_ready, got %v", got)
	}
	if got, _ := body["check"].(string); got != "executors" {
		t.Errorf("/readyz: want the failing gate named as %q, got %v", "executors", body["check"])
	}
	// The remediation is the whole point of failing loudly: an operator
	// reading `kubectl describe pod` must get the fix, not just the symptom.
	rem, _ := body["remediation"].(string)
	if rem == "" {
		t.Fatal("/readyz: not-ready body must carry a remediation field")
	}
	if !strings.Contains(rem, "executors.container") && !strings.Contains(rem, "executor") {
		t.Errorf("/readyz: remediation should name an executor to configure, got %q", rem)
	}
	if reason, _ := body["reason"].(string); !strings.Contains(reason, "strict mode") {
		t.Errorf("/readyz: want a reason naming strict mode, got %q", body["reason"])
	}
}

// TestReadyz_StrictModeWithIsolatingExecutorIsReady is the other half: the
// gate must open as soon as something isolating is registered — including an
// agent that enrolled long after startup, which is why readiness is computed
// live rather than frozen into the startup report.
func TestReadyz_StrictModeWithIsolatingExecutorIsReady(t *testing.T) {
	wd := t.TempDir()
	initStateDB(t, wd)
	s := New(wd, 0, "")

	enterStrictMode(t)

	iso := &readyzStubExecutor{id: "readyz-remote-stub"}
	if err := executor.DefaultRegistry.Register(iso); err != nil {
		t.Fatalf("register isolating stub: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(iso.id) })

	code, body := probeReadyz(t, s)
	if code != http.StatusOK {
		t.Fatalf("/readyz: want 200 once an isolating executor is registered, got %d (body=%v)", code, body)
	}
	if got := body["status"]; got != "ready" {
		t.Errorf("/readyz: want status=ready, got %v", got)
	}
}

// TestReadyz_PermissiveModeUnaffected guards the single-machine install: the
// new gate must never fire when host execution is allowed, or every laptop
// running `cloop ui` would report itself unready.
func TestReadyz_PermissiveModeUnaffected(t *testing.T) {
	wd := t.TempDir()
	initStateDB(t, wd)
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

// TestReadyz_StorageFailureStillReportedFirst: adding the executor gate must
// not mask the SQLite one. A hub with no state store is broken for reasons
// that have nothing to do with executors, and saying "executors" would send
// the operator to the wrong place.
func TestReadyz_StorageFailureStillReportedFirst(t *testing.T) {
	s := New(t.TempDir(), 0, "") // no state.db initialised

	enterStrictMode(t)

	code, body := probeReadyz(t, s)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz: want 503 with no state store, got %d (body=%v)", code, body)
	}
	if got, _ := body["check"].(string); got != "sqlite" {
		t.Errorf("/readyz: storage failure must be reported as the sqlite gate, got %v", body["check"])
	}
}

// errStub is returned by every dispatch method on the stub: it exists to be
// registered and counted as isolating, never to run anything.
var errStub = errors.New("readyz stub executor does not run workloads")

// readyzStubExecutor is a minimal isolating executor standing in for an
// enrolled remote agent.
type readyzStubExecutor struct{ id string }

func (s *readyzStubExecutor) ID() string   { return s.id }
func (s *readyzStubExecutor) Kind() string { return executor.KindRemoteAgent }
func (s *readyzStubExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationRemote}
}
func (s *readyzStubExecutor) HealthCheck(ctx context.Context) error { return nil }
func (s *readyzStubExecutor) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errStub
}
func (s *readyzStubExecutor) Status(ctx context.Context, id string) (executor.Status, error) {
	return executor.Status{}, errStub
}
func (s *readyzStubExecutor) Stream(ctx context.Context, id string) (<-chan executor.LogLine, error) {
	return nil, errStub
}
func (s *readyzStubExecutor) Signal(ctx context.Context, id string, sig executor.Signal) error {
	return errStub
}
