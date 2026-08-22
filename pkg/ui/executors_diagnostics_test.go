package ui

// Cover for the "surface those diagnostics" half of Task 20170.
//
// A diagnostic that only exists in a startup log line is one nobody reads.
// The Executors tab is where an operator goes when a run will not start, so
// GET /api/executors has to carry both the per-driver reconciliation record
// and the readiness verdict — including for a driver that failed to register,
// which has no registry entry and no executors-table row and was therefore
// completely invisible before this task.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/reconcile"
)

// executorsPayload is the subset of the response these tests assert on.
type executorsPayload struct {
	Executors []struct {
		ID                   string `json:"id"`
		Registered           bool   `json:"registered"`
		ReconcileStatus      string `json:"reconcile_status"`
		ReconcileMessage     string `json:"reconcile_message"`
		ReconcileRemediation string `json:"reconcile_remediation"`
	} `json:"executors"`
	Reconciliation *struct {
		Diagnostics []reconcile.Diagnostic `json:"diagnostics"`
		Problems    int                    `json:"problems"`
	} `json:"reconciliation"`
	Ready          bool   `json:"ready"`
	NotReadyReason string `json:"not_ready_reason"`
	Remediation    string `json:"remediation"`
}

func getExecutors(t *testing.T, s *Server) executorsPayload {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/executors", nil)
	rr := httptest.NewRecorder()
	s.handleExecutorsList(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/executors: want 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var out executorsPayload
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET /api/executors: invalid JSON: %v (body=%s)", err, rr.Body.String())
	}
	return out
}

// publishDiagnostic installs a reconciliation report describing a container
// driver that could not be built, and restores the previous state after.
//
// Going through reconcile.FromConfig would need a real (broken) container
// runtime on PATH; what is under test here is the plumbing from the report to
// the HTTP response, and pkg/executor/reconcile already pins down that a
// missing runtime produces exactly this diagnostic.
func publishFailedDiagnostic(t *testing.T, id string) {
	t.Helper()
	reconcile.PublishForTest(reconcile.Report{
		Dir:          t.TempDir(),
		ReconciledAt: time.Now(),
		StrictMode:   !executor.HostExecutionAllowed(),
		Diagnostics: []reconcile.Diagnostic{{
			ID:          id,
			Kind:        executor.KindContainer,
			Status:      reconcile.StatusFailed,
			Isolating:   true,
			Message:     "could not be registered: no container runtime found",
			Remediation: "install a container runtime (podman or docker) on the hub host",
			CheckedAt:   time.Now(),
		}},
	})
	t.Cleanup(reconcile.ResetForTest)
}

// TestExecutorsAPI_SurfacesFailedDriverThatNeverRegistered is the core case:
// a configured executor that failed to build has no registry entry, so
// without the reconciliation report the panel showed nothing at all and the
// operator had no way to tell that their config had even been read.
func TestExecutorsAPI_SurfacesFailedDriverThatNeverRegistered(t *testing.T) {
	wd := t.TempDir()
	initStateDB(t, wd)
	s := New(wd, 0, "")
	publishFailedDiagnostic(t, "sandbox")

	got := getExecutors(t, s)

	if got.Reconciliation == nil {
		t.Fatal("expected the reconciliation report in the response")
	}
	if got.Reconciliation.Problems != 1 {
		t.Errorf("expected 1 problem, got %d", got.Reconciliation.Problems)
	}
	if len(got.Reconciliation.Diagnostics) != 1 || got.Reconciliation.Diagnostics[0].ID != "sandbox" {
		t.Fatalf("expected the sandbox diagnostic, got %+v", got.Reconciliation.Diagnostics)
	}

	// And it must appear as a card, or the panel silently omits the one
	// executor the operator is looking for.
	var found bool
	for _, ex := range got.Executors {
		if ex.ID != "sandbox" {
			continue
		}
		found = true
		if ex.Registered {
			t.Error("a driver that failed to build must not be reported as registered")
		}
		if ex.ReconcileStatus != string(reconcile.StatusFailed) {
			t.Errorf("want reconcile_status=failed, got %q", ex.ReconcileStatus)
		}
		if ex.ReconcileRemediation == "" {
			t.Error("the card must carry the remediation, not just the failure")
		}
	}
	if !found {
		ids := make([]string, 0, len(got.Executors))
		for _, ex := range got.Executors {
			ids = append(ids, ex.ID)
		}
		t.Fatalf("failed executor absent from the card list; got %v", ids)
	}
}

// TestExecutorsAPI_ReportsNotReadyVerdict: the panel shows the same verdict
// /readyz does, so an operator and an orchestrator never disagree about
// whether the hub can run anything.
func TestExecutorsAPI_ReportsNotReadyVerdict(t *testing.T) {
	wd := t.TempDir()
	initStateDB(t, wd)
	s := New(wd, 0, "")
	enterStrictMode(t)
	if len(executor.IsolatedIDs()) > 0 {
		t.Skip("another test left an isolating executor in the default registry")
	}

	got := getExecutors(t, s)
	if got.Ready {
		t.Fatal("expected ready=false under strict mode with no isolating executor")
	}
	if got.NotReadyReason == "" {
		t.Error("expected a not_ready_reason")
	}
	if got.Remediation == "" {
		t.Error("expected a remediation alongside the not-ready verdict")
	}
}

// TestExecutorsAPI_ReadyInPermissiveMode guards the common case: a laptop
// install must not be told it is not ready.
func TestExecutorsAPI_ReadyInPermissiveMode(t *testing.T) {
	wd := t.TempDir()
	initStateDB(t, wd)
	s := New(wd, 0, "")
	prev := executor.SetAllowHostExecution(true)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })

	got := getExecutors(t, s)
	if !got.Ready {
		t.Fatalf("expected ready=true in permissive mode, got reason %q", got.NotReadyReason)
	}
}
