package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// PATCH /tasks/{id} gives a human review gate's status its own meaning (Task
// 20477): done approves it, pending closes it again, and a status no gate
// takes is refused without touching the gate.
func TestPatchTaskGateRules(t *testing.T) {
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	ps, err := state.Init(dir, "goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	gate := pm.NewHumanGate("", "")
	gate.ID, gate.Priority = 1, 1
	ps.PMMode = true
	ps.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{gate}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	s := New(dir, 0, "")
	patch := func(body string) int {
		req := httptest.NewRequest(http.MethodPatch, "/tasks/1", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("id", "1")
		rr := httptest.NewRecorder()
		s.handlePatchTask(rr, req)
		return rr.Code
	}
	loadGate := func() *pm.Task {
		st, err := state.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		return st.Plan.TaskByID(1)
	}

	if code := patch(`{"status":"in_progress"}`); code != http.StatusBadRequest {
		t.Errorf("in_progress on a gate = %d, want 400", code)
	}
	if g := loadGate(); g.Status != pm.TaskPending {
		t.Fatalf("a refused status reached the gate: %s", g.Status)
	}
	if code := patch(`{"status":"done"}`); code != http.StatusOK {
		t.Fatalf("done on a gate = %d", code)
	}
	if g := loadGate(); !g.Approved || g.Status != pm.TaskDone {
		t.Fatalf("done did not approve the gate: %+v", g)
	}
	if code := patch(`{"status":"pending"}`); code != http.StatusOK {
		t.Fatalf("pending on a gate = %d", code)
	}
	if g := loadGate(); g.Approved || !g.GateClosed() {
		t.Fatalf("pending did not close the gate: %+v", g)
	}
}
