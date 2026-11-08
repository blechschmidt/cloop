package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// complete_task is what an agent calls, so it never opens a human review gate
// (Task 20477): the gate stays closed, and the answer says who approves it.
func TestCompleteTaskRefusesAReviewGate(t *testing.T) {
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	ps, err := state.Init(dir, "goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	gate := pm.NewHumanGate("Check the parser", "")
	gate.ID, gate.Priority = 2, 2
	ps.PMMode = true
	ps.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{{ID: 1, Title: "work", Priority: 1, Status: pm.TaskPending}, gate}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"complete_task","arguments":{"id":2}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"complete_task","arguments":{"id":1}}}` + "\n"
	var out strings.Builder
	if err := New(dir, nil, strings.NewReader(in), &out).Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "only a person approves") {
		t.Errorf("complete_task on a gate answered:\n%s", out.String())
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if g := st.Plan.TaskByID(2); !g.GateClosed() || g.Status != pm.TaskPending {
		t.Fatalf("complete_task opened the gate: %+v", g)
	}
	if w := st.Plan.TaskByID(1); w.Status != pm.TaskDone {
		t.Fatalf("complete_task on ordinary work = %s, want done", w.Status)
	}
}
