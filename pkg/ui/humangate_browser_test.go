package ui

// Browser gate for human review gates on the Tasks tab (Task 20477). See
// testdata/humangate_browser.js for what it drives and why a browser. Skips
// when Chrome or node is missing, like the others; humangate_api_test.go holds
// the hub's side.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

type humanGateRow struct {
	Gate      bool     `json:"gate"`
	Icon      string   `json:"icon"`
	Meta      string   `json:"meta"`
	Buttons   []string `json:"buttons"`
	Draggable bool     `json:"draggable"`
	Border    string   `json:"border"`
}

func (r *humanGateRow) offers(label string) bool {
	for _, b := range r.Buttons {
		if b == label {
			return true
		}
	}
	return false
}

func TestHumanReviewGates_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot press the buttons a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	t.Setenv(multiui.EnvRoot, t.TempDir())
	waiting := pm.NewHumanGate("Check the migration", "Look at the column types.")
	waiting.ID, waiting.Priority = 3, 3
	later := pm.NewHumanGate("Review the API", "")
	later.ID, later.Priority = 5, 5
	dir := setupProjectDir(t, "review gates in a browser", []*pm.Task{
		{ID: 1, Title: "Design the data model", Status: pm.TaskDone, Priority: 1},
		{ID: 2, Title: "Write the migration", Status: pm.TaskDone, Priority: 2},
		waiting,
		{ID: 4, Title: "Build the API", Status: pm.TaskPending, Priority: 4},
		later,
		// A task recorded done on a provider refusal, for the verdict buttons
		// that moved to deferred/ledger.js.
		{ID: 7, Title: "Write the docs", Status: pm.TaskDone, Priority: 9, Result: "You've hit your limit",
			Abort: &pm.TaskAbort{Class: "usage_limit", Reason: "subscription limit reached", Evidence: "You've hit your limit"}},
	})
	// The run stopped at gate 3.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.SetPaused(pausereason.NewForTask(pausereason.CodeApproval, "waiting for human review at gate #3: Check the migration", 3))
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, dir, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	args := []string{mustAbs(t, "testdata/humangate_browser.js"), chrome, ts.URL}
	if shots := os.Getenv("CLOOP_HUMANGATE_SHOTS"); shots != "" {
		args = append(args, shots)
	}
	out, err := exec.CommandContext(ctx, node, args...).Output()
	var got struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
		Waiting       *humanGateRow `json:"waiting"`
		Later         *humanGateRow `json:"later"`
		Added         *humanGateRow `json:"added"`
		Approved      *humanGateRow `json:"approved"`
		AddedToast    string        `json:"added_toast"`
		ApprovedToast string        `json:"approved_toast"`
		OrderBefore   []int         `json:"order_before"`
		OrderAfter    []int         `json:"order_after"`
		LedgerBefore  bool          `json:"ledger_before"`
		LedgerAfter   bool          `json:"ledger_after"`
		ReopenToast   string        `json:"reopen_toast"`
	}
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%s\nstderr:\n%s", err, jerr, out, stderr)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s\nraw:\n%s", got.Error.Message, out)
	}
	if got.Waiting == nil || got.Later == nil || got.Added == nil || got.Approved == nil {
		t.Fatalf("a scenario did not run:\n%s", out)
	}

	t.Run("a gate's row is drawn as a gate and can be dragged", func(t *testing.T) {
		for name, r := range map[string]*humanGateRow{"waiting": got.Waiting, "later": got.Later, "added": got.Added} {
			if !r.Gate || r.Icon != "⏸" || !strings.HasPrefix(r.Meta, "review gate · ") || r.Border != "dashed" {
				t.Errorf("%s gate row = %+v", name, *r)
			}
			if !r.Draggable {
				t.Errorf("%s gate cannot be dragged like a queued task", name)
			}
			for _, label := range []string{"Done", "Fail", "Split"} {
				if r.offers(label) {
					t.Errorf("%s gate offers %q, a task's button", name, label)
				}
			}
		}
	})

	t.Run("the gate the run stopped at offers Approve & continue", func(t *testing.T) {
		if got.Waiting.Meta != "review gate · waiting for review" || !got.Waiting.offers("Approve & continue") {
			t.Errorf("waiting gate row = %+v", *got.Waiting)
		}
		if got.Later.Meta != "review gate · the run stops here" || !got.Later.offers("Approve") || got.Later.offers("Approve & continue") {
			t.Errorf("later gate row = %+v", *got.Later)
		}
		if want := []int{3, 4, 5}; !sameOrder(got.OrderBefore, want) {
			t.Errorf("rows %v, want %v: the queue in the order it runs", got.OrderBefore, want)
		}
	})

	t.Run("+ Review gate adds one to the end and Approve opens it", func(t *testing.T) {
		if n := len(got.OrderAfter); n == 0 || got.OrderAfter[n-1] != 8 {
			t.Errorf("rows after adding %v, want the new gate last", got.OrderAfter)
		}
		if !strings.Contains(got.AddedToast, "Gate #8 added") {
			t.Errorf("adding toasted %q", got.AddedToast)
		}
		if got.Approved.Meta != "review gate · approved" || !got.Approved.offers("Reopen") || got.Approved.offers("Approve") {
			t.Errorf("approved gate row = %+v", *got.Approved)
		}
		if !strings.Contains(got.ApprovedToast, "Gate #8 approved") {
			t.Errorf("approving toasted %q", got.ApprovedToast)
		}
		st, err := state.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		if g := st.Plan.TaskByID(8); g == nil || !g.IsHumanGate() || !g.Approved || g.Status != pm.TaskDone {
			t.Errorf("stored gate 8 = %+v", g)
		}
		if g := st.Plan.TaskByID(3); !g.GateClosed() {
			t.Errorf("the gate the run stopped at was opened: %+v", g)
		}
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "task.gate_approve"}); err != nil || len(evs) != 1 {
			t.Errorf("task.gate_approve rows = %d, %v", len(evs), err)
		}
	})

	t.Run("Reopen on a refusal is fetched on its first press and still works", func(t *testing.T) {
		if got.LedgerBefore || !got.LedgerAfter {
			t.Errorf("ledger.js fetched before the press %v, after %v: it belongs off first paint and on demand",
				got.LedgerBefore, got.LedgerAfter)
		}
		if !strings.Contains(got.ReopenToast, "Task 7 reopened") {
			t.Errorf("Reopen toasted %q", got.ReopenToast)
		}
		st, err := state.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		if task := st.Plan.TaskByID(7); task.Status != pm.TaskPending {
			t.Errorf("task 7 after Reopen = %s, want pending", task.Status)
		}
	})
}
