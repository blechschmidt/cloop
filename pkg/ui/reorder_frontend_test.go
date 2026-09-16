package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// reorderScenario is one drag driven through the real bundle.
type reorderScenario struct {
	Error string `json:"error"`
	// Before is the rendered task order the user was looking at.
	Before []int `json:"before"`
	// Posted is the id list the drop handler sent, or nil if it sent nothing.
	Posted []int `json:"posted"`
	// After is the rendered order once the server's rewrite is applied.
	After []int `json:"after"`
	// DisabledHandles counts rows rendered without a usable drag handle.
	DisabledHandles int `json:"disabledHandles"`
}

func runReorderScenarios(t *testing.T) map[string]reorderScenario {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}

	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/reorder_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}

	cmd := exec.Command(node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var results map[string]reorderScenario
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, r := range results {
		if r.Error != "" {
			t.Fatalf("scenario %s threw: %s", name, r.Error)
		}
	}
	return results
}

func eqOrder(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The load-bearing test: a drag has to move the row to where the user dropped
// it, in the list the user was looking at.
func TestDashboard_DragReorderFollowsTheRenderedOrder(t *testing.T) {
	t.Parallel()

	results := runReorderScenarios(t)

	t.Run("plain queue", func(t *testing.T) {
		got := results["plain_queue_drag_to_top"]
		if !eqOrder(got.Before, []int{1, 2, 3}) {
			t.Fatalf("rendered order was %v, want [1 2 3]", got.Before)
		}
		if !eqOrder(got.Posted, []int{3, 1, 2}) {
			t.Errorf("drag posted %v, want [3 1 2]", got.Posted)
		}
		if !eqOrder(got.After, []int{3, 1, 2}) {
			t.Errorf("after the reorder the list reads %v, want [3 1 2]", got.After)
		}
	})

	// The regression. A pinned task renders first while sorting last by
	// priority, so the rendered list and a priority-only sort disagree. The old
	// handler indexed into the priority sort and produced the order that was
	// already on screen: the row visibly moved, snapped back, and no amount of
	// re-dragging helped.
	t.Run("pinned row at the head", func(t *testing.T) {
		got := results["pinned_head_drag_below_it"]
		if !eqOrder(got.Before, []int{3, 1, 2}) {
			t.Fatalf("rendered order was %v, want [3 1 2] — the pinned task leads", got.Before)
		}
		if got.Posted == nil {
			t.Fatal("dragging task 2 above task 1 sent no reorder at all")
		}
		if !eqOrder(got.After, []int{3, 2, 1}) {
			t.Errorf("after dragging 2 above 1 the list reads %v, want [3 2 1] — "+
				"the drop was computed against a list the user was not looking at",
				got.After)
		}
	})

	// The other half of the same mismatch, and the one that silently did damage:
	// dragging a row onto the pinned head is a position priorities cannot
	// express, and the old handler answered it by moving the task to the bottom
	// of the list. Dragged to the top, landed last, said nothing.
	t.Run("drag across the pin boundary is refused, not mangled", func(t *testing.T) {
		got := results["drag_across_the_pin_boundary"]
		if !eqOrder(got.Before, []int{3, 1, 2}) {
			t.Fatalf("rendered order was %v, want [3 1 2]", got.Before)
		}
		if got.Posted != nil {
			t.Errorf("dragging onto the pinned head posted %v — pinned tasks lead "+
				"the queue, so this move cannot be honoured and must not be "+
				"half-applied", got.Posted)
		}
		if !eqOrder(got.After, []int{3, 1, 2}) {
			t.Errorf("the list now reads %v, want it unchanged at [3 1 2] — the "+
				"refused drag moved the task anyway", got.After)
		}
	})

	// A running task has left the queue, so it is neither a source nor a target.
	t.Run("running row is not a drop target", func(t *testing.T) {
		got := results["drop_onto_running_row"]
		if !eqOrder(got.Before, []int{1, 2, 3}) {
			t.Fatalf("rendered order was %v, want [1 2 3] — the running task leads", got.Before)
		}
		if got.Posted != nil {
			t.Errorf("dropping onto the running row posted %v, want no request — "+
				"a task that is already executing has no place in the queue", got.Posted)
		}
	})

	// Completed rows are interleaved when "show completed" is on, and must not
	// end up in the queue that gets renumbered.
	t.Run("completed rows are excluded", func(t *testing.T) {
		got := results["completed_rows_are_not_in_the_queue"]
		if len(got.Before) != 3 {
			t.Fatalf("rendered %d rows with completed shown, want 3: %v", len(got.Before), got.Before)
		}
		if got.DisabledHandles != 1 {
			t.Errorf("%d rows rendered a disabled drag handle, want 1 — the "+
				"completed task must not offer a reorder it cannot honour",
				got.DisabledHandles)
		}
		if !eqOrder(got.Posted, []int{3, 2}) {
			t.Errorf("drag posted %v, want [3 2] — the completed task is history "+
				"and must not be renumbered", got.Posted)
		}
	})

	// A filter narrows what is on screen; it must not narrow what gets
	// rewritten, or the hidden rows silently change places with the visible
	// ones the next time anything renders.
	t.Run("filtered rows stay in the queue", func(t *testing.T) {
		got := results["filtered_view_keeps_hidden_tasks_in_the_queue"]
		if !eqOrder(got.Before, []int{4}) {
			t.Fatalf("the filtered view rendered %v, want just [4]", got.Before)
		}
		if !eqOrder(got.Posted, []int{1, 4, 2, 3}) {
			t.Errorf("drag posted %v, want [1 4 2 3] — every task that can run "+
				"stays in the queue, filtered or not", got.Posted)
		}
	})
}
