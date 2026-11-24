package e2e_test

// Tasks added on the hub while a device works are run too (Task 20516).
//
// A run on an edge device works through the copy of the plan it was sent. On
// the sgx-rust-attestation project a task added while the device worked on
// the one before it was in no plan the device had, so the device finished
// its plan, came back, and the project sat paused: "the run finished the plan
// it was sent, but 1 task here still has work left — added or reset on the
// hub while it was out", until someone pressed Run again.
//
// This runs it for real on loopback, in the hub-restart test's scene: a hub,
// a `cloop executor agent` whose work root the hub cannot see, and a
// stand-in `claude` that blocks on a FIFO. The run is started with one task;
// while its harness is blocked on the device, a second task is added through
// the API, as the dashboard adds it. Then the harness is released, and the
// hub has to start a second run for the second task by itself.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestE2EADeviceRunCarriesOnWithTasksAddedWhileItRan(t *testing.T) {
	s := newRestartScene(t, false)
	s.cloop(s.proj, "task", "add", "Write the report", "--no-ai", "--auto")
	s.startHub()
	s.startAgent()
	s.bind()
	idx := s.projectIdx(s.proj)

	if code, body := s.call("POST", fmt.Sprintf("/api/run?project_idx=%d", idx), nil); code != http.StatusOK {
		t.Fatalf("start the run = %d %v", code, body)
	}
	s.waitFor("the harness to be running on the device", 90*time.Second, func() bool {
		return s.stubStarts() == 1
	})
	s.assertListedRunning(s.proj, "with the first task running on the device")

	// While the device works on task 1, a second task is added on the hub.
	code, body := s.call("POST", fmt.Sprintf("/api/tasks?project_idx=%d", idx),
		map[string]any{"title": "Proofread the report", "description": "Fix the typos in the report."})
	if code != http.StatusOK {
		t.Fatalf("add a task while the run is out = %d %v", code, body)
	}
	if got := s.taskStatus(s.proj, 2); got != "pending" {
		t.Fatalf("task 2 is %q in the hub's copy, want pending", got)
	}

	s.releaseHarness(true)
	s.waitFor("task 1 to be done in the hub's copy", 90*time.Second, func() bool {
		return s.taskStatus(s.proj, 1) == "done"
	})
	// The hub starts a run for task 2 on its own: the harness starts again.
	s.waitFor("the hub to start a run for the task added while the first was out", 90*time.Second, func() bool {
		return s.stubStarts() == 2
	})
	s.assertListedRunning(s.proj, "with the added task running on the device")
	s.releaseHarness(true)
	s.waitFor("task 2 to be done in the hub's copy", 90*time.Second, func() bool {
		return s.taskStatus(s.proj, 2) == "done"
	})
	s.waitFor("the run's control-plane rows to be cleared", 60*time.Second, func() bool {
		return len(s.leftovers()) == 0
	})

	// Done, and nothing started a third time.
	if rows := s.query(s.proj, `SELECT value FROM metadata WHERE key = 'status'`); len(rows) != 1 || rows[0][0] != "complete" {
		reason := s.query(s.proj, `SELECT value FROM metadata WHERE key = 'pause_reason'`)
		t.Errorf("project status %v (%v), want complete", rows, reason)
	}
	if n := s.stubStarts(); n != 2 {
		t.Errorf("the harness was started %d times for two tasks", n)
	}

	// The journal says what the hub did, one row per run: the first names
	// the task it carries on with, the second records it done.
	results := s.query(s.proj, `SELECT message FROM events WHERE type = 'project_result' ORDER BY id`)
	if len(results) != 2 {
		t.Fatalf("project_result journal rows = %d, want one per run: %v", len(results), results)
	}
	if !strings.Contains(results[0][0], "#1 done") ||
		!strings.Contains(results[0][0], "(#2), so the hub starts another run for it") {
		t.Errorf("the first run's row does not say the hub carries on with task 2: %s", results[0][0])
	}
	if !strings.Contains(results[1][0], "#2 done") || strings.Contains(results[1][0], "starts another run") {
		t.Errorf("the second run's row: %s", results[1][0])
	}

	// And the trail records that a machine started the second run, and why.
	resumed := s.query(s.proj, `SELECT payload FROM audit_events WHERE event_type = 'run.cap_resumed'`)
	if len(resumed) != 1 {
		t.Fatalf("run.cap_resumed rows = %d, want 1", len(resumed))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(resumed[0][0]), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(payload["paused_detail"]), "task #2 was added or reset here while the run was out") {
		t.Errorf("run.cap_resumed records %v", payload)
	}
}
