package e2e_test

// A task a device has finished reads done in its own details while the run
// goes on (Task 20518).
//
// On sgx-rust-attestation, task #21 was done on the sgx device at 23:37 UTC
// on 2026-11-23, and the run went on with another task. The task list showed
// #21 done. Its details, which the operator opened again and again, read the
// hub's own copy of the project, which says pending until the run ends: "task
// #21 was completed although still being in pending state".
//
// This replays it on loopback, in the hub-restart test's scene: a hub, a
// `cloop executor agent` whose work root the hub cannot see, and a stand-in
// `claude` that blocks on a FIFO. The run is started with two tasks. Task 1's
// harness is let go, and while task 2's is blocked on the device, task 1 has
// to read done in its details as it does in the list, with the hub's copy
// still saying pending. The device reports its plan every quarter minute, so
// the test takes about twenty seconds. Then task 2 is let go.

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestE2EATaskADeviceFinishedReadsDoneInItsDetails(t *testing.T) {
	s := newRestartScene(t, false)
	s.cloop(s.proj, "task", "add", "Investigate verification without an Intel API key", "--no-ai", "--auto")
	s.cloop(s.proj, "task", "add", "Fix the OutOfDateConfigurationNeeded issue", "--no-ai", "--auto")
	s.startHub()
	s.startAgent()
	s.bind()
	idx := s.projectIdx(s.proj)

	// listed is a task's status in the task list, details its own view.
	listed := func(id int) string {
		_, body := s.call("GET", fmt.Sprintf("/api/state?project_idx=%d", idx), nil)
		plan, _ := body["plan"].(map[string]any)
		tasks, _ := plan["tasks"].([]any)
		for _, raw := range tasks {
			if task, _ := raw.(map[string]any); task != nil && task["id"] == float64(id) {
				return fmt.Sprint(task["status"])
			}
		}
		return ""
	}
	details := func(id int) (int, map[string]any) {
		code, body := s.call("GET", fmt.Sprintf("/api/tasks/%d/details?project_idx=%d", id, idx), nil)
		task, _ := body["task"].(map[string]any)
		return code, task
	}

	if code, body := s.call("POST", fmt.Sprintf("/api/run?project_idx=%d", idx), nil); code != http.StatusOK {
		t.Fatalf("start the run = %d %v", code, body)
	}
	s.waitFor("the harness to be running task 1 on the device", 90*time.Second, func() bool {
		return s.stubStarts() == 1
	})
	s.waitFor("task 1 to read in progress in the task list", 60*time.Second, func() bool {
		return listed(1) == "in_progress"
	})
	if code, task := details(1); code != http.StatusOK || task["status"] != "in_progress" {
		t.Errorf("while the device works on task 1 its details = HTTP %d, status %v; the list shows it in progress",
			code, task["status"])
	}

	s.releaseHarness(true)
	s.waitFor("the harness to be running task 2 on the device", 90*time.Second, func() bool {
		return s.stubStarts() == 2
	})
	s.waitFor("task 1 to read done in the task list", 60*time.Second, func() bool {
		return listed(1) == "done"
	})
	if got := s.taskStatus(s.proj, 1); got != "pending" {
		t.Fatalf("task 1 is %q in the hub's copy; this test means something only while the run is out", got)
	}
	code, task := details(1)
	if code != http.StatusOK || task["status"] != "done" || task["result"] == nil || task["result"] == "" ||
		task["completed_at"] == nil {
		t.Errorf("task 1 is done on the device and in the list, and its details = HTTP %d, status %v, "+
			"result %v, completed %v", code, task["status"], task["result"], task["completed_at"])
	}
	if code, task := details(2); code != http.StatusOK || task["status"] != "in_progress" {
		t.Errorf("task 2's details = HTTP %d, status %v, while the device works on it", code, task["status"])
	}

	s.releaseHarness(true)
	s.waitFor("task 2 to be done in the hub's copy", 90*time.Second, func() bool {
		return s.taskStatus(s.proj, 2) == "done"
	})
	s.waitFor("the run's control-plane rows to be cleared", 60*time.Second, func() bool {
		return len(s.leftovers()) == 0
	})
	// Written down now, and every view agrees with the record.
	for _, id := range []int{1, 2} {
		if code, task := details(id); code != http.StatusOK || task["status"] != "done" || s.taskStatus(s.proj, id) != "done" {
			t.Errorf("after the run task %d's details = HTTP %d, status %v; the hub's copy says %q",
				id, code, task["status"], s.taskStatus(s.proj, id))
		}
	}
	if n := s.stubStarts(); n != 2 {
		t.Errorf("the harness was started %d times for two tasks", n)
	}
}
