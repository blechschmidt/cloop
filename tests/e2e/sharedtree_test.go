package e2e_test

// A dashboard helper sent to a device while a run works there leaves the run's
// directory alone (Task 20517).
//
// On the sgx-rust-attestation project finished tasks reappeared, twice. A run
// was working through its plan on the sgx device when the operator opened the
// Requirements tab, which dispatches `cloop requirements validate` to the
// project's executor to read the spec file. The device prepared the project's
// directory for it as it would for a run, placing the hub's copy of the
// project there — which deletes the database it finds, the run's. The run's
// next look at its database found tasks the operator had added on the hub
// since it started. It logged them "added externally", worked through them,
// and came back with them as tasks it had made; the hub merged them in beside
// the originals, which were still pending and ran again.
//
// This replays that on loopback, in the hub-restart test's scene: a hub, a
// `cloop executor agent` whose work root the hub cannot see, and a stand-in
// `claude` that blocks on a FIFO. While the harness works on task 1, task 2
// is added on the hub and the spec file is read. Before the fix the read left
// the hub's copy of the project in the run's directory and its database gone,
// and the first run's journal came back without its start. Then the harness is
// let go, once per start, until the project settles: two tasks, two starts.
//
// CLOOP_E2E_AGENT_BIN runs the device on another cloop, for an A/B against an
// agent older than the rule: the hub's half alone has to keep it out of the
// run's directory.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestE2EAHelperBesideADeviceRunLeavesItsDirectoryAlone(t *testing.T) {
	s := newRestartScene(t, false)
	s.cloop(s.proj, "task", "add", "Fix the OutOfDateConfigurationNeeded issue", "--no-ai", "--auto")
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

	// While the device works on task 1, a task is added on the hub, and the
	// Requirements tab reads the spec file on the project's executor.
	code, body := s.call("POST", fmt.Sprintf("/api/tasks?project_idx=%d", idx),
		map[string]any{"title": "Add a GitHub Action to run an integration test against sgx-playground"})
	if code != http.StatusOK {
		t.Fatalf("add a task while the run is out = %d %v", code, body)
	}
	if code, body := s.call("POST", fmt.Sprintf("/api/requirements/spec/read?project_idx=%d", idx),
		map[string]any{}); code != http.StatusAccepted && code != http.StatusOK {
		t.Fatalf("read the spec file = %d %v", code, body)
	}
	s.waitFor("the spec file read to end on the device", 90*time.Second, func() bool {
		code, body := s.call("GET", fmt.Sprintf("/api/requirements/spec?project_idx=%d", idx), nil)
		return code == http.StatusOK && body["reading"] == false
	})
	// The run's directory on the device is as the run had it: its database,
	// holding the start of its journal, and the seed it was sent — not the
	// hub's copy of the project with the task added since.
	devDir := filepath.Join(s.root, "device", executor.DeviceWorkDir(s.proj))
	if seed, err := os.ReadFile(filepath.Join(devDir, ".cloop", "state.json")); err != nil {
		t.Fatalf("the run's seed on the device: %v", err)
	} else if strings.Contains(string(seed), "GitHub Action") {
		t.Fatal("the spec file read placed the hub's copy of the project, with the task added since, " +
			"in the directory the run works in")
	}
	if rows, err := s.tryQuery(devDir, `SELECT COUNT(*) FROM events WHERE type = 'session_started'`); err != nil ||
		len(rows) != 1 || rows[0][0] != "1" {
		t.Fatalf("after the spec file read the run's database on the device answers %v (%v): "+
			"it is no longer the run's", rows, err)
	}

	// Let every harness start finish until the project settles: two tasks,
	// each run once, and nothing left running.
	released := 0
	s.waitFor("the project to settle", 4*time.Minute, func() bool {
		if n := s.stubStarts(); n > released {
			s.releaseHarness(true)
			released++
			return false
		}
		if s.taskStatus(s.proj, 1) != "done" || s.taskStatus(s.proj, 2) != "done" {
			return false
		}
		return len(s.leftovers()) == 0
	})

	tasks := s.query(s.proj, `SELECT id, status, title FROM plan_tasks ORDER BY id`)
	if len(tasks) != 2 {
		t.Errorf("the plan holds %d tasks, want the 2 it was given: %v", len(tasks), tasks)
	}
	if n := s.stubStarts(); n != 2 {
		t.Errorf("the harness started %d times for two tasks", n)
	}
	if rows := s.query(s.proj, `SELECT message FROM events WHERE type = 'task_added_external'`); len(rows) != 0 {
		t.Errorf("the device's run took tasks for its own: %v", rows)
	}
	// Each run's journal came back whole, its start included.
	if rows := s.query(s.proj, `SELECT id FROM events WHERE type = 'session_started'`); len(rows) != 2 {
		t.Errorf("the journal holds %d run starts for two runs", len(rows))
	}
	if os.Getenv("CLOOP_E2E_AGENT_BIN") == "" && !strings.Contains(s.agentLog.String(), "as run ") {
		t.Errorf("the agent never said it started the read on the run's directory:\n%s", s.agentLog.String())
	}
}
