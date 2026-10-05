package ui

// The Event History panel through a live run, in the real bundle (Task 20384;
// testdata/history_scenarios.js). The property is about requests the bundle
// does not make, which no grep of the source can show: a live run's messages
// must leave the panel current without one GET /api/event-history, a
// reconnect must read only what it missed, and a page the user scrolled to is
// never read twice.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type historyScenario struct {
	Requests       []string `json:"requests"`
	Rendered       []string `json:"rendered"`
	Want           []string `json:"want"`
	Sockets        int      `json:"sockets"`
	AfterReconnect int      `json:"afterReconnect"`
	Error          string   `json:"error"`
}

// requestKinds names each event-history request by what it asked for.
func requestKinds(reqs []string) []string {
	out := make([]string, len(reqs))
	for i, q := range reqs {
		switch {
		case strings.Contains(q, "after="):
			out[i] = "after"
		case strings.Contains(q, "before="):
			out[i] = "before"
		case strings.Contains(q, "offset="):
			out[i] = "offset"
		default:
			out[i] = "newest"
		}
	}
	return out
}

func TestDashboard_EventHistoryStaysLiveWithoutRefetching(t *testing.T) {
	t.Parallel()
	results := runHistoryScenarios(t)

	cases := []struct {
		scenario string
		requests []string // by kind, in order
		before   string   // what the bundle did before the change
	}{{
		scenario: "live_run",
		requests: []string{"newest"},
		before:   "9 reads of the newest page: the first, then one per task's burst of messages",
	}, {
		scenario: "reconnect_after_missed_rows",
		requests: []string{"newest", "after"},
		before:   "6 reads, one per burst; the reconnect itself prompted none, so rows missed while down waited for the next burst",
	}, {
		scenario: "reconnect_without_missed_rows",
		requests: []string{"newest"},
		before:   "4 reads, one per burst",
	}, {
		scenario: "dropped_push",
		requests: []string{"newest", "after"},
		before:   "5 reads, one per burst",
	}, {
		scenario: "scrolled_history",
		requests: []string{"newest", "before", "before"},
		before:   "every burst re-read the top of the list as deep as it had been scrolled (limit = rows held)",
	}, {
		scenario: "sse_fallback",
		requests: []string{"newest"},
		before:   "4 reads: the first, then one per full-state frame's burst",
	}}
	if len(cases) != len(results) {
		t.Errorf("testdata/history_scenarios.js runs %d scenarios and this table asserts on %d", len(results), len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			got, ok := results[tc.scenario]
			if !ok {
				t.Fatalf("scenario %q produced no result", tc.scenario)
			}
			if got.Error != "" {
				t.Fatalf("scenario %q threw in the browser shim:\n%s", tc.scenario, got.Error)
			}
			if kinds := requestKinds(got.Requests); strings.Join(kinds, " ") != strings.Join(tc.requests, " ") {
				t.Errorf("event-history requests = %v (%v), want %v\n  before the change: %s",
					kinds, got.Requests, tc.requests, tc.before)
			}
			if len(got.Want) == 0 {
				t.Fatal("the scenario's journal is empty; it proves nothing")
			}
			if strings.Join(got.Rendered, " ") != strings.Join(got.Want, " ") {
				t.Errorf("the panel shows\n  %v\nwant the journal, newest first\n  %v", got.Rendered, got.Want)
			}
		})
	}

	if r := results["reconnect_after_missed_rows"]; r.Sockets != 2 || r.AfterReconnect != 2 {
		t.Errorf("reconnect_after_missed_rows: %d sockets, %d reads by the time the new socket settled; "+
			"want a second socket and the gap read made right after its sync point", r.Sockets, r.AfterReconnect)
	}
	if r := results["scrolled_history"]; len(r.Rendered) != 136 {
		t.Errorf("scrolled_history shows %d rows, want all 136: the pages scrolled to and the rows pushed since", len(r.Rendered))
	}
}

func runHistoryScenarios(t *testing.T) map[string]historyScenario {
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
		t.Fatal(err)
	}
	scenarios, err := filepath.Abs("testdata/history_scenarios.js")
	if err != nil {
		t.Fatal(err)
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
	var results map[string]historyScenario
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	return results
}
