package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type bootScenario struct {
	Requests []string `json:"requests"`
	Sockets  int      `json:"sockets"`
	Error    string   `json:"error"`
}

// TestDashboard_FirstPaintDoesNotFetchProjectState pins the boot request order.
//
// The landing page is the projects list, and it was gated behind a /api/state
// download it did not use: the probe ran against the hub's own WorkDir, which
// for this repository is a 448-task project serialising to 734 KB, and in
// multi-project mode the response body was discarded without being read. The
// user waited for it anyway, because /api/projects was issued from inside its
// .then() (Task 20280).
//
// Driven through the real bundle rather than grepped, because both halves of
// the property — the order of the two requests, and which branch consumes a
// body — are behaviour that text matching cannot express.
func TestDashboard_FirstPaintDoesNotFetchProjectState(t *testing.T) {
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
	scenarios, err := filepath.Abs("testdata/boot_scenarios.js")
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

	var results map[string]bootScenario
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}

	multi, ok := results["multi"]
	if !ok {
		t.Fatal("multi-project scenario produced no result")
	}
	if multi.Error != "" {
		t.Fatalf("multi-project scenario threw:\n%s", multi.Error)
	}

	// The whole point: nothing on the landing path may pull a project's state
	// document. Opening a project reconnects the WebSocket scoped to it and
	// the connect burst carries that state.
	for _, u := range multi.Requests {
		if strings.HasPrefix(u, "/api/state") {
			t.Errorf("first paint requested %q in multi-project mode.\n"+
				"That document is the hub's own project — 734 KB for this "+
				"repository — and the landing page does not render it.\n"+
				"full request order: %v", u, multi.Requests)
		}
	}

	// And the roster must be the first thing asked for, since it is both the
	// authentication probe and the data the landing page draws.
	if len(multi.Requests) == 0 {
		t.Fatal("first paint issued no requests at all")
	}
	if !strings.HasPrefix(multi.Requests[0], "/api/projects") {
		t.Errorf("first request was %q, want /api/projects — anything ahead of "+
			"it delays the landing page.\nfull request order: %v",
			multi.Requests[0], multi.Requests)
	}

	// And exactly once. /api/projects is the hub's most expensive read — it
	// opens every registered project's database in series — so the boot path
	// asking for it twice doubled the cost of the landing page. It did:
	// checkAuthAndInit fetched the roster and then switchTab('projects') sent
	// loadProjects() to fetch the same document again.
	roster := 0
	for _, u := range multi.Requests {
		if strings.HasPrefix(u, "/api/projects") {
			roster++
		}
	}
	if roster != 1 {
		t.Errorf("first paint requested /api/projects %d times, want 1.\n"+
			"full request order: %v", roster, multi.Requests)
	}

	// Single-project mode has no roster to land on and renders the Overview
	// directly, so there the state document is genuinely needed. Asserting it
	// keeps the fix from becoming "never fetch state", which would leave that
	// mode with a permanently empty dashboard.
	single, ok := results["single"]
	if !ok {
		t.Fatal("single-project scenario produced no result")
	}
	if single.Error != "" {
		t.Fatalf("single-project scenario threw:\n%s", single.Error)
	}
	found := false
	for _, u := range single.Requests {
		if strings.HasPrefix(u, "/api/state") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("single-project mode never fetched /api/state, so its Overview "+
			"would stay empty.\nfull request order: %v", single.Requests)
	}
}
