package ui

// The Active Sessions panel with a terminal's session beside a browser's
// (Task 20412), driven through the real dashboard bundle.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboard_TerminalSessionsIdleOnTheirOwnClock(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatal(err)
	}
	shim, _ := filepath.Abs("testdata/domshim.js")
	scenario, _ := filepath.Abs("testdata/sessions_kind_scenarios.js")
	cmd := exec.Command(node, scenario, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the scenario failed: %v\n%s", err, out)
	}
	var res struct {
		Rows        int    `json:"rows"`
		CLIIdle     string `json:"cli_idle"`
		BrowserIdle string `json:"browser_idle"`
		Policy      string `json:"policy"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(out, &res); err != nil || res.Error != "" {
		t.Fatalf("scenario output %s: %v %s", out, err, res.Error)
	}
	if res.Rows != 2 {
		t.Fatalf("rendered %d rows, want 2", res.Rows)
	}
	// Fifty minutes quiet: ten left on the terminal's one-hour clock, seven
	// hours on the browser's eight.
	if res.CLIIdle != "sec-ttl warn" {
		t.Errorf("the terminal's idle cell is %q, want it warned against its own one-hour clock", res.CLIIdle)
	}
	if res.BrowserIdle != "sec-ttl" {
		t.Errorf("the browser's idle cell is %q, want it plain against its eight-hour clock", res.BrowserIdle)
	}
	if !strings.Contains(res.Policy, "Terminal sessions") {
		t.Errorf("the policy line does not state the terminals' own clocks: %s", res.Policy)
	}
}
