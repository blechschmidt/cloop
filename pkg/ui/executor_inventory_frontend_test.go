package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type execInventoryResult struct {
	HTML  string `json:"html"`
	Error string `json:"error"`
}

// TestDashboard_ExecutorInventoryIsVisible drives the real bundle and checks
// that an edge device's build version and hardware reach the page.
//
// This runs the shipped JavaScript rather than grepping it because the defect
// being fixed was itself grep-invisible. The backend had been sending each
// device's full capability advertisement in every /api/executors response since
// remote executors existed — OS, arch, CPU count, memory, container runtimes,
// installed harnesses — and the panel rendered none of it: buildExecutorView
// passed it through as an opaque json.RawMessage and no renderer ever unpacked
// it. Every field was in the payload and absent from the screen. A gate
// asserting "the markup exists in 23-executors.js" would have passed the entire
// time the fields were invisible.
func TestDashboard_ExecutorInventoryIsVisible(t *testing.T) {
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
	scenarios, err := filepath.Abs("testdata/executor_inventory_scenarios.js")
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

	var results map[string]execInventoryResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, res := range results {
		if res.Error != "" {
			t.Fatalf("scenario %s threw: %s", name, res.Error)
		}
	}

	// ---- a device trailing the hub -------------------------------------
	stale := results["stale_device"].HTML
	if strings.TrimSpace(stale) == "" {
		t.Fatal("stale_device rendered nothing")
	}
	// Every advertised field, each named so a failure says which one vanished.
	for _, want := range []struct{ label, substr string }{
		{"build version", "v0.1.0"},
		{"platform", "linux/arm64"},
		{"cpu count", "4 cores"},
		{"memory", "7.7 GB"},
		{"first harness", "claude"},
		{"second harness", "codex"},
		{"container runtime", "podman"},
		{"workdir root (the sandbox boundary)", "/var/lib/cloop-executor/work"},
	} {
		if !strings.Contains(stale, want.substr) {
			t.Errorf("the %s (%q) is not on the page.\nrendered:\n%s",
				want.label, want.substr, stale)
		}
	}
	// The skew warning, and the remediation that actually works. The message
	// this replaces named `--upgrade` when no such flag existed.
	if !strings.Contains(stale, "materially trails") {
		t.Errorf("no skew warning for a device two minor releases behind:\n%s", stale)
	}
	if !strings.Contains(stale, AgentUpgradeCommand) {
		t.Errorf("the skew warning does not name %q:\n%s", AgentUpgradeCommand, stale)
	}

	// ---- a device on the hub's own build -------------------------------
	current := results["current_device"].HTML
	if !strings.Contains(current, "v0.3.0") {
		t.Errorf("a current device's build is not shown:\n%s", current)
	}
	if !strings.Contains(current, "8 cores") {
		t.Errorf("a current device's hardware is not shown:\n%s", current)
	}
	// Silence is the requirement here. A panel that warns about every device
	// trains operators to ignore the warning that matters.
	for _, forbidden := range []string{"materially trails", AgentUpgradeCommand} {
		if strings.Contains(current, forbidden) {
			t.Errorf("a device on the hub's own build was flagged with %q:\n%s",
				forbidden, current)
		}
	}

	// ---- an offline device --------------------------------------------
	offline := results["offline_device"].HTML
	if !strings.Contains(offline, "last known") {
		t.Errorf("stored inventory for an offline device is not marked as "+
			"last-known, so it reads as current:\n%s", offline)
	}
	if !strings.Contains(offline, "legacy") {
		t.Errorf("the legacy build placeholder is not surfaced:\n%s", offline)
	}

	// ---- a container backend -----------------------------------------
	container := results["container_backend"].HTML
	if strings.TrimSpace(container) == "" {
		t.Fatal("container_backend rendered nothing")
	}
	// It runs the hub's own binary, so there is no device build to report and
	// nothing to compare. Chips claiming otherwise would be fiction.
	for _, forbidden := range []string{"build ", "last known", AgentUpgradeCommand} {
		if strings.Contains(container, forbidden) {
			t.Errorf("a container backend rendered %q, which only applies to a "+
				"device with its own build:\n%s", forbidden, container)
		}
	}
}
