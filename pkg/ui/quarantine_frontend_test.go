package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDashboard_QuarantineIsShownInTaskDetails runs the shipped bundle and
// checks that a task quarantined as a suspected node killer says so in its
// details (Task 20391): how many distinct executors went down under it, each
// one and when, and what releases it — escaped, since an executor id is
// operator-chosen text.
func TestDashboard_QuarantineIsShownInTaskDetails(t *testing.T) {
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
	scenarios, _ := filepath.Abs("testdata/quarantine_scenarios.js")
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
	var results map[string]struct {
		HTML  string `json:"html"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}

	suspect := results["suspect"]
	if suspect.Error != "" {
		t.Fatalf("the suspect scenario threw:\n%s", suspect.Error)
	}
	for _, want := range []struct{ needle, why string }{
		{"Suspected node killer", "the section must be there"},
		{"2 executors went unreachable", "distinct executors are counted, not losses (sgx went down twice)"},
		{"<code>sgx</code>", "each lost node must be named"},
		{"edge-&lt;b&gt;2&lt;/b&gt;", "an executor id must be escaped, not rendered as markup"},
		{"Reset it to pending", "the section must say what releases the task"},
	} {
		if !strings.Contains(suspect.HTML, want.needle) {
			t.Errorf("task details missing %q — %s:\n%s", want.needle, want.why, suspect.HTML)
		}
	}
	if strings.Contains(suspect.HTML, "<b>2</b>") {
		t.Error("an executor id reached the page as markup")
	}

	ordinary := results["ordinary"]
	if ordinary.Error != "" {
		t.Fatalf("the control scenario threw:\n%s", ordinary.Error)
	}
	if ordinary.HTML == "" || strings.Contains(ordinary.HTML, "Suspected node killer") {
		t.Errorf("an ordinary failed task's details are wrong:\n%s", ordinary.HTML)
	}
}
