package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type assistantScenario struct {
	Bubble *struct {
		Text  string `json:"text"`
		Error bool   `json:"error"`
	} `json:"bubble"`
	Toast  string `json:"toast"`
	Posted int    `json:"posted"`
	Error  string `json:"error"`
}

// TestDashboard_AssistantRefusals: the plan assistant's model call runs on the
// project's executor (Task 20442), so a request can be refused before its
// stream starts, with a JSON body. The bubble shows the reason, and a sandbox
// with no Claude login opens the credential dialog. See
// testdata/assistant_scenarios.js.
func TestDashboard_AssistantRefusals(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatal(err)
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatal(err)
	}
	scenarios, err := filepath.Abs("testdata/assistant_scenarios.js")
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
	var got map[string]assistantScenario
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	if f, ok := got["fatal"]; ok {
		t.Fatalf("the scenarios threw: %s", f.Error)
	}
	for name, want := range map[string]struct{ text, toast string }{
		"harness_refusal": {"No active grant gives the sandbox a Claude credential.",
			"Refused: this sandbox has no usable Claude credential"},
		"policy_refusal": {"executor: host execution is disabled by policy (executors.allow_host_process: false)", ""},
	} {
		r, ok := got[name]
		if !ok || r.Bubble == nil {
			t.Fatalf("scenario %s did not run or drew no answer:\n%s", name, out)
		}
		if r.Posted != 1 {
			t.Errorf("%s: posted %d question(s), want 1", name, r.Posted)
		}
		if r.Bubble.Text != want.text || !r.Bubble.Error || strings.Contains(r.Bubble.Text, `"code"`) {
			t.Errorf("%s: the answer reads %q (error %v), want the reason %q", name, r.Bubble.Text, r.Bubble.Error, want.text)
		}
		if want.toast != "" && r.Toast != want.toast {
			t.Errorf("%s: toast %q, want %q", name, r.Toast, want.toast)
		}
		if want.toast == "" && strings.Contains(r.Toast, "Claude credential") {
			t.Errorf("%s: a refusal that is not about a credential offered one: %q", name, r.Toast)
		}
	}
}
