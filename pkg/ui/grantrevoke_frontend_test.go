package ui

// The Secrets panel's grant revocation, driven through the real dashboard
// bundle (Task 20403): what the confirmation tells the operator about the
// workloads holding the grant, and what the result tells them each did.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type grantRevokeScenario struct {
	Prompt       string `json:"prompt"`
	HoldersAsked int    `json:"holdersAsked"`
	Deletes      int    `json:"deletes"`
	Result       string `json:"result"`
	ResultShown  bool   `json:"resultShown"`
	Toast        string `json:"toast"`
	Error        string `json:"error"`
}

func runGrantRevokeScenarios(t *testing.T) map[string]grantRevokeScenario {
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
	scenarios, err := filepath.Abs("testdata/grantrevoke_scenarios.js")
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
	var results map[string]grantRevokeScenario
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

// TestDashboard_GrantRevokeConfirmationAndResult: before revoking, the
// operator is told how many running workloads hold the grant, which hold it in
// their environment — and that the containers among them will be terminated
// while the others keep their copy — and afterwards what each holder did.
func TestDashboard_GrantRevokeConfirmationAndResult(t *testing.T) {
	results := runGrantRevokeScenarios(t)

	r := results["confirm_names_the_holders_and_the_result_lists_them"]
	if r.HoldersAsked != 1 || r.Deletes != 1 {
		t.Fatalf("holders asked %d times, revocations sent %d; want one each", r.HoldersAsked, r.Deletes)
	}
	for _, want := range []string{
		"3 running workload(s) hold it", "2 hold it in their environment", "GIT_CONFIG_GLOBAL", "GITHUB_TOKEN",
		"1 of them, container or Kubernetes sandboxes, will be terminated", "The other 1 keep their copy",
		"1 were taken over from a hub process that stopped",
	} {
		if !strings.Contains(r.Prompt, want) {
			t.Errorf("the confirmation does not say %q:\n%s", want, r.Prompt)
		}
	}
	if !r.ResultShown {
		t.Fatal("the per-holder result was not shown")
	}
	for _, want := range []string{"ctr-1", "edge-1", "3 file(s) removed", "1 workload(s) terminated",
		"variables dropped from its copy: GITHUB_TOKEN", "protocol v18"} {
		if !strings.Contains(r.Result, want) {
			t.Errorf("the result does not show %q:\n%s", want, r.Result)
		}
	}
	if !strings.Contains(r.Toast, "taken back") {
		t.Errorf("the toast is %q, not the server's note", r.Toast)
	}

	if d := results["declining_sends_no_revocation"]; d.Deletes != 0 {
		t.Errorf("declining the confirmation still revoked: %d request(s)", d.Deletes)
	}
	if n := results["nobody_holding_it_is_said"]; !strings.Contains(n.Prompt, "No running workload holds it") || n.Deletes != 1 {
		t.Errorf("an unheld grant's confirmation = %q (deletes %d)", n.Prompt, n.Deletes)
	}
	e := results["an_egress_grant_asks_for_no_holders"]
	if e.HoldersAsked != 0 || e.Deletes != 1 || !strings.Contains(e.Prompt, "egress proxy sessions") {
		t.Errorf("egress revoke = %+v", e)
	}
}
