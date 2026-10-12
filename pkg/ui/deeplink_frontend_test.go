package ui

// The dashboard link `cloop remote init` prints (Task 20417), driven through
// the real bundle: /?project=<path> opens that project once the list that
// indexes it has loaded, then drops the query.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type deepLinkResult struct {
	Opened   string   `json:"opened"`
	Replaced []string `json:"replaced"`
	Error    string   `json:"error"`
}

func TestDashboard_OpensTheProjectALinkNames(t *testing.T) {
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
	scenarios, err := filepath.Abs("testdata/deeplink_scenarios.js")
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
	var results map[string]deepLinkResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, r := range results {
		if r.Error != "" {
			t.Fatalf("scenario %s threw: %s", name, r.Error)
		}
	}
	if r := results["opensTheNamedProject"]; r.Opened != "beta" || len(r.Replaced) != 1 || r.Replaced[0] != "/" {
		t.Errorf("a link to beta opened %q and rewrote the address to %v", r.Opened, r.Replaced)
	}
	if r := results["ignoresAnUnknownProject"]; r.Opened != "" || len(r.Replaced) != 1 {
		t.Errorf("a link to no project opened %q and rewrote the address to %v", r.Opened, r.Replaced)
	}
	if r := results["noLink"]; r.Opened != "" || len(r.Replaced) != 0 {
		t.Errorf("without a link the dashboard opened %q and rewrote the address to %v", r.Opened, r.Replaced)
	}
}
