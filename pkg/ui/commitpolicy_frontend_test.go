package ui

// The Overview's "done means committed" badges (Task 20370), driven through
// the real dashboard bundle against testdata/domshim.js.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type commitBadges struct {
	Committed string `json:"committed"`
	Pushed    string `json:"pushed"`
}

type commitPolicyResult struct {
	Off        *commitBadges `json:"off"`
	Committed  *commitBadges `json:"committed"`
	Pushed     *commitBadges `json:"pushed"`
	Remembered *commitBadges `json:"remembered"`
	After      *commitBadges `json:"after"`
	Posts      []string      `json:"posts"`
	Error      string        `json:"error"`
}

func TestDashboard_CommitPolicyBadges(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	shim, _ := filepath.Abs("testdata/domshim.js")
	scenarios, _ := filepath.Abs("testdata/commit_policy_scenarios.js")
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
	var results map[string]commitPolicyResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, r := range results {
		if r.Error != "" {
			t.Fatalf("scenario %s threw: %s", name, r.Error)
		}
	}

	want := func(what string, got *commitBadges, committed, pushed string) {
		t.Helper()
		if got == nil || got.Committed != committed || got.Pushed != pushed {
			t.Errorf("%s: badges = %+v, want committed %s, pushed %s", what, got, committed, pushed)
		}
	}
	f := results["badges_follow_the_policy"]
	want("a project that never set it", f.Off, "off", "off")
	want("committed", f.Committed, "on", "off")
	want("committed and pushed", f.Pushed, "on", "on")
	want("off with pushed remembered", f.Remembered, "off", "off")

	p := results["pushed_badge_posts_and_applies_the_answer"]
	if len(p.Posts) != 1 || p.Posts[0] != `{"flag":"require_pushed","value":true}` {
		t.Errorf("posts = %q", p.Posts)
	}
	want("after the hub answered", p.After, "on", "on")
}
