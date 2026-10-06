package ui

// The "running build X, N builds behind this hub" note, its one-shot adoption
// and the Follow New Builds badge (Task 20389), driven through the real
// dashboard bundle against testdata/domshim.js.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type runBuildNote struct {
	Shown bool   `json:"shown"`
	HTML  string `json:"html"`
}

type runBuildNotes struct {
	Overview runBuildNote `json:"overview"`
	Tasks    runBuildNote `json:"tasks"`
	Error    string       `json:"error"`
}

func TestDashboard_RunBuildNote(t *testing.T) {
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
	scenarios, _ := filepath.Abs("testdata/run_build_scenarios.js")
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
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	decode := func(name string, v any) {
		t.Helper()
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw[name], &e)
		if e.Error != "" {
			t.Fatalf("scenario %s threw: %s", name, e.Error)
		}
		if err := json.Unmarshal(raw[name], v); err != nil {
			t.Fatalf("scenario %s: %v", name, err)
		}
	}
	const lagText = "Running build dev+g4e35bf6, 132 builds behind this hub"

	var lag struct {
		Lagging runBuildNotes `json:"lagging"`
		Level   runBuildNotes `json:"level"`
	}
	decode("lagging_then_level", &lag)
	if o := lag.Lagging.Overview; !o.Shown || !strings.Contains(o.HTML, lagText) || !strings.Contains(o.HTML, "adoptBuild()") {
		t.Errorf("Overview, lagging run: %+v", o)
	}
	if tb := lag.Lagging.Tasks; !tb.Shown || !strings.Contains(tb.HTML, lagText) || strings.Contains(tb.HTML, "<button") {
		t.Errorf("Tasks run bar, lagging run: %+v", tb)
	}
	if lag.Level.Overview.Shown || lag.Level.Tasks.Shown {
		t.Errorf("a run level with the hub is still named: %+v", lag.Level)
	}

	var pending runBuildNotes
	decode("request_pending", &pending)
	if o := pending.Overview; !strings.Contains(o.HTML, "adoption requested") || strings.Contains(o.HTML, "<button") {
		t.Errorf("a pending request: %+v", o)
	}

	var device runBuildNotes
	decode("device_run", &device)
	if o := device.Overview; !strings.Contains(o.HTML, "remote executor keeps its own upgrade path") || strings.Contains(o.HTML, "<button") {
		t.Errorf("a device run: %+v", o)
	}

	var viewer runBuildNotes
	decode("viewer", &viewer)
	if o := viewer.Overview; !o.Shown || strings.Contains(o.HTML, "<button") {
		t.Errorf("a viewer: %+v; want the note without the action", o)
	}

	var posts struct {
		Posts []string `json:"posts"`
	}
	decode("adopt_posts", &posts)
	if len(posts.Posts) != 1 || posts.Posts[0] != "POST" {
		t.Errorf("adopt button requests = %v; want one POST", posts.Posts)
	}

	var esc runBuildNotes
	decode("escaped", &esc)
	if strings.Contains(esc.Overview.HTML, "<img") || strings.Contains(esc.Tasks.HTML, "<img") {
		t.Errorf("a build version was rendered as markup: %+v", esc)
	}

	var follow struct {
		Off   string   `json:"off"`
		On    string   `json:"on"`
		Posts []string `json:"posts"`
	}
	decode("follow_badge", &follow)
	if follow.Off != "off" || follow.On != "on" {
		t.Errorf("Follow New Builds badge = %s then %s; want off then on", follow.Off, follow.On)
	}
	if len(follow.Posts) != 1 || follow.Posts[0] != `{"flag":"follow_builds","value":false}` {
		t.Errorf("Follow New Builds posts = %q", follow.Posts)
	}
}
