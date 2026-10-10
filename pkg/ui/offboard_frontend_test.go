package ui

// The offboarding preview's stored-credentials section and its legal hold
// (Task 20400), driven through the real bundle: what the Legal hold box sends,
// and what the preview shows. See testdata/offboard_panel_scenarios.js.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type offboardPanelResult struct {
	Calls                int  `json:"calls"`
	DryRunSent           bool `json:"dry_run_sent"`
	KeepSent             bool `json:"keep_sent"`
	ListsSecret          bool `json:"lists_secret"`
	NamesSharedProject   bool `json:"names_shared_project"`
	ListsClaudeCopy      bool `json:"lists_claude_copy"`
	NamesMember          bool `json:"names_member"`
	NamesUnreachedMember bool `json:"names_unreached_member"`
	SaysDestroyed        bool `json:"says_destroyed"`
	SaysKept             bool `json:"says_kept"`
	RawMarkupInjected    bool `json:"raw_markup_injected"`
	EscapedNameShown     bool `json:"escaped_name_shown"`
	ButtonNamesHold      bool `json:"button_names_hold"`
}

func TestDashboard_OffboardPreviewShowsTheStoredFootprint(t *testing.T) {
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
	scenarios, err := filepath.Abs("testdata/offboard_panel_scenarios.js")
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
	var results map[string]json.RawMessage
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	if fatal, ok := results["fatal"]; ok {
		t.Fatalf("the scenarios threw: %s", fatal)
	}
	read := func(name string) offboardPanelResult {
		t.Helper()
		raw, ok := results[name]
		if !ok {
			t.Fatalf("the %s scenario did not report", name)
		}
		var r offboardPanelResult
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	got := read("destroy")
	if got.Calls == 0 || !got.DryRunSent {
		t.Fatalf("the preview did not ask the server for a dry run: %+v", got)
	}
	if got.KeepSent {
		t.Error("an unticked Legal hold box was sent as keep_credentials")
	}
	if !got.ListsSecret || !got.NamesSharedProject || !got.ListsClaudeCopy || !got.NamesMember {
		t.Errorf("the preview leaves part of the stored footprint out: %+v", got)
	}
	if !got.NamesUnreachedMember {
		t.Error("a hub member that could not be asked is not shown — its copy would survive unannounced")
	}
	if !got.SaysDestroyed || got.SaysKept {
		t.Errorf("without a hold the preview must say the secrets are destroyed: %+v", got)
	}
	if got.RawMarkupInjected || !got.EscapedNameShown {
		t.Errorf("a secret name reached the page unescaped: injected=%v escaped=%v",
			got.RawMarkupInjected, got.EscapedNameShown)
	}

	got = read("keep")
	if !got.KeepSent {
		t.Error("a ticked Legal hold box was not sent as keep_credentials")
	}
	if !got.SaysKept || got.SaysDestroyed || !got.ButtonNamesHold {
		t.Errorf("under a hold the preview must say what is kept, and the button must say so: %+v", got)
	}
}
