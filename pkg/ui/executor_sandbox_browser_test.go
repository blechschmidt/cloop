package ui

// Browser gate for the per-executor Sandbox panel (Task 20307).
//
// The task asks that sandbox configuration be performable *through the UI*. That
// is a claim about a form, and the honest test of a claim about a form is to fill
// it in — against a real hub, with a real control-plane database behind it.
//
// Why not testdata/domshim.js, which every other frontend gate in this package
// uses. The shim runs the real bundle and would answer "did the page call the
// right endpoint". It cannot answer the two questions this panel turns on:
//
//   - whether the container fields are reachable. They sit behind a
//     `style.display` the mode selector drives, and the shim models no layout, so
//     a querySelector hit reports them present whether or not a user could ever
//     see or type into them. Task 20300 is the standing reminder that measuring
//     visibility without a layout engine reports a clean number on exactly the
//     broken page.
//   - whether a real `change` on a real <select> reaches the handler. The
//     selector is wired with an inline onchange and the bundle lives in an IIFE,
//     so a handler that was not exported onto window is a silent no-op — the bug
//     class of Tasks 20033 and 20065, and one a shim that calls the function
//     directly cannot reproduce.
//
// It skips when Chrome or node is missing, which is the normal case in CI: the
// assertions gate a developer box and any runner that has a browser, never a
// source of red builds on one that does not.

import (
	"encoding/json"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// sandboxPanelResult mirrors the JSON testdata/sandbox_browser.js prints.
type sandboxPanelResult struct {
	// container_fields_follow_the_mode
	HiddenAtFirst     bool `json:"hidden_at_first"`
	ShownForContainer bool `json:"shown_for_container"`
	RuntimeTypable    bool `json:"runtime_typable"`
	EngineTypable     bool `json:"engine_typable"`
	HiddenForHost     bool `json:"hidden_for_host"`

	// save_persists_container_mode
	EngineSet     string `json:"engine_set"`
	RuntimeSet    string `json:"runtime_set"`
	ImageSet      string `json:"image_set"`
	DialogClosed  bool   `json:"dialog_closed"`
	StoredMode    string `json:"stored_mode"`
	StoredEngine  string `json:"stored_engine"`
	StoredRuntime string `json:"stored_runtime"`
	StoredImage   string `json:"stored_image"`
	Configured    bool   `json:"configured"`
	SetBy         string `json:"set_by"`

	// reopen_shows_saved_values
	Mode          string `json:"mode"`
	Engine        string `json:"engine"`
	Runtime       string `json:"runtime"`
	Image         string `json:"image"`
	FieldsVisible bool   `json:"fields_visible"`

	// rejected_runtime_changes_nothing
	DialogStillOpen bool `json:"dialog_still_open"`

	// error
	Message string `json:"message"`
}

const sandboxPanelExecutorID = "edge-browser-1"

// TestExecutorSandboxPanel_InBrowser is the whole gate; the subtests read from
// the single browser run it performs, because launching Chrome and booting the
// dashboard costs seconds and every scenario shares that setup.
func TestExecutorSandboxPanel_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot measure a panel a user can actually see")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	dir := setupProjectDir(t, "sandbox panel", nil)

	// A real enrolled device, seeded into the control plane so the fleet view
	// reports it as kind=remote — which is the only kind whose sandbox mode this
	// panel governs, and the only kind whose card offers the button.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	if err := db.UpsertExecutor(statedb.ExecutorRow{
		ID:        sandboxPanelExecutorID,
		Name:      "edge-browser-1",
		Kind:      executor.KindRemoteAgent,
		Status:    statedb.ExecutorStatusOffline,
		CreatedAt: time.Now(),
	}); err != nil {
		_ = db.Close()
		t.Fatalf("seed executor row: %v", err)
	}
	_ = db.Close()

	// The real dashboard and the real API. Nothing is stubbed: the point of this
	// test is that the form drives the endpoint that writes the row the dispatch
	// path reads.
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	cmd := exec.Command(node, mustAbs(t, "testdata/sandbox_browser.js"),
		chrome, ts.URL, sandboxPanelExecutorID)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var got map[string]sandboxPanelResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if e, ok := got["error"]; ok {
		t.Fatalf("the driver reported an error: %s\nraw:\n%s", e.Message, out)
	}
	// A scenario the driver never reached leaves a zero value, and several of the
	// assertions below would pass on one by accident.
	for _, name := range []string{
		"container_fields_follow_the_mode", "save_persists_container_mode",
		"reopen_shows_saved_values", "rejected_runtime_changes_nothing",
	} {
		if _, ok := got[name]; !ok {
			t.Fatalf("scenario %q did not run:\n%s", name, out)
		}
	}

	t.Run("the container fields appear with the mode and not before", func(t *testing.T) {
		r := got["container_fields_follow_the_mode"]
		if !r.HiddenAtFirst {
			t.Error("the container fields are visible on an unconfigured executor — the engine " +
				"and runtime mean nothing for host execution, and showing them invites an " +
				"admin to set a value that is then discarded")
		}
		if !r.ShownForContainer {
			t.Fatal("selecting container mode did not reveal the container fields — with them " +
				"hidden there is no way to choose a runtime through the UI at all, which is " +
				"the capability this task exists to add")
		}
		// The two a user actually has to reach.
		if !r.RuntimeTypable {
			t.Error("the runtime field is not visible in container mode")
		}
		if !r.EngineTypable {
			t.Error("the engine selector is not visible in container mode")
		}
		if !r.HiddenForHost {
			t.Error("switching back to host left the container fields on screen")
		}
	})

	t.Run("saving the form writes the configuration the hub will dispatch with", func(t *testing.T) {
		r := got["save_persists_container_mode"]
		if r.EngineSet != "podman" {
			t.Fatalf("the engine selector would not take podman (got %q) — the option the "+
				"backend offers is not selectable in the form it generated", r.EngineSet)
		}
		if r.RuntimeSet != "kata" || r.ImageSet != "ghcr.io/acme/sandbox:v3" {
			t.Fatalf("form fields did not take their values: runtime=%q image=%q",
				r.RuntimeSet, r.ImageSet)
		}
		if !r.DialogClosed {
			t.Error("the dialog stayed open after a successful save")
		}
		// The assertion the whole file is for: the hub's own answer, read back
		// through the API rather than off the screen we just typed into.
		if r.StoredMode != string(executor.SandboxModeContainer) {
			t.Errorf("stored mode = %q, want %q — the form did not change where payloads run",
				r.StoredMode, executor.SandboxModeContainer)
		}
		if r.StoredEngine != "podman" {
			t.Errorf("stored engine = %q, want podman", r.StoredEngine)
		}
		if r.StoredRuntime != "kata" {
			t.Errorf("stored runtime = %q, want kata — this is the field that decides whether "+
				"the payload sits behind a hypervisor", r.StoredRuntime)
		}
		if r.StoredImage != "ghcr.io/acme/sandbox:v3" {
			t.Errorf("stored image = %q", r.StoredImage)
		}
		if !r.Configured {
			t.Error("the executor does not report as configured after a save")
		}
	})

	t.Run("reopening shows what was saved", func(t *testing.T) {
		r := got["reopen_shows_saved_values"]
		if r.Mode != string(executor.SandboxModeContainer) {
			t.Errorf("mode on reopen = %q, want container", r.Mode)
		}
		if r.Engine != "podman" || r.Runtime != "kata" || r.Image != "ghcr.io/acme/sandbox:v3" {
			t.Errorf("reopened form shows engine=%q runtime=%q image=%q, want what was saved",
				r.Engine, r.Runtime, r.Image)
		}
		// Populated from the stored mode, without the admin touching the
		// selector — otherwise the saved runtime is invisible on reopen and reads
		// as lost.
		if !r.FieldsVisible {
			t.Error("the container fields are hidden on reopening a container-mode executor, " +
				"so the runtime it is configured with cannot be seen")
		}
	})

	t.Run("a refused runtime changes nothing and says so", func(t *testing.T) {
		r := got["rejected_runtime_changes_nothing"]
		// A path would turn "name a runtime" into "name a binary the engine runs
		// as root". The backend refuses it; what matters here is that the refusal
		// leaves the stored value alone and leaves the admin somewhere they can
		// fix it.
		if r.StoredRuntime != "kata" {
			t.Errorf("stored runtime after a refused save = %q, want the previous kata — "+
				"a rejected value must not disturb what is configured", r.StoredRuntime)
		}
		if !r.DialogStillOpen {
			t.Error("the dialog closed on a refused save, so the admin loses the form and the " +
				"reason without being able to correct the field")
		}
	})
}
