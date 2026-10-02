package ui

// Browser gate for the Settings → Telemetry panel (Task 20311).
//
// telemetry_config_api_test.go checks the backend: a save narrows, a narrowing
// is enforced on the write path, a change is audited. All of that passed while
// the panel itself was unusable — ticking the master switch and pressing Save
// submitted "collect, from nowhere", because the per-source boxes had been
// rendered from a policy that collected nothing and nobody had ticked them. The
// operator turned collection on and watched it stay off.
//
// That failure lives entirely in the assembled page: which boxes are ticked
// after a toggle, and what Save therefore sends. testdata/domshim.js cannot see
// it — its elements are auto-vivified stubs with no tree, so the panel's
// `querySelectorAll('#telemetryPolicySources input[data-tel-source]')` matches
// nothing there and every assertion about checkboxes would be vacuous.
//
// Skips when no browser is installed, like the other browser gates here: a
// developer-box and Chrome-equipped-runner check, never a source of red builds
// on a runner without one.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
)

type telemetryPanelSource struct {
	Name     string `json:"name"`
	Checked  bool   `json:"checked"`
	Disabled bool   `json:"disabled"`
}

type telemetryPanelView struct {
	SectionPresent bool                   `json:"section_present"`
	InSettings     bool                   `json:"in_settings"`
	Badge          string                 `json:"badge"`
	Enabled        bool                   `json:"enabled"`
	Sources        []telemetryPanelSource `json:"sources"`
	Note           string                 `json:"note"`
}

func (v telemetryPanelView) checked() map[string]bool {
	out := map[string]bool{}
	for _, s := range v.Sources {
		out[s.Name] = s.Checked
	}
	return out
}

type telemetryClientPolicyJSON struct {
	Source  string `json:"source"`
	Collect bool   `json:"collect"`
}

type telemetryPanelResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`

	Fresh         telemetryPanelView `json:"fresh"`
	AfterToggle   telemetryPanelView `json:"after_toggle"`
	AfterSave     telemetryPanelView `json:"after_save"`
	AfterNarrow   telemetryPanelView `json:"after_narrow"`
	AfterReload   telemetryPanelView `json:"after_reload"`
	AfterDisable  telemetryPanelView `json:"after_disable"`
	AfterReenable telemetryPanelView `json:"after_reenable"`
	AfterResave   telemetryPanelView `json:"after_resave"`

	ClientPolicy struct {
		Dashboard telemetryClientPolicyJSON `json:"dashboard"`
		Glasses   telemetryClientPolicyJSON `json:"glasses"`
	} `json:"client_policy"`
	DisabledClientPolicy telemetryClientPolicyJSON `json:"disabled_client_policy"`

	ConsoleErrors []string `json:"console_errors"`
}

func TestTelemetryPanel_CollectionSwitchInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot drive the panel")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// The real dashboard against a real hub. No project is seeded: a fresh
	// deployment is exactly the state whose default this feature changed. A
	// registry of its own, so it is a single-project hub whatever other tests
	// registered — a multi-project boot lands on the Projects tab.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	s := New(t.TempDir(), 0, "")
	// Two full dashboard loads plus the saves come from one address, which is
	// the per-IP limiter's to measure, not this test's.
	s.RPS, s.Burst = 1e6, 1e6
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Bounded: a Chrome that stalls must fail this test, not eat the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/telemetry_panel_browser.js"), chrome, srv.URL)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	if os.Getenv("TELEMETRY_PANEL_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}

	var got telemetryPanelResults
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("driver output is not JSON: %v\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("driver failed in the browser:\n%s", got.Error.Message)
	}

	// A fresh hub: the control is there, it says off, and it says so in a way
	// that distinguishes "nobody decided" from "somebody switched it off".
	if !got.Fresh.SectionPresent {
		t.Fatal("the Telemetry block is not on the Settings tab — the switch this task " +
			"exists to provide is unreachable")
	}
	if !got.Fresh.InSettings {
		t.Error("the collection switch is not under Settings, where an admin configures the hub")
	}
	if got.Fresh.Enabled {
		t.Error("a fresh hub renders the collection switch as on")
	}
	if got.Fresh.Badge != "off (default)" {
		t.Errorf("fresh badge = %q, want \"off (default)\" so an operator can tell an "+
			"unconfigured hub from one that was deliberately switched off", got.Fresh.Badge)
	}
	if len(got.Fresh.Sources) == 0 {
		t.Fatal("the panel offers no per-source checkboxes")
	}
	for _, s := range got.Fresh.Sources {
		// Ticked, because nothing was ever narrowed: switching on collects
		// from every front end. Greyed until it is.
		if !s.Checked {
			t.Errorf("source %q is offered unticked on a hub that never narrowed collection", s.Name)
		}
		if !s.Disabled {
			t.Errorf("source %q is editable while the master switch is off", s.Name)
		}
	}

	// The regression. Ticking the master switch must leave a form that means
	// "collect", and Save must store that.
	for _, s := range got.AfterToggle.Sources {
		if !s.Checked {
			t.Errorf("after switching collection on, source %q is still unticked; Save would "+
				"submit a policy with no front end in it, which the hub stores as off", s.Name)
		}
	}
	if !got.AfterSave.Enabled {
		t.Fatal("ticking the switch and pressing Save left collection off — the panel " +
			"silently discards the operator's decision")
	}
	if got.AfterSave.Badge != "collecting" {
		t.Errorf("badge after enabling = %q, want \"collecting\"", got.AfterSave.Badge)
	}

	// Narrowing to one front end, the posture the feature exists for.
	if !got.AfterNarrow.Enabled {
		t.Error("narrowing to one source switched collection off entirely")
	}
	if c := got.AfterNarrow.checked(); c["dashboard"] || !c["glasses"] {
		t.Errorf("after narrowing to the glasses the boxes read %v", c)
	}

	// A reload: the narrowing came back from the hub, not from the DOM.
	if !got.AfterReload.Enabled {
		t.Error("collection reads as off after a reload; the save did not persist")
	}
	if c := got.AfterReload.checked(); c["dashboard"] || !c["glasses"] {
		t.Errorf("after a reload the boxes read %v; the narrowing did not survive", c)
	}

	// And the answer each front end gets — which is what decides whether a
	// browser transmits anything at all.
	if got.ClientPolicy.Dashboard.Collect {
		t.Error("the dashboard is told to send its trail while collection is narrowed to the glasses")
	}
	if !got.ClientPolicy.Glasses.Collect {
		t.Error("the glasses are told not to send while they are the one collected source")
	}

	// Switching off again, the direction that matters in a hurry.
	if got.AfterDisable.Enabled {
		t.Error("the panel still reads as collecting after being switched off")
	}
	if got.DisabledClientPolicy.Collect {
		t.Error("a front end is still told to send after collection was switched off")
	}
	if c := got.AfterDisable.checked(); c["dashboard"] || !c["glasses"] {
		t.Errorf("switched off, the boxes read %v; the narrowing to the glasses should still show", c)
	}

	// On again: the form must still say glasses only, or Save widens it.
	if c := got.AfterReenable.checked(); c["dashboard"] || !c["glasses"] {
		t.Errorf("switched back on, the boxes read %v; the narrowing to the glasses was lost", c)
	}
	if c := got.AfterResave.checked(); !got.AfterResave.Enabled || c["dashboard"] || !c["glasses"] {
		t.Errorf("after switching back on and saving: enabled=%v boxes %v; want glasses only",
			got.AfterResave.Enabled, c)
	}

	if len(got.ConsoleErrors) > 0 {
		t.Errorf("the panel threw in the browser: %v", got.ConsoleErrors)
	}
}
