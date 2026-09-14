package ui

// Frontend gate for the Settings speech-to-text panel (Task 20250).
//
// The assertions here are behavioural because the property at stake cannot be
// expressed as a grep. Every other field in the Settings tab is saved through
// pUrl('/api/config/set'), which carries ?project_idx; this one must not, and
// both call styles look identical to a text search. Running the real bundle in
// testdata/domshim.js is what makes "asks the hub, not the selected project"
// falsifiable — see testdata/stt_settings_scenarios.js.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type sttPanelResult struct {
	// load_is_hub_scoped_even_with_a_project_selected
	Requested bool     `json:"requested"`
	URLs      []string `json:"urls"`
	AnyScoped bool     `json:"anyScoped"`

	// save_puts_clears_the_field_and_rechecks_dictation
	PutCount         int    `json:"putCount"`
	FieldAfter       string `json:"fieldAfter"`
	DictateRechecked bool   `json:"dictateRechecked"`
	ClearOffered     bool   `json:"clearOffered"`

	// clear_is_offered_only_for_a_stored_key
	WithNothing   bool `json:"withNothing"`
	WithEnvKey    bool `json:"withEnvKey"`
	WithStoredKey bool `json:"withStoredKey"`

	// blank_save_does_not_reach_the_network
	PutsBefore int `json:"putsBefore"`
	PutsAfter  int `json:"putsAfter"`

	// clearing_hides_the_dictate_button
	VisibleBefore bool `json:"visibleBefore"`
	VisibleAfter  bool `json:"visibleAfter"`

	Error string `json:"error"`
}

func runSTTPanelScenarios(t *testing.T) map[string]sttPanelResult {
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
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/stt_settings_scenarios.js")
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

	var results map[string]sttPanelResult
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

func TestDashboard_STTSettingsPanel(t *testing.T) {
	results := runSTTPanelScenarios(t)

	t.Run("load is hub scoped", func(t *testing.T) {
		got := results["load_is_hub_scoped_even_with_a_project_selected"]
		if !got.Requested {
			t.Fatal("opening Settings never asked /api/config/stt — the panel renders nothing")
		}
		if got.AnyScoped {
			t.Errorf("the panel asked for the selected project's config (%v) — dictation "+
				"resolves against the hub alone, so a project-scoped read reports on a "+
				"config nothing will ever use", got.URLs)
		}
	})

	t.Run("save puts, clears the field and rechecks dictation", func(t *testing.T) {
		got := results["save_puts_clears_the_field_and_rechecks_dictation"]
		if got.PutCount != 1 {
			t.Errorf("Save issued %d PUTs, want exactly 1", got.PutCount)
		}
		if strings.TrimSpace(got.FieldAfter) != "" {
			t.Errorf("the key is still in the input after saving (%q) — a credential "+
				"left in the DOM outlives the request that needed it", got.FieldAfter)
		}
		if !got.DictateRechecked {
			t.Error("saving a key did not re-probe /api/dictate — the Tasks tab decides " +
				"once at load, so the button this panel exists to enable would stay " +
				"hidden until a reload")
		}
		if !got.ClearOffered {
			t.Error("Clear is not offered after storing a key")
		}
	})

	t.Run("clear is offered only for a stored key", func(t *testing.T) {
		got := results["clear_is_offered_only_for_a_stored_key"]
		if got.WithNothing {
			t.Error("Clear is offered with no key at all")
		}
		if got.WithEnvKey {
			t.Error("Clear is offered for a GROQ_API_KEY-supplied key — the hub cannot " +
				"remove the environment's key, so the button would do nothing")
		}
		if !got.WithStoredKey {
			t.Error("Clear is withheld for a key the hub actually stored")
		}
	})

	t.Run("blank save does not reach the network", func(t *testing.T) {
		got := results["blank_save_does_not_reach_the_network"]
		if got.PutsAfter != got.PutsBefore {
			t.Errorf("a blank Save issued a request (%d → %d); the field already knows "+
				"it is empty", got.PutsBefore, got.PutsAfter)
		}
	})

	t.Run("clearing hides the dictate button", func(t *testing.T) {
		got := results["clearing_hides_the_dictate_button"]
		if !got.VisibleBefore {
			t.Fatal("the Dictate button was not shown with a key configured — " +
				"the scenario cannot prove anything about hiding it")
		}
		if got.VisibleAfter {
			t.Error("clearing the key left the Dictate button on screen; pressing it " +
				"now fails only after the user has spoken a sentence into it")
		}
	})
}
