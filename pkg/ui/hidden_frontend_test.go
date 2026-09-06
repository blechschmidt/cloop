package ui

// Hiding projects, driven through the real dashboard bundle (Task 20206).
//
// The grid renders a subset of the /api/projects list while every action on a
// card — open, run, stop, delete, hide — dispatches on that project's index
// in the *full* list. Those two facts only coexist safely if filtering
// preserves the original index, and that is a property of the rendered DOM
// rather than of any string in the source. Grep-style gates have guarded this
// bug class seven times before (Tasks 150, 152, 163, 168, 8000, 20013, 20018)
// and did not stop the eighth, so these run the bundle in node against
// testdata/domshim.js and read back what the user would click.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type hiddenPanelResult struct {
	Indices []int    `json:"indices"`
	Names   []string `json:"names"`
	Empty   bool     `json:"empty"`
}

type hiddenScenarioResult struct {
	Grid              []int             `json:"grid"`
	Dropdown          []int             `json:"dropdown"`
	Names             []string          `json:"names"`
	Panel             hiddenPanelResult `json:"panel"`
	Total             string            `json:"total"`
	Posts             []string          `json:"posts"`
	Deletes           []string          `json:"deletes"`
	MentionsSettings  bool              `json:"mentionsSettings"`
	MentionsCompleted bool              `json:"mentionsCompleted"`
	Error             string            `json:"error"`
}

// runHiddenScenarios assembles the served bundle, runs the scenarios in node
// and returns them by name.
func runHiddenScenarios(t *testing.T) map[string]hiddenScenarioResult {
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
	scenarios, err := filepath.Abs("testdata/hidden_scenarios.js")
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

	var results map[string]hiddenScenarioResult
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

// TestDashboard_HidingPreservesProjectIndices is the load-bearing test. Hiding
// the middle of three projects must leave the survivors dispatching on 0 and
// 2 — renumbering them to 0 and 1 points every button on the last card at the
// hidden project instead.
func TestDashboard_HidingPreservesProjectIndices(t *testing.T) {
	t.Parallel()

	results := runHiddenScenarios(t)

	base := results["nothing_hidden"]
	if !sameInts(base.Grid, []int{0, 1, 2}) {
		t.Fatalf("baseline grid = %v, want all three projects at their own indices", base.Grid)
	}
	if !base.Panel.Empty {
		t.Errorf("with nothing hidden the settings panel is not empty: %+v", base.Panel)
	}

	got := results["middle_hidden_keeps_indices"]
	if !sameInts(got.Grid, []int{0, 2}) {
		t.Errorf("grid dispatches on %v, want [0 2] — hiding renumbered the list, "+
			"so every action on the last card now targets the hidden project", got.Grid)
	}
	if strings.Join(got.Names, ",") != "alpha,gamma" {
		t.Errorf("grid shows %v, want alpha and gamma", got.Names)
	}
	if got.Total != "2" {
		t.Errorf("project counter reads %q, want \"2\" — it must agree with the cards on screen", got.Total)
	}

	// The Overview tab renders the same list from its own code path. Filtering
	// applied to one grid and forgotten in the other is the specific way this
	// bug class keeps coming back.
	overview := results["overview_grid_also_hides"]
	if !sameInts(overview.Grid, []int{0, 2}) {
		t.Errorf("overview grid dispatches on %v, want [0 2]", overview.Grid)
	}
	if len(overview.Names) != 0 {
		t.Errorf("the hidden project is still on the Overview grid — hiding "+
			"reached the Projects tab but not this one (%v)", overview.Names)
	}

	// And the header dropdown, which would otherwise put the hidden project
	// one click from being selected again.
	if !sameInts(overview.Dropdown, []int{0, 2}) {
		t.Errorf("project selector dropdown offers %v, want [0 2]", overview.Dropdown)
	}
}

// TestDashboard_HiddenProjectsAreRestorableFromSettings checks the other half
// of the feature: what disappeared from the grid has to be reachable, by name,
// from the place the user is told to look.
func TestDashboard_HiddenProjectsAreRestorableFromSettings(t *testing.T) {
	t.Parallel()

	results := runHiddenScenarios(t)

	panel := results["middle_hidden_keeps_indices"].Panel
	if !sameInts(panel.Indices, []int{1}) {
		t.Errorf("settings offers to unhide %v, want the hidden project's own index [1]", panel.Indices)
	}
	if strings.Join(panel.Names, ",") != "beta" {
		t.Errorf("settings lists %v, want beta", panel.Names)
	}

	// Settings may be the first tab opened in a session, before anything has
	// populated the cached projects payload.
	first := results["settings_first_still_lists_hidden"].Panel
	if !sameInts(first.Indices, []int{1}) || strings.Join(first.Names, ",") != "beta" {
		t.Errorf("opening Settings first listed %+v, want beta at index 1 — "+
			"the panel must fetch when there is no cached payload", first)
	}
}

// TestDashboard_HideButtonPostsPreferenceNotDeletion pins hiding to the
// preference endpoint. The Hide and Delete buttons sit next to each other on
// the card, one is reversible and the other is not, and the difference is a
// single interpolated index apart in the markup.
func TestDashboard_HideButtonPostsPreferenceNotDeletion(t *testing.T) {
	t.Parallel()

	results := runHiddenScenarios(t)

	hide := results["hide_button_posts_preference"]
	if len(hide.Deletes) != 0 {
		t.Errorf("hiding issued %v — a hide must never delete anything", hide.Deletes)
	}
	if len(hide.Posts) != 1 || !strings.HasSuffix(hide.Posts[0], "/api/projects/2/hidden") {
		t.Errorf("hiding posted %v, want a single POST to /api/projects/2/hidden", hide.Posts)
	}

	unhide := results["unhide_button_posts_preference"]
	if len(unhide.Posts) != 1 || !strings.HasSuffix(unhide.Posts[0], "/api/projects/1/hidden") {
		t.Errorf("unhiding posted %v, want a single POST to /api/projects/1/hidden", unhide.Posts)
	}
}

// TestDashboard_AllProjectsHiddenExplainsItself covers the state a user can
// reach in three clicks and cannot otherwise get out of: an empty grid that
// blames the wrong filter would send them looking for a Show-completed button
// that changes nothing.
func TestDashboard_AllProjectsHiddenExplainsItself(t *testing.T) {
	t.Parallel()

	got := results_allHidden(t)
	if len(got.Grid) != 0 {
		t.Errorf("grid rendered %v cards with everything hidden", got.Grid)
	}
	if !got.MentionsSettings {
		t.Error("the empty grid does not name Settings — the only way back is unreachable")
	}
	if got.MentionsCompleted {
		t.Error("the empty grid blames completed projects for an all-hidden list")
	}
	if got.Panel.Empty || len(got.Panel.Indices) != 3 {
		t.Errorf("settings offers %+v, want all three projects restorable", got.Panel)
	}
}

func results_allHidden(t *testing.T) hiddenScenarioResult {
	t.Helper()
	return runHiddenScenarios(t)["all_hidden_explains_itself"]
}
