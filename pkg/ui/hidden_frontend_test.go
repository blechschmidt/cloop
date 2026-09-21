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

// hiddenButtonResult is what the Settings page itself shows now that the names
// have moved into a dialog (Task 20328): a label, and whether it can be clicked.
type hiddenButtonResult struct {
	Label    string `json:"label"`
	Disabled bool   `json:"disabled"`
}

// hiddenRevealResult is one reading of the page — which elements mention the
// hidden project, and the state of the two controls — taken at a single point
// in the dialog's lifecycle.
type hiddenRevealResult struct {
	Name   []string           `json:"name"`
	Path   []string           `json:"path"`
	Button hiddenButtonResult `json:"button"`
	Panel  hiddenPanelResult  `json:"panel"`
}

type hiddenScenarioResult struct {
	Grid              []int              `json:"grid"`
	Dropdown          []int              `json:"dropdown"`
	Names             []string           `json:"names"`
	Button            hiddenButtonResult `json:"button"`
	Panel             hiddenPanelResult  `json:"panel"`
	Total             string             `json:"total"`
	Posts             []string           `json:"posts"`
	Deletes           []string           `json:"deletes"`
	MentionsSettings  bool               `json:"mentionsSettings"`
	MentionsCompleted bool               `json:"mentionsCompleted"`

	// settings_page_does_not_reveal: the page as read before the dialog was
	// opened, while it was open, and after it was dismissed again.
	Closed   hiddenRevealResult `json:"closed"`
	Open     hiddenRevealResult `json:"open"`
	Reclosed hiddenRevealResult `json:"reclosed"`

	// broadcast_respects_the_dialog.
	WhileClosed hiddenRevealResult `json:"whileClosed"`
	WhileOpen   hiddenRevealResult `json:"whileOpen"`

	Error string `json:"error"`
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
		t.Errorf("with nothing hidden the dialog is not empty: %+v", base.Panel)
	}
	if !base.Button.Disabled {
		t.Errorf("with nothing hidden the Settings button is still clickable (%q); "+
			"it opens a dialog that can only say the same thing", base.Button.Label)
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
// from the place the user is told to look — which since Task 20328 is a dialog
// one click into Settings rather than the Settings page itself.
func TestDashboard_HiddenProjectsAreRestorableFromSettings(t *testing.T) {
	t.Parallel()

	results := runHiddenScenarios(t)

	got := results["middle_hidden_keeps_indices"]
	if !sameInts(got.Panel.Indices, []int{1}) {
		t.Errorf("the dialog offers to unhide %v, want the hidden project's own index [1]", got.Panel.Indices)
	}
	if strings.Join(got.Panel.Names, ",") != "beta" {
		t.Errorf("the dialog lists %v, want beta", got.Panel.Names)
	}
	// The button is the only thing standing between the user and that dialog,
	// so it has to say there is something behind it. A label that never counts
	// makes the feature look broken for the user who hid one project and finds
	// nothing acknowledging it.
	if got.Button.Disabled || !strings.Contains(got.Button.Label, "1") {
		t.Errorf("the Settings button reads %q (disabled=%v), want an enabled label "+
			"carrying the count of 1 hidden project", got.Button.Label, got.Button.Disabled)
	}

	// Settings may be the first tab opened in a session, before anything has
	// populated the cached projects payload.
	first := results["settings_first_still_lists_hidden"]
	if !sameInts(first.Panel.Indices, []int{1}) || strings.Join(first.Panel.Names, ",") != "beta" {
		t.Errorf("opening Settings first listed %+v, want beta at index 1 — "+
			"the dialog must fetch when there is no cached payload", first.Panel)
	}
	if first.Button.Disabled {
		t.Errorf("opening Settings first left the button disabled (%q), so the one hidden "+
			"project is unreachable until some other tab is visited", first.Button.Label)
	}
}

// TestDashboard_SettingsDoesNotRevealHiddenProjects is Task 20328, and the
// property the dialog exists for.
//
// Hiding a project is not access control — the project keeps running and anyone
// can unhide it — but it is the only control a user has over what their screen
// says, and Settings is a tab you open for the STT key or the OIDC issuer. If
// the names are listed there, they are on screen for whoever is looking at it or
// sharing it, for a reason that has nothing to do with the projects. So the page
// carries a count and the names are put into the DOM only while the dialog is up.
//
// Swept across every node the bundle wrote to rather than just the list
// container, because the leak this guards against is a render of the hidden
// project, and it would be no less of one for happening in a panel nobody
// thought to check.
func TestDashboard_SettingsDoesNotRevealHiddenProjects(t *testing.T) {
	t.Parallel()

	got := results_named(t, "settings_page_does_not_reveal")

	if len(got.Closed.Name) != 0 {
		t.Errorf("opening Settings put the hidden project's name on the page, in %v.\n"+
			"  Hidden projects belong in the #hiddenproj-overlay dialog, which "+
			"openHiddenProjectsModal() fills on demand. Rendering them into the Settings\n"+
			"  panel undoes the hiding for anyone who opens that tab for an unrelated reason.",
			got.Closed.Name)
	}
	if len(got.Closed.Path) != 0 {
		t.Errorf("opening Settings put the hidden project's path on the page, in %v — "+
			"a path names the work as surely as the name does", got.Closed.Path)
	}
	// The count is what the page is allowed to say, and it has to be there:
	// without it the button is a coin flip and the feature looks inert.
	if !strings.Contains(got.Closed.Button.Label, "1") || got.Closed.Button.Disabled {
		t.Errorf("the Settings button reads %q (disabled=%v), want an enabled label "+
			"reporting that 1 project is hidden", got.Closed.Button.Label, got.Closed.Button.Disabled)
	}
	if len(got.Closed.Panel.Names) != 0 || got.Closed.Panel.Empty {
		t.Errorf("the dialog's list node is not empty while the dialog is shut: %+v.\n"+
			"  It must hold nothing at all — neither rows nor the 'No hidden projects' "+
			"placeholder — so that nothing can be read out of it.", got.Closed.Panel)
	}

	// Clicking through must actually produce the list, or the names are simply
	// gone and the feature is a one-way door.
	if strings.Join(got.Open.Panel.Names, ",") != "beta" {
		t.Errorf("the dialog lists %v once opened, want beta", got.Open.Panel.Names)
	}
	if len(got.Open.Name) == 0 {
		t.Error("opening the dialog rendered the name nowhere — the only way back is gone")
	}

	// And closing it takes them off the page again. A dialog that merely hides
	// its rows keeps every hidden name in the document for the session.
	if len(got.Reclosed.Name) != 0 {
		t.Errorf("after the dialog was dismissed the name is still on the page, in %v.\n"+
			"  closeHiddenProjectsModal() must empty #hiddenProjectsList, not just hide "+
			"the overlay.", got.Reclosed.Name)
	}
}

// TestDashboard_ProjectsBroadcastRespectsHiddenDialog covers the way the leak
// would come back after being fixed once: not through the Settings render path
// but through the 'projects' WebSocket frame, which fires on every run state
// change and re-renders the whole list. A renderer that fills the dialog
// unconditionally puts the names back in the page seconds after the user closed
// it, with nothing on screen to show it happened.
func TestDashboard_ProjectsBroadcastRespectsHiddenDialog(t *testing.T) {
	t.Parallel()

	got := results_named(t, "broadcast_respects_the_dialog")

	if len(got.WhileClosed.Name) != 0 {
		t.Errorf("a 'projects' broadcast while the dialog was shut wrote the hidden name "+
			"into %v — renderHiddenProjects() must refuse to render unless the dialog is open",
			got.WhileClosed.Name)
	}
	if len(got.WhileClosed.Panel.Names) != 0 {
		t.Errorf("the broadcast refilled the dialog's list behind the user: %+v", got.WhileClosed.Panel)
	}

	// Open, the rows must track the payload: a second project became hidden.
	if !sameInts(got.WhileOpen.Panel.Indices, []int{0, 1}) {
		t.Errorf("the open dialog offers %v after a broadcast hid a second project, want [0 1] — "+
			"a stale list offers to unhide projects whose state has moved on",
			got.WhileOpen.Panel.Indices)
	}
	if strings.Join(got.WhileOpen.Panel.Names, ",") != "alpha,beta" {
		t.Errorf("the open dialog lists %v, want alpha and beta", got.WhileOpen.Panel.Names)
	}
	if !strings.Contains(got.WhileOpen.Button.Label, "2") {
		t.Errorf("the Settings button reads %q after a second project was hidden, want a count of 2",
			got.WhileOpen.Button.Label)
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

	got := results_named(t, "all_hidden_explains_itself")
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
		t.Errorf("the dialog offers %+v, want all three projects restorable", got.Panel)
	}
	if got.Button.Disabled || !strings.Contains(got.Button.Label, "3") {
		t.Errorf("the Settings button reads %q (disabled=%v) with everything hidden, want an "+
			"enabled label counting all 3", got.Button.Label, got.Button.Disabled)
	}
}

func results_named(t *testing.T, name string) hiddenScenarioResult {
	t.Helper()
	return runHiddenScenarios(t)[name]
}
