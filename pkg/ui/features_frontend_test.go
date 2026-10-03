package ui

// Parallel features in the dashboard (Task 20341), driven through the served
// bundle in node against testdata/domshim.js. See features_scenarios.js for
// why these read the rendered DOM and the requests made rather than the
// source: the bug class they guard — an action addressed to the wrong index —
// has recurred in this dashboard every time a grep was trusted to catch it.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type featureRequest struct {
	Method string         `json:"method"`
	URL    string         `json:"url"`
	Body   map[string]any `json:"body"`
}

type featureScenario struct {
	Error string `json:"error"`

	// grid_nests_features
	Cards            []int  `json:"cards"`
	Chips            []int  `json:"chips"`
	ChipsInsideAlpha bool   `json:"chipsInsideAlpha"`
	Escaped          bool   `json:"escaped"`
	Total            string `json:"total"`

	// dropdown_nests_features
	Order []int `json:"order"`
	Sub   int   `json:"sub"`

	// parent_panel, non_git_project, feature_banner
	Section    string `json:"section"`
	Banner     string `json:"banner"`
	RunIdx     []int  `json:"runIdx"`
	StopIdx    []int  `json:"stopIdx"`
	PRIdx      []int  `json:"prIdx"`
	RemoveIdx  []int  `json:"removeIdx"`
	UpdatePR   int    `json:"updatePR"`
	PRLink     bool   `json:"prLink"`
	UnsafeLink bool   `json:"unsafeLink"`
	Options    bool   `json:"options"`
	NewButton  string `json:"newButton"`
	Kept       bool   `json:"kept"`
	Says       bool   `json:"says"`
	ParentIdx  []int  `json:"parentIdx"`
	Updates    bool   `json:"updates"`
	Branch     bool   `json:"branch"`
	Repos      string `json:"repos"`

	// flows
	Requests     []featureRequest `json:"requests"`
	SocketIdx    *int             `json:"socketIdx"`
	Overlay      string           `json:"overlay"`
	Sent         int              `json:"sent"`
	ErrorText    string           `json:"errorText"`
	UpdateTitle  string           `json:"updateTitle"`
	UpdateFields string           `json:"updateFields"`
	OpenTitle    string           `json:"openTitle"`
	Opened       []string         `json:"opened"`
	PRAfterGone  int              `json:"prAfterGone"`
	Rendered     string           `json:"rendered"`
	PRError      string           `json:"prError"`
}

func runFeatureScenarios(t *testing.T) map[string]featureScenario {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	// The served bundle — comments stripped — because that is what a browser
	// runs.
	if err := os.WriteFile(bundle, []byte(loadAssets().served), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	cmd := exec.Command(node, mustAbs(t, "testdata/features_scenarios.js"), mustAbs(t, "testdata/domshim.js"), bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var raw map[string]map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	results := map[string]featureScenario{}
	for name, doc := range raw {
		b, _ := json.Marshal(doc)
		var r featureScenario
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("scenario %s: %v", name, err)
		}
		if strings.Contains(r.Error, "\n    at ") {
			t.Fatalf("scenario %s threw: %s", name, r.Error)
		}
		results[name] = r
	}
	return results
}

func TestDashboard_FeaturesNestUnderTheirProject(t *testing.T) {
	res := runFeatureScenarios(t)

	g := res["grid_nests_features"]
	if !reflect.DeepEqual(g.Cards, []int{0, 1}) {
		t.Errorf("project cards dispatch on %v, want [0 1] — a feature must not be a card of its own", g.Cards)
	}
	if !reflect.DeepEqual(g.Chips, []int{2, 3}) || !g.ChipsInsideAlpha {
		t.Errorf("feature chips = %v (inside alpha's card: %v), want [2 3] inside it", g.Chips, g.ChipsInsideAlpha)
	}
	if !g.Escaped {
		t.Error("a feature title was rendered as markup rather than text")
	}
	if g.Total != "2" {
		t.Errorf("the project counter reads %q — features are not projects", g.Total)
	}

	if o := res["overview_cards"]; !reflect.DeepEqual(o.Cards, []int{0, 1}) {
		t.Errorf("the all-projects Overview shows cards for %v, want the two projects only", o.Cards)
	}

	d := res["dropdown_nests_features"]
	if !reflect.DeepEqual(d.Order, []int{0, 2, 3, 1}) || d.Sub != 2 {
		t.Errorf("dropdown order = %v with %d indented, want [0 2 3 1] with the two features indented", d.Order, d.Sub)
	}
}

func TestDashboard_FeaturePanels(t *testing.T) {
	res := runFeatureScenarios(t)

	p := res["parent_panel"]
	if p.Section != "" || p.Banner != "none" {
		t.Errorf("on a project: features section %q, banner %q — want shown, hidden", p.Section, p.Banner)
	}
	if !reflect.DeepEqual(p.RunIdx, []int{2}) || !reflect.DeepEqual(p.StopIdx, []int{3}) {
		t.Errorf("run buttons %v, stop buttons %v — want Run on the idle feature (2), Stop on the running one (3)", p.RunIdx, p.StopIdx)
	}
	if !reflect.DeepEqual(p.PRIdx, []int{2, 3}) || !reflect.DeepEqual(p.RemoveIdx, []int{2, 3}) {
		t.Errorf("PR buttons %v, remove buttons %v, want both on [2 3]", p.PRIdx, p.RemoveIdx)
	}
	if !p.PRLink {
		t.Error("an open pull request is not linked, in a new tab")
	}
	if p.UnsafeLink {
		t.Error("a javascript: URL reported as a pull request's address reached an href")
	}
	if !p.Options {
		t.Error("a feature's evolve and innovate settings are not shown on its row")
	}
	if p.NewButton != "" {
		t.Errorf("New feature button display %q on a git project", p.NewButton)
	}
	if !p.Kept {
		t.Error("a feature whose returned work was kept on a branch of its own does not say so (or its message reached the page unescaped)")
	}

	n := res["non_git_project"]
	if !n.Says || n.NewButton != "none" {
		t.Errorf("a project that is not a git repository offers features (button %q) or does not say why (%v)", n.NewButton, n.Says)
	}

	b := res["feature_banner"]
	if b.Banner != "" || b.Section != "none" {
		t.Errorf("on a feature: banner %q, features section %q — want shown, hidden", b.Banner, b.Section)
	}
	if !reflect.DeepEqual(b.ParentIdx, []int{0}) || !reflect.DeepEqual(b.PRIdx, []int{2}) {
		t.Errorf("banner links parent %v and PR %v, want [0] and [2]", b.ParentIdx, b.PRIdx)
	}
	if !b.Updates || !b.Branch {
		t.Error("the banner does not name the branch or offer to update the open pull request")
	}
	if b.Repos != "none" {
		t.Errorf("the Repository Access panel shows on a feature (%q); a feature holds its project's grants", b.Repos)
	}
}

func TestDashboard_FeatureDialogs(t *testing.T) {
	res := runFeatureScenarios(t)

	c := res["create_flow"]
	if len(c.Requests) != 2 {
		t.Fatalf("create made %d mutating requests, want the create and the start: %+v", len(c.Requests), c.Requests)
	}
	create, start := c.Requests[0], c.Requests[1]
	if create.Method != "POST" || create.URL != "/api/projects/0/features" {
		t.Errorf("create went to %s %s", create.Method, create.URL)
	}
	want := map[string]any{
		"name": "Payments", "description": "Take payments", "base": "develop",
		"tasks": []any{"Stripe", "Invoices"}, "auto_evolve": true, "innovate": false,
		"parallel": true, "auto_pr": true,
	}
	if !reflect.DeepEqual(create.Body, want) {
		t.Errorf("create body = %v\nwant          %v", create.Body, want)
	}
	if start.URL != "/api/run?project_idx=4" {
		t.Errorf("the new feature was started at %s, want its own index 4", start.URL)
	}
	if c.SocketIdx == nil || *c.SocketIdx != 4 {
		t.Errorf("after creating, the dashboard is on project %v, want the new feature (4)", c.SocketIdx)
	}
	if c.Overlay != "none" {
		t.Error("the New feature dialog stayed open after success")
	}

	if r := res["create_requires_goal"]; r.Sent != 0 || r.ErrorText == "" {
		t.Errorf("a feature with no goal was submitted (%d requests) or not explained (%q)", r.Sent, r.ErrorText)
	}

	pr := res["pr_flow"]
	if pr.UpdateTitle != "Update pull request #12" || pr.UpdateFields != "none" {
		t.Errorf("for an open PR the dialog reads %q with fields %q — want an update, no title/body", pr.UpdateTitle, pr.UpdateFields)
	}
	if pr.OpenTitle != "Open pull request" {
		t.Errorf("for no PR the dialog reads %q", pr.OpenTitle)
	}
	if len(pr.Requests) != 1 || pr.Requests[0].URL != "/api/projects/0/features/dark-mode/pr" ||
		!reflect.DeepEqual(pr.Requests[0].Body, map[string]any{"title": "Dark mode (WIP)", "body": "", "draft": true}) {
		t.Errorf("PR request = %+v", pr.Requests)
	}
	if !reflect.DeepEqual(pr.Opened, []string{"https://github.com/acme/app/pull/14"}) {
		t.Errorf("opened %v, want the new pull request", pr.Opened)
	}

	rm := res["remove_flow"]
	if len(rm.Requests) != 1 || rm.Requests[0].Method != "DELETE" || rm.Requests[0].URL != "/api/projects/0/features/dark-mode" ||
		!reflect.DeepEqual(rm.Requests[0].Body, map[string]any{"delete_branch": true, "force": false}) {
		t.Errorf("remove request = %+v", rm.Requests)
	}
	if rm.SocketIdx == nil || *rm.SocketIdx != 0 {
		t.Errorf("after removing the feature being viewed, the dashboard is on %v, want its project (0)", rm.SocketIdx)
	}
}

// TestDashboard_SelectionFollowsTheProjectNotTheIndex is the regression the
// re-anchoring exists for: removing one feature renumbers the ones after it,
// and a Run pressed afterwards must start the feature on screen.
func TestDashboard_SelectionFollowsTheProjectNotTheIndex(t *testing.T) {
	r := runFeatureScenarios(t)["reanchors_after_shift"]
	if len(r.Requests) != 1 || r.Requests[0].URL != "/api/run?project_idx=2" {
		t.Errorf("Run after the list shifted = %+v, want /api/run?project_idx=2 (the feature's new index)", r.Requests)
	}
	if r.SocketIdx == nil || *r.SocketIdx != 2 {
		t.Errorf("the stream was not reopened under the new index (%v); its frames would all be refused", r.SocketIdx)
	}
	if r.Rendered != "after the shift" {
		t.Errorf("a frame after the shift did not reach the page (goal reads %q)", r.Rendered)
	}
}

// TestDashboard_VanishedSelectionReturnsToProjects: when the feature on screen
// is removed elsewhere, the dashboard goes back to the projects page rather
// than keep addressing the index it had, which now names a different project.
func TestDashboard_VanishedSelectionReturnsToProjects(t *testing.T) {
	r := runFeatureScenarios(t)["selection_vanishes"]
	if r.SocketIdx != nil {
		t.Errorf("after the selected feature vanished, the dashboard is still subscribed to project %d", *r.SocketIdx)
	}
}

// TestDashboard_DialogsFollowTheFeatureNotTheIndex is the data-loss case: a
// Remove dialog with force ticked, opened on one feature, is submitted after
// another feature's removal renumbered the list. It must remove the feature it
// named — and a dialog whose feature is gone must send nothing.
func TestDashboard_DialogsFollowTheFeatureNotTheIndex(t *testing.T) {
	r := runFeatureScenarios(t)["dialogs_follow_identity"]
	if len(r.Requests) != 1 || r.Requests[0].URL != "/api/projects/0/features/dark-mode" ||
		r.Requests[0].Body["force"] != true {
		t.Errorf("removal after the list shifted = %+v, want DELETE …/features/dark-mode with force", r.Requests)
	}
	if r.PRAfterGone != 0 || r.PRError == "" {
		t.Errorf("a PR dialog for a vanished feature sent %d requests (error %q)", r.PRAfterGone, r.PRError)
	}
}
