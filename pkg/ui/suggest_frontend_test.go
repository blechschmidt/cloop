package ui

// The suggestions panel, driven through the real dashboard bundle (Task
// 20342). See testdata/suggest_scenarios.js for what each scenario does.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type suggestPanelView struct {
	Titles      []string `json:"titles"`
	After       []string `json:"after"`
	Badge       string   `json:"badge"`
	Summary     string   `json:"summary"`
	AddAll      bool     `json:"addAll"`
	Label       string   `json:"label"`
	Placeholder string   `json:"placeholder"`
	Input       string   `json:"input"`
	Toast       string   `json:"toast"`
}

type suggestGenerateCase struct {
	Status string         `json:"status"`
	URL    string         `json:"url"`
	Body   map[string]any `json:"body"`
}

type suggestPost struct {
	URL  string         `json:"url"`
	Body map[string]any `json:"body"`
}

type suggestScenario struct {
	suggestPanelView

	Brainstorm suggestPanelView      `json:"brainstorm"`
	Plan       suggestPanelView      `json:"plan"`
	Blank      suggestPanelView      `json:"blank"`
	Cases      []suggestGenerateCase `json:"cases"`
	Adds       json.RawMessage       `json:"adds"`
	One        suggestPanelView      `json:"one"`
	All        suggestPanelView      `json:"all"`
	Rendered   []int                 `json:"rendered"`
	Error      string                `json:"error"`
}

func runSuggestScenarios(t *testing.T) map[string]suggestScenario {
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
	cmd := exec.Command(node, mustAbs(t, "testdata/suggest_scenarios.js"), mustAbs(t, "testdata/domshim.js"), bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var results map[string]suggestScenario
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

func TestDashboard_SuggestPanelPlansARequest(t *testing.T) {
	t.Parallel()
	got := runSuggestScenarios(t)

	t.Run("the count says what it counts", func(t *testing.T) {
		m := got["mode_follows_the_input"]
		if m.Brainstorm.Label != "Ideas to generate:" || m.Brainstorm.Placeholder != "5" {
			t.Errorf("with no request: %q / placeholder %q", m.Brainstorm.Label, m.Brainstorm.Placeholder)
		}
		if m.Plan.Label != "Tasks in plan:" || m.Plan.Placeholder != "auto" {
			t.Errorf("with a request: %q / placeholder %q — blank must read as the AI deciding", m.Plan.Label, m.Plan.Placeholder)
		}
		if m.Blank.Label != "Ideas to generate:" {
			t.Errorf("a whitespace-only request is no request, got %q", m.Blank.Label)
		}
	})

	t.Run("generate posts the request and the count", func(t *testing.T) {
		cases := got["generate_posts_request_and_optional_count"].Cases
		want := []struct {
			status string
			body   map[string]any
		}{
			{"Planning tasks with AI...", map[string]any{"input": "Add OAuth login", "count": 0.0}},
			{"Planning 4 tasks with AI...", map[string]any{"input": "Add OAuth login", "count": 4.0}},
			{"Generating 5 ideas with AI...", map[string]any{"input": "", "count": 0.0}},
			{"Generating 5 ideas with AI...", map[string]any{"input": "", "count": 0.0}},
		}
		if len(cases) != len(want) {
			t.Fatalf("got %d cases, want %d", len(cases), len(want))
		}
		for i, c := range cases {
			if c.Status != want[i].status {
				t.Errorf("case %d: status line %q, want %q", i, c.Status, want[i].status)
			}
			if !reflect.DeepEqual(c.Body, want[i].body) {
				t.Errorf("case %d: posted %v, want %v", i, c.Body, want[i].body)
			}
			if !strings.Contains(c.URL, "project_idx=1") {
				t.Errorf("case %d: posted to %q, not the project on screen", i, c.URL)
			}
		}
	})

	t.Run("a plan renders as steps", func(t *testing.T) {
		p := got["plan_renders_as_steps"]
		wantTitles := []string{
			"Step 1 · Add provider config", "Step 2 · Callback handler",
			"Step 3 · Login button", "Step 4 · Document &lt;login&gt;",
		}
		if !reflect.DeepEqual(p.Titles, wantTitles) {
			t.Errorf("cards = %q, want %q", p.Titles, wantTitles)
		}
		if !reflect.DeepEqual(p.After, []string{"1", "1", "2, 3"}) {
			t.Errorf("dependency tags = %q, want [1 1 2, 3]", p.After)
		}
		if p.Badge != "· 4 tasks to review" || !p.AddAll || p.Summary != "OAuth login in four steps" {
			t.Errorf("badge %q, add-all %v, summary %q", p.Badge, p.AddAll, p.Summary)
		}
		if p.Toast != "Planned 4 tasks — review below" {
			t.Errorf("toast %q", p.Toast)
		}
	})

	t.Run("accepting sends IDs and the generation", func(t *testing.T) {
		a := got["accepting_sends_ids_and_generation"]
		var adds []suggestPost
		if err := json.Unmarshal(a.Adds, &adds); err != nil {
			t.Fatal(err)
		}
		want := []map[string]any{
			{"gen": 7.0, "ids": []any{3.0}},
			{"gen": 7.0, "ids": []any{1.0, 2.0, 4.0}},
		}
		if len(adds) != 2 {
			t.Fatalf("posted %d adds, want 2: %v", len(adds), adds)
		}
		for i, p := range adds {
			if !reflect.DeepEqual(p.Body, want[i]) {
				t.Errorf("add %d posted %v, want %v", i, p.Body, want[i])
			}
			if !strings.Contains(p.URL, "project_idx=1") {
				t.Errorf("add %d went to %q", i, p.URL)
			}
		}
		if len(a.One.Titles) != 3 || strings.Contains(strings.Join(a.One.Titles, "|"), "Login button") {
			t.Errorf("after accepting step 3 the cards are %q", a.One.Titles)
		}
		if a.One.Toast != `Added "Login button" as task` {
			t.Errorf("toast %q", a.One.Toast)
		}
		if len(a.All.Titles) != 0 || a.All.AddAll || a.All.Toast != "Added 3 tasks" {
			t.Errorf("after add all: cards %q, add-all shown %v, toast %q", a.All.Titles, a.All.AddAll, a.All.Toast)
		}
		if a.All.Summary != "" {
			t.Errorf("the summary of a plan with nothing left to review is still shown: %q", a.All.Summary)
		}
		if !reflect.DeepEqual(a.Rendered, []int{12}) {
			t.Errorf("the task list shows %v; the accepted task should appear without waiting for a state_diff", a.Rendered)
		}
	})

	t.Run("a re-sent generation keeps skips and stays quiet", func(t *testing.T) {
		s := got["same_generation_update_keeps_skips"]
		want := []string{"Step 3 · Login button", "Step 4 · Document &lt;login&gt;"}
		if !reflect.DeepEqual(s.Titles, want) {
			t.Errorf("cards = %q, want %q — step 1 added elsewhere gone, skipped step 2 not back", s.Titles, want)
		}
		if s.Toast != "" {
			t.Errorf("a re-sent generation toasted %q", s.Toast)
		}
	})

	t.Run("ideas render as ideas", func(t *testing.T) {
		i := got["ideas_render_as_ideas"]
		if !reflect.DeepEqual(i.Titles, []string{"Dark mode", "Rate limits"}) || len(i.After) != 0 {
			t.Errorf("idea cards %q, tags %q", i.Titles, i.After)
		}
		if i.Badge != "· 2 ideas to review" || i.Toast != "Generated 2 ideas — review below" {
			t.Errorf("badge %q, toast %q", i.Badge, i.Toast)
		}
	})

	t.Run("a late add reply leaves the next project alone", func(t *testing.T) {
		l := got["add_reply_after_switching_projects_stays_out"]
		if !reflect.DeepEqual(l.Titles, []string{"Alpha idea"}) {
			t.Errorf("alpha's cards are %q; beta's add reply struck the one sharing an ID", l.Titles)
		}
		for _, id := range l.Rendered {
			if id == 12 {
				t.Errorf("beta's new task #12 was merged into alpha's task list: %v", l.Rendered)
			}
		}
	})

	t.Run("leaving the project clears the panel", func(t *testing.T) {
		l := got["leaving_the_project_clears_the_panel"]
		if len(l.Titles) != 0 || l.AddAll || l.Badge != "" || l.Summary != "" {
			t.Errorf("the next project still shows the last one's plan: %+v", l.suggestPanelView)
		}
		if l.Input != "" || l.Label != "Ideas to generate:" {
			t.Errorf("the request box kept %q (label %q)", l.Input, l.Label)
		}
		var adds []suggestPost
		if err := json.Unmarshal(l.Adds, &adds); err != nil || len(adds) != 0 {
			t.Errorf("add all on the next project posted %v (%v)", adds, err)
		}
	})
}
