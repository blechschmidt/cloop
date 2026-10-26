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

	// Decompose (Task 20441).
	Closed           bool          `json:"closed"`
	Opened           bool          `json:"opened"`
	Status           string        `json:"status"`
	FormBefore       []string      `json:"form_before"`
	FormAfter        []string      `json:"form_after"`
	Toggle           string        `json:"toggle"`
	Posts            []suggestPost `json:"posts"`
	GenerateDisabled bool          `json:"generate_disabled"`
	AfterOnly        string        `json:"after_only"`

	// The Split dialog, deferred by Task 20441.
	SplitTitle string        `json:"split_title"`
	SplitBody  string        `json:"split_body"`
	Count      string        `json:"count"`
	Button     string        `json:"button"`
	SplitPosts []suggestPost `json:"split_posts"`
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

	t.Run("Decompose plans the task typed into Add Task", func(t *testing.T) {
		d := got["decompose_plans_the_typed_task"]
		const request = "Add OAuth login\n\nGitHub and Google.\nKeep sessions."
		if !d.Closed || !d.Opened || d.Toggle != "Hide suggestions" {
			t.Errorf("the panel was closed %v, then opened %v (toggle %q): the plan has to be on screen", d.Closed, d.Opened, d.Toggle)
		}
		if d.Input != request || d.Label != "Tasks in plan:" || d.Placeholder != "auto" {
			t.Errorf("the panel's request is %q (%q, placeholder %q), want the title and details as a plan of any length",
				d.Input, d.Label, d.Placeholder)
		}
		if d.Status != "Planning tasks with AI..." {
			t.Errorf("status line %q", d.Status)
		}
		if len(d.Posts) != 1 {
			t.Fatalf("posted %d generations, want 1: %v", len(d.Posts), d.Posts)
		}
		want := map[string]any{"count": 0.0, "input": request, "priority": 2.0, "depends_on": []any{1.0, 3.0}}
		if !reflect.DeepEqual(d.Posts[0].Body, want) {
			t.Errorf("posted %v, want %v", d.Posts[0].Body, want)
		}
		if !strings.Contains(d.Posts[0].URL, "project_idx=1") {
			t.Errorf("posted to %q, not the project on screen", d.Posts[0].URL)
		}
		if !reflect.DeepEqual(d.FormBefore, []string{"  Add OAuth login ", "GitHub and Google.\nKeep sessions.", "2", "1, 3"}) {
			t.Errorf("before the hub answered the form held %q; it must keep what was typed until then", d.FormBefore)
		}
		if !reflect.DeepEqual(d.FormAfter, []string{"", "", "", ""}) {
			t.Errorf("after the hub took the job the form still holds %q", d.FormAfter)
		}

		a := got["decompose_a_title_alone"]
		if len(a.Posts) != 1 || !reflect.DeepEqual(a.Posts[0].Body,
			map[string]any{"count": 0.0, "input": "Add OAuth login", "priority": 0.0, "depends_on": []any{}}) {
			t.Errorf("a title alone posted %v", a.Posts)
		}
	})

	t.Run("Decompose needs a title", func(t *testing.T) {
		n := got["decompose_needs_a_title"]
		if len(n.Posts) != 0 || n.Toast != "Title is required" {
			t.Errorf("with no title: %d generations posted, toast %q", len(n.Posts), n.Toast)
		}
		if !reflect.DeepEqual(n.FormAfter, []string{"   ", "only details", "", ""}) {
			t.Errorf("the form became %q", n.FormAfter)
		}
	})

	t.Run("a refused Decompose keeps what was typed", func(t *testing.T) {
		r := got["decompose_refused_keeps_the_form"]
		if !reflect.DeepEqual(r.FormAfter, []string{"Add OAuth login", "", "", "9"}) {
			t.Errorf("after a refusal the form holds %q", r.FormAfter)
		}
		if r.Status != "Error: dependency task 9 does not exist" || !strings.Contains(r.Toast, "dependency task 9 does not exist") {
			t.Errorf("the refusal reads %q / toast %q", r.Status, r.Toast)
		}
		if r.GenerateDisabled {
			t.Error("Generate stayed disabled after a refused generation")
		}
	})

	t.Run("Decompose waits for a running generation", func(t *testing.T) {
		w := got["decompose_waits_for_a_running_generation"]
		if len(w.Posts) != 0 || w.Toast != "Suggestions are still being generated" {
			t.Errorf("while one ran: %d generations posted, toast %q", len(w.Posts), w.Toast)
		}
		if len(w.FormAfter) == 0 || w.FormAfter[0] != "Add OAuth login" {
			t.Errorf("the form became %q", w.FormAfter)
		}
	})

	t.Run("a placed plan says where its tasks go", func(t *testing.T) {
		p := got["plan_says_where_its_tasks_go"]
		if p.Summary != "OAuth login in four steps\nEach task runs at priority 2 and waits for #1, #3." {
			t.Errorf("summary %q", p.Summary)
		}
		if p.AfterOnly != "OAuth login in four steps\nEach task waits for #5." {
			t.Errorf("with dependencies alone the summary is %q", p.AfterOnly)
		}
	})

	t.Run("the deferred Split dialog proposes and applies", func(t *testing.T) {
		s := got["split_dialog_is_fetched_and_works"]
		if s.SplitTitle != "Split Task #4" {
			t.Errorf("title %q", s.SplitTitle)
		}
		if !strings.Contains(s.SplitBody, "First &lt;part&gt;") || strings.Contains(s.SplitBody, "First <part>") ||
			!strings.Contains(s.SplitBody, `data-change="toggle"`) || !strings.Contains(s.SplitBody, "est: 30m") {
			t.Errorf("the proposal rendered as %q", s.SplitBody)
		}
		if s.Count != "2/3 selected" || s.Button != "Add 2 sub-tasks" {
			t.Errorf("after dropping one: %q, %q", s.Count, s.Button)
		}
		if len(s.SplitPosts) != 2 {
			t.Fatalf("posted %d requests, want the proposal and the apply: %v", len(s.SplitPosts), s.SplitPosts)
		}
		if !strings.HasPrefix(s.SplitPosts[0].URL, "/api/tasks/4/decompose?") {
			t.Errorf("the proposal went to %q", s.SplitPosts[0].URL)
		}
		wantApply := map[string]any{"subtasks": []any{
			map[string]any{"title": "First <part>", "description": "d1", "role": "backend", "estimated_minutes": 30.0},
			map[string]any{"title": "Third part", "description": "d3", "role": "", "estimated_minutes": 0.0},
		}}
		if !strings.HasPrefix(s.SplitPosts[1].URL, "/api/tasks/4/decompose/apply") || !reflect.DeepEqual(s.SplitPosts[1].Body, wantApply) {
			t.Errorf("the apply posted %v to %q, want %v", s.SplitPosts[1].Body, s.SplitPosts[1].URL, wantApply)
		}
		if s.Toast != "Task #4 split into 2 sub-tasks" {
			t.Errorf("toast %q", s.Toast)
		}
	})

	t.Run("a Split refused for want of a Claude login offers one", func(t *testing.T) {
		s := got["split_refused_for_want_of_a_claude_login"]
		if s.Error != "" {
			t.Fatalf("the scenario threw: %s", s.Error)
		}
		if len(s.SplitPosts) != 1 || s.Closed || s.Toast != "Refused: this sandbox has no usable Claude credential" ||
			!strings.Contains(s.SplitBody, "Split failed") || !strings.Contains(s.SplitBody, "No active grant") {
			t.Errorf("posts %v, Split closed %v, toast %q, body %q: want one proposal asked, the dialog left open "+
				"saying why, and the credential dialog's refusal", s.SplitPosts, s.Closed, s.Toast, s.SplitBody)
		}
	})
}
