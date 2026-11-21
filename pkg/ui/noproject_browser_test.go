package ui

// Browser gate for the no-project navigation (Task 20508): on a hub of several
// projects the per-project tabs, the phone menu's Project section, the back
// arrow and the task-key hints are off screen until a project is opened, from
// the first paint on, and come with the project. noproject_frontend_test.go
// holds the logic; this holds what only a stylesheet in a real browser decides
// — that "hidden" is hidden. See testdata/noproject_browser.js for what is
// driven; skips without Chrome or node, like every browser gate.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
)

// noProjectViewport is a browser window, as chatFitViewport is.
type noProjectViewport struct {
	Name   string  `json:"name"`
	Width  int     `json:"width"`
	Height int     `json:"height"`
	Scale  float64 `json:"scale"`
	Mobile bool    `json:"mobile"`
}

// The first is where the keys, the palette and the clicks are driven: the
// 1920x1200 laptop this hub's desktop sessions come from, less its browser
// bars. Then a small laptop, a tablet (which keeps the tab strip, scrolling)
// and the 360px phone the users' Android sessions report.
var noProjectViewports = []noProjectViewport{
	{Name: "desktop-1920", Width: 1920, Height: 1050, Scale: 1},
	{Name: "laptop-1366", Width: 1366, Height: 625, Scale: 1},
	{Name: "tablet-768", Width: 768, Height: 1024, Scale: 2, Mobile: true},
	{Name: "phone-360", Width: 360, Height: 780, Scale: 3, Mobile: true},
}

// noProjectNav is what the driver reads off the page (NAV in the driver).
type noProjectNav struct {
	InProject     bool     `json:"in_project"`
	Active        string   `json:"active"`
	Strip         []string `json:"strip"`
	StripCovered  []string `json:"strip_covered"`
	StripRows     int      `json:"strip_rows"`
	Menu          []string `json:"menu"`
	Labels        []string `json:"labels"`
	Back          bool     `json:"back"`
	Hints         []string `json:"hints"`
	AddTaskForm   bool     `json:"add_task_form"`
	DangerZone    bool     `json:"danger_zone"`
	ProviderCards bool     `json:"provider_cards"`
	ProjectCaps   bool     `json:"project_caps"`
	GlobalLimits  bool     `json:"global_limits"`
	Selector      string   `json:"selector"`
	Scope         string   `json:"scope"`
	Focus         string   `json:"focus"`
	OverflowX     int      `json:"overflow_x"`
	HeaderHeight  int      `json:"header_height"`
	Search        string   `json:"search"`

	OpenedMenu *noProjectNav `json:"opened_menu"`
}

type noProjectTasks struct {
	Nav    noProjectNav `json:"nav"`
	Titles []string     `json:"titles"`
}

func runNoProjectDriver(t *testing.T, chrome, node, base string, cfg map[string]any, out any) {
	t.Helper()
	cfg["viewports"] = noProjectViewports
	cfg["shots"] = os.Getenv("NOPROJECT_SHOTS")
	var tabs []string
	for _, c := range parseServedNav(t).desktop {
		tabs = append(tabs, c.tab)
	}
	cfg["tabs"] = tabs
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "noproject.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Bounded: a Chrome that stalls must fail this test, not eat the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	stdout, err := exec.CommandContext(ctx, node, mustAbs(t, "testdata/noproject_browser.js"), chrome, base, cfgPath).Output()
	if testing.Verbose() {
		t.Logf("driver output:\n%s", stdout)
	}
	var failed struct {
		Error string `json:"error"`
	}
	if jerr := json.Unmarshal(stdout, &failed); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%s\nstderr:\n%s", err, jerr, stdout, stderr)
	}
	if failed.Error != "" {
		t.Fatalf("the driver reported an error: %s", failed.Error)
	}
	if err := json.Unmarshal(stdout, out); err != nil {
		t.Fatalf("the driver's output does not decode: %v\n%s", err, stdout)
	}
}

// navTabs returns the tabs of the served page in the order it draws them: the
// header strip's, and the phone menu's (which has no Quotas entry), each split
// into a project's and the hub's.
func navTabs(t *testing.T) (stripProject, stripGlobal, menuProject, menuGlobal []string) {
	t.Helper()
	nav := parseServedNav(t)
	for _, c := range nav.desktop {
		if c.projOnly {
			stripProject = append(stripProject, c.tab)
		} else {
			stripGlobal = append(stripGlobal, c.tab)
		}
	}
	for _, c := range nav.mobile {
		if c.projOnly {
			menuProject = append(menuProject, c.tab)
		} else {
			menuGlobal = append(menuGlobal, c.tab)
		}
	}
	if len(stripProject) < 12 || len(stripGlobal) < 6 || len(menuProject) < 12 || len(menuGlobal) < 6 {
		t.Fatalf("the served page's navigation reads as %d+%d strip tabs and %d+%d menu tabs; "+
			"the markup has moved from where this test reads it", len(stripProject), len(stripGlobal), len(menuProject), len(menuGlobal))
	}
	return
}

func concat(a, b []string) []string {
	return append(append([]string(nil), a...), b...)
}

// sameTabs compares two lists of tab names; none is none, however it is spelt
// (the driver's JSON says [], a Go literal nil).
func sameTabs(a, b []string) bool {
	return len(a) == len(b) && (len(a) == 0 || reflect.DeepEqual(a, b))
}

// The footer's hints for the keys that work anywhere, and the ones that act
// on an open project's tasks and tabs.
var (
	noProjectHintsAlways  = []string{"? help", "⌘K palette", "/ search", "r refresh", "t theme", "Esc close"}
	noProjectHintsProject = []string{"jk navigate", "n new task", "1-9 tabs"}
)

// TestNoProjectOpen_PerProjectNavigationIsOffScreenInBrowser drives a hub of
// three projects: with none open nothing per-project is on screen at any
// width, from the first paint; opening a project brings its tabs; leaving it
// takes them away.
func TestNoProjectOpen_PerProjectNavigationIsOffScreenInBrowser(t *testing.T) {
	chrome, node := browserTools(t)
	// A registry of this test's own: the roster is asserted on.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	own := sessionProject(t, "np-own", "np-own-task")
	beta := sessionProject(t, "np-beta", "np-beta-task")
	gamma := sessionProject(t, "np-gamma", "np-gamma-task")

	// Configured before the listener starts: requests from Chrome carry no
	// happens-before edge the race detector can see.
	srv := New(own, 0, "")
	srv.Projects = []string{beta, gamma}
	srv.RPS, srv.Burst = 100000, 100000
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var got struct {
		Held         noProjectNav            `json:"held"`
		Landing      map[string]noProjectNav `json:"landing"`
		KeysNone     noProjectNav            `json:"keys_none"`
		PaletteNone  []string                `json:"palette_none"`
		HelpNone     []string                `json:"help_none"`
		LinkNone     noProjectNav            `json:"link_none"`
		SettingsNone noProjectNav            `json:"settings_none"`
		BudgetNone   noProjectNav            `json:"budget_none"`
		RequestsNone []string                `json:"requests_none"`
		Opened       noProjectNav            `json:"opened"`
		Tasks        noProjectTasks          `json:"tasks"`
		KeysOpen     noProjectNav            `json:"keys_open"`
		PaletteOpen  []string                `json:"palette_open"`
		SettingsOpen noProjectNav            `json:"settings_open"`
		BudgetOpen   noProjectNav            `json:"budget_open"`
		Closed       noProjectNav            `json:"closed"`
		PhoneMenu    noProjectNav            `json:"phone_menu_open"`
		PhoneTasks   noProjectTasks          `json:"phone_tasks"`
	}
	runNoProjectDriver(t, chrome, node, ts.URL, map[string]any{
		"mode": "several",
		"open": map[string]any{"idx": 1, "name": "np-beta", "task": "np-beta-task"},
	}, &got)

	stripProject, stripGlobal, menuProject, menuGlobal := navTabs(t)
	everyStrip, everyMenu := concat(stripProject, stripGlobal), concat(menuProject, menuGlobal)

	// offNothingPerProject is the whole claim for a page with no project open.
	off := func(where string, n noProjectNav, wantStrip []string) {
		t.Helper()
		if n.InProject {
			t.Errorf("%s: <body> carries in-project with no project open", where)
		}
		if !sameTabs(n.Strip, wantStrip) {
			t.Errorf("%s: the tab strip shows %v, want %v — a project's tabs with no project to show", where, n.Strip, wantStrip)
		}
		if len(n.StripCovered) != 0 {
			t.Errorf("%s: these tabs are drawn but cannot be pressed where they are: %v", where, n.StripCovered)
		}
		if n.Back {
			t.Errorf("%s: the back-to-all-projects arrow is on screen with no project to leave", where)
		}
		if n.AddTaskForm {
			t.Errorf("%s: the add-task form is on screen — a task typed there goes to the hub's own project", where)
		}
		for _, l := range n.Labels {
			if l == "Project" {
				t.Errorf("%s: the Project section heading is on screen over no tabs", where)
			}
		}
		if n.OverflowX > 0 {
			t.Errorf("%s: the page is %dpx wider than its window", where, n.OverflowX)
		}
	}

	// From the first paint: while the page does not yet know how many projects
	// the hub has, it must not show a project's tabs it is about to take away.
	off("first paint, the project list not yet answered", got.Held, stripGlobal)

	if len(got.Landing) != len(noProjectViewports) {
		t.Fatalf("the driver measured %d of %d viewports", len(got.Landing), len(noProjectViewports))
	}
	for _, v := range noProjectViewports {
		n, where := got.Landing[v.Name], "the list at "+v.Name
		wantStrip := stripGlobal
		if v.Width < 480 {
			wantStrip = nil // a phone has the menu instead of the strip
		}
		off(where, n, wantStrip)
		if n.Active != "projects" {
			t.Errorf("%s: the tab on screen is %q, want the project list", where, n.Active)
		}
		if n.Selector != "All Projects" {
			t.Errorf("%s: the project selector reads %q, want \"All Projects\"", where, n.Selector)
		}
		// The eight global tabs fit one row once the fifteen are gone.
		if v.Width >= 1366 && n.StripRows != 1 {
			t.Errorf("%s: the tab strip takes %d rows, want 1", where, n.StripRows)
		}
		// The footer is not drawn on a phone; elsewhere it hints only at keys
		// that do something.
		if v.Width >= 768 && !reflect.DeepEqual(n.Hints, noProjectHintsAlways) {
			t.Errorf("%s: the footer hints at %v, want %v", where, n.Hints, noProjectHintsAlways)
		}
		if v.Width < 480 {
			m := n.OpenedMenu
			if m == nil {
				t.Fatalf("%s: the driver did not open the phone's menu", where)
			}
			if !reflect.DeepEqual(m.Menu, menuGlobal) {
				t.Errorf("%s: the menu lists %v, want %v", where, m.Menu, menuGlobal)
			}
			if !reflect.DeepEqual(m.Labels, []string{"Global"}) {
				t.Errorf("%s: the menu's section headings are %v, want Global alone", where, m.Labels)
			}
		}
	}

	// Keys, a link, the palette and the help, with none open.
	off("after pressing 2 and n", got.KeysNone, stripGlobal)
	if got.KeysNone.Active != "projects" || got.KeysNone.Focus == "newTaskTitle" {
		t.Errorf("after pressing 2 and n with no project open: on %q with the caret in %q; want the list, untouched",
			got.KeysNone.Active, got.KeysNone.Focus)
	}
	off("behind /?tab=tasks", got.LinkNone, stripGlobal)
	if got.LinkNone.Active != "projects" || got.LinkNone.Search != "" {
		t.Errorf("/?tab=tasks with no project open: on %q, query %q; want the list and the query dropped",
			got.LinkNone.Active, got.LinkNone.Search)
	}
	var wantNone, wantAll []string
	for _, e := range paletteEntries(t) {
		wantAll = append(wantAll, e.label)
		if e.global {
			wantNone = append(wantNone, e.label)
		}
	}
	if !reflect.DeepEqual(got.PaletteNone, wantNone) {
		t.Errorf("the command palette with no project open lists %v, want %v", got.PaletteNone, wantNone)
	}
	for _, g := range got.HelpNone {
		if strings.HasPrefix(g, "Project") {
			t.Errorf("the shortcut help shows the %q group with no project open (groups: %v)", g, got.HelpNone)
		}
	}
	if len(got.HelpNone) == 0 {
		t.Error("the shortcut help opened empty")
	}
	off("Settings with no project open", got.SettingsNone, stripGlobal)
	if got.SettingsNone.Active != "settings" || got.SettingsNone.DangerZone || got.SettingsNone.ProviderCards {
		t.Errorf("Settings with no project open: on %q, Danger Zone on screen = %v, provider cards on screen = %v; "+
			"both are the open project's, and with none open would be the hub's own",
			got.SettingsNone.Active, got.SettingsNone.DangerZone, got.SettingsNone.ProviderCards)
	}
	off("Budget with no project open", got.BudgetNone, stripGlobal)
	if got.BudgetNone.Active != "budget" || !got.BudgetNone.GlobalLimits || got.BudgetNone.ProjectCaps {
		t.Errorf("Budget with no project open: on %q, the hub's limits on screen = %v, Per-Project Caps on screen = %v; "+
			"want the hub's limits alone — the caps form showed the hub's own project's, and saved to it",
			got.BudgetNone.Active, got.BudgetNone.GlobalLimits, got.BudgetNone.ProjectCaps)
	}
	// Everything the page asked the hub for while no project was open.
	if len(got.RequestsNone) == 0 {
		t.Error("the driver recorded no requests while no project was open; the next check proves nothing")
	}
	if bad := askedOfNoProject(t, got.RequestsNone); len(bad) != 0 {
		t.Errorf("with no project open the page asked the hub for what only a project has — answered, "+
			"with no index, for the hub's own:\n  %s", strings.Join(bad, "\n  "))
	}

	// on is the claim for a page with a project open.
	on := func(where string, n noProjectNav) {
		t.Helper()
		if !n.InProject {
			t.Errorf("%s: <body> lacks in-project with a project open", where)
		}
		if !reflect.DeepEqual(n.Strip, everyStrip) {
			t.Errorf("%s: the tab strip shows %v, want every tab %v", where, n.Strip, everyStrip)
		}
		if len(n.StripCovered) != 0 {
			t.Errorf("%s: these tabs are drawn but cannot be pressed where they are: %v", where, n.StripCovered)
		}
		if !n.Back {
			t.Errorf("%s: the back-to-all-projects arrow is missing", where)
		}
		if !reflect.DeepEqual(n.Hints, concat(noProjectHintsAlways, noProjectHintsProject)) {
			t.Errorf("%s: the footer hints at %v, want the project's keys too", where, n.Hints)
		}
		if n.Selector != "np-beta" {
			t.Errorf("%s: the project selector reads %q, want np-beta", where, n.Selector)
		}
		if n.OverflowX > 0 {
			t.Errorf("%s: the page is %dpx wider than its window", where, n.OverflowX)
		}
	}
	on("after opening np-beta", got.Opened)
	if got.Opened.Active != "overview" {
		t.Errorf("after opening np-beta: on %q, want its Overview", got.Opened.Active)
	}
	on("on np-beta's Tasks tab", got.Tasks.Nav)
	if !reflect.DeepEqual(got.Tasks.Titles, []string{"np-beta-task"}) || !got.Tasks.Nav.AddTaskForm {
		t.Errorf("np-beta's Tasks tab lists %v (add-task form on screen = %v); want its one task and the form",
			got.Tasks.Titles, got.Tasks.Nav.AddTaskForm)
	}
	if got.KeysOpen.Active != "tasks" {
		t.Errorf("1 then 2 with a project open: on %q, want Tasks", got.KeysOpen.Active)
	}
	if !reflect.DeepEqual(got.PaletteOpen, wantAll) {
		t.Errorf("the command palette with a project open lists %v, want every entry %v", got.PaletteOpen, wantAll)
	}
	on("on Settings, from inside np-beta", got.SettingsOpen)
	if got.SettingsOpen.Active != "settings" || !got.SettingsOpen.DangerZone || !got.SettingsOpen.ProviderCards {
		t.Errorf("Settings from inside np-beta: on %q, Danger Zone on screen = %v, provider cards on screen = %v; "+
			"want both offered for the open project",
			got.SettingsOpen.Active, got.SettingsOpen.DangerZone, got.SettingsOpen.ProviderCards)
	}

	on("on Budget, from inside np-beta", got.BudgetOpen)
	if got.BudgetOpen.Active != "budget" || !got.BudgetOpen.GlobalLimits || !got.BudgetOpen.ProjectCaps {
		t.Errorf("Budget from inside np-beta: on %q, the hub's limits on screen = %v, Per-Project Caps on screen = %v; "+
			"want both", got.BudgetOpen.Active, got.BudgetOpen.GlobalLimits, got.BudgetOpen.ProjectCaps)
	}

	off("after the back arrow", got.Closed, stripGlobal)
	if got.Closed.Active != "projects" || got.Closed.Selector != "All Projects" {
		t.Errorf("after the back arrow: on %q, selector %q; want the list", got.Closed.Active, got.Closed.Selector)
	}

	// The phone's menu with the project open, and its Tasks entry pressed.
	if !reflect.DeepEqual(got.PhoneMenu.Menu, everyMenu) {
		t.Errorf("the phone menu with np-beta open lists %v, want %v", got.PhoneMenu.Menu, everyMenu)
	}
	if !reflect.DeepEqual(got.PhoneMenu.Labels, []string{"Project", "Global"}) {
		t.Errorf("the phone menu with np-beta open has the headings %v, want Project and Global", got.PhoneMenu.Labels)
	}
	if got.PhoneTasks.Nav.Active != "tasks" || !reflect.DeepEqual(got.PhoneTasks.Titles, []string{"np-beta-task"}) {
		t.Errorf("Tasks pressed in the phone's menu: on %q listing %v; want np-beta's Tasks",
			got.PhoneTasks.Nav.Active, got.PhoneTasks.Titles)
	}
}

// TestNoProjectOpen_AHubWithOneProjectKeepsItsTabsInBrowser: nothing is taken
// from a hub with one project. Its tabs arrive with the project list's answer
// — until then the page cannot know — and work as they did.
func TestNoProjectOpen_AHubWithOneProjectKeepsItsTabsInBrowser(t *testing.T) {
	chrome, node := browserTools(t)
	t.Setenv(multiui.EnvRoot, t.TempDir())
	own := sessionProject(t, "np-only", "np-only-task")
	srv := New(own, 0, "")
	srv.RPS, srv.Burst = 100000, 100000
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var got struct {
		Held     noProjectNav   `json:"held"`
		Landing  noProjectNav   `json:"landing"`
		Tasks    noProjectTasks `json:"tasks"`
		Projects noProjectNav   `json:"projects"`
	}
	runNoProjectDriver(t, chrome, node, ts.URL, map[string]any{"mode": "one"}, &got)

	stripProject, stripGlobal, _, _ := navTabs(t)
	every := concat(stripProject, stripGlobal)

	if !reflect.DeepEqual(got.Held.Strip, stripGlobal) {
		t.Errorf("before the project list answered, the strip showed %v, want the global tabs %v", got.Held.Strip, stripGlobal)
	}
	for where, n := range map[string]noProjectNav{"once booted": got.Landing, "on its Tasks tab": got.Tasks.Nav, "on its Projects tab": got.Projects} {
		if !n.InProject || !reflect.DeepEqual(n.Strip, every) {
			t.Errorf("a hub with one project, %s: in-project = %v, strip %v; want every tab %v", where, n.InProject, n.Strip, every)
		}
		if len(n.StripCovered) != 0 {
			t.Errorf("a hub with one project, %s: tabs drawn but covered: %v", where, n.StripCovered)
		}
		if !reflect.DeepEqual(n.Hints, concat(noProjectHintsAlways, noProjectHintsProject)) {
			t.Errorf("a hub with one project, %s: the footer hints at %v", where, n.Hints)
		}
	}
	if got.Landing.Active != "overview" {
		t.Errorf("a hub with one project lands on %q, want its Overview", got.Landing.Active)
	}
	if got.Tasks.Nav.Active != "tasks" || !reflect.DeepEqual(got.Tasks.Titles, []string{"np-only-task"}) {
		t.Errorf("its Tasks tab: on %q listing %v", got.Tasks.Nav.Active, got.Tasks.Titles)
	}
	if got.Projects.Active != "projects" {
		t.Errorf("its Projects tab: on %q", got.Projects.Active)
	}
}
