package ui

// A hub that lists several projects, with none of them opened (Task 20508).
//
// The report: "it is unintuitive that tasks are empty if no project has been
// selected yet … menu items whose view only makes sense if a project has been
// selected, such as Tasks and others, should be hidden."
//
// What was behind it is worse than an empty list. A request that names no
// project is answered for the hub's own (resolveWorkDir), so with the Project
// tabs on screen and nothing selected:
//
//   - Tasks showed "No tasks yet" — and a task typed into its form was added
//     to the hub's own project, where the list on screen never showed it;
//   - Requirements read that project's requirements and asked its executor
//     for the spec file; Knowledge Base, Chat and Analytics read it too;
//   - the palette's Start run and Stop run started and stopped its run;
//   - under single sign-on that project may be one the viewer cannot see.
//
// Nothing per-project is offered now until a project is open. Three layers,
// each tested here or in noproject_browser_test.go:
//
//   - the markup marks what is per-project (class proj-only) and one CSS rule
//     hides all of it unless <body> carries in-project — this file's first
//     test holds the markup, the stylesheet and the bundle's GLOBAL_TABS to
//     one another, so a tab added later cannot be left unclassified;
//   - switchTab refuses a per-project tab while none is open, which covers
//     every way in that is not a button: a link, a resumed view, a key;
//   - the command palette and the shortcut help list only what can be done.
//
// The scenarios run the real bundle in node against testdata/domshim.js; see
// testdata/noproject_scenarios.js for what each one does.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/html"
)

// navControl is one tab button of the served page.
type navControl struct {
	id       string
	tab      string // data-arg
	classes  []string
	projOnly bool // inside (or itself) class proj-only
}

func hasClass(classes []string, c string) bool {
	for _, x := range classes {
		if x == c {
			return true
		}
	}
	return false
}

func attrOf(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func textOf(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		b.WriteString(textOf(c))
	}
	return b.String()
}

// servedNav parses the page a browser is served and returns what the
// no-project rule is about: the tab buttons of the header strip and of the
// phone's menu, every element by id with whether it is per-project, the tab
// panels, and the section labels with their text.
type servedNav struct {
	desktop, mobile []navControl
	panels          []string
	projOnlyByID    map[string]bool
	labels          map[string]bool // "desktop:Project" → proj-only?
	footerHints     map[string]bool // hint text → proj-only?
	bodyClasses     []string
}

func parseServedNav(t *testing.T) servedNav {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(loadAssets().servedPage))
	if err != nil {
		t.Fatalf("the served page does not parse: %v", err)
	}
	out := servedNav{projOnlyByID: map[string]bool{}, labels: map[string]bool{}, footerHints: map[string]bool{}}
	var walk func(n *html.Node, projOnly bool, within string)
	walk = func(n *html.Node, projOnly bool, within string) {
		if n.Type == html.ElementNode {
			classes := strings.Fields(attrOf(n, "class"))
			id := attrOf(n, "id")
			projOnly = projOnly || hasClass(classes, "proj-only")
			switch id {
			case "tabNav":
				within = "desktop"
			case "mobileNavOverlay":
				within = "mobile"
			case "kb-footer":
				within = "footer"
			}
			if n.Data == "body" {
				out.bodyClasses = classes
			}
			if id != "" {
				out.projOnlyByID[id] = projOnly
				if strings.HasPrefix(id, "tab-") && hasClass(classes, "tab-panel") {
					out.panels = append(out.panels, strings.TrimPrefix(id, "tab-"))
				}
			}
			if attrOf(n, "data-action") == "switchTab" && (within == "desktop" || within == "mobile") {
				c := navControl{id: id, tab: attrOf(n, "data-arg"), classes: classes, projOnly: projOnly}
				if within == "desktop" {
					out.desktop = append(out.desktop, c)
				} else {
					out.mobile = append(out.mobile, c)
				}
			}
			if hasClass(classes, "tab-section-label") || hasClass(classes, "mobile-nav-section-label") {
				out.labels[within+":"+strings.TrimSpace(textOf(n))] = projOnly
			}
			// A footer hint is a span holding a <kbd>; its words are what it says.
			if within == "footer" && n.Data == "span" && !hasClass(classes, "kb-sep") && !hasClass(classes, "proj-only") && id == "" {
				words := strings.Join(strings.Fields(textOf(n)), " ")
				if words != "" {
					out.footerHints[words] = projOnly
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, projOnly, within)
		}
	}
	walk(doc, false, "")
	return out
}

// TestDashboard_PerProjectNavigationIsMarked holds the three places that say
// which tabs are a project's to one another: the bundle's GLOBAL_TABS (what
// switchTab refuses without a project, what the scope badge reads), the
// markup's global-tab class (how a tab is drawn) and its proj-only wrappers
// (what the stylesheet hides without a project). They are three files, and a
// tab added to one and not the others is either offered with no project to
// show or hidden for good.
func TestDashboard_PerProjectNavigationIsMarked(t *testing.T) {
	set := loadAssets()
	global := globalTabsOf(set.bundle)
	if len(global) < 6 {
		t.Fatalf("GLOBAL_TABS = %v; 00-core.js no longer declares it as this test reads it", global)
	}
	isGlobal := map[string]bool{}
	for _, g := range global {
		isGlobal[g] = true
	}

	nav := parseServedNav(t)
	if len(nav.desktop) < 20 || len(nav.mobile) < 20 || len(nav.panels) < 20 {
		t.Fatalf("read %d header tabs, %d menu tabs and %d panels from the served page; "+
			"the dashboard has 23, so the markup has moved from where this test reads it",
			len(nav.desktop), len(nav.mobile), len(nav.panels))
	}

	// The page starts with nothing per-project on offer: the class is syncNav's
	// to set once it knows a project is in view.
	if hasClass(nav.bodyClasses, "in-project") {
		t.Error("<body> is served with class in-project: on a hub of several projects the Project " +
			"tabs would paint first and vanish once the project list arrives")
	}

	seen := map[string]bool{}
	for where, controls := range map[string][]navControl{"the header's tab strip": nav.desktop, "the phone's menu": nav.mobile} {
		for _, c := range controls {
			if where == "the header's tab strip" {
				seen[c.tab] = true
				if hasClass(c.classes, "global-tab") != isGlobal[c.tab] {
					t.Errorf("%s: tab %q has class global-tab = %v, but GLOBAL_TABS lists it = %v",
						where, c.tab, hasClass(c.classes, "global-tab"), isGlobal[c.tab])
				}
			}
			switch {
			case isGlobal[c.tab] && c.projOnly:
				t.Errorf("%s: the global tab %q (#%s) is inside a proj-only element — it would be "+
					"hidden until a project is opened", where, c.tab, c.id)
			case !isGlobal[c.tab] && !c.projOnly:
				t.Errorf("%s: the per-project tab %q (#%s) is not inside a proj-only element — it is "+
					"offered with no project open, and pressing it does nothing", where, c.tab, c.id)
			}
		}
	}

	// Every panel is one or the other, and reachable from the strip.
	for _, p := range nav.panels {
		if !seen[p] {
			t.Errorf("panel tab-%s has no button in the header's tab strip, so nothing says whether "+
				"it is a project's tab or the hub's", p)
		}
	}
	for _, g := range global {
		if !seen[g] {
			t.Errorf("GLOBAL_TABS lists %q, which the header's tab strip does not draw", g)
		}
	}

	// The section headings go with their sections.
	for label, want := range map[string]bool{
		"desktop:Project": true, "desktop:Global": false,
		"mobile:Project": true, "mobile:Global": false,
	} {
		got, ok := nav.labels[label]
		if !ok {
			t.Errorf("no %q section label in the served page", label)
		} else if got != want {
			t.Errorf("section label %q: per-project = %v, want %v", label, got, want)
		}
	}

	// The header's back arrow leaves a project; with none open there is none
	// to leave.
	if !nav.projOnlyByID["projBackBtn"] {
		t.Error("#projBackBtn (back to all projects) is offered with no project open")
	}
	// The selector itself is how a project is picked: always there.
	for _, id := range []string{"projSelectorBtn", "hamburgerBtn", "tbtn-projects", "mtbtn-projects"} {
		if nav.projOnlyByID[id] {
			t.Errorf("#%s is per-project, so a page with no project open could not open one", id)
		}
	}

	// The footer's key hints: the keys that act on a project's tasks and tabs
	// are hinted only with one open.
	wantHints := map[string]bool{
		"? help": false, "⌘K palette": false, "/ search": false, "r refresh": false, "t theme": false, "Esc close": false,
		"jk navigate": true, "n new task": true, "1-9 tabs": true,
	}
	if !reflect.DeepEqual(nav.footerHints, wantHints) {
		t.Errorf("the footer's key hints, each with whether it is per-project:\n got  %v\n want %v", nav.footerHints, wantHints)
	}

	// The one rule that does the hiding, in the stylesheet as served. It has
	// to be !important: the footer's wrapper is display:contents by a rule
	// with an id in its selector, which would otherwise win.
	hide := regexp.MustCompile(`body:not\(\.in-project\)\s+\.proj-only\s*\{\s*display:\s*none\s*!important;?\s*\}`)
	if !hide.MatchString(set.servedCSS) {
		t.Error("app.css no longer hides .proj-only while <body> lacks in-project " +
			"(body:not(.in-project) .proj-only { display: none !important })")
	}
	// And the two wrappers that are not boxes of their own.
	for _, sel := range []string{".mobile-nav-panel .proj-only", "#kb-footer .proj-only"} {
		if !regexp.MustCompile(regexp.QuoteMeta(sel) + `[^{}]*\{\s*display:\s*contents`).MatchString(set.servedCSS) {
			t.Errorf("app.css no longer lays %s out as display: contents — its children would lose "+
				"the gaps their container gives them", sel)
		}
	}
}

// paletteEntry is one line of the bundle's CMD_REGISTRY.
type paletteEntry struct {
	label, action string
	global        bool
}

func paletteEntries(t *testing.T) []paletteEntry {
	t.Helper()
	bundle := loadAssets().bundle
	start := strings.Index(bundle, "const CMD_REGISTRY = [")
	if start < 0 {
		t.Fatal("18-shortcuts.js no longer declares CMD_REGISTRY; this gate reads it")
	}
	end := strings.Index(bundle[start:], "\n];")
	if end < 0 {
		t.Fatal("CMD_REGISTRY is not closed")
	}
	entry := regexp.MustCompile(`^\s*\{\s*(g:1,\s*)?label:'([^']*)'.*action:\s*\(\)\s*=>(.*)\},?\s*$`)
	var out []paletteEntry
	for _, line := range strings.Split(bundle[start:start+end], "\n")[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := entry.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("a CMD_REGISTRY line this gate cannot read (one entry per line, g:1 first):\n%s", line)
		}
		out = append(out, paletteEntry{label: m[2], action: m[3], global: m[1] != ""})
	}
	if len(out) < 20 {
		t.Fatalf("read %d palette entries; the registry has ~26, so this gate has gone vacuous", len(out))
	}
	return out
}

// TestCommandPaletteMarksWhatNeedsAProject reads the palette's registry: an
// entry is offered with no project open exactly when it is marked g, so the
// mark has to agree with what the entry does. Start run and Stop run are the
// ones that matter most — chosen with nothing selected they acted on the
// hub's own project.
func TestCommandPaletteMarksWhatNeedsAProject(t *testing.T) {
	isGlobal := map[string]bool{}
	for _, g := range globalTabsOf(loadAssets().bundle) {
		isGlobal[g] = true
	}
	// What an action does that only makes sense inside a project.
	perProject := regexp.MustCompile(`apiRun\(|apiStop\(|confirmReset|newTaskTitle|suggestPanel`)
	tabOf := regexp.MustCompile(`switchTab\('([a-z0-9-]+)'\)`)

	var offered []string
	for _, e := range paletteEntries(t) {
		needs := perProject.MatchString(e.action)
		for _, m := range tabOf.FindAllStringSubmatch(e.action, -1) {
			if !isGlobal[m[1]] {
				needs = true
			}
		}
		if needs && e.global {
			t.Errorf("palette entry %q is marked g (offered with no project open) but acts on a project: %s",
				e.label, strings.TrimSpace(e.action))
		}
		if !needs && !e.global {
			t.Errorf("palette entry %q needs no project but is not marked g, so it is withheld "+
				"until one is open: %s", e.label, strings.TrimSpace(e.action))
		}
		if e.global {
			offered = append(offered, e.label)
		}
	}
	if len(offered) < 6 {
		t.Errorf("only %v would be offered with no project open; the palette would open nearly empty", offered)
	}
}

// ── scenarios ───────────────────────────────────────────────────────────────

type noProjectView struct {
	Tab       string   `json:"tab"`
	InProject bool     `json:"in_project"`
	Socket    string   `json:"socket"`
	Requests  []string `json:"requests"`
	Rendered  []int    `json:"rendered"`
	Toast     string   `json:"toast"`
	Focus     string   `json:"focus"`
}

type noProjectHelp struct {
	Groups          []string `json:"groups"`
	MentionsNewTask bool     `json:"mentionsNewTask"`
	MentionsTabs    bool     `json:"mentionsTabs"`
}

// The scenarios run once for the tests that read them: they are one node
// process over one bundle, and each test judges a different part of its answer.
var noProjectScenarios struct {
	once sync.Once
	raw  map[string]json.RawMessage
	skip string
	fail string
}

func runNoProjectScenarios(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	s := &noProjectScenarios
	s.once.Do(func() { s.raw, s.skip, s.fail = noProjectScenarioRun(t) })
	if s.skip != "" {
		t.Skip(s.skip)
	}
	if s.fail != "" {
		t.Fatal(s.fail)
	}
	return s.raw
}

// noProjectScenarioRun runs testdata/noproject_scenarios.js and returns its
// answer by scenario, or why the tests must skip or fail. It reports rather
// than fails, because its caller runs it under a sync.Once: a t.Fatal inside
// one would end that test only, and leave the others an empty answer.
func noProjectScenarioRun(t *testing.T) (raw map[string]json.RawMessage, skip, fail string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		return nil, "node not installed; cannot drive the bundle", ""
	}
	set := loadAssets()

	// The tabs as the served page draws them, split by the bundle's own list:
	// the scenarios walk every one, so a tab added later is walked too.
	isGlobal := map[string]bool{}
	global := globalTabsOf(set.bundle)
	for _, g := range global {
		isGlobal[g] = true
	}
	var project []string
	for _, p := range parseServedNav(t).panels {
		if !isGlobal[p] {
			project = append(project, p)
		}
	}
	if len(project) < 12 || len(global) < 6 {
		return nil, "", fmt.Sprintf("found %d per-project and %d global tabs; the dashboard has 15 and 8", len(project), len(global))
	}

	// Not t.TempDir: the directory is made by whichever test gets here first
	// and read by the node process only, which has exited before this returns.
	dir, err := os.MkdirTemp("", "cloop-noproject-*")
	if err != nil {
		return nil, "", err.Error()
	}
	defer os.RemoveAll(dir)
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(set.bundle), 0o644); err != nil {
		return nil, "", err.Error()
	}
	cfg, _ := json.Marshal(map[string][]string{"project_tabs": project, "global_tabs": global})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		return nil, "", err.Error()
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		return nil, "", err.Error()
	}
	scenarios, err := filepath.Abs("testdata/noproject_scenarios.js")
	if err != nil {
		return nil, "", err.Error()
	}
	cmd := exec.Command(node, scenarios, shim, bundle, cfgPath)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		return nil, "", fmt.Sprintf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, "", fmt.Sprintf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, doc := range raw {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(doc, &e) == nil && e.Error != "" {
			return nil, "", fmt.Sprintf("scenario %s threw: %s", name, e.Error)
		}
	}
	return raw, "", ""
}

func decodeScenario(t *testing.T, raw map[string]json.RawMessage, name string, into any) {
	t.Helper()
	doc, ok := raw[name]
	if !ok {
		t.Fatalf("scenario %s did not run", name)
	}
	if err := json.Unmarshal(doc, into); err != nil {
		t.Fatalf("scenario %s: %v\n%s", name, err, doc)
	}
}

// scopedRequest is a request to a route whose project the hub works out from
// ?project_idx (scopeProject in the route table), and whether it named one.
type scopedRequest struct {
	req, pattern string
	named        bool
}

// projectScopedRequests picks, from requests written "/api/x?…" (a GET) or
// "POST /api/x?…", the ones the hub answers for one project — by the hub's own
// route table, so a route added later is classified as it declares itself.
func projectScopedRequests(t *testing.T, reqs []string) []scopedRequest {
	t.Helper()
	mux := http.NewServeMux()
	specs := map[string]routeSpec{}
	for _, rs := range (&Server{}).routeTable() {
		specs[rs.Pattern] = rs
		mux.HandleFunc(rs.Pattern, func(http.ResponseWriter, *http.Request) {})
	}
	var out []scopedRequest
	for _, r := range reqs {
		method, target := http.MethodGet, r
		if i := strings.IndexByte(r, ' '); i > 0 {
			method, target = r[:i], r[i+1:]
		}
		req, err := http.NewRequest(method, "http://hub"+target, nil)
		if err != nil {
			t.Fatalf("the page's request %q does not parse: %v", r, err)
		}
		_, pattern := mux.Handler(req)
		if rs, ok := specs[pattern]; ok && rs.Scope == scopeProject {
			out = append(out, scopedRequest{req: r, pattern: pattern, named: req.URL.Query().Get("project_idx") != ""})
		}
	}
	return out
}

// askedOfNoProjectByDesign are the project-scoped routes the page asks without
// naming a project on purpose, each with why the hub's own project is the
// right one to answer. They predate Task 20508 and are about the hub. Anything
// else asked that way with no project open is what that task removed: a
// request for a project nobody chose.
var askedOfNoProjectByDesign = map[string]string{
	"GET /api/dictate": "first paint asks whether the hub holds a speech-to-text key; the key is the hub's",
	"GET /api/budget":  "Budget's hub-wide limits and spend come in one answer with a project's caps, whose form is hidden while none is open",
}

// askedOfNoProject returns the requests among reqs that went to a
// project-scoped route and named no project: the hub answers those for its own
// project (resolveWorkDir), so with no project open on a hub of several none
// may be made but the few in askedOfNoProjectByDesign.
func askedOfNoProject(t *testing.T, reqs []string) []string {
	t.Helper()
	var out []string
	for _, r := range projectScopedRequests(t, reqs) {
		if _, ok := askedOfNoProjectByDesign[r.pattern]; !r.named && !ok {
			out = append(out, r.req)
		}
	}
	return out
}

// TestAskedOfNoProjectReadsTheRouteTable keeps the classifier honest: it has
// to flag what the task was about, and only that.
func TestAskedOfNoProjectReadsTheRouteTable(t *testing.T) {
	flagged := askedOfNoProject(t, []string{
		"/api/state", "POST /api/task/add", "POST /api/stop", "POST /api/run", "/api/requirements",
		"/api/kb", "/api/event-history?after=1,0&limit=500", "POST /api/reset", "/api/config",
		"POST /api/config/set", "PUT /api/budget/project", "/api/claudecode-limits", "/api/disk-usage",
	})
	if len(flagged) != 13 {
		t.Errorf("of thirteen requests for a project that name none, the classifier flags %v", flagged)
	}
	clean := []string{
		"/api/state?project_idx=2", "POST /api/stop?project_idx=0", // name their project
		"/api/projects", "/api/me", "/api/executors", "/api/approvals/count", "/api/hub/health?summary=1", // the hub's
		"/api/dictate", "/api/budget", // by design
	}
	if got := askedOfNoProject(t, clean); len(got) != 0 {
		t.Errorf("the classifier flags %v, which name their project or are about the hub", got)
	}
	for pattern, why := range askedOfNoProjectByDesign {
		found := false
		for _, rs := range (&Server{}).routeTable() {
			found = found || (rs.Pattern == pattern && rs.Scope == scopeProject)
		}
		if !found {
			t.Errorf("askedOfNoProjectByDesign excuses %q (%s), which is not a project-scoped route any more", pattern, why)
		}
	}
}

// TestDashboard_NoProjectOpen_NothingPerProjectIsReachable walks every way
// into a project's tab on a hub of several with none opened.
func TestDashboard_NoProjectOpen_NothingPerProjectIsReachable(t *testing.T) {
	t.Parallel()
	raw := runNoProjectScenarios(t)

	// First paint: the list, the navigation off, a stream that asked for no
	// project, and no project's state read.
	var landing noProjectView
	decodeScenario(t, raw, "landing", &landing)
	if landing.Tab != "projects" || landing.InProject {
		t.Errorf("first paint: on tab %q with the per-project navigation on = %v; want the project list and off",
			landing.Tab, landing.InProject)
	}
	if !strings.Contains(landing.Socket, "scope=global") {
		t.Errorf("first paint: the stream is %q, want one that asks for no project (scope=global)", landing.Socket)
	}
	if !containsString(landing.Requests, "/api/me") || !containsString(landing.Requests, "/api/dictate") {
		t.Fatalf("first paint asked for %v: without /api/me and /api/dictate the scenario is not the page's "+
			"whole first paint, and the next check proves less than it says", landing.Requests)
	}
	if got := askedOfNoProject(t, landing.Requests); len(got) != 0 {
		t.Errorf("first paint asked the hub for a project nobody opened: %v", got)
	}

	// Before the list answers the page cannot tell one project from several,
	// and must not guess "one": a key or a call for a project's tab in that
	// window opened it on the hub's own project.
	var early struct {
		Held       noProjectView `json:"held"`
		ProjectTab noProjectView `json:"project_tab"`
		GlobalTab  noProjectView `json:"global_tab"`
		Answered   noProjectView `json:"answered"`
	}
	decodeScenario(t, raw, "before_the_list_answers", &early)
	if early.Held.InProject || early.Held.Socket != "" {
		t.Errorf("before the project list answered: navigation on = %v, stream %q; want off, and no stream — "+
			"one opened now is the hub's own project's", early.Held.InProject, early.Held.Socket)
	}
	if early.ProjectTab.Tab == "tasks" || early.ProjectTab.InProject {
		t.Errorf("2, n and a call for Tasks before the project list answered: on %q, navigation on = %v; "+
			"want nothing to happen", early.ProjectTab.Tab, early.ProjectTab.InProject)
	}
	if got := askedOfNoProject(t, early.ProjectTab.Requests); len(got) != 0 {
		t.Errorf("before the project list answered the page asked for a project: %v", got)
	}
	if early.GlobalTab.Tab != "settings" || early.GlobalTab.InProject {
		t.Errorf("Settings, pressed before the project list answered: on %q, navigation on = %v; want Settings "+
			"with the navigation still off", early.GlobalTab.Tab, early.GlobalTab.InProject)
	}
	if got := askedOfNoProject(t, early.GlobalTab.Requests); len(got) != 0 {
		t.Errorf("Settings, opened before the project list answered, asked for a project: %v", got)
	}
	if early.Answered.Tab != "projects" || early.Answered.InProject || !strings.Contains(early.Answered.Socket, "scope=global") {
		t.Errorf("once the list answered: on %q, navigation on = %v, stream %q; want the list of a hub of several",
			early.Answered.Tab, early.Answered.InProject, early.Answered.Socket)
	}

	// Every per-project tab, by its button's action.
	var refused struct {
		noProjectView
		Opened  []string `json:"opened"`
		Scripts []string `json:"scripts"`
	}
	decodeScenario(t, raw, "tabs_refused", &refused)
	if len(refused.Opened) != 0 {
		t.Errorf("with no project open these per-project tabs opened anyway: %v", refused.Opened)
	}
	if refused.Tab != "projects" || refused.InProject {
		t.Errorf("after asking for every per-project tab: on %q, navigation on = %v", refused.Tab, refused.InProject)
	}
	if got := askedOfNoProject(t, refused.Requests); len(got) != 0 {
		t.Errorf("a refused tab still asked the hub for something — answered for the hub's own project: %v", got)
	}
	if len(refused.Scripts) != 0 {
		t.Errorf("a refused tab still fetched its script: %v", refused.Scripts)
	}

	// The global tabs are not caught by the refusal.
	var globals struct {
		Reached []string `json:"reached"`
		Offered []bool   `json:"offered"`
	}
	decodeScenario(t, raw, "global_tabs_open", &globals)
	want := globalTabsOf(loadAssets().bundle)
	if !reflect.DeepEqual(globals.Reached, want) {
		t.Errorf("the global tabs reached with no project open: %v, want each of %v in turn", globals.Reached, want)
	}
	for i, on := range globals.Offered {
		if on {
			t.Errorf("opening the global tab %q turned the per-project navigation on", want[i])
		}
	}

	// Links.
	var link struct {
		noProjectView
		Replaced   []string `json:"replaced"`
		Badge      string   `json:"badge"`
		Breadcrumb string   `json:"breadcrumb"`
	}
	decodeScenario(t, raw, "link_to_a_project_tab", &link)
	if link.Tab != "projects" || link.InProject {
		t.Errorf("/?tab=tasks with no project: on %q, navigation on = %v; want the project list", link.Tab, link.InProject)
	}
	if got := askedOfNoProject(t, link.Requests); len(got) != 0 {
		t.Errorf("/?tab=tasks with no project asked for: %v", got)
	}
	if len(link.Replaced) != 1 {
		t.Errorf("/?tab=tasks: the query was rewritten %d times (%v), want once — a reload must not ask again", len(link.Replaced), link.Replaced)
	}
	link.Tab, link.InProject = "", false
	decodeScenario(t, raw, "link_to_a_global_tab", &link)
	if link.Tab != "settings" || link.InProject {
		t.Errorf("/?tab=settings: on %q, navigation on = %v; want Settings with the navigation off", link.Tab, link.InProject)
	}
	link = struct {
		noProjectView
		Replaced   []string `json:"replaced"`
		Badge      string   `json:"badge"`
		Breadcrumb string   `json:"breadcrumb"`
	}{}
	decodeScenario(t, raw, "link_to_a_project_and_tab", &link)
	if link.Tab != "tasks" || !link.InProject || !strings.Contains(link.Socket, "project_idx=1") ||
		!reflect.DeepEqual(link.Rendered, []int{201, 202}) {
		t.Errorf("/?project=/srv/beta&tab=tasks: on %q, navigation on = %v, stream %q, tasks %v; "+
			"want beta's Tasks tab", link.Tab, link.InProject, link.Socket, link.Rendered)
	}
	if len(link.Replaced) != 1 {
		t.Errorf("/?project=…&tab=tasks rewrote the address %d times (%v), want once", len(link.Replaced), link.Replaced)
	}
	if link.Badge != "Project" || link.Breadcrumb != "flex" {
		t.Errorf("/?project=/srv/beta&tab=tasks: the header's badge reads %q and its breadcrumb is %q; want "+
			"\"Project\" and shown — the Projects tab that opened the project must not put its own back over it",
			link.Badge, link.Breadcrumb)
	}
	link.Tab, link.Badge = "", ""
	decodeScenario(t, raw, "link_to_a_project", &link)
	if link.Tab != "overview" || link.Badge != "Project" {
		t.Errorf("/?project=/srv/beta: on %q with the badge %q; want its Overview, badged Project", link.Tab, link.Badge)
	}

	// A view resumed after a sign-in.
	var resumed noProjectView
	decodeScenario(t, raw, "resume_without_the_project", &resumed)
	if resumed.Tab != "projects" || resumed.InProject {
		t.Errorf("resuming the Tasks tab of a project that is gone: on %q, navigation on = %v; want the list",
			resumed.Tab, resumed.InProject)
	}
	resumed = noProjectView{}
	decodeScenario(t, raw, "resume_with_the_project", &resumed)
	if resumed.Tab != "tasks" || !resumed.InProject || !strings.Contains(resumed.Socket, "project_idx=2") {
		t.Errorf("resuming gamma's Tasks tab: on %q, navigation on = %v, stream %q", resumed.Tab, resumed.InProject, resumed.Socket)
	}

	// Keys.
	var keys struct {
		None        noProjectView `json:"none"`
		RefreshNone noProjectView `json:"refresh_none"`
		Open        noProjectView `json:"open"`
		RefreshOpen noProjectView `json:"refresh_open"`
	}
	decodeScenario(t, raw, "keys", &keys)
	// (The header's approvals badge asks for its count a moment after the
	// stream opens; that is the hub's, and may fall in any of these windows.)
	if got := askedOfNoProject(t, keys.None.Requests); keys.None.Tab != "projects" || len(got) != 0 {
		t.Errorf("2, n and 5 with no project open: on %q after requests %v; want nothing to happen",
			keys.None.Tab, got)
	}
	if keys.None.Focus == "newTaskTitle" {
		t.Error("n with no project open put the caret in the add-task title, on a tab that is not on screen")
	}
	if got := askedOfNoProject(t, keys.RefreshNone.Requests); len(got) != 0 ||
		!containsString(keys.RefreshNone.Requests, "/api/projects") || keys.RefreshNone.Toast != "Refreshed" {
		t.Errorf("r with no project open asked for %v and said %q; want the project list, no project's state, "+
			"and \"Refreshed\" — it used to download the hub's own project's state",
			keys.RefreshNone.Requests, keys.RefreshNone.Toast)
	}
	if keys.Open.Tab != "tasks" || !reflect.DeepEqual(keys.Open.Rendered, []int{201, 202}) {
		t.Errorf("2 with beta open: on %q showing tasks %v; want beta's Tasks tab", keys.Open.Tab, keys.Open.Rendered)
	}
	if got := projectScopedRequests(t, keys.RefreshOpen.Requests); len(got) != 1 || got[0].req != "/api/state?project_idx=1" {
		t.Errorf("r with beta open asked for %v, want beta's state", keys.RefreshOpen.Requests)
	}
}

// TestDashboard_NoProjectOpen_NavigationFollowsTheProject: the per-project
// navigation is on exactly while a project is in view.
func TestDashboard_NoProjectOpen_NavigationFollowsTheProject(t *testing.T) {
	t.Parallel()
	raw := runNoProjectScenarios(t)

	var oc struct {
		Before   noProjectView `json:"before"`
		Opened   noProjectView `json:"opened"`
		Tasks    noProjectView `json:"tasks"`
		Settings noProjectView `json:"settings"`
		Closed   noProjectView `json:"closed"`
		After    noProjectView `json:"after"`
	}
	decodeScenario(t, raw, "open_then_close", &oc)
	if oc.Before.InProject || oc.Before.Tab != "projects" {
		t.Errorf("before a project is opened: on %q, navigation on = %v", oc.Before.Tab, oc.Before.InProject)
	}
	if !oc.Opened.InProject || oc.Opened.Tab != "overview" || !strings.Contains(oc.Opened.Socket, "project_idx=1") {
		t.Errorf("after opening beta: on %q, navigation on = %v, stream %q; want its Overview with the navigation on",
			oc.Opened.Tab, oc.Opened.InProject, oc.Opened.Socket)
	}
	if oc.Tasks.Tab != "tasks" || !reflect.DeepEqual(oc.Tasks.Rendered, []int{201, 202}) {
		t.Errorf("beta's Tasks tab: on %q showing %v, want its two tasks", oc.Tasks.Tab, oc.Tasks.Rendered)
	}
	if oc.Settings.Tab != "settings" || !oc.Settings.InProject {
		t.Errorf("Settings, visited from inside beta: on %q, navigation on = %v; the project is still open, "+
			"so its tabs must stay", oc.Settings.Tab, oc.Settings.InProject)
	}
	if oc.Closed.InProject || oc.Closed.Tab != "projects" || !strings.Contains(oc.Closed.Socket, "scope=global") {
		t.Errorf("after going back to the list: on %q, navigation on = %v, stream %q", oc.Closed.Tab, oc.Closed.InProject, oc.Closed.Socket)
	}
	if got := askedOfNoProject(t, oc.After.Requests); oc.After.Tab != "projects" || len(got) != 0 {
		t.Errorf("the Tasks tab, asked for after the project was closed: on %q after requests %v", oc.After.Tab, got)
	}

	// The back arrow, pressed from the keyboard, leaves the caret on the selector.
	var back struct {
		Tab   string `json:"tab"`
		Focus string `json:"focus"`
	}
	decodeScenario(t, raw, "back_arrow_keeps_the_caret", &back)
	if back.Tab != "projects" || back.Focus != "projSelectorBtn" {
		t.Errorf("after the back arrow, pressed from the keyboard: on %q with the caret on %q; want the list with the "+
			"caret on the project selector — the arrow itself is gone", back.Tab, back.Focus)
	}

	// A state document that arrives after its project closed is not adopted.
	var late struct {
		Idle            bool `json:"idle"`
		TakenWhileOpen  bool `json:"taken_while_open"`
		IdleAgain       bool `json:"idle_again"`
		TakenAfterClose bool `json:"taken_after_close"`
	}
	decodeScenario(t, raw, "late_state", &late)
	if late.Idle || !late.TakenWhileOpen || late.IdleAgain {
		t.Fatalf("the scenario's control is off: the Stop button showed %v idle, %v after a running state "+
			"arrived with the project open, %v idle again; want false, true, false", late.Idle, late.TakenWhileOpen, late.IdleAgain)
	}
	if late.TakenAfterClose {
		t.Error("a state document that arrived after its project was closed was taken as the page's state " +
			"(its Stop button came up): with no project open, a state is nobody's")
	}

	// A hub with one project: nothing changes for it.
	var one struct {
		noProjectView
		Tasks noProjectView `json:"tasks"`
	}
	decodeScenario(t, raw, "one_project", &one)
	if !one.InProject || one.Tab != "overview" || strings.Contains(one.Socket, "scope=global") {
		t.Errorf("a hub with one project: on %q, navigation on = %v, stream %q; its project is in view once "+
			"its list has said so", one.Tab, one.InProject, one.Socket)
	}
	if one.Tasks.Tab != "tasks" || !reflect.DeepEqual(one.Tasks.Rendered, []int{101, 102}) {
		t.Errorf("a hub with one project: the Tasks tab is %q showing %v", one.Tasks.Tab, one.Tasks.Rendered)
	}
}

// TestDashboard_NoProjectOpen_TheProjectListDecides: whether a project is in
// view without being picked follows from the hub's project list, and from
// nothing else — not from a list that has not answered, could not be read or
// was an error, and not from how long a list is. When the answer changes under
// the page, the page changes sides whole: its stream, what it has drawn and
// what it offers.
func TestDashboard_NoProjectOpen_TheProjectListDecides(t *testing.T) {
	t.Parallel()
	raw := runNoProjectScenarios(t)

	type at struct {
		noProjectView
		Cards    int    `json:"cards"`
		Sockets  int    `json:"sockets"`
		Selector string `json:"selector"`
	}

	// An error for an answer.
	var failed struct {
		Before, Refreshed, Key, Revisited, Recovered at
	}
	decodeScenario(t, raw, "the_list_answers_with_an_error", &failed)
	if failed.Before.Cards != 3 {
		t.Fatalf("the scenario starts with %d project cards, want 3", failed.Before.Cards)
	}
	for when, v := range map[string]at{
		"after r met a 429": failed.Refreshed, "after 2 was pressed next": failed.Key,
		"after the Projects tab's own read met it": failed.Revisited,
	} {
		if v.InProject || v.Tab != "projects" {
			t.Errorf("the project list answered with an error; %s the page is on %q with the per-project "+
				"navigation on = %v — an error was read as \"the hub has one project\"", when, v.Tab, v.InProject)
		}
	}
	if failed.Refreshed.Cards != 3 || failed.Revisited.Cards != 3 {
		t.Errorf("the project list answered with an error and the grid went from 3 cards to %d, then %d: an "+
			"error is not an empty list", failed.Refreshed.Cards, failed.Revisited.Cards)
	}
	if failed.Refreshed.Toast != "Load failed" {
		t.Errorf("r met a 429 and the page said %q, want \"Load failed\"", failed.Refreshed.Toast)
	}
	if failed.Recovered.Toast != "Refreshed" || failed.Recovered.Cards != 3 || failed.Recovered.InProject {
		t.Errorf("once the list answered again: %q, %d cards, navigation on = %v", failed.Recovered.Toast,
			failed.Recovered.Cards, failed.Recovered.InProject)
	}

	// No answer at first paint, and an error at first paint: no project is
	// shown, no stream is opened, and the page asks again until it knows.
	for _, name := range []string{"the_list_is_unreadable", "the_list_is_an_error_at_first_paint"} {
		var boot struct {
			Down, Key, Back at
		}
		decodeScenario(t, raw, name, &boot)
		if boot.Down.InProject || boot.Down.Sockets != 0 {
			t.Errorf("%s: with no project list the navigation is on = %v and %d stream(s) are open; want off and "+
				"none — a stream opened without the list is the hub's own project's, and the page used to show it",
				name, boot.Down.InProject, boot.Down.Sockets)
		}
		if got := askedOfNoProject(t, boot.Down.Requests); len(got) != 0 {
			t.Errorf("%s: with no project list the page asked for a project: %v", name, got)
		}
		if !strings.Contains(boot.Down.Toast, "Could not load the project list") {
			t.Errorf("%s: the page said %q while it could not list the projects; want it to say so, not stay blank",
				name, boot.Down.Toast)
		}
		if name == "the_list_is_unreadable" && (boot.Key.InProject || boot.Key.Tab == "tasks") {
			t.Errorf("%s: 2 opened %q with the navigation on = %v", name, boot.Key.Tab, boot.Key.InProject)
		}
		if boot.Back.Tab != "projects" || boot.Back.InProject || boot.Back.Sockets != 1 || boot.Back.Cards != 3 ||
			!strings.Contains(boot.Back.Socket, "scope=global") {
			t.Errorf("%s: once the hub answered, the page is on %q with %d cards, navigation on = %v, %d stream(s), "+
				"the last %q; want it to have asked again and come up on the list by itself", name, boot.Back.Tab,
				boot.Back.Cards, boot.Back.InProject, boot.Back.Sockets, boot.Back.Socket)
		}
	}

	// A list of one on a hub of several.
	var member struct {
		Landing at `json:"landing"`
		OldPush at `json:"old_push"`
		Push    at `json:"push"`
	}
	decodeScenario(t, raw, "a_list_of_one_on_a_hub_of_several", &member)
	for when, v := range map[string]at{
		"at first paint": member.Landing, "after a push that carries no multi_project": member.OldPush,
		"after a push that says multi_project": member.Push,
	} {
		if v.InProject || !strings.Contains(v.Socket, "scope=global") {
			t.Errorf("a list of one project on a hub of several, %s: navigation on = %v, stream %q; the one "+
				"project is not the hub's own and must be opened to be in view", when, v.InProject, v.Socket)
		}
	}

	// One project becomes two under its Tasks tab: read, and pushed.
	var grew struct {
		Before at `json:"before"`
		After  at `json:"after"`
	}
	decodeScenario(t, raw, "second_project_appears", &grew)
	if grew.Before.Tab != "tasks" || !grew.Before.InProject {
		t.Fatalf("the scenario did not start on the one project's Tasks tab: %+v", grew.Before)
	}
	if grew.After.Tab != "tasks" || !grew.After.InProject || !strings.Contains(grew.After.Socket, "project_idx=0") ||
		grew.After.Selector != "alpha" || !reflect.DeepEqual(grew.After.Rendered, []int{101, 102}) {
		t.Errorf("a second project appeared under the first one's Tasks tab: now on %q, navigation on = %v, "+
			"stream %q, selector %q, tasks %v; want the page to stay on alpha's Tasks with alpha picked by name",
			grew.After.Tab, grew.After.InProject, grew.After.Socket, grew.After.Selector, grew.After.Rendered)
	}
	var pushed struct {
		Pushed at `json:"pushed"`
		Opened at `json:"opened"`
	}
	decodeScenario(t, raw, "second_project_is_pushed", &pushed)
	if pushed.Pushed.Tab != "tasks" || !pushed.Pushed.InProject || !strings.Contains(pushed.Pushed.Socket, "project_idx=0") {
		t.Errorf("a second project was pushed under the first one's Tasks tab: on %q, navigation on = %v, stream %q; "+
			"want alpha picked by name", pushed.Pushed.Tab, pushed.Pushed.InProject, pushed.Pushed.Socket)
	}
	if !strings.Contains(pushed.Opened.Socket, "project_idx=1") || !reflect.DeepEqual(pushed.Opened.Rendered, []int{201, 202}) {
		t.Errorf("the pushed second project, opened from its card: stream %q, tasks %v; want its own stream and "+
			"its own tasks — it used to open on the first project's stream and draw that project's",
			pushed.Opened.Socket, pushed.Opened.Rendered)
	}

	// …and under a global tab: none is picked.
	var under struct {
		Before at `json:"before"`
		After  at `json:"after"`
		Tasks  at `json:"tasks"`
	}
	decodeScenario(t, raw, "second_project_under_a_global_tab", &under)
	if !under.Before.InProject {
		t.Fatalf("the scenario did not start as a hub of one project: %+v", under.Before)
	}
	if under.After.InProject || under.After.Tab != "settings" || !strings.Contains(under.After.Socket, "scope=global") {
		t.Errorf("a second project appeared under Settings: on %q, navigation on = %v, stream %q; want Settings, "+
			"the navigation off and a stream that carries no project", under.After.Tab, under.After.InProject, under.After.Socket)
	}
	if got := askedOfNoProject(t, under.Tasks.Requests); under.Tasks.Tab != "settings" || len(got) != 0 {
		t.Errorf("Tasks, asked for after that: on %q after requests %v", under.Tasks.Tab, got)
	}

	// The only project is replaced by two others under its Tasks tab.
	var replaced struct {
		Before at `json:"before"`
		After  at `json:"after"`
	}
	decodeScenario(t, raw, "the_only_project_is_replaced", &replaced)
	if replaced.Before.Tab != "tasks" || !replaced.Before.InProject {
		t.Fatalf("the scenario did not start on the one project's Tasks tab: %+v", replaced.Before)
	}
	if replaced.After.Tab != "projects" || replaced.After.InProject || replaced.After.Cards != 2 ||
		!strings.Contains(replaced.After.Socket, "scope=global") {
		t.Errorf("the hub's only project was replaced by two others under its Tasks tab: now on %q with %d cards, "+
			"navigation on = %v, stream %q; want the list of the two, the navigation off and a stream that "+
			"carries no project", replaced.After.Tab, replaced.After.Cards, replaced.After.InProject, replaced.After.Socket)
	}

	// Two projects become one with none open.
	var shrank struct {
		Before at `json:"before"`
		Turned at `json:"turned"`
		After  at `json:"after"`
	}
	decodeScenario(t, raw, "down_to_one_project", &shrank)
	if shrank.Before.InProject {
		t.Fatalf("the scenario did not start with no project open: %+v", shrank.Before)
	}
	if !shrank.Turned.InProject || strings.Contains(shrank.Turned.Socket, "scope=global") ||
		strings.Contains(shrank.Turned.Socket, "project_idx") {
		t.Errorf("the hub went from two projects to one with none open: navigation on = %v, stream %q; want the one "+
			"project in view on a stream of its own — the page kept the stream that carries no project",
			shrank.Turned.InProject, shrank.Turned.Socket)
	}
	if shrank.After.Tab != "tasks" || !reflect.DeepEqual(shrank.After.Rendered, []int{101, 102}) {
		t.Errorf("the one project left, on its Tasks tab: on %q showing %v; want its two tasks",
			shrank.After.Tab, shrank.After.Rendered)
	}
}

// TestDashboard_NoProjectOpen_PaletteAndHelp: the command palette and the
// shortcut help list what can be done now.
func TestDashboard_NoProjectOpen_PaletteAndHelp(t *testing.T) {
	t.Parallel()
	raw := runNoProjectScenarios(t)

	var wantNone, wantAll []string
	for _, e := range paletteEntries(t) {
		wantAll = append(wantAll, e.label)
		if e.global {
			wantNone = append(wantNone, e.label)
		}
	}
	var pal struct {
		None []string `json:"none"`
		Open []string `json:"open"`
	}
	decodeScenario(t, raw, "palette", &pal)
	if !reflect.DeepEqual(pal.None, wantNone) {
		t.Errorf("the palette with no project open lists\n  %v\nwant only what needs none:\n  %v", pal.None, wantNone)
	}
	for _, l := range pal.None {
		switch l {
		case "Start run", "Stop run", "Run plan", "Reset session", "New task", "Add task", "Tasks", "Overview":
			t.Errorf("the palette offers %q with no project open", l)
		}
	}
	if !reflect.DeepEqual(pal.Open, wantAll) {
		t.Errorf("the palette with a project open lists\n  %v\nwant every entry:\n  %v", pal.Open, wantAll)
	}

	var stale struct {
		Listed bool     `json:"listed"`
		Open   []string `json:"open"`
		Closed []string `json:"closed"`
	}
	decodeScenario(t, raw, "palette_after_the_project_closed", &stale)
	if !stale.Listed || !reflect.DeepEqual(stale.Open, []string{"POST /api/stop?project_idx=1"}) {
		t.Errorf("Stop run, chosen with beta open: listed = %v, sent %v; want beta's run stopped", stale.Listed, stale.Open)
	}
	if len(stale.Closed) != 0 {
		t.Errorf("Stop run, chosen after its project closed under the open palette, sent %v — "+
			"with no index, that is the hub's own project's run", stale.Closed)
	}

	var help struct {
		None noProjectHelp `json:"none"`
		Open noProjectHelp `json:"open"`
	}
	decodeScenario(t, raw, "help", &help)
	if len(help.None.Groups) == 0 || help.None.MentionsNewTask || help.None.MentionsTabs {
		t.Errorf("the shortcut help with no project open: groups %v, lists New task = %v, lists the tab keys = %v; "+
			"want the general keys only", help.None.Groups, help.None.MentionsNewTask, help.None.MentionsTabs)
	}
	for _, g := range help.None.Groups {
		if strings.HasPrefix(g, "Project") {
			t.Errorf("the shortcut help shows the %q group with no project open", g)
		}
	}
	if !help.Open.MentionsNewTask || !help.Open.MentionsTabs || len(help.Open.Groups) != len(help.None.Groups)+2 {
		t.Errorf("the shortcut help with a project open: groups %v, lists New task = %v, lists the tab keys = %v; "+
			"want the general group and the two project groups", help.Open.Groups, help.Open.MentionsNewTask, help.Open.MentionsTabs)
	}
}

// TestDashboard_NoProjectOpen_ResyncReadsNoProject: the hub tells a client it
// dropped frames. With a project open the page reads it again; with none open
// it used to read the hub's own project instead — its whole state, and its
// history rows into the list the last project left behind.
func TestDashboard_NoProjectOpen_ResyncReadsNoProject(t *testing.T) {
	t.Parallel()
	raw := runNoProjectScenarios(t)

	var rs struct {
		HistoryOpen bool     `json:"history_open"`
		Open        []string `json:"open"`
		None        []string `json:"none"`
		Reopened    struct {
			Beta  bool `json:"beta"`
			Alpha bool `json:"alpha"`
		} `json:"reopened"`
	}
	decodeScenario(t, raw, "resync", &rs)
	if !rs.HistoryOpen {
		t.Fatal("the scenario never showed beta's history, so it proves nothing about what is spliced into it")
	}
	// With beta open: its state, and the rows above its history's top.
	sort.Strings(rs.Open)
	if len(rs.Open) != 2 || !strings.HasPrefix(rs.Open[0], "/api/event-history?after=") ||
		!strings.HasSuffix(rs.Open[0], "project_idx=1") || rs.Open[1] != "/api/state?project_idx=1" {
		t.Errorf("a resync with beta open read %v; want beta's state and the history rows it missed", rs.Open)
	}
	if got := askedOfNoProject(t, rs.None); len(got) != 0 {
		t.Errorf("a resync with no project open read %v — with no index these are the hub's own project's", got)
	}
	if !rs.Reopened.Beta || rs.Reopened.Alpha {
		t.Errorf("beta's history after reopening it: shows its own rows = %v, shows the hub's own project's rows = %v",
			rs.Reopened.Beta, rs.Reopened.Alpha)
	}
}

// TestDashboard_NoProjectOpen_NothingIsAskedOrSavedForTheHubsOwnProject: what
// the page does by itself, or from a global tab, while no project is open. A
// dropped stream's probe, the caps card's refresh on coming back to the tab,
// and the four things two global tabs do for one project — Settings' provider
// cards and reset, Budget's per-project caps and its breakdown of a project's
// .cloop directory — each used to go out with no index, and so to the hub's
// own project.
func TestDashboard_NoProjectOpen_NothingIsAskedOrSavedForTheHubsOwnProject(t *testing.T) {
	t.Parallel()
	raw := runNoProjectScenarios(t)

	var drop struct {
		None         []string `json:"none"`
		Open         []string `json:"open"`
		Fallback     string   `json:"fallback"`
		FallbackNone []string `json:"fallback_none"`
	}
	decodeScenario(t, raw, "a_stream_drops", &drop)
	if got := askedOfNoProject(t, drop.None); len(got) != 0 || !containsString(drop.None, "/api/projects") {
		t.Errorf("the stream dropped with no project open and the page asked for %v before reconnecting; want the "+
			"project list — it used to be the hub's own project's state, whole, for its status code", drop.None)
	}
	if !reflect.DeepEqual(drop.Open, []string{"/api/state?project_idx=1"}) {
		t.Errorf("the stream dropped with beta open and the page asked for %v; want beta's state", drop.Open)
	}
	if !strings.Contains(drop.Fallback, "/api/events") || !strings.Contains(drop.Fallback, "scope=global") {
		t.Fatalf("the scenario's event-stream fallback opened %q; want a stream that carries no project", drop.Fallback)
	}
	if got := askedOfNoProject(t, drop.FallbackNone); len(got) != 0 || !containsString(drop.FallbackNone, "/api/projects") {
		t.Errorf("the fallback stream dropped with no project open and the page asked for %v; want the project list",
			drop.FallbackNone)
	}

	var limits struct {
		Open []string `json:"open"`
		None []string `json:"none"`
	}
	decodeScenario(t, raw, "limits_after_the_project_closed", &limits)
	if !reflect.DeepEqual(limits.Open, []string{"/api/claudecode-limits?project_idx=1"}) {
		t.Fatalf("with beta open the caps card read %v; the scenario needs it to read beta's", limits.Open)
	}
	if len(limits.None) != 0 {
		t.Errorf("after its project was closed the caps card read %v — the hub's own project's caps", limits.None)
	}

	var forOne struct {
		None      []string `json:"none"`
		Open      []string `json:"open"`
		DiskNone  string   `json:"disk_none"`
		DiskOpen  string   `json:"disk_open"`
		DiskError string   `json:"disk_error"`
	}
	decodeScenario(t, raw, "settings_and_budget_for_a_project", &forOne)
	if len(forOne.None) != 0 {
		t.Errorf("with no project open, Settings and Budget read or saved for one all the same: %v — a provider "+
			"saved there landed in the hub's own project's configuration", forOne.None)
	}
	wantOpen := []string{"/api/config?project_idx=1", "/api/disk-usage?project_idx=1", "POST /api/config/set?project_idx=1",
		"POST /api/reset?project_idx=1", "PUT /api/budget/project?project_idx=1"}
	if !reflect.DeepEqual(forOne.Open, wantOpen) {
		t.Errorf("with beta open, Settings and Budget sent %v; want %v", forOne.Open, wantOpen)
	}
	// Budget's Disk & Retention says why it shows no directory, and shows the
	// open project's once there is one.
	if !strings.Contains(forOne.DiskNone, "Open a project") || strings.Contains(forOne.DiskNone, "state.db") {
		t.Errorf("Budget's Disk & Retention with no project open reads %q; want it to ask for a project to be opened",
			forOne.DiskNone)
	}
	if !strings.Contains(forOne.DiskOpen, "state.db") {
		t.Errorf("Budget's Disk & Retention with beta open reads %q; want beta's breakdown", forOne.DiskOpen)
	}
	if !strings.Contains(forOne.DiskError, "Could not load disk usage") || strings.Contains(forOne.DiskError, "Retention is") {
		t.Errorf("Budget's Disk & Retention, answered with an error, reads %q; want the error, not an empty "+
			"directory with retention off", forOne.DiskError)
	}
}
