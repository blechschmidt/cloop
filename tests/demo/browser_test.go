package demo_test

// The documentation site's dashboard demo, in a real browser (Task 20507).
//
// fixtures_test.go holds the demo to the reads the dashboard can make and to
// what its fixtures may contain. This test holds it to what a reader gets. It
// builds the demo as the site's build does (scripts/build-demo.py), serves it
// from a local server under /cloop/ as GitHub Pages does, and has
// scripts/demo/walk.js walk it in headless Chrome, which:
//
//   - opens every project tab for each of the three projects, every hub tab,
//     each task's details, and the main admin dialogs: an executor's details
//     and firewall, the enrollment form, a new secret, a grant, a knowledge
//     source, the approvals inbox and an audit row's details;
//   - lays each out at a phone, a tablet and a desktop width and measures it
//     with the dashboard's own layout sweep (internal/layoutsweep), so the demo
//     is held to the same definition of overflow as the dashboard;
//   - presses Add task, Start run and Delete.
//
// It fails when the page throws, logs an error or is blocked by its own policy;
// when a request goes anywhere but the local server, in the browser or in the
// demo's shim, or reaches the server outside the demo's directory; when
// anything overflows; and when a write is not refused with the read-only notice
// or changes what the page shows.
//
// Like every browser test here, it skips when Chrome or node is missing (and
// python3, which builds the demo). CI's "Dashboard demo in a browser" job runs
// it beside the documentation jobs and fails if it skipped.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/layoutsweep"
)

// siteEnv names a built documentation site (the directory holding demo/, such
// as dist/docs-site after `make docs-site`) to test instead of building the
// demo afresh.
const siteEnv = "CLOOP_DEMO_SITE"

// demoViewports are the widths every tab and dialog is laid out at: the phone
// the hub's own users carry, a tablet in portrait and a desktop. The walk
// itself happens at the last.
var demoViewports = []string{"phone-360", "tablet-768", "desktop-1280"}

// pagesPrefix is where GitHub Pages serves the site, and so the demo
// (https://blechschmidt.github.io/cloop/demo/).
const pagesPrefix = "/cloop/"

// walkReport is what walk.js check writes.
type walkReport struct {
	Tabs []struct {
		Project string   `json:"project"`
		Tab     string   `json:"tab"`
		Drawn   bool     `json:"drawn"`
		Empty   []string `json:"empty"`
	} `json:"tabs"`
	Unpopulated []string `json:"unpopulated"`
	Unopened    []string `json:"unopened"`
	Details     []struct {
		Project string `json:"project"`
		ID      int    `json:"id"`
		Shown   bool   `json:"shown"`
	} `json:"details"`
	Scenarios []layoutsweep.Scenario `json:"scenarios"`
	Dialogs   []struct {
		ID     string `json:"id"`
		Opened bool   `json:"opened"`
		Error  string `json:"error"`
	} `json:"dialogs"`
	Message string `json:"message"`
	Writes  []struct {
		Name      string `json:"name"`
		Error     string `json:"error"`
		Toast     bool   `json:"toast"`
		ToastText string `json:"toast_text"`
		Before    string `json:"before"`
		After     string `json:"after"`
		Requests  []struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Answer string `json:"answer"`
		} `json:"requests"`
	} `json:"writes"`
	Problems []struct {
		Scenario string `json:"scenario"`
		Kind     string `json:"kind"`
		Text     string `json:"text"`
		URL      string `json:"url"`
	} `json:"problems"`
	Foreign []struct {
		Scenario string `json:"scenario"`
		URL      string `json:"url"`
		Type     string `json:"type"`
	} `json:"foreign"`
	RealSockets []struct {
		Scenario string `json:"scenario"`
		URL      string `json:"url"`
	} `json:"real_sockets"`
	Away []struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"away"`
	// RequestsSeen counts every request the browser made, and Control whether
	// an error the walk threw on purpose reached its listener: the two show
	// the checks for requests and errors had something to listen to.
	RequestsSeen int  `json:"requests_seen"`
	Control      bool `json:"control"`
	Requests     []struct {
		Answer string `json:"answer"`
	} `json:"requests"`
	ElapsedMS int `json:"elapsed_ms"`
}

func TestTheDemoInABrowser(t *testing.T) {
	chrome := layoutsweep.FindChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot open the demo")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	root := repoRoot(t)

	site := os.Getenv(siteEnv)
	if site == "" {
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Skip("python3 not installed; cannot build the demo")
		}
		site = buildDemo(t, python, root)
	}
	if _, err := os.Stat(filepath.Join(site, "demo", "index.html")); err != nil {
		t.Fatalf("%s holds no demo/index.html: %v", site, err)
	}

	srv, served := servePages(t, site)
	projects := demoProjects(t, root)
	report := runWalk(t, node, chrome, root, srv.URL+pagesPrefix+"demo", projects)
	t.Logf("walked the demo in %.1fs: %d tab visits, %d task details, %d dialogs, %d layouts measured",
		float64(report.ElapsedMS)/1000, len(report.Tabs), len(report.Details), len(report.Dialogs), len(report.Scenarios))

	t.Run("every tab of every project and of the hub was visited", func(t *testing.T) {
		if len(report.Unopened) > 0 {
			t.Errorf("projects that did not open: %v", report.Unopened)
		}
		visited := map[string]map[string]bool{}
		for _, v := range report.Tabs {
			if visited[v.Tab] == nil {
				visited[v.Tab] = map[string]bool{}
			}
			visited[v.Tab][v.Project] = true
		}
		for _, tab := range dashboardTabs(t, root) {
			for _, p := range projects {
				if !visited[tab][p.Name] {
					t.Errorf("the %s tab was never opened on %s: walk.js's PROJECT_TABS and HUB_TABS "+
						"must name every tab index.html has", tab, p.Name)
				}
			}
		}
		if len(report.Unpopulated) > 0 {
			t.Errorf("tabs that drew none of the recording on any project: %v — a fixture the tab "+
				"needs is missing or no longer matches what the dashboard asks for", report.Unpopulated)
		}
	})

	t.Run("each task's details and every admin dialog opened with their content", func(t *testing.T) {
		if len(report.Details) < len(projects) {
			t.Errorf("only %d tasks' details were opened", len(report.Details))
		}
		for _, d := range report.Details {
			if !d.Shown {
				t.Errorf("the details of %s's task #%d never showed", d.Project, d.ID)
			}
		}
		if len(report.Dialogs) < 8 {
			t.Errorf("only %d dialogs were tried; walk.js's DIALOGS and the audit row make eight", len(report.Dialogs))
		}
		for _, d := range report.Dialogs {
			if !d.Opened {
				t.Errorf("%s did not open: %s", d.ID, d.Error)
			}
		}
	})

	t.Run("nothing threw or logged an error", func(t *testing.T) {
		if !report.Control {
			t.Error("an error the walk threw in the page on purpose was never caught, so no error would be")
		}
		for _, p := range report.Problems {
			t.Errorf("%s: %s: %s %s", p.Scenario, p.Kind, p.Text, p.URL)
		}
	})

	t.Run("nothing left the local server", func(t *testing.T) {
		answered := 0
		for _, r := range report.Requests {
			if r.Answer == "fixture" {
				answered++
			}
		}
		if report.RequestsSeen == 0 || answered == 0 {
			t.Errorf("the browser made %d requests and the shim answered %d from a fixture: the walk "+
				"saw nothing to check", report.RequestsSeen, answered)
		}
		for _, f := range report.Foreign {
			t.Errorf("%s: the browser requested %s (%s)", f.Scenario, f.URL, f.Type)
		}
		for _, s := range report.RealSockets {
			t.Errorf("%s: the browser opened a WebSocket to %s around the demo's shim", s.Scenario, s.URL)
		}
		for _, a := range report.Away {
			t.Errorf("the page asked another site for %s %s (the shim answered it in the page)", a.Method, a.URL)
		}
		// Everything the server saw is a file of the demo's own: a request
		// for a hub route went around the shim, and on github.io it is a 404.
		paths := served()
		if len(paths) == 0 {
			t.Fatal("the server saw no request at all")
		}
		for _, p := range paths {
			if !strings.HasPrefix(p, pagesPrefix+"demo/") {
				t.Errorf("the server was asked for %s, outside the demo", p)
			}
		}
	})

	t.Run("writes are refused in the page and change nothing", func(t *testing.T) {
		if report.Message == "" || !strings.Contains(report.Message, "read-only demo") {
			t.Fatalf("the demo's notice is %q", report.Message)
		}
		if len(report.Writes) < 3 {
			t.Fatalf("only %d writes were tried, want Add task, Start run and Delete", len(report.Writes))
		}
		for _, w := range report.Writes {
			if w.Error != "" {
				t.Errorf("%s: %s", w.Name, w.Error)
				continue
			}
			if !w.Toast {
				t.Errorf("%s: the toast never said %q; it says %q", w.Name, report.Message, w.ToastText)
			}
			if w.Before != w.After {
				t.Errorf("%s changed what the page shows:\nbefore %s\nafter  %s", w.Name, w.Before, w.After)
			}
			if len(w.Requests) == 0 {
				t.Errorf("%s made no write at all, so the test proves nothing about refusing one", w.Name)
			}
			for _, r := range w.Requests {
				if r.Answer != "refused" {
					t.Errorf("%s: %s %s was answered %q, want refused", w.Name, r.Method, r.URL, r.Answer)
				}
			}
		}
	})

	t.Run("nothing overflows at a phone, tablet or desktop width", func(t *testing.T) {
		for _, s := range report.Scenarios {
			if s.Error != "" {
				t.Errorf("%s: could not be measured: %s", s.Name, s.Error)
				continue
			}
			if len(s.Measurements) != len(demoViewports) {
				t.Errorf("%s: measured %d times, want %d", s.Name, len(s.Measurements), len(demoViewports))
			}
			for _, m := range s.Measurements {
				// A scope that matched nothing visible passes every check
				// without testing anything.
				if m.Roots == 0 || m.Elements < 3 {
					t.Errorf("%s at %s: nothing on screen to measure (%d roots, %d elements)",
						s.Name, m.Viewport, m.Roots, m.Elements)
				}
			}
		}
		for _, f := range layoutsweep.Findings(report.Scenarios) {
			t.Errorf("%s", f)
		}
	})
}

// buildDemo builds the demo into a fresh site directory, from the fixtures
// CLOOP_DEMO_FIXTURES names if it is set (a recording not yet written into
// website/demo, as record-fixtures.sh checks one) and from the tree's
// otherwise, and returns the site directory.
func buildDemo(t *testing.T, python, root string) string {
	t.Helper()
	site := t.TempDir()
	args := []string{filepath.Join(root, "scripts", "build-demo.py"), "--out", filepath.Join(site, "demo")}
	if alt := os.Getenv(fixturesEnv); alt != "" {
		args = append(args, "--fixtures", alt)
	}
	cmd := exec.Command(python, args...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the demo: %v\n%s", err, out)
	}
	return site
}

// servePages serves site under /cloop/, as GitHub Pages serves the project's
// site, and nothing anywhere else. served lists every path asked for.
func servePages(t *testing.T, site string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	files := http.StripPrefix(strings.TrimSuffix(pagesPrefix, "/"), http.FileServer(http.Dir(site)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if !strings.HasPrefix(r.URL.Path, pagesPrefix) {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), paths...)
		sort.Strings(out)
		return slicesCompact(out)
	}
}

func slicesCompact(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// demoProject is a project as the fixtures show it, and as walk.js wants it.
type demoProject struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// demoProjects are the demo's projects, read from the fixture that answers the
// dashboard's project list: the three made up for it, without the parallel
// feature one of them carries (a feature is opened from its project).
func demoProjects(t *testing.T, root string) []demoProject {
	t.Helper()
	dir := filepath.Join(root, fixturesDir)
	if alt := os.Getenv(fixturesEnv); alt != "" {
		dir = alt
	}
	raw, err := os.ReadFile(filepath.Join(dir, "hub", "projects.json"))
	if err != nil {
		t.Fatalf("the demo's project list: %v", err)
	}
	var list []struct {
		Request string `json:"request"`
		Body    struct {
			Projects []demoProject `json:"projects"`
		} `json:"body"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		var one struct {
			Request string `json:"request"`
			Body    struct {
				Projects []demoProject `json:"projects"`
			} `json:"body"`
		}
		if err := json.Unmarshal(raw, &one); err != nil {
			t.Fatalf("the demo's project list: %v", err)
		}
		list = append(list, one)
	}
	var out []demoProject
	for _, fx := range list {
		if fx.Request != "GET /api/projects" {
			continue
		}
		for _, p := range fx.Body.Projects {
			if !strings.Contains(p.Path, "/.cloop/features/") {
				out = append(out, p)
			}
		}
	}
	if len(out) < 3 {
		t.Fatalf("the demo's project list names %d projects, want the three made up for it: %+v", len(out), out)
	}
	return out
}

// dashboardTabs are the tabs index.html's tab strip offers.
func dashboardTabs(t *testing.T, root string) []string {
	t.Helper()
	html, err := os.ReadFile(filepath.Join(root, assetsDir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var tabs []string
	for _, m := range regexp.MustCompile(`id="tbtn-([a-z-]+)"`).FindAllStringSubmatch(string(html), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			tabs = append(tabs, m[1])
		}
	}
	if len(tabs) < 20 {
		t.Fatalf("index.html offers %d tabs; the pattern no longer finds the tab strip", len(tabs))
	}
	return tabs
}

// runWalk runs walk.js check against url and decodes its report.
func runWalk(t *testing.T, node, chrome, root, url string, projects []demoProject) walkReport {
	t.Helper()
	dir := t.TempDir()
	vps, err := layoutsweep.Named(demoViewports...)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON := func(name string, v any) string {
		p := filepath.Join(dir, name)
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	projectsFile := writeJSON("projects.json", projects)
	sweepFile := writeJSON("sweep.json", map[string]any{
		"viewports": vps, "allow": layoutsweep.DashboardScrollAllowlist,
		"probe": filepath.Join(root, "internal", "layoutsweep", "probe.js"),
	})
	out := filepath.Join(dir, "report.json")
	// Bounded, so a stalled Chrome cannot hold the package to its timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, filepath.Join(root, "scripts", "demo", "walk.js"), "check", chrome, url,
		projectsFile, out, sweepFile)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("walk.js wrote no report (%v): %v\n%s", runErr, err, tail(stderr.String(), 60))
	}
	var r walkReport
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("walk.js's report: %v", err)
	}
	// walk.js exits 1 on what it judges itself; the subtests say which.
	if runErr != nil {
		t.Logf("walk.js: %v; its log ends:\n%s", runErr, tail(stderr.String(), 40))
	}
	if d := os.Getenv("CLOOP_DEMO_REPORT"); d != "" {
		_ = os.WriteFile(d, raw, 0o644)
	}
	return r
}

// tail is the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return fmt.Sprint(strings.Join(lines, "\n"))
}
