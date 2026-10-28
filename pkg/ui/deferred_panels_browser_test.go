package ui

// Browser gate for the panels Task 20386 moved off first paint.
//
// The Settings and admin tabs (Settings, Budget, Secrets, Audit, Quotas,
// Telemetry) and the executor dialogs used to arrive with the bundle. Each is
// now a deferred script, fetched the first time it is opened, which carries its
// own markup and whose buttons mountPanel routes to functions the script never
// puts on window. Three things can go wrong that no grep can see, and this gate
// drives a real Chromium against a real hub to see them:
//
//   - a panel is not fetched when it is opened, or is fetched before — the
//     driver opens every one from a fresh navigation with the cache off, and
//     records which deferred scripts had been requested before and after;
//   - a button in the moved markup reaches nothing — every scenario presses
//     the panel's primary action and asks the hub what it stored;
//   - a fetch that fails leaves an empty panel — the second run refuses the
//     deferred scripts and needs an error with a Retry that works.
//
// It skips when Chrome or node is missing, like every browser gate here.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// deferredScenario is what the driver reports for one panel or dialog.
type deferredScenario struct {
	Error         string          `json:"error"`
	FetchedBefore []string        `json:"fetched_before"`
	Fetched       []string        `json:"fetched"`
	Rendered      bool            `json:"rendered"`
	Stored        json.RawMessage `json:"stored"`
	// Scenario-specific evidence, each checked below where it applies.
	OIDCSection bool   `json:"oidc_section"`
	DiskUsage   bool   `json:"disk_usage"`
	SavedNote   bool   `json:"saved_note"`
	Refreshed   bool   `json:"refreshed"`
	Rows        int    `json:"rows"`
	Verified    bool   `json:"verified"`
	Verdict     string `json:"verdict"`
	Summary     string `json:"summary"`
	Command     string `json:"command"`
	DialogType  string `json:"dialog_type"`
	Message     string `json:"message"`
	Enabled     bool   `json:"enabled"`
	Minted      bool   `json:"minted"`
	Filed       bool   `json:"filed"`
	Approved    bool   `json:"approved"`
	// secret_dialog and audience: the refusal path, and the ownership choice.
	Refusal          string `json:"refusal"`
	OpenAfterRefusal bool   `json:"open_after_refusal"`
	OwnershipShown   bool   `json:"ownership_shown"`
}

// deferredFailRun is what the driver reports with the deferred scripts refused.
type deferredFailRun struct {
	Error string `json:"error"`
	Tab   struct {
		Error        string `json:"error"`
		RetryOffered bool   `json:"retry_offered"`
		PanelAbsent  bool   `json:"panel_absent"`
		Recovered    bool   `json:"recovered"`
	} `json:"tab"`
	Dialog struct {
		Banner       string `json:"banner"`
		Buttons      int    `json:"buttons"`
		DialogAbsent bool   `json:"dialog_absent"`
		Recovered    bool   `json:"recovered"`
		BannerGone   bool   `json:"banner_gone"`
	} `json:"dialog"`
	Refused []string `json:"refused"`
}

func TestDeferredPanels_ColdOpenInBrowser(t *testing.T) {
	chrome, node := browserTools(t)
	ts, _, device := deferredPanelsHub(t)

	t.Run("each panel from a cold page", func(t *testing.T) {
		var got map[string]deferredScenario
		runDeferredDriver(t, node, chrome, ts.URL, device, "cold", &got)

		// Which deferred script each scenario has to have fetched, and only
		// once it was opened.
		want := map[string]string{
			"settings": "settings", "budget": "budget", "secrets": "secrets", "audit": "audit",
			"quotas": "quotas", "telemetry": "telemetry",
			"enroll": "execadmin", "detail": "execadmin", "sandbox": "execadmin", "virtual": "execadmin",
			"firewall": "execadmin", "limits": "execadmin", "audience": "execadmin", "upgrade": "execadmin",
			"autoupdate":    "execadmin",
			"secret_dialog": "secrets", "grant_dialog": "secrets", "token_dialog": "secrets",
			"request_dialog": "secrets", "decide_dialog": "secrets",
			"palette": "settings",
			// Moved tabs (Task 20456) from a number key and from the palette.
			"shortcut": "kanban", "palette_moved": "analytics",
		}
		for name, script := range want {
			s, ok := got[name]
			if !ok {
				t.Errorf("%s: the driver reported nothing", name)
				continue
			}
			if s.Error != "" {
				t.Errorf("%s: %s", name, s.Error)
				continue
			}
			if len(s.FetchedBefore) != 0 {
				t.Errorf("%s: a cold page fetched %v before anything was opened — first paint is "+
					"paying for a deferred panel", name, s.FetchedBefore)
			}
			if !fetchedScript(s.Fetched, script) {
				t.Errorf("%s: opening it never fetched %s.js (fetched %v)", name, script, s.Fetched)
			}
			if !s.Rendered {
				t.Errorf("%s: never rendered", name)
			}
		}

		check := func(name string, ok bool, what string) {
			t.Helper()
			if s, found := got[name]; found && s.Error == "" && !ok {
				t.Errorf("%s: %s", name, what)
			}
		}
		check("settings", got["settings"].OIDCSection, "the OIDC section of the moved markup is not on screen")
		check("settings", strings.Contains(string(got["settings"].Stored), "anthropic"), "Save Provider stored nothing")
		check("budget", got["budget"].DiskUsage, "Disk & Retention did not load with its tab")
		check("budget", got["budget"].SavedNote, "Save Global Limits did not say it saved")
		check("secrets", got["secrets"].Refreshed, "Refresh did not re-read the secrets")
		check("audit", got["audit"].Verified && strings.Contains(got["audit"].Verdict, "intact"),
			"Verify chain did not re-verify: "+got["audit"].Verdict)
		check("audit", got["audit"].Rows > 0, "the trail has no rows")
		check("quotas", strings.Contains(compact(got["quotas"].Stored), `"max_projects":7`), "the edited quota was not stored")
		check("telemetry", strings.HasPrefix(got["telemetry"].Summary, "Showing 1 of 1"),
			"the filter did not narrow the trail: "+got["telemetry"].Summary)
		check("enroll", strings.Contains(got["enroll"].Command, "cloop executor"),
			"enrolling shows no join command: "+got["enroll"].Command)
		check("detail", got["detail"].Verdict != "", "the history dialog shows no verdict")
		check("sandbox", strings.Contains(string(got["sandbox"].Stored), "ghcr.io/acme/sandbox:v1"), "the sandbox image was not stored")
		check("virtual", string(got["virtual"].Stored) == "true", "the virtual executor was not created")
		check("firewall", strings.Contains(string(got["firewall"].Stored), "443"), "the device firewall was not stored")
		check("limits", strings.Contains(compact(got["limits"].Stored), `"memory_mb":2048`), "the ceiling was not stored")
		// Refused with the reason, in the dialog, which stays open: on a hub
		// without sign-on the first principal would lock its admin out.
		check("audience", strings.Contains(got["audience"].Message, "remove your own access") &&
			got["audience"].OpenAfterRefusal, "Add did not show the hub's answer: "+got["audience"].Message)
		check("upgrade", got["upgrade"].Message != "", "the upgrade dialog said nothing")
		check("autoupdate", got["autoupdate"].Enabled, "automatic upgrades were not switched on")
		check("secret_dialog", string(got["secret_dialog"].Stored) == "true", "the secret was not stored")
		// A refused store must say so and leave the form up: it used to report
		// "Secret stored" over the hub's 400 and close.
		check("secret_dialog", strings.Contains(got["secret_dialog"].Refusal, "already exists") &&
			got["secret_dialog"].OpenAfterRefusal, "a refused store did not say why and stay open: "+
			got["secret_dialog"].Refusal)
		check("secret_dialog", !got["secret_dialog"].OwnershipShown,
			"a hub without sign-on offers a personal secret, which it refuses")
		check("grant_dialog", string(got["grant_dialog"].Stored) == "true", "the grant was not stored")
		check("token_dialog", got["token_dialog"].Minted, "no token was minted")
		check("request_dialog", got["request_dialog"].Filed, "the request was not filed")
		check("decide_dialog", got["decide_dialog"].Approved, "the request was not approved")
		check("shortcut", strings.Contains(string(got["shortcut"].Stored), "in_progress"),
			"l did not move the focused card to the next column")
	})

	t.Run("a deferred script that does not arrive", func(t *testing.T) {
		var got deferredFailRun
		runDeferredDriver(t, node, chrome, ts.URL, device, "fail", &got)
		if got.Error != "" {
			t.Fatalf("the driver failed: %s", got.Error)
		}
		if !strings.Contains(got.Tab.Error, "did not load") || !got.Tab.RetryOffered {
			t.Errorf("a tab whose script failed shows %q, retry offered %v; want the failure and a Retry",
				got.Tab.Error, got.Tab.RetryOffered)
		}
		if !got.Tab.PanelAbsent {
			t.Error("the tab's panel is on the page although its script was refused")
		}
		if !got.Tab.Recovered {
			t.Error("Retry did not bring the tab back once the network did")
		}
		if !strings.Contains(got.Dialog.Banner, "did not load") || got.Dialog.Buttons != 2 {
			t.Errorf("a dialog whose script failed shows banner %q with %d buttons; want the failure, "+
				"Retry and Dismiss", got.Dialog.Banner, got.Dialog.Buttons)
		}
		if !got.Dialog.DialogAbsent {
			t.Error("the dialog is on the page although its script was refused")
		}
		if !got.Dialog.Recovered || !got.Dialog.BannerGone {
			t.Errorf("Retry in the banner: dialog opened %v, banner gone %v", got.Dialog.Recovered, got.Dialog.BannerGone)
		}
		if !fetchedScript(got.Refused, "audit") || !fetchedScript(got.Refused, "execadmin") {
			t.Errorf("the run refused %v; the scenario is vacuous unless it refused audit and execadmin", got.Refused)
		}
	})
}

// browserTools returns the Chrome and node the browser gates drive, or skips.
func browserTools(t *testing.T) (chrome, node string) {
	t.Helper()
	chrome = findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot open a panel a user would")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	return chrome, node
}

// deferredPanelsHub is the hub both gates drive, with everything its panels
// show seeded, and the device enrolled for the Executors tab's card.
func deferredPanelsHub(t *testing.T) (ts *httptest.Server, srv *Server, device string) {
	t.Helper()
	// One project, so the landing tab is its Overview and boot never moves
	// the page under the driver; and a secret store, so the Secrets dialogs
	// have something to act on (set here rather than inherited, so this runs
	// the same in CI as on a hub's own box).
	t.Setenv(multiui.EnvRoot, t.TempDir())
	t.Setenv(secretbroker.EnvPassphraseKey, "deferred-panels-browser-passphrase")
	// Two tasks, the second waiting on the first: the moved tabs (Task 20456)
	// draw them — a board, a graph with an edge, the replay picker.
	dir := setupProjectDir(t, "deferred panels", []*pm.Task{
		{ID: 1, Title: "dp-task-alpha", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "dp-task-beta", Status: pm.TaskPending, Priority: 2, DependsOn: []int{1}},
	})
	device = seedDevice(t, dir, "dp-device-1")
	t.Cleanup(func() {
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			return
		}
		defer db.Close()
		rows, _ := db.ListVirtualExecutors()
		for _, v := range rows {
			executor.DefaultRegistry.Unregister(v.ID)
		}
	})

	// Configured before the listener starts: requests from Chrome carry no
	// happens-before edge the race detector can see. The driver polls the hub
	// for what a save stored, which the default limiter would answer with 429.
	srv = New(dir, 0, "")
	srv.RPS, srv.Burst = 100000, 100000
	installQuotas(t, srv, quota.Config{Defaults: quota.Limits{quota.ResProjects: 1}})
	ts = httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// What the panels show: a secret, a quota override, a telemetry event, and
	// an access request filed by somebody else — the only kind this hub's
	// anonymous admin may decide; and a knowledge-base entry (Task 20456).
	seedHub(t, ts, http.MethodPost, "/api/secrets",
		`{"name":"dp-seeded","kind":"env","payload":"{\"FOO\":\"bar\"}","personal":false}`)
	seedHub(t, ts, http.MethodPut, "/api/quotas/bob@example.com", `{"limits":{"max_projects":3}}`)
	seedHub(t, ts, http.MethodPut, "/api/config/telemetry", `{"enabled":true}`)
	seedHub(t, ts, http.MethodPost, "/api/telemetry",
		`{"source":"dashboard","session":"dp0000000000000000","events":[{"kind":"error","seq":1,"message":"deferred-panels-seed"}]}`)
	fileRequestAs(t, dir, "dana@example.com")
	seedHub(t, ts, http.MethodPost, "/api/kb", `{"title":"dp-kb-seeded","body":"seeded","tags":[]}`)
	return ts, srv, device
}

// TestDeferredTabs_EachWayInBrowser opens every tab Task 20456 moved off
// first paint, each from a page of its own, one way per run: its tab button,
// a link that names it, the tab a sign-in round trip restores, after the hub
// dropped the page's stream, and on Fast 3G. Each has to draw from a script
// fetched for it alone, answer a control of its moved markup, and log no
// error doing so; a change made before its code arrived has to be on it, and
// after a reconnect a change pushed over the new stream has to reach it.
func TestDeferredTabs_EachWayInBrowser(t *testing.T) {
	chrome, node := browserTools(t)
	ts, srv, device := deferredPanelsHub(t)
	control := severControl(t, srv)
	for _, way := range []string{"cold", "link", "resume", "reconnect", "fast3g"} {
		t.Run(way, func(t *testing.T) {
			var got map[string]movedTabScenario
			runDeferredDriver(t, node, chrome, ts.URL, device, "tabs:"+way, &got, control)
			checkMovedTabs(t, way, got)
		})
	}
}

// movedTabScenario is what the driver reports for one tab Task 20456 moved.
type movedTabScenario struct {
	Error        string   `json:"error"`
	Fetched      []string `json:"fetched"`
	OpenedBefore []string `json:"opened_before"`
	Rendered     bool     `json:"rendered"`
	Active       bool     `json:"active"`
	Pressed      string   `json:"pressed"`
	Problems     []string `json:"problems"`
	BootProblems []string `json:"boot_problems"`
	MS           int      `json:"ms"`
	LinkDropped  bool     `json:"link_dropped"`
	Reconnected  []string `json:"reconnected"`
	AfterEvent   bool     `json:"after_event"`
}

// movedTabs is DEFERRED_TABS less the tabs Task 20386 had already moved:
// each is a deferred script of its own name.
var movedTabs = []string{"queue", "kanban", "kb", "deps", "risk-matrix", "analytics", "chat", "assistant",
	"replay", "provider-calls", "executors"}

// checkMovedTabs holds one way's run to what opening a moved tab must do: draw
// the tab from a script fetched for it alone, answer a control of its moved
// markup, and log no error doing so.
func checkMovedTabs(t *testing.T, way string, got map[string]movedTabScenario) {
	t.Helper()
	moved := map[string]bool{}
	for _, tab := range movedTabs {
		moved[tab] = true
	}
	for _, tab := range movedTabs {
		s, ok := got[tab]
		if !ok {
			t.Errorf("%s: the driver reported nothing", tab)
			continue
		}
		if s.Error != "" {
			t.Errorf("%s: %s\n  logged: %v", tab, s.Error, s.Problems)
			continue
		}
		if !s.Rendered || !s.Active || s.Pressed == "" {
			t.Errorf("%s: rendered %v, on screen %v, pressed %q", tab, s.Rendered, s.Active, s.Pressed)
		}
		if !fetchedScript(s.Fetched, tab) {
			t.Errorf("%s: opening it never fetched %s.js (fetched %v)", tab, tab, s.Fetched)
		}
		// Its own script and nothing else moved — the Executors tab's dialogs
		// are execadmin's, fetched beside it.
		for _, f := range s.Fetched {
			if moved[f] && f != tab {
				t.Errorf("%s: opening it also fetched %s.js, another tab's", tab, f)
			}
		}
		if tab == "executors" && !fetchedScript(s.Fetched, "execadmin") {
			t.Errorf("executors: the tab's forwarders and card dialogs never fetched execadmin.js (fetched %v)", s.Fetched)
		}
		if way != "link" && way != "resume" && len(s.OpenedBefore) != 0 {
			t.Errorf("%s: the page had fetched %v before the tab was opened", tab, s.OpenedBefore)
		}
		if len(s.Problems) != 0 {
			t.Errorf("%s: opening it logged errors:\n  %s", tab, strings.Join(s.Problems, "\n  "))
		}
		switch way {
		case "link":
			if !s.LinkDropped {
				t.Errorf("%s: the link's query is still in the address, so a reload opens the tab again", tab)
			}
		case "reconnect":
			if len(s.Reconnected) == 0 {
				t.Errorf("%s: the page never opened a new event stream after the hub dropped its own", tab)
			}
			if (tab == "kanban" || tab == "analytics") && !s.AfterEvent {
				t.Errorf("%s: a change pushed over the new stream did not reach the open tab", tab)
			}
		case "fast3g":
			t.Logf("%s on Fast 3G: drawn %d ms after its tab was pressed", tab, s.MS)
		}
	}
}

// severControl is a server of the test's own whose POST /sever closes every
// WebSocket the hub holds, as a hub going down does: the lever the driver
// pulls to make a page reconnect (Task 20456).
func severControl(t *testing.T, srv *Server) string {
	t.Helper()
	ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/sever" {
			http.NotFound(w, r)
			return
		}
		srv.closeAllWebSocketsForShutdown(5 * time.Second)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ctl.Close)
	return ctl.URL
}

// TestDeferredTabs_ProjectsAndTasksFetchNothing is the other half of Task
// 20456's claim, on a hub with two projects: a session that keeps to Projects
// and Tasks fetches no deferred script at all, and a moved tab shows the
// project switched to rather than the one before it (Task 20197's bug class).
func TestDeferredTabs_ProjectsAndTasksFetchNothing(t *testing.T) {
	chrome, node := browserTools(t)
	t.Setenv(multiui.EnvRoot, t.TempDir())
	// A secret store, so the Overview a project switch lands on answers its
	// repository card rather than logging a 503 for it.
	t.Setenv(secretbroker.EnvPassphraseKey, "deferred-tabs-session-passphrase")
	a := sessionProject(t, "dp-session-a", "dp-task-a")
	b := sessionProject(t, "dp-session-b", "dp-task-b")
	srv := New(a, 0, "")
	srv.Projects = []string{b}
	srv.RPS, srv.Burst = 100000, 100000
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	// A knowledge-base entry of each project's own, by its index in the list.
	var list struct {
		Projects []struct {
			Path string `json:"path"`
		} `json:"projects"`
	}
	resp, err := http.Get(ts.URL + "/api/projects")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for i, p := range list.Projects {
		name := map[string]string{a: "dp-kb-a", b: "dp-kb-b"}[p.Path]
		if name == "" {
			continue
		}
		seedHub(t, ts, http.MethodPost, fmt.Sprintf("/api/kb?project_idx=%d", i),
			`{"title":"`+name+`","body":"seeded","tags":[]}`)
	}

	var got map[string]struct {
		Error           string   `json:"error"`
		Rendered        bool     `json:"rendered"`
		Scripts         []string `json:"scripts"`
		OverviewSkipped bool     `json:"overview_skipped"`
		BoardLeak       bool     `json:"board_leak"`
		KBLeak          bool     `json:"kb_leak"`
		Problems        []string `json:"problems"`
	}
	runDeferredDriver(t, node, chrome, ts.URL, "", "session", &got, "", a+","+b)
	s := got["projects_and_tasks"]
	switch {
	case s.Error != "":
		t.Errorf("projects and tasks: %s", s.Error)
	case !s.Rendered:
		t.Error("projects and tasks: never rendered")
	default:
		if len(s.Scripts) != 0 {
			t.Errorf("a session that kept to Projects and Tasks fetched %v — first paint's savings are spent "+
				"by the tabs it shows after all", s.Scripts)
		}
		if !s.OverviewSkipped {
			t.Error("the link to a project's Tasks ran the Overview's loaders on the way there")
		}
		if len(s.Problems) != 0 {
			t.Errorf("projects and tasks logged errors:\n  %s", strings.Join(s.Problems, "\n  "))
		}
	}
	sw := got["project_switch"]
	switch {
	case sw.Error != "":
		t.Errorf("project switch: %s", sw.Error)
	case !sw.Rendered:
		t.Error("project switch: never rendered")
	default:
		if sw.BoardLeak || sw.KBLeak {
			t.Errorf("after switching projects the moved tabs still show the first one's content "+
				"(board %v, knowledge base %v)", sw.BoardLeak, sw.KBLeak)
		}
		if len(sw.Problems) != 0 {
			t.Errorf("the project switch logged errors:\n  %s", strings.Join(sw.Problems, "\n  "))
		}
	}
}

// sessionProject is a project the dashboard names name (it shows a project by
// its directory), with one pending task.
func sessionProject(t *testing.T, name, task string) string {
	t.Helper()
	dir := namedProjectDir(t, name, "deferred tabs: "+name)
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	ps.PMMode = true
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{{ID: 1, Title: task, Status: pm.TaskPending, Priority: 1}}}
	if err := ps.Save(); err != nil {
		t.Fatalf("state.Save(%s): %v", dir, err)
	}
	return dir
}

// runDeferredDriver runs testdata/deferred_panels_browser.js in mode and
// decodes what it printed into out. extra is the control server's URL and the
// session's project paths, where the mode takes them.
func runDeferredDriver(t *testing.T, node, chrome, base, device, mode string, out any, extra ...string) {
	t.Helper()
	// Bounded, so a stalled Chrome cannot hold the package to its timeout
	// (Task 20340).
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	args := append([]string{mustAbs(t, "testdata/deferred_panels_browser.js"), chrome, base, device, mode}, extra...)
	raw, err := exec.CommandContext(ctx, node, args...).Output()
	if os.Getenv("DEFERRED_PANELS_DEBUG") != "" {
		t.Logf("driver output (%s):\n%s", mode, raw)
	}
	if jerr := json.Unmarshal(raw, out); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%s\nstderr:\n%s", err, jerr, raw, stderr)
	}
}

// seedHub makes one API call the test needs before the browser starts.
func seedHub(t *testing.T, ts *httptest.Server, method, path, body string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s = %d: %s", method, path, resp.StatusCode, b)
	}
}

// fileRequestAs files an access request for the seeded secret as actor, the
// way another user's dashboard would have.
func fileRequestAs(t *testing.T, dir, actor string) {
	t.Helper()
	bs, err := openBrokersAt(dir)
	if err != nil {
		t.Fatalf("open brokers: %v", err)
	}
	defer bs.close()
	if bs.secret == nil {
		t.Fatalf("no secret broker: %+v", bs.status)
	}
	subject, err := secretbroker.ParseSubject("project:*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bs.secret.RequestAccess(context.Background(), secretbroker.AccessRequestInput{
		SecretRef:     "dp-seeded",
		Subject:       subject,
		Constraints:   secretbroker.Constraints{EnvKeys: []string{"FOO"}},
		TTL:           time.Hour,
		Justification: "deferred panels: filed by somebody else",
		Actor:         actor,
	}); err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
}

// compact is raw JSON without the driver's indentation, for substring checks.
func compact(raw json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return string(raw)
	}
	return b.String()
}

// fetchedScript reports whether the driver saw the deferred script stem fetched.
func fetchedScript(list []string, stem string) bool {
	for _, x := range list {
		if x == stem {
			return true
		}
	}
	return false
}
