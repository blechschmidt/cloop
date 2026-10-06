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
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot open a panel a user would")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// One project, so the landing tab is its Overview and boot never moves
	// the page under the driver; and a secret store, so the Secrets dialogs
	// have something to act on (set here rather than inherited, so this runs
	// the same in CI as on a hub's own box).
	t.Setenv(multiui.EnvRoot, t.TempDir())
	t.Setenv(secretbroker.EnvPassphraseKey, "deferred-panels-browser-passphrase")
	dir := setupProjectDir(t, "deferred panels", nil)
	device := seedDevice(t, dir, "dp-device-1")
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
	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 100000, 100000
	installQuotas(t, srv, quota.Config{Defaults: quota.Limits{quota.ResProjects: 1}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// What the panels show: a secret, a quota override, a telemetry event, and
	// an access request filed by somebody else — the only kind this hub's
	// anonymous admin may decide.
	seedHub(t, ts, http.MethodPost, "/api/secrets",
		`{"name":"dp-seeded","kind":"env","payload":"{\"FOO\":\"bar\"}","personal":false}`)
	seedHub(t, ts, http.MethodPut, "/api/quotas/bob@example.com", `{"limits":{"max_projects":3}}`)
	seedHub(t, ts, http.MethodPut, "/api/config/telemetry", `{"enabled":true}`)
	seedHub(t, ts, http.MethodPost, "/api/telemetry",
		`{"source":"dashboard","session":"dp0000000000000000","events":[{"kind":"error","seq":1,"message":"deferred-panels-seed"}]}`)
	fileRequestAs(t, dir, "dana@example.com")

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

// runDeferredDriver runs testdata/deferred_panels_browser.js in mode and
// decodes what it printed into out.
func runDeferredDriver(t *testing.T, node, chrome, base, device, mode string, out any) {
	t.Helper()
	// Bounded, so a stalled Chrome cannot hold the package to its timeout
	// (Task 20340).
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	raw, err := exec.CommandContext(ctx, node, mustAbs(t, "testdata/deferred_panels_browser.js"),
		chrome, base, device, mode).Output()
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
