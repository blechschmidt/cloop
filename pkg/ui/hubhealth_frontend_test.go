package ui

// The hub health indicator and its Settings panel, driven through the real
// dashboard bundle under the node DOM shim (Tasks 20434, 20446): an
// administrator's indicator is asked once at load and on reconnect, and
// follows the hub_health push with no request of its own; a viewer's page
// never asks, and the panel draws what a check wrote as text.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type hubHealthBadgeState struct {
	Shown bool   `json:"shown"`
	Text  string `json:"text"`
	Label string `json:"label"`
	Asked int    `json:"asked"`
}

type hubHealthScenario struct {
	hubHealthBadgeState
	Retry   bool                `json:"retry"`
	First   hubHealthBadgeState `json:"first"`
	Before  hubHealthBadgeState `json:"before"`
	After   hubHealthBadgeState `json:"after"`
	Again   hubHealthBadgeState `json:"again"`
	Expired hubHealthBadgeState `json:"expired"`
	Me      int                 `json:"me"`
	Opened  int                 `json:"opened"`
	Same    int                 `json:"same"`
	Newer   int                 `json:"newer"`
	HTML    string              `json:"html"`
	CA      string              `json:"ca"`
	Status  string              `json:"status"`
	Full    int                 `json:"full"`
	XSS     any                 `json:"xss"`
	Error   string              `json:"error"`
}

// The three tests below read one run of the scenarios: each run takes seconds
// of node time, and what they assert is independent.
var (
	hubHealthScenariosOnce sync.Once
	hubHealthScenariosOut  map[string]hubHealthScenario
	hubHealthScenariosErr  string
)

func runHubHealthScenarios(t *testing.T) map[string]hubHealthScenario {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}
	hubHealthScenariosOnce.Do(func() {
		dir, err := os.MkdirTemp("", "cloop-hubhealth-scenarios-")
		if err != nil {
			hubHealthScenariosErr = err.Error()
			return
		}
		defer os.RemoveAll(dir)
		hubHealthScenariosOut, hubHealthScenariosErr = hubHealthScenarioRun(dir)
	})
	if hubHealthScenariosErr != "" {
		t.Fatal(hubHealthScenariosErr)
	}
	return hubHealthScenariosOut
}

func hubHealthScenarioRun(dir string) (map[string]hubHealthScenario, string) {
	node, _ := exec.LookPath("node")
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		return nil, "write bundle: " + err.Error()
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		return nil, err.Error()
	}
	scenarios, err := filepath.Abs("testdata/hubhealth_scenarios.js")
	if err != nil {
		return nil, err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		return nil, fmt.Sprintf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var results map[string]hubHealthScenario
	if err := json.Unmarshal(out, &results); err != nil {
		return nil, fmt.Sprintf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, r := range results {
		if r.Error != "" {
			return nil, fmt.Sprintf("scenario %s threw: %s", name, r.Error)
		}
	}
	return results, ""
}

// TestDashboard_HubHealthIndicator: lit with the failing count for an
// administrator, asked once at load however many reasons arrive together and
// once more when the socket opens again; not asked after a refusal, asked
// again a minute after a failed answer, and put out — with /api/me re-read and
// nothing asked — when the hub says this socket may no longer read the report.
func TestDashboard_HubHealthIndicator(t *testing.T) {
	results := runHubHealthScenarios(t)

	a := results["admin_indicator_follows_the_report"]
	if !a.First.Shown || !strings.HasSuffix(a.First.Text, " 2") || a.First.Label != "2 hub health checks failing" ||
		a.First.Asked != 1 {
		t.Errorf("at load the indicator is %+v; want it lit with 2, asked once for /api/me and the socket together", a.First)
	}

	c := results["a_reconnect_asks_once"]
	if c.Asked != 2 || !strings.HasSuffix(c.Text, " 3") {
		t.Errorf("after the socket opened again the indicator is %+v; want one more question and its answer shown", c)
	}

	r := results["a_refusal_is_not_asked_again"]
	if r.Asked != 1 || r.Shown {
		t.Errorf("after a 403 the report was asked for %d time(s) (shown %v); want once and no indicator", r.Asked, r.Shown)
	}

	f := results["a_failed_answer_is_retried"]
	if f.Asked != 1 || f.Shown || !f.Retry {
		t.Errorf("after a 500 the indicator is %+v; want it asked once, out, and asking again in a minute", f)
	}

	w := results["a_withdrawal_puts_it_out"]
	if !w.Before.Shown || w.After.Shown || w.After.Asked != w.Before.Asked || w.Me < 1 {
		t.Errorf("a withdrawal left the indicator %+v (from %+v) after %d /api/me read(s); want it out, nothing asked, "+
			"/api/me re-read", w.After, w.Before, w.Me)
	}

	o := results["an_older_hubs_push_is_asked_about"]
	if o.Asked != 2 || !strings.HasSuffix(o.Text, " 6") {
		t.Errorf("an empty push from an older hub left %+v; want it asked once more and the answer shown", o)
	}
}

// TestDashboard_HubHealthPushNeedsNoFetch: the hub's push is the indicator's
// news (Task 20446). An all-clear puts it out and a new failure lights it with
// no request; a report's expiry passes without one, the next report arriving
// by push; and a push of a new report re-reads Settings → Hub health while it
// is on screen, while a push of the report it shows does not.
func TestDashboard_HubHealthPushNeedsNoFetch(t *testing.T) {
	results := runHubHealthScenarios(t)

	a := results["admin_indicator_follows_the_report"]
	if a.After.Shown || a.After.Asked != 1 {
		t.Errorf("after an all-clear push the indicator is %+v; want it out with no further question", a.After)
	}
	if !a.Again.Shown || !strings.HasSuffix(a.Again.Text, " 5") || a.Again.Label != "5 hub health checks failing" ||
		a.Again.Asked != 1 {
		t.Errorf("after a push of 5 failing the indicator is %+v; want it lit with 5 and still one question", a.Again)
	}

	e := results["the_expiry_is_not_asked_about"]
	if !e.Before.Shown || e.Before.Asked != 1 || e.Expired.Asked != 1 || !e.After.Shown ||
		!strings.HasSuffix(e.After.Text, " 4") || e.After.Asked != 1 {
		t.Errorf("around the report's expiry, by the hub's clock an hour behind the page's: before %+v, past it %+v, "+
			"after the push %+v; want one question in all and the pushed count shown", e.Before, e.Expired, e.After)
	}

	p := results["a_push_while_the_panel_is_open_rereads_it"]
	if p.Opened == 0 || p.Same != p.Opened || p.Newer != p.Opened+1 {
		t.Errorf("Settings → Hub health read the report %d time(s) when opened, %d after a push of the same "+
			"generation and %d after a newer one; want one more read, for the newer push only", p.Opened, p.Same, p.Newer)
	}
}

// TestDashboard_HubHealthNotAskedWithoutConfigWrite is the "no indicator"
// half of the route's RBAC: a page whose /api/me grants no config.write sends
// no request for the report — at load, on the push, or on reconnect.
func TestDashboard_HubHealthNotAskedWithoutConfigWrite(t *testing.T) {
	v := runHubHealthScenarios(t)["viewer_never_asks"]
	if v.Asked != 0 || v.Shown {
		t.Errorf("a viewer's page asked for the report %d time(s) and shows %+v; want neither", v.Asked, v)
	}
}

// TestDashboard_HubHealthPanelRendersText: the indicator opens Settings → Hub
// health, which reads the full report and draws it grouped by severity, names
// the member that answered, escapes everything a check wrote, and links only
// to documentation that is a https URL.
func TestDashboard_HubHealthPanelRendersText(t *testing.T) {
	p := runHubHealthScenarios(t)["the_indicator_opens_the_panel"]
	if p.Full == 0 {
		t.Fatal("opening the panel never asked for the full report")
	}
	for _, want := range []string{
		"Failing (1)", "Warnings (1)", "Passing (1)", "<code>hub-a1b2</code>", "hub-01.internal",
		"one of the cluster’s members", ".cloop/config.ui-8081.yaml", "Run the checks again",
		`href="https://blechschmidt.github.io/cloop/docs/operations/runbook/#doctor-gitproxy"`,
		`rel="noopener noreferrer"`, "&lt;img src=x onerror=&quot;window.__xss=1&quot;&gt;",
		"cloop hub doctor --smoke --port 8081",
	} {
		if !strings.Contains(p.HTML, want) {
			t.Errorf("the panel does not show %q:\n%s", want, p.HTML)
		}
	}
	if strings.Contains(p.HTML, "<img") || strings.Contains(p.HTML, "javascript:") {
		t.Errorf("the panel carries markup or a script URL a check wrote:\n%s", p.HTML)
	}
	if p.Status != "1 failing" {
		t.Errorf("the section's badge says %q, want 1 failing", p.Status)
	}
	// The hub CA's section (Task 20438): where the rotation stands, what it
	// waits for, the steps it allows — every value a workload or a member
	// chose drawn as text.
	for _, want := range []string{
		"Certificate authority", ">staged<", "permits hub.internal", "<code>hub_b</code>",
		"Activate anyway…", "Abort the stage…", "&lt;img src=x onerror=&quot;window.__xss=2&quot;&gt;",
		"&lt;script&gt;x&lt;/script&gt;", "user:&lt;b&gt;alice&lt;/b&gt;", "the longest monitor session is 60 min",
	} {
		if !strings.Contains(p.CA, want) {
			t.Errorf("the hub CA section does not show %q:\n%s", want, p.CA)
		}
	}
	if strings.Contains(p.CA, "<img") || strings.Contains(p.CA, "<script") || strings.Contains(p.CA, ">Activate</button>") {
		t.Errorf("the hub CA section carries markup, or offers a plain activation the runs forbid:\n%s", p.CA)
	}
	if p.XSS != nil {
		t.Errorf("something ran: window.__xss = %v", p.XSS)
	}
}
