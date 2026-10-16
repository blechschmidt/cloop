package ui

// The hub health indicator and its Settings panel, driven through the real
// dashboard bundle under the node DOM shim (Task 20434): an administrator's
// indicator follows the hub's report — at load, on the hub_health push, at the
// report's expiry — a viewer's page never asks, and the panel draws what a
// check wrote as text.

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
	Retry  bool                `json:"retry"`
	First  hubHealthBadgeState `json:"first"`
	Before hubHealthBadgeState `json:"before"`
	After  hubHealthBadgeState `json:"after"`
	HTML   string              `json:"html"`
	Status string              `json:"status"`
	Full   int                 `json:"full"`
	XSS    any                 `json:"xss"`
	Error  string              `json:"error"`
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
// administrator, asked once at load however many reasons arrive together, put
// out by a push that brings an all-clear, asked again when the report
// expires, and not asked again after a refusal.
func TestDashboard_HubHealthIndicator(t *testing.T) {
	results := runHubHealthScenarios(t)

	a := results["admin_indicator_follows_the_report"]
	if !a.First.Shown || !strings.HasSuffix(a.First.Text, " 2") || a.First.Label != "2 hub health checks failing" ||
		a.First.Asked != 1 {
		t.Errorf("at load the indicator is %+v; want it lit with 2, asked once for /api/me and the socket together", a.First)
	}
	if a.After.Shown || a.After.Asked != 2 {
		t.Errorf("after an all-clear push the indicator is %+v; want it out after one more question", a.After)
	}

	e := results["the_expiry_is_asked_about"]
	if !e.Before.Shown || e.Before.Asked != 1 || !e.After.Shown || !strings.HasSuffix(e.After.Text, " 4") ||
		e.After.Asked != 2 {
		t.Errorf("past the report's expiry by the hub's clock, an hour behind the page's: before %+v, after %+v; "+
			"want one more question and its answer shown", e.Before, e.After)
	}

	r := results["a_refusal_is_not_asked_again"]
	if r.Asked != 1 || r.Shown {
		t.Errorf("after a 403 the report was asked for %d time(s) (shown %v); want once and no indicator", r.Asked, r.Shown)
	}

	f := results["a_failed_answer_is_retried"]
	if f.Asked != 1 || f.Shown || !f.Retry {
		t.Errorf("after a 500 the indicator is %+v; want it asked once, out, and asking again in a minute", f)
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
	if p.XSS != nil {
		t.Errorf("something ran: window.__xss = %v", p.XSS)
	}
}
