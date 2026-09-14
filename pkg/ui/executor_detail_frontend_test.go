package ui

// The executor detail drill-in, executed rather than grepped (Task 20258).
//
// GET /api/executors/{id} computed the hub's audit answer — in-flight work,
// recent completions with project attribution, sweep coverage, and host_total —
// from Task 20244 onward, and no frontend code called it. That defect is
// invisible to a source-level gate: every assertion a grep could make about
// 23-executors.js ("the markup exists", "the endpoint is named") would have
// passed while the panel was unreachable.
//
// What a grep cannot check at all is the property this panel exists for: the
// three states of the host verdict must be distinguishable on screen. "We swept
// everything and found no host runs", "we hit the cap so zero is a lower bound",
// and "we could not look" are three different facts, and rendering the second
// or third like the first turns an audit view into false reassurance. Those
// assertions are about rendered output, so the bundle is run.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type execDetailResult struct {
	HTML       string   `json:"html"`
	List       string   `json:"list"`
	Overlay    string   `json:"overlay"`
	Toast      string   `json:"toast"`
	Breadcrumb string   `json:"breadcrumb"`
	Requests   []string `json:"requests"`
	Error      string   `json:"error"`
}

// runExecDetailScenarios executes the shipped bundle against the DOM shim and
// returns each scenario's rendered output.
func runExecDetailScenarios(t *testing.T) map[string]execDetailResult {
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
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/executor_detail_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}

	cmd := exec.Command(node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var results map[string]execDetailResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	for name, res := range results {
		if res.Error != "" {
			t.Fatalf("scenario %s threw: %s", name, res.Error)
		}
	}
	return results
}

// openingTag returns the opening tag containing the first occurrence of needle,
// so an assertion can ask what a specific element carries rather than what the
// markup contains somewhere. Attribute order inside the tag does not matter.
func openingTag(html, needle string) (string, bool) {
	i := strings.Index(html, needle)
	if i < 0 {
		return "", false
	}
	start := strings.LastIndex(html[:i], "<")
	end := strings.Index(html[i:], ">")
	if start < 0 || end < 0 {
		return "", false
	}
	return html[start : i+end+1], true
}

// TestDashboard_ExecutorDetailIsAuditable is the reachability half: clicking a
// card calls the endpoint, and what comes back reaches the screen.
func TestDashboard_ExecutorDetailIsAuditable(t *testing.T) {
	results := runExecDetailScenarios(t)

	// ---- the card is the way in ----------------------------------------
	//
	// The card *surface*, not merely some button on it. Asserting that
	// "openExecutorDetail(0)" appears anywhere in the list would be satisfied
	// by the History button alone, and clicking the card — which is what the
	// panel's affordances promise — would silently do nothing.
	list := results["clean"].List
	if tag, ok := openingTag(list, "exec-card-main"); !ok {
		t.Errorf("no exec-card-main region on the card, so there is no clickable "+
			"surface to drill in from:\n%s", list)
	} else if !strings.Contains(tag, "openExecutorDetail(") {
		t.Errorf("the executor card's main region carries no drill-in handler, so "+
			"clicking the card does nothing:\n%s", tag)
	}
	if !strings.Contains(list, "openExecutorDetail(0)") {
		t.Errorf("no index-dispatched drill-in on the card, so the detail "+
			"endpoint stays unreachable from the dashboard:\n%s", list)
	}

	// ---- the endpoint is actually called -------------------------------
	var called bool
	for _, u := range results["clean"].Requests {
		if strings.HasPrefix(u, "/api/executors/edge-1") {
			called = true
			break
		}
	}
	if !called {
		t.Errorf("opening the drill-in never requested GET /api/executors/{id} — "+
			"the panel is rendering from the list payload, which carries no "+
			"workload at all.\nrequests: %v", results["clean"].Requests)
	}
	if results["clean"].Overlay != "flex" {
		t.Errorf("the detail overlay was not shown (display=%q)", results["clean"].Overlay)
	}

	// ---- liveness and coverage -----------------------------------------
	clean := results["clean"].HTML
	if strings.TrimSpace(clean) == "" {
		t.Fatal("the detail panel rendered nothing")
	}
	for _, want := range []struct{ label, substr string }{
		{"last heartbeat", "Last heartbeat"},
		{"sweep coverage", "Swept 2 projects"},
		{"in-flight section", "In flight"},
		{"completions section", "Recent completions"},
		{"the completed task's title", "ran in a sandbox"},
		{"the owning project", "alpha"},
	} {
		if !strings.Contains(clean, want.substr) {
			t.Errorf("the %s (%q) is not on the page.\nrendered:\n%s",
				want.label, want.substr, clean)
		}
	}
}

// TestDashboard_ExecutorDetailHostVerdictIsPlain pins the headline: host_total
// is stated in words, and the three ways of arriving at a zero do not render
// alike.
func TestDashboard_ExecutorDetailHostVerdictIsPlain(t *testing.T) {
	results := runExecDetailScenarios(t)

	// ---- work ran on the host ------------------------------------------
	host := results["host_runs"].HTML
	if !strings.Contains(host, "ran directly on this host") {
		t.Errorf("an executor with host_total=2 does not say so in words — the "+
			"number is buried where an operator has to notice a 2 is not a 0:\n%s", host)
	}
	if !strings.Contains(host, "2 tasks") {
		t.Errorf("the host run count is not stated:\n%s", host)
	}
	if !strings.Contains(host, "exec-detail-verdict bad") {
		t.Errorf("the host-run verdict is not rendered in the alarming style, so "+
			"it reads like any other row:\n%s", host)
	}
	// Each offending task is identifiable, not just counted: a total an
	// operator cannot act on is half an answer.
	for _, want := range []string{"ran on host", "#11", "#12", "beta"} {
		if !strings.Contains(host, want) {
			t.Errorf("the host-run rows do not carry %q:\n%s", want, host)
		}
	}

	// ---- a complete sweep that found nothing ---------------------------
	clean := results["clean"].HTML
	if !strings.Contains(clean, "exec-detail-verdict good") {
		t.Errorf("a complete sweep with no host runs does not render the "+
			"affirmative verdict:\n%s", clean)
	}
	if strings.Contains(clean, "ran directly on this host") {
		t.Errorf("a clean executor was flagged for host execution:\n%s", clean)
	}
	// Silence about the cap is the requirement: hedging a complete sweep
	// teaches operators to ignore the hedge when it is real.
	if strings.Contains(clean, "lower bound") {
		t.Errorf("an untruncated sweep was hedged as a lower bound:\n%s", clean)
	}

	// ---- the same zero, from a capped sweep ----------------------------
	trunc := results["truncated"].HTML
	if !strings.Contains(trunc, "lower bound") {
		t.Errorf("a truncated sweep does not say its figures are a lower bound — "+
			"silent truncation reads as 'we checked everything' when it did "+
			"not:\n%s", trunc)
	}
	if strings.Contains(trunc, "exec-detail-verdict good") {
		t.Errorf("a capped sweep earned the affirmative verdict. host_total is 0 "+
			"here for the same reason it is 0 in the clean case, and the panel "+
			"must not present the two identically:\n%s", trunc)
	}
	if !strings.Contains(trunc, "not every project was read") {
		t.Errorf("the capped sweep does not say what it failed to cover:\n%s", trunc)
	}

	// ---- the same zero, from a sweep that read nothing -----------------
	//
	// Found by pointing the panel at a live `cloop ui`: a project with no plan
	// yet is skipped without incrementing projects_scanned, so a fresh hub
	// reports host_total 0 over zero projects read. That is the truncation
	// problem reached by a different route, and it fires on a hub's first day
	// — precisely when someone checks the guarantee for the first time.
	none := results["nothing_scanned"].HTML
	if strings.Contains(none, "exec-detail-verdict good") {
		t.Errorf("a sweep that read no project at all still earned the affirmative "+
			"verdict. Zero projects scanned supports no claim about host "+
			"execution:\n%s", none)
	}
	if !strings.Contains(none, "No project history was read") {
		t.Errorf("a sweep that covered nothing does not say so:\n%s", none)
	}
}

// TestDashboard_ExecutorDetailRefusalIsNotACleanRecord is the security-relevant
// assertion. A caller who may not read the fleet gets 404 rather than 403 —
// require() withholds existence instead of confirming it — and a panel that
// rendered that as "0 tasks ran on the host" would report the absence of an
// answer as proof of compliance.
func TestDashboard_ExecutorDetailRefusalIsNotACleanRecord(t *testing.T) {
	results := runExecDetailScenarios(t)

	// Both refusal shapes: a 404 body arrives in .then(), while a 403 is
	// rejected inside parseAPIResponse and never reaches the panel as data.
	for _, name := range []string{"not_found", "forbidden"} {
		got := results[name].HTML
		if strings.TrimSpace(got) == "" {
			t.Errorf("%s: the panel is still showing nothing — a refused request "+
				"left 'Loading…' on screen instead of explaining itself", name)
			continue
		}
		if strings.Contains(got, "Loading") {
			t.Errorf("%s: the panel never left its loading state:\n%s", name, got)
		}
		if !strings.Contains(got, "could not be read") {
			t.Errorf("%s: the panel does not say the history was unreadable:\n%s", name, got)
		}
		// The whole point: no verdict, no counts, nothing that could be read
		// as evidence either way.
		for _, forbidden := range []string{
			"exec-detail-verdict good",
			"Nothing attributed to this executor ran on the host",
			"Swept ",
			"Recent completions",
			"In flight",
		} {
			if strings.Contains(got, forbidden) {
				t.Errorf("%s: a refused request rendered %q — an unread history is "+
					"being presented as an empty one:\n%s", name, forbidden, got)
			}
		}
	}
}

// TestDashboard_ExecutorDetailLinksBackToTheTask covers the navigation half:
// a completion links to its own project's task, and a row whose project this
// browser does not hold refuses rather than guessing.
func TestDashboard_ExecutorDetailLinksBackToTheTask(t *testing.T) {
	results := runExecDetailScenarios(t)

	// ---- the cap is stated ---------------------------------------------
	capped := results["in_flight_and_cap"].HTML
	if !strings.Contains(capped, "showing 25 of 400") {
		t.Errorf("25 rows out of 400 completions are presented without saying so, "+
			"so the list reads as the whole history:\n%s", capped)
	}
	if !strings.Contains(capped, "running right now") {
		t.Errorf("in-flight work is not listed:\n%s", capped)
	}
	// Attributed-but-reset tasks are counted in host_total, so their absence
	// from both lists has to be explained or the totals look like a bug.
	if !strings.Contains(capped, "neither running nor finished") {
		t.Errorf("the not_running count is not explained:\n%s", capped)
	}

	// ---- a resolvable project ------------------------------------------
	known := results["known_project_link"]
	if known.Breadcrumb != "beta" {
		t.Errorf("clicking a completion did not open its own project "+
			"(breadcrumb=%q, want %q)", known.Breadcrumb, "beta")
	}
	var opened bool
	for _, u := range known.Requests {
		// project_idx=1 is beta's position in this browser's list. The index
		// matters: /api/tasks/{id}/details is project-scoped, so resolving to
		// the wrong one would show a different project's task 42.
		if strings.Contains(u, "/api/tasks/42/details") && strings.Contains(u, "project_idx=1") {
			opened = true
			break
		}
	}
	if !opened {
		t.Errorf("the task was not opened in the project that ran it.\nrequests: %v",
			known.Requests)
	}

	// ---- a project this browser does not have --------------------------
	//
	// The sweep reads every project the hub serves, which is not the same set
	// as the list this browser holds. Navigating anyway would send an operator
	// to whichever project sits at that index — a wrong answer dressed as a
	// right one, and on an audit screen that is worse than refusing.
	unknown := results["unknown_project_link"]
	if unknown.Breadcrumb != "" {
		t.Errorf("a row whose project is not in the browser's list still "+
			"navigated somewhere (breadcrumb=%q)", unknown.Breadcrumb)
	}
	if !strings.Contains(unknown.Toast, "gamma") {
		t.Errorf("the refusal does not name the project it could not resolve "+
			"(toast=%q)", unknown.Toast)
	}
}
