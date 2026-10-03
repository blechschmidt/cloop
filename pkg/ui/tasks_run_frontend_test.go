package ui

// The Tasks tab's Start/Stop bar, driven through the real dashboard bundle
// (Task 20253).
//
// Adding a third place that starts a run is cheap; keeping three places
// agreeing about one project is not. These run the shipped bundle in node
// against testdata/domshim.js and read back what the user would click, because
// the properties that matter here — "follows run state without a navigation",
// "acts on the viewed project" — are not statements about any string in the
// source. A grep gate cannot fail when a Start button sits on a running
// project, and that is the case that costs a duplicate harness.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runPair is every copy of the Run/Stop affordance, as the user sees it, and
// what the Tasks tab's run bar says beside it.
type runPair struct {
	OverviewRun  bool   `json:"overviewRun"`
	OverviewStop bool   `json:"overviewStop"`
	TasksRun     bool   `json:"tasksRun"`
	TasksStop    bool   `json:"tasksStop"`
	BarVisible   bool   `json:"barVisible"`
	Status       string `json:"status"`
	StatusClass  string `json:"statusClass"`
	EvolveChip   bool   `json:"evolveChip"`
	Title        string `json:"title"`
}

type tasksRunResult struct {
	// Flat scenarios report one snapshot.
	runPair
	// Sequenced scenarios report one per step.
	Started    *runPair `json:"started"`
	Stopped    *runPair `json:"stopped"`
	After      *runPair `json:"after"`
	Running    *runPair `json:"running"`
	Evolving   *runPair `json:"evolving"`
	Discovered *runPair `json:"discovered"`
	Replayed   *runPair `json:"replayed"`
	Resumed    *runPair `json:"resumed"`
	Finished   *runPair `json:"finished"`
	Paused     *runPair `json:"paused"`
	Complete   *runPair `json:"complete"`

	Posts         []string `json:"posts"`
	WhileSelected *bool    `json:"whileSelected"`
	AfterClearing *bool    `json:"afterClearing"`
	WithGoal      *bool    `json:"withGoal"`
	WithoutGoal   *bool    `json:"withoutGoal"`
	Off           *bool    `json:"off"`
	On            *bool    `json:"on"`
	ToggledOff    *bool    `json:"toggledOff"`
	Error         string   `json:"error"`
}

func runTasksRunScenarios(t *testing.T) map[string]tasksRunResult {
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
	scenarios, err := filepath.Abs("testdata/tasks_run_scenarios.js")
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

	var results map[string]tasksRunResult
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

// wantPair asserts exactly one of Start/Stop is offered, in both places, and
// that the run bar's status says word.
func wantPair(t *testing.T, what string, got runPair, running bool, word string) {
	t.Helper()

	if got.TasksRun == running {
		t.Errorf("%s: Tasks tab Start visible = %v with running = %v — "+
			"a Start button on a running project invites the duplicate harness "+
			"handleRun refuses", what, got.TasksRun, running)
	}
	if got.TasksStop != running {
		t.Errorf("%s: Tasks tab Stop visible = %v, want %v", what, got.TasksStop, running)
	}
	// The two pages are driven from one function precisely so this can never
	// diverge; if it does, someone has added a second updater.
	if got.OverviewRun != got.TasksRun || got.OverviewStop != got.TasksStop {
		t.Errorf("%s: Overview offers run=%v/stop=%v while Tasks offers run=%v/stop=%v — "+
			"the two pages disagree about the same project",
			what, got.OverviewRun, got.OverviewStop, got.TasksRun, got.TasksStop)
	}
	// A lone button says nothing about which state it belongs to; the page
	// carries no other status of its own. Since Task 20358 that status is the
	// project's own, in the Overview's words, so the word differs by state.
	if !strings.Contains(got.Status, word) {
		t.Errorf("%s: run bar status reads %q, want it to say %q", what, got.Status, word)
	}
	// And never the opposite of the button beside it.
	if running && strings.Contains(got.Status, "Not running") {
		t.Errorf("%s: run bar says %q beside a Stop button", what, got.Status)
	}
	if !running && (strings.Contains(got.Status, ">Running") || strings.Contains(got.Status, ">Evolving")) {
		t.Errorf("%s: run bar says %q beside a Start button", what, got.Status)
	}
}

// TestDashboard_TasksTabStartsRuns is the reason the bar exists: an idle
// project must be startable from the page its plan is on.
func TestDashboard_TasksTabStartsRuns(t *testing.T) {
	t.Parallel()

	results := runTasksRunScenarios(t)

	idle := results["idle_offers_start"]
	if !idle.BarVisible {
		t.Fatal("the Tasks tab shows no run bar for a loaded project — starting a run " +
			"still means navigating back to the Overview tab or the Projects grid")
	}
	// An initialised project that has never run is "Ready", as on the Overview.
	wantPair(t, "idle project", idle.runPair, false, "Ready")
}

// TestDashboard_TasksRunBarFollowsRunState covers the live path. A bar that
// only refreshed on navigation would sit there offering Start for as long as
// the user stayed on the page.
func TestDashboard_TasksRunBarFollowsRunState(t *testing.T) {
	t.Parallel()

	results := runTasksRunScenarios(t)

	flip := results["run_state_flips_the_pair_without_navigating"]
	if flip.Started == nil || flip.Stopped == nil {
		t.Fatal("scenario returned no snapshots")
	}
	wantPair(t, "after run_state{running:true}", *flip.Started, true, "Running")
	wantPair(t, "after run_state{running:false}", *flip.Stopped, false, "Ready")

	// And on first paint, where the status rides in on the hydrating frame
	// rather than on a run_state event.
	wantPair(t, "project already running when opened",
		results["running_project_offers_stop_on_arrival"].runPair, true, "Running")
}

// TestDashboard_TasksStartActsOnTheViewedProject is the scoping guard. Every
// previous recurrence of this bug class was a control that rendered under one
// project and dispatched against another.
func TestDashboard_TasksStartActsOnTheViewedProject(t *testing.T) {
	t.Parallel()

	results := runTasksRunScenarios(t)

	got := results["start_posts_the_viewed_project"]
	if len(got.Posts) != 1 {
		t.Fatalf("Start produced %d requests to /api/run (%v), want exactly one", len(got.Posts), got.Posts)
	}
	// beta is index 1. An unscoped URL is the failure: the server then falls
	// back to its own WorkDir and starts a run on a project nobody asked about.
	if !strings.Contains(got.Posts[0], "project_idx=1") {
		t.Errorf("Start posted %q — it must carry the selected project's index, "+
			"or the hub starts a run on whatever its own working directory points at",
			got.Posts[0])
	}
}

// TestDashboard_TasksRunBarBelievesTheServersRefusal checks the client defers
// to the 409 rather than leaving a Start button on a project it now knows is
// running.
func TestDashboard_TasksRunBarBelievesTheServersRefusal(t *testing.T) {
	t.Parallel()

	results := runTasksRunScenarios(t)
	wantPair(t, "after the server refused a second run",
		results["refusal_corrects_the_button"].runPair, true, "Running")
}

// TestDashboard_TasksRunBarHidesWithoutAProject checks the bar disappears when
// there is nothing for it to start. Both cases would otherwise offer a button
// whose only outcome is acting on the wrong project or an error.
func TestDashboard_TasksRunBarHidesWithoutAProject(t *testing.T) {
	t.Parallel()

	results := runTasksRunScenarios(t)

	sel := results["no_selection_hides_the_bar"]
	if sel.WhileSelected == nil || sel.AfterClearing == nil {
		t.Fatal("scenario returned no visibility readings")
	}
	if !*sel.WhileSelected {
		t.Error("the bar was already hidden with a project selected — the scenario proves nothing")
	}
	if *sel.AfterClearing {
		t.Error("the run bar survives clearing the project selection — pUrl then drops " +
			"the index, so Start would run the hub's own default project")
	}

	init := results["uninitialised_project_hides_the_bar"]
	if init.WithGoal == nil || init.WithoutGoal == nil {
		t.Fatal("scenario returned no visibility readings")
	}
	if !*init.WithGoal {
		t.Error("the bar was already hidden for a project with a goal — the scenario proves nothing")
	}
	if *init.WithoutGoal {
		t.Error("the run bar is offered on a project with no goal, where Start can only fail")
	}
}

// TestDashboard_EvolvingRunOffersStop is Task 20358: a run in an evolve round is
// a running run. The hub has always counted 'evolving' as in flight — stale
// recovery, health, the quota sweep — but the dashboard keyed on 'running'
// alone, so every evolve round offered Start on a live harness (one click from
// the duplicate dispatch handleRun refuses) and the Tasks tab read
// "Not running".
func TestDashboard_EvolvingRunOffersStop(t *testing.T) {
	t.Parallel()

	results := runTasksRunScenarios(t)

	arrival := results["evolving_project_offers_stop_on_arrival"].runPair
	wantPair(t, "project opened mid evolve round", arrival, true, "Evolving")
	if !strings.Contains(arrival.StatusClass, "evolving") {
		t.Errorf("run bar status class is %q, want the Overview's evolving badge", arrival.StatusClass)
	}
	if !strings.Contains(arrival.Title, "Evolving") {
		t.Errorf("browser title is %q while the run evolves, want it to say so", arrival.Title)
	}

	// The frames a live run produces. None of the round's redraws comes with a
	// run_state, so this is the sequence that used to flip the pair to Start.
	round := results["evolve_round_keeps_stop"]
	steps := []struct {
		name    string
		got     *runPair
		running bool
		word    string
	}{
		{"running its last task", round.Running, true, "Running"},
		{"status turned evolving", round.Evolving, true, "Evolving"},
		{"evolve round added a task", round.Discovered, true, "Evolving"},
		{"run_state replayed mid round", round.Replayed, true, "Evolving"},
		{"run picked up the new task", round.Resumed, true, "Running"},
		{"run finished", round.Finished, false, "Complete"},
	}
	for _, st := range steps {
		if st.got == nil {
			t.Fatalf("evolve round: no snapshot for %q", st.name)
		}
		wantPair(t, "evolve round, "+st.name, *st.got, st.running, st.word)
	}

	// Stop answered before the process exits: the stored status still says
	// evolving, but the bar must not name it beside the Start button.
	wantPair(t, "after Stop during an evolve round",
		results["stop_during_evolve"].runPair, false, "Not running")
}

// TestDashboard_TasksRunBarShowsEvolveMode checks the Tasks tab says when the
// project is in Evolve Mode (Task 20358). It decides whether a run stops when
// the plan drains or keeps adding tasks, and it was set and shown only on the
// Overview.
func TestDashboard_TasksRunBarShowsEvolveMode(t *testing.T) {
	t.Parallel()

	results := runTasksRunScenarios(t)

	if !results["evolving_project_offers_stop_on_arrival"].EvolveChip {
		t.Error("a project in Evolve Mode shows no Evolve Mode chip on the Tasks tab")
	}
	chip := results["evolve_chip_follows_the_option"]
	if chip.Off == nil || chip.On == nil || chip.ToggledOff == nil {
		t.Fatal("scenario returned no chip readings")
	}
	if *chip.Off {
		t.Error("the Evolve Mode chip shows on a project with Evolve Mode off")
	}
	if !*chip.On {
		t.Error("the Evolve Mode chip stays hidden after the project's state turned Evolve Mode on")
	}
	if *chip.ToggledOff {
		t.Error("the Evolve Mode chip outlives the Overview toggle turning it off — " +
			"the two copies of the option disagree until the server's next frame")
	}
}

// TestDashboard_TasksRunBarNamesTheIdleStatus checks an idle project's bar says
// which kind of idle (Task 20358): a paused run says why, as on the Overview,
// and a finished plan says so, instead of one "Not running" for both.
func TestDashboard_TasksRunBarNamesTheIdleStatus(t *testing.T) {
	t.Parallel()

	results := runTasksRunScenarios(t)

	idle := results["idle_bar_names_the_status"]
	if idle.Paused == nil || idle.Complete == nil {
		t.Fatal("scenario returned no snapshots")
	}
	wantPair(t, "paused by the operator", *idle.Paused, false, "Paused: stopped by operator")
	wantPair(t, "plan complete", *idle.Complete, false, "Complete")
	if idle.Complete.EvolveChip {
		t.Error("the Evolve Mode chip shows on a project with Evolve Mode off")
	}
}
