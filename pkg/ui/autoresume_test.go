package ui

import (
	"sort"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
)

// These drive the sweep with an injected clock rather than a sleep: the thing
// being tested is a five-hour or seven-day window rolling over, and there is
// no wait short enough to make that real and long enough to make it honest.
//
// autoResumeStart is stubbed throughout, so nothing here dispatches a harness.
// A successful run start in a pkg/ui test poisons global executor state and
// flakes the whole package.

// pausedProject builds a project parked with the given reason.
func pausedProject(t *testing.T, reason pausereason.Reason) string {
	t.Helper()
	dir := setupProjectDir(t, "cap pause fixture", nil)

	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	ps.SetPaused(reason)
	if err := ps.Save(); err != nil {
		t.Fatalf("save %s: %v", dir, err)
	}
	return dir
}

// resumeProbe wires a Server with a frozen clock and a dispatch stub,
// returning the server and a pointer to the list of resumed projects.
func resumeProbe(t *testing.T, dir string, now time.Time) (*Server, *[]string) {
	t.Helper()
	srv := New(dir, 0, "")
	srv.nowFn = func() time.Time { return now }
	var resumed []string
	srv.autoResumeStart = func(workDir string) error {
		resumed = append(resumed, workDir)
		return nil
	}
	return srv, &resumed
}

func TestAutoResumeRestartsACapPauseWhoseWindowRolledOver(t *testing.T) {
	reset := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	dir := pausedProject(t, pausereason.NewUntil(
		pausereason.CodeUsageCap, "5-hour cap reached", reset))

	// One second before the reset: still capped, must not be touched.
	srv, resumed := resumeProbe(t, dir, reset.Add(-time.Second))
	if srv.maybeAutoResume(dir) {
		t.Error("resumed a run one second before its window reopened")
	}
	if len(*resumed) != 0 {
		t.Errorf("dispatched %v before the reset", *resumed)
	}

	// One second after: the window has reopened and nothing should be
	// waiting on a human.
	srv, resumed = resumeProbe(t, dir, reset.Add(time.Second))
	if !srv.maybeAutoResume(dir) {
		t.Fatal("did not resume a cap-paused run after its window reopened")
	}
	if len(*resumed) != 1 || (*resumed)[0] != dir {
		t.Errorf("resumed %v, want exactly [%s]", *resumed, dir)
	}
}

func TestAutoResumeLeavesEveryOtherPauseAlone(t *testing.T) {
	past := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	now := past.Add(24 * time.Hour)

	// Each of these is a pause a human has to clear. Resuming any of them on
	// a timer would override the decision that stopped the run — an approval
	// someone declined, a budget someone set, a Stop someone pressed.
	for _, reason := range []pausereason.Reason{
		pausereason.NewUntil(pausereason.CodeApproval, "approval declined", past),
		pausereason.NewUntil(pausereason.CodeBudget, "daily budget spent", past),
		pausereason.NewUntil(pausereason.CodeOperator, "run stopped", past),
		pausereason.NewUntil(pausereason.CodeAbort, "credentials rejected", past),
		pausereason.NewUntil(pausereason.CodeTokenBudget, "token budget spent", past),
		pausereason.NewUntil(pausereason.CodeStale, "run died", past),
		pausereason.NewUntil(pausereason.CodeIdle, "nothing to run", past),
		pausereason.NewUntil(pausereason.CodePlanOnly, "plan only", past),
		// A cap with no reported reset is also off limits: without a reset
		// there is nothing to say the wall has moved.
		pausereason.New(pausereason.CodeUsageCap, "cap reached"),
	} {
		t.Run(string(reason.Code)+"/"+reason.Detail, func(t *testing.T) {
			dir := pausedProject(t, reason)
			srv, resumed := resumeProbe(t, dir, now)
			if srv.maybeAutoResume(dir) {
				t.Errorf("resumed a run paused for %q — only a rolled-over usage cap may resume itself", reason.Code)
			}
			if len(*resumed) != 0 {
				t.Errorf("dispatched %v for a %q pause", *resumed, reason.Code)
			}
		})
	}
}

func TestAutoResumeSkipsAProjectThatIsNotPaused(t *testing.T) {
	reset := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	dir := pausedProject(t, pausereason.NewUntil(
		pausereason.CodeUsageCap, "5-hour cap reached", reset))

	// Someone restarted it by hand. The status write clears the reason at the
	// persistence funnel, so the sweep must see nothing to do — this is the
	// regression that would otherwise start a second harness in one working
	// directory.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ps.Status = "running"
	if err := ps.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	srv, resumed := resumeProbe(t, dir, reset.Add(time.Hour))
	if srv.maybeAutoResume(dir) {
		t.Error("resumed a project whose status is no longer paused")
	}
	if len(*resumed) != 0 {
		t.Errorf("dispatched %v for a running project", *resumed)
	}
}

func TestAutoResumeHonoursTheConfigSwitch(t *testing.T) {
	reset := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	dir := pausedProject(t, pausereason.NewUntil(
		pausereason.CodeUsageCap, "5-hour cap reached", reset))
	srv, resumed := resumeProbe(t, dir, reset.Add(time.Hour))

	// Absent config means on: the default must survive a project that has
	// never been configured for this at all.
	if !srv.autoResumeEnabled() {
		t.Error("auto-resume defaulted to off; an unconfigured hub would keep stalling silently")
	}

	off := false
	cfg, err := srv.loadHubConfig()
	if err != nil {
		t.Fatalf("load hub config: %v", err)
	}
	cfg.UI.AutoResumeOnCapReset = &off
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	if srv.autoResumeEnabled() {
		t.Error("auto-resume stayed on after being switched off in config")
	}

	// The sweep is what reads the switch; maybeAutoResume itself is the
	// per-project policy and is reached only through it.
	srv.runAutoResumeSweep(t.Context())
	if len(*resumed) != 0 {
		t.Errorf("sweep dispatched %v with auto-resume disabled", *resumed)
	}
}

func TestPauseReasonSurvivesAStateRoundTrip(t *testing.T) {
	reset := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	dir := pausedProject(t, pausereason.NewUntil(
		pausereason.CodeUsageCap, "5-hour cap reached", reset))

	// Both load paths matter: the dashboard's project cards are built from
	// LoadLite, so a reason that only survived a full Load would be invisible
	// exactly where it is most needed.
	full, err := state.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	lite, err := state.LoadLite(dir)
	if err != nil {
		t.Fatalf("LoadLite: %v", err)
	}

	for name, ps := range map[string]*state.ProjectState{"Load": full, "LoadLite": lite} {
		if ps.PauseReason == nil {
			t.Errorf("%s: pause reason was dropped by persistence", name)
			continue
		}
		if ps.PauseReason.Code != pausereason.CodeUsageCap {
			t.Errorf("%s: code = %q, want usage_cap", name, ps.PauseReason.Code)
		}
		if ps.PauseReason.Detail != "5-hour cap reached" {
			t.Errorf("%s: detail = %q", name, ps.PauseReason.Detail)
		}
		if ps.PauseReason.ResumesAt == nil || !ps.PauseReason.ResumesAt.Equal(reset) {
			t.Errorf("%s: resumes_at = %v, want %v", name, ps.PauseReason.ResumesAt, reset)
		}
	}
}

// TestPauseReasonReachesTheHTTPAPIs proves the field is actually served, not
// merely persisted. Both endpoints matter and for different screens: /api/state
// drives the project's own Overview badge, /api/projects drives the fleet grid.
// A field that survived to disk but never reached the wire would leave the
// dashboard exactly as uninformative as before.
func TestPauseReasonReachesTheHTTPAPIs(t *testing.T) {
	reset := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	dir := pausedProject(t, pausereason.NewUntil(
		pausereason.CodeUsageCap, "5-hour cap reached", reset))
	ts := newTestServer(t, dir, nil)

	t.Run("/api/state", func(t *testing.T) {
		got := apiGET(t, ts, "/api/state")
		pr, ok := got["pause_reason"].(map[string]interface{})
		if !ok {
			t.Fatalf("/api/state carries no pause_reason; keys present: %v", keysOf(got))
		}
		if pr["code"] != "usage_cap" {
			t.Errorf("code = %v, want usage_cap", pr["code"])
		}
		if pr["detail"] != "5-hour cap reached" {
			t.Errorf("detail = %v", pr["detail"])
		}
		if pr["resumes_at"] == nil {
			t.Error("resumes_at is absent — the dashboard could not say when the run resumes")
		}
	})

	t.Run("/api/projects", func(t *testing.T) {
		got := apiGET(t, ts, "/api/projects")
		list, _ := got["projects"].([]interface{})
		if len(list) == 0 {
			t.Fatalf("/api/projects returned no projects: %v", got)
		}
		first, _ := list[0].(map[string]interface{})
		pr, ok := first["pause_reason"].(map[string]interface{})
		if !ok {
			t.Fatalf("project card carries no pause_reason; keys present: %v", keysOf(first))
		}
		if pr["code"] != "usage_cap" || pr["detail"] != "5-hour cap reached" {
			t.Errorf("project card pause_reason = %v", pr)
		}
		if pr["resumes_at"] == nil {
			t.Error("project card has no resumes_at")
		}
	})
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestResumingClearsThePauseReasonOnDisk(t *testing.T) {
	reset := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	dir := pausedProject(t, pausereason.NewUntil(
		pausereason.CodeUsageCap, "5-hour cap reached", reset))

	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// The caller sets only the status — clearing the reason is the
	// persistence funnel's job, which is what stops a resumed project from
	// still advertising a cap that lifted hours ago.
	ps.Status = "running"
	if err := ps.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	reloaded, err := state.Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.PauseReason != nil {
		t.Errorf("a running project still carries a pause reason: %+v", reloaded.PauseReason)
	}
}
