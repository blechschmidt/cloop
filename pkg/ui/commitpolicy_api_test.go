package ui

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// TestOptionsToggle_CommitPolicy: the Overview's "Done = Committed" and
// "…and Pushed" badges (Task 20370) store the project's commit policy through
// its own setter — not a full save of the handler's copy, which could write
// stale tasks over a running orchestrator's — and pushing implies committing.
func TestOptionsToggle_CommitPolicy(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	policy := func() *pm.CommitPolicy {
		t.Helper()
		return loadStateOrFail(t, dir).CommitPolicy
	}
	toggle := func(flag string, value bool) map[string]interface{} {
		t.Helper()
		body := apiPOST(t, ts, "/api/options/toggle", map[string]interface{}{"flag": flag, "value": value})
		if body["ok"] != true {
			t.Fatalf("toggle %s=%v: %v", flag, value, body)
		}
		return body
	}

	if p := policy(); p.Active() {
		t.Fatalf("a new project already requires commits: %+v", p)
	}

	// "…and Pushed" alone turns the whole check on.
	body := toggle("require_pushed", true)
	if got, _ := body["commit_policy"].(map[string]interface{}); got["enabled"] != true || got["pushed"] != true {
		t.Errorf("response commit_policy = %v", body["commit_policy"])
	}
	if p := policy(); !p.RequiresPush() {
		t.Fatalf("policy after require_pushed = %+v", p)
	}

	// Off keeps the pushed preference for the next time it is switched on.
	toggle("require_committed", false)
	if p := policy(); p.Active() || !p.Pushed {
		t.Errorf("policy after switching off = %+v, want off with pushed remembered", p)
	}
	toggle("require_committed", true)
	if p := policy(); !p.RequiresPush() {
		t.Errorf("policy after switching back on = %+v", p)
	}
	toggle("require_pushed", false)
	if p := policy(); !p.Active() || p.Pushed {
		t.Errorf("policy after dropping pushed = %+v, want committed only", p)
	}

	// The setting is not touched by the other badges' full saves.
	toggle("auto_evolve", true)
	if p := policy(); !p.Active() {
		t.Errorf("another badge's save switched the policy off: %+v", p)
	}
	if !loadStateOrFail(t, dir).AutoEvolve {
		t.Error("auto_evolve was not stored")
	}
}

// A running orchestrator's merging save adopts a policy the dashboard set
// meanwhile instead of writing its own stale copy back.
func TestCommitPolicyReachesARunningProcess(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	run, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if run.Plan == nil {
		run.Plan = &pm.Plan{Goal: "g"}
	}
	run.Plan.Tasks = append(run.Plan.Tasks, &pm.Task{ID: 99, Title: "t", Status: pm.TaskInProgress})
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}
	if err := state.SetCommitPolicy(dir, &pm.CommitPolicy{Enabled: true, Pushed: true}); err != nil {
		t.Fatal(err)
	}
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}
	if !run.CommitPolicy.RequiresPush() {
		t.Errorf("the run's own copy did not pick the policy up on save: %+v", run.CommitPolicy)
	}
	if p := loadStateOrFail(t, dir).CommitPolicy; !p.RequiresPush() {
		t.Errorf("the run's save undid the policy: %+v", p)
	}
}
