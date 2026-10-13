package ui

// The approvals badge, driven through the real dashboard bundle under the node
// DOM shim (Task 20427): it follows the hub's broadcasts — a request filed,
// decided, withdrawn, lapsed, a token waiting — by asking for the caller's own
// count, never by reading a row out of the broadcast.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type badgeState struct {
	Step  string `json:"step"`
	Shown bool   `json:"shown"`
	Text  string `json:"text"`
	Asked int    `json:"asked"`
}

type badgeScenario struct {
	Steps  []badgeState `json:"steps"`
	Asked  int          `json:"asked"`
	Shown  bool         `json:"shown"`
	Text   string       `json:"text"`
	Before badgeState   `json:"before"`
	After  badgeState   `json:"after"`
	Other  string       `json:"other"`
	Mine   string       `json:"mine"`
	Error  string       `json:"error"`
}

func runBadgeScenarios(t *testing.T) map[string]badgeScenario {
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
		t.Fatal(err)
	}
	scenarios, err := filepath.Abs("testdata/approvals_badge_scenarios.js")
	if err != nil {
		t.Fatal(err)
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
	var results map[string]badgeScenario
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

// TestDashboard_ApprovalsBadgeFollowsTheBroadcasts: filing shows the badge,
// deciding, withdrawing and lapsing take it away, a waiting token brings it
// back — each through one fresh count, asked because a broadcast arrived.
func TestDashboard_ApprovalsBadgeFollowsTheBroadcasts(t *testing.T) {
	results := runBadgeScenarios(t)

	steps := results["badge_follows_file_decide_withdraw_lapse"].Steps
	want := []struct {
		step  string
		shown bool
		text  string
	}{
		{"connect", false, ""}, {"file", true, "1"}, {"decide", false, ""}, {"file again", true, "1"},
		{"withdraw", false, ""}, {"file a third", true, "1"}, {"lapse", false, ""}, {"token waits", true, "1"},
	}
	if len(steps) != len(want) {
		t.Fatalf("steps = %+v", steps)
	}
	for i, w := range want {
		s := steps[i]
		if s.Step != w.step || s.Shown != w.shown || (w.shown && !strings.HasSuffix(s.Text, w.text)) {
			t.Errorf("after %q the badge is shown=%v %q, want shown=%v %q", s.Step, s.Shown, s.Text, w.shown, w.text)
		}
		if s.Asked != i+1 {
			t.Errorf("after %q the count was asked %d time(s), want %d: one on connect and one per broadcast", s.Step, s.Asked, i+1)
		}
	}

	if b := results["a_burst_is_asked_about_once"]; b.Asked != 1 || !b.Shown || !strings.HasSuffix(b.Text, "3") {
		t.Errorf("a burst of five broadcasts asked %d time(s) and shows %v %q; want one question and 3", b.Asked, b.Shown, b.Text)
	}
	if c := results["lease_churn_is_not_asked_about"]; c.Asked != 0 || !c.Shown {
		t.Errorf("lease and grant churn asked %d time(s) (badge shown=%v); want none — it moves nothing the badge counts",
			c.Asked, c.Shown)
	}

	d := results["the_soonest_deadline_is_asked_about"]
	if !d.Before.Shown || d.After.Shown || d.After.Asked != d.Before.Asked+1 {
		t.Errorf("past the soonest deadline: before %+v, after %+v; want one more question and the badge gone", d.Before, d.After)
	}

	o := results["the_answer_is_said_once"]
	if !strings.Contains(o.Mine, "Your access request was approved") || o.Other != "" {
		t.Errorf("a decision broadcast twice was said %q, then %q; want it said once", o.Mine, o.Other)
	}

	r := results["the_requester_hears_the_answer"]
	if r.Other != "" {
		t.Errorf("a decision on somebody else's request was announced: %q", r.Other)
	}
	if !strings.Contains(r.Mine, "Your access request was denied") {
		t.Errorf("the requester was not told their request was denied: %q", r.Mine)
	}
}
