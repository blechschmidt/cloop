package soak

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The soak's value is entirely in its ability to fail. A green run over a hub
// that delivered nothing, wiped nothing and grew not at all would look exactly
// like a green run over a correct one, so these tests plant the defects the
// soak exists to catch and assert each detector reports them — naming the
// tenant, the task and the offending frame, not a count.
//
// They need no container runtime and are not gated behind CLOOP_SOAK: they
// must run on every `go test ./...`, because a detector that silently stopped
// working would otherwise be discovered only by a soak that quietly passed.

// fakeWorld builds the minimum world the frame classifier reads: two tenants,
// one project each. No hub, no containers.
func fakeWorld() (*world, *project, *project) {
	w := &world{}
	for _, name := range []string{"alpha", "bravo"} {
		tn := &tenant{name: name, email: name + "@soak.invalid", sub: "sub-" + name}
		p := &project{
			name:           name + "-proj0",
			dir:            "/nonexistent/" + name,
			tenant:         tn,
			secretSentinel: "CLOOPSOAKSECRET-" + name + "-" + name + "-proj0",
		}
		tn.projects = append(tn.projects, p)
		w.tenants = append(w.tenants, tn)
		w.projects = append(w.projects, p)
	}
	return w, w.projects[0], w.projects[1]
}

func frame(typ, chunk string) string {
	return fmt.Sprintf(`{"type":%q,"data":{"chunk":%q}}`, typ, chunk)
}

// TestDetector_CatchesCrossTenantLogFrame plants the Task 20189 defect: one
// tenant's live harness output delivered to another tenant's subscriber.
func TestDetector_CatchesCrossTenantLogFrame(t *testing.T) {
	w, alpha, bravo := fakeWorld()
	sub := &subscriber{tenant: alpha.tenant, scope: alpha.name, project: alpha}

	// Alpha's own output: must be counted, must not be a leak.
	sub.classify(w, frame("step_output", "soak line 3 canary="+canaryFor(alpha, 7)))
	// Bravo's output arriving on alpha's stream: the defect.
	sub.classify(w, frame("step_output", "soak line 4 canary="+canaryFor(bravo, 12)))

	frames, own, leaks := sub.snapshot()
	if frames != 2 {
		t.Fatalf("classified %d frames, want 2", frames)
	}
	if own != 1 {
		t.Errorf("own-canary count = %d, want 1 — the positive control is broken, so a "+
			"real soak could report a silent hub as clean", own)
	}
	if len(leaks) != 1 {
		t.Fatalf("detected %d leaks, want 1: a cross-tenant frame went unnoticed", len(leaks))
	}

	// The failure must be actionable. A soak that says "mismatch" teaches
	// nobody anything, so assert the message names all four facts.
	msg := leaks[0].String()
	for _, want := range []string{
		"alpha",       // the recipient that should not have seen it
		"bravo-proj0", // the owner it belonged to
		"task0012",    // the task that produced it
		"step_output", // the frame type that carried it
		"soak line 4", // the offending payload itself
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("leak report omits %q, so a failure would not identify it:\n%s", want, msg)
		}
	}
}

// TestDetector_CatchesLeakedCredentialFrame asserts a leased credential on any
// stream is a finding — including its own owner's, since the hub redacts
// leased values out of harness output and the workload never prints them.
func TestDetector_CatchesLeakedCredentialFrame(t *testing.T) {
	w, alpha, bravo := fakeWorld()

	t.Run("foreign", func(t *testing.T) {
		sub := &subscriber{tenant: alpha.tenant, scope: alpha.name, project: alpha}
		sub.classify(w, frame("step_output", "token: "+bravo.secretSentinel))
		_, _, leaks := sub.snapshot()
		if len(leaks) != 1 || leaks[0].kind != "credential" {
			t.Fatalf("got %+v, want one credential leak", leaks)
		}
	})

	t.Run("own", func(t *testing.T) {
		sub := &subscriber{tenant: alpha.tenant, scope: alpha.name, project: alpha}
		sub.classify(w, frame("step_output", "token: "+alpha.secretSentinel))
		_, _, leaks := sub.snapshot()
		if len(leaks) != 1 {
			t.Fatalf("a tenant's own credential appearing in its log stream is still a "+
				"redaction failure; got %d leaks", len(leaks))
		}
	})
}

// TestDetector_IgnoresCleanTraffic guards the other direction: a detector that
// fires on everything would make the soak useless in a different way.
func TestDetector_IgnoresCleanTraffic(t *testing.T) {
	w, alpha, _ := fakeWorld()
	sub := &subscriber{tenant: alpha.tenant, scope: alpha.name, project: alpha}
	for _, f := range []string{
		frame("step_output", "soak line 1 canary="+canaryFor(alpha, 1)),
		`{"type":"run_state","data":{"running":true}}`,
		`{"type":"presence","data":{"users":[{"id":"abc","name":"Swift Panda"}]}}`,
		`{"type":"projects","data":{"projects":[]}}`,
	} {
		sub.classify(w, f)
	}
	if _, _, leaks := sub.snapshot(); len(leaks) != 0 {
		t.Errorf("clean traffic reported %d leaks: %v", len(leaks), leaks)
	}
	if running, known := sub.isRunning(); !known || !running {
		t.Errorf("run_state not tracked (known=%v running=%v); the driver would never "+
			"learn a dispatch finished and every task would time out", known, running)
	}
}

// TestDetector_CountsRunsThatEndBetweenPolls guards the completion signal the
// driver waits on.
//
// The driver first sampled the latest run_state and waited for it to go true
// then false. Under concurrency both frames routinely arrive inside one 50ms
// poll interval, so the wait never latched and every task sat out its full
// four-minute timeout — the soak appeared to hang after its warm-up. Counting
// transitions instead cannot miss a run, however short, because the classifier
// sees every frame.
func TestDetector_CountsRunsThatEndBetweenPolls(t *testing.T) {
	w, alpha, _ := fakeWorld()
	sub := &subscriber{tenant: alpha.tenant, scope: alpha.name, project: alpha}

	if got := sub.completedRuns(); got != 0 {
		t.Fatalf("completedRuns = %d before anything ran", got)
	}
	// A whole run delivered back to back, as it arrives under load.
	sub.classify(w, `{"type":"run_state","data":{"running":true}}`)
	sub.classify(w, `{"type":"run_state","data":{"running":false}}`)
	if got := sub.completedRuns(); got != 1 {
		t.Fatalf("completedRuns = %d after one full run; a dispatch would wait out its "+
			"entire timeout instead of proceeding", got)
	}

	// A second run must count separately.
	sub.classify(w, `{"type":"run_state","data":{"running":true}}`)
	sub.classify(w, `{"type":"run_state","data":{"running":false}}`)
	if got := sub.completedRuns(); got != 2 {
		t.Fatalf("completedRuns = %d after two runs, want 2", got)
	}

	// A repeated false is not a second ending: the hub broadcasts run state
	// on reconnect and resync too, and counting those would let a dispatch
	// return before its container had finished.
	sub.classify(w, `{"type":"run_state","data":{"running":false}}`)
	if got := sub.completedRuns(); got != 2 {
		t.Errorf("a repeated running=false counted as an extra ending (%d); a task could "+
			"be declared finished while its container is still executing", got)
	}
}

// TestDetector_CatchesSurvivingCredentialOnDisk plants credential bytes where
// a failed wipe would leave them and asserts the sweep finds them.
func TestDetector_CatchesSurvivingCredentialOnDisk(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "cloop-lease-abc123")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := "CLOOPSOAKSECRET-alpha-alpha-proj0"
	if err := os.WriteFile(filepath.Join(nested, "kubeconfig"),
		[]byte("token: "+sentinel+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A file that predates the run must be ignored, or the scan would blame
	// this suite for every other process on the machine.
	old := filepath.Join(root, "unrelated")
	if err := os.WriteFile(old, []byte("token: "+sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}

	idx := map[string]string{sentinel: "alpha/alpha-proj0"}
	hits := scanForSentinels(root, idx, time.Now().Add(-time.Minute), 8)
	if len(hits) != 1 {
		t.Fatalf("found %d hits, want exactly 1 (the recent one): %v", len(hits), hits)
	}
	if !strings.Contains(hits[0], "alpha/alpha-proj0") || !strings.Contains(hits[0], "kubeconfig") {
		t.Errorf("hit does not name the owner and the file: %s", hits[0])
	}

	// And nothing to find once it is wiped.
	if err := os.RemoveAll(nested); err != nil {
		t.Fatal(err)
	}
	if hits := scanForSentinels(root, idx, time.Now().Add(-time.Minute), 8); len(hits) != 0 {
		t.Errorf("wiped tree still reports %v", hits)
	}
}

// recorder captures what checkGrowth reported, so a test can assert on the
// message and not merely on the verdict.
type recorder struct {
	errs []string
	logs []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...interface{}) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}
func (r *recorder) Logf(format string, args ...interface{}) {
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}
func (r *recorder) failed() bool { return len(r.errs) > 0 }
func (r *recorder) text() string { return strings.Join(r.errs, "\n") }

// TestDetector_CatchesSuperlinearGrowth feeds the growth check the shape of
// the Task 20218 audit amplification — each task costing more than the last —
// and asserts it fails, then feeds it series that must not fail.
func TestDetector_CatchesSuperlinearGrowth(t *testing.T) {
	fmtFloat := func(v float64) string { return fmt.Sprintf("%.1f", v) }
	fmtBytes := func(v float64) string { return humanBytes(int64(v)) }

	t.Run("quadratic fails", func(t *testing.T) {
		// rows(n) = n²: the plan-sized emission on every save.
		var r recorder
		checkGrowth(&r, "audit rows", 0, 10, 20, 0, 100, 400,
			auditRowFactor, auditRowSlack, fmtFloat)
		if !r.failed() {
			t.Fatal("quadratic growth (0 → 100 → 400 rows) was not reported; " +
				"the Task 20218 amplification could be reintroduced without this suite noticing")
		}
		// The message has to be a lead, not a number.
		for _, want := range []string{
			"audit rows",  // which resource
			"superlinear", // what is wrong with it
			"at 10 tasks", // where it was measured
			"Task 20218",  // the regression this is standing in for
			"Task 20229",
		} {
			if !strings.Contains(r.text(), want) {
				t.Errorf("growth failure omits %q:\n%s", want, r.text())
			}
		}
	})

	t.Run("linear passes", func(t *testing.T) {
		var r recorder
		checkGrowth(&r, "audit rows", 0, 10, 20, 0, 30, 60,
			auditRowFactor, auditRowSlack, fmtFloat)
		if r.failed() {
			t.Errorf("constant per-task growth was reported as superlinear, so the soak "+
				"would fail on every correct hub:\n%s", r.text())
		}
	})

	t.Run("shrinking passes", func(t *testing.T) {
		// A WAL checkpoint or a vacuum reclaims space mid-soak. That is not a
		// regression, and a check that called it one would be unusable.
		var r recorder
		checkGrowth(&r, "control-plane database", 0, 10, 20, 4<<20, 9<<20, 6<<20,
			dbFactor, dbSlackBytes, fmtBytes)
		if r.failed() {
			t.Errorf("a resource that shrank in the second interval was reported as growing:\n%s", r.text())
		}
	})

	t.Run("reclaim then grow falls back to absolute slack", func(t *testing.T) {
		// The first interval reclaimed space, so there is no positive rate to
		// scale. A modest second-interval growth must still pass, or a vacuum
		// early in a soak would fail every run after it.
		var r recorder
		checkGrowth(&r, "control-plane database", 0, 10, 20, 9<<20, 4<<20, 5<<20,
			dbFactor, dbSlackBytes, fmtBytes)
		if r.failed() {
			t.Errorf("growth after a reclaim was misreported:\n%s", r.text())
		}
	})
}
