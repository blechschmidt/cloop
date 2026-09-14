package soak

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Per-dispatch budgets. Each is separate so a timeout says which stage hung
// rather than only that the soak did.
const (
	// dispatchTimeout bounds one POST /api/run.
	dispatchTimeout = 60 * time.Second
	// runTimeout bounds one container from accepted dispatch to run_state
	// false. A cold image layer and a cgroup setup fit inside this; an
	// agent harness would not, which is one reason the workload is not one.
	runTimeout = 4 * time.Minute
	// settleTimeout bounds the wait for in-flight teardown after the last
	// dispatch, before leak detection samples anything.
	settleTimeout = 90 * time.Second
	// pollInterval is the granularity of every wait below.
	pollInterval = 50 * time.Millisecond
)

// TestSoakMultiTenantIsolation drives concurrent tasks across tenants and
// fails on bleed, leak, or unbounded growth.
//
// The three assertions share one soak rather than getting one each. That is
// not only about runtime: they are three symptoms of the same condition, and
// running them against the same load means a failure in one can be read
// against the others' numbers — a goroutine leak and an RSS climb in the same
// run are one finding, not two.
func TestSoakMultiTenantIsolation(t *testing.T) {
	gate(t)

	w := newWorld(t)
	t.Logf("soak: %d tenants × %d projects = %d concurrent slots, %d tasks, executor %s, image %s",
		*flagTenants, *flagProjectsPerTenant, len(w.projects), *flagTasks, w.executorID, w.image)

	// One warm-up dispatch per project before any baseline is taken.
	//
	// Everything lazily initialised — the executor's runtime probe, the
	// image stage, the SQLite pools, the lease janitor — comes into
	// existence on the first dispatch. A baseline taken before that would
	// attribute all of it to the soak and report a fixed startup cost as a
	// per-task leak.
	w.warmup(t)

	baseline := w.mustMeasure(t, 0)
	baseContainers := w.containerInventory(t)
	baseLeases := leaseDirs(w.startedAt)
	t.Logf("baseline  %s", baseline)
	if len(baseContainers) != 0 {
		t.Logf("baseline containers still present after warm-up: %v", baseContainers)
	}

	samples := w.drive(t, baseline)

	t.Run("NoCrossTenantBleed", func(t *testing.T) { w.assertNoBleed(t) })
	t.Run("NoLeakedResources", func(t *testing.T) { w.assertNoLeaks(t, baseline, baseContainers, baseLeases) })
	t.Run("BoundedGrowth", func(t *testing.T) { w.assertBoundedGrowth(t, samples) })
}

// warmup runs one dispatch per project and waits for all of them.
//
// A failure here is fatal rather than logged: everything after this point
// measures deltas against a baseline taken immediately afterwards, and a
// baseline taken over a project that never ran is not a baseline.
func (w *world) warmup(t *testing.T) {
	t.Helper()
	var (
		mu   sync.Mutex
		bad  []string
		wg   sync.WaitGroup
		took = time.Now()
	)
	for _, p := range w.projects {
		wg.Add(1)
		go func(p *project) {
			defer wg.Done()
			if err := w.runOne(p, 0); err != "" {
				mu.Lock()
				bad = append(bad, err)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	if len(bad) > 0 {
		t.Fatalf("%d of %d warm-up dispatches failed, so no baseline is meaningful:\n  %s",
			len(bad), len(w.projects), strings.Join(bad, "\n  "))
	}
	t.Logf("warm-up: %d concurrent dispatches in %s",
		len(w.projects), time.Since(took).Round(time.Millisecond))
}

// drive runs flagTasks dispatches across every project concurrently, sampling
// growth at quarter marks.
//
// One goroutine per project, not per task: the hub refuses a second
// simultaneous run on a project with 409, by design, so a per-task fan-out
// would spend the soak colliding with that check instead of exercising
// concurrency. The projects are what run in parallel; the tasks queue behind
// them.
func (w *world) drive(t *testing.T, baseline sample) []sample {
	t.Helper()

	var (
		issued    atomic.Int64
		completed atomic.Int64
		failures  = make(chan string, *flagTasks)
	)

	samples := []sample{baseline}
	var sampleMu sync.Mutex
	// Sample at quarter marks: two intervals are the minimum that can
	// distinguish linear growth from superlinear, and four gives the
	// comparison a shape rather than a single ratio.
	interval := *flagTasks / 4
	if interval < 1 {
		interval = 1
	}

	start := time.Now()
	var wg sync.WaitGroup
	for _, p := range w.projects {
		wg.Add(1)
		go func(p *project) {
			defer wg.Done()
			for {
				seq := int(issued.Add(1))
				if seq > *flagTasks {
					return
				}
				if err := w.runOne(p, seq); err != "" {
					failures <- err
					return
				}
				done := int(completed.Add(1))
				if done%interval == 0 || done == *flagTasks {
					s, merr := w.measure(done)
					if merr != nil {
						failures <- fmt.Sprintf("%s task %d: sample: %v", p.name, seq, merr)
						return
					}
					sampleMu.Lock()
					samples = append(samples, s)
					sampleMu.Unlock()
					t.Logf("sample    %s", s)
				}
			}
		}(p)
	}
	wg.Wait()
	close(failures)

	var fatal []string
	for f := range failures {
		fatal = append(fatal, f)
	}
	if len(fatal) > 0 {
		t.Fatalf("%d dispatch(es) failed, so the load below was never applied:\n  %s",
			len(fatal), strings.Join(fatal, "\n  "))
	}

	t.Logf("drove %d tasks across %d projects in %s", completed.Load(), len(w.projects),
		time.Since(start).Round(time.Millisecond))

	// Give in-flight teardown — container reap, lease wipe, stream close —
	// a chance to finish before anything samples for leaks. Without this the
	// suite would race its own cleanup and report work-in-progress as a leak.
	w.settle(t)

	final := w.mustMeasure(t, int(completed.Load()))
	sampleMu.Lock()
	samples = append(samples, final)
	sampleMu.Unlock()
	t.Logf("settled   %s", final)

	sort.Slice(samples, func(i, j int) bool { return samples[i].tasks < samples[j].tasks })
	return samples
}

// runOne drives a single task through one project: plant the canary, dispatch,
// wait for the run to end. Returns "" on success or a describable failure.
//
// It deliberately takes no *testing.T. It is called from the driver's
// per-project goroutines, where t.Fatalf does not fail the test — it exits
// that one goroutine — so every outcome has to come back as a value the
// caller on the test's own goroutine can report.
func (w *world) runOne(p *project, seq int) string {
	canary := canaryFor(p, seq)
	if err := os.WriteFile(p.dirCanaryPath(), []byte(canary), 0o644); err != nil {
		return fmt.Sprintf("%s task %d: plant canary: %v", p.name, seq, err)
	}

	sub := w.subscriberFor(p)
	if sub == nil {
		return fmt.Sprintf("%s task %d: no subscriber watching this project", p.name, seq)
	}
	// Snapshot before dispatching, not after: the run can finish before the
	// POST returns, and a baseline taken afterwards would already include
	// this run's completion and then wait forever for the next one.
	endedBefore := sub.completedRuns()

	ctx, cancel := context.WithTimeout(context.Background(), dispatchTimeout)
	code, body, err := w.do(ctx, "POST", "/api/run", p.tenant, p.idx)
	cancel()
	if err != nil {
		return fmt.Sprintf("%s task %d: POST /api/run: %v", p.name, seq, err)
	}
	if code != 200 {
		return fmt.Sprintf("%s task %d: POST /api/run returned %d: %s",
			p.name, seq, code, truncate(body, 300))
	}

	p.mu.Lock()
	p.dispatched++
	p.mu.Unlock()

	// Wait for the hub to say the run ended. run_state on this project's own
	// stream is the hub's own signal, so waiting on it also asserts that the
	// signal arrives — a run that finishes without telling its subscriber is
	// itself a defect this would catch.
	deadline := time.Now().Add(runTimeout)
	for {
		if sub.completedRuns() > endedBefore {
			return ""
		}
		if time.Now().After(deadline) {
			running, known := sub.isRunning()
			return fmt.Sprintf(
				"%s task %d (%s): the hub never reported this run ending within %s "+
					"(last run_state: running=%v known=%v, completed runs seen: %d)",
				p.name, seq, canary, runTimeout, running, known, sub.completedRuns())
		}
		time.Sleep(pollInterval)
	}
}

func (p *project) dirCanaryPath() string { return joinPath(p.dir, canaryFile) }

// settle waits until no project reports a running workload.
func (w *world) settle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(settleTimeout)
	for {
		busy := ""
		for _, p := range w.projects {
			if sub := w.subscriberFor(p); sub != nil {
				if running, known := sub.isRunning(); known && running {
					busy = p.name
					break
				}
			}
		}
		if busy == "" {
			// One more settle interval past the last observed run: the
			// container reap and the lease wipe happen after the stream
			// closes, not before it.
			time.Sleep(2 * time.Second)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("project %s still reports a running workload %s after the last dispatch; "+
				"leak detection below would measure a soak that has not finished", busy, settleTimeout)
		}
		time.Sleep(pollInterval)
	}
}

// ---------------------------------------------------------------- assertions

// assertNoBleed fails if any frame carrying one tenant's material reached
// another, and fails just as hard if no tenant saw its own.
//
// The second half matters as much as the first. A hub that delivered nothing
// to anybody would have zero cross-tenant frames and would pass a
// leak-only check while being completely broken — so the positive control is
// part of the assertion, not a diagnostic beside it.
func (w *world) assertNoBleed(t *testing.T) {
	t.Helper()

	var all []leak
	for _, tn := range w.tenants {
		for _, sub := range tn.subs {
			frames, own, leaks := sub.snapshot()
			all = append(all, leaks...)

			dispatched := -1
			if sub.project != nil {
				sub.project.mu.Lock()
				dispatched = sub.project.dispatched
				sub.project.mu.Unlock()
			}
			t.Logf("tenant %-8s stream %-14s tasks=%-4s frames=%-5d own-canary frames=%-4d leaks=%d",
				tn.name, sub.scope, dispatchCount(dispatched), frames, own, len(leaks))

			switch {
			case sub.project != nil && own == 0:
				// Every project-scoped stream must have carried its own
				// project's output. A silent one means the dispatch never
				// reached the broadcast path and this tenant's isolation was
				// never tested.
				t.Errorf("tenant %s stream %s ran %d task(s) and received %d frames but never "+
					"carried its own canary %s…; its isolation was never exercised, so a clean "+
					"result here proves nothing",
					tn.name, sub.scope, dispatched, frames, canaryPrefix(sub.project))

			case sub.project == nil && own != 0:
				// A global-scope stream joins the room that belongs to no
				// project, which broadcastToProject cannot reach. Project log
				// output arriving there is a scoping defect even when it
				// belongs to the connection's own tenant — the landing page
				// renders no per-project data, and under OIDC the frames would
				// then surface under whatever project the user opened next
				// (Task 20197).
				t.Errorf("tenant %s global-scope stream carried %d frame(s) of its own project "+
					"output; a stream that declared it has no project selected must receive no "+
					"project payload at all", tn.name, own)
			}
		}
	}

	if len(all) == 0 {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	var b strings.Builder
	fmt.Fprintf(&b, "%d cross-tenant frame(s) delivered to the wrong tenant:\n", len(all))
	for i, l := range all {
		if i == 12 {
			fmt.Fprintf(&b, "  … and %d more\n", len(all)-i)
			break
		}
		fmt.Fprintf(&b, "  [%d] %s\n", i+1, l)
	}
	t.Error(b.String())
}

// assertNoLeaks fails on anything the soak created and did not give back:
// containers, credential staging directories, credential bytes on disk, or
// goroutines above the post-warm-up baseline.
func (w *world) assertNoLeaks(t *testing.T, baseline sample, baseContainers, baseLeases []string) {
	t.Helper()

	// --- containers -------------------------------------------------------
	if got := w.containerInventory(t); len(got) > 0 {
		t.Errorf("%d container(s) from executor %s survived the soak; "+
			"each is a workload the hub started and never reaped:\n  %s",
			len(got), w.executorID, strings.Join(got, "\n  "))
	}

	// --- credential staging directories -----------------------------------
	// Set difference against the baseline as well as the creation-time bound:
	// a directory that was already there when the soak began belongs to
	// something else on this machine.
	was := make(map[string]bool, len(baseLeases))
	for _, d := range baseLeases {
		was[d] = true
	}
	var staleLeases []string
	for _, d := range leaseDirs(w.startedAt) {
		if !was[d] {
			staleLeases = append(staleLeases, d)
		}
	}
	if len(staleLeases) > 0 {
		t.Errorf("%d credential staging director(ies) created during the soak still exist; "+
			"the lease wipe did not run for them:\n  %s",
			len(staleLeases), strings.Join(staleLeases, "\n  "))
	}

	// --- credential bytes -------------------------------------------------
	// The strongest form of the wipe guarantee: not "the directory is gone"
	// but "the bytes are nowhere". Scanned across the staging roots and every
	// project tree, since a credential that ended up inside a tenant's
	// workspace is both a wipe failure and a cross-tenant exposure.
	sentinels := w.sentinelIndex()
	var hits []string
	roots := append(leaseDirRoots(), w.root)
	for _, root := range roots {
		hits = append(hits, scanForSentinels(root, sentinels, w.startedAt, 8)...)
		if len(hits) >= 8 {
			break
		}
	}
	if len(hits) > 0 {
		t.Errorf("leased credential material survived on disk in %d location(s):\n  %s",
			len(hits), strings.Join(hits, "\n  "))
	}

	// --- goroutines -------------------------------------------------------
	// Measured against the post-warm-up baseline so a fixed startup cost is
	// not counted, and with slack that does not scale with task count: the
	// defect this catches is one goroutine per dispatch, which at the default
	// task count is an order of magnitude above the slack.
	post := settleGoroutines()
	delta := post - baseline.goroutines
	slack := goroutineSlack()
	if delta > slack {
		t.Errorf("goroutine leak: baseline=%d post=%d delta=%d (>%d) after %d tasks "+
			"— roughly %.2f per dispatch\n%s",
			baseline.goroutines, post, delta, slack, *flagTasks,
			float64(delta)/float64(*flagTasks), goroutineDump())
	} else {
		t.Logf("goroutines: baseline=%d post=%d delta=%d (slack %d)",
			baseline.goroutines, post, delta, slack)
	}
}

// goroutineSlack is the tolerated goroutine delta.
//
// Fixed rather than proportional to task count, deliberately: a leak that
// scales with the load is the whole defect class, so a budget that also scaled
// would grow to accommodate it. The value absorbs the handful of pooled
// connections and watchers the hub legitimately keeps warm after its first
// several dispatches.
func goroutineSlack() int { return 24 }

// goroutineDump renders live stacks, capped, so a leak failure names the
// goroutines rather than only counting them.
func goroutineDump() string {
	buf := make([]byte, 1<<16)
	n := runtimeStack(buf)
	return "live goroutine stacks (truncated):\n" + string(buf[:n])
}

// assertBoundedGrowth fails when a resource's cost per task rises as the soak
// proceeds.
//
// Comparing the second half's per-task cost with the first half's, rather than
// checking an absolute ceiling, is what makes this a regression test for the
// two defects it stands in for. Task 20218's audit amplification and the
// unbounded retention Task 20229 fixed both look fine at small totals; what
// gives them away is that each additional task costs more than the last.
func (w *world) assertBoundedGrowth(t *testing.T, samples []sample) {
	t.Helper()
	if len(samples) < 3 {
		t.Fatalf("only %d growth samples; need at least 3 to compare two intervals "+
			"(raise -soak.tasks)", len(samples))
	}

	first := samples[0]
	mid := samples[len(samples)/2]
	last := samples[len(samples)-1]
	if mid.tasks == first.tasks || last.tasks == mid.tasks {
		t.Fatalf("growth samples do not span two intervals: %d, %d, %d tasks",
			first.tasks, mid.tasks, last.tasks)
	}

	t.Logf("growth intervals: [%d→%d] then [%d→%d] tasks",
		first.tasks, mid.tasks, mid.tasks, last.tasks)

	checkGrowth(t, "audit rows", first.tasks, mid.tasks, last.tasks,
		float64(first.auditRows), float64(mid.auditRows), float64(last.auditRows),
		auditRowFactor, auditRowSlack, func(v float64) string { return fmt.Sprintf("%.1f", v) })

	checkGrowth(t, "control-plane database", first.tasks, mid.tasks, last.tasks,
		float64(first.hubDBBytes), float64(mid.hubDBBytes), float64(last.hubDBBytes),
		dbFactor, dbSlackBytes, func(v float64) string { return humanBytes(int64(v)) })

	checkGrowth(t, "project databases", first.tasks, mid.tasks, last.tasks,
		float64(first.projectDBBytes), float64(mid.projectDBBytes), float64(last.projectDBBytes),
		dbFactor, dbSlackBytes, func(v float64) string { return humanBytes(int64(v)) })

	if first.rssBytes == 0 || last.rssBytes == 0 {
		t.Logf("RSS unavailable on this platform; skipping the memory bound")
	} else {
		checkGrowth(t, "resident memory", first.tasks, mid.tasks, last.tasks,
			float64(first.rssBytes), float64(mid.rssBytes), float64(last.rssBytes),
			rssFactor, rssSlackBytes, func(v float64) string { return humanBytes(int64(v)) })
	}
}

// Growth tolerances. Each is a factor on the per-task rate plus an absolute
// slack that absorbs quantisation, and each is loose enough that only a
// genuinely superlinear trend trips it.
const (
	// auditRowFactor is the tightest: rows are counted exactly, so there is
	// no quantisation to absorb and amplification is unmistakable.
	auditRowFactor = 2.5
	auditRowSlack  = 8.0

	// dbFactor is looser because SQLite allocates in pages and reuses
	// freelist space, so a byte count moves in steps rather than smoothly.
	dbFactor     = 4.0
	dbSlackBytes = 4 << 20

	// rssFactor is loosest of all. The Go heap grows in arenas and shrinks
	// only when the scavenger gets to it, so this bound exists to catch a
	// runaway — a per-task retention — rather than to police allocation.
	rssFactor     = 6.0
	rssSlackBytes = 96 << 20
)

// reporter is the slice of testing.TB the growth check uses.
//
// Narrowed to an interface so the check can be exercised against a recording
// implementation that captures what it *said*, not merely whether it failed.
// The failure text is the deliverable here — a soak that reports "mismatch"
// teaches nobody anything — so it needs to be assertable.
type reporter interface {
	Helper()
	Errorf(format string, args ...interface{})
	Logf(format string, args ...interface{})
}

// checkGrowth compares the per-task growth rate of two consecutive intervals.
func checkGrowth(t reporter, what string, t0, t1, t2 int, v0, v1, v2 float64,
	factor, slack float64, format func(float64) string) {
	t.Helper()

	firstRate := (v1 - v0) / float64(t1-t0)
	secondRate := (v2 - v1) / float64(t2-t1)
	// A resource that shrank or held flat in the second interval cannot be
	// growing superlinearly, whatever the ratio of two small numbers says.
	if secondRate <= 0 {
		t.Logf("%s: %s → %s → %s; per-task %s then %s (not growing)",
			what, format(v0), format(v1), format(v2), format(firstRate), format(secondRate))
		return
	}

	budget := firstRate*factor + slack/float64(t2-t1)
	if firstRate < 0 {
		// The first interval reclaimed space — a WAL checkpoint, a vacuum.
		// Comparing against a negative rate would make any growth look
		// infinite, so fall back to the absolute slack alone.
		budget = slack / float64(t2-t1)
	}

	if secondRate > budget {
		t.Errorf("%s grows superlinearly in task count: "+
			"%s at %d tasks → %s at %d tasks → %s at %d tasks. "+
			"Per-task cost rose from %s to %s, above the %s budget (%.1f× the first interval plus %s slack). "+
			"This is the shape of the audit amplification fixed in Task 20218 and the unbounded "+
			"retention fixed in Task 20229.",
			what, format(v0), t0, format(v1), t1, format(v2), t2,
			format(firstRate), format(secondRate), format(budget), factor, format(slack))
		return
	}
	t.Logf("%s: %s → %s → %s; per-task %s then %s (budget %s)",
		what, format(v0), format(v1), format(v2),
		format(firstRate), format(secondRate), format(budget))
}
