package hubdoctor

// The diagnosis a hub makes of itself (Task 20434).
//
// `cloop hub doctor` runs in a shell on the hub host, in the hub's directory,
// with both of its configuration files in reach — which an administrator of a
// Helm or compose deployment, or one without shell access, never has. GET
// /api/hub/health runs the same checks inside the serving hub instead, against
// the configuration that process runs under. Running them in a process that is
// serving requests changes what a run has to promise:
//
//   - Nothing that starts work, and as little as possible that a hub asking
//     itself should not. The two steps that start work — --smoke's throwaway
//     dispatch, --probe-network-policy's Pods — are not part of it at all,
//     whatever Options says. The executor check reads the drivers this process
//     reconciled at startup instead of reconciling again, which would replace
//     the drivers the hub is dispatching to (checkExecutorsLive), and
//     Options.Self lets the hub answer what the shell's doctor asks from
//     outside: its own sign-in, its KMS clients, its executors' liveness.
//   - A check that hangs or panics reports itself; it does not take the report
//     — or the hub — with it. Each step runs on a goroutine of its own against
//     a deadline of its own, a panic is recovered into a finding, and anything
//     a step adds after its deadline is dropped.
//   - A step that never returns is not started again for every report. Live
//     remembers the steps still running from an earlier report and says so
//     instead of starting a second copy, so a wedged check costs one goroutine
//     rather than one a minute.
//   - A step heavier than a report is worth is made less often. The integrity
//     check reads the whole database file, so a live run makes it at most
//     every quarter of an hour and carries its last findings in between
//     (liveEvery, in steps.go).
//
// Steps run concurrently. Each opens what it reads itself — its own database
// handle, its own probe client — so the only things they share are the
// configuration, which no check writes, and the executor registry, which is
// safe for concurrent use. The report keeps Run's order whatever order the
// steps finish in.

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// DefaultCheckTimeout bounds one step of a live run. A step's own probes are
// bounded by Options.Timeout each, and the slowest steps make two or three of
// them; this is the backstop for a step that waits on something with no
// timeout of its own — a lock, a socket nobody answers.
const DefaultCheckTimeout = 20 * time.Second

// The check ids of the findings a live run adds about its own steps.
const (
	// CheckUnfinished: a step that did not finish by its deadline, or is
	// still running from an earlier report.
	CheckUnfinished = "doctor.unfinished"
	// CheckPanicked: a step that panicked.
	CheckPanicked = "doctor.panic"
)

// StepOutcome is how one step of a live run ended.
type StepOutcome string

const (
	// StepFinished: it returned in time; its findings are in the report.
	StepFinished StepOutcome = "finished"
	// StepTimedOut: it was still running at its deadline. What it added
	// before then is in the report; the rest of its findings are not.
	StepTimedOut StepOutcome = "timed_out"
	// StepPanicked: it panicked. What it added first is in the report.
	StepPanicked StepOutcome = "panicked"
	// StepStillRunning: an earlier report's run of it has not returned, so
	// it was not started again.
	StepStillRunning StepOutcome = "still_running"
	// StepReused: the step is made less often than reports are (liveEvery),
	// and this report carries the findings of its last run, at RanAt.
	StepReused StepOutcome = "reused"
)

// StepResult is what one step of a live run did.
type StepResult struct {
	ID         string      `json:"id"`
	Title      string      `json:"title"`
	Outcome    StepOutcome `json:"outcome"`
	DurationMS int64       `json:"duration_ms"`
	// Panic is the recovered value of a step that panicked, rendered.
	Panic string `json:"panic,omitempty"`
	// RanAt is when a reused step's findings were made.
	RanAt time.Time `json:"ran_at,omitzero"`
}

// Check is a step a caller adds to a live run: a test's check that hangs or
// panics, or an embedder's own. Its ID must not be one of the hub's steps'.
type Check struct {
	ID, Title string
	Run       func(ctx context.Context, add func(Finding))
	// Timeout bounds this check. Zero uses the run's CheckTimeout.
	Timeout time.Duration
	// Every, when set, is how often a live run makes this check at most, as
	// liveEvery says for the hub's own.
	Every time.Duration
}

// NotRun is a part of `cloop hub doctor` a live run never makes, and why.
type NotRun struct {
	Check string `json:"check"`
	Flag  string `json:"flag"`
	Why   string `json:"why"`
}

// LiveOptions tunes a live run.
type LiveOptions struct {
	// Options are the checks' own. Smoke and ProbeNetworkPolicy are ignored:
	// a live run has no step that starts work.
	Options

	// CheckTimeout bounds each step. Zero uses DefaultCheckTimeout.
	CheckTimeout time.Duration

	// Extra steps run after the hub's own.
	Extra []Check

	// OnPanic, when set, is told of every step that panics — also one that
	// panics after its deadline, which no report will mention — with where.
	// It runs on the panicking step's goroutine.
	OnPanic func(step string, value any, stack []byte)

	// Generation names the configuration the run is made under. A step made
	// less often than reports are (liveEvery) is reused only by a run of the
	// same generation, so a changed configuration is diagnosed afresh.
	Generation string

	// Fresh asks for a run of everything recent enough not to be: a step
	// made less often than reports are is reused only if its last run is
	// under a minute old.
	Fresh bool
}

// freshFloor is how old a reused step's findings may be in a Fresh run.
const freshFloor = time.Minute

// LiveReport is a live run's result: the findings, as Run reports them, and
// what each step did.
type LiveReport struct {
	Report
	Steps []StepResult `json:"steps"`
	// NotRun names what this diagnosis leaves to `cloop hub doctor`.
	NotRun []NotRun `json:"not_run"`
	// Elapsed is how long the run took.
	Elapsed time.Duration `json:"-"`
}

// notRunLive is what a live run leaves out, in the order the CLI runs them.
var notRunLive = []NotRun{
	{Check: "executors.network_policy_probe", Flag: "--probe-network-policy",
		Why: "creates two Pods and a default-deny NetworkPolicy in each Kubernetes executor's cluster"},
	{Check: "smoke", Flag: "--smoke",
		Why: "starts a workload on every executor and mints a throwaway credential for it"},
}

// Live runs live diagnoses. The zero value is ready. A hub keeps one for its
// lifetime, which is what lets it notice a step that never returned.
type Live struct {
	mu      sync.Mutex
	running map[string]*stepRun // step id → its run that has not returned
	// last is the latest finished run of each step made less often than
	// reports are (liveEvery).
	last map[string]stepMemo
}

// stepMemo is what a step found, when, and under which configuration.
type stepMemo struct {
	at       time.Time
	gen      string
	findings []Finding
}

// stepRun is one step on its way through a live run.
type stepRun struct {
	step     step
	started  time.Time
	deadline time.Time
	done     chan struct{}
	// earlier is the run of this step an earlier report started and is still
	// waiting on; this one was not started.
	earlier *stepRun
	// reused is the last run of a step made less often than reports are;
	// this one was not started either.
	reused *stepMemo

	mu       sync.Mutex
	closed   bool      // the report stopped listening
	findings []Finding // what the report takes: everything added before it stopped
	all      []Finding // everything the step added, for liveEvery's reuse
	panicked bool
	panicVal any
	ended    time.Time
}

func (r *stepRun) add(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.all = append(r.all, f)
	if !r.closed {
		r.findings = append(r.findings, f)
	}
}

// Run diagnoses the control plane rooted at dir with cfg, the configuration
// the hub runs under. Like Run it never fails: what could not be checked is a
// finding.
func (l *Live) Run(ctx context.Context, dir string, cfg *config.Config, opts LiveOptions) *LiveReport {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	timeout := opts.CheckTimeout
	if timeout <= 0 {
		timeout = DefaultCheckTimeout
	}
	o := opts.Options
	o.Smoke, o.ProbeNetworkPolicy = false, false
	out := &LiveReport{
		Report: Report{Dir: dir, CheckedAt: o.now(), Offline: o.Offline},
		NotRun: append([]NotRun(nil), notRunLive...),
	}
	// Before anything opens the database: see walSample.
	wal := sampleWAL(dir)
	if cfg == nil {
		out.Findings = append(out.Findings, configAbsent())
		out.Elapsed = time.Since(start)
		return out
	}
	out.StrictMode = !cfg.Executors.HostProcessAllowed()

	list := steps(dir, cfg, o, wal, &out.Report, stepSet{executors: checkExecutorsLive})
	limits := make([]time.Duration, len(list), len(list)+len(opts.Extra))
	every := make([]time.Duration, len(list), len(list)+len(opts.Extra))
	for i, s := range list {
		limits[i], every[i] = timeout, liveEvery[s.id]
	}
	for _, c := range opts.Extra {
		run := c.Run
		list = append(list, step{id: c.ID, title: c.Title, run: func(ctx context.Context, add addFn) { run(ctx, add) }})
		limit := c.Timeout
		if limit <= 0 {
			limit = timeout
		}
		limits, every = append(limits, limit), append(every, c.Every)
	}

	runs := make([]*stepRun, len(list))
	for i, s := range list {
		if m, ok := l.recent(s.id, every[i], opts.Generation, opts.Fresh); ok {
			runs[i] = &stepRun{step: s, reused: &m}
			continue
		}
		runs[i] = l.start(ctx, s, limits[i], every[i], opts)
	}
	for i, r := range runs {
		out.Steps = append(out.Steps, l.collect(ctx, r, limits[i], &out.Report))
	}
	out.Elapsed = time.Since(start)
	return out
}

// recent returns the last run of a step that is made less often than reports
// are, while it is still recent enough to stand for one: within its interval
// (a minute, for a Fresh run) and under the same configuration.
func (l *Live) recent(id string, every time.Duration, gen string, fresh bool) (stepMemo, bool) {
	if every <= 0 {
		return stepMemo{}, false
	}
	if fresh && every > freshFloor {
		every = freshFloor
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	m, ok := l.last[id]
	if !ok || m.gen != gen || time.Since(m.at) >= every {
		return stepMemo{}, false
	}
	return stepMemo{at: m.at, gen: m.gen, findings: append([]Finding(nil), m.findings...)}, true
}

// remember records a completed run of a step made less often than reports
// are. Called by the step's own goroutine, so a run that outlived its report's
// deadline still serves the next ones — the slow case is the one the interval
// is for.
func (l *Live) remember(id string, every time.Duration, gen string, at time.Time, findings []Finding) {
	if every <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]stepMemo{}
	}
	l.last[id] = stepMemo{at: at, gen: gen, findings: append([]Finding(nil), findings...)}
}

// start launches s on a goroutine of its own, unless an earlier report's run
// of it has not returned yet.
func (l *Live) start(ctx context.Context, s step, timeout, every time.Duration, opts LiveOptions) *stepRun {
	onPanic := opts.OnPanic
	r := &stepRun{step: s, started: time.Now(), done: make(chan struct{})}
	r.deadline = r.started.Add(timeout)
	l.mu.Lock()
	if earlier := l.running[s.id]; earlier != nil {
		l.mu.Unlock()
		r.earlier = earlier
		close(r.done)
		return r
	}
	if l.running == nil {
		l.running = map[string]*stepRun{}
	}
	l.running[s.id] = r
	l.mu.Unlock()

	sctx, cancel := context.WithDeadline(ctx, r.deadline)
	go func() {
		defer func() {
			v := recover()
			if v != nil && onPanic != nil {
				// Whatever the hook does, it is not allowed to take the
				// process down from a goroutine nobody waits on.
				func() {
					defer func() { _ = recover() }()
					onPanic(s.id, v, debug.Stack())
				}()
			}
			r.mu.Lock()
			r.panicked, r.panicVal, r.ended = v != nil, v, time.Now()
			all := r.all
			r.mu.Unlock()
			if v == nil {
				l.remember(s.id, every, opts.Generation, r.started, all)
			}
			cancel()
			l.mu.Lock()
			if l.running[s.id] == r {
				delete(l.running, s.id)
			}
			l.mu.Unlock()
			close(r.done)
		}()
		s.run(sctx, r.add)
	}()
	return r
}

// collect waits for r until its deadline, then reports what it did: its
// findings into rep, followed by one about the step itself when it did not
// simply finish.
func (l *Live) collect(ctx context.Context, r *stepRun, timeout time.Duration, rep *Report) StepResult {
	res := StepResult{ID: r.step.id, Title: r.step.title}
	if m := r.reused; m != nil {
		res.Outcome, res.RanAt = StepReused, m.at.UTC()
		for _, f := range m.findings {
			f.AsOf = res.RanAt
			rep.Findings = append(rep.Findings, f)
		}
		return res
	}
	if e := r.earlier; e != nil {
		res.Outcome = StepStillRunning
		rep.Findings = append(rep.Findings, Finding{
			Check: CheckUnfinished, Title: r.step.title, Severity: SeverityWarn,
			Message: fmt.Sprintf("this check has been running since %s, for an earlier report, and has not "+
				"returned; it is not started twice, so its findings are missing until it does",
				e.started.UTC().Format(time.RFC3339)),
			Remediation: unfinishedRemedy,
			Details:     map[string]any{"step": r.step.id, "running_since": e.started.UTC().Format(time.RFC3339)},
		})
		return res
	}

	timer := time.NewTimer(time.Until(r.deadline))
	select {
	case <-r.done:
	case <-timer.C:
	case <-ctx.Done():
	}
	timer.Stop()
	finished := false
	select {
	case <-r.done:
		finished = true
	default:
	}

	r.mu.Lock()
	r.closed = true
	found := append([]Finding(nil), r.findings...)
	panicked, value, ended := r.panicked, r.panicVal, r.ended
	r.mu.Unlock()
	rep.Findings = append(rep.Findings, found...)

	switch {
	case finished && panicked:
		res.Outcome = StepPanicked
		res.Panic = fmt.Sprint(value)
		res.DurationMS = ended.Sub(r.started).Milliseconds()
		rep.Findings = append(rep.Findings, Finding{
			Check: CheckPanicked, Title: r.step.title, Severity: SeverityWarn,
			Message: fmt.Sprintf("this check failed with a panic, so what it had yet to check is missing from "+
				"this report: %v", value),
			Remediation: "This is a bug in cloop, not in the hub's configuration: report it with the stack " +
				"trace in the hub's log (event health_check). `cloop hub doctor` on the hub host runs the " +
				"same check",
			Details: map[string]any{"step": r.step.id},
		})
	case finished:
		res.Outcome = StepFinished
		res.DurationMS = ended.Sub(r.started).Milliseconds()
	default:
		res.Outcome = StepTimedOut
		res.DurationMS = time.Since(r.started).Milliseconds()
		msg := fmt.Sprintf("this check did not finish within %s, so its findings are missing from this report", timeout)
		if len(found) > 0 {
			msg = fmt.Sprintf("this check did not finish within %s, so only the %d finding(s) it made "+
				"before then are in this report", timeout, len(found))
		}
		rep.Findings = append(rep.Findings, Finding{
			Check: CheckUnfinished, Title: r.step.title, Severity: SeverityWarn,
			Message:     msg + "; it is still running, and is not started again until it returns",
			Remediation: unfinishedRemedy,
			Details:     map[string]any{"step": r.step.id, "timeout": timeout.String()},
		})
	}
	return res
}

// unfinishedRemedy is the advice for a step that did not finish.
const unfinishedRemedy = "Run `cloop hub doctor` on the hub host: the same check with no deadline shows " +
	"where it stops — usually a probe of something that never answers, or a database another process holds " +
	"locked"
