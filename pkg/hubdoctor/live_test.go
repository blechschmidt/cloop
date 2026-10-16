package hubdoctor

// The diagnosis a hub makes of itself (Task 20434): the same checks as Run,
// none of the steps that start work, and a step that hangs or panics reported
// rather than inherited.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/globalbudget"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// liveOpts is what the hub's own runs look like: offline, so the suite dials
// nothing, and with the machine's host-wide caps out of the picture.
func liveOpts() LiveOptions {
	return LiveOptions{Options: Options{
		Offline: true,
		Timeout: 2 * time.Second,
		GlobalBudget: func() (globalbudget.GlobalBudgetConfig, error) {
			return globalbudget.GlobalBudgetConfig{}, nil
		},
	}}
}

// findingsOf indexes a report's findings by check id.
func findingsOf(rep *Report) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range rep.Findings {
		out[f.Check] = append(out[f.Check], f)
	}
	return out
}

func stepOf(t *testing.T, lr *LiveReport, id string) StepResult {
	t.Helper()
	for _, s := range lr.Steps {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no step %q among %+v", id, lr.Steps)
	return StepResult{}
}

// TestLiveRunsRunsChecks: a live run makes the same checks in the same order
// as Run, minus the two that start work, and its findings agree with Run's
// for everything but how the executors were found.
func TestLiveRunsRunsChecks(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	cfg := hubCfg()

	var l Live
	lr := l.Run(context.Background(), dir, cfg, liveOpts())

	all := steps(dir, cfg, Options{}, walSample{}, &Report{}, stepSet{
		executors: checkExecutors, networkPolicy: checkNetworkPolicyEnforcement, smoke: checkSmoke})
	var want []string
	for _, s := range all {
		if s.id != "smoke" && s.id != "executors.network_policy_probe" {
			want = append(want, s.id)
		}
	}
	var got []string
	for _, s := range lr.Steps {
		got = append(got, s.ID)
		if s.Outcome != StepFinished {
			t.Errorf("step %s: %s, want finished", s.ID, s.Outcome)
		}
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("live steps:\n  %v\nwant Run's without the ones that start work:\n  %v", got, want)
	}

	opts := liveOpts().Options
	rep := Run(context.Background(), dir, cfg, opts)
	sequence := func(r *Report) []string {
		var ids []string
		for _, f := range r.Findings {
			if !strings.HasPrefix(f.Check, "executors.") || f.Check == "executors.edge_lag" ||
				f.Check == "executors.rollback_protection" {
				ids = append(ids, f.Check+"/"+string(f.Severity))
			}
		}
		return ids
	}
	if a, b := strings.Join(sequence(&lr.Report), " "), strings.Join(sequence(rep), " "); a != b {
		t.Errorf("a live run's findings differ from Run's:\nlive: %s\nrun:  %s", a, b)
	}
	if lr.StrictMode != rep.StrictMode || lr.Dir != dir {
		t.Errorf("strict mode %v and dir %q, want %v and %q", lr.StrictMode, lr.Dir, rep.StrictMode, dir)
	}
}

// TestLiveNeverStartsWork: a live run has no step that dispatches a workload
// or creates Pods, whatever its options ask for, and says how to make them.
func TestLiveNeverStartsWork(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	opts := liveOpts()
	opts.Offline = false
	opts.Smoke, opts.ProbeNetworkPolicy = true, true
	// Nothing below may dial: the hub's identity provider is unreachable on
	// purpose, so a probe that ran would be a finding about it.
	cfg := hubCfg()
	cfg.UI.OIDC.Issuer = "https://127.0.0.1:1"
	opts.Timeout = 200 * time.Millisecond

	var l Live
	lr := l.Run(context.Background(), dir, cfg, opts)
	for _, f := range lr.Findings {
		if strings.HasPrefix(f.Check, "smoke.") || f.Check == "executors.network_policy_probe" {
			t.Errorf("a live run made %s: %s", f.Check, f.Message)
		}
	}
	for _, s := range lr.Steps {
		if s.ID == "smoke" || s.ID == "executors.network_policy_probe" {
			t.Errorf("a live run has the step %s", s.ID)
		}
	}
	if lr.SmokeRan || len(lr.Smoke) > 0 {
		t.Errorf("a live run smoked an executor: %+v", lr.Smoke)
	}
	flags := map[string]bool{}
	for _, n := range lr.NotRun {
		flags[n.Flag] = n.Why != ""
	}
	if !flags["--smoke"] || !flags["--probe-network-policy"] {
		t.Errorf("not_run = %+v, want --smoke and --probe-network-policy, each with why", lr.NotRun)
	}
}

// TestLiveReadsTheExecutorsTheHubHas: the executor check of a live run probes
// what is in this process's registry and reconciles nothing, so a driver the
// configuration enables but the hub never built is not built by a report.
func TestLiveReadsTheExecutorsTheHubHas(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	ex := registerExtraExecutor(t)

	cfg := hubCfg()
	cfg.Executors.Container.Enabled = true
	cfg.Executors.Container.ID = fmt.Sprintf("live-container-%d", nextExecutorSeq())
	before := len(executor.DefaultRegistry.List())

	var l Live
	lr := l.Run(context.Background(), dir, cfg, liveOpts())
	if after := len(executor.DefaultRegistry.List()); after != before {
		t.Errorf("a live run changed the registry from %d executors to %d", before, after)
	}
	if _, err := executor.DefaultRegistry.Get(cfg.Executors.Container.ID); err == nil {
		t.Errorf("a live run registered the configured container driver %s", cfg.Executors.Container.ID)
	}
	var probed bool
	for _, f := range findingsOf(&lr.Report)["executors.health"] {
		if f.Title == "Executor "+ex.ID() {
			probed = true
		}
	}
	if !probed {
		t.Errorf("the registered executor %s was not reported: %+v", ex.ID(), findingsOf(&lr.Report)["executors.health"])
	}
}

// TestLiveReportsAHangingCheck: a step that does not return by its deadline
// is reported as unfinished, keeps what it found before then, loses what it
// finds after, and does not hold up the report; the other steps are intact.
func TestLiveReportsAHangingCheck(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	returned := make(chan struct{})

	opts := liveOpts()
	const deadline = 400 * time.Millisecond
	opts.Extra = []Check{{ID: "test.hang", Title: "A check that hangs", Timeout: deadline, Run: func(_ context.Context, add func(Finding)) {
		defer close(returned)
		add(Finding{Check: "test.hang", Title: "Before the deadline", Severity: SeverityFail, Message: "seen",
			Remediation: "none"})
		<-release // ignores its context, as a wedged check does
		add(Finding{Check: "test.hang", Title: "After the deadline", Severity: SeverityFail, Message: "late",
			Remediation: "none"})
	}}}

	var l Live
	start := time.Now()
	lr := l.Run(context.Background(), dir, hubCfg(), opts)
	if took := time.Since(start); took > DefaultCheckTimeout {
		t.Errorf("the report took %s: the hanging step held it up", took)
	}
	if s := stepOf(t, lr, "test.hang"); s.Outcome != StepTimedOut {
		t.Errorf("the hanging step ended %s, want %s", s.Outcome, StepTimedOut)
	}
	got := findingsOf(&lr.Report)
	if hang := got["test.hang"]; len(hang) != 1 || hang[0].Title != "Before the deadline" {
		t.Errorf("the hanging step's findings = %+v, want only the one it made before its deadline", hang)
	}
	un := got[CheckUnfinished]
	if len(un) != 1 || un[0].Title != "A check that hangs" || un[0].Severity != SeverityWarn ||
		!strings.Contains(un[0].Message, "did not finish within 400ms") || un[0].Remediation == "" ||
		un[0].Details["step"] != "test.hang" {
		t.Errorf("unfinished findings = %+v", un)
	}
	if len(got["policy.host_execution"]) != 1 || len(got["storage.integrity"]) != 1 {
		t.Errorf("the hub's own checks are missing beside the hanging one: %v", got)
	}
	for _, s := range lr.Steps {
		if s.ID != "test.hang" && s.Outcome != StepFinished {
			t.Errorf("step %s ended %s beside the hanging one", s.ID, s.Outcome)
		}
	}

	// The next report does not start a second copy while the first has not
	// returned; once it has, the step runs again.
	lr = l.Run(context.Background(), dir, hubCfg(), opts)
	if s := stepOf(t, lr, "test.hang"); s.Outcome != StepStillRunning {
		t.Errorf("with its first run still blocked, the step ended %s, want %s", s.Outcome, StepStillRunning)
	}
	if un := findingsOf(&lr.Report)[CheckUnfinished]; len(un) != 1 || !strings.Contains(un[0].Message, "earlier report") ||
		un[0].Details["running_since"] == nil {
		t.Errorf("a step still running from an earlier report is reported as %+v", un)
	}

	release <- struct{}{}
	<-returned
	// The late finding went nowhere, and the step's slot is free again.
	waitFor(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.running["test.hang"] == nil
	})
	fresh := make(chan struct{})
	opts.Extra[0].Run = func(_ context.Context, add func(Finding)) {
		defer close(fresh)
		add(Finding{Check: "test.hang", Title: "Third time", Severity: SeverityPass, Message: "ran"})
	}
	lr = l.Run(context.Background(), dir, hubCfg(), opts)
	<-fresh
	if s := stepOf(t, lr, "test.hang"); s.Outcome != StepFinished {
		t.Errorf("once it returned, the step ended %s, want it run again and finished", s.Outcome)
	}
	if hang := findingsOf(&lr.Report)["test.hang"]; len(hang) != 1 || hang[0].Title != "Third time" {
		t.Errorf("the step's findings after it returned = %+v", hang)
	}
}

// TestLiveRecoversAPanickingCheck: a step that panics is reported, keeps what
// it found first, and is told to OnPanic with its stack; the report — and the
// process — carry on.
func TestLiveRecoversAPanickingCheck(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	var told atomic.Value
	opts := liveOpts()
	opts.OnPanic = func(step string, v any, stack []byte) {
		told.Store(fmt.Sprintf("%s|%v|%s", step, v, stack))
	}
	opts.Extra = []Check{{ID: "test.boom", Title: "A check that panics", Run: func(_ context.Context, add func(Finding)) {
		add(Finding{Check: "test.boom", Title: "First", Severity: SeverityWarn, Message: "seen", Remediation: "none"})
		counts()["nil map"]++ // a runtime panic, not a deliberate one
	}}}

	var l Live
	lr := l.Run(context.Background(), dir, hubCfg(), opts)
	s := stepOf(t, lr, "test.boom")
	if s.Outcome != StepPanicked || !strings.Contains(s.Panic, "nil map") {
		t.Errorf("the panicking step = %+v, want %s naming the panic", s, StepPanicked)
	}
	got := findingsOf(&lr.Report)
	if boom := got["test.boom"]; len(boom) != 1 || boom[0].Title != "First" {
		t.Errorf("the panicking step's findings = %+v, want the one it made first", boom)
	}
	p := got[CheckPanicked]
	if len(p) != 1 || p[0].Title != "A check that panics" || p[0].Severity != SeverityWarn ||
		!strings.Contains(p[0].Message, "nil map") || p[0].Remediation == "" {
		t.Errorf("panic findings = %+v", p)
	}
	tell, _ := told.Load().(string)
	if !strings.HasPrefix(tell, "test.boom|") || !strings.Contains(tell, "TestLiveRecoversAPanickingCheck") {
		t.Errorf("OnPanic was told %q, want the step and a stack through the test", tell)
	}
	if len(got["policy.host_execution"]) != 1 {
		t.Error("the hub's own checks are missing beside the panicking one")
	}
}

// TestLiveMakesHeavyStepsLessOften: the integrity check, which reads the
// whole database file, is made once per interval; the reports in between carry
// what it found, saying when, and the next one after the interval makes it
// again.
func TestLiveMakesHeavyStepsLessOften(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	var l Live
	first := l.Run(context.Background(), dir, hubCfg(), liveOpts())
	if s := stepOf(t, first, "storage.integrity"); s.Outcome != StepFinished {
		t.Fatalf("the first report's integrity check ended %s", s.Outcome)
	}
	second := l.Run(context.Background(), dir, hubCfg(), liveOpts())
	s := stepOf(t, second, "storage.integrity")
	if s.Outcome != StepReused || s.RanAt.IsZero() {
		t.Errorf("the second report's integrity check = %+v, want the first one's findings, dated", s)
	}
	if got, want := findingsOf(&second.Report)["storage.integrity"], findingsOf(&first.Report)["storage.integrity"]; len(got) != 1 ||
		len(want) != 1 || got[0].Message != want[0].Message || got[0].Severity != want[0].Severity {
		t.Errorf("reused findings %+v, first %+v", got, want)
	}
	if o := stepOf(t, second, "storage").Outcome; o != StepFinished {
		t.Errorf("the schema and log checks were reused too (%s): only the integrity check is heavy", o)
	}

	l.mu.Lock()
	m := l.last["storage.integrity"]
	m.at = m.at.Add(-liveEvery["storage.integrity"])
	l.last["storage.integrity"] = m
	l.mu.Unlock()
	third := l.Run(context.Background(), dir, hubCfg(), liveOpts())
	if o := stepOf(t, third, "storage.integrity").Outcome; o != StepFinished {
		t.Errorf("past its interval the integrity check ended %s, want it made again", o)
	}

	// The operator's diagnosis makes it every time.
	if got := findingsOf(Run(context.Background(), dir, hubCfg(), liveOpts().Options))["storage.integrity"]; len(got) != 1 {
		t.Errorf("Run's integrity findings = %+v", got)
	}
}

// TestLiveWithoutConfiguration says what Run says.
func TestLiveWithoutConfiguration(t *testing.T) {
	var l Live
	lr := l.Run(context.Background(), t.TempDir(), nil, liveOpts())
	if len(lr.Findings) != 1 || lr.Findings[0].Check != "config.present" || lr.Findings[0].Severity != SeverityFail {
		t.Errorf("findings = %+v, want the one config.present failure", lr.Findings)
	}
}

// TestLiveStaticTokenIsTheHubs: the hub's own word on its static token is
// what the exposure check judges and names, not the doctor's environment.
func TestLiveStaticTokenIsTheHubs(t *testing.T) {
	t.Setenv(envUIToken, "")
	cfg := config.Default()
	opts := liveOpts()
	opts.Self = &Self{StaticToken: true}
	var l Live
	lr := l.Run(context.Background(), t.TempDir(), cfg, opts)
	ex := findingsOf(&lr.Report)["ui.exposure"]
	if len(ex) != 1 || !strings.Contains(ex[0].Message, "the static token is set on this hub") ||
		strings.Contains(ex[0].Message, "in this shell") {
		t.Errorf("ui.exposure = %+v, want it to say the hub has a static token", ex)
	}
}

// TestLiveDoesNotAskItsOwnListener: a hub diagnosing itself judges its
// exposure from how it runs instead of sending its own listener a request
// without credentials, which on a hub with a static token counts as a failed
// sign-in — five lock the address out.
func TestLiveDoesNotAskItsOwnListener(t *testing.T) {
	t.Setenv(envUIToken, "")
	var dials atomic.Int32
	port, opts := exposureHub(t, http.StatusUnauthorized, `{"error":"sign in"}`)
	opts.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	opts.Self = &Self{StaticToken: true}
	f := exposureFinding(t, config.Default(), opts)
	if dials.Load() != 0 {
		t.Errorf("the hub asked its own listener on :%d %d time(s)", port, dials.Load())
	}
	if f.Severity != SeverityPass || !strings.Contains(f.Message, "as this hub runs") ||
		!strings.Contains(f.Message, "the static token set on this hub") {
		t.Errorf("with a static token, a wildcard listener = %s %q", f.Severity, f.Message)
	}

	// The same listener on a hub with no way to tell people apart still fails,
	// from what the hub says of itself.
	opts.Self = &Self{}
	if f := exposureFinding(t, config.Default(), opts); f.Severity != SeverityFail || dials.Load() != 0 {
		t.Errorf("an open hub on every interface = %s %q after %d dial(s)", f.Severity, f.Message, dials.Load())
	}
}

// countingKMS is the hub's own KMS provider, counting what the doctor asks
// of it.
type countingKMS struct {
	kms.Provider
	status, closes atomic.Int32
}

func (c *countingKMS) Status(ctx context.Context) (kms.Status, error) {
	c.status.Add(1)
	return c.Provider.Status(ctx)
}
func (c *countingKMS) Close() error { c.closes.Add(1); return nil }

// TestLiveUsesTheHubsKMS: the sealing-key checks of a live run go through the
// providers the hub pinned at startup — no client of their own, so no new KMS
// login — and leave them open.
func TestLiveUsesTheHubsKMS(t *testing.T) {
	dir, _, cfg := kmsHub(t)
	prov, err := kms.Open(cfg.Secrets.KMS)
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()
	own := &countingKMS{Provider: prov}
	opts := liveOpts()
	opts.Self = &Self{KMS: func() (kms.Roots, bool) {
		return kms.Roots{Current: secretbroker.KMSRoot(own), Providers: []kms.Provider{own}}, true
	}}
	// Unreachable as configured: a check that resolved secrets.kms itself
	// would report that, not the hub's provider's answer.
	cfg.Secrets.KMS.KMSv2.Endpoint = "unix:///nonexistent/kms.sock"
	secretbroker.ForgetOpenedKeys()
	var l Live
	lr := l.Run(context.Background(), dir, cfg, opts)
	got := findingsOf(&lr.Report)
	for _, check := range []string{"secrets.kms.reachable", "secret_key.matches"} {
		if fs := got[check]; len(fs) != 1 || fs[0].Severity != SeverityPass {
			t.Errorf("%s = %+v, want a pass through the hub's own provider", check, fs)
		}
	}
	if own.status.Load() == 0 || own.closes.Load() != 0 {
		t.Errorf("the hub's provider was asked %d time(s) and closed %d time(s); want asked, never closed",
			own.status.Load(), own.closes.Load())
	}
}

// probedExecutor counts the probes the doctor makes of it itself.
type probedExecutor struct {
	*fakeSmokeExecutor
	probes atomic.Int32
}

func (p *probedExecutor) HealthCheck(ctx context.Context) error {
	p.probes.Add(1)
	return nil
}

// TestLiveAsksTheHubAboutExecutors: a live run's liveness verdicts are the
// hub's own — what its supervisor last saw — and it dials nothing itself.
func TestLiveAsksTheHubAboutExecutors(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	ex := &probedExecutor{fakeSmokeExecutor: newFakeExecutor(fmt.Sprintf("fake-exec-%d", nextExecutorSeq()))}
	if err := executor.DefaultRegistry.Ensure(ex); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.ID()) })

	opts := liveOpts()
	opts.Offline = false
	asked := map[string]bool{}
	var mu sync.Mutex
	opts.Self = &Self{Probe: func(_ context.Context, e executor.Executor) (string, error) {
		mu.Lock()
		asked[e.ID()] = true
		mu.Unlock()
		if e.ID() == ex.ID() {
			return "as the hub's supervisor last probed it", errors.New("no live session")
		}
		return "as the hub's supervisor last probed it", nil
	}}
	cfg := hubCfg()
	cfg.UI.OIDC.Enabled = false // nothing here may dial an issuer
	var l Live
	lr := l.Run(context.Background(), dir, cfg, opts)
	if ex.probes.Load() != 0 {
		t.Errorf("the live run probed the executor itself %d time(s)", ex.probes.Load())
	}
	var found bool
	for _, f := range findingsOf(&lr.Report)["executors.health"] {
		if f.Title == "Executor "+ex.ID() {
			found = true
			if f.Severity != SeverityWarn || !strings.Contains(f.Message, "no live session") ||
				f.Details["probed"] != "as the hub's supervisor last probed it" {
				t.Errorf("the hub's answer was reported as %+v", f)
			}
		}
	}
	if !found || !asked[ex.ID()] {
		t.Errorf("the executor was not reported (asked %v)", asked)
	}
}

// TestLiveRemembersALateHeavyStep: a step made less often than reports are is
// remembered when it finishes, even after its report's deadline, so the next
// report carries its findings — dated — instead of starting it again; a
// changed configuration, and a Fresh run past a minute, make it again.
func TestLiveRemembersALateHeavyStep(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	var runs atomic.Int32
	release := make(chan struct{})
	opts := liveOpts()
	opts.Generation = "config-1"
	opts.Extra = []Check{{ID: "test.heavy", Title: "A slow, heavy check", Timeout: 300 * time.Millisecond, Every: time.Hour,
		Run: func(_ context.Context, add func(Finding)) {
			if runs.Add(1) == 1 {
				<-release
			}
			add(Finding{Check: "test.heavy", Title: "Heavy", Severity: SeverityPass, Message: "made"})
		}}}
	var l Live
	if s := stepOf(t, l.Run(context.Background(), dir, hubCfg(), opts), "test.heavy"); s.Outcome != StepTimedOut {
		t.Fatalf("the slow first run ended %s", s.Outcome)
	}
	close(release)
	waitFor(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		_, ok := l.last["test.heavy"]
		return ok && l.running["test.heavy"] == nil
	})

	lr := l.Run(context.Background(), dir, hubCfg(), opts)
	s := stepOf(t, lr, "test.heavy")
	heavy := findingsOf(&lr.Report)["test.heavy"]
	if s.Outcome != StepReused || len(heavy) != 1 || heavy[0].AsOf.IsZero() || runs.Load() != 1 {
		t.Errorf("after the late run finished: %+v, findings %+v, %d run(s); want its findings, dated, and no new run",
			s, heavy, runs.Load())
	}

	opts.Generation = "config-2"
	if s := stepOf(t, l.Run(context.Background(), dir, hubCfg(), opts), "test.heavy"); s.Outcome != StepFinished || runs.Load() != 2 {
		t.Errorf("under a changed configuration the step ended %s after %d run(s), want a new run", s.Outcome, runs.Load())
	}
	if s := stepOf(t, l.Run(context.Background(), dir, hubCfg(), opts), "test.heavy"); s.Outcome != StepReused {
		t.Errorf("a minute later the step ended %s, want reused", s.Outcome)
	}
	l.mu.Lock()
	m := l.last["test.heavy"]
	m.at = m.at.Add(-2 * freshFloor)
	l.last["test.heavy"] = m
	l.mu.Unlock()
	opts.Fresh = true
	if s := stepOf(t, l.Run(context.Background(), dir, hubCfg(), opts), "test.heavy"); s.Outcome != StepFinished || runs.Load() != 3 {
		t.Errorf("a Fresh run past a minute ended %s after %d run(s), want it made again", s.Outcome, runs.Load())
	}
}

// counts is a map nobody made.
func counts() map[string]int { return nil }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 10s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
