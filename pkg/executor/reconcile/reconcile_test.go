package reconcile

// Tests for Task 20170: a hub must come up with the executors its config
// names, must say so when one of them did not, and must refuse readiness when
// strict mode leaves it with nothing to dispatch to.
//
// The container driver is exercised through a fake runtime binary placed on
// PATH rather than through real docker/podman. That is not only about CI
// portability: it is the only way to drive preflight to a *chosen* outcome.
// A real daemon that happens to be healthy cannot demonstrate that a fatal
// preflight finding degrades one executor without aborting the pass, which is
// precisely the behaviour this file exists to pin down.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// fakeRuntime writes an executable named `docker` into a fresh directory and
// prepends it to PATH for the duration of the test. The script's behaviour is
// driven by the subcommand it is handed, so a test can make `docker version`
// succeed while `docker info` fails.
func fakeRuntime(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	body := "#!/bin/sh\n" + script + "\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake runtime: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// healthyRuntime answers every probe preflight makes well enough to produce a
// clean report.
const healthyRuntime = `
case "$1" in
  version) echo "27.0.0" ;;
  info)    echo "rootless" ;;
  image)   echo '[{"Id":"sha256:deadbeef"}]' ;;
  *)       exit 0 ;;
esac
`

// deadDaemonRuntime is installed and answers --version, but its daemon is
// unreachable. This is the single most common real failure: a hub container
// that has the docker CLI but no socket mounted.
const deadDaemonRuntime = `
case "$1" in
  version) echo "27.0.0" ;;
  *)       echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock." >&2; exit 1 ;;
esac
`

// strict turns on no-host-execution mode for one test and restores the
// previous value afterwards. The policy is process-global, so leaking it
// would silently change every later test's readiness verdict.
func strict(t *testing.T) {
	t.Helper()
	prev := executor.SetAllowHostExecution(false)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })
}

// permissive is strict's counterpart, for tests asserting the ungated path.
func permissive(t *testing.T) {
	t.Helper()
	prev := executor.SetAllowHostExecution(true)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })
}

// isolatedReport keeps a test's reconciliation out of the process-global
// published report unless the test asks for it.
func isolatedOpts(reg *executor.Registry) Options {
	no := false
	return Options{
		Registry: reg,
		Publish:  &no,
		Logf:     func(string, ...any) {},
	}
}

func containerConfig(id string) *config.Config {
	cfg := &config.Config{}
	cfg.Executors.Container.Enabled = true
	cfg.Executors.Container.ID = id
	cfg.Executors.Container.Runtime = "docker"
	cfg.Executors.Container.Image = "example.invalid/harness:latest"
	return cfg
}

func diagFor(t *testing.T, r Report, id string) Diagnostic {
	t.Helper()
	for _, d := range r.Diagnostics {
		if d.ID == id {
			return d
		}
	}
	t.Fatalf("no diagnostic for %q; got %+v", id, r.Diagnostics)
	return Diagnostic{}
}

// TestStrictModeRegistersConfiguredContainerExecutor is the regression test
// for the bug this task names: a hub with allow_host_process:false and a
// container executor configured came up with zero usable executors, because
// the only bootstrap the server ran registered localprocess (which strict
// mode then refused) and nothing ever registered the container driver.
func TestStrictModeRegistersConfiguredContainerExecutor(t *testing.T) {
	fakeRuntime(t, healthyRuntime)
	strict(t)

	reg := executor.NewRegistry()
	opts := isolatedOpts(reg)
	opts.SkipPreflight = true

	report := FromConfig(context.Background(), t.TempDir(), containerConfig("sandbox"), opts)

	d := diagFor(t, report, "sandbox")
	if d.Status != StatusOK {
		t.Fatalf("expected the container executor to reconcile OK, got %s: %s", d.Status, d.Message)
	}
	if !d.Registered {
		t.Fatal("expected the container executor to be registered")
	}
	if !d.Isolating {
		t.Fatal("a container executor must count as isolating, or strict mode has nothing to accept")
	}

	// The registry, not just the diagnostic, must actually hold it — that is
	// what Resolve consults.
	ex, err := reg.Get("sandbox")
	if err != nil {
		t.Fatalf("container executor missing from the registry: %v", err)
	}
	if ex.Kind() != executor.KindContainer {
		t.Fatalf("expected a container executor, got kind %q", ex.Kind())
	}
	if got := reg.IsolatedIDs(); len(got) != 1 || got[0] != "sandbox" {
		t.Fatalf("expected the container executor to be the isolating one, got %v", got)
	}

	// And the hub must consider itself able to serve traffic.
	if err := ReadyIn(reg); err != nil {
		t.Fatalf("expected readiness with a registered isolating executor, got: %v", err)
	}
}

// TestStrictModeWithNoIsolatingExecutorIsNotReady is the readiness half: a
// hub that cannot dispatch anything must fail its probe rather than accept
// traffic it can only answer with 409s.
func TestStrictModeWithNoIsolatingExecutorIsNotReady(t *testing.T) {
	strict(t)
	resetForTest()

	reg := executor.NewRegistry()
	// A config with no executors section at all — exactly what the Helm
	// chart renders when kubernetes.enabled is left false.
	report := FromConfig(context.Background(), t.TempDir(), &config.Config{}, isolatedOpts(reg))
	if len(report.Diagnostics) != 0 {
		t.Fatalf("expected no diagnostics for an empty config, got %+v", report.Diagnostics)
	}
	if report.IsolatingRegistered() {
		t.Fatal("no isolating executor was configured, so none can be registered")
	}

	err := ReadyIn(reg)
	if err == nil {
		t.Fatal("expected not-ready when strict mode is on and nothing isolating is registered")
	}
	var notReady *NotReadyError
	if !errors.As(err, &notReady) {
		t.Fatalf("expected a *NotReadyError so the probe can render the remediation, got %T", err)
	}
	if notReady.Remediation == "" {
		t.Fatal("a not-ready verdict must carry a remediation, or the operator only learns the symptom")
	}
	if !strings.Contains(notReady.Reason, "strict mode") {
		t.Fatalf("expected the reason to name strict mode, got %q", notReady.Reason)
	}
}

// TestPermissiveModeIsReadyWithoutIsolatingExecutor guards the other
// direction: the readiness gate must not break the single-machine install,
// where the host driver is the whole configuration.
func TestPermissiveModeIsReadyWithoutIsolatingExecutor(t *testing.T) {
	permissive(t)
	reg := executor.NewRegistry()
	if err := ReadyIn(reg); err != nil {
		t.Fatalf("permissive mode must never gate readiness on executors, got: %v", err)
	}
}

// TestPreflightFailureDegradesOneExecutorWithoutAbortingStartup: a broken
// container runtime must not take the hub down, and must not take an
// unrelated executor with it.
//
// Degraded rather than unregistered is deliberate. Preflight is a
// point-in-time probe; a driver dropped from the registry because the daemon
// was restarting during boot would stay gone until someone restarted the hub.
func TestPreflightFailureDegradesOneExecutorWithoutAbortingStartup(t *testing.T) {
	fakeRuntime(t, deadDaemonRuntime)
	strict(t)

	reg := executor.NewRegistry()
	// A second, healthy isolating executor stands in for "the rest of the
	// hub": the pass must complete and leave it usable.
	other := &stubExecutor{id: "remote-1", kind: executor.KindRemoteAgent, isolation: executor.IsolationRemote}
	if err := reg.Register(other); err != nil {
		t.Fatalf("register stub: %v", err)
	}

	report := FromConfig(context.Background(), t.TempDir(), containerConfig("sandbox"), isolatedOpts(reg))

	d := diagFor(t, report, "sandbox")
	if d.Status != StatusDegraded {
		t.Fatalf("expected a failed preflight to degrade the executor, got %s: %s", d.Status, d.Message)
	}
	if !d.Registered {
		t.Fatal("a degraded executor stays registered so a later dispatch can retry")
	}
	if d.Remediation == "" {
		t.Fatal("a degraded executor must carry a remediation")
	}
	if len(d.Findings) == 0 {
		t.Fatal("expected the preflight checklist to be recorded, not just a summary")
	}
	// Naming the check proves the fake runtime was actually driven: only a
	// real `docker info` probe against the dead-daemon script produces this.
	var sawDaemonFail bool
	for _, f := range d.Findings {
		if f.Level == "fail" && f.Name == "daemon" {
			sawDaemonFail = true
		}
	}
	if !sawDaemonFail {
		t.Fatalf("expected a fatal 'daemon' finding among %+v", d.Findings)
	}

	// Startup was not aborted: the unrelated executor is untouched, and the
	// hub is still ready because something isolating is registered.
	if _, err := reg.Get("remote-1"); err != nil {
		t.Fatalf("an unrelated executor must survive another driver's preflight failure: %v", err)
	}
	if err := ReadyIn(reg); err != nil {
		t.Fatalf("one degraded executor must not make the hub unready: %v", err)
	}
}

// TestReconcileIsIdempotent: the hub reconciles more than once by design —
// cmd/root.go's PersistentPreRunE runs a pass, then the server runs another
// from its own workdir, and Bootstrap runs a third in the background to
// attach preflight results. None of them may duplicate a registration or
// rebuild a driver.
func TestReconcileIsIdempotent(t *testing.T) {
	fakeRuntime(t, healthyRuntime)
	strict(t)

	reg := executor.NewRegistry()
	opts := isolatedOpts(reg)
	opts.SkipPreflight = true
	dir := t.TempDir()
	cfg := containerConfig("sandbox")

	first := FromConfig(context.Background(), dir, cfg, opts)
	firstEx, err := reg.Get("sandbox")
	if err != nil {
		t.Fatalf("first pass did not register: %v", err)
	}

	for i := 0; i < 3; i++ {
		again := FromConfig(context.Background(), dir, cfg, opts)
		if len(again.Diagnostics) != len(first.Diagnostics) {
			t.Fatalf("pass %d produced %d diagnostics, first produced %d",
				i+2, len(again.Diagnostics), len(first.Diagnostics))
		}
		d := diagFor(t, again, "sandbox")
		if d.Status != StatusOK || !d.Registered {
			t.Fatalf("pass %d degraded an already-good executor: %s %s", i+2, d.Status, d.Message)
		}
	}

	// Exactly one registry row, and the *same driver instance* — a rebuilt
	// Kubernetes executor would leak the state database handle its credential
	// source holds open for the process's lifetime.
	all := reg.List()
	if len(all) != 1 {
		ids := make([]string, 0, len(all))
		for _, ex := range all {
			ids = append(ids, ex.ID())
		}
		t.Fatalf("expected exactly one registered executor after repeated passes, got %v", ids)
	}
	afterEx, err := reg.Get("sandbox")
	if err != nil {
		t.Fatalf("executor vanished across passes: %v", err)
	}
	if afterEx != firstEx {
		t.Fatal("repeated reconciliation rebuilt the driver instead of reusing the registered one")
	}
}

// TestUnbuildableDriverFailsWithoutRegistering covers the other failure
// class: a runtime that is not installed at all. There is nothing to
// register, so the diagnostic must say failed — and under strict mode with
// nothing else, readiness must go red.
func TestUnbuildableDriverFailsWithoutRegistering(t *testing.T) {
	// A PATH with no container runtime on it whatsoever.
	t.Setenv("PATH", t.TempDir())
	strict(t)
	resetForTest()

	reg := executor.NewRegistry()
	report := FromConfig(context.Background(), t.TempDir(), containerConfig("sandbox"), isolatedOpts(reg))

	d := diagFor(t, report, "sandbox")
	if d.Status != StatusFailed {
		t.Fatalf("expected failed for a missing runtime, got %s: %s", d.Status, d.Message)
	}
	if d.Registered {
		t.Fatal("a driver that could not be built must not be reported as registered")
	}
	if !strings.Contains(d.Remediation, "container runtime") {
		t.Fatalf("expected a remediation naming the missing runtime, got %q", d.Remediation)
	}
	if _, err := reg.Get("sandbox"); err == nil {
		t.Fatal("nothing should have been registered")
	}
	if err := ReadyIn(reg); err == nil {
		t.Fatal("expected not-ready: strict mode with the only configured executor unbuildable")
	}
}

// TestLastReportPublishesDiagnostics: the API and the probes read the
// reconciliation through LastReport, so a pass that does not publish is a
// pass the operator cannot see.
func TestLastReportPublishesDiagnostics(t *testing.T) {
	fakeRuntime(t, healthyRuntime)
	permissive(t)
	resetForTest()
	t.Cleanup(resetForTest)

	reg := executor.NewRegistry()
	FromConfig(context.Background(), t.TempDir(), containerConfig("sandbox"), Options{
		Registry:      reg,
		SkipPreflight: true,
		Logf:          func(string, ...any) {},
	})

	got, ok := LastReport()
	if !ok {
		t.Fatal("expected a published report")
	}
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].ID != "sandbox" {
		t.Fatalf("expected the sandbox diagnostic to be published, got %+v", got.Diagnostics)
	}

	// The copy must be a copy: a caller marshalling it must not be able to
	// mutate what the next reader sees.
	got.Diagnostics[0].Message = "tampered"
	again, _ := LastReport()
	if again.Diagnostics[0].Message == "tampered" {
		t.Fatal("LastReport handed out a reference to the live report")
	}
}

// TestDisabledConfigProducesNoDiagnostic: an executor nobody asked for is not
// a problem, and must not clutter the panel or the readiness message.
func TestDisabledConfigProducesNoDiagnostic(t *testing.T) {
	permissive(t)
	reg := executor.NewRegistry()
	cfg := containerConfig("sandbox")
	cfg.Executors.Container.Enabled = false

	report := FromConfig(context.Background(), t.TempDir(), cfg, isolatedOpts(reg))
	if len(report.Diagnostics) != 0 {
		t.Fatalf("expected no diagnostics for a disabled executor, got %+v", report.Diagnostics)
	}
}

// TestBootstrapRegistersSynchronously: whatever Bootstrap defers to the
// background, registration is not part of it. A server whose listener opened
// before its executors were registered would report a false not-ready — or
// worse, resolve a project to the wrong backend.
func TestBootstrapRegistersSynchronously(t *testing.T) {
	fakeRuntime(t, healthyRuntime)
	strict(t)
	resetForTest()
	t.Cleanup(resetForTest)

	reg := executor.NewRegistry()
	no := false
	report := Bootstrap(t.TempDir(), containerConfig("sandbox"), Options{
		Registry:      reg,
		Publish:       &no,
		SkipPreflight: true, // keep the background pass out of this test
		Logf:          func(string, ...any) {},
	})

	if _, err := reg.Get("sandbox"); err != nil {
		t.Fatalf("Bootstrap must register before returning: %v", err)
	}
	if d := diagFor(t, report, "sandbox"); !d.Registered {
		t.Fatalf("expected the returned report to show the executor registered, got %+v", d)
	}
	if err := ReadyIn(reg); err != nil {
		t.Fatalf("expected readiness immediately after Bootstrap returns: %v", err)
	}
}

// stubExecutor is a minimal isolating executor standing in for an enrolled
// remote agent.
type stubExecutor struct {
	id        string
	kind      string
	isolation executor.Isolation
}

func (s *stubExecutor) ID() string   { return s.id }
func (s *stubExecutor) Kind() string { return s.kind }
func (s *stubExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: s.isolation}
}
func (s *stubExecutor) HealthCheck(context.Context) error { return nil }
func (s *stubExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("stub")
}
func (s *stubExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, errors.New("stub")
}
func (s *stubExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("stub")
}
func (s *stubExecutor) Signal(context.Context, string, executor.Signal) error {
	return errors.New("stub")
}

// TestKubernetesCredentialCleanupOnRegistrationFailure covers a resource leak
// that repeated reconciliation would otherwise make unbounded.
//
// BrokerCredentials opens a state database that the executor keeps for the
// process's lifetime — so it is deliberately never closed on the success path.
// When the source is built but registration then fails there is no executor to
// hold it and no other reference to it, so without an explicit release each
// pass strands one SQLite handle and its WAL lock. Bootstrap runs two passes
// per server start, which turns a one-off into a per-start leak.
func TestKubernetesCredentialCleanupOnRegistrationFailure(t *testing.T) {
	permissive(t)
	reg := executor.NewRegistry()

	var cleanups int
	opts := isolatedOpts(reg)
	// A nil CredentialSource with a live cleanup: kubernetes.New rejects it,
	// so registration fails *after* the source was built — exactly the shape
	// of a broker that opened its database and then hit a bad driver option.
	opts.KubernetesCredentials = func(dir string, cfg *config.Config, execID string) (kubernetes.CredentialSource, func(), error) {
		return nil, func() { cleanups++ }, nil
	}

	cfg := &config.Config{}
	cfg.Executors.Kubernetes.Enabled = true
	cfg.Executors.Kubernetes.ID = "k8s"

	report := FromConfig(context.Background(), t.TempDir(), cfg, opts)

	d := diagFor(t, report, "k8s")
	if d.Status != StatusFailed {
		t.Fatalf("expected registration to fail, got %s: %s", d.Status, d.Message)
	}
	if d.Registered {
		t.Fatal("nothing should have been registered")
	}
	if cleanups != 1 {
		t.Fatalf("expected the credential source to be released exactly once, got %d", cleanups)
	}
	if _, err := reg.Get("k8s"); err == nil {
		t.Fatal("no kubernetes executor should be in the registry")
	}
}

// TestPublishOrderingIgnoresStalePass: Bootstrap deliberately overlaps two
// passes and a preflight can take most of a minute, so publication has to be
// ordered by when a pass STARTED, not by when it happened to finish.
// Otherwise the slowest pass wins and /readyz explains a live hub with a dead
// one's diagnostics.
func TestPublishOrderingIgnoresStalePass(t *testing.T) {
	permissive(t)
	resetForTest()
	t.Cleanup(resetForTest)

	stale := nextPublishTicket() // an early pass that will finish late
	fresh := nextPublishTicket() // a later pass that finishes first

	publishAt(fresh, Report{Diagnostics: []Diagnostic{{ID: "fresh", Status: StatusOK}}})
	publishAt(stale, Report{Diagnostics: []Diagnostic{{ID: "stale", Status: StatusFailed}}})

	got, ok := LastReport()
	if !ok {
		t.Fatal("expected a published report")
	}
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].ID != "fresh" {
		t.Fatalf("a pass that started earlier overwrote a later one: %+v", got.Diagnostics)
	}
}

// TestResetForTestRetiresInFlightPasses: a background preflight left running
// by an earlier test must not republish over the next test's fixture.
func TestResetForTestRetiresInFlightPasses(t *testing.T) {
	permissive(t)
	resetForTest()
	t.Cleanup(resetForTest)

	inFlight := nextPublishTicket() // a pass that started before the reset
	resetForTest()

	publishAt(inFlight, Report{Diagnostics: []Diagnostic{{ID: "leaked", Status: StatusFailed}}})

	if _, ok := LastReport(); ok {
		t.Fatal("a pass from before ResetForTest republished over the cleared report")
	}
}

// TestLastReportDeepCopiesFindings: handlers hand Findings straight into view
// structs, so a shallow copy would let one request mutate what every other
// in-flight request and every future reader sees, under no lock.
func TestLastReportDeepCopiesFindings(t *testing.T) {
	permissive(t)
	resetForTest()
	t.Cleanup(resetForTest)

	PublishForTest(Report{Diagnostics: []Diagnostic{{
		ID:       "c",
		Status:   StatusDegraded,
		Findings: []Finding{{Name: "runtime", Level: "fail", Message: "original"}},
	}}})

	first, _ := LastReport()
	first.Diagnostics[0].Findings[0].Message = "tampered"

	second, _ := LastReport()
	if second.Diagnostics[0].Findings[0].Message != "original" {
		t.Fatal("LastReport shares the Findings backing array between callers")
	}
}
