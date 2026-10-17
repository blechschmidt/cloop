package isolationverify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }

// sgx's kernel, and what its runc and runsc sandboxes served (see
// pkg/isolationprobe/testdata).
var (
	sgx = isolationprobe.Evidence{Schema: 1, Release: "6.8.0-79-generic",
		Version: "#79-Ubuntu SMP PREEMPT_DYNAMIC Tue Aug 12 14:42:46 UTC 2025",
		BootID:  "2d725fb0-4ac8-4443-b68c-8c50313f7439", UptimeSeconds: 14460005, Hypervisor: true,
		DMIVendor: "Alibaba Cloud"}
	gvisor = isolationprobe.Evidence{Schema: 1, Release: "4.19.0-gvisor", Version: isolationprobe.GVisorBuildString,
		BootID: "e4bdf59a-6ddf-4e29-912c-36f0bd406295", GVisor: []string{"boot log \"Starting gVisor...\""}}
)

// stubProber is an executor whose probe answers from a script.
type stubProber struct {
	id, runtime string
	answer      func() (executor.IsolationProbe, error)
	calls       atomic.Int32
	gate        chan struct{}
}

func (s *stubProber) ID() string   { return s.id }
func (s *stubProber) Kind() string { return executor.KindContainer }
func (s *stubProber) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer,
		Virtualized: executor.IsVirtualizedRuntime(s.runtime), KernelIsolated: executor.IsKernelIsolatedRuntime(s.runtime)}
}
func (s *stubProber) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("not here")
}
func (s *stubProber) Signal(context.Context, string, executor.Signal) error { return nil }
func (s *stubProber) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (s *stubProber) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("not here")
}
func (s *stubProber) HealthCheck(context.Context) error { return nil }
func (s *stubProber) IsolationRuntime() (string, bool)  { return s.runtime, true }
func (s *stubProber) ProbeIsolation(context.Context) (executor.IsolationProbe, error) {
	s.calls.Add(1)
	if s.gate != nil {
		<-s.gate
	}
	return s.answer()
}

// runcAs answers like runc registered under the prober's runtime name.
func runcAs(runtime string) func() (executor.IsolationProbe, error) {
	return func() (executor.IsolationProbe, error) {
		ev, host := sgx, sgx
		return executor.IsolationProbe{Runtime: runtime, Engine: "docker", Image: "alpine:3.20", Evidence: ev,
			Reference: isolationprobe.Reference{Kernel: &host, Source: isolationprobe.SourceHub, EngineKernel: sgx.Release}}, nil
	}
}

func controlPlane(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	return path
}

func verdictAudits(t *testing.T, path string) []statedb.AuditEvent {
	t.Helper()
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionExecutorIsolationVerdict)})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestProbeRecordsTheVerdictAndPlacementSeesIt is the hub's whole chain for
// the case the task names: a runtime called kata that is runc. The verdict is
// recorded, audited once, read by placement through the source, and refuses a
// project requiring a hypervisor.
func TestProbeRecordsTheVerdictAndPlacementSeesIt(t *testing.T) {
	path := controlPlane(t)
	v := New(Options{DBPath: path, Instance: "member-a"})
	prev := executor.SetIsolationEvidenceSource(v.Lookup)
	t.Cleanup(func() { executor.SetIsolationEvidenceSource(prev) })

	ex := &stubProber{id: "kata-box", runtime: "kata", answer: runcAs("kata")}
	rec, err := v.Probe(context.Background(), ex, executor.ProbePointReconcile)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Verdict != isolationprobe.KindHostKernel || rec.Status() != isolationprobe.StatusContradicted {
		t.Fatalf("record = %+v", rec)
	}

	db, _ := statedb.Open(path)
	row, ok, err := db.IsolationEvidence("kata-box", "kata")
	_ = db.Close()
	if err != nil || !ok || row.ProbedBy != "member-a" || row.Engine != "docker" ||
		!strings.Contains(row.Evidence, sgx.BootID) || !strings.Contains(row.Reference, `"source":"hub"`) {
		t.Fatalf("row = %+v, %v, %v", row, ok, err)
	}
	audits := verdictAudits(t, path)
	if len(audits) != 1 || !strings.Contains(audits[0].Payload, `"status":"contradicted"`) ||
		!strings.Contains(audits[0].Payload, `"previous_status":""`) {
		t.Fatalf("audits = %+v", audits)
	}

	_, err = executor.Select([]executor.Candidate{{Executor: ex, Health: executor.Health{State: executor.NodeReady}}},
		executor.Requirements{RequireVirtualization: true})
	if err == nil || !strings.Contains(err.Error(), "isolation_evidence") {
		t.Fatalf("Select = %v, want the contradiction", err)
	}

	// The same verdict again is not news.
	if _, err := v.Probe(context.Background(), ex, executor.ProbePointDaily); err != nil {
		t.Fatal(err)
	}
	if n := len(verdictAudits(t, path)); n != 1 {
		t.Errorf("an unchanged verdict was audited again (%d rows)", n)
	}
}

// TestAFailedProbeKeepsTheContradiction: breaking the probe must not be the
// way out of a contradiction. A fixed runtime is.
func TestAFailedProbeKeepsTheContradiction(t *testing.T) {
	path := controlPlane(t)
	v := New(Options{DBPath: path})
	ex := &stubProber{id: "kata-box", runtime: "kata", answer: runcAs("kata")}
	if _, err := v.Probe(context.Background(), ex, executor.ProbePointReconcile); err != nil {
		t.Fatal(err)
	}
	ex.answer = func() (executor.IsolationProbe, error) { return executor.IsolationProbe{}, errors.New("image gone") }
	rec, err := v.Probe(context.Background(), ex, executor.ProbePointDaily)
	if err == nil || rec.Status() != isolationprobe.StatusContradicted || rec.Error != "image gone" {
		t.Fatalf("after a failed probe: %+v, %v", rec, err)
	}
	// A fresh verifier reads the same from the database.
	if got, ok := New(Options{DBPath: path}).Lookup("kata-box", "kata"); !ok || got.Status() != isolationprobe.StatusContradicted {
		t.Fatalf("Lookup = %+v, %v", got, ok)
	}

	// The operator fixes the runtime: it now really is a VM.
	ex.answer = func() (executor.IsolationProbe, error) {
		guest := isolationprobe.Evidence{Schema: 1, Release: "6.6.142-0-virt", Version: "#1-Alpine SMP",
			BootID: "37031ef6-ddd1-44bb-a61d-990106817d96", Hypervisor: true, DMIVendor: "QEMU"}
		host := sgx
		return executor.IsolationProbe{Runtime: "kata", Evidence: guest,
			Reference: isolationprobe.Reference{Kernel: &host, Source: isolationprobe.SourceHub}}, nil
	}
	rec, err = v.Probe(context.Background(), ex, executor.ProbePointManual)
	if err != nil || rec.Status() != isolationprobe.StatusVerified || rec.Error != "" {
		t.Fatalf("after the fix: %+v, %v", rec, err)
	}
	audits := verdictAudits(t, path)
	if len(audits) != 2 || !strings.Contains(audits[1].Payload, `"previous_status":"contradicted"`) {
		t.Fatalf("audits = %+v", audits)
	}
}

// TestAnotherMembersVerdictReachesPlacement: a cluster member that did not
// run the probe sees its verdict once its cache expires.
func TestAnotherMembersVerdictReachesPlacement(t *testing.T) {
	path := controlPlane(t)
	clock := time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	reader := New(Options{DBPath: path, Now: now, CacheTTL: time.Minute})
	if _, ok := reader.Lookup("gv", "runsc"); ok {
		t.Fatal("a record before any probe")
	}
	writer := New(Options{DBPath: path, Now: now})
	ex := &stubProber{id: "gv", runtime: "runsc", answer: func() (executor.IsolationProbe, error) {
		ev, host := gvisor, sgx
		return executor.IsolationProbe{Runtime: "runsc", Evidence: ev,
			Reference: isolationprobe.Reference{Kernel: &host, Source: isolationprobe.SourceAgent}}, nil
	}}
	if _, err := writer.Probe(context.Background(), ex, executor.ProbePointHello); err != nil {
		t.Fatal(err)
	}
	if _, ok := reader.Lookup("gv", "runsc"); ok {
		t.Fatal("the reader's cache was not used")
	}
	mu.Lock()
	clock = clock.Add(2 * time.Minute)
	mu.Unlock()
	rec, ok := reader.Lookup("gv", "runsc")
	if !ok || rec.Verdict != isolationprobe.KindUserspaceKernel || rec.Status() != isolationprobe.StatusVerified {
		t.Fatalf("Lookup = %+v, %v", rec, ok)
	}
}

// TestProbeAsyncRunsOneAtATime: a burst of triggers — a reconnect storm, a
// double click — starts one probe per executor and runtime.
func TestProbeAsyncRunsOneAtATime(t *testing.T) {
	v := New(Options{})
	gate := make(chan struct{})
	ex := &stubProber{id: "kata-box", runtime: "kata", answer: runcAs("kata"), gate: gate}
	if !v.ProbeAsync(ex, executor.ProbePointHello) {
		t.Fatal("the first probe did not start")
	}
	for i := 0; i < 5; i++ {
		if v.ProbeAsync(ex, executor.ProbePointHello) {
			t.Fatal("a second probe started while the first ran")
		}
	}
	close(gate)
	v.Wait()
	if n := ex.calls.Load(); n != 1 {
		t.Fatalf("%d probes ran", n)
	}
	if rec, ok := v.Lookup("kata-box", "kata"); !ok || rec.Verdict != isolationprobe.KindHostKernel {
		t.Fatalf("Lookup = %+v, %v", rec, ok)
	}
}

// TestRoundProbesWhatIsDue: the daily round skips an executor probed within
// the day and one with no runtime.
func TestRoundProbesWhatIsDue(t *testing.T) {
	clock := time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC)
	v := New(Options{Now: func() time.Time { return clock }})
	fresh := &stubProber{id: "fresh", runtime: "kata", answer: runcAs("kata")}
	stale := &stubProber{id: "stale", runtime: "kata", answer: runcAs("kata")}
	if _, err := v.Probe(context.Background(), fresh, executor.ProbePointReconcile); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	n := v.Round(context.Background(), []executor.Executor{fresh, stale, plainExecutor{}}, executor.ProbePointDaily, DueAfter)
	if n != 1 || fresh.calls.Load() != 1 || stale.calls.Load() != 1 {
		t.Fatalf("Round probed %d (fresh %d, stale %d)", n, fresh.calls.Load(), stale.calls.Load())
	}
	clock = clock.Add(DueAfter)
	if !v.Due(fresh, DueAfter) {
		t.Error("a day-old record is not due")
	}
	if err := v.Forget("fresh"); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Lookup("fresh", "kata"); ok {
		t.Error("Forget left the record")
	}
}

// TestWithoutADatabaseTheVerdictStaysInMemory: a process with no control plane
// keeps what it found, past the cache's lifetime.
func TestWithoutADatabaseTheVerdictStaysInMemory(t *testing.T) {
	clock := time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC)
	v := New(Options{DBPath: filepath.Join(t.TempDir(), "missing", "state.db"), Now: func() time.Time { return clock }})
	ex := &stubProber{id: "kata-box", runtime: "kata", answer: runcAs("kata")}
	if _, err := v.Probe(context.Background(), ex, executor.ProbePointReconcile); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	if rec, ok := v.Lookup("kata-box", "kata"); !ok || rec.Verdict != isolationprobe.KindHostKernel {
		t.Fatalf("Lookup = %+v, %v", rec, ok)
	}
}

// TestAProbeThatPanicsIsAFailedProbe.
func TestAProbeThatPanicsIsAFailedProbe(t *testing.T) {
	v := New(Options{})
	ex := &stubProber{id: "x", runtime: "kata", answer: func() (executor.IsolationProbe, error) { panic("boom") }}
	rec, err := v.Probe(context.Background(), ex, executor.ProbePointManual)
	if err == nil || !strings.Contains(rec.Error, "panicked") || rec.Status() != isolationprobe.StatusUnverified {
		t.Fatalf("rec = %+v, err = %v", rec, err)
	}
}

// plainExecutor has no runtime to probe.
type plainExecutor struct{}

func (plainExecutor) ID() string                          { return "host" }
func (plainExecutor) Kind() string                        { return executor.KindLocalProcess }
func (plainExecutor) Capabilities() executor.Capabilities { return executor.Capabilities{} }
func (plainExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, nil
}
func (plainExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (plainExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (plainExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, nil
}
func (plainExecutor) HealthCheck(context.Context) error { return nil }
