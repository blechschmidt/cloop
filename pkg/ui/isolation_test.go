package ui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
	"github.com/blechschmidt/cloop/pkg/state"
)

// sgxKernel is sgx's own kernel; a runc sandbox there read the same boot ID.
var sgxKernel = isolationprobe.Evidence{Schema: 1, Release: "6.8.0-79-generic",
	Version: "#79-Ubuntu SMP PREEMPT_DYNAMIC Tue Aug 12 14:42:46 UTC 2025",
	BootID:  "2d725fb0-4ac8-4443-b68c-8c50313f7439", UptimeSeconds: 14460005, Hypervisor: true,
	DMIVendor: "Alibaba Cloud"}

// isoExec is a container executor whose runtime is named for isolation and
// whose probe answers from a script.
type isoExec struct {
	id, runtime string
	answer      func() (executor.IsolationProbe, error)
	probes      atomic.Int32
}

func (e *isoExec) ID() string   { return e.id }
func (e *isoExec) Kind() string { return executor.KindContainer }
func (e *isoExec) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationVM, Virtualized: executor.IsVirtualizedRuntime(e.runtime),
		KernelIsolated: executor.IsKernelIsolatedRuntime(e.runtime), SupportsStream: true, SupportsSignal: true}
}
func (e *isoExec) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("not in this test")
}
func (e *isoExec) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *isoExec) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (e *isoExec) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("not in this test")
}
func (e *isoExec) HealthCheck(context.Context) error { return nil }
func (e *isoExec) IsolationRuntime() (string, bool)  { return e.runtime, true }
func (e *isoExec) ProbeIsolation(context.Context) (executor.IsolationProbe, error) {
	e.probes.Add(1)
	return e.answer()
}

// runcNamedKata answers as runc does under a runtime called kata.
func runcNamedKata() (executor.IsolationProbe, error) {
	ev, host := sgxKernel, sgxKernel
	return executor.IsolationProbe{Runtime: "kata", Engine: "docker", Evidence: ev,
		Reference: isolationprobe.Reference{Kernel: &host, Source: isolationprobe.SourceHub, EngineKernel: host.Release}}, nil
}

func registerIsoExec(t *testing.T, ex *isoExec) {
	t.Helper()
	if err := executor.DefaultRegistry.Register(ex); err != nil {
		t.Fatalf("register %s: %v", ex.id, err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.id) })
}

func executorViewFor(t *testing.T, base, id string) map[string]any {
	t.Helper()
	resp, err := http.Get(base + "/api/executors")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Executors []map[string]any `json:"executors"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, raw)
	}
	for _, ex := range body.Executors {
		if ex["id"] == id {
			return ex
		}
	}
	t.Fatalf("executor %s not listed", id)
	return nil
}

// TestExecutorCardShowsClaimedAgainstVerified: the executor list carries what
// the card renders — "claims kata, runs on the host kernel" — with the
// evidence, and says projects requiring isolation are refused there.
func TestExecutorCardShowsClaimedAgainstVerified(t *testing.T) {
	dir := setupProjectDir(t, "isolation evidence", nil)
	ts := newTestServer(t, dir, nil)
	ex := &isoExec{id: "kata-alias", runtime: "kata", answer: runcNamedKata}
	registerIsoExec(t, ex)

	before := executorViewFor(t, ts.URL, "kata-alias")["isolation_evidence"].(map[string]any)
	if before["summary"] != "claims kata, never verified" || before["status"] != "unverified" {
		t.Fatalf("before any probe: %v", before)
	}

	v := activeIsolationVerifier()
	if v == nil {
		t.Fatal("the hub started no isolation verifier")
	}
	if _, err := v.Probe(context.Background(), ex, executor.ProbePointManual); err != nil {
		t.Fatal(err)
	}
	iso := executorViewFor(t, ts.URL, "kata-alias")["isolation_evidence"].(map[string]any)
	if iso["summary"] != "claims kata, runs on the host kernel" || iso["status"] != "contradicted" ||
		iso["refused"] != true || iso["verdict"] != "host-kernel" {
		t.Fatalf("after the probe: %v", iso)
	}
	if !strings.Contains(iso["detail"].(string), "2d725fb0") {
		t.Errorf("the card's detail does not carry the evidence: %v", iso["detail"])
	}
}

// TestReprobeEndpoint: the card's Re-probe runs the probe in the background
// and answers at once; an executor with no runtime, or none at all, is
// refused.
func TestReprobeEndpoint(t *testing.T) {
	dir := setupProjectDir(t, "isolation reprobe", nil)
	ts := newTestServer(t, dir, nil)
	ex := &isoExec{id: "gv-box", runtime: "runsc", answer: func() (executor.IsolationProbe, error) {
		ev := isolationprobe.Evidence{Schema: 1, Release: "4.19.0-gvisor", Version: isolationprobe.GVisorBuildString,
			BootID: "e4bdf59a-6ddf-4e29-912c-36f0bd406295", GVisor: []string{"boot log \"Starting gVisor...\""}}
		host := sgxKernel
		return executor.IsolationProbe{Runtime: "runsc", Evidence: ev,
			Reference: isolationprobe.Reference{Kernel: &host, Source: isolationprobe.SourceHub}}, nil
	}}
	registerIsoExec(t, ex)

	code, body := doJSON(t, http.DefaultClient, http.MethodPost, ts.URL+"/api/executors/gv-box/isolation-probe", "{}")
	if code != http.StatusAccepted || body["started"] != true {
		t.Fatalf("POST = %d %v", code, body)
	}
	activeIsolationVerifier().Wait()
	if ex.probes.Load() != 1 {
		t.Fatalf("%d probes ran", ex.probes.Load())
	}
	iso := executorViewFor(t, ts.URL, "gv-box")["isolation_evidence"].(map[string]any)
	if iso["status"] != "verified" || iso["point"] != executor.ProbePointManual {
		t.Fatalf("after the re-probe: %v", iso)
	}

	if code, _ := doJSON(t, http.DefaultClient, http.MethodPost, ts.URL+"/api/executors/nope/isolation-probe", "{}"); code != http.StatusNotFound {
		t.Errorf("an unknown executor: %d", code)
	}
	plain := &plainExec{id: "no-runtime"}
	if err := executor.DefaultRegistry.Register(plain); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(plain.id) })
	if code, _ := doJSON(t, http.DefaultClient, http.MethodPost, ts.URL+"/api/executors/no-runtime/isolation-probe", "{}"); code != http.StatusConflict {
		t.Errorf("an executor with no runtime: %d, want 409", code)
	}
}

// plainExec runs its payloads under no runtime.
type plainExec struct{ id string }

func (e *plainExec) ID() string   { return e.id }
func (e *plainExec) Kind() string { return executor.KindContainer }
func (e *plainExec) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer}
}
func (e *plainExec) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("not in this test")
}
func (e *plainExec) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *plainExec) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (e *plainExec) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("not in this test")
}
func (e *plainExec) HealthCheck(context.Context) error { return nil }

// TestUnverifiedPlacementIsJournaledOnce: a run placed for a project requiring
// a hypervisor on a claim nothing verified carries one warning per executor
// runtime and probe attempt, not one per task.
func TestUnverifiedPlacementIsJournaledOnce(t *testing.T) {
	dir := setupProjectDir(t, "isolation journal", nil)
	newTestServer(t, dir, nil)
	ex := &isoExec{id: "never-probed", runtime: "kata-qemu", answer: func() (executor.IsolationProbe, error) {
		return executor.IsolationProbe{}, errors.New("the image is not present")
	}}
	req := executor.Requirements{RequireVirtualization: true}
	journalUnverifiedIsolation(dir, ex, req)
	journalUnverifiedIsolation(dir, ex, req)
	rows, err := state.ListEventsOfType(dir, state.EventIsolationEvidence, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "never-probed") ||
		!strings.Contains(rows[0].Message, "requires a hypervisor") {
		t.Fatalf("rows = %+v", rows)
	}
	// A new attempt — this one failed — is news: the next run says why.
	if _, err := activeIsolationVerifier().Probe(context.Background(), ex, executor.ProbePointDaily); err == nil {
		t.Fatal("the scripted probe did not fail")
	}
	journalUnverifiedIsolation(dir, ex, req)
	rows, _ = state.ListEventsOfType(dir, state.EventIsolationEvidence, 10)
	if len(rows) != 2 || !strings.Contains(rows[0].Message+rows[1].Message, "the image is not present") {
		t.Fatalf("rows = %+v", rows)
	}
}
