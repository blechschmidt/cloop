package ui

// A run started over the API never asks cloop run for --pm (Task 20491).
//
// POST /api/projects/{idx}/run took {"pm": true} and passed it on as
// `cloop run --pm`. cloop run has had no such flag since May 2026, so such a
// run stopped at "unknown flag: --pm" before it began, on this hub and on
// every device. (The dashboard's old ▶ PM button meant to send it but nested
// it inside another field, so its runs started without it.) A client that
// still sends it now gets a run that starts.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestProjectRunNeverPassesTheRemovedPMFlag(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // a project registry of the test's own
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, "a run started the old way", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	setProvider(t, dir, "mock")

	host := newHarnessExec("pm-flag-host", executor.KindLocalProcess, executor.IsolationNone)
	registerStub(t, host)
	executor.DefaultRegistry.Unbind(dir)
	if err := executor.Bind(dir, host.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 1000, 1000
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/projects/0/run", bytes.NewBufferString(`{"pm":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/projects/0/run {\"pm\":true} = %d, want 200", resp.StatusCode)
	}
	settleRuns(t, srv)

	specs := host.started()
	if len(specs) != 1 {
		t.Fatalf("started %d workloads, want the one run", len(specs))
	}
	argv := specs[0].Argv
	if slices.Contains(argv, "--pm") {
		t.Errorf("the run was dispatched as %q: cloop run has no --pm", argv)
	}
	if len(argv) == 0 || argv[len(argv)-1] != "run" {
		t.Errorf("the run was dispatched as %q, want `<cloop> run`", argv)
	}
}
