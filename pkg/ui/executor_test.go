// Integration tests for the UI's executor plumbing (Task 20156).
//
// pkg/executor and pkg/executor/localprocess carry the unit tests for
// registry policy and driver mechanics. What is tested here is the wiring
// the UI owns: that the helpers the handlers call actually start real work,
// stream it back, and read project→executor bindings out of the control
// plane's database.
//
// The fixture "workload" is this test binary re-invoked with -test.run
// pointing at a trivial test, which avoids depending on /bin/sh, coreutils,
// or PATH while still exercising a genuine fork+exec.

package ui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestExecutorFixtureNoOp exists so the tests below have a cheap,
// deterministic thing to execute. Running it prints "PASS" and exits 0.
func TestExecutorFixtureNoOp(t *testing.T) {}

// fixtureArgv re-invokes this test binary running only TestExecutorFixtureNoOp.
func fixtureArgv(t *testing.T) []string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	return []string{self, "-test.run", "^TestExecutorFixtureNoOp$"}
}

func TestRunWorkloadCollectsOutput(t *testing.T) {
	out, err := runWorkload(context.Background(), t.TempDir(), fixtureArgv(t), nil)
	if err != nil {
		t.Fatalf("runWorkload: %v (output: %q)", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("runWorkload output = %q, want it to contain PASS", out)
	}
}

func TestRunWorkloadPropagatesFailure(t *testing.T) {
	argv := []string{filepath.Join(t.TempDir(), "definitely-not-a-binary")}
	if _, err := runWorkload(context.Background(), t.TempDir(), argv, nil); err == nil {
		t.Fatal("runWorkload on a nonexistent binary returned nil error")
	}
}

func TestRunWorkloadHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runWorkload(ctx, t.TempDir(), fixtureArgv(t), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("runWorkload with a cancelled ctx = %v, want context.Canceled", err)
	}
}

// TestStartWorkloadReportsLivePID guards the property pkg/multiui's /proc
// scan depends on: the handle must carry the real OS PID of a process that
// is actually alive, or the Stop button can never find the run it started.
func TestStartWorkloadReportsLivePID(t *testing.T) {
	dir := t.TempDir()
	ex, handle, err := startWorkload(dir, fixtureArgv(t), map[string]string{"handler": "test"})
	if err != nil {
		t.Fatalf("startWorkload: %v", err)
	}
	if handle.PID <= 0 {
		t.Fatalf("Handle.PID = %d, want a real PID", handle.PID)
	}
	if handle.ID == "" || handle.ExecutorID == "" {
		t.Fatalf("incomplete handle: %+v", handle)
	}

	// Signal 0 probes for existence without delivering anything. The process
	// may already have exited (it is short-lived); ESRCH is therefore
	// acceptable, but any other error means the PID was never plausible.
	if proc, perr := os.FindProcess(handle.PID); perr == nil {
		if sigErr := proc.Signal(syscall.Signal(0)); sigErr != nil &&
			!errors.Is(sigErr, os.ErrProcessDone) && !errors.Is(sigErr, syscall.ESRCH) {
			t.Errorf("probing PID %d: %v", handle.PID, sigErr)
		}
	}

	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var sb strings.Builder
	done := time.After(60 * time.Second)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				if !strings.Contains(sb.String(), "PASS") {
					t.Fatalf("streamed output = %q, want it to contain PASS", sb.String())
				}
				st, statusErr := ex.Status(context.Background(), handle.ID)
				if statusErr != nil {
					t.Fatalf("Status: %v", statusErr)
				}
				if !st.State.Terminal() {
					t.Fatalf("State = %q once the stream closed, want terminal", st.State)
				}
				return
			}
			sb.WriteString(line.Text)
		case <-done:
			t.Fatalf("workload did not finish within 60s; got %q", sb.String())
		}
	}
}

// TestUISpecCarriesProvenance: labels are how a remote executor attributes a
// workload back to the project and handler that asked for it.
func TestUISpecCarriesProvenance(t *testing.T) {
	spec := uiSpec("/srv/app", []string{"cloop", "run"}, map[string]string{"handler": "run"})
	if spec.WorkDir != "/srv/app" {
		t.Errorf("WorkDir = %q", spec.WorkDir)
	}
	if len(spec.Argv) != 2 || spec.Argv[0] != "cloop" {
		t.Errorf("Argv = %v", spec.Argv)
	}
	for k, want := range map[string]string{
		"component": "web-ui",
		"project":   "/srv/app",
		"handler":   "run",
	} {
		if spec.Labels[k] != want {
			t.Errorf("Labels[%q] = %q, want %q", k, spec.Labels[k], want)
		}
	}
	if err := spec.Validate(); err != nil {
		t.Errorf("uiSpec produced an invalid spec: %v", err)
	}

	// The voice handler passes an empty workDir to mean "inherit the
	// server's cwd"; that must not produce a bogus project label.
	bare := uiSpec("", []string{"cloop", "listen"}, nil)
	if _, ok := bare.Labels["project"]; ok {
		t.Error("empty WorkDir should not produce a project label")
	}
}

// TestLookupProjectExecutorReadsBindings closes the loop between statedb and
// the registry: what the operator persisted is what Resolve will see.
func TestLookupProjectExecutorReadsBindings(t *testing.T) {
	controlPlane := t.TempDir()
	if err := os.MkdirAll(filepath.Join(controlPlane, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	dbPath := state.DBPath(controlPlane)
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.UpsertExecutor(statedb.ExecutorRow{
		ID: "edge-01", Kind: "remote", Status: statedb.ExecutorStatusOnline,
	}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
	if err := db.BindProjectExecutor("/srv/pinned", "edge-01", "tester"); err != nil {
		t.Fatalf("BindProjectExecutor: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if id, ok := lookupProjectExecutor(controlPlane, "/srv/pinned"); !ok || id != "edge-01" {
		t.Fatalf("lookupProjectExecutor = (%q, %v), want (edge-01, true)", id, ok)
	}
	if id, ok := lookupProjectExecutor(controlPlane, "/srv/unpinned"); ok {
		t.Fatalf("unbound project reported binding %q", id)
	}
}

// TestLookupProjectExecutorDegradesGracefully: a missing or unreadable
// control-plane database must read as "no binding" rather than blowing up a
// request. Before bindings existed every project used the default; that is
// the behavior to fall back to.
func TestLookupProjectExecutorDegradesGracefully(t *testing.T) {
	cases := []struct {
		name            string
		controlPlaneDir string
		project         string
	}{
		{name: "no database", controlPlaneDir: t.TempDir(), project: "/srv/app"},
		{name: "blank control plane dir", controlPlaneDir: "", project: "/srv/app"},
		{name: "blank project path", controlPlaneDir: t.TempDir(), project: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if id, ok := lookupProjectExecutor(tc.controlPlaneDir, tc.project); ok {
				t.Fatalf("lookupProjectExecutor = (%q, true), want no binding", id)
			}
		})
	}

	// A corrupt database file must not panic either.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(state.DBPath(dir), []byte("this is not sqlite"), 0o600); err != nil {
		t.Fatalf("write corrupt db: %v", err)
	}
	if id, ok := lookupProjectExecutor(dir, "/srv/app"); ok {
		t.Fatalf("corrupt database reported binding %q, want none", id)
	}
}

// TestDefaultExecutorIsRegistered: without this, every run handler would
// fail closed on a fresh single-machine install.
func TestDefaultExecutorIsRegistered(t *testing.T) {
	registerBuiltinExecutors()
	ex, err := executor.Resolve(t.TempDir())
	if err != nil {
		t.Fatalf("Resolve on an unbound project: %v", err)
	}
	if ex.Kind() != executor.KindLocalProcess {
		t.Fatalf("default executor kind = %q, want %q", ex.Kind(), executor.KindLocalProcess)
	}
	if err := ex.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}
