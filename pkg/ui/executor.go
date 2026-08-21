// Executor plumbing for the Web UI (Task 20156).
//
// The UI used to fork harness processes itself with raw exec.Command. It no
// longer does — every workload the UI starts goes through
// executor.Resolve(projectPath).Start(...), so where that workload actually
// runs (this host, a container, a remote edge device) becomes a deployment
// decision instead of a hard-coded assumption. no_direct_exec_test.go
// enforces that no exec.Command creeps back into this package.
//
// This file holds the three things the UI needs from that abstraction:
//
//   - bootstrap: registering the built-in host driver and wiring the
//     persistent project→executor binding lookup to statedb;
//   - startWorkload / runWorkload: the two call shapes the handlers use
//     (detached-with-streaming, and synchronous-collect-output);
//   - drainToStderr: the "echo the child's output to the server log"
//     behavior the pre-abstraction handlers got for free by assigning
//     cmd.Stdout = os.Stderr.

package ui

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var builtinExecutorsOnce sync.Once

// registerBuiltinExecutors registers the drivers that ship in-process. It is
// idempotent and is called from both Server construction and every workload
// entry point, so a Server built as a struct literal (as several tests do)
// still has a usable registry.
//
// The host driver is registered unconditionally so a fresh single-machine
// install works with no configuration. Deployments that must never execute
// on the control-plane host unbind it and pin every project to an isolated
// executor; Resolve then fails closed rather than falling back here.
func registerBuiltinExecutors() {
	builtinExecutorsOnce.Do(func() {
		if err := localprocess.Ensure(executor.DefaultRegistry); err != nil {
			fmt.Fprintf(os.Stderr, "ui: register local executor: %v\n", err)
		}
	})
}

// bootstrapExecutors registers the built-in drivers and points the registry
// at this control plane's persisted project→executor bindings.
func bootstrapExecutors(controlPlaneDir string) {
	registerBuiltinExecutors()
	executor.SetBindingLookup(func(projectPath string) (string, bool) {
		return lookupProjectExecutor(controlPlaneDir, projectPath)
	})
}

// lookupProjectExecutor reads the persisted project→executor binding from
// the control plane's state database.
//
// Bindings live in the control plane's own DB rather than each project's,
// because a project pinned to a remote executor may not have a readable
// local .cloop directory at all. A missing database, an unmigrated one, or
// any read error yields "no binding" — the registry then falls back to its
// default, which is the same behavior as before bindings existed.
func lookupProjectExecutor(controlPlaneDir, projectPath string) (string, bool) {
	if controlPlaneDir == "" || projectPath == "" {
		return "", false
	}
	dbPath := state.DBPath(controlPlaneDir)
	if _, err := os.Stat(dbPath); err != nil {
		return "", false
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return "", false
	}
	defer db.Close()

	id, ok, err := db.ProjectExecutor(projectPath)
	if err != nil || !ok {
		return "", false
	}
	return id, true
}

// uiSpec builds an executor.Spec for a cloop subcommand run in workDir.
// Labels carry provenance so an executor (especially a remote one) can
// attribute a workload back to the project and handler that requested it.
func uiSpec(workDir string, argv []string, labels map[string]string) executor.Spec {
	spec := executor.Spec{
		WorkDir: workDir,
		Argv:    argv,
		Labels:  map[string]string{"component": "web-ui"},
	}
	if workDir != "" {
		spec.Labels["project"] = workDir
	}
	for k, v := range labels {
		spec.Labels[k] = v
	}
	return spec
}

// startWorkload resolves the executor bound to workDir and starts argv on
// it, detached: the workload outlives the HTTP request that started it.
//
// It returns the executor alongside the handle because the caller needs the
// same instance to Stream and Status the handle — re-resolving later could
// pick a different executor if bindings changed mid-run.
func startWorkload(workDir string, argv []string, labels map[string]string) (executor.Executor, executor.Handle, error) {
	registerBuiltinExecutors()
	ex, err := executor.Resolve(workDir)
	if err != nil {
		return nil, executor.Handle{}, fmt.Errorf("no executor available for %s: %w", workDir, err)
	}
	handle, err := ex.Start(context.Background(), uiSpec(workDir, argv, labels))
	if err != nil {
		return nil, executor.Handle{}, err
	}
	return ex, handle, nil
}

// runWorkload resolves the executor bound to workDir and runs argv to
// completion, returning combined output. ctx bounds the workload: when it is
// cancelled or times out the workload is killed, matching the
// exec.CommandContext semantics the UI relied on before.
func runWorkload(ctx context.Context, workDir string, argv []string, labels map[string]string) ([]byte, error) {
	registerBuiltinExecutors()
	ex, err := executor.Resolve(workDir)
	if err != nil {
		return nil, fmt.Errorf("no executor available for %s: %w", workDir, err)
	}
	res, runErr := executor.Run(ctx, ex, uiSpec(workDir, argv, labels))
	return res.Output, runErr
}

// drainToStderr copies a workload's output stream to the UI server's stderr,
// reproducing what `cmd.Stdout = os.Stderr` did before. Runs until the
// workload finishes and the driver closes the channel.
func drainToStderr(lines <-chan executor.LogLine, prefix string) {
	defer recoverGoroutine("executor stderr drain: " + prefix)
	for line := range lines {
		if line.Text == "" {
			continue
		}
		_, _ = io.WriteString(os.Stderr, line.Text)
	}
}
