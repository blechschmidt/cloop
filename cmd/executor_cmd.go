package cmd

// executor_cmd.go is the operator's view of the execution backends: which
// ones exist, whether they actually work, and what to fix when they do not.
//
// `cloop executor test` is the important one. Configuring a container
// executor touches a container runtime, an image, a bind mount, a UID
// mapping, cgroup delegation and (on some hosts) SELinux — and when any of
// them is wrong the symptom is identical: a run that produces no output and
// dies instantly. The test command turns that into a checklist plus a real
// workload, so the operator learns which layer is broken before wiring a
// project to it.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
)

var executorCmd = &cobra.Command{
	Use:   "executor",
	Short: "Inspect and test the execution backends that run cloop workloads",
	Long: `Execution backends ("executors") decide where a cloop workload actually
runs: as a child process on this host, in a container sandbox, or on a
remote agent.

Projects are pinned to an executor; a project bound to an executor that is
not available fails rather than silently falling back to host execution.`,
}

var executorListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the registered execution backends and what they isolate",
	RunE: func(cmd *cobra.Command, args []string) error {
		header := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)

		executors := executor.List()
		if len(executors) == 0 {
			fmt.Println("No executors are registered.")
			return nil
		}

		defaultID := executor.DefaultRegistry.DefaultID()
		header.Printf("%-20s %-14s %-12s %-8s %s\n", "ID", "KIND", "ISOLATION", "EGRESS", "NOTES")
		for _, ex := range executors {
			caps := ex.Capabilities()
			egress := "no"
			if caps.NetworkEgress {
				egress = "yes"
			}
			notes := make([]string, 0, 3)
			if ex.ID() == defaultID {
				notes = append(notes, "default")
			}
			if c, ok := ex.(*container.Executor); ok {
				notes = append(notes, c.Runtime().String(), c.Image())
			}
			if caps.Isolation == executor.IsolationNone {
				notes = append(notes, "no isolation")
			}
			fmt.Printf("%-20s %-14s %-12s %-8s %s\n",
				ex.ID(), ex.Kind(), caps.Isolation, egress, strings.Join(notes, ", "))
		}
		dim.Println("\nBind a project with `cloop executor bind` (see the Executors panel in the Web UI).")
		return nil
	},
}

var executorTestCmd = &cobra.Command{
	Use:   "test <executor-id>",
	Short: "Preflight an executor and run `cloop version` inside it",
	Long: `Verify that an executor can actually run a workload.

Two phases:

  1. Preflight — checks the environment the executor depends on (runtime
     binary, daemon reachability, image presence, workspace permissions,
     SELinux labelling, network posture) and prints each finding with the
     command that fixes it.

  2. Smoke test — runs ` + "`cloop version`" + ` inside the sandbox and prints what
     it returned. For the container executor, the control plane's own binary
     is bind-mounted read-only into the sandbox, so the test is meaningful
     even against an image that does not yet ship cloop.

Exit codes:
  0  the executor ran the workload successfully
  1  the smoke test failed
  2  preflight found a fatal problem, so the smoke test was not attempted`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		workdir, _ := cmd.Flags().GetString("workdir")
		skipPreflight, _ := cmd.Flags().GetBool("skip-preflight")

		header := color.New(color.FgCyan, color.Bold)
		pass := color.New(color.FgGreen, color.Bold)
		warn := color.New(color.FgYellow, color.Bold)
		fail := color.New(color.FgRed, color.Bold)
		dim := color.New(color.Faint)

		ex, err := executor.Get(id)
		if err != nil {
			fail.Printf("No executor %q is registered.\n\n", id)
			dim.Println("Registered executors:")
			for _, e := range executor.List() {
				dim.Printf("  %s (%s)\n", e.ID(), e.Kind())
			}
			dim.Println("\nA container executor is registered only when executors.container.enabled")
			dim.Println("is true in .cloop/config.yaml. See `cloop config set executors.container.enabled true`.")
			return err
		}

		header.Printf("cloop executor test — %s (%s)\n\n", ex.ID(), ex.Kind())

		ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
		defer cancel()

		// --- phase 1: preflight ---------------------------------------
		cex, isContainer := ex.(*container.Executor)
		if isContainer && !skipPreflight {
			report := cex.Preflight(ctx, workdir)
			header.Println("Preflight")
			for _, f := range report.Findings {
				switch f.Level {
				case container.LevelOK:
					pass.Printf("  ok   ")
				case container.LevelWarn:
					warn.Printf("  warn ")
				default:
					fail.Printf("  FAIL ")
				}
				fmt.Printf("%-12s %s\n", f.Name, f.Message)
				if f.Fix != "" {
					dim.Printf("       %-12s fix: %s\n", "", f.Fix)
				}
			}
			fmt.Println()
			if !report.OK() {
				fail.Println("Preflight failed; not attempting to run a workload.")
				dim.Println("Re-run with --skip-preflight to try anyway.")
				return errExit{code: 2, err: report.Err()}
			}
		} else if !isContainer {
			dim.Printf("Preflight is container-specific; running the smoke test directly.\n\n")
		}

		// --- phase 2: smoke test --------------------------------------
		header.Println("Smoke test")
		started := time.Now()

		if isContainer {
			result, err := cex.SmokeTest(ctx, workdir)
			printSmokeOutput(result.Output)
			if err != nil {
				fail.Printf("\nFAILED after %s\n", result.Duration.Round(time.Millisecond))
				return err
			}
			pass.Printf("\nOK — the sandbox ran the workload in %s\n", result.Duration.Round(time.Millisecond))
			dim.Printf("  image:     %s\n", result.Image)
			dim.Printf("  runtime:   %s\n", result.Runtime)
			dim.Printf("  container: %s\n", result.ContainerName)
			if result.MountedBinary != "" {
				dim.Printf("  binary:    %s (bind-mounted read-only at %s)\n",
					result.MountedBinary, container.ContainerCloopPath)
			}
			return nil
		}

		// Generic path for non-container drivers: run the same workload
		// through the shared interface.
		self, err := os.Executable()
		if err != nil {
			self = "cloop"
		}
		if workdir == "" {
			workdir, _ = os.Getwd()
		}
		res, runErr := executor.Run(ctx, ex, executor.Spec{
			WorkDir: workdir,
			Argv:    []string{self, "version"},
			Labels:  map[string]string{"component": "smoke-test"},
		})
		printSmokeOutput(strings.TrimSpace(string(res.Output)))
		if runErr != nil {
			fail.Printf("\nFAILED after %s\n", time.Since(started).Round(time.Millisecond))
			return runErr
		}
		pass.Printf("\nOK — the executor ran the workload in %s\n", time.Since(started).Round(time.Millisecond))
		return nil
	},
}

var executorReapCmd = &cobra.Command{
	Use:   "reap <executor-id>",
	Short: "Remove exited sandbox containers left behind by earlier runs",
	Long: `Remove containers this control plane created but no longer tracks — the
residue of a control plane that was killed mid-run.

Running containers are never touched: they may belong to another live control
plane sharing the same runtime.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ex, err := executor.Get(args[0])
		if err != nil {
			return err
		}
		cex, ok := ex.(*container.Executor)
		if !ok {
			return fmt.Errorf("executor %q is a %s executor; reaping applies to container executors",
				ex.ID(), ex.Kind())
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
		defer cancel()

		removed, err := cex.ReapOrphans(ctx)
		if err != nil {
			return err
		}
		if len(removed) == 0 {
			fmt.Println("No orphaned containers found.")
			return nil
		}
		for _, name := range removed {
			fmt.Printf("removed %s\n", name)
		}
		color.New(color.FgGreen).Printf("\nReaped %d orphaned container(s).\n", len(removed))
		return nil
	},
}

// printSmokeOutput renders the workload's output indented, so it is visually
// distinct from cloop's own reporting.
func printSmokeOutput(out string) {
	dim := color.New(color.Faint)
	if strings.TrimSpace(out) == "" {
		dim.Println("  (no output)")
		return
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		dim.Printf("  | %s\n", line)
	}
}

// errExit carries a specific process exit code.
type errExit struct {
	code int
	err  error
}

func (e errExit) Error() string { return e.err.Error() }
func (e errExit) Unwrap() error { return e.err }

// exitCodeFor maps an error returned by any command onto a process exit
// code, so `cloop executor test` can distinguish "preflight found a problem"
// (2) from "the workload failed" (1). Everything else keeps the historical
// exit code of 1.
func exitCodeFor(err error) int {
	if err == nil {
		return 0
	}
	var ee errExit
	if errors.As(err, &ee) {
		return ee.code
	}
	return 1
}

// registerContainerExecutor builds and registers the container executor from
// the project config, when enabled.
//
// A configured-but-unbuildable executor is a warning rather than a fatal
// error: cloop has many subcommands that never execute a workload, and
// failing every one of them because a container runtime is missing would be
// disproportionate. The failure surfaces where it matters — `cloop executor
// test` reports it, and executor.Resolve fails closed for any project bound
// to the missing ID rather than downgrading it to host execution.
func registerContainerExecutor(cfg *config.Config) {
	if cfg == nil || !cfg.Executors.Container.Enabled {
		return
	}
	opts, err := cfg.Executors.Container.DriverOptions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: executors.container is enabled but invalid: %v\n", err)
		return
	}
	if _, err := container.Ensure(executor.DefaultRegistry, opts); err != nil {
		fmt.Fprintf(os.Stderr, "warning: container executor %q could not be registered: %v\n", opts.ID, err)
		fmt.Fprintf(os.Stderr, "         projects bound to it will fail rather than run on this host.\n")
	}
}

func init() {
	executorTestCmd.Flags().String("workdir", "",
		"project directory to bind-mount and preflight (default: a temporary directory)")
	executorTestCmd.Flags().Bool("skip-preflight", false,
		"run the workload even if preflight reports a fatal problem")

	executorCmd.AddCommand(executorListCmd)
	executorCmd.AddCommand(executorTestCmd)
	executorCmd.AddCommand(executorReapCmd)
	rootCmd.AddCommand(executorCmd)
}
