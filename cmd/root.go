package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/janitor"
	"github.com/blechschmidt/cloop/pkg/migrate"
	"github.com/blechschmidt/cloop/pkg/workspace"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// globalLogJSON is the global --log-json flag value for structured NDJSON output.
var globalLogJSON bool

// globalWorkspace is the --workspace flag value. When set, all commands operate
// in the named workspace's directory instead of the current working directory.
var globalWorkspace string

var rootCmd = &cobra.Command{
	Use:   "cloop",
	Short: "AI product manager and autonomous task pipeline",
	Long: `cloop is a multi-provider AI product manager.

Define a project goal and cloop decomposes it into a visible task plan, then
drives an AI provider through that plan autonomously. Supports Anthropic
(Claude API), OpenAI, Ollama (local), and Claude Code.

Commands are grouped below. Every group has more in it than the examples show —
` + docsURL + ` is the full reference.`,
	Example: `  cloop init "Build a REST API with user auth and CRUD endpoints"
  cloop run --auto-evolve   # keep discovering work after the plan drains
  cloop status              # where the plan stands
  cloop task list           # the tasks themselves
  cloop ui                  # web dashboard on localhost:8080
  cloop doctor              # check the environment before you start`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCodeFor(err))
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&globalLogJSON, "log-json", false, "Emit structured NDJSON log lines for key events (task_start, task_done, step, etc.) instead of colored text. Enables piping to Datadog, Splunk, or jq.")
	rootCmd.PersistentFlags().StringVar(&globalWorkspace, "workspace", "", "Named workspace to operate in (overrides cwd for all commands)")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Silence usage output for any error returned from RunE. Cobra's default
		// behavior is to dump the full --help text whenever RunE returns a non-nil
		// error, which is noisy and misleading for runtime errors (network
		// failures, missing files, AI provider errors). PersistentPreRunE runs
		// only after flag parsing and Args validation have succeeded, so
		// genuine CLI misuse (unknown flag, wrong arg count) still produces
		// usage output — only post-validation runtime errors are silenced.
		cmd.SilenceUsage = true

		if globalWorkspace != "" {
			// Resolve the workspace path and chdir so all commands transparently
			// use the workspace directory when calling os.Getwd().
			workDir, err := workspace.ResolveWorkDir(globalWorkspace)
			if err != nil {
				return fmt.Errorf("--workspace: %w", err)
			}
			if err := os.Chdir(workDir); err != nil {
				return err
			}
		}

		// Register the execution backends this project configures. Done here
		// rather than in an init() because it needs the project config, and
		// therefore the final working directory — which --workspace may have
		// just changed. The host driver is registered by executors.go's
		// init(); this adds the isolated backends the operator opted into.
		if cwd, err := os.Getwd(); err == nil {
			if cfg, cfgErr := config.Load(cwd); cfgErr == nil {
				// Bound plan-history at write time (Task 20229). Applied for
				// every command, not just the server, because the writer that
				// grew .cloop/plan-history to 2 GB is the orchestrator — which
				// the hub runs as a subprocess, so it inherits none of the
				// hub's in-process settings and has to read the policy itself.
				janitor.ApplySnapshotRetention(cfg)

				// Strict no-host-execution mode (Task 20160), applied BEFORE
				// reconciling. Two reasons, and the first is a correctness
				// bug fixed in Task 20170: reconcile.FromConfig records
				// StrictMode from this switch, so reconciling first stamped
				// every CLI report strict_mode:false and suppressed the
				// "no isolating executor is registered" warning in exactly
				// the deployments that needed it. Second, it matches the
				// order pkg/ui and pkg/apiserver use — one bootstrap order,
				// not three. Registering isolated drivers afterwards is
				// safe: strict mode refuses only non-isolating ones. The
				// policy is a ratchet — see executor.ApplyHostExecutionPolicy.
				executor.ApplyHostExecutionPolicy(cfg.Executors.HostProcessAllowed())
				// Same ratchet, same reason: a tenant's config.yaml must not be
				// able to lower the fleet's minimum agent build.
				executor.ApplyMinAgentBuild(cfg.Executors.MinAgentBuild)

				// Commands that construct a control plane reconcile from
				// their OWN workdir a moment later, and skipping the pass
				// here is what lets that one win. Reconciliation reuses an
				// executor already registered under the same ID, so a pass
				// against cwd would otherwise claim the ID and leave the
				// server's — including the state database its Kubernetes
				// credentials are brokered from — permanently unused. It
				// also saves a redundant SQLite open and key derivation on
				// every server start.
				if !hostsControlPlane(cmd.Name()) {
					reconcileExecutors(cwd, cfg, wantsPodReconcile(cmd.Name()))
				}
			}
		}

		// Warn if the .cloop schema is behind the current version, unless the
		// user is already running 'cloop migrate' (which would be redundant).
		// Only emit the warning when stderr is an interactive terminal — otherwise
		// it pollutes machine-readable output captured by tests/pipes/CI.
		if cmd.Name() != "migrate" && isatty.IsTerminal(os.Stderr.Fd()) {
			cwd, _ := os.Getwd()
			if migrate.NeedsUpgrade(cwd) {
				color.New(color.FgYellow).Fprintln(os.Stderr,
					"warning: .cloop schema is out of date — run 'cloop migrate' to upgrade")
			}
		}
		return nil
	}
}
