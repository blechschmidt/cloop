package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/reviewgate"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	gateEnable       bool
	gateDisable      bool
	gateProvider     string
	gateModel        string
	gateEffort       string
	gateMode         string
	gateMaxFixRounds int
	gateInstructions string
	gateJSON         bool
)

// reviewGateCmd configures the review gate (Task 20357).
var reviewGateCmd = &cobra.Command{
	Use:   "gate",
	Short: "Show or configure the review gate: a reviewer model that checks each task's changes before they are pushed or merged",
	Long: `The review gate is an optional reviewer — its own provider and model, not
necessarily the ones doing the work — that checks every task's changes before
anything leaves the working copy.

While a task runs, the agent's git pushes are held: they are reported to the
agent as "held by cloop's review gate" and recorded instead of sent. When the
agent reports the task done, the reviewer reads the task's diff (across the
project's repository and any repository the task cloned inside it). If it
approves, cloop sends the held pushes itself — at the reviewed commits, and
never with a commit the reviewer did not see — and lets git-mode and parallel
worktree merges proceed. If it does not:

  fix       send the findings back to the agent, review again, and block
            if it is still not approved after --max-fix-rounds (default)
  block     fail the task at once; nothing is pushed or merged
  advisory  record the review and publish anyway

A reviewer that cannot be reached, or answers without a verdict, blocks the
task in fix and block mode: the gate fails closed.

With no flags, the current settings are shown.

Examples:
  cloop review gate --enable --provider anthropic --model claude-opus-5-5
  cloop review gate --enable --model claude-opus-5-5 --effort high   # the project's own provider
  cloop review gate --mode block --instructions "Reject any change to migrations/."
  cloop review gate --disable`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if gateEnable && gateDisable {
			return fmt.Errorf("--enable and --disable are mutually exclusive")
		}
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		g := s.ReviewGate.Clone()
		if g == nil {
			g = &pm.ReviewGate{}
		}
		changed := false
		set := func(flag string, apply func()) {
			if cmd.Flags().Changed(flag) {
				apply()
				changed = true
			}
		}
		set("enable", func() { g.Enabled = true })
		set("disable", func() { g.Enabled = false })
		set("provider", func() { g.Provider = gateProvider })
		set("model", func() { g.Model = gateModel })
		set("effort", func() { g.Effort = gateEffort })
		set("mode", func() { g.Mode = gateMode })
		set("max-fix-rounds", func() { g.MaxFixRounds = gateMaxFixRounds })
		set("instructions", func() { g.Instructions = gateInstructions })
		if changed {
			g.Normalize()
			if err := g.Validate(); err != nil {
				return err
			}
			if err := state.SetReviewGate(workdir, g); err != nil {
				return err
			}
		}
		if gateJSON {
			return clijson.Emit(cmd.OutOrStdout(), g)
		}
		if changed {
			color.New(color.FgGreen).Println("Review gate updated.")
		}
		printReviewGate(g, s.Provider, s.Model)
		return nil
	},
}

// printReviewGate renders the settings for people.
func printReviewGate(g *pm.ReviewGate, projectProvider, projectModel string) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	if !g.Active() {
		bold.Print("Review gate: ")
		fmt.Println("off")
		if g.Provider == "" && g.Model == "" && g.Instructions == "" {
			dim.Println("  Turn it on with: cloop review gate --enable [--provider P] [--model M]")
			return
		}
	} else {
		bold.Print("Review gate: ")
		color.New(color.FgGreen).Println("on")
	}
	prov, model := g.Provider, g.Model
	if prov == "" {
		prov = "the project's provider"
		if projectProvider != "" {
			prov += " (" + projectProvider + ")"
		}
		if model == "" {
			model = "the project's model"
			if projectModel != "" {
				model += " (" + projectModel + ")"
			}
		}
	}
	if model == "" {
		model = "that provider's default model"
	}
	fmt.Printf("  Reviewer:   %s / %s", prov, model)
	if g.Effort != "" {
		fmt.Printf(" (effort %s)", g.Effort)
	}
	fmt.Println()
	switch g.EffectiveMode() {
	case pm.ReviewModeFix:
		fmt.Printf("  On reject:  fix — send the findings back to the agent, up to %d round(s), then block\n", g.EffectiveFixRounds())
	case pm.ReviewModeBlock:
		fmt.Println("  On reject:  block — fail the task; nothing is pushed or merged")
	case pm.ReviewModeAdvisory:
		fmt.Println("  On reject:  advisory — record the review and publish anyway")
	}
	if g.Instructions != "" {
		fmt.Printf("  Criteria:   %s\n", strings.ReplaceAll(g.Instructions, "\n", "\n              "))
	}
}

// reviewGateHelperCmd is the git remote helper that holds an agent's pushes
// while the review gate runs (Task 20357). git runs it — through the
// git-remote-cloopgate script the gate puts on the agent's PATH — as
// `git-remote-cloopgate <remote> <url>`, speaking the remote-helper protocol
// on stdin and stdout. It records each ref update and refuses it; nothing
// here can reach a remote.
var reviewGateHelperCmd = &cobra.Command{
	Use:    reviewgate.HelperSubcommand + " <remote> [<url>]",
	Short:  "Internal: the git remote helper that holds pushes for the review gate",
	Hidden: true,
	Args:   cobra.RangeArgs(1, 2),
	// git passes a URL and a remote name verbatim; none of it is a flag.
	DisableFlagParsing: true,
	// Replaces the root's hook, which loads the project configuration and
	// registers executors: this runs inside a `git push`, in a repository
	// that need not be a cloop project, and uses none of that.
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		return reviewgate.ServeRemoteHelper(ctx, args, os.Getenv(reviewgate.HoldFileEnv), os.Stdin, os.Stdout)
	},
}

func init() {
	f := reviewGateCmd.Flags()
	f.BoolVar(&gateEnable, "enable", false, "Turn the review gate on")
	f.BoolVar(&gateDisable, "disable", false, "Turn the review gate off (its settings are kept)")
	f.StringVar(&gateProvider, "provider", "", "Reviewer provider: claudecode, anthropic, openai, ollama (empty = the project's)")
	f.StringVar(&gateModel, "model", "", "Reviewer model (empty = the project's model on its own provider, else that provider's default)")
	f.StringVar(&gateEffort, "effort", "", "Reviewer reasoning effort: low, medium, high, xhigh, max (claudecode only)")
	f.StringVar(&gateMode, "mode", "", "What a rejection does: fix (default), block, advisory")
	f.IntVar(&gateMaxFixRounds, "max-fix-rounds", 0, fmt.Sprintf("How often fix mode sends a task back (0 = %d, at most %d)", pm.DefaultReviewFixRounds, pm.MaxReviewFixRounds))
	f.StringVar(&gateInstructions, "instructions", "", "Extra review criteria sent with every review")
	f.BoolVar(&gateJSON, "json", false, "Print the settings as JSON")
	reviewCmd.AddCommand(reviewGateCmd)
	rootCmd.AddCommand(reviewGateHelperCmd)
}
