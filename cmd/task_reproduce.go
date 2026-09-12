package cmd

// task_reproduce.go is both halves of `cloop task reproduce`.
//
//	cloop task reproduce <id>       the operator's command, run on the hub
//	cloop task reproduce-exec       the in-sandbox half, run by the executor
//
// The second is hidden, the way `cloop workspace writeback` is hidden: it is
// not a thing a person runs, it is the command the driver puts in the sandbox's
// argv. Keeping it in this file rather than its own makes the two ends of the
// protocol — the flags one writes and the other parses, and the result marker
// one prints and the other reads — visible together, which is the only thing
// that keeps them in step.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/taskreplay"
	"github.com/blechschmidt/cloop/pkg/ui"
)

var (
	reproduceTimeout  string
	reproduceJSON     bool
	reproduceSkipTest bool
	reproduceNoSave   bool
	reproduceShowDiff bool

	reproExecPromptFile string
	reproExecProvider   string
	reproExecModel      string
	reproExecEffort     string
	reproExecTestCmd    string
	reproExecTestsOnly  bool
)

var taskReproduceCmd = &cobra.Command{
	Use:   "reproduce <task-id>",
	Short: "Re-run a task in a fresh sandbox and prove whether it produces the same commit",
	Long: `Re-execute a completed task in a fresh isolating sandbox and compare the
commit it returns against the one the original run returned.

Unlike 'cloop task replay', which re-sends a prompt to a different model and
scores the two transcripts for textual overlap, this re-executes the task and
compares the CODE. It reconstructs the original input state — the parent
commit, the plan, the rendered prompt, the provider/model/effort, and the
sandbox from .cloop/sandbox.yaml — provisions a clean checkout at that parent
commit on an isolating executor, and diffs the two resulting trees.

The verdict is one of:

  IDENTICAL     the reproduction produced the same tree hash
  EQUIVALENT    different bytes, but the project's own tests pass on both
  DIVERGENT     a different change; the diff-of-diffs is attached
  INCONCLUSIVE  no verdict could be reached (no test command, no recorded
                base commit, or the sandbox could not run)

A DIVERGENT verdict on a task that touched no external state is a precise
signal of nondeterminism worth investigating.

The reproduction is strictly non-destructive: it never writes back, never
touches this project's git refs or working tree, and runs on an isolating
executor — never on the host.

Examples:
  cloop task reproduce 42
  cloop task reproduce 42 --show-diff
  cloop task reproduce 42 --json
  cloop task reproduce 42 --skip-tests --timeout 20m`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		timeout := taskreplay.DefaultReproduceTimeout
		if strings.TrimSpace(reproduceTimeout) != "" {
			timeout, err = time.ParseDuration(reproduceTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout %q: %w", reproduceTimeout, err)
			}
		}

		emit := func(line string) { fmt.Fprint(os.Stderr, line) }
		if reproduceJSON {
			// Progress on stderr would still corrupt a caller that merges the
			// streams, and --json exists for callers that parse stdout.
			emit = func(string) {}
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), timeout+2*time.Minute)
		defer cancel()

		rep, err := taskreplay.Reproduce(ctx, workdir, taskID, taskreplay.ReproduceOptions{
			Runner:    ui.NewReproduceRunner(selfExePath()),
			Timeout:   timeout,
			SkipTests: reproduceSkipTest,
			Emit:      emit,
		})
		if err != nil {
			return err
		}
		if !reproduceNoSave {
			if saveErr := taskreplay.SaveReproduction(workdir, rep); saveErr != nil {
				// The verdict is the product; failing to file it must not
				// discard it. Say so and keep going.
				fmt.Fprintf(os.Stderr, "warning: the verdict could not be recorded: %v\n", saveErr)
			}
		}

		if reproduceJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rep)
		}
		printReproduction(rep, reproduceShowDiff)
		return nil
	},
}

// taskReproduceExecCmd is the in-sandbox half.
//
// It runs inside the reproduction's container, against a clean checkout at the
// recorded parent commit. It does two things and nothing else: put the
// reconstructed prompt through the same provider the original run used, then
// run the project's test command and report the outcome on stdout. The commit
// is not made here — the executor's write-back machinery does that after this
// process exits, against a tree nobody is writing to any more.
var taskReproduceExecCmd = &cobra.Command{
	Use:    "reproduce-exec",
	Short:  "Internal: execute one reproduction inside a sandbox",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		var testCmd []string
		if strings.TrimSpace(reproExecTestCmd) != "" {
			if err := json.Unmarshal([]byte(reproExecTestCmd), &testCmd); err != nil {
				return fmt.Errorf("invalid --test-command (expected a JSON array): %w", err)
			}
		}

		if !reproExecTestsOnly {
			if err := runReproducePrompt(cmd.Context(), workdir); err != nil {
				return err
			}
		}
		if len(testCmd) > 0 {
			reportTestOutcome(runProjectTests(cmd.Context(), workdir, testCmd))
		}
		return nil
	},
}

// runReproducePrompt puts the reconstructed prompt through the provider.
func runReproducePrompt(ctx context.Context, workdir string) error {
	if strings.TrimSpace(reproExecPromptFile) == "" {
		return fmt.Errorf("--prompt-file is required unless --tests-only is set")
	}
	prompt, err := os.ReadFile(reproExecPromptFile)
	if err != nil {
		return fmt.Errorf("read the reconstructed prompt: %w", err)
	}
	if len(prompt) == 0 {
		return fmt.Errorf("the reconstructed prompt at %s is empty", reproExecPromptFile)
	}

	cfg, _ := config.Load(workdir)
	name := strings.TrimSpace(reproExecProvider)
	if name == "" {
		name = cfg.Provider
	}
	if name == "" {
		name = autoSelectProvider()
	}
	prov, err := provider.Build(provider.ProviderConfig{
		Name:             name,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	})
	if err != nil {
		return fmt.Errorf("build provider %q: %w", name, err)
	}

	res, err := prov.Complete(ctx, string(prompt), provider.Options{
		Model:     reproExecModel,
		Effort:    reproExecEffort,
		WorkDir:   workdir,
		OnToken:   func(tok string) { fmt.Print(tok) },
		Timeout:   0,
		MaxTokens: 0,
	})
	if err != nil {
		return fmt.Errorf("the reproduction's provider call failed: %w", err)
	}
	if res != nil && res.Output != "" {
		fmt.Println()
	}
	return nil
}

// runProjectTests runs the project's own test command in the sandbox.
//
// A failing suite is an outcome, not an error: "the tests fail on this tree" is
// exactly what the caller asked to find out, and returning an error here would
// abort the reproduction before the outcome could be reported.
func runProjectTests(ctx context.Context, workdir string, argv []string) taskreplay.TestOutcome {
	out := taskreplay.TestOutcome{Command: argv}
	started := time.Now()

	c := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // the command comes from the hub's own detection
	c.Dir = workdir
	combined, err := c.CombinedOutput()
	out.Duration = time.Since(started)
	out.Output = tailBytes(combined, maxTestOutputBytes)

	if c.ProcessState == nil && err != nil {
		// Never started: a missing toolchain in the image, most often. Not a
		// failing suite, and the verdict logic distinguishes the two.
		out.Ran = false
		out.Output = strings.TrimSpace(out.Output + "\n" + err.Error())
		return out
	}
	out.Ran = true
	out.ExitCode = c.ProcessState.ExitCode()
	out.Passed = out.ExitCode == 0
	return out
}

// maxTestOutputBytes bounds the suite output carried home in the marker line.
const maxTestOutputBytes = 16 << 10

// reportTestOutcome prints the marker line pkg/ui's runner parses.
func reportTestOutcome(out taskreplay.TestOutcome) {
	data, err := json.Marshal(out)
	if err != nil {
		return
	}
	// Leading newline: the suite's own output rarely ends in one, and a marker
	// appended to a partial line is a marker the parser will not find.
	fmt.Printf("\n%s%s\n", ui.ReproduceResultMarker, data)
}

// tailBytes returns at most n bytes from the end of b.
func tailBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return "[…truncated…]\n" + string(b[len(b)-n:])
}

// printReproduction renders a verdict for a terminal.
func printReproduction(rep *taskreplay.Reproduction, showDiff bool) {
	if rep == nil {
		return
	}
	bold := color.New(color.Bold).SprintFunc()

	var tint func(a ...interface{}) string
	switch rep.Verdict {
	case taskreplay.VerdictIdentical:
		tint = color.New(color.FgGreen, color.Bold).SprintFunc()
	case taskreplay.VerdictEquivalent:
		tint = color.New(color.FgCyan, color.Bold).SprintFunc()
	case taskreplay.VerdictDivergent:
		tint = color.New(color.FgRed, color.Bold).SprintFunc()
	default:
		tint = color.New(color.FgYellow, color.Bold).SprintFunc()
	}

	fmt.Printf("\n%s  task %d — %s\n", tint(strings.ToUpper(string(rep.Verdict))), rep.TaskID, rep.TaskTitle)
	fmt.Printf("  %s\n\n", rep.Reason)

	if c := rep.Comparison; c != nil {
		fmt.Printf("  %s %s\n", bold("base:    "), c.BaseSHA)
		fmt.Printf("  %s %s → tree %s\n", bold("original:"), c.OriginalCommit, c.OriginalTree)
		fmt.Printf("  %s %s → tree %s\n", bold("replay:  "), c.ReplayCommit, c.ReplayTree)
	}
	if rep.ExecutorID != "" {
		fmt.Printf("  %s %s (%s, isolation=%s)\n", bold("executor:"), rep.ExecutorID, rep.ExecutorKind, rep.Isolation)
	}
	printTestLine(bold("original tests:"), rep.OriginalTest)
	printTestLine(bold("replay tests:  "), rep.ReplayTest)

	if rep.Provenance != nil {
		for _, w := range rep.Provenance.Warnings {
			fmt.Printf("  %s %s\n", color.YellowString("warning:"), w)
		}
		if rep.Provenance.Sandbox.PinnedImage != "" && !rep.Provenance.PinnedImage() {
			fmt.Printf("  %s the original ran from the floating tag %s, so a difference may be the image moving rather than the agent\n",
				color.YellowString("warning:"), rep.Provenance.Sandbox.PinnedImage)
		}
	}
	if rep.Err != "" {
		fmt.Printf("  %s %s\n", color.RedString("error:"), rep.Err)
	}

	if c := rep.Comparison; c != nil && c.DiffStat != "" {
		fmt.Printf("\n%s\n%s\n", bold("diff-of-diffs:"), c.DiffStat)
		if showDiff && c.DiffOfDiffs != "" {
			fmt.Println(c.DiffOfDiffs)
			if c.DiffTruncated {
				fmt.Println("[…diff truncated…]")
			}
		} else if c.DiffOfDiffs != "" {
			fmt.Println("  (re-run with --show-diff for the full patch)")
		}
	}
	fmt.Printf("\n  took %s\n\n", rep.Duration.Round(time.Second))
}

func printTestLine(label string, t *taskreplay.TestOutcome) {
	if t == nil {
		return
	}
	status := color.GreenString("pass")
	switch {
	case !t.Ran:
		status = color.YellowString("did not run")
	case !t.Passed:
		status = color.RedString(fmt.Sprintf("fail (exit %d)", t.ExitCode))
	}
	fmt.Printf("  %s %s — %s\n", label, status, t.Framework)
}

// selfExePath is the cloop binary to run inside the sandbox.
//
// The sandbox image carries its own cloop; what matters is the name, not this
// host's path, so a resolution failure falls back to the bare command rather
// than failing the reproduction.
func selfExePath() string {
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		return exe
	}
	return "cloop"
}

func init() {
	taskReproduceCmd.Flags().StringVar(&reproduceTimeout, "timeout", "",
		"Bound the whole reproduction (e.g. 20m, 1h; default 45m)")
	taskReproduceCmd.Flags().BoolVar(&reproduceJSON, "json", false, "Emit the verdict as JSON")
	taskReproduceCmd.Flags().BoolVar(&reproduceSkipTest, "skip-tests", false,
		"Skip the behavioural gate; a non-identical result can then only be INCONCLUSIVE")
	taskReproduceCmd.Flags().BoolVar(&reproduceNoSave, "no-save", false,
		"Do not record the verdict in the project's database")
	taskReproduceCmd.Flags().BoolVar(&reproduceShowDiff, "show-diff", false,
		"Print the full diff-of-diffs, not just its summary")

	taskReproduceExecCmd.Flags().StringVar(&reproExecPromptFile, "prompt-file", "",
		"File holding the reconstructed prompt")
	taskReproduceExecCmd.Flags().StringVar(&reproExecProvider, "provider", "", "Provider the original run used")
	taskReproduceExecCmd.Flags().StringVar(&reproExecModel, "model", "", "Model the original run used")
	taskReproduceExecCmd.Flags().StringVar(&reproExecEffort, "effort", "", "Reasoning effort the original run used")
	taskReproduceExecCmd.Flags().StringVar(&reproExecTestCmd, "test-command", "",
		"Project test command as a JSON array")
	taskReproduceExecCmd.Flags().BoolVar(&reproExecTestsOnly, "tests-only", false,
		"Run only the test command; do not re-execute the agent")

	taskCmd.AddCommand(taskReproduceCmd)
	taskCmd.AddCommand(taskReproduceExecCmd)
}
