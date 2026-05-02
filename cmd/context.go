package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/ctxedit"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var contextCmd = &cobra.Command{
	Use:   "context",
	Short: "Inspect and edit the AI context window before a task runs",
	Long: `Inspect, edit, or clear the context (prompt) that will be sent to the AI
before a task executes. This lets power users trim or augment the context
with surgical precision.

Subcommands:
  show [task-id]         Print the full context with per-section token counts
  edit [task-id]         Open context in $EDITOR; save as an override file
  clear [task-id|--all]  Remove context override file(s)

Examples:
  cloop context show 3
  cloop context edit 3
  cloop context clear 3
  cloop context clear --all`,
}

// contextShowCmd ---------------------------------------------------------------

var contextShowCmd = &cobra.Command{
	Use:   "show [task-id]",
	Short: "Print the full context with section headers and token counts",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm --plan-only' to create one")
		}

		task, err := resolveTask(s, args)
		if err != nil {
			return err
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("\ncloop context show — task %d: %s\n\n", task.ID, task.Title)

		// Check for existing override
		override, overrideErr := ctxedit.LoadOverride(workdir, task.ID)
		if overrideErr != nil {
			dimColor.Printf("Warning: %v\n", overrideErr)
		}
		if override != "" {
			warnColor.Printf("NOTE: A context override is active for this task.\n")
			warnColor.Printf("      The override (not the auto-built context) will be sent to the AI.\n")
			warnColor.Printf("      Run 'cloop context clear %d' to remove it.\n\n", task.ID)
		}

		// Build context
		prompt := ctxedit.Build(s.Plan, task, workdir, false, 0)
		annotated, sections := ctxedit.Annotate(prompt)

		// Print section summary
		dimColor.Printf("Sections:\n")
		totalToks := 0
		for _, sec := range sections {
			totalToks += sec.Tokens
			dimColor.Printf("  %-40s  ~%d tokens\n", sec.Header, sec.Tokens)
		}
		dimColor.Printf("  %-40s  ~%d tokens total\n\n", "──────────────────────────────────────", totalToks)

		sep := strings.Repeat("─", 70)
		fmt.Println(sep)
		fmt.Println(annotated)
		fmt.Println(sep)

		if override != "" {
			fmt.Println()
			warnColor.Printf("ACTIVE OVERRIDE for task %d:\n", task.ID)
			fmt.Println(strings.Repeat("─", 70))
			fmt.Println(override)
			fmt.Println(strings.Repeat("─", 70))
		}

		return nil
	},
}

// contextEditCmd ---------------------------------------------------------------

var contextEditCmd = &cobra.Command{
	Use:   "edit [task-id]",
	Short: "Open context in $EDITOR; save as an override file for the AI",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm --plan-only' to create one")
		}

		task, err := resolveTask(s, args)
		if err != nil {
			return err
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		successColor := color.New(color.FgGreen, color.Bold)

		headerColor.Printf("\ncloop context edit — task %d: %s\n\n", task.ID, task.Title)

		// Determine starting content: existing override or freshly built prompt.
		existing, _ := ctxedit.LoadOverride(workdir, task.ID)
		var startContent string
		if existing != "" {
			dimColor.Printf("Loading existing override for editing...\n")
			startContent = existing
		} else {
			dimColor.Printf("Building auto-generated context...\n")
			startContent = ctxedit.Build(s.Plan, task, workdir, false, 0)
		}

		// Write to temp file.
		tmpFile, err := os.CreateTemp("", fmt.Sprintf("cloop-ctx-%d-*.txt", task.ID))
		if err != nil {
			return fmt.Errorf("creating temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		defer os.Remove(tmpPath)

		if _, err := tmpFile.WriteString(startContent); err != nil {
			tmpFile.Close()
			return fmt.Errorf("writing temp file: %w", err)
		}
		tmpFile.Close()

		// Open editor.
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "nano"
		}
		editorCmd := exec.Command(editor, tmpPath)
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = os.Stdout
		editorCmd.Stderr = os.Stderr
		if err := editorCmd.Run(); err != nil {
			return fmt.Errorf("editor exited with error: %w", err)
		}

		// Read back edited content.
		edited, err := os.ReadFile(tmpPath)
		if err != nil {
			return fmt.Errorf("reading edited file: %w", err)
		}
		editedStr := string(edited)

		if strings.TrimSpace(editedStr) == "" {
			dimColor.Printf("Empty content — override not saved.\n")
			return nil
		}

		// If unchanged, skip save.
		if editedStr == startContent {
			dimColor.Printf("No changes detected — override not saved.\n")
			return nil
		}

		if err := ctxedit.SaveOverride(workdir, task.ID, editedStr); err != nil {
			return fmt.Errorf("saving override: %w", err)
		}

		overridePath := ctxedit.OverridePath(workdir, task.ID)
		successColor.Printf("Override saved: %s\n", overridePath)
		dimColor.Printf("The orchestrator will use this context instead of the auto-built one.\n")
		dimColor.Printf("Run 'cloop context clear %d' to remove the override.\n", task.ID)
		return nil
	},
}

// contextClearCmd --------------------------------------------------------------

var contextClearAll bool

var contextClearCmd = &cobra.Command{
	Use:   "clear [task-id]",
	Short: "Remove context override file(s)",
	Long: `Remove a context override for a specific task, or remove all overrides.

Examples:
  cloop context clear 3       # remove override for task 3
  cloop context clear --all   # remove all overrides`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		successColor := color.New(color.FgGreen, color.Bold)
		dimColor := color.New(color.Faint)

		if contextClearAll {
			n, err := ctxedit.ClearAllOverrides(workdir)
			if err != nil {
				return fmt.Errorf("clearing overrides: %w", err)
			}
			if n == 0 {
				dimColor.Printf("No context overrides found.\n")
			} else {
				successColor.Printf("Cleared %d context override(s).\n", n)
			}
			return nil
		}

		if len(args) == 0 {
			return fmt.Errorf("provide a task-id or use --all")
		}
		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task-id %q: must be an integer", args[0])
		}
		if err := ctxedit.ClearOverride(workdir, taskID); err != nil {
			return fmt.Errorf("clearing override for task %d: %w", taskID, err)
		}
		successColor.Printf("Context override for task %d cleared.\n", taskID)
		return nil
	},
}

// resolveTask picks the task from state. If args has one element it is parsed as
// a task ID. Otherwise the next pending task (or first task) is used.
func resolveTask(s *state.ProjectState, args []string) (*pm.Task, error) {
	if len(args) > 0 {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return nil, fmt.Errorf("invalid task-id %q: must be an integer", args[0])
		}
		for _, t := range s.Plan.Tasks {
			if t.ID == id {
				return t, nil
			}
		}
		return nil, fmt.Errorf("task %d not found in plan", id)
	}
	// Default: next pending task, or first task.
	next := s.Plan.NextTask()
	if next != nil {
		return next, nil
	}
	if len(s.Plan.Tasks) > 0 {
		return s.Plan.Tasks[0], nil
	}
	return nil, fmt.Errorf("no tasks in plan")
}

func init() {
	contextClearCmd.Flags().BoolVar(&contextClearAll, "all", false, "Clear all context overrides")

	contextCmd.AddCommand(contextShowCmd)
	contextCmd.AddCommand(contextEditCmd)
	contextCmd.AddCommand(contextClearCmd)
	rootCmd.AddCommand(contextCmd)
}
