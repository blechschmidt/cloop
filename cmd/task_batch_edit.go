package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/batchedit"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var taskBatchEditCmd = &cobra.Command{
	Use:   "batch-edit",
	Short: "Visual TUI for bulk-editing multiple tasks at once",
	Long: `Open a full-screen TUI editor for batch-editing tasks.

Left panel   — scrollable task list with multi-select:
  ↑/↓ or j/k  navigate
  Space        toggle task selection
  a            select / deselect all
  Enter / Tab  move to edit form

Right panel  — edit form (fields applied to ALL selected tasks):
  Priority     1–100  (lower = higher priority)
  Tags         comma-separated list to merge into existing tags
  Assignee     team member name
  Deadline     relative (2d, 1w), date (2026-01-01), or "none" to clear
  Status       pending / in_progress / done / failed / skipped

  ↑/↓ or Tab / Shift-Tab   cycle fields
  Type                      edit the active field
  Enter                     apply changes to all selected tasks and exit
  Esc / q                   exit without saving

On exit a summary table of all changes is printed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		result, err := batchedit.Run(s.Plan.Tasks)
		if err != nil {
			return fmt.Errorf("batch-edit: %w", err)
		}

		if !result.Saved || len(result.Changes) == 0 {
			color.New(color.Faint).Println("No changes saved.")
			return nil
		}

		// Persist the mutated tasks (they were mutated in-place by the TUI).
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		// Print summary table.
		green := color.New(color.FgGreen)
		dim := color.New(color.Faint)
		green.Printf("Applied %d change(s):\n\n", len(result.Changes))

		// Column widths
		const idW, fieldW, oldW, newW = 5, 10, 20, 20
		header := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %s",
			idW, "ID", fieldW, "FIELD", oldW, "OLD", newW, "NEW", "TASK")
		dim.Println(header)
		dim.Println("  " + strings.Repeat("─", idW+fieldW+oldW+newW+len("TASK")+10))

		for _, c := range result.Changes {
			oldVal := truncateSummary(c.OldValue, oldW)
			newVal := truncateSummary(c.NewValue, newW)
			title := truncateSummary(c.TaskTitle, 40)
			fmt.Printf("  %-*d  %-*s  %-*s  %-*s  %s\n",
				idW, c.TaskID,
				fieldW, c.Field,
				oldW, oldVal,
				newW, newVal,
				title,
			)
		}
		fmt.Println()
		return nil
	},
}

// truncateSummary truncates a string for table display, adding "…" if needed.
func truncateSummary(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func init() {
	taskCmd.AddCommand(taskBatchEditCmd)
}
