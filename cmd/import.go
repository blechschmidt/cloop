package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/importer"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)


var importFormat string

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import tasks from a Jira, Linear, or GitHub Issues CSV export",
	Long: `Import tasks from an external project management tool CSV export.

Supported formats (--format):
  auto    Detect format by inspecting CSV headers (default)
  jira    Jira export: Summary, Description, Priority, Status, Labels
  linear  Linear export: Title, Description, Priority, State, Identifier
  github  GitHub Issues export: title, body, labels, state

Status mapping:
  done/closed/resolved → done
  in_progress/in-progress/doing → in_progress
  everything else → pending

Priority mapping (string → integer, 1=highest):
  highest/critical/blocker/urgent → 1
  high/major → 2
  medium/normal → 3 (default)
  low/minor → 4
  lowest/trivial → 5

Tasks are appended to the existing plan. If no plan exists, a new one is
created with a goal derived from the imported file name.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			// No project yet — create a minimal state so we can save the plan.
			s = &state.ProjectState{
				WorkDir: workdir,
				PMMode:  true,
			}
		}

		// Ensure a plan exists to append to.
		if s.Plan == nil {
			goal := fmt.Sprintf("Imported tasks from %s", filePath)
			s.Plan = pm.NewPlan(goal)
			s.PMMode = true
		}

		// Determine starting ID (max existing ID + 1).
		startID := 1
		for _, t := range s.Plan.Tasks {
			if t.ID >= startID {
				startID = t.ID + 1
			}
		}

		tasks, err := importer.Import(filePath, importer.Format(importFormat), startID)
		if err != nil {
			return fmt.Errorf("import: %w", err)
		}

		if len(tasks) == 0 {
			fmt.Println("No tasks found in the file.")
			return nil
		}

		s.Plan.Tasks = append(s.Plan.Tasks, tasks...)

		if err := s.Save(); err != nil {
			return fmt.Errorf("save state: %w", err)
		}

		fmt.Printf("Imported %d task(s) into plan \"%s\"\n", len(tasks), s.Plan.Goal)
		for _, t := range tasks {
			statusIcon := map[pm.TaskStatus]string{
				pm.TaskPending:    "○",
				pm.TaskInProgress: "●",
				pm.TaskDone:       "✓",
				pm.TaskFailed:     "✗",
				pm.TaskSkipped:    "⊘",
			}[t.Status]
			tagStr := ""
			if len(t.Tags) > 0 {
				tagStr = fmt.Sprintf(" [%s]", joinStrings(t.Tags, ", "))
			}
			fmt.Printf("  %s #%d  %s  (priority %d)%s\n", statusIcon, t.ID, t.Title, t.Priority, tagStr)
		}

		return nil
	},
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

func init() {
	importCmd.Flags().StringVar(&importFormat, "format", "auto", "CSV format: auto, jira, linear, github")
	rootCmd.AddCommand(importCmd)
}
