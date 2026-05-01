package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var exportOutput string

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export session as a markdown report",
	Long: `Export the current cloop session as a markdown report.

Includes the goal, status, token usage, step history, and task plan (in PM mode).
Useful for documenting what the AI did or sharing results with teammates.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		report := buildReport(s)

		if exportOutput == "" || exportOutput == "-" {
			fmt.Print(report)
			return nil
		}

		if err := os.WriteFile(exportOutput, []byte(report), 0644); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		fmt.Printf("Report written to %s\n", exportOutput)
		return nil
	},
}

func buildReport(s *state.ProjectState) string {
	var b strings.Builder

	b.WriteString("# cloop Session Report\n\n")

	b.WriteString(fmt.Sprintf("**Goal:** %s\n\n", s.Goal))
	b.WriteString(fmt.Sprintf("**Status:** %s\n", s.Status))

	prov := s.Provider
	if prov == "" {
		prov = "claudecode"
	}
	b.WriteString(fmt.Sprintf("**Provider:** %s\n", prov))

	if s.Model != "" {
		b.WriteString(fmt.Sprintf("**Model:** %s\n", s.Model))
	}

	if s.PMMode {
		b.WriteString("**Mode:** product manager\n")
	}

	b.WriteString(fmt.Sprintf("**Created:** %s\n", s.CreatedAt.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("**Updated:** %s\n", s.UpdatedAt.Format("2006-01-02 15:04:05")))

	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		b.WriteString(fmt.Sprintf("**Tokens:** %d in / %d out\n", s.TotalInputTokens, s.TotalOutputTokens))
	}

	if s.Instructions != "" {
		b.WriteString(fmt.Sprintf("\n**Instructions:** %s\n", s.Instructions))
	}

	// Task plan (PM mode)
	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		b.WriteString("\n## Task Plan\n\n")
		b.WriteString(fmt.Sprintf("*%s*\n\n", s.Plan.Summary()))
		b.WriteString("| # | Priority | Status | Title |\n")
		b.WriteString("|---|----------|--------|-------|\n")
		for _, t := range s.Plan.Tasks {
			marker := taskStatusIcon(t.Status)
			b.WriteString(fmt.Sprintf("| %d | %d | %s %s | %s |\n",
				t.ID, t.Priority, marker, t.Status, escapeMD(t.Title)))
		}

		// Detailed task descriptions
		b.WriteString("\n### Task Details\n\n")
		for _, t := range s.Plan.Tasks {
			b.WriteString(fmt.Sprintf("#### Task %d: %s\n\n", t.ID, t.Title))
			b.WriteString(fmt.Sprintf("**Status:** %s | **Priority:** %d\n\n", t.Status, t.Priority))
			if t.Description != "" {
				b.WriteString(t.Description + "\n\n")
			}
			if t.StartedAt != nil {
				b.WriteString(fmt.Sprintf("*Started: %s*\n", t.StartedAt.Format("2006-01-02 15:04:05")))
			}
			if t.CompletedAt != nil {
				b.WriteString(fmt.Sprintf("*Completed: %s*\n", t.CompletedAt.Format("2006-01-02 15:04:05")))
				if t.StartedAt != nil {
					dur := t.CompletedAt.Sub(*t.StartedAt).Round(time.Second)
					b.WriteString(fmt.Sprintf("*Duration: %s*\n", dur))
				}
			}
			if t.Result != "" {
				b.WriteString("\n**Result summary:**\n\n")
				b.WriteString(t.Result + "\n")
			}
			b.WriteString("\n")
		}
	}

	// Step history
	if len(s.Steps) > 0 {
		b.WriteString("## Step History\n\n")
		b.WriteString(fmt.Sprintf("*%d steps recorded*\n\n", len(s.Steps)))

		for _, step := range s.Steps {
			b.WriteString(fmt.Sprintf("### Step %d", step.Step+1))
			if step.Task != "" && step.Task != fmt.Sprintf("Step %d", step.Step+1) {
				b.WriteString(fmt.Sprintf(": %s", step.Task))
			}
			b.WriteString("\n\n")

			b.WriteString(fmt.Sprintf("*Time: %s | Duration: %s", step.Time.Format("2006-01-02 15:04:05"), step.Duration))
			if step.InputTokens > 0 || step.OutputTokens > 0 {
				b.WriteString(fmt.Sprintf(" | Tokens: %d in / %d out", step.InputTokens, step.OutputTokens))
			}
			b.WriteString("*\n\n")

			if step.Output != "" {
				b.WriteString("```\n")
				b.WriteString(step.Output)
				if !strings.HasSuffix(step.Output, "\n") {
					b.WriteString("\n")
				}
				b.WriteString("```\n\n")
			}

			b.WriteString("---\n\n")
		}
	} else {
		b.WriteString("\n*No steps recorded yet.*\n")
	}

	return b.String()
}

func taskStatusIcon(status pm.TaskStatus) string {
	switch status {
	case pm.TaskDone:
		return "[x]"
	case pm.TaskSkipped:
		return "[-]"
	case pm.TaskFailed:
		return "[!]"
	case pm.TaskInProgress:
		return "[~]"
	default:
		return "[ ]"
	}
}

// escapeMD escapes pipe characters in markdown table cells.
func escapeMD(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func init() {
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Write report to file (default: stdout)")
	rootCmd.AddCommand(exportCmd)
}
