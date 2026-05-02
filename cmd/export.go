package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var exportOutput string
var exportFormat string

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export session as a report (markdown, json, or csv)",
	Long: `Export the current cloop session as a report.

Supported formats (--format):
  markdown  Full session report with goal, tasks, step history (default)
  json      Machine-readable full state dump
  csv       Task list with id,title,status,priority,role columns

Useful for documenting what the AI did, CI summaries, dashboards, and audit trails.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		var report string
		switch exportFormat {
		case "json":
			data, err := buildJSONReport(s)
			if err != nil {
				return err
			}
			report = string(data)
		case "csv":
			data, err := buildCSVReport(s)
			if err != nil {
				return err
			}
			report = data
		case "markdown", "md", "":
			report = buildReport(s)
		default:
			return fmt.Errorf("unknown format %q: supported formats are markdown, json, csv", exportFormat)
		}

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
		b.WriteString("| # | Priority | Status | Title | Est (min) | Actual (min) | Variance |\n")
		b.WriteString("|---|----------|--------|-------|-----------|--------------|----------|\n")
		for _, t := range s.Plan.Tasks {
			marker := taskStatusIcon(t.Status)
			estStr := "-"
			actStr := "-"
			varStr := "-"
			if t.EstimatedMinutes > 0 {
				estStr = strconv.Itoa(t.EstimatedMinutes)
			}
			actual := t.ActualMinutes
			if actual == 0 && t.StartedAt != nil && t.CompletedAt != nil {
				actual = int(t.CompletedAt.Sub(*t.StartedAt).Minutes())
			}
			if actual > 0 {
				actStr = strconv.Itoa(actual)
			}
			if t.EstimatedMinutes > 0 && actual > 0 {
				variance := float64(actual-t.EstimatedMinutes) / float64(t.EstimatedMinutes) * 100
				varStr = fmt.Sprintf("%+.0f%%", variance)
			}
			b.WriteString(fmt.Sprintf("| %d | %d | %s %s | %s | %s | %s | %s |\n",
				t.ID, t.Priority, marker, t.Status, escapeMD(t.Title), estStr, actStr, varStr))
		}

		// Detailed task descriptions
		b.WriteString("\n### Task Details\n\n")
		for _, t := range s.Plan.Tasks {
			b.WriteString(fmt.Sprintf("#### Task %d: %s\n\n", t.ID, t.Title))
			b.WriteString(fmt.Sprintf("**Status:** %s | **Priority:** %d\n\n", t.Status, t.Priority))
			if t.Description != "" {
				b.WriteString(t.Description + "\n\n")
			}
			if t.EstimatedMinutes > 0 {
				b.WriteString(fmt.Sprintf("*Estimated: %d min*\n", t.EstimatedMinutes))
			}
			if t.StartedAt != nil {
				b.WriteString(fmt.Sprintf("*Started: %s*\n", t.StartedAt.Format("2006-01-02 15:04:05")))
			}
			if t.CompletedAt != nil {
				b.WriteString(fmt.Sprintf("*Completed: %s*\n", t.CompletedAt.Format("2006-01-02 15:04:05")))
				if t.StartedAt != nil {
					dur := t.CompletedAt.Sub(*t.StartedAt).Round(time.Second)
					b.WriteString(fmt.Sprintf("*Duration: %s*\n", dur))
					actualMin := t.ActualMinutes
					if actualMin == 0 {
						actualMin = int(dur.Minutes())
					}
					if t.EstimatedMinutes > 0 && actualMin > 0 {
						variance := float64(actualMin-t.EstimatedMinutes) / float64(t.EstimatedMinutes) * 100
						b.WriteString(fmt.Sprintf("*Time variance: %+.0f%%*\n", variance))
					}
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

// buildJSONReport returns a JSON dump of the full state.
func buildJSONReport(s *state.ProjectState) ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// buildCSVReport returns a CSV with columns: id,title,status,priority,role,estimated_minutes,actual_minutes,variance_pct
// Only meaningful in PM mode; falls back to a header-only CSV if no plan exists.
func buildCSVReport(s *state.ProjectState) (string, error) {
	var sb strings.Builder
	w := csv.NewWriter(&sb)

	header := []string{"id", "title", "status", "priority", "role", "estimated_minutes", "actual_minutes", "variance_pct"}
	if err := w.Write(header); err != nil {
		return "", fmt.Errorf("csv write: %w", err)
	}

	if s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			actual := t.ActualMinutes
			if actual == 0 && t.StartedAt != nil && t.CompletedAt != nil {
				actual = int(t.CompletedAt.Sub(*t.StartedAt).Minutes())
			}
			varStr := ""
			if t.EstimatedMinutes > 0 && actual > 0 {
				variance := float64(actual-t.EstimatedMinutes) / float64(t.EstimatedMinutes) * 100
				varStr = fmt.Sprintf("%.1f", variance)
			}
			actStr := ""
			if actual > 0 {
				actStr = strconv.Itoa(actual)
			}
			estStr := ""
			if t.EstimatedMinutes > 0 {
				estStr = strconv.Itoa(t.EstimatedMinutes)
			}
			row := []string{
				strconv.Itoa(t.ID),
				t.Title,
				string(t.Status),
				strconv.Itoa(t.Priority),
				string(t.Role),
				estStr,
				actStr,
				varStr,
			}
			if err := w.Write(row); err != nil {
				return "", fmt.Errorf("csv write row: %w", err)
			}
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("csv flush: %w", err)
	}
	return sb.String(), nil
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
	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "markdown", "Output format: markdown, json, csv")
	rootCmd.AddCommand(exportCmd)
}
