package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/blocker"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/milestone"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/profile"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/trace"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// healthScoreColor returns the display color for a given health score.
func healthScoreColor(score int) *color.Color {
	if score >= 75 {
		return color.New(color.FgGreen, color.Bold)
	}
	if score >= 60 {
		return color.New(color.FgYellow, color.Bold)
	}
	return color.New(color.FgRed, color.Bold)
}

var statusJSON bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show project status",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		if statusJSON {
			data, err := json.MarshalIndent(s, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling status: %w", err)
			}
			fmt.Println(string(data))
			return nil
		}

		statusColor := color.New(color.FgWhite, color.Bold)
		switch s.Status {
		case "complete":
			statusColor = color.New(color.FgGreen, color.Bold)
		case "running":
			statusColor = color.New(color.FgCyan, color.Bold)
		case "failed":
			statusColor = color.New(color.FgRed, color.Bold)
		case "paused", "initialized":
			statusColor = color.New(color.FgYellow, color.Bold)
		}

		fmt.Printf("Goal:     %s\n", s.Goal)
		fmt.Printf("Status:   ")
		statusColor.Println(s.Status)

		if activeProf := profile.GetActive(); activeProf != "" {
			fmt.Printf("Profile:  %s\n", activeProf)
		}

		prov := s.Provider
		if prov == "" {
			prov = "claudecode (default)"
		}
		fmt.Printf("Provider: %s\n", prov)

		if s.Model != "" {
			fmt.Printf("Model:    %s\n", s.Model)
		}

		if s.PMMode {
			fmt.Printf("Mode:     product manager\n")
			if s.Plan != nil {
				fmt.Printf("Tasks:    %s\n", s.Plan.Summary())
				// Sort tasks by priority (ascending) for consistent display.
				sorted := make([]*pm.Task, len(s.Plan.Tasks))
				copy(sorted, s.Plan.Tasks)
				sort.SliceStable(sorted, func(i, j int) bool {
					return sorted[i].Priority < sorted[j].Priority
				})
				// Pre-compute blocked task IDs for O(1) lookup
				blockedInfos := blocker.DetectAll(workdir, s.Plan)
				blockedIDs := make(map[int]*blocker.BlockerInfo, len(blockedInfos))
				for _, bi := range blockedInfos {
					blockedIDs[bi.TaskID] = bi
				}
				for _, t := range sorted {
					failCountSuffix := ""
					if t.FailCount > 0 {
						failCountSuffix = fmt.Sprintf(" (failed %d×)", t.FailCount)
					}
					// Surface ai-reviewer verdict separately from human notes.
					reviewVerdict := ""
					humanNotes := 0
					for _, a := range t.Annotations {
						if a.Author == "ai-reviewer" {
							text := a.Text
							if len(text) > 2 && text[0] == '[' {
								if end := strings.Index(text, "]"); end > 0 {
									reviewVerdict = text[1:end]
								}
							}
						} else {
							humanNotes++
						}
					}
					notesSuffix := ""
					if humanNotes > 0 {
						notesSuffix = fmt.Sprintf(" [%d notes]", humanNotes)
					}
					reviewSuffix := ""
					if reviewVerdict == "PASS" {
						reviewSuffix = color.New(color.FgGreen).Sprint(" [review:PASS]")
					} else if reviewVerdict == "FAIL" {
						reviewSuffix = color.New(color.FgRed).Sprint(" [review:FAIL]")
					}
					deadlineSuffix := ""
					if t.Deadline != nil && t.Status != pm.TaskDone && t.Status != pm.TaskSkipped {
						countdown := pm.FormatCountdown(pm.TimeUntilDeadlineD(t))
						if pm.IsOverdue(t) {
							deadlineSuffix = color.New(color.FgRed, color.Bold).Sprintf(" [deadline: %s]", countdown)
						} else {
							deadlineSuffix = color.New(color.FgYellow).Sprintf(" [deadline: %s]", countdown)
						}
					}
					assigneeSuffix := ""
				if t.Assignee != "" {
					assigneeSuffix = color.New(color.FgBlue).Sprintf(" [@%s]", t.Assignee)
				}
				blockerSuffix := ""
				if _, isBlocked := blockedIDs[t.ID]; isBlocked {
					blockerSuffix = color.New(color.FgRed, color.Bold).Sprint(" [BLOCKED]")
				}
				fmt.Printf("          %s Task %d: %s%s%s%s%s%s%s\n", taskMarker(t.Status), t.ID, t.Title, failCountSuffix, notesSuffix, reviewSuffix, deadlineSuffix, assigneeSuffix, blockerSuffix)
					if t.Condition != "" {
						condStr := t.Condition
						if len(condStr) > 80 {
							condStr = condStr[:80] + "..."
						}
						condColor := color.New(color.Faint)
						if t.Status == pm.TaskSkipped {
							condColor = color.New(color.FgYellow)
						}
						condColor.Printf("            [condition: %s]\n", condStr)
					}
					if t.Status == pm.TaskFailed && t.FailureDiagnosis != "" {
						diag := t.FailureDiagnosis
						if len(diag) > 300 {
							diag = diag[:300] + "..."
						}
						color.New(color.FgRed).Printf("            Diagnosis: %s\n", diag)
					}
				}
			}
		} else {
			if s.MaxSteps > 0 {
				fmt.Printf("Progress: %d/%d steps\n", s.CurrentStep, s.MaxSteps)
			} else {
				fmt.Printf("Progress: %d steps (unlimited)\n", s.CurrentStep)
			}
		}

		if len(s.Milestones) > 0 {
			milestone.SortByID(s.Milestones)
			fmt.Printf("Milestones: %d total\n", len(s.Milestones))
			for _, ms := range s.Milestones {
				p := ms.Progress(s.Plan)
				deadlineStr := ""
				if ms.Deadline != nil {
					deadlineStr = " (" + ms.Deadline.Format("2006-01-02") + ")"
				}
				fmt.Printf("           #%d %s%s — %.0f%%\n", ms.ID, ms.Name, deadlineStr, p.PctDone)
			}
		}

		if s.HealthReport != nil {
			hr := s.HealthReport
			scoreCol := healthScoreColor(hr.Score)
			fmt.Printf("Health:   ")
			scoreCol.Printf("%d/100 (Grade: %s)", hr.Score, hr.Grade())
			if hr.Summary != "" {
				fmt.Printf("  — %s", hr.Summary)
			}
			fmt.Println()
			if len(hr.Issues) > 0 {
				for _, issue := range hr.Issues {
					color.New(color.FgRed).Printf("          ! %s\n", issue)
				}
			}
		}

		fmt.Printf("Created:  %s\n", s.CreatedAt.Format("2006-01-02 15:04"))
		fmt.Printf("Updated:  %s\n", s.UpdatedAt.Format("2006-01-02 15:04"))

		if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
			fmt.Printf("Tokens:   %d in / %d out\n", s.TotalInputTokens, s.TotalOutputTokens)
			if usd := cost.EstimateSessionCost(s.Provider, s.Model, s.TotalInputTokens, s.TotalOutputTokens); usd > 0 {
				fmt.Printf("Cost:     %s\n", cost.FormatCost(usd))
			}
		}

		if len(s.Steps) > 0 {
			last := s.Steps[len(s.Steps)-1]
			fmt.Printf("\nLast step (#%d): %s, %s\n", last.Step+1, last.Task, last.Duration)
		}

		if linked := trace.LastLinkedCommit(workdir); linked != nil {
			taskRef := fmt.Sprintf("task #%d", linked.MatchedTaskID)
			if linked.MatchedTaskTitle != "" {
				taskRef = fmt.Sprintf("task #%d (%s)", linked.MatchedTaskID, linked.MatchedTaskTitle)
			}
			color.New(color.Faint).Printf("Trace:    last commit %s → %s [%s]\n",
				linked.Hash, taskRef, linked.Confidence)
		}

		return nil
	},
}

func init() {
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output status as JSON")
	rootCmd.AddCommand(statusCmd)
}
