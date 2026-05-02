package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/milestone"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/profile"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

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
				for _, t := range sorted {
					failCountSuffix := ""
					if t.FailCount > 0 {
						failCountSuffix = fmt.Sprintf(" (failed %d×)", t.FailCount)
					}
					notesSuffix := ""
					if len(t.Annotations) > 0 {
						notesSuffix = fmt.Sprintf(" [%d notes]", len(t.Annotations))
					}
					fmt.Printf("          %s Task %d: %s%s%s\n", taskMarker(t.Status), t.ID, t.Title, failCountSuffix, notesSuffix)
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

		return nil
	},
}

func init() {
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output status as JSON")
	rootCmd.AddCommand(statusCmd)
}
