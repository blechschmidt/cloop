package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show project status",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
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
				for _, t := range s.Plan.Tasks {
					marker := "[ ]"
					switch t.Status {
					case "done":
						marker = "[x]"
					case "skipped":
						marker = "[-]"
					case "failed":
						marker = "[!]"
					case "in_progress":
						marker = "[~]"
					}
					fmt.Printf("          %s Task %d: %s\n", marker, t.ID, t.Title)
				}
			}
		} else {
			if s.MaxSteps > 0 {
				fmt.Printf("Progress: %d/%d steps\n", s.CurrentStep, s.MaxSteps)
			} else {
				fmt.Printf("Progress: %d steps (unlimited)\n", s.CurrentStep)
			}
		}

		fmt.Printf("Created:  %s\n", s.CreatedAt.Format("2006-01-02 15:04"))
		fmt.Printf("Updated:  %s\n", s.UpdatedAt.Format("2006-01-02 15:04"))

		if len(s.Steps) > 0 {
			last := s.Steps[len(s.Steps)-1]
			fmt.Printf("\nLast step (#%d): %s, %s\n", last.Step+1, last.Task, last.Duration)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
