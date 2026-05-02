package cmd

import (
	"fmt"

	clooptemplate "github.com/blechschmidt/cloop/pkg/template"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var templatesCmd = &cobra.Command{
	Use:   "templates",
	Short: "List available built-in project templates",
	Long: `List the built-in templates that can be used with 'cloop init --template <name>'.

Templates pre-populate the project goal and a full task list, skipping AI decomposition.
Run immediately with 'cloop run' after initialisation.

Examples:
  cloop templates                          # list all templates
  cloop init --template web-app            # bootstrap a full-stack web app
  cloop init --template api-service "My API" --provider anthropic`,
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")

		templates := clooptemplate.All()
		bold := color.New(color.Bold)

		fmt.Printf("Available templates (%d):\n\n", len(templates))
		for _, t := range templates {
			bold.Printf("  %-18s", t.Name)
			fmt.Printf("  %s\n", t.Description)
			if verbose {
				fmt.Printf("  %sGoal:%s %s\n", color.HiBlackString(""), "", t.Goal)
				fmt.Printf("  %sTasks (%d):%s\n", color.HiBlackString(""), len(t.Tasks), "")
				for i, task := range t.Tasks {
					role := ""
					if task.Role != "" {
						role = fmt.Sprintf(" [%s]", task.Role)
					}
					est := ""
					if task.EstimatedMinutes > 0 {
						est = fmt.Sprintf(" ~%dm", task.EstimatedMinutes)
					}
					fmt.Printf("    %d. %s%s%s\n", i+1, task.Title, role, est)
				}
				fmt.Println()
			}
		}

		if !verbose {
			fmt.Printf("\nRun 'cloop templates --verbose' to see tasks for each template.\n")
		}
		fmt.Printf("Usage: cloop init --template <name> [goal]\n")
		return nil
	},
}

func init() {
	templatesCmd.Flags().BoolP("verbose", "v", false, "Show goal and task list for each template")
	rootCmd.AddCommand(templatesCmd)
}
