package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/report"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var (
	reportFormat      string
	reportShowOutputs bool
	reportOutput      string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a project progress report",
	Long: `Generate a rich report of the current project state.

Shows task completion status, timeline, token usage, cost estimates,
and optionally step/task output excerpts.

Examples:
  cloop report                        # terminal report
  cloop report --format md            # markdown report to stdout
  cloop report --format md -o out.md  # save markdown to file
  cloop report --format html -o report.html  # self-contained HTML report
  cloop report --show-outputs         # include output excerpts`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		// Normalize format aliases
		switch reportFormat {
		case "md":
			reportFormat = "markdown"
		case "htm":
			reportFormat = "html"
		}
		format := report.Format(reportFormat)
		if format != report.FormatMarkdown && format != report.FormatTerminal && format != report.FormatHTML {
			return fmt.Errorf("invalid format %q: must be 'terminal', 'md'/'markdown', or 'html'", reportFormat)
		}

		opts := report.Options{
			Format:      format,
			ShowOutputs: reportShowOutputs,
		}

		if reportOutput != "" {
			f, err := os.Create(reportOutput)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer f.Close()
			report.Generate(f, s, opts)
			fmt.Printf("Report saved to %s\n", reportOutput)
		} else {
			report.Generate(os.Stdout, s, opts)
		}

		return nil
	},
}

func init() {
	reportCmd.Flags().StringVar(&reportFormat, "format", "terminal", "Output format: terminal, md/markdown, html")
	reportCmd.Flags().BoolVar(&reportShowOutputs, "show-outputs", false, "Include step/task output excerpts")
	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "Save report to file instead of stdout")
	rootCmd.AddCommand(reportCmd)
}
