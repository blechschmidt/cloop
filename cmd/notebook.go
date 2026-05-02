package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/notebook"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var (
	notebookOutput string
	notebookFormat string
)

var notebookCmd = &cobra.Command{
	Use:   "notebook",
	Short: "Export plan and outputs as a shareable notebook document",
	Long: `Generate a rich, shareable notebook capturing the full project story.

The notebook includes:
  - Project goal
  - Plan health score and summary table
  - Task list with status, priority, role, tags, and time estimates vs actuals
  - Per-task output excerpts (from persisted task artifacts)
  - Retrospective summary

Two formats are supported:
  --format md    GitHub-flavoured Markdown (default)
  --format html  Self-contained HTML with inline CSS and collapsible task sections

Examples:
  cloop notebook                              # Markdown to stdout
  cloop notebook --format html -o notebook.html
  cloop notebook --output plan.md`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		s, err := state.Load(workDir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}

		// Normalise format aliases
		switch notebookFormat {
		case "md", "markdown":
			notebookFormat = "md"
		case "htm", "html":
			notebookFormat = "html"
		default:
			return fmt.Errorf("unknown format %q: use 'md' or 'html'", notebookFormat)
		}

		doc, err := notebook.Build(workDir, s, notebookFormat)
		if err != nil {
			return fmt.Errorf("building notebook: %w", err)
		}

		if notebookOutput != "" {
			if err := os.WriteFile(notebookOutput, []byte(doc), 0o644); err != nil {
				return fmt.Errorf("writing notebook: %w", err)
			}
			fmt.Printf("Notebook saved to %s\n", notebookOutput)
			return nil
		}

		fmt.Print(doc)
		return nil
	},
}

func init() {
	notebookCmd.Flags().StringVarP(&notebookOutput, "output", "o", "", "Save notebook to file instead of stdout")
	notebookCmd.Flags().StringVar(&notebookFormat, "format", "md", "Output format: md (Markdown) or html")
	rootCmd.AddCommand(notebookCmd)
}
