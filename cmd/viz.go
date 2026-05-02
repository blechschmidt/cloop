package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/viz"
	"github.com/spf13/cobra"
)

var vizFormat string
var vizOutput string

var vizCmd = &cobra.Command{
	Use:   "viz",
	Short: "Visualize the task dependency graph",
	Long: `Render the task dependency graph in the terminal (ASCII) or export to
Mermaid / Graphviz DOT format for external tools.

Supported formats (--format):
  ascii    Box-drawing ASCII graph with color-coded status nodes (default)
  mermaid  Mermaid flowchart wrapped in a fenced code block
  dot      Graphviz DOT digraph (pipe to dot -Tpng or similar)

Examples:
  cloop viz                          # ASCII graph in terminal
  cloop viz --format mermaid         # Mermaid for GitHub markdown
  cloop viz --format dot             # DOT for Graphviz
  cloop viz --format dot -o graph.dot && dot -Tpng graph.dot -o graph.png`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no active plan — run 'cloop run --pm' first")
		}

		var output string
		switch viz.Format(vizFormat) {
		case viz.FormatMermaid:
			output = viz.RenderMermaid(s.Plan)
		case viz.FormatDOT:
			output = viz.RenderDOT(s.Plan)
		case viz.FormatASCII, "":
			useColor := vizOutput == "" // color only when writing to stdout
			output = viz.RenderASCII(s.Plan, useColor)
		default:
			return fmt.Errorf("unknown format %q — use ascii, mermaid, or dot", vizFormat)
		}

		if vizOutput != "" {
			if err := os.WriteFile(vizOutput, []byte(output), 0644); err != nil {
				return fmt.Errorf("write %s: %w", vizOutput, err)
			}
			fmt.Fprintf(os.Stderr, "wrote %s\n", vizOutput)
			return nil
		}

		fmt.Print(output)
		return nil
	},
}

func init() {
	vizCmd.Flags().StringVarP(&vizFormat, "format", "f", "ascii", "Output format: ascii, mermaid, or dot")
	vizCmd.Flags().StringVarP(&vizOutput, "output", "o", "", "Write output to file instead of stdout")
	rootCmd.AddCommand(vizCmd)
}
