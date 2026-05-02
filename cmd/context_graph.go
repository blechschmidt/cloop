package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/contextgraph"
	"github.com/spf13/cobra"
)

var (
	ctxGraphFormat string
	ctxGraphOutput string
)

var contextGraphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Build a knowledge graph of task/artifact/decision relationships",
	Long: `Build a directed knowledge graph that links:
  - Tasks (nodes) and their dependency edges
  - File artifacts produced under .cloop/artifacts/ and .cloop/tasks/
  - Knowledge base entries (cloop kb)
  - Task annotations
  - Git commits correlated to tasks (via .cloop/trace.json)

Output formats (--format):
  dot      Graphviz DOT digraph — pipe to "dot -Tpng" for an image
  mermaid  Mermaid flowchart wrapped in a fenced code block
  json     {nodes:[{id,type,label}], edges:[{from,to,rel}]}

Node types use distinct shapes/colours in dot and mermaid output:
  task       box (colour by status: green=done, yellow=in_progress, red=failed)
  artifact   note/blue
  kb         ellipse/purple
  annotation dashed-box/yellow
  commit     hexagon/orange

Examples:
  cloop context graph                          # DOT to stdout
  cloop context graph --format mermaid         # Mermaid for GitHub markdown
  cloop context graph --format json            # machine-readable JSON
  cloop context graph --format dot -o g.dot && dot -Tpng g.dot -o g.png`,
	RunE: runContextGraph,
}

func runContextGraph(_ *cobra.Command, _ []string) error {
	workDir, _ := os.Getwd()

	g, err := contextgraph.Collect(workDir)
	if err != nil {
		return fmt.Errorf("context graph: %w", err)
	}

	if len(g.Nodes) == 0 {
		fmt.Fprintln(os.Stderr, "No graph data found. Run 'cloop run --pm' to create a plan, or use 'cloop kb add' to add knowledge base entries.")
		return nil
	}

	var output string
	switch strings.ToLower(ctxGraphFormat) {
	case "json":
		output, err = contextgraph.RenderJSON(g)
		if err != nil {
			return fmt.Errorf("render JSON: %w", err)
		}
	case "mermaid":
		output = contextgraph.RenderMermaid(g)
	case "dot", "":
		output = contextgraph.RenderDOT(g)
	default:
		return fmt.Errorf("unknown format %q — use dot, mermaid, or json", ctxGraphFormat)
	}

	if ctxGraphOutput != "" {
		if err := os.WriteFile(ctxGraphOutput, []byte(output), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", ctxGraphOutput, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d nodes, %d edges)\n", ctxGraphOutput, len(g.Nodes), len(g.Edges))
		return nil
	}

	fmt.Print(output)
	return nil
}

func init() {
	contextGraphCmd.Flags().StringVarP(&ctxGraphFormat, "format", "f", "dot", "Output format: dot, mermaid, or json")
	contextGraphCmd.Flags().StringVarP(&ctxGraphOutput, "output", "o", "", "Write output to file instead of stdout")
	contextCmd.AddCommand(contextGraphCmd)
}
