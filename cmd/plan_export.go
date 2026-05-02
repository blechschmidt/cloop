package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/planio"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	planExportFormat string
	planExportOutput string
)

var planExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export current plan to a portable file",
	Long: `Serialise the current task plan (goal + all tasks) to a portable file
that can be shared with team members who do not have git access.

Supported formats: yaml (default), json, toml

The format is inferred from the --output file extension when --format is not set.

Examples:
  cloop plan export                          # print YAML to stdout
  cloop plan export --format json            # print JSON to stdout
  cloop plan export --output plan.yaml       # write YAML to plan.yaml
  cloop plan export --output plan.toml       # write TOML to plan.toml
  cloop plan export --format json -o out.json`,
	Aliases: []string{"exp"},
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Resolve format: explicit flag > infer from output extension > default yaml.
		format := strings.ToLower(strings.TrimSpace(planExportFormat))
		if format == "" && planExportOutput != "" && planExportOutput != "-" {
			format = planio.DetectFormat(planExportOutput)
		}
		if format == "" {
			format = "yaml"
		}

		if err := planio.Export(s.Plan, format, planExportOutput); err != nil {
			return fmt.Errorf("export failed: %w", err)
		}

		// Only print success message when writing to a file (not stdout).
		if planExportOutput != "" && planExportOutput != "-" {
			successColor := color.New(color.FgGreen, color.Bold)
			dimColor := color.New(color.Faint)
			successColor.Printf("Plan exported")
			dimColor.Printf(" → %s (%s, %d task(s))\n",
				planExportOutput, format, len(s.Plan.Tasks))
		}

		return nil
	},
}

func init() {
	planExportCmd.Flags().StringVarP(&planExportFormat, "format", "f", "", "Output format: yaml, json, toml (default: yaml, or inferred from --output extension)")
	planExportCmd.Flags().StringVarP(&planExportOutput, "output", "o", "", "Output file path (default: stdout)")
}
