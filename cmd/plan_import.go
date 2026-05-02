package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/planio"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	planImportMerge   bool
	planImportReplace bool
	planImportFormat  string
	planImportYes     bool
)

var planImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import a plan from a portable file",
	Long: `Read a plan file (YAML, JSON, or TOML) and load it into the current project.

Supported formats are detected automatically from the file extension.
Use --format to override when the extension is ambiguous.

Merge modes:
  --replace  Discard the current plan and replace it with the imported one (default).
  --merge    Append new tasks (matched by title) to the existing plan.
             Tasks with duplicate titles are skipped.
             Dependency references are cleared for merged tasks to avoid ID conflicts.

Examples:
  cloop plan import plan.yaml
  cloop plan import plan.json --replace
  cloop plan import colleague-plan.toml --merge
  cloop plan import sprint.yaml --merge --yes`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		// Determine merge mode.
		if planImportMerge && planImportReplace {
			return fmt.Errorf("--merge and --replace are mutually exclusive")
		}
		mode := planio.MergeReplace
		if planImportMerge {
			mode = planio.MergeMerge
		}

		// Resolve format.
		format := strings.ToLower(strings.TrimSpace(planImportFormat))

		// Validate that a plan exists when merging.
		var existing *pm.Plan
		if mode == planio.MergeMerge && s.Plan != nil && len(s.Plan.Tasks) > 0 {
			existing = s.Plan
		}

		result, err := planio.Import(filePath, format, existing, mode)
		if err != nil {
			return fmt.Errorf("import failed: %w", err)
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		addColor := color.New(color.FgGreen)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("Plan Import Preview\n")
		fmt.Println(strings.Repeat("─", 60))

		switch mode {
		case planio.MergeReplace:
			addColor.Printf("  Goal: %s\n", result.Plan.Goal)
			dimColor.Printf("  Tasks: %d task(s) will replace the current plan.\n", result.Replaced)
		case planio.MergeMerge:
			addColor.Printf("  + %d new task(s) to append\n", result.Added)
			if result.Skipped > 0 {
				warnColor.Printf("  ~ %d task(s) skipped (title already exists)\n", result.Skipped)
			}
		}

		fmt.Println(strings.Repeat("─", 60))

		if !planImportYes {
			fmt.Printf("Apply import? (y/N): ")
			var answer string
			fmt.Scanln(&answer) //nolint:errcheck
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				fmt.Println("Import cancelled.")
				return nil
			}
		}

		// Commit: enable PM mode and set the updated plan.
		s.PMMode = true
		s.Plan = result.Plan

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		successColor := color.New(color.FgGreen, color.Bold)
		switch mode {
		case planio.MergeReplace:
			successColor.Printf("Plan replaced: %d task(s) imported from %s.\n", result.Replaced, filePath)
		case planio.MergeMerge:
			successColor.Printf("Plan merged: +%d task(s) added", result.Added)
			if result.Skipped > 0 {
				dimColor.Printf(", %d skipped", result.Skipped)
			}
			fmt.Println(".")
		}

		return nil
	},
}

func init() {
	planImportCmd.Flags().BoolVar(&planImportMerge, "merge", false, "Append new tasks to the existing plan (preserving existing tasks)")
	planImportCmd.Flags().BoolVar(&planImportReplace, "replace", false, "Replace the current plan entirely (default behaviour)")
	planImportCmd.Flags().StringVarP(&planImportFormat, "format", "f", "", "Force format: yaml, json, toml (default: inferred from extension)")
	planImportCmd.Flags().BoolVarP(&planImportYes, "yes", "y", false, "Skip confirmation prompt")
}
