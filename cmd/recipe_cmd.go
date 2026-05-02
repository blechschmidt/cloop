package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/recipe"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var recipeCmd = &cobra.Command{
	Use:   "recipe",
	Short: "Shareable composable workflow library",
	Long: `Manage and run named, shareable workflows (recipes).

A recipe bundles a flow pipeline, a goal template, lifecycle hooks, and
default environment variables into a single installable YAML file stored
in .cloop/recipes/<name>.yaml.

  cloop recipe list                        # list installed recipes
  cloop recipe install <file-or-url>       # install a recipe
  cloop recipe run <name> [--goal <text>]  # run an installed recipe
  cloop recipe export <name>               # print recipe YAML to stdout
  cloop recipe remove <name>               # uninstall a recipe
  cloop recipe init                        # print an example recipe to stdout`,
}

var recipeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed recipes",
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		recipes, err := recipe.List(workDir)
		if err != nil {
			return err
		}

		bold := color.New(color.Bold)
		faint := color.New(color.Faint)

		if len(recipes) == 0 {
			faint.Println("No recipes installed.")
			faint.Printf("Install one with: cloop recipe install <file-or-url>\n")
			faint.Printf("Or view an example: cloop recipe init\n")
			return nil
		}

		bold.Printf("%-20s  %-8s  %s\n", "NAME", "VERSION", "DESCRIPTION")
		fmt.Printf("%-20s  %-8s  %s\n", "--------------------", "--------", "-----------")
		for _, r := range recipes {
			ver := r.Version
			if ver == "" {
				ver = faint.Sprint("-")
			}
			desc := r.Description
			if desc == "" {
				desc = faint.Sprint("(no description)")
			}
			fmt.Printf("%-20s  %-8s  %s\n", r.Name, ver, desc)
		}
		return nil
	},
}

var recipeInstallCmd = &cobra.Command{
	Use:   "install <file-or-url>",
	Short: "Install a recipe from a local file or URL",
	Long: `Copy a recipe YAML file into .cloop/recipes/.

The source may be a local file path or an HTTP(S) URL.  The recipe name is
taken from the 'name' field inside the YAML.

Examples:
  cloop recipe install ./my-recipe.yaml
  cloop recipe install https://example.com/recipes/release.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		source := args[0]

		r, err := recipe.Install(workDir, source)
		if err != nil {
			return err
		}

		green := color.New(color.FgGreen)
		green.Printf("Recipe %q installed", r.Name)
		if r.Version != "" {
			green.Printf(" (v%s)", r.Version)
		}
		green.Println()
		if r.Description != "" {
			fmt.Printf("  %s\n", r.Description)
		}
		fmt.Printf("  Run with: cloop recipe run %s\n", r.Name)
		return nil
	},
}

var (
	recipeRunGoal    string
	recipeRunDryRun  bool
	recipeRunExtras  []string
)

var recipeRunCmd = &cobra.Command{
	Use:   "run <name>",
	Short: "Run an installed recipe",
	Long: `Instantiate the recipe template, inject the rendered flow, set env vars,
fire lifecycle hooks, and execute the pipeline.

The --goal flag provides the goal string passed to the recipe's goal_template.
If the recipe has no goal_template, --goal is used verbatim (or may be empty).

Examples:
  cloop recipe run release-pipeline --goal "v2.1.0"
  cloop recipe run dev-cycle --dry-run
  cloop recipe run onboarding --goal "new feature" --set env=prod`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		name := args[0]

		r, err := recipe.Load(workDir, name)
		if err != nil {
			return err
		}

		bold := color.New(color.Bold)
		cyan := color.New(color.FgCyan)
		faint := color.New(color.Faint)
		green := color.New(color.FgGreen)
		red := color.New(color.FgRed)

		bold.Printf("Recipe: %s", r.Name)
		if r.Version != "" {
			faint.Printf(" v%s", r.Version)
		}
		fmt.Println()
		if r.Description != "" {
			faint.Printf("  %s\n", r.Description)
		}
		if recipeRunGoal != "" {
			fmt.Printf("  Goal: %s\n", recipeRunGoal)
		}
		if recipeRunDryRun {
			cyan.Println("  (dry-run mode — steps will not execute)")
		}
		fmt.Println()

		// Parse --set key=value extras.
		extras := parseKeyValues(recipeRunExtras)

		cfg := recipe.RunConfig{
			Goal:      recipeRunGoal,
			ExtraVars: extras,
			WorkDir:   workDir,
			DryRun:    recipeRunDryRun,
		}

		start := time.Now()
		result, err := recipe.Run(cmd.Context(), r, cfg)
		if err != nil {
			return fmt.Errorf("recipe %q failed: %w", name, err)
		}

		// Print summary.
		fmt.Println()
		bold.Println("Pipeline summary:")
		passed, failed, skipped := 0, 0, 0
		for _, sr := range result.FlowResults {
			switch {
			case sr.Skipped:
				skipped++
				faint.Printf("  SKIP  %s\n", sr.StepName)
			case sr.Err != nil:
				failed++
				red.Printf("  FAIL  %s (%v)\n", sr.StepName, sr.Duration.Round(time.Millisecond))
			default:
				passed++
				green.Printf("  PASS  %s (%v)\n", sr.StepName, sr.Duration.Round(time.Millisecond))
			}
		}
		total := time.Since(start)
		fmt.Printf("\n  Total: %d passed, %d failed, %d skipped in %v\n",
			passed, failed, skipped, total.Round(time.Millisecond))

		if result.Err != nil {
			fmt.Println()
			red.Printf("Recipe %q aborted: %v\n", name, result.Err)
			return fmt.Errorf("recipe %q failed", name)
		}
		fmt.Println()
		green.Printf("Recipe %q completed successfully.\n", name)
		return nil
	},
}

var recipeExportCmd = &cobra.Command{
	Use:   "export <name>",
	Short: "Print a recipe YAML to stdout for sharing",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		data, err := recipe.Export(workDir, args[0])
		if err != nil {
			return err
		}
		fmt.Print(string(data))
		return nil
	},
}

var recipeRemoveCmd = &cobra.Command{
	Use:     "remove <name>",
	Aliases: []string{"rm", "uninstall"},
	Short:   "Uninstall a recipe",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		name := args[0]
		if err := recipe.Remove(workDir, name); err != nil {
			return err
		}
		color.New(color.FgGreen).Printf("Recipe %q removed.\n", name)
		return nil
	},
}

var recipeInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Print an example recipe YAML to stdout",
	Long: `Print a fully-annotated example recipe YAML to stdout.

Redirect or copy it to a file, customise, then install:
  cloop recipe init > my-recipe.yaml
  # edit my-recipe.yaml ...
  cloop recipe install my-recipe.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		r := recipe.ExampleRecipe()
		// Inline the marshalling logic via Export-like call.
		workDir, _ := os.Getwd()
		// Install temporarily to a temp file approach is not needed —
		// just serialize directly.
		_ = workDir
		data, err := recipe.MarshalExample(r)
		if err != nil {
			return err
		}
		fmt.Print(string(data))
		return nil
	},
}

// parseKeyValues converts ["key=value", ...] into a map.
func parseKeyValues(pairs []string) map[string]string {
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		idx := -1
		for i, c := range p {
			if c == '=' {
				idx = i
				break
			}
		}
		if idx > 0 {
			out[p[:idx]] = p[idx+1:]
		}
	}
	return out
}

func init() {
	recipeRunCmd.Flags().StringVarP(&recipeRunGoal, "goal", "g", "", "Goal string passed to the recipe template")
	recipeRunCmd.Flags().BoolVar(&recipeRunDryRun, "dry-run", false, "Print steps without executing them")
	recipeRunCmd.Flags().StringArrayVar(&recipeRunExtras, "set", nil, "Extra template variables as key=value (repeatable)")

	rootCmd.AddCommand(recipeCmd)
	recipeCmd.AddCommand(recipeListCmd, recipeInstallCmd, recipeRunCmd, recipeExportCmd, recipeRemoveCmd, recipeInitCmd)
}
