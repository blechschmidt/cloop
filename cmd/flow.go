package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/flow"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var flowCmd = &cobra.Command{
	Use:   "flow",
	Short: "Declarative automation pipeline runner",
	Long: `Run and manage YAML-defined automation pipelines.

A flow file describes an ordered sequence of cloop subcommands (steps) with
optional shell conditions (if:), failure policies (on_failure:), and per-step
environment variables.

  cloop flow init [name]              # generate an example flow YAML
  cloop flow init --template release  # use a built-in template
  cloop flow run <flow.yaml>          # execute a flow file
  cloop flow list                     # list flows in .cloop/flows/`,
}

var (
	flowDryRun      bool
	flowTemplate    string
	flowInitOutput  string
)

var flowRunCmd = &cobra.Command{
	Use:   "run <flow-file.yaml>",
	Short: "Execute a declarative automation pipeline",
	Long: `Execute each step defined in the flow YAML file sequentially.

Steps can declare:
  command:    the cloop subcommand to run (required)
  args:       extra arguments passed to the subcommand
  if:         shell condition; step is skipped when it exits non-zero
  on_failure: continue | abort (default) | retry
  env:        per-step environment variable overrides
  max_retries: max additional attempts when on_failure is "retry"

Example flow file:
  name: my-pipeline
  steps:
    - name: lint
      command: lint
      on_failure: continue
    - name: run tasks
      command: run
      args: [--pm]
      if: test -f .cloop/state.db
      on_failure: abort`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		flowPath := args[0]

		f, err := flow.Load(flowPath)
		if err != nil {
			return fmt.Errorf("loading flow: %w", err)
		}

		workDir, _ := os.Getwd()

		bold := color.New(color.Bold)
		cyan := color.New(color.FgCyan)
		green := color.New(color.FgGreen)
		red := color.New(color.FgRed)
		faint := color.New(color.Faint)

		bold.Printf("Flow: %s\n", f.Name)
		if f.Description != "" {
			faint.Printf("  %s\n", f.Description)
		}
		fmt.Printf("Steps: %d\n", len(f.Steps))
		if flowDryRun {
			cyan.Println("  (dry-run mode — commands will not execute)")
		}
		fmt.Println()

		start := time.Now()

		cfg := flow.RunConfig{
			WorkDir: workDir,
			DryRun:  flowDryRun,
			Stdout:  os.Stdout,
			Stderr:  os.Stderr,
		}

		results, runErr := flow.Run(cmd.Context(), f, cfg)

		fmt.Println()
		bold.Println("Pipeline summary:")

		passed, failed, skipped := 0, 0, 0
		for _, r := range results {
			switch {
			case r.Skipped:
				skipped++
				faint.Printf("  SKIP  %s\n", r.StepName)
			case r.Err != nil:
				failed++
				red.Printf("  FAIL  %s (%v)\n", r.StepName, r.Duration.Round(time.Millisecond))
			default:
				passed++
				green.Printf("  PASS  %s (%v)\n", r.StepName, r.Duration.Round(time.Millisecond))
			}
		}

		total := time.Since(start)
		fmt.Println()
		fmt.Printf("  Total: %d passed, %d failed, %d skipped in %v\n",
			passed, failed, skipped, total.Round(time.Millisecond))

		if runErr != nil {
			fmt.Println()
			red.Printf("Pipeline aborted: %v\n", runErr)
			return fmt.Errorf("flow %q failed", f.Name)
		}
		fmt.Println()
		green.Printf("Flow %q completed successfully.\n", f.Name)
		return nil
	},
}

var flowInitCmd = &cobra.Command{
	Use:   "init [name]",
	Short: "Generate an example flow YAML file",
	Long: `Generate a flow YAML file with boilerplate or from a built-in template.

Built-in templates:
  release   lint → health → changelog → pr
  review    analyze → health → risk → explain

Examples:
  cloop flow init                        # example flow → stdout
  cloop flow init my-pipeline            # writes .cloop/flows/my-pipeline.yaml
  cloop flow init --template release     # built-in release template`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var f *flow.Flow

		if flowTemplate != "" {
			templates := flow.BuiltinTemplates()
			t, ok := templates[flowTemplate]
			if !ok {
				names := make([]string, 0, len(templates))
				for k := range templates {
					names = append(names, k)
				}
				return fmt.Errorf("unknown template %q; available: %s", flowTemplate, strings.Join(names, ", "))
			}
			f = t
		} else {
			f = flow.ExampleFlow()
		}

		if len(args) > 0 {
			f.Name = args[0]
		}

		data, err := flow.MarshalYAML(f)
		if err != nil {
			return fmt.Errorf("marshalling flow: %w", err)
		}

		// If a name was provided (or -o flag), write to .cloop/flows/<name>.yaml
		outPath := flowInitOutput
		if outPath == "" && len(args) > 0 {
			workDir, _ := os.Getwd()
			dir := filepath.Join(workDir, ".cloop", "flows")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("creating flows directory: %w", err)
			}
			outPath = filepath.Join(dir, f.Name+".yaml")
		}

		if outPath != "" {
			if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
				return fmt.Errorf("creating output directory: %w", err)
			}
			if err := os.WriteFile(outPath, data, 0o644); err != nil {
				return fmt.Errorf("writing flow file: %w", err)
			}
			color.New(color.FgGreen).Printf("Flow written to %s\n", outPath)
			return nil
		}

		// Default: print to stdout.
		fmt.Print(string(data))
		return nil
	},
}

var flowListCmd = &cobra.Command{
	Use:   "list",
	Short: "List flow files in .cloop/flows/",
	Long:  `List all YAML flow files found in the .cloop/flows/ directory.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		paths, err := flow.ListFlows(workDir)
		if err != nil {
			return err
		}

		bold := color.New(color.Bold)
		faint := color.New(color.Faint)

		bold.Printf("Built-in templates:\n")
		for name, t := range flow.BuiltinTemplates() {
			fmt.Printf("  %-12s  %s\n", name, t.Description)
		}
		fmt.Println()

		if len(paths) == 0 {
			faint.Printf("No flow files found in .cloop/flows/\n")
			faint.Printf("Run `cloop flow init <name>` to create one.\n")
			return nil
		}

		bold.Printf("Project flows (%s/.cloop/flows/):\n", filepath.Base(workDir))
		for _, p := range paths {
			f, err := flow.Load(p)
			name := filepath.Base(p)
			if err == nil {
				desc := f.Description
				if desc == "" {
					desc = faint.Sprintf("(%d steps)", len(f.Steps))
				}
				fmt.Printf("  %-30s  %s\n", name, desc)
			} else {
				fmt.Printf("  %-30s  %s\n", name, faint.Sprint("(parse error)"))
			}
		}
		return nil
	},
}

func init() {
	flowRunCmd.Flags().BoolVar(&flowDryRun, "dry-run", false, "Print steps without executing them")

	flowInitCmd.Flags().StringVar(&flowTemplate, "template", "", "Use a built-in template (release, review)")
	flowInitCmd.Flags().StringVarP(&flowInitOutput, "output", "o", "", "Write to this file path instead of stdout or .cloop/flows/")

	rootCmd.AddCommand(flowCmd)
	flowCmd.AddCommand(flowRunCmd, flowInitCmd, flowListCmd)
}
