package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/profile"
	"github.com/blechschmidt/cloop/pkg/state"
	clooptemplate "github.com/blechschmidt/cloop/pkg/template"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	maxSteps     int
	instructions string
	model        string
	initProvider string
	initPMMode   bool
	initTemplate string
	initProfile  string
)

var initCmd = &cobra.Command{
	Use:   "init [goal]",
	Short: "Initialize a new cloop project with a goal",
	Long: `Set the project goal that cloop will work towards autonomously.

Examples:
  cloop init "Build a Go REST API with SQLite, JWT auth, and user CRUD"
  cloop init --max-steps 20 "Refactor the codebase to use clean architecture"
  cloop init --provider anthropic --model claude-opus-4-6 "Build a CLI tool"
  cloop init --provider ollama --model llama3.2 "Write unit tests for this package"
  cloop init --template web-app "My e-commerce site"
  cloop init --template api-service
  cloop init --template security-audit`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Resolve template (if requested) before determining goal.
		var tmpl *clooptemplate.Template
		if initTemplate != "" {
			var err error
			tmpl, err = clooptemplate.Get(initTemplate)
			if err != nil {
				return err
			}
		}

		// Determine goal: explicit arg > template default > error.
		var goal string
		if len(args) == 1 {
			goal = args[0]
		} else if tmpl != nil {
			goal = tmpl.Goal
		} else {
			return fmt.Errorf("a goal argument is required when --template is not specified")
		}

		// Check for existing state
		if _, err := state.Load(workdir); err == nil {
			color.Yellow("⚠ Existing cloop project found. Overwriting.")
		}

		s, err := state.Init(workdir, goal, maxSteps)
		if err != nil {
			return fmt.Errorf("failed to initialize: %w", err)
		}

		// Apply named profile before explicit flags so flags always win.
		activeProfileName := initProfile
		if activeProfileName == "" {
			activeProfileName = profile.GetActive()
		}
		if activeProfileName != "" {
			if prof, err := profile.Get(activeProfileName); err == nil {
				cfg, _ := config.Load(workdir)
				if cfg == nil {
					cfg = config.Default()
				}
				profile.Apply(*prof, cfg)
				if s.Provider == "" && cfg.Provider != "" {
					s.Provider = cfg.Provider
				}
				// Derive model from the profile-applied config if not already set.
				if s.Model == "" {
					switch cfg.Provider {
					case "anthropic":
						s.Model = cfg.Anthropic.Model
					case "openai":
						s.Model = cfg.OpenAI.Model
					case "ollama":
						s.Model = cfg.Ollama.Model
					case "claudecode":
						s.Model = cfg.ClaudeCode.Model
					}
				}
			} else {
				color.Yellow("⚠ profile %q not found: %v", activeProfileName, err)
			}
		}

		if instructions != "" {
			s.Instructions = instructions
		}
		if model != "" {
			s.Model = model
		}
		if initProvider != "" {
			s.Provider = initProvider
		}
		if initPMMode {
			s.PMMode = true
		}
		// Apply template: pre-populate the plan with template tasks, enabling
		// PM mode automatically so 'cloop run' executes them directly without
		// calling the AI decomposition step.
		if tmpl != nil {
			s.PMMode = true
			s.Plan = tmpl.ToPlan()
			// Allow a custom goal to override the template default.
			if len(args) == 1 {
				s.Plan.Goal = goal
			}
		}
		if err := s.Save(); err != nil {
			return err
		}

		// Write config.yaml if provider was specified and config doesn't exist
		if initProvider != "" {
			cfg, _ := config.Load(workdir)
			if cfg == nil {
				cfg = config.Default()
			}
			cfg.Provider = initProvider
			if err := config.Save(workdir, cfg); err != nil {
				color.Yellow("⚠ Could not write config.yaml: %v", err)
			}
		} else {
			// Write default config if none exists
			config.WriteDefault(workdir)
		}

		// Ensure .cloop/env.yaml is in .gitignore so secrets are not committed.
		ensureGitignore(workdir, ".cloop/env.yaml")

		color.Green("✓ cloop initialized")
		fmt.Printf("  Goal: %s\n", goal)
		if tmpl != nil {
			fmt.Printf("  Template: %s (%s)\n", tmpl.Name, tmpl.Description)
			fmt.Printf("  Tasks: %d pre-defined tasks loaded (skipping AI decomposition)\n", len(tmpl.Tasks))
		}
		fmt.Printf("  Max steps: %d\n", maxSteps)
		fmt.Printf("  State: %s\n", state.StatePath(workdir))
		fmt.Printf("  Config: %s\n", config.ConfigPath(workdir))

		prov := initProvider
		if prov == "" {
			prov = "claudecode (default)"
		}
		fmt.Printf("  Provider: %s\n", prov)

		if model != "" {
			fmt.Printf("  Model: %s\n", model)
		}
		if instructions != "" {
			fmt.Printf("  Instructions: %s\n", instructions)
		}
		fmt.Printf("\nRun 'cloop run' to start.\n")
		if s.PMMode && tmpl != nil {
			fmt.Printf("PM mode enabled — pre-defined tasks loaded from template '%s'. Run 'cloop run' to execute them.\n", tmpl.Name)
		} else if s.PMMode {
			fmt.Printf("PM mode enabled — run 'cloop run' to decompose and execute tasks.\n")
		} else {
			fmt.Printf("Use 'cloop run --pm' for product manager mode (task decomposition).\n")
		}
		return nil
	},
}

// ensureGitignore appends entry to .gitignore in workDir if it is not already present.
// Creates the file if it does not exist.
func ensureGitignore(workDir, entry string) {
	giPath := workDir + "/.gitignore"
	data, _ := os.ReadFile(giPath)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == entry {
			return // already present
		}
	}
	f, err := os.OpenFile(giPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	// Ensure new line separation.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		f.WriteString("\n")
	}
	f.WriteString(entry + "\n")
}

func init() {
	initCmd.Flags().IntVar(&maxSteps, "max-steps", 0, "Maximum number of autonomous steps (0 = unlimited)")
	initCmd.Flags().StringVar(&instructions, "instructions", "", "Additional instructions/constraints for the AI")
	initCmd.Flags().StringVar(&model, "model", "", "Model to use (provider-specific)")
	initCmd.Flags().StringVar(&initProvider, "provider", "", "AI provider: anthropic, openai, ollama, claudecode (default)")
	initCmd.Flags().BoolVar(&initPMMode, "pm", false, "Enable product manager mode (task decomposition) by default for this project")
	initCmd.Flags().StringVar(&initTemplate, "template", "", "Bootstrap from a built-in template ("+clooptemplate.NamesString()+")")
	initCmd.Flags().StringVar(&initProfile, "profile", "", "Named configuration profile to apply (overrides the active profile)")
	rootCmd.AddCommand(initCmd)
}
