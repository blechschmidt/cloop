package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/eval"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	evalProvider string
	evalModel    string
	evalTimeout  string
	evalRubric   string
	evalTaskID   int
)

var evalCmd = &cobra.Command{
	Use:   "eval [task-id]",
	Short: "Score completed task output against a quality rubric",
	Long: `Evaluate the AI output for a completed task against a configurable rubric.

Each criterion is scored 1-10 by the AI judge; an overall weighted average is
computed and the result is saved to .cloop/evals/<task-id>.json.

Default rubric covers: correctness (35%), completeness (30%), code quality (20%),
conciseness (15%). Supply --rubric to use a custom YAML rubric file.

Examples:
  cloop eval 3                          # score task 3 with default rubric
  cloop eval --task 5 --rubric r.yaml   # score task 5 with custom rubric
  cloop eval 2 --provider anthropic     # force provider`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// Resolve task ID from positional arg or --task flag.
		taskID := evalTaskID
		if len(args) > 0 {
			n, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid task-id %q: %w", args[0], err)
			}
			taskID = n
		}
		if taskID == 0 {
			return fmt.Errorf("task-id is required (positional arg or --task flag)")
		}

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}
		if s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no plan found — run 'cloop run --pm' first")
		}

		// Find task.
		var task *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == taskID {
				task = t
				break
			}
		}
		if task == nil {
			return fmt.Errorf("task %d not found in current plan", taskID)
		}
		if task.Status != pm.TaskDone {
			return fmt.Errorf("task %d is not done (status: %s) — only done tasks can be evaluated", taskID, task.Status)
		}

		// Load task output: prefer artifact file, fall back to task.Result.
		output := loadTaskOutput(workdir, task)
		if output == "" {
			return fmt.Errorf("no output found for task %d — run the task first", taskID)
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Resolve provider.
		providerName := evalProvider
		if providerName == "" {
			providerName = cfg.Provider
		}
		if providerName == "" {
			providerName = s.Provider
		}
		if providerName == "" {
			providerName = autoSelectProvider()
		}

		// Resolve model.
		model := evalModel
		if model == "" {
			model = s.Model
		}
		if model == "" {
			switch providerName {
			case "anthropic":
				model = cfg.Anthropic.Model
			case "openai":
				model = cfg.OpenAI.Model
			case "ollama":
				model = cfg.Ollama.Model
			case "claudecode":
				model = cfg.ClaudeCode.Model
			}
		}

		provCfg := provider.ProviderConfig{
			Name:             providerName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		timeout := 60 * time.Second
		if evalTimeout != "" {
			timeout, err = time.ParseDuration(evalTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		// Load rubric.
		rubric := eval.DefaultRubric()
		if evalRubric != "" {
			rubric, err = loadRubricYAML(evalRubric)
			if err != nil {
				return fmt.Errorf("loading rubric: %w", err)
			}
		}

		dimColor := color.New(color.Faint)
		dimColor.Printf("Evaluating task %d: %s\n", task.ID, task.Title)
		dimColor.Printf("Provider: %s  Criteria: %d\n\n", prov.Name(), len(rubric.Criteria))

		ctx := context.Background()
		result, err := eval.Evaluate(ctx, prov, model, timeout, workdir, task, output, rubric)
		if err != nil {
			return fmt.Errorf("evaluation failed: %w", err)
		}

		printEvalTable(result)
		return nil
	},
}

// loadTaskOutput reads the full AI output for a task.
// If ArtifactPath is set and readable, returns its body (stripping YAML frontmatter).
// Falls back to task.Result.
func loadTaskOutput(workdir string, task *pm.Task) string {
	if task.ArtifactPath != "" {
		absPath := task.ArtifactPath
		if !isAbsPath(absPath) {
			absPath = workdir + "/" + task.ArtifactPath
		}
		data, err := os.ReadFile(absPath)
		if err == nil {
			return stripFrontmatter(string(data))
		}
	}
	return task.Result
}

func isAbsPath(p string) bool {
	return len(p) > 0 && p[0] == '/'
}

// stripFrontmatter removes YAML frontmatter (--- ... ---) from the beginning of s.
func stripFrontmatter(s string) string {
	if len(s) < 4 || s[:3] != "---" {
		return s
	}
	// Find closing ---
	rest := s[3:]
	idx := -1
	for i := 0; i < len(rest)-2; i++ {
		if rest[i] == '\n' && rest[i+1] == '-' && i+4 <= len(rest) && rest[i+1:i+4] == "---" {
			idx = i + 4
			break
		}
	}
	if idx < 0 {
		return s
	}
	body := rest[idx:]
	// Trim leading newlines.
	for len(body) > 0 && body[0] == '\n' {
		body = body[1:]
	}
	return body
}

// loadRubricYAML parses a YAML rubric file into an eval.Rubric.
func loadRubricYAML(path string) (eval.Rubric, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return eval.Rubric{}, err
	}
	var r eval.Rubric
	if err := yaml.Unmarshal(data, &r); err != nil {
		return eval.Rubric{}, fmt.Errorf("parse rubric YAML: %w", err)
	}
	if len(r.Criteria) == 0 {
		return eval.Rubric{}, fmt.Errorf("rubric file has no criteria")
	}
	return r, nil
}

// printEvalTable renders the evaluation result as a formatted table.
func printEvalTable(r *eval.EvalResult) {
	header := color.New(color.FgCyan, color.Bold)
	boldColor := color.New(color.Bold)
	dimColor := color.New(color.Faint)

	header.Printf("Evaluation: Task %d — %s\n", r.TaskID, r.TaskTitle)
	header.Printf("══════════════════════════════════════════════\n\n")

	// Table header.
	boldColor.Printf("%-20s  %6s  %6s  %s\n", "CRITERION", "WEIGHT", "SCORE", "RATIONALE")
	dimColor.Printf("%-20s  %6s  %6s  %s\n", "─────────────────", "──────", "─────", "─────────────────────────────────────────")

	for _, s := range r.Scores {
		scoreColor := color.New(color.FgGreen)
		if s.Value <= 4 {
			scoreColor = color.New(color.FgRed)
		} else if s.Value <= 6 {
			scoreColor = color.New(color.FgYellow)
		}

		rationale := s.Rationale
		const maxRat = 60
		if len(rationale) > maxRat {
			rationale = rationale[:maxRat] + "..."
		}

		fmt.Printf("%-20s  %5.0f%%  ", s.Criterion.Name, s.Criterion.Weight*100)
		scoreColor.Printf("%5d  ", s.Value)
		dimColor.Printf("%s\n", rationale)
	}

	fmt.Printf("\n")

	// Overall score.
	boldColor.Printf("Weighted average: ")
	overallColor := color.New(color.FgGreen, color.Bold)
	if r.Weighted < 5 {
		overallColor = color.New(color.FgRed, color.Bold)
	} else if r.Weighted < 7 {
		overallColor = color.New(color.FgYellow, color.Bold)
	}
	overallColor.Printf("%.2f / 10\n", r.Weighted)
	dimColor.Printf("Saved to .cloop/evals/%d.json  (evaluated at %s)\n\n", r.TaskID, r.EvaluatedAt.Format(time.RFC3339))

	// Full rationales section.
	boldColor.Printf("Detailed Rationales\n")
	dimColor.Printf("───────────────────\n")
	for _, s := range r.Scores {
		boldColor.Printf("  %s (%d/10)\n", s.Criterion.Name, s.Value)
		fmt.Printf("    %s\n\n", s.Rationale)
	}
}

func init() {
	evalCmd.Flags().StringVar(&evalProvider, "provider", "", "Provider to use for scoring")
	evalCmd.Flags().StringVar(&evalModel, "model", "", "Model to use for scoring")
	evalCmd.Flags().StringVar(&evalTimeout, "timeout", "", "Timeout per criterion call (e.g. 60s, 2m)")
	evalCmd.Flags().StringVar(&evalRubric, "rubric", "", "Path to custom rubric YAML file")
	evalCmd.Flags().IntVar(&evalTaskID, "task", 0, "Task ID to evaluate (alternative to positional arg)")
	rootCmd.AddCommand(evalCmd)
}
