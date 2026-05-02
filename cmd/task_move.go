package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	moveToDir      string
	moveAdapt      bool
	moveYes        bool
	moveProvider   string
	moveModel      string
	moveTimeout    string
)

// taskRelocateCmd implements `cloop task move <id> --to <dir>`.
// It is registered under the name "relocate" with an alias "move-to" to avoid
// collision with the existing taskMoveCmd (which handles up/down priority).
// The user-facing name is intentionally descriptive; the task spec says
// "cloop task move --to" so we keep "move" as the primary name but gate
// on the presence of --to to route to this handler.
var taskRelocateCmd = &cobra.Command{
	Use:     "relocate <id> --to <dir>",
	Aliases: []string{"move-to"},
	Short:   "Move a task to another cloop project directory",
	Long: `Move a task from the current project to another cloop project directory.

The task is marked as skipped in the source plan (preserving history) and
appended to the destination plan with a new unique ID. Both plans are saved.

Use --adapt to have the AI rewrite the task title and description so they fit
naturally in the destination project's goal and context.

The destination may be:
  - An absolute or relative path to a project directory (must contain .cloop/)
  - A workspace name registered with 'cloop workspace add'
  - A session directory (contains session.json)

Examples:
  cloop task relocate 5 --to ../other-project
  cloop task relocate 5 --to /home/user/projects/backend
  cloop task relocate 5 --to ../frontend --adapt
  cloop task relocate 5 --to ../api --adapt --yes`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if moveToDir == "" {
			return fmt.Errorf("--to <dir> is required")
		}

		srcDir, _ := os.Getwd()

		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		// Load source state.
		srcState, err := state.Load(srcDir)
		if err != nil {
			return err
		}
		if !srcState.PMMode || srcState.Plan == nil || len(srcState.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Resolve destination directory.
		dstDir, err := resolveMoveDestination(moveToDir)
		if err != nil {
			return fmt.Errorf("resolving destination %q: %w", moveToDir, err)
		}

		// Load destination state.
		dstState, err := state.LoadFromDir(dstDir)
		if err != nil {
			return fmt.Errorf("loading destination state: %w", err)
		}
		if dstState == nil {
			return fmt.Errorf("no cloop project found at %s (run 'cloop init' there first)", dstDir)
		}
		if !dstState.PMMode || dstState.Plan == nil {
			return fmt.Errorf("destination project at %s has no PM plan — run 'cloop run --pm' there first", dstDir)
		}

		// Find the task for preview.
		var srcTask *pm.Task
		for _, t := range srcState.Plan.Tasks {
			if t.ID == taskID {
				srcTask = t
				break
			}
		}
		if srcTask == nil {
			return fmt.Errorf("task %d not found", taskID)
		}

		// Build provider if --adapt was requested.
		var prov provider.Provider
		var provOpts provider.Options
		if moveAdapt {
			cfg, cfgErr := config.Load(srcDir)
			if cfgErr != nil {
				return fmt.Errorf("loading config: %w", cfgErr)
			}
			applyEnvOverrides(cfg)

			pName := moveProvider
			if pName == "" {
				pName = cfg.Provider
			}
			if pName == "" && srcState.Provider != "" {
				pName = srcState.Provider
			}
			if pName == "" {
				pName = autoSelectProvider()
			}

			model := moveModel
			if model == "" {
				switch pName {
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
			if model == "" {
				model = srcState.Model
			}

			provCfg := provider.ProviderConfig{
				Name:             pName,
				AnthropicAPIKey:  cfg.Anthropic.APIKey,
				AnthropicBaseURL: cfg.Anthropic.BaseURL,
				OpenAIAPIKey:     cfg.OpenAI.APIKey,
				OpenAIBaseURL:    cfg.OpenAI.BaseURL,
				OllamaBaseURL:    cfg.Ollama.BaseURL,
			}
			prov, err = provider.Build(provCfg)
			if err != nil {
				return fmt.Errorf("provider: %w", err)
			}

			to := 5 * time.Minute
			if moveTimeout != "" {
				to, err = time.ParseDuration(moveTimeout)
				if err != nil {
					return fmt.Errorf("invalid timeout: %w", err)
				}
			}
			provOpts = provider.Options{Model: model, Timeout: to}
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("Moving task %d: %s\n", srcTask.ID, srcTask.Title)
		dimColor.Printf("  From: %s\n", srcDir)
		dimColor.Printf("  To:   %s\n", dstDir)
		if srcTask.Description != "" {
			dimColor.Printf("  Desc: %s\n", truncateStr(srcTask.Description, 100))
		}
		fmt.Println()

		if moveAdapt {
			fmt.Printf("Asking AI to adapt task for destination project...\n\n")
		}

		// Deep-copy source and destination plans to allow preview before saving.
		srcPlanCopy := deepCopyPlan(srcState.Plan)
		dstPlanCopy := deepCopyPlan(dstState.Plan)

		to := 5 * time.Minute
		if moveTimeout != "" {
			to, err = time.ParseDuration(moveTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), to)
		defer cancel()

		result, err := pm.Move(ctx, srcPlanCopy, dstPlanCopy, dstState.Goal, taskID, moveAdapt, prov, provOpts)
		if err != nil {
			return fmt.Errorf("move failed: %w", err)
		}

		// Preview.
		warnColor.Printf("Proposed move:\n\n")
		rolePart := ""
		if result.Task.Role != "" {
			rolePart = fmt.Sprintf(" [%s]", result.Task.Role)
		}
		warnColor.Printf("  Destination task #%d%s: %s\n", result.DstTaskID, rolePart, result.Task.Title)
		if result.Task.Description != "" {
			dimColor.Printf("       %s\n", truncateStr(result.Task.Description, 140))
		}
		if len(result.Task.Tags) > 0 {
			dimColor.Printf("       tags: %s\n", strings.Join(result.Task.Tags, ", "))
		}
		fmt.Println()
		dimColor.Printf("Source task #%d will be marked as skipped.\n\n", taskID)

		// Confirm unless --yes.
		if !moveYes {
			fmt.Printf("Apply move? (y/N): ")
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				return fmt.Errorf("no input received")
			}
			answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if answer != "y" && answer != "yes" {
				fmt.Println("Move cancelled.")
				return nil
			}
		}

		// Commit source: apply the modified copy.
		srcState.Plan = srcPlanCopy
		srcState.WorkDir = srcDir
		if saveErr := srcState.Save(); saveErr != nil {
			return fmt.Errorf("saving source state: %w", saveErr)
		}

		// Commit destination.
		dstState.Plan = dstPlanCopy
		dstState.WorkDir = dstDir
		if saveErr := dstState.Save(); saveErr != nil {
			return fmt.Errorf("saving destination state: %w", saveErr)
		}

		color.New(color.FgGreen).Printf(
			"Task moved: source #%d → destination #%d (%s)\n",
			result.SrcTaskID, result.DstTaskID, result.Task.Title,
		)
		return nil
	},
}

// resolveMoveDestination resolves a --to value to an absolute directory path.
// It accepts absolute paths, relative paths, and workspace names.
func resolveMoveDestination(to string) (string, error) {
	// Try as an absolute or relative path first.
	candidate := to
	if !filepath.IsAbs(candidate) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		candidate = filepath.Join(cwd, candidate)
	}
	candidate = filepath.Clean(candidate)

	// If the path exists, use it directly (whether it has .cloop/ or is a session dir).
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	// Try as a workspace name via the global registry.
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	wsFile := filepath.Join(homedir, ".cloop", "workspaces.json")
	data, err := os.ReadFile(wsFile)
	if err == nil {
		// Simple JSON unmarshal: [{name, path}, ...]
		type wsEntry struct {
			Name string `json:"name"`
			Path string `json:"path"`
		}
		var entries []wsEntry
		if jsonErr := json.Unmarshal(data, &entries); jsonErr == nil {
			for _, e := range entries {
				if strings.EqualFold(e.Name, to) {
					return e.Path, nil
				}
			}
		}
	}

	return "", fmt.Errorf("path %q does not exist and no workspace named %q found", to, to)
}

// deepCopyPlan deep-copies a plan so mutations don't affect the original.
func deepCopyPlan(plan *pm.Plan) *pm.Plan {
	cp := &pm.Plan{
		Goal:    plan.Goal,
		Version: plan.Version,
		Tasks:   make([]*pm.Task, len(plan.Tasks)),
	}
	for i, t := range plan.Tasks {
		tc := *t
		if tc.DependsOn != nil {
			tc.DependsOn = append([]int{}, tc.DependsOn...)
		}
		if tc.Tags != nil {
			tc.Tags = append([]string{}, tc.Tags...)
		}
		cp.Tasks[i] = &tc
	}
	return cp
}

func init() {
	taskRelocateCmd.Flags().StringVar(&moveToDir, "to", "", "Destination project directory or workspace name (required)")
	taskRelocateCmd.Flags().BoolVar(&moveAdapt, "adapt", false, "Use AI to rewrite the task for the destination project's context")
	taskRelocateCmd.Flags().BoolVar(&moveYes, "yes", false, "Skip confirmation prompt and apply immediately")
	taskRelocateCmd.Flags().StringVar(&moveProvider, "provider", "", "AI provider for --adapt (anthropic, openai, ollama, claudecode)")
	taskRelocateCmd.Flags().StringVar(&moveModel, "model", "", "Model override for the AI provider")
	taskRelocateCmd.Flags().StringVar(&moveTimeout, "timeout", "5m", "Timeout for the AI call (e.g. 2m, 300s)")

	taskCmd.AddCommand(taskRelocateCmd)
}
