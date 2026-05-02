package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/plandiff"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	diffStat         bool
	diffSession      bool
	diffNameOnly     bool
	diffPlan         bool
	diffNoAI         bool
	diffPlanProvider string
	diffPlanModel    string
)

var diffCmd = &cobra.Command{
	Use:   "diff [snapshot-a] [snapshot-b]",
	Short: "Show changes in the working directory, session, or plan snapshots",
	Long: `Show git diff for the current project, or compare plan snapshots with AI narrative.

Git diff mode (default, no snapshot args):
  cloop diff                  # all uncommitted changes vs HEAD
  cloop diff --session        # changes since cloop session started
  cloop diff --stat           # summary stats instead of full diff
  cloop diff --name-only      # only file names

Plan snapshot diff mode (when snapshot args provided or --plan flag used):
  cloop diff --plan           # diff the two most recent plan snapshots
  cloop diff 3                # diff snapshot v3 against the latest
  cloop diff 2 5              # diff snapshot v2 against v5
  cloop diff 2 5 --no-ai      # structural diff only, skip AI narrative`,
	Args: cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		// If snapshot args provided or --plan flag, run plan diff mode.
		if diffPlan || len(args) > 0 {
			return runDiffPlan(workdir, args)
		}

		// Git diff mode.
		var gitArgs []string

		if diffSession {
			s, err := state.Load(workdir)
			if err != nil {
				return err
			}
			baseRef, err := commitBeforeTime(workdir, s.CreatedAt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not find session base commit (%v); falling back to HEAD diff\n", err)
				gitArgs = []string{"diff", "HEAD"}
			} else {
				gitArgs = []string{"diff", baseRef}
			}
		} else {
			// Default: all uncommitted changes vs HEAD
			gitArgs = []string{"diff", "HEAD"}
		}

		if diffStat {
			gitArgs = append(gitArgs, "--stat")
		} else if diffNameOnly {
			gitArgs = append(gitArgs, "--name-only")
		}

		gitCmd := exec.Command("git", gitArgs...)
		gitCmd.Dir = workdir
		gitCmd.Stdout = os.Stdout
		gitCmd.Stderr = os.Stderr

		if err := gitCmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				// git diff exits 1 when differences exist — not an error.
				return nil
			}
			return fmt.Errorf("git diff: %w", err)
		}
		return nil
	},
}

// runDiffPlan compares two plan snapshots and optionally generates an AI narrative.
func runDiffPlan(workdir string, args []string) error {
	s, err := state.Load(workdir)
	if err != nil {
		return err
	}

	metas, err := pm.ListSnapshots(workdir)
	if err != nil {
		return fmt.Errorf("listing snapshots: %w", err)
	}
	if len(metas) == 0 {
		return fmt.Errorf("no plan snapshots found — run 'cloop run --pm' to create a plan")
	}
	if len(metas) < 2 && len(args) < 2 {
		return fmt.Errorf("need at least 2 snapshots for a diff (have %d)", len(metas))
	}

	var v1, v2 int
	switch len(args) {
	case 0:
		v1 = metas[len(metas)-2].Version
		v2 = metas[len(metas)-1].Version
	case 1:
		parsed, parseErr := parseVersion(args[0])
		if parseErr != nil {
			return parseErr
		}
		v1 = parsed
		v2 = metas[len(metas)-1].Version
	case 2:
		parsed1, parseErr := parseVersion(args[0])
		if parseErr != nil {
			return parseErr
		}
		parsed2, parseErr := parseVersion(args[1])
		if parseErr != nil {
			return parseErr
		}
		v1, v2 = parsed1, parsed2
	}

	if v1 == v2 {
		return fmt.Errorf("v%d and v%d are the same version", v1, v2)
	}

	snap1, err := pm.LoadSnapshot(workdir, v1)
	if err != nil {
		return fmt.Errorf("loading v%d: %w", v1, err)
	}
	snap2, err := pm.LoadSnapshot(workdir, v2)
	if err != nil {
		return fmt.Errorf("loading v%d: %w", v2, err)
	}

	d := pm.DiffPlans(snap1.Plan, snap2.Plan)
	printPlanDiff(snap1, snap2, d)

	if diffNoAI {
		return nil
	}

	cfg, err := config.Load(workdir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	applyEnvOverrides(cfg)

	pName := diffPlanProvider
	if pName == "" {
		pName = cfg.Provider
	}
	if pName == "" && s.Provider != "" {
		pName = s.Provider
	}
	if pName == "" {
		pName = autoSelectProvider()
	}

	model := diffPlanModel
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
		model = s.Model
	}

	provCfg := provider.ProviderConfig{
		Name:             pName,
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

	dimColor := color.New(color.Faint)
	narrateColor := color.New(color.FgCyan)

	fmt.Println()
	dimColor.Printf("Generating AI narrative (provider: %s)...\n\n", prov.Name())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	narrative, err := plandiff.Narrate(ctx, prov, model, plandiff.NarrateInput{
		Snap1: snap1,
		Snap2: snap2,
		Diff:  d,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: AI narrative failed: %v\n", err)
		dimColor.Printf("(Use --no-ai to skip the narrative.)\n")
		return nil
	}

	narrateColor.Println("AI Narrative")
	fmt.Println(strings.Repeat("─", 72))
	fmt.Println(narrative)
	fmt.Println(strings.Repeat("─", 72))
	return nil
}

// commitBeforeTime returns the SHA of the most recent git commit that existed
// strictly before t. Returns an error if no such commit is found.
func commitBeforeTime(workdir string, t time.Time) (string, error) {
	// Use --before which is exclusive (strictly before), so commits AT t are excluded.
	// Format: ISO 8601 timestamp.
	timeStr := t.UTC().Format(time.RFC3339)
	out, err := exec.Command(
		"git", "-C", workdir,
		"log", "--format=%H", "--before="+timeStr, "-n", "1",
	).Output()
	if err != nil {
		return "", fmt.Errorf("git log: %w", err)
	}
	sha := strings.TrimSpace(string(out))
	if sha == "" {
		return "", fmt.Errorf("no commit found before %s (session may have started before first commit)", timeStr)
	}
	return sha, nil
}

func init() {
	diffCmd.Flags().BoolVar(&diffStat, "stat", false, "Show diff statistics (files changed, insertions, deletions)")
	diffCmd.Flags().BoolVar(&diffNameOnly, "name-only", false, "Show only names of changed files")
	diffCmd.Flags().BoolVar(&diffSession, "session", false, "Diff from when the cloop session was initialized")
	diffCmd.Flags().BoolVar(&diffPlan, "plan", false, "Compare plan snapshots instead of git changes")
	diffCmd.Flags().BoolVar(&diffNoAI, "no-ai", false, "Skip AI narrative and show only structural diff")
	diffCmd.Flags().StringVar(&diffPlanProvider, "provider", "", "AI provider for narrative (anthropic, openai, ollama, claudecode)")
	diffCmd.Flags().StringVar(&diffPlanModel, "model", "", "Model override for narrative provider")
	rootCmd.AddCommand(diffCmd)
}
