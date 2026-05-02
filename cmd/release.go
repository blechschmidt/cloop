package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	gh "github.com/blechschmidt/cloop/pkg/github"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/release"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	releaseDryRun       bool
	releasePush         bool
	releaseGitHubCreate bool
	releaseTagPrefix    string
	releaseProvider     string
	releaseModel        string
	releaseGitHubToken  string
	releaseGitHubRepo   string
	releasePushRemote   string
)

var releaseCmd = &cobra.Command{
	Use:   "release [patch|minor|major|auto]",
	Short: "Semantic versioning and release automation",
	Long: `Create a new semantic version release from the current cloop project.

Analyzes completed tasks and git history to compute the next version,
generates polished AI-narrated release notes, creates an annotated git tag,
and optionally pushes the tag and creates a GitHub release.

Bump modes:
  patch  — bug fixes and minor improvements (default)
  minor  — new features, backwards compatible
  major  — breaking changes or major milestones
  auto   — infer bump from completed task titles/descriptions and git log

Examples:
  cloop release patch                          # bump patch, create tag
  cloop release minor --push                   # bump minor, tag, push to origin
  cloop release auto --dry-run                 # infer bump, preview notes
  cloop release major --push --github-release  # tag, push, create GitHub release
  cloop release auto --tag-prefix "release-"   # custom tag prefix
  cloop release patch --provider anthropic     # use specific AI provider`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRelease,
}

func runRelease(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()

	// ── Load config and state ────────────────────────────────────────────────
	cfg, err := config.Load(workdir)
	if err != nil {
		cfg = &config.Config{}
	}
	applyEnvOverrides(cfg)

	s, _ := state.Load(workdir)

	// ── Resolve provider ─────────────────────────────────────────────────────
	pName := releaseProvider
	if pName == "" {
		pName = cfg.Provider
	}
	if pName == "" && s != nil && s.Provider != "" {
		pName = s.Provider
	}
	if pName == "" {
		pName = autoSelectProvider()
	}

	model := releaseModel
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
	if model == "" && s != nil {
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

	// ── Determine bump ───────────────────────────────────────────────────────
	bump := "patch"
	if len(args) > 0 {
		bump = strings.ToLower(strings.TrimSpace(args[0]))
	}

	switch bump {
	case "patch", "minor", "major":
		// explicit — use as-is
	case "auto", "":
		bump = inferBumpFromState(workdir, s)
	default:
		return fmt.Errorf("invalid bump mode %q: choose patch, minor, major, or auto", bump)
	}

	tagPrefix := releaseTagPrefix

	// ── Output setup ─────────────────────────────────────────────────────────
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.Faint)

	if releaseDryRun {
		yellow.Println("\n[DRY RUN] No git tags will be created or pushed.")
	}

	bold.Printf("\nGenerating %s release with %s (bump: %s)...\n\n", tagPrefix+"<next>", prov.Name(), bump)

	// ── Generate release ─────────────────────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rel, err := release.Generate(ctx, prov, model, workdir, tagPrefix, bump, releaseDryRun)
	if err != nil {
		return fmt.Errorf("release generation failed: %w", err)
	}

	// ── Print release notes ──────────────────────────────────────────────────
	cyan.Println("╔══ RELEASE NOTES ═══════════════════════════════════════════════════")
	bold.Printf("║  Tag:      %s\n", rel.Tag)
	bold.Printf("║  Bump:     %s", rel.Bump)
	if rel.PreviousTag != "" {
		dim.Printf("  (was %s)", rel.PreviousTag)
	}
	fmt.Println()
	if releaseDryRun {
		yellow.Printf("║  Status:   dry-run (no tag created)\n")
	} else {
		green.Printf("║  Status:   tag created ✓\n")
	}
	cyan.Println("╠══ Notes ═══════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println(rel.Notes)
	fmt.Println()
	cyan.Println("╚════════════════════════════════════════════════════════════════════")
	fmt.Println()

	if releaseDryRun {
		yellow.Println("Dry-run complete. Run without --dry-run to create the tag.")
		return nil
	}

	// ── Push tag ─────────────────────────────────────────────────────────────
	if releasePush {
		remote := releasePushRemote
		if remote == "" {
			remote = "origin"
		}
		bold.Printf("Pushing tag %s to %s...\n", rel.Tag, remote)
		if err := release.PushTag(workdir, rel.Tag, remote); err != nil {
			return fmt.Errorf("pushing tag: %w", err)
		}
		rel.TagPushed = true
		green.Printf("Tag pushed to %s.\n\n", remote)
	}

	// ── GitHub release ────────────────────────────────────────────────────────
	if releaseGitHubCreate {
		if !releasePush {
			yellow.Println("Warning: --github-release without --push; the tag may not exist on GitHub yet.")
		}
		client, ghErr := resolveGitHubForRelease(cfg)
		if ghErr != nil {
			return fmt.Errorf("GitHub client: %w", ghErr)
		}
		bold.Printf("Creating GitHub release %s on %s...\n", rel.Tag, client.Repo)
		ghRel, ghErr := client.CreateRelease(rel.Tag, rel.Tag, rel.Notes, false)
		if ghErr != nil {
			return fmt.Errorf("creating GitHub release: %w", ghErr)
		}
		rel.GitHubURL = ghRel.HTMLURL
		green.Printf("GitHub release created: %s\n\n", rel.GitHubURL)
	}

	// ── Summary ───────────────────────────────────────────────────────────────
	bold.Printf("Release %s complete.\n", rel.Tag)
	if rel.TagPushed {
		dim.Printf("  Tag pushed to remote.\n")
	} else {
		dim.Printf("  Run `git push origin %s` to publish the tag.\n", rel.Tag)
	}
	if rel.GitHubURL != "" {
		dim.Printf("  GitHub release: %s\n", rel.GitHubURL)
	}
	fmt.Println()

	return nil
}

// inferBumpFromState collects completed tasks and git log to auto-detect the bump level.
func inferBumpFromState(workDir string, s *state.ProjectState) string {
	var tasks []*pm.Task
	if s != nil && s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskDone {
				tasks = append(tasks, t)
			}
		}
	}

	// Collect recent git log for keyword analysis.
	out, err := gitLogForBump(workDir)
	if err != nil {
		out = ""
	}

	bump := release.InferBump(tasks, out)
	color.New(color.Faint).Printf("Auto-detected bump: %s\n\n", bump)
	return bump
}

// gitLogForBump returns the last 50 git commit lines for InferBump analysis.
func gitLogForBump(workDir string) (string, error) {
	c := exec.Command("git", "log", "--oneline", "-50")
	c.Dir = workDir
	out, err := c.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func resolveGitHubForRelease(cfg *config.Config) (*gh.Client, error) {
	token := releaseGitHubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = cfg.GitHub.Token
	}
	repo := releaseGitHubRepo
	if repo == "" {
		repo = cfg.GitHub.Repo
	}
	if repo == "" {
		detected, err := gh.DetectRepo()
		if err != nil {
			return nil, fmt.Errorf("no GitHub repo specified (use --repo owner/repo): %w", err)
		}
		repo = detected
	}
	return gh.New(token, repo), nil
}

func init() {
	releaseCmd.Flags().BoolVar(&releaseDryRun, "dry-run", false, "Preview release notes and computed tag without creating anything")
	releaseCmd.Flags().BoolVar(&releasePush, "push", false, "Push the created tag to the remote (default remote: origin)")
	releaseCmd.Flags().StringVar(&releasePushRemote, "remote", "origin", "Git remote to push the tag to (used with --push)")
	releaseCmd.Flags().BoolVar(&releaseGitHubCreate, "github-release", false, "Create a GitHub release via the API (requires GITHUB_TOKEN or config)")
	releaseCmd.Flags().StringVar(&releaseTagPrefix, "tag-prefix", "v", "Prefix to prepend to the version number (e.g. \"v\" → \"v1.2.3\")")
	releaseCmd.Flags().StringVar(&releaseProvider, "provider", "", "Provider to use (claudecode, anthropic, openai, ollama)")
	releaseCmd.Flags().StringVar(&releaseModel, "model", "", "Model to use for release note generation")
	releaseCmd.Flags().StringVar(&releaseGitHubToken, "token", "", "GitHub token (overrides GITHUB_TOKEN env and config)")
	releaseCmd.Flags().StringVar(&releaseGitHubRepo, "repo", "", "GitHub repo in owner/repo format (overrides auto-detect)")
	rootCmd.AddCommand(releaseCmd)
}
