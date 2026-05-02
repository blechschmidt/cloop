package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	gh "github.com/blechschmidt/cloop/pkg/github"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/pr"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	prBase     string
	prProvider string
	prModel    string
	prCopy     bool
	prOpen     bool
	prCreate   bool
	prDraft    bool
	prRepo     string
	prToken    string
)

var prCmd = &cobra.Command{
	Use:   "pr",
	Short: "AI-generated pull request title and description",
	Long: `Generate a pull request title and markdown body using AI.

cloop pr inspects completed PM tasks, git log, and git diff since a base
branch/SHA, then asks the configured provider to write a well-structured
PR description covering summary, motivation, changes, and testing notes.

Examples:
  cloop pr                               # generate PR description (base: main)
  cloop pr --base develop                # compare against develop branch
  cloop pr --base abc1234                # compare against a specific commit
  cloop pr --copy                        # copy result to clipboard
  cloop pr --open                        # open GitHub new-PR page in browser
  cloop pr --create                      # create the PR via GitHub API
  cloop pr --create --draft              # create as draft PR
  cloop pr --provider anthropic --model claude-opus-4-6`,
	RunE: runPR,
}

func runPR(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()

	// Load state (non-fatal; we can generate without a PM plan)
	s, _ := state.Load(workdir)

	cfg, err := config.Load(workdir)
	if err != nil {
		cfg = &config.Config{}
	}
	applyEnvOverrides(cfg)

	// Resolve provider
	pName := prProvider
	if pName == "" {
		pName = cfg.Provider
	}
	if pName == "" && s != nil && s.Provider != "" {
		pName = s.Provider
	}
	if pName == "" {
		pName = autoSelectProvider()
	}

	model := prModel
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

	// Collect completed tasks from PM plan
	var completedTasks []*pm.Task
	goal := ""
	if s != nil {
		goal = s.Goal
		if s.Plan != nil {
			for _, t := range s.Plan.Tasks {
				if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
					completedTasks = append(completedTasks, t)
				}
			}
		}
	}

	base := prBase
	if base == "" {
		base = "main"
	}

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)

	bold.Printf("\nGenerating PR description with %s (base: %s)...\n\n", prov.Name(), base)

	prCtx, err := pr.Collect(workdir, base, completedTasks, goal)
	if err != nil {
		return fmt.Errorf("collecting PR context: %w", err)
	}

	dim.Printf("Commits: %d lines  |  Diff: %d bytes  |  Completed tasks: %d\n\n",
		countLines(prCtx.GitLog),
		len(prCtx.GitDiff),
		len(prCtx.CompletedTasks),
	)

	genCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := pr.Generate(genCtx, prov, model, 2*time.Minute, prCtx)
	if err != nil {
		return fmt.Errorf("generating PR description: %w", err)
	}

	// ── Print result ────────────────────────────────────────────────────────
	fmt.Println()
	cyan.Println("╔══ PULL REQUEST ══════════════════════════════════════════════════")
	bold.Printf("║  Title: %s\n", result.Title)
	cyan.Println("╠══ Body ══════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println(result.Body)
	fmt.Println()
	cyan.Println("╚══════════════════════════════════════════════════════════════════")
	fmt.Println()

	// ── Copy to clipboard ───────────────────────────────────────────────────
	if prCopy {
		if err := copyTextToClipboard(result.Title + "\n\n" + result.Body); err != nil {
			color.New(color.FgYellow).Printf("Warning: clipboard copy failed: %v\n", err)
		} else {
			green.Println("Copied to clipboard.")
		}
	}

	// ── Open browser ────────────────────────────────────────────────────────
	if prOpen {
		ghURL, err := buildGitHubNewPRURL(workdir, base, result.Title, result.Body)
		if err != nil {
			color.New(color.FgYellow).Printf("Warning: could not build GitHub URL: %v\n", err)
		} else {
			openBrowser(ghURL)
			green.Printf("Opened browser.\n")
		}
	}

	// ── Create PR via GitHub API ─────────────────────────────────────────────
	if prCreate {
		client, err := resolveGitHubForPR(cfg)
		if err != nil {
			return fmt.Errorf("GitHub client: %w", err)
		}

		headBranch, err := currentBranch(workdir)
		if err != nil {
			return fmt.Errorf("detecting current branch: %w", err)
		}

		bold.Printf("Creating PR on github.com/%s  (%s → %s)...\n", client.Repo, headBranch, base)

		created, err := client.CreatePR(headBranch, base, result.Title, result.Body, prDraft)
		if err != nil {
			return fmt.Errorf("creating PR: %w", err)
		}

		green.Printf("PR created: %s\n", created.HTMLURL)
	}

	return nil
}

// ── helpers ────────────────────────────────────────────────────────────────

func countLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

func copyTextToClipboard(text string) error {
	var cmd *exec.Cmd
	// Try pbcopy (macOS), xclip, or xsel (Linux)
	if _, err := exec.LookPath("pbcopy"); err == nil {
		cmd = exec.Command("pbcopy")
	} else if _, err := exec.LookPath("xclip"); err == nil {
		cmd = exec.Command("xclip", "-selection", "clipboard")
	} else if _, err := exec.LookPath("xsel"); err == nil {
		cmd = exec.Command("xsel", "--clipboard", "--input")
	} else {
		return fmt.Errorf("no clipboard utility found (install xclip, xsel, or pbcopy)")
	}
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

func buildGitHubNewPRURL(workdir, base, title, body string) (string, error) {
	repo, err := gh.DetectRepo()
	if err != nil {
		return "", fmt.Errorf("cannot detect GitHub repo: %w", err)
	}

	headBranch, err := currentBranch(workdir)
	if err != nil {
		headBranch = "HEAD"
	}

	params := url.Values{}
	params.Set("quick_pull", "1")
	params.Set("expand", "1")
	params.Set("title", title)
	bodyForURL := body
	if len(bodyForURL) > 2000 {
		bodyForURL = bodyForURL[:2000] + "\n\n*(body truncated — paste full description)*"
	}
	params.Set("body", bodyForURL)

	return fmt.Sprintf("https://github.com/%s/compare/%s...%s?%s",
		repo, base, headBranch, params.Encode()), nil
}

func currentBranch(workdir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = workdir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func resolveGitHubForPR(cfg *config.Config) (*gh.Client, error) {
	token := prToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = cfg.GitHub.Token
	}
	repo := prRepo
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

// ── init ───────────────────────────────────────────────────────────────────

func init() {
	prCmd.Flags().StringVar(&prBase, "base", "main", "Base branch or SHA to compare against")
	prCmd.Flags().StringVar(&prProvider, "provider", "", "Provider to use (claudecode, anthropic, openai, ollama)")
	prCmd.Flags().StringVar(&prModel, "model", "", "Model to use")
	prCmd.Flags().BoolVar(&prCopy, "copy", false, "Copy the generated PR description to clipboard")
	prCmd.Flags().BoolVar(&prOpen, "open", false, "Open GitHub new-PR page in browser with pre-filled title/body")
	prCmd.Flags().BoolVar(&prCreate, "create", false, "Create the PR via GitHub API")
	prCmd.Flags().BoolVar(&prDraft, "draft", false, "Create as draft PR (requires --create)")
	prCmd.Flags().StringVar(&prRepo, "repo", "", "GitHub repo in owner/repo format (for --create, overrides auto-detect)")
	prCmd.Flags().StringVar(&prToken, "token", "", "GitHub token (for --create, overrides GITHUB_TOKEN env)")

	rootCmd.AddCommand(prCmd)
}
