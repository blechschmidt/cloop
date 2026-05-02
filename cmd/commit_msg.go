package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/commitmsg"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	commitMsgProvider string
	commitMsgModel    string
	commitMsgType     string
	commitMsgCommit   bool
	commitMsgCopy     bool
)

var commitMsgCmd = &cobra.Command{
	Use:   "commit-msg",
	Short: "AI-generated conventional commit message from staged changes and task context",
	Long: `Generate a Conventional Commits message from staged git changes and the
active PM task.

cloop commit-msg reads:
  - git diff --cached  (staged changes)
  - the in_progress task from .cloop/state.json (if PM mode is active)

It sends both to the AI provider and prints a ready-to-use commit message
following the Conventional Commits spec (type(scope): description + body).

Examples:
  cloop commit-msg                          # print generated message
  cloop commit-msg --commit                 # commit with the generated message
  cloop commit-msg --type feat              # force commit type to "feat"
  cloop commit-msg --copy                   # copy message to clipboard

Git hook integration — add to .git/hooks/prepare-commit-msg:

  #!/bin/sh
  case "$2" in merge|squash) exit 0 ;; esac
  msg=$(cloop commit-msg 2>/dev/null)
  [ -n "$msg" ] && echo "$msg" > "$1"

Make it executable: chmod +x .git/hooks/prepare-commit-msg`,
	RunE: runCommitMsg,
}

func runCommitMsg(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()

	// Load config and state (non-fatal)
	cfg, err := config.Load(workdir)
	if err != nil {
		cfg = &config.Config{}
	}
	applyEnvOverrides(cfg)

	s, _ := state.Load(workdir)

	// Resolve provider
	pName := commitMsgProvider
	if pName == "" {
		pName = cfg.Provider
	}
	if pName == "" && s != nil && s.Provider != "" {
		pName = s.Provider
	}
	if pName == "" {
		pName = autoSelectProvider()
	}

	model := commitMsgModel
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

	// Collect staged diff
	diff, err := commitmsg.CollectDiff(workdir)
	if err != nil {
		return fmt.Errorf("collecting staged diff: %w", err)
	}

	// Find active (in_progress) task
	var activeTask *pm.Task
	goal := ""
	if s != nil {
		goal = s.Goal
		if s.Plan != nil {
			for _, t := range s.Plan.Tasks {
				if t.Status == pm.TaskInProgress {
					activeTask = t
					break
				}
			}
		}
	}

	// Build commit context
	c := &commitmsg.CommitContext{
		StagedDiff:   diff,
		ActiveTask:   activeTask,
		Goal:         goal,
		TypeOverride: commitMsgType,
	}

	// Print status header to stderr so that when used as a git hook only the
	// message goes to stdout.
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	fmt.Fprintf(os.Stderr, "\n")
	bold.Fprintf(os.Stderr, "Generating commit message with %s...\n", prov.Name())
	if activeTask != nil {
		dim.Fprintf(os.Stderr, "Active task: #%d %s\n", activeTask.ID, activeTask.Title)
	}
	diffLines := strings.Count(diff, "\n") + 1
	if diff == "" {
		diffLines = 0
	}
	dim.Fprintf(os.Stderr, "Staged diff: %d lines\n\n", diffLines)

	genCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	result, err := commitmsg.Generate(genCtx, prov, model, 90*time.Second, c)
	if err != nil {
		return fmt.Errorf("generating commit message: %w", err)
	}

	// ── Print result ─────────────────────────────────────────────────────────
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)

	fmt.Fprintf(os.Stderr, "\n")
	cyan.Fprintln(os.Stderr, "╔══ COMMIT MESSAGE ════════════════════════════════════════════════")
	fmt.Fprintln(os.Stderr, result.Message)
	cyan.Fprintln(os.Stderr, "╚══════════════════════════════════════════════════════════════════")
	fmt.Fprintf(os.Stderr, "\n")

	// Print the raw message to stdout (useful for hook mode)
	fmt.Println(result.Message)

	// ── Copy to clipboard ────────────────────────────────────────────────────
	if commitMsgCopy {
		if err := copyTextToClipboard(result.Message); err != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr, "Warning: clipboard copy failed: %v\n", err)
		} else {
			green.Fprintln(os.Stderr, "Copied to clipboard.")
		}
	}

	// ── Commit directly ──────────────────────────────────────────────────────
	if commitMsgCommit {
		if diff == "" {
			return fmt.Errorf("no staged changes to commit")
		}
		gitCmd := exec.Command("git", "commit", "-m", result.Message)
		gitCmd.Dir = workdir
		gitCmd.Stdout = os.Stdout
		gitCmd.Stderr = os.Stderr
		if err := gitCmd.Run(); err != nil {
			return fmt.Errorf("git commit failed: %w", err)
		}
		green.Fprintln(os.Stderr, "Committed.")
	}

	return nil
}

func init() {
	commitMsgCmd.Flags().StringVar(&commitMsgProvider, "provider", "", "Provider to use (claudecode, anthropic, openai, ollama)")
	commitMsgCmd.Flags().StringVar(&commitMsgModel, "model", "", "Model to use")
	commitMsgCmd.Flags().StringVar(&commitMsgType, "type", "", "Override commit type (feat, fix, chore, docs, ...)")
	commitMsgCmd.Flags().BoolVar(&commitMsgCommit, "commit", false, "Commit staged changes with the generated message")
	commitMsgCmd.Flags().BoolVar(&commitMsgCopy, "copy", false, "Copy the generated message to clipboard")

	rootCmd.AddCommand(commitMsgCmd)
}
