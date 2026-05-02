// Package commitmsg implements AI-powered conventional commit message generation.
// It reads staged git changes and the active PM task, then asks the configured
// provider to produce a Conventional Commits spec message.
//
// Git hook integration:
//
//	To use as a prepare-commit-msg hook, create .git/hooks/prepare-commit-msg:
//
//	  #!/bin/sh
//	  # Only run when there is no commit message yet (interactive commit)
//	  case "$2" in
//	    merge|squash) exit 0 ;;
//	  esac
//	  msg=$(cloop commit-msg 2>/dev/null)
//	  if [ -n "$msg" ]; then
//	    echo "$msg" > "$1"
//	  fi
//
//	Make it executable: chmod +x .git/hooks/prepare-commit-msg
package commitmsg

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// maxDiffBytes is the maximum number of bytes of staged diff to include in the
// prompt. Diffs beyond this are truncated to avoid overwhelming the context.
const maxDiffBytes = 10_000

// CommitContext holds the data used to generate a commit message.
type CommitContext struct {
	// StagedDiff is the output of `git diff --cached`.
	StagedDiff string
	// ActiveTask is the currently in-progress PM task, if any.
	ActiveTask *pm.Task
	// Goal is the project goal from state.
	Goal string
	// TypeOverride, when non-empty, forces a specific Conventional Commits type
	// (e.g. "feat", "fix", "chore").
	TypeOverride string
}

// Result holds the generated commit message.
type Result struct {
	// Message is the full Conventional Commits message (subject + optional body).
	Message string
}

// CollectDiff runs `git diff --cached` in workDir and returns the output.
// If there are no staged changes the returned string is empty.
func CollectDiff(workDir string) (string, error) {
	out, err := runGit(workDir, "diff", "--cached")
	if err != nil {
		return "", fmt.Errorf("git diff --cached: %w", err)
	}
	diff := out
	if len(diff) > maxDiffBytes {
		diff = diff[:maxDiffBytes] + "\n\n... (diff truncated) ..."
	}
	return diff, nil
}

// BuildPrompt constructs the AI prompt from the commit context.
func BuildPrompt(c *CommitContext) string {
	var b strings.Builder

	b.WriteString("You are an expert software engineer. Generate a single conventional commit message for the staged changes below.\n\n")
	b.WriteString("Requirements:\n")
	b.WriteString("- Follow the Conventional Commits specification (https://www.conventionalcommits.org/)\n")
	b.WriteString("- Format: <type>(<scope>): <description>\n")
	b.WriteString("- Types: feat, fix, refactor, chore, docs, test, style, perf, ci, build\n")
	if c.TypeOverride != "" {
		fmt.Fprintf(&b, "- You MUST use type: %q (user override)\n", c.TypeOverride)
	}
	b.WriteString("- Scope is optional but helpful (e.g. the package or component name)\n")
	b.WriteString("- Description: imperative mood, lowercase, no trailing period, ≤72 chars per line\n")
	b.WriteString("- Add a blank line then a body paragraph when the change needs explanation\n")
	b.WriteString("- Output ONLY the commit message — no commentary, no code fences, no extra text\n\n")

	if c.Goal != "" {
		fmt.Fprintf(&b, "Project goal: %s\n\n", c.Goal)
	}

	if c.ActiveTask != nil {
		fmt.Fprintf(&b, "Active task (#%d): %s\n", c.ActiveTask.ID, c.ActiveTask.Title)
		if c.ActiveTask.Description != "" {
			fmt.Fprintf(&b, "Task description: %s\n", c.ActiveTask.Description)
		}
		b.WriteString("\n")
	}

	b.WriteString("Staged diff:\n```diff\n")
	if c.StagedDiff == "" {
		b.WriteString("(no staged changes)\n")
	} else {
		b.WriteString(c.StagedDiff)
	}
	b.WriteString("\n```\n")

	return b.String()
}

// Generate calls the provider to produce a commit message.
func Generate(ctx context.Context, prov provider.Provider, model string, timeout time.Duration, c *CommitContext) (*Result, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	genCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	prompt := BuildPrompt(c)

	opts := provider.Options{
		Model: model,
	}

	res, err := prov.Complete(genCtx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("provider completion: %w", err)
	}

	msg := strings.TrimSpace(res.Output)
	// Strip accidental code fences that some models emit
	msg = strings.TrimPrefix(msg, "```")
	msg = strings.TrimSuffix(msg, "```")
	msg = strings.TrimSpace(msg)

	return &Result{Message: msg}, nil
}

// runGit executes a git command in workDir and returns combined stdout.
func runGit(workDir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = workDir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
