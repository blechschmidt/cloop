// Package pr implements AI-powered pull request description generation.
// It collects completed PM tasks, git diff, and git log since a base ref,
// then asks the configured provider to write a PR title and markdown body.
package pr

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// PRContext holds the raw data used to generate a pull request description.
type PRContext struct {
	// Base is the branch or SHA used as the comparison base.
	Base string
	// HeadSHA is the resolved HEAD SHA at collection time.
	HeadSHA string
	// GitLog is the output of `git log --oneline <base>..HEAD`.
	GitLog string
	// GitDiff is the output of `git diff <base>..HEAD` (possibly truncated).
	GitDiff string
	// CompletedTasks are PM tasks with status == done, collected from the plan.
	CompletedTasks []*pm.Task
	// Goal is the project goal from state.
	Goal string
}

// PRResult holds the generated pull request title and body.
type PRResult struct {
	Title string
	Body  string
}

// maxDiffBytes is the maximum number of bytes of git diff to include in the
// prompt. Diffs beyond this are truncated to avoid overwhelming the context.
const maxDiffBytes = 12_000

// Collect gathers git history and plan data needed to generate a PR description.
// workDir must be the git repository root (or any sub-directory).
// base is a branch name or SHA; defaults to "main" if empty.
func Collect(workDir, base string, completedTasks []*pm.Task, goal string) (*PRContext, error) {
	if base == "" {
		base = "main"
	}

	// Resolve HEAD SHA
	headOut, err := runGit(workDir, "rev-parse", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("resolving HEAD: %w", err)
	}
	headSHA := strings.TrimSpace(headOut)

	// git log --oneline <base>..HEAD
	logOut, err := runGit(workDir, "log", "--oneline", base+"..HEAD")
	if err != nil {
		// If base doesn't exist locally, fall back to short log
		logOut, _ = runGit(workDir, "log", "--oneline", "-20")
	}
	gitLog := strings.TrimSpace(logOut)

	// git diff <base>..HEAD
	diffOut, err := runGit(workDir, "diff", base+"..HEAD")
	if err != nil {
		// Try staged + unstaged diff as fallback
		diffOut, _ = runGit(workDir, "diff", "HEAD~1..HEAD")
	}
	gitDiff := diffOut
	if len(gitDiff) > maxDiffBytes {
		gitDiff = gitDiff[:maxDiffBytes] + "\n\n... (diff truncated) ..."
	}

	return &PRContext{
		Base:           base,
		HeadSHA:        headSHA,
		GitLog:         gitLog,
		GitDiff:        gitDiff,
		CompletedTasks: completedTasks,
		Goal:           goal,
	}, nil
}

// BuildPrompt constructs the AI prompt for PR generation.
func BuildPrompt(ctx *PRContext) string {
	var b strings.Builder

	b.WriteString("You are a senior software engineer writing a GitHub pull request description.\n")
	b.WriteString("Based on the information below, generate a concise PR title and a well-structured markdown body.\n")
	b.WriteString(fmt.Sprintf("Base branch: %s\n\n", ctx.Base))

	b.WriteString("## Output Format\n\n")
	b.WriteString("Your response MUST follow this exact format (do not add anything before or after):\n\n")
	b.WriteString("TITLE: <single-line PR title, under 72 characters>\n\n")
	b.WriteString("<markdown body with the following sections>\n\n")
	b.WriteString("Required sections in the body:\n")
	b.WriteString("- ## Summary  (2-4 bullet points describing what this PR does)\n")
	b.WriteString("- ## Motivation & Context  (why this change is needed)\n")
	b.WriteString("- ## Changes  (key files/packages modified and what changed)\n")
	b.WriteString("- ## Testing  (how to verify this PR works)\n\n")

	if ctx.Goal != "" {
		b.WriteString("## Project Goal\n\n")
		b.WriteString(ctx.Goal)
		b.WriteString("\n\n")
	}

	if len(ctx.CompletedTasks) > 0 {
		b.WriteString("## Completed Tasks Included in This PR\n\n")
		for _, t := range ctx.CompletedTasks {
			status := string(t.Status)
			b.WriteString(fmt.Sprintf("- [%s] Task #%d: %s\n", status, t.ID, t.Title))
			if t.Description != "" {
				desc := t.Description
				if len(desc) > 200 {
					desc = desc[:200] + "..."
				}
				b.WriteString(fmt.Sprintf("  %s\n", desc))
			}
		}
		b.WriteString("\n")
	}

	if ctx.GitLog != "" {
		b.WriteString("## Git Commits (")
		b.WriteString(ctx.Base)
		b.WriteString("..HEAD)\n\n```\n")
		b.WriteString(ctx.GitLog)
		b.WriteString("\n```\n\n")
	}

	if ctx.GitDiff != "" {
		// Truncate large diffs in the prompt as well (Collect may have already
		// truncated, but PRContext can also be constructed directly in tests).
		diff := ctx.GitDiff
		if len(diff) > maxDiffBytes {
			diff = diff[:maxDiffBytes] + "\n\n... (diff truncated) ..."
		}
		b.WriteString("## Git Diff (")
		b.WriteString(ctx.Base)
		b.WriteString("..HEAD)\n\n```diff\n")
		b.WriteString(diff)
		b.WriteString("\n```\n\n")
	}

	b.WriteString("Now write the TITLE line followed by the markdown body:\n")

	return b.String()
}

// Generate calls the provider to generate a PR title and body.
func Generate(ctx context.Context, prov provider.Provider, model string, timeout time.Duration, prCtx *PRContext) (*PRResult, error) {
	prompt := BuildPrompt(prCtx)

	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	opts := provider.Options{Model: model}
	res, err := prov.Complete(callCtx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("provider error: %w", err)
	}

	return ParseResponse(res.Output), nil
}

// ParseResponse extracts the title and body from the raw provider response.
// It expects the format:
//
//	TITLE: <title>
//
//	<markdown body>
func ParseResponse(raw string) *PRResult {
	raw = strings.TrimSpace(raw)

	title := ""
	bodyLines := []string{}
	foundTitle := false

	for _, line := range strings.Split(raw, "\n") {
		if !foundTitle {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "TITLE:") {
				title = strings.TrimSpace(strings.TrimPrefix(trimmed, "TITLE:"))
				foundTitle = true
				continue
			}
			// Skip blank lines before TITLE
			if trimmed == "" {
				continue
			}
			// If the first non-blank line is not TITLE:, treat the whole response as body
			// and use the first line as title
			title = trimmed
			foundTitle = true
			continue
		}
		bodyLines = append(bodyLines, line)
	}

	body := strings.TrimSpace(strings.Join(bodyLines, "\n"))

	// If parsing resulted in no body sections, use the whole raw as body
	if body == "" && title != "" {
		// Nothing to do — the AI gave only a title
	}
	if title == "" {
		title = "chore: update project"
	}

	return &PRResult{
		Title: title,
		Body:  body,
	}
}

// runGit executes a git command in workDir and returns stdout as a string.
func runGit(workDir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = workDir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}
