package pr

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

func TestBuildPrompt_ContainsGoal(t *testing.T) {
	ctx := &PRContext{
		Base:  "main",
		Goal:  "Build a REST API with user auth",
		GitLog: "abc1234 feat: add user endpoint",
	}
	prompt := BuildPrompt(ctx)
	if !strings.Contains(prompt, "Build a REST API with user auth") {
		t.Error("prompt missing Goal")
	}
}

func TestBuildPrompt_ContainsGitLog(t *testing.T) {
	ctx := &PRContext{
		Base:   "main",
		GitLog: "abc1234 feat: add login handler\ndef5678 fix: validation bug",
	}
	prompt := BuildPrompt(ctx)
	if !strings.Contains(prompt, "abc1234 feat: add login handler") {
		t.Error("prompt missing git log entry")
	}
	if !strings.Contains(prompt, "def5678 fix: validation bug") {
		t.Error("prompt missing second git log entry")
	}
}

func TestBuildPrompt_ContainsDiff(t *testing.T) {
	ctx := &PRContext{
		Base:    "main",
		GitDiff: "+func NewHandler() http.Handler {",
	}
	prompt := BuildPrompt(ctx)
	if !strings.Contains(prompt, "+func NewHandler()") {
		t.Error("prompt missing diff content")
	}
}

func TestBuildPrompt_ContainsCompletedTasks(t *testing.T) {
	ctx := &PRContext{
		Base: "main",
		CompletedTasks: []*pm.Task{
			{ID: 1, Title: "Add authentication", Description: "Implement JWT auth", Status: pm.TaskDone},
			{ID: 2, Title: "Write unit tests", Status: pm.TaskDone},
		},
	}
	prompt := BuildPrompt(ctx)
	if !strings.Contains(prompt, "Task #1: Add authentication") {
		t.Error("prompt missing task #1")
	}
	if !strings.Contains(prompt, "Task #2: Write unit tests") {
		t.Error("prompt missing task #2")
	}
	if !strings.Contains(prompt, "Implement JWT auth") {
		t.Error("prompt missing task description")
	}
}

func TestBuildPrompt_ContainsFormatInstructions(t *testing.T) {
	ctx := &PRContext{Base: "main"}
	prompt := BuildPrompt(ctx)
	if !strings.Contains(prompt, "TITLE:") {
		t.Error("prompt missing TITLE format instruction")
	}
	if !strings.Contains(prompt, "## Summary") {
		t.Error("prompt missing Summary section instruction")
	}
	if !strings.Contains(prompt, "## Motivation") {
		t.Error("prompt missing Motivation section instruction")
	}
	if !strings.Contains(prompt, "## Changes") {
		t.Error("prompt missing Changes section instruction")
	}
	if !strings.Contains(prompt, "## Testing") {
		t.Error("prompt missing Testing section instruction")
	}
}

func TestBuildPrompt_DiffTruncation(t *testing.T) {
	bigDiff := strings.Repeat("x", maxDiffBytes+5000)
	ctx := &PRContext{
		Base:    "main",
		GitDiff: bigDiff,
	}
	prompt := BuildPrompt(ctx)
	// The diff in the prompt should be truncated
	if !strings.Contains(prompt, "truncated") {
		t.Error("expected truncation marker in prompt for large diff")
	}
}

func TestBuildPrompt_EmptyContext(t *testing.T) {
	ctx := &PRContext{Base: "develop"}
	prompt := BuildPrompt(ctx)
	if prompt == "" {
		t.Error("prompt should not be empty even with minimal context")
	}
	if !strings.Contains(prompt, "develop") {
		t.Error("prompt should reference the base branch")
	}
}

func TestBuildPrompt_NoGitLogWhenEmpty(t *testing.T) {
	ctx := &PRContext{Base: "main", GitLog: ""}
	prompt := BuildPrompt(ctx)
	// Should not contain the git commits section header when log is empty
	if strings.Contains(prompt, "Git Commits") {
		t.Error("prompt should not include Git Commits section when GitLog is empty")
	}
}

func TestBuildPrompt_NoGitDiffWhenEmpty(t *testing.T) {
	ctx := &PRContext{Base: "main", GitDiff: ""}
	prompt := BuildPrompt(ctx)
	if strings.Contains(prompt, "Git Diff") {
		t.Error("prompt should not include Git Diff section when GitDiff is empty")
	}
}

// ── ParseResponse tests ────────────────────────────────────────────────────

func TestParseResponse_StandardFormat(t *testing.T) {
	raw := `TITLE: feat: add user authentication

## Summary

- Implements JWT-based authentication
- Adds login and registration endpoints

## Motivation & Context

Users need a secure login flow.

## Changes

- pkg/auth: new package with JWT helpers
- cmd/api: added /login and /register routes

## Testing

Run go test ./pkg/auth/... to verify.`

	result := ParseResponse(raw)
	if result.Title != "feat: add user authentication" {
		t.Errorf("unexpected title: %q", result.Title)
	}
	if !strings.Contains(result.Body, "## Summary") {
		t.Error("body missing Summary section")
	}
	if !strings.Contains(result.Body, "JWT-based authentication") {
		t.Error("body missing Summary content")
	}
	if !strings.Contains(result.Body, "## Testing") {
		t.Error("body missing Testing section")
	}
}

func TestParseResponse_TitleWithLeadingWhitespace(t *testing.T) {
	raw := "TITLE:   fix: resolve memory leak in worker pool\n\nSome body text."
	result := ParseResponse(raw)
	if result.Title != "fix: resolve memory leak in worker pool" {
		t.Errorf("unexpected title: %q", result.Title)
	}
}

func TestParseResponse_NoTitleLine(t *testing.T) {
	// If no TITLE: prefix, first non-blank line becomes title
	raw := "chore: bump dependencies\n\nUpdated go.mod and go.sum."
	result := ParseResponse(raw)
	if result.Title != "chore: bump dependencies" {
		t.Errorf("unexpected title: %q", result.Title)
	}
	if !strings.Contains(result.Body, "Updated go.mod") {
		t.Error("body should contain remaining lines")
	}
}

func TestParseResponse_EmptyInput(t *testing.T) {
	result := ParseResponse("")
	if result.Title == "" {
		t.Error("title should have a fallback value")
	}
}

func TestParseResponse_TitleOnly(t *testing.T) {
	raw := "TITLE: feat: only a title"
	result := ParseResponse(raw)
	if result.Title != "feat: only a title" {
		t.Errorf("unexpected title: %q", result.Title)
	}
}

func TestParseResponse_BodyPreservesMarkdown(t *testing.T) {
	raw := `TITLE: docs: update README

## Summary

- Added installation instructions
- Clarified config options

## Changes

- README.md: major rewrite`

	result := ParseResponse(raw)
	if !strings.Contains(result.Body, "## Summary") {
		t.Error("body should preserve markdown headings")
	}
	if !strings.Contains(result.Body, "- Added installation instructions") {
		t.Error("body should preserve bullet points")
	}
}
