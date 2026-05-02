// Package review provides AI-powered code review for git diffs.
// It parses structured feedback from a provider and returns
// categorized issues, quality scores, and actionable suggestions.
// It also provides ReviewDiff for lightweight post-task annotation reviews.
package review

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// Author is the annotation author used for AI code review annotations.
const Author = "ai-reviewer"

// Verdict values for post-task reviews.
const (
	VerdictPass = "PASS"
	VerdictFail = "FAIL"
)

// GetDiff runs `git diff HEAD~1` in workDir and returns the diff output.
// Returns an empty string (no error) when there is no parent commit or no diff.
func GetDiff(workDir string) (string, error) {
	cmd := exec.Command("git", "diff", "HEAD~1")
	cmd.Dir = workDir
	out, err := cmd.Output()
	if err != nil {
		// No parent commit (initial commit) or not a git repo — non-fatal.
		return "", nil
	}
	return string(out), nil
}

// ReviewDiff calls the provider with a structured code review prompt for the
// given diff and task title. It returns the full review text (markdown) and
// an error. The text ends with a "VERDICT: PASS" or "VERDICT: FAIL" line.
// If the diff is empty the function returns a short note without calling the provider.
func ReviewDiff(ctx context.Context, p provider.Provider, model string, timeout time.Duration, diff, taskTitle string) (string, error) {
	if strings.TrimSpace(diff) == "" {
		return "No git changes detected — nothing to review.\n\nVERDICT: PASS", nil
	}

	prompt := buildReviewDiffPrompt(diff, taskTitle)
	res, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return "", fmt.Errorf("code review: %w", err)
	}
	return strings.TrimSpace(res.Output), nil
}

// ExtractVerdict scans review text for "VERDICT: PASS" or "VERDICT: FAIL".
// Defaults to VerdictPass when no verdict line is found.
func ExtractVerdict(text string) string {
	for _, line := range strings.Split(text, "\n") {
		upper := strings.ToUpper(strings.TrimSpace(line))
		if strings.Contains(upper, "VERDICT: FAIL") {
			return VerdictFail
		}
		if strings.Contains(upper, "VERDICT: PASS") {
			return VerdictPass
		}
	}
	return VerdictPass
}

// buildReviewDiffPrompt builds the post-task code review prompt.
func buildReviewDiffPrompt(diff, taskTitle string) string {
	var b strings.Builder
	b.WriteString("You are an expert code reviewer performing an automated post-task review.\n")
	b.WriteString("Review the git diff below and provide a concise structured report.\n\n")

	b.WriteString("## COMPLETED TASK\n")
	b.WriteString(taskTitle)
	b.WriteString("\n\n")

	b.WriteString("## GIT DIFF\n```diff\n")
	// Truncate very large diffs to keep the prompt manageable.
	const maxDiff = 8000
	if len(diff) > maxDiff {
		b.WriteString(diff[:maxDiff/2])
		b.WriteString("\n... (diff truncated) ...\n")
		b.WriteString(diff[len(diff)-maxDiff/2:])
	} else {
		b.WriteString(diff)
	}
	b.WriteString("\n```\n\n")

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Provide a review with exactly these four sections:\n\n")
	b.WriteString("### Correctness\n")
	b.WriteString("List any bugs, logic errors, incorrect assumptions, or broken edge cases. Write \"None found\" if clean.\n\n")
	b.WriteString("### Security\n")
	b.WriteString("List any security concerns: injection, improper input validation, exposed secrets, auth issues, etc. Write \"None found\" if clean.\n\n")
	b.WriteString("### Style\n")
	b.WriteString("Note any style, naming, or maintainability issues. Write \"None found\" if clean.\n\n")
	b.WriteString("### Verdict\n")
	b.WriteString("End with exactly one of these lines:\n")
	b.WriteString("VERDICT: PASS\n")
	b.WriteString("VERDICT: FAIL\n\n")
	b.WriteString("Use FAIL only when there are correctness or security issues that should be fixed.\n")
	b.WriteString("Style issues alone do not warrant FAIL.\n")
	b.WriteString("Keep the full review under 400 words.\n")

	return b.String()
}

// Severity levels for code review issues.
const (
	SeverityCritical   = "critical"   // bugs, security holes, data loss
	SeverityMajor      = "major"      // logic errors, missing error handling
	SeverityMinor      = "minor"      // style, naming, duplication
	SeveritySuggestion = "suggestion" // optional improvements
)

// Issue is a single code review finding.
type Issue struct {
	// Severity is one of: critical, major, minor, suggestion.
	Severity string `json:"severity"`

	// File is the path of the affected file (may be empty for cross-cutting issues).
	File string `json:"file"`

	// Line is the approximate line number (0 means unknown).
	Line int `json:"line"`

	// Title is a short one-line description of the issue.
	Title string `json:"title"`

	// Detail explains the problem in full.
	Detail string `json:"detail"`

	// Fix is a concrete suggestion or code snippet to resolve the issue.
	Fix string `json:"fix"`
}

// Review is the structured output of an AI code review.
type Review struct {
	// Score is an overall code quality score from 1–10.
	Score float64 `json:"score"`

	// Summary is a 2–3 sentence high-level assessment.
	Summary string `json:"summary"`

	// Issues is the list of findings ordered by severity (critical first).
	Issues []Issue `json:"issues"`

	// Praise lists specific things that are well done.
	Praise []string `json:"praise"`

	// Suggestions lists general improvement ideas that don't map to a single issue.
	Suggestions []string `json:"suggestions"`

	// TestFeedback is targeted feedback on test coverage and quality.
	TestFeedback string `json:"test_feedback"`

	// SecurityNotes lists any security-relevant observations.
	SecurityNotes []string `json:"security_notes"`
}

// Counts returns the number of issues at each severity level.
func (r *Review) Counts() (critical, major, minor, suggestion int) {
	for _, iss := range r.Issues {
		switch iss.Severity {
		case SeverityCritical:
			critical++
		case SeverityMajor:
			major++
		case SeverityMinor:
			minor++
		case SeveritySuggestion:
			suggestion++
		}
	}
	return
}

// Perform sends the provided diff to the AI provider and returns a structured review.
// taskContext is optional — if set it's included in the prompt so the AI can judge
// whether the code actually solves the intended PM task.
func Perform(ctx context.Context, prov provider.Provider, model string, timeout time.Duration, diff, taskContext, goal string) (*Review, error) {
	if strings.TrimSpace(diff) == "" {
		return nil, fmt.Errorf("diff is empty — nothing to review")
	}

	// Truncate extremely large diffs to avoid token limits.
	const maxDiffBytes = 32_000
	if len(diff) > maxDiffBytes {
		diff = diff[:maxDiffBytes] + "\n\n[...diff truncated for brevity...]"
	}

	prompt := buildPrompt(diff, taskContext, goal)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := prov.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("provider: %w", err)
	}

	rev, err := parseResponse(result.Output)
	if err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return rev, nil
}

func buildPrompt(diff, taskContext, goal string) string {
	var sb strings.Builder

	sb.WriteString("You are a senior software engineer conducting a thorough code review.\n\n")

	if goal != "" {
		sb.WriteString("## Project Goal\n")
		sb.WriteString(goal)
		sb.WriteString("\n\n")
	}
	if taskContext != "" {
		sb.WriteString("## Task Being Reviewed\n")
		sb.WriteString(taskContext)
		sb.WriteString("\n\n")
	}

	sb.WriteString("## Git Diff\n```diff\n")
	sb.WriteString(diff)
	sb.WriteString("\n```\n\n")

	sb.WriteString(`Review the diff above and return ONLY valid JSON matching this schema:

{
  "score": <number 1-10, overall code quality>,
  "summary": "<2-3 sentence high-level assessment>",
  "issues": [
    {
      "severity": "<critical|major|minor|suggestion>",
      "file": "<file path or empty>",
      "line": <line number or 0>,
      "title": "<short one-line title>",
      "detail": "<full explanation>",
      "fix": "<concrete fix or code snippet>"
    }
  ],
  "praise": ["<specific things done well>"],
  "suggestions": ["<general improvement ideas>"],
  "test_feedback": "<assessment of test coverage and quality>",
  "security_notes": ["<any security-relevant observations>"]
}

Guidelines:
- severity "critical": bugs, security holes, data loss risks, broken logic
- severity "major": missing error handling, incorrect algorithms, performance problems
- severity "minor": naming, style, minor duplication
- severity "suggestion": optional refactors, nice-to-haves
- Be specific: name the file and line when possible
- Keep each issue's "fix" to 1-3 lines of concrete guidance
- If the diff is clean and high quality, say so in praise and give a high score
- Score 9-10: excellent, minimal issues; 7-8: good, minor issues; 5-6: needs work; <5: significant problems
- Return ONLY the JSON object, no markdown code fences, no explanation text`)

	return sb.String()
}

func parseResponse(resp string) (*Review, error) {
	resp = strings.TrimSpace(resp)

	// Strip markdown code fences if present.
	if strings.HasPrefix(resp, "```") {
		lines := strings.SplitN(resp, "\n", 2)
		if len(lines) == 2 {
			resp = lines[1]
		}
		resp = strings.TrimSuffix(resp, "```")
		resp = strings.TrimSpace(resp)
	}

	// Find first '{' to skip any preamble.
	if idx := strings.Index(resp, "{"); idx > 0 {
		resp = resp[idx:]
	}
	// Trim after last '}'.
	if idx := strings.LastIndex(resp, "}"); idx >= 0 {
		resp = resp[:idx+1]
	}

	var r Review
	if err := json.Unmarshal([]byte(resp), &r); err != nil {
		return nil, fmt.Errorf("JSON unmarshal: %w\nraw: %.400s", err, resp)
	}
	return &r, nil
}

// FormatMarkdown renders a Review as a Markdown document.
func FormatMarkdown(r *Review, diff, source string) string {
	var sb strings.Builder

	sb.WriteString("# Code Review\n\n")
	if source != "" {
		sb.WriteString(fmt.Sprintf("**Source:** %s\n\n", source))
	}

	sb.WriteString(fmt.Sprintf("**Quality Score:** %.1f / 10\n\n", r.Score))
	sb.WriteString(fmt.Sprintf("**Summary:** %s\n\n", r.Summary))

	critical, major, minor, suggestion := r.Counts()
	sb.WriteString(fmt.Sprintf("**Issues:** %d critical · %d major · %d minor · %d suggestions\n\n",
		critical, major, minor, suggestion))

	if len(r.Issues) > 0 {
		sb.WriteString("## Issues\n\n")
		for _, iss := range r.Issues {
			icon := issueIcon(iss.Severity)
			loc := ""
			if iss.File != "" {
				loc = fmt.Sprintf(" `%s`", iss.File)
				if iss.Line > 0 {
					loc = fmt.Sprintf(" `%s:%d`", iss.File, iss.Line)
				}
			}
			sb.WriteString(fmt.Sprintf("### %s [%s]%s — %s\n\n", icon, strings.ToUpper(iss.Severity), loc, iss.Title))
			sb.WriteString(iss.Detail + "\n\n")
			if iss.Fix != "" {
				sb.WriteString(fmt.Sprintf("**Fix:** %s\n\n", iss.Fix))
			}
		}
	}

	if len(r.Praise) > 0 {
		sb.WriteString("## What's Good\n\n")
		for _, p := range r.Praise {
			sb.WriteString(fmt.Sprintf("- %s\n", p))
		}
		sb.WriteString("\n")
	}

	if len(r.Suggestions) > 0 {
		sb.WriteString("## General Suggestions\n\n")
		for _, s := range r.Suggestions {
			sb.WriteString(fmt.Sprintf("- %s\n", s))
		}
		sb.WriteString("\n")
	}

	if r.TestFeedback != "" {
		sb.WriteString("## Test Coverage\n\n")
		sb.WriteString(r.TestFeedback + "\n\n")
	}

	if len(r.SecurityNotes) > 0 {
		sb.WriteString("## Security Notes\n\n")
		for _, n := range r.SecurityNotes {
			sb.WriteString(fmt.Sprintf("- %s\n", n))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func issueIcon(severity string) string {
	switch severity {
	case SeverityCritical:
		return "!!"
	case SeverityMajor:
		return "!"
	case SeverityMinor:
		return "~"
	default:
		return "?"
	}
}
