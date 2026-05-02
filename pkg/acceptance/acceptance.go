// Package acceptance generates formal acceptance criteria for tasks using AI.
// Supported formats: Gherkin (Given/When/Then) and Checklist (numbered pass/fail items).
package acceptance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// ProjectState is an alias to avoid repeating the full package path in signatures.
type ProjectState = state.ProjectState

// Format controls the output style of the generated acceptance criteria.
type Format string

const (
	FormatGherkin   Format = "gherkin"
	FormatChecklist Format = "checklist"
)

// Result holds the generated acceptance criteria text and metadata.
type Result struct {
	TaskID    int
	TaskTitle string
	Format    Format
	Criteria  string
}

// BuildPrompt constructs the AI prompt for acceptance criteria generation.
func BuildPrompt(task *pm.Task, format Format, artifactOutput string) string {
	var b strings.Builder

	b.WriteString("You are a QA engineer writing formal acceptance criteria for a software task.\n\n")
	b.WriteString("## Task\n\n")
	b.WriteString(fmt.Sprintf("**ID:** %d\n", task.ID))
	b.WriteString(fmt.Sprintf("**Title:** %s\n", task.Title))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("**Description:** %s\n", task.Description))
	}
	if task.Status != "" {
		b.WriteString(fmt.Sprintf("**Status:** %s\n", string(task.Status)))
	}
	if len(task.Tags) > 0 {
		b.WriteString(fmt.Sprintf("**Tags:** %s\n", strings.Join(task.Tags, ", ")))
	}

	if artifactOutput != "" {
		trimmed := strings.TrimSpace(artifactOutput)
		// Cap context at ~2000 chars to avoid bloating the prompt.
		if len(trimmed) > 2000 {
			trimmed = trimmed[:2000] + "\n...(truncated)"
		}
		b.WriteString("\n## Existing Output / Artifact\n\n")
		b.WriteString(trimmed)
		b.WriteString("\n")
	}

	b.WriteString("\n## Instructions\n\n")

	switch format {
	case FormatGherkin:
		b.WriteString(`Generate formal acceptance criteria in Gherkin BDD format.

Rules:
- Write 3-6 scenarios covering the main happy path, at least one edge case, and one failure/error case.
- Each scenario must use the exact keywords: Scenario, Given, When, Then (and optionally And, But).
- Use concrete, testable language — no vague terms like "properly" or "correctly".
- Do NOT wrap output in a markdown code block.
- Output ONLY the Feature block and its Scenarios — no extra prose.

Example format:
Feature: <feature name>

  Scenario: <happy path description>
    Given <precondition>
    When <action>
    Then <expected outcome>

  Scenario: <edge case>
    Given <precondition>
    When <action>
    Then <expected outcome>
`)
	case FormatChecklist:
		b.WriteString(`Generate formal acceptance criteria as a numbered checklist of pass/fail items.

Rules:
- Write 5-10 concrete, independently verifiable items.
- Each item must be a clear, unambiguous statement that can be tested as PASS or FAIL.
- Begin each line with a number, e.g. "1. The command exits with code 0 on success."
- Cover: functional correctness, error handling, edge cases, and observable side-effects.
- Do NOT use vague terms — every item must be objectively testable.
- Output ONLY the numbered list — no extra prose, headers, or markdown.
`)
	}

	b.WriteString("\nGenerate the acceptance criteria now:")
	return b.String()
}

// Generate calls the AI provider to produce acceptance criteria for the task.
func Generate(ctx context.Context, prov provider.Provider, opts provider.Options, task *pm.Task, format Format, artifactOutput string) (*Result, error) {
	prompt := BuildPrompt(task, format, artifactOutput)

	var sb strings.Builder
	callOpts := opts
	callOpts.OnToken = func(tok string) { sb.WriteString(tok) }

	if _, err := prov.Complete(ctx, prompt, callOpts); err != nil {
		return nil, fmt.Errorf("AI call failed: %w", err)
	}

	criteria := strings.TrimSpace(sb.String())
	if criteria == "" {
		return nil, fmt.Errorf("AI returned empty response")
	}

	return &Result{
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Format:    format,
		Criteria:  criteria,
	}, nil
}

// Apply persists the acceptance criteria by:
//  1. Adding an Annotation to the task in the plan (writes state to disk).
//  2. Writing the criteria to .cloop/acceptance/<task-id>.md.
//
// Returns the path of the written markdown file.
func Apply(workDir string, s *ProjectState, task *pm.Task, result *Result) (string, error) {
	// 1. Annotate the task.
	annotation := pm.Annotation{
		Timestamp: time.Now().UTC(),
		Author:    "ai-acceptance",
		Text:      fmt.Sprintf("**Acceptance Criteria (%s)**\n\n%s", result.Format, result.Criteria),
	}
	task.Annotations = append(task.Annotations, annotation)

	if err := s.Save(); err != nil {
		return "", fmt.Errorf("saving state: %w", err)
	}

	// 2. Write .cloop/acceptance/<task-id>.md
	dir := filepath.Join(workDir, ".cloop", "acceptance")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create acceptance dir: %w", err)
	}

	slug := slugify(task.Title, 40)
	filename := fmt.Sprintf("%d-%s.md", task.ID, slug)
	absPath := filepath.Join(dir, filename)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Acceptance Criteria: Task #%d — %s\n\n", task.ID, task.Title))
	b.WriteString(fmt.Sprintf("**Format:** %s  \n", result.Format))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().UTC().Format(time.RFC3339)))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("## Task Description\n\n%s\n\n", task.Description))
	}
	b.WriteString("## Criteria\n\n")
	b.WriteString(result.Criteria)
	b.WriteString("\n")

	if err := os.WriteFile(absPath, []byte(b.String()), 0o644); err != nil {
		return "", fmt.Errorf("write acceptance file: %w", err)
	}

	rel, err := filepath.Rel(workDir, absPath)
	if err != nil {
		rel = absPath
	}
	return rel, nil
}

// ReadArtifactOutput is a convenience wrapper around artifact.ReadTaskOutput.
func ReadArtifactOutput(workDir string, task *pm.Task) string {
	return artifact.ReadTaskOutput(workDir, task)
}

// slugify converts a string to a lowercase hyphenated slug truncated to maxLen.
func slugify(s string, maxLen int) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	var out []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			out = append(out, r)
		}
	}
	result := string(out)
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	result = strings.Trim(result, "-")
	if len(result) > maxLen {
		result = strings.TrimRight(result[:maxLen], "-")
	}
	return result
}
