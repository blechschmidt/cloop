package multiagent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Result holds the outputs of all three sub-agent passes plus the final signal.
type Result struct {
	ArchitectOutput string
	CoderOutput     string
	ReviewerOutput  string
	// Signal is the final task signal extracted from the reviewer's output,
	// falling back to the coder's signal. One of TASK_DONE, TASK_FAILED, TASK_SKIPPED.
	Signal      pm.TaskStatus
	ArtifactDir string // relative path of the per-task artifact directory
}

var nonSlugRe = regexp.MustCompile(`[^a-z0-9-]+`)

func slug(title string, maxLen int) string {
	s := strings.ToLower(title)
	s = strings.ReplaceAll(s, " ", "-")
	s = nonSlugRe.ReplaceAllString(s, "")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if len(s) > maxLen {
		s = s[:maxLen]
		s = strings.TrimRight(s, "-")
	}
	return s
}

// RunTask executes a single PM task through the three-pass multi-agent pipeline
// (architect → coder → reviewer) and returns the combined result.
//
// Each pass uses its own system prompt from roles.go. The coder receives the
// architect's output as context, and the reviewer receives both prior outputs.
// Sub-agent responses are stored as artifact files under
// .cloop/tasks/<id>-<slug>-multiagent/{architect,coder,reviewer}.txt.
func RunTask(
	ctx context.Context,
	prov provider.Provider,
	model string,
	timeout time.Duration,
	task *pm.Task,
	goal string,
	instructions string,
	projectContext string,
) (*Result, error) {
	res := &Result{}

	// Build the base task description block used by all passes.
	var header strings.Builder
	if projectContext != "" {
		header.WriteString("## Project Context\n\n")
		header.WriteString(projectContext)
		header.WriteString("\n\n")
	}
	header.WriteString("## Goal\n\n")
	header.WriteString(goal)
	header.WriteString("\n\n")
	if instructions != "" {
		header.WriteString("## Instructions\n\n")
		header.WriteString(instructions)
		header.WriteString("\n\n")
	}
	header.WriteString(fmt.Sprintf("## Task %d: %s\n\n", task.ID, task.Title))
	header.WriteString(task.Description)
	header.WriteString("\n")
	baseContext := header.String()

	opts := provider.Options{
		Model:   model,
		Timeout: timeout,
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Minute
	}

	// ── Pass 1: Architect ──────────────────────────────────────────────────
	architectPrompt := baseContext + "\nDesign the technical approach for this task."
	archOpts := opts
	archOpts.SystemPrompt = ArchitectSystemPrompt
	archResult, err := prov.Complete(ctx, architectPrompt, archOpts)
	if err != nil {
		return nil, fmt.Errorf("architect pass: %w", err)
	}
	res.ArchitectOutput = archResult.Output

	// ── Pass 2: Coder ──────────────────────────────────────────────────────
	var coderPrompt strings.Builder
	coderPrompt.WriteString(baseContext)
	coderPrompt.WriteString("\n## Architect's Design\n\n")
	coderPrompt.WriteString(res.ArchitectOutput)
	coderPrompt.WriteString("\n\nImplement the task following the architect's design above.")

	coderOpts := opts
	coderOpts.SystemPrompt = CoderSystemPrompt
	coderResult, err := prov.Complete(ctx, coderPrompt.String(), coderOpts)
	if err != nil {
		return nil, fmt.Errorf("coder pass: %w", err)
	}
	res.CoderOutput = coderResult.Output

	// ── Pass 3: Reviewer ───────────────────────────────────────────────────
	var reviewerPrompt strings.Builder
	reviewerPrompt.WriteString(baseContext)
	reviewerPrompt.WriteString("\n## Architect's Design\n\n")
	reviewerPrompt.WriteString(res.ArchitectOutput)
	reviewerPrompt.WriteString("\n\n## Coder's Implementation\n\n")
	reviewerPrompt.WriteString(res.CoderOutput)
	reviewerPrompt.WriteString("\n\nReview the implementation and emit your verdict.")

	reviewerOpts := opts
	reviewerOpts.SystemPrompt = ReviewerSystemPrompt
	reviewerResult, err := prov.Complete(ctx, reviewerPrompt.String(), reviewerOpts)
	if err != nil {
		return nil, fmt.Errorf("reviewer pass: %w", err)
	}
	res.ReviewerOutput = reviewerResult.Output

	// ── Signal resolution ─────────────────────────────────────────────────
	// Reviewer's verdict takes precedence; fall back to coder's signal.
	reviewerSignal := pm.CheckTaskSignal(res.ReviewerOutput)
	coderSignal := pm.CheckTaskSignal(res.CoderOutput)

	switch {
	case reviewerSignal == pm.TaskDone || reviewerSignal == pm.TaskFailed || reviewerSignal == pm.TaskSkipped:
		res.Signal = reviewerSignal
	case coderSignal == pm.TaskDone || coderSignal == pm.TaskFailed || coderSignal == pm.TaskSkipped:
		res.Signal = coderSignal
	default:
		// Neither emitted a recognizable signal — treat as done (matches single-agent behaviour).
		res.Signal = pm.TaskDone
	}

	return res, nil
}

// WriteArtifacts persists the three sub-agent outputs as text files under
// .cloop/tasks/<id>-<slug>-multiagent/ and returns the relative directory path.
func WriteArtifacts(workDir string, task *pm.Task, res *Result) (string, error) {
	s := slug(task.Title, 40)
	dirName := fmt.Sprintf("%d-%s-multiagent", task.ID, s)
	absDir := filepath.Join(workDir, ".cloop", "tasks", dirName)
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return "", fmt.Errorf("create multiagent artifact dir: %w", err)
	}

	files := map[string]string{
		"architect.txt": res.ArchitectOutput,
		"coder.txt":     res.CoderOutput,
		"reviewer.txt":  res.ReviewerOutput,
	}
	for name, content := range files {
		absPath := filepath.Join(absDir, name)
		if err := os.WriteFile(absPath, []byte(content), 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", name, err)
		}
	}

	rel, err := filepath.Rel(workDir, absDir)
	if err != nil {
		rel = absDir
	}
	return rel, nil
}
