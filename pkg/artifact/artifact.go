// Package artifact persists the full AI response for each PM task as a
// human-readable Markdown file with YAML frontmatter under .cloop/tasks/.
// It also stores shell verification scripts and their results.
package artifact

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// WriteExecArtifact persists the output of a 'cloop task exec' run under
// .cloop/tasks/<id>-<slug>-exec-<ts>.md.
// Returns the relative path (relative to workDir) of the artifact file.
func WriteExecArtifact(workDir string, task *pm.Task, cmdArgs []string, exitCode int, elapsed time.Duration, output string) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create artifact dir: %w", err)
	}

	s := slug(task.Title, 40)
	ts := time.Now().UTC().Format("20060102-150405")
	filename := fmt.Sprintf("%d-%s-exec-%s.md", task.ID, s, ts)
	absPath := filepath.Join(dir, filename)

	var b strings.Builder

	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("id: %d\n", task.ID))
	b.WriteString(fmt.Sprintf("title: %q\n", task.Title))
	b.WriteString(fmt.Sprintf("status: %s\n", task.Status))
	b.WriteString(fmt.Sprintf("event: exec\n"))
	b.WriteString(fmt.Sprintf("command: %q\n", strings.Join(cmdArgs, " ")))
	b.WriteString(fmt.Sprintf("exit_code: %d\n", exitCode))
	b.WriteString(fmt.Sprintf("elapsed: %s\n", elapsed.Round(time.Millisecond)))
	b.WriteString(fmt.Sprintf("recorded_at: %s\n", ts))
	b.WriteString("---\n\n")

	b.WriteString(fmt.Sprintf("## Command\n\n```\n%s\n```\n\n", strings.Join(cmdArgs, " ")))
	b.WriteString(fmt.Sprintf("**Exit code:** %d | **Elapsed:** %s\n\n", exitCode, elapsed.Round(time.Millisecond)))

	b.WriteString("## Output\n\n```\n")
	if output != "" {
		b.WriteString(output)
		if !strings.HasSuffix(output, "\n") {
			b.WriteByte('\n')
		}
	} else {
		b.WriteString("(no output)\n")
	}
	b.WriteString("```\n")

	if err := os.WriteFile(absPath, []byte(b.String()), 0o644); err != nil {
		return "", fmt.Errorf("write exec artifact: %w", err)
	}

	rel, err := filepath.Rel(workDir, absPath)
	if err != nil {
		rel = absPath
	}
	return rel, nil
}

var nonSlugRe = regexp.MustCompile(`[^a-z0-9-]+`)

// LiveArtifactDir returns the directory where live streaming artifacts are written.
func LiveArtifactDir(workDir string) string {
	return filepath.Join(workDir, ".cloop", "artifacts")
}

// LiveArtifactPath returns the canonical path for the live streaming output file
// for the given task ID. The file is written incrementally during execution.
func LiveArtifactPath(workDir string, taskID int) string {
	return filepath.Join(LiveArtifactDir(workDir), fmt.Sprintf("%d_output.txt", taskID))
}

// OpenLiveArtifact creates (or truncates) the live streaming output file for a
// task and returns the open file handle. The caller is responsible for closing it.
// Errors are non-fatal; the caller should treat nil as "no live artifact".
func OpenLiveArtifact(workDir string, taskID int) (*os.File, error) {
	dir := LiveArtifactDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create artifact dir: %w", err)
	}
	return os.OpenFile(LiveArtifactPath(workDir, taskID), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
}

// slug converts a task title into a URL-safe, lowercase, hyphen-separated
// string truncated to maxLen characters.
func slug(title string, maxLen int) string {
	s := strings.ToLower(title)
	s = strings.ReplaceAll(s, " ", "-")
	s = nonSlugRe.ReplaceAllString(s, "")
	// Collapse consecutive hyphens.
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

// WriteTaskArtifact writes the full AI response for a completed task to
// .cloop/tasks/<id>-<slug>.md with YAML frontmatter.
// Returns the relative path (relative to workDir) of the artifact file.
func WriteTaskArtifact(workDir string, task *pm.Task, fullOutput string) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create artifact dir: %w", err)
	}

	s := slug(task.Title, 40)
	filename := fmt.Sprintf("%d-%s.md", task.ID, s)
	absPath := filepath.Join(dir, filename)

	var b strings.Builder

	// YAML frontmatter
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("id: %d\n", task.ID))
	b.WriteString(fmt.Sprintf("title: %q\n", task.Title))
	b.WriteString(fmt.Sprintf("status: %s\n", task.Status))
	if task.Role != "" {
		b.WriteString(fmt.Sprintf("role: %s\n", task.Role))
	}
	if task.StartedAt != nil {
		b.WriteString(fmt.Sprintf("started_at: %s\n", task.StartedAt.UTC().Format(time.RFC3339)))
	}
	if task.CompletedAt != nil {
		b.WriteString(fmt.Sprintf("finished_at: %s\n", task.CompletedAt.UTC().Format(time.RFC3339)))
	}
	if task.EstimatedMinutes > 0 {
		b.WriteString(fmt.Sprintf("estimated_minutes: %d\n", task.EstimatedMinutes))
	}
	if task.ActualMinutes > 0 {
		b.WriteString(fmt.Sprintf("actual_minutes: %d\n", task.ActualMinutes))
	}
	b.WriteString("---\n\n")

	// Full AI response body
	b.WriteString(fullOutput)
	if !strings.HasSuffix(fullOutput, "\n") {
		b.WriteByte('\n')
	}

	if err := os.WriteFile(absPath, []byte(b.String()), 0o644); err != nil {
		return "", fmt.Errorf("write artifact: %w", err)
	}

	// Return path relative to workDir for storage in task.ArtifactPath.
	rel, err := filepath.Rel(workDir, absPath)
	if err != nil {
		rel = absPath
	}
	return rel, nil
}

// WriteVerificationArtifact persists a shell verification script and its
// execution result under .cloop/tasks/<id>-<slug>-verify.md.
// Returns the relative path (relative to workDir) of the artifact file.
func WriteVerificationArtifact(workDir string, task *pm.Task, script, scriptOutput string, passed bool) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create artifact dir: %w", err)
	}

	s := slug(task.Title, 40)
	filename := fmt.Sprintf("%d-%s-verify.md", task.ID, s)
	absPath := filepath.Join(dir, filename)

	verdict := "PASS"
	if !passed {
		verdict = "FAIL"
	}

	var b strings.Builder

	// YAML frontmatter
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("id: %d\n", task.ID))
	b.WriteString(fmt.Sprintf("title: %q\n", task.Title))
	b.WriteString(fmt.Sprintf("verification: %s\n", verdict))
	b.WriteString(fmt.Sprintf("generated_at: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("---\n\n")

	// Script
	b.WriteString("## Verification Script\n\n")
	b.WriteString("```bash\n")
	b.WriteString(script)
	if !strings.HasSuffix(script, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("```\n\n")

	// Output
	b.WriteString("## Script Output\n\n")
	b.WriteString("```\n")
	if scriptOutput != "" {
		b.WriteString(scriptOutput)
		if !strings.HasSuffix(scriptOutput, "\n") {
			b.WriteByte('\n')
		}
	} else {
		b.WriteString("(no output)\n")
	}
	b.WriteString("```\n\n")

	b.WriteString(fmt.Sprintf("**Verdict: %s**\n", verdict))

	if err := os.WriteFile(absPath, []byte(b.String()), 0o644); err != nil {
		return "", fmt.Errorf("write verification artifact: %w", err)
	}

	rel, err := filepath.Rel(workDir, absPath)
	if err != nil {
		rel = absPath
	}
	return rel, nil
}
