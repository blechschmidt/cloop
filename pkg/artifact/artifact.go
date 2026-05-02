// Package artifact persists the full AI response for each PM task as a
// human-readable Markdown file with YAML frontmatter under .cloop/tasks/.
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

var nonSlugRe = regexp.MustCompile(`[^a-z0-9-]+`)

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
