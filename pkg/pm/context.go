package pm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ProjectContext holds a lightweight snapshot of the project's current state.
// It is injected into task prompts to give the AI situational awareness.
type ProjectContext struct {
	FileTree    string
	GitStatus   string
	RecentLog   string
	WorkDir     string
}

// BuildProjectContext collects project state from the filesystem and git.
// Failures are silently ignored — context is best-effort.
func BuildProjectContext(workdir string) *ProjectContext {
	ctx := &ProjectContext{WorkDir: workdir}
	ctx.FileTree = buildFileTree(workdir)
	ctx.GitStatus = runGit(workdir, "status", "--short")
	ctx.RecentLog = runGit(workdir, "log", "--oneline", "-8")
	return ctx
}

// Format returns a human-readable string of the project context for prompt injection.
// Returns empty string if context is entirely empty.
func (c *ProjectContext) Format() string {
	if c == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("## PROJECT CONTEXT (current state)\n")
	hasContent := false

	if c.FileTree != "" {
		b.WriteString("### File Tree\n```\n")
		b.WriteString(c.FileTree)
		b.WriteString("```\n\n")
		hasContent = true
	}
	if c.GitStatus != "" {
		b.WriteString("### Git Status\n```\n")
		b.WriteString(c.GitStatus)
		b.WriteString("\n```\n\n")
		hasContent = true
	}
	if c.RecentLog != "" {
		b.WriteString("### Recent Commits\n```\n")
		b.WriteString(c.RecentLog)
		b.WriteString("\n```\n\n")
		hasContent = true
	}

	if !hasContent {
		return ""
	}
	return b.String()
}

// runGit runs a git command in workdir and returns stdout (trimmed).
// Returns empty string on error.
func runGit(workdir string, args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = workdir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}

// buildFileTree generates a compact directory listing (depth 3, skip hidden/.git/vendor/node_modules).
// Returns empty string if workdir can't be read.
func buildFileTree(workdir string) string {
	var lines []string
	err := walkTree(workdir, workdir, 0, 3, &lines)
	if err != nil {
		return ""
	}
	if len(lines) == 0 {
		return ""
	}
	// Limit to 60 lines to avoid bloating prompts
	if len(lines) > 60 {
		lines = lines[:60]
		lines = append(lines, fmt.Sprintf("... (%d+ entries omitted)", 60))
	}
	return strings.Join(lines, "\n")
}

// skipDir returns true for directories that should not be traversed.
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".cloop", "__pycache__", ".venv", "venv",
		"dist", "build", ".idea", ".vscode":
		return true
	}
	return strings.HasPrefix(name, ".")
}

func walkTree(root, dir string, depth, maxDepth int, lines *[]string) error {
	if depth > maxDepth {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // silently skip unreadable dirs
	}
	indent := strings.Repeat("  ", depth)
	for _, e := range entries {
		name := e.Name()
		if depth == 0 && skipDir(name) {
			continue
		}
		if e.IsDir() {
			if skipDir(name) {
				continue
			}
			*lines = append(*lines, fmt.Sprintf("%s%s/", indent, name))
			_ = walkTree(root, filepath.Join(dir, name), depth+1, maxDepth, lines)
		} else {
			*lines = append(*lines, fmt.Sprintf("%s%s", indent, name))
		}
	}
	return nil
}
