// Package docs implements AI-powered documentation maintenance for cloop projects.
// It collects existing documentation, computes a coverage score, and produces
// AI-refreshed content via RefreshPrompt.
package docs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// DocFile describes a single documentation file tracked by cloop docs.
type DocFile struct {
	// RelPath is the path relative to projectDir (e.g. "README.md", "docs/API.md").
	RelPath string
	// AbsPath is the absolute filesystem path.
	AbsPath string
	// Content is the file's current text, empty when Exists is false.
	Content string
	// Exists reports whether the file was found on disk.
	Exists bool
	// IsStale is true when the file was last modified before the most recent
	// completed task — a heuristic for "potentially outdated".
	IsStale bool
}

// ProjectDocs is the result of Collect and carries all context needed to
// refresh or score documentation.
type ProjectDocs struct {
	WorkDir    string
	ProjectDir string

	// Files is the ordered list of tracked documentation files.
	Files []*DocFile

	// GitLog is the recent git commit history (last 20 lines, oneline).
	GitLog string

	// CompletedTasks holds tasks in done/skipped status for context.
	CompletedTasks []*pm.Task

	// CodeSignature is a compact representation of the project structure
	// (directory tree + manifest content).
	CodeSignature string
}

// coverageTargets defines the files that contribute to the coverage score.
// Each entry is a relative path and its point value (total = 100).
var coverageTargets = []struct {
	RelPath string
	Points  int
	Label   string
}{
	{"README.md", 30, "README.md"},
	{"CONTRIBUTING.md", 25, "CONTRIBUTING.md"},
	{"LICENSE", 20, "LICENSE"},
	{"docs/API.md", 15, "docs/API.md"},
	{"CHANGELOG.md", 10, "CHANGELOG.md"},
}

// CoverageScore checks for key documentation files in projectDir and returns
// a 0–100 score together with the list of missing file labels.
func CoverageScore(projectDir string) (score int, missing []string) {
	for _, t := range coverageTargets {
		path := filepath.Join(projectDir, t.RelPath)
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() && info.Size() > 0 {
			score += t.Points
		} else {
			missing = append(missing, t.Label)
		}
	}
	return score, missing
}

// Collect gathers existing docs, git log summary, and completed task history
// from workDir (the cloop project root, containing .cloop/) and projectDir
// (where documentation files are located; often the same as workDir).
func Collect(workDir, projectDir string) (*ProjectDocs, error) {
	pd := &ProjectDocs{
		WorkDir:    workDir,
		ProjectDir: projectDir,
	}

	// Collect tracked doc files.
	var lastCompletedAt time.Time

	// Load state to get task history.
	s, err := state.Load(workDir)
	if err == nil && s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			switch t.Status {
			case pm.TaskDone, pm.TaskSkipped:
				pd.CompletedTasks = append(pd.CompletedTasks, t)
				if t.CompletedAt != nil && t.CompletedAt.After(lastCompletedAt) {
					lastCompletedAt = *t.CompletedAt
				}
			}
		}
	}

	// Read tracked documentation files.
	for _, target := range coverageTargets {
		absPath := filepath.Join(projectDir, target.RelPath)
		df := &DocFile{
			RelPath: target.RelPath,
			AbsPath: absPath,
		}
		data, readErr := os.ReadFile(absPath)
		if readErr == nil {
			df.Exists = true
			df.Content = string(data)
			// Mark stale if the file is older than the most recent completed task.
			if !lastCompletedAt.IsZero() {
				info, statErr := os.Stat(absPath)
				if statErr == nil && info.ModTime().Before(lastCompletedAt) {
					df.IsStale = true
				}
			}
		}
		pd.Files = append(pd.Files, df)
	}

	// Collect any additional *.md files under docs/ directory.
	docsDir := filepath.Join(projectDir, "docs")
	if entries, err := os.ReadDir(docsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(strings.ToLower(name), ".md") {
				continue
			}
			relPath := filepath.Join("docs", name)
			// Skip files already in the tracked list.
			alreadyTracked := false
			for _, f := range pd.Files {
				if f.RelPath == relPath {
					alreadyTracked = true
					break
				}
			}
			if alreadyTracked {
				continue
			}
			absPath := filepath.Join(docsDir, name)
			df := &DocFile{RelPath: relPath, AbsPath: absPath}
			if data, err := os.ReadFile(absPath); err == nil {
				df.Exists = true
				df.Content = string(data)
				if !lastCompletedAt.IsZero() {
					if info, statErr := os.Stat(absPath); statErr == nil && info.ModTime().Before(lastCompletedAt) {
						df.IsStale = true
					}
				}
			}
			pd.Files = append(pd.Files, df)
		}
	}

	// Git log.
	if out, err := runGit(projectDir, "log", "--oneline", "-20"); err == nil {
		pd.GitLog = strings.TrimSpace(out)
	}

	// Code signature: directory tree + manifest.
	if tree, err := runCmd(projectDir, "find", ".", "-not", "-path", "./.git/*",
		"-not", "-path", "./.cloop/*", "-not", "-path", "./vendor/*",
		"-maxdepth", "4", "-name", "*.go", "-o", "-name", "*.ts", "-o",
		"-name", "*.py", "-o", "-name", "*.rs"); err == nil {
		lines := strings.Split(strings.TrimSpace(tree), "\n")
		if len(lines) > 50 {
			lines = lines[:50]
		}
		pd.CodeSignature = strings.Join(lines, "\n")
	}
	for _, manifest := range []string{"go.mod", "package.json", "Cargo.toml", "pyproject.toml"} {
		mPath := filepath.Join(projectDir, manifest)
		if data, err := os.ReadFile(mPath); err == nil {
			content := string(data)
			if len(content) > 600 {
				content = content[:600] + "\n..."
			}
			pd.CodeSignature += "\n\n" + manifest + ":\n" + content
			break
		}
	}

	return pd, nil
}

// TaskHistory builds a compact Markdown summary of completed tasks suitable
// for inclusion in an AI prompt.
func TaskHistory(tasks []*pm.Task) string {
	if len(tasks) == 0 {
		return "(no completed tasks)"
	}
	var b strings.Builder
	// Include at most 40 most recent.
	start := 0
	if len(tasks) > 40 {
		start = len(tasks) - 40
	}
	for _, t := range tasks[start:] {
		b.WriteString(fmt.Sprintf("- [%s] Task %d: %s\n", t.Status, t.ID, t.Title))
		if t.Result != "" {
			summary := t.Result
			if len(summary) > 200 {
				summary = summary[:200] + "…"
			}
			b.WriteString(fmt.Sprintf("  Result: %s\n", summary))
		} else if t.Description != "" {
			desc := t.Description
			if len(desc) > 150 {
				desc = desc[:150] + "…"
			}
			b.WriteString(fmt.Sprintf("  %s\n", desc))
		}
	}
	return b.String()
}

// RefreshPrompt builds the AI prompt that asks the provider to produce an
// updated version of the documentation file described by existing.
// taskHistory is the output of TaskHistory; codeSignature is pd.CodeSignature.
func RefreshPrompt(existing *DocFile, taskHistory, codeSignature string) string {
	var b strings.Builder

	b.WriteString("You are a technical writer maintaining project documentation.\n")
	b.WriteString("Your task is to produce an UPDATED version of the documentation file below.\n\n")

	b.WriteString(fmt.Sprintf("## FILE: %s\n\n", existing.RelPath))

	if existing.Exists && existing.Content != "" {
		content := existing.Content
		if len(content) > 6000 {
			content = content[:6000] + "\n...(truncated)"
		}
		b.WriteString("### CURRENT CONTENT\n")
		b.WriteString("```markdown\n")
		b.WriteString(content)
		b.WriteString("\n```\n\n")
	} else {
		b.WriteString("### CURRENT CONTENT\n(file does not exist yet — create it from scratch)\n\n")
	}

	b.WriteString("### RECENT TASK HISTORY\n")
	b.WriteString(taskHistory + "\n\n")

	if codeSignature != "" {
		sig := codeSignature
		if len(sig) > 2000 {
			sig = sig[:2000] + "\n..."
		}
		b.WriteString("### CODE SIGNATURE (project structure)\n")
		b.WriteString("```\n" + sig + "\n```\n\n")
	}

	b.WriteString("---\n\n")
	b.WriteString("## INSTRUCTIONS\n\n")
	b.WriteString(fmt.Sprintf("Produce a complete, updated `%s` that:\n", existing.RelPath))
	b.WriteString("- Incorporates all recently completed work listed in the task history\n")
	b.WriteString("- Removes or corrects outdated information\n")
	b.WriteString("- Uses GitHub-flavored Markdown\n")
	b.WriteString("- Is professional, concise, and accurate\n\n")
	b.WriteString("Output ONLY the raw Markdown content. Do NOT wrap it in a code block.\n")
	b.WriteString("Do NOT add any preamble, explanation, or commentary — just the document.\n")

	return b.String()
}

// Refresh calls the AI provider to produce updated content for a single doc
// file and returns the refreshed Markdown string.
func Refresh(ctx context.Context, p provider.Provider, model string, timeout time.Duration, df *DocFile, pd *ProjectDocs) (string, error) {
	history := TaskHistory(pd.CompletedTasks)
	prompt := RefreshPrompt(df, history, pd.CodeSignature)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return "", fmt.Errorf("docs refresh %s: %w", df.RelPath, err)
	}
	return result.Output, nil
}

// runGit runs a git command in dir and returns its combined output.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}

// runCmd runs an arbitrary command in dir.
func runCmd(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}
