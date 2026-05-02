// Package testgen generates AI-produced test suites for completed PM tasks.
// It reads the task artifact output, detects the project language, asks the
// provider to write appropriate tests, and writes them to .cloop/tests/.
package testgen

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Lang represents the detected project / task language.
type Lang string

const (
	LangGo     Lang = "go"
	LangPython Lang = "python"
	LangNode   Lang = "node"
	LangShell  Lang = "shell"
)

// Result holds the output of a test generation run.
type Result struct {
	Lang     Lang
	FilePath string // absolute path where tests were written
	Code     string // raw test code written
	Ran      bool   // true if --run was used
	Output   string // combined stdout+stderr when Ran == true
	ExitCode int    // 0 = all tests passed
}

// DetectLang probes workDir for project files and returns the best matching Lang.
// Priority: go.mod > package.json > *.py files > shell (fallback).
func DetectLang(workDir string) Lang {
	if _, err := os.Stat(filepath.Join(workDir, "go.mod")); err == nil {
		return LangGo
	}
	if _, err := os.Stat(filepath.Join(workDir, "package.json")); err == nil {
		return LangNode
	}
	// Any .py file in project root?
	entries, _ := os.ReadDir(workDir)
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".py") {
			return LangPython
		}
	}
	return LangShell
}

// TestFileExt returns the file extension (without leading dot) for the given Lang.
func TestFileExt(lang Lang) string {
	switch lang {
	case LangGo:
		return "go"
	case LangPython:
		return "py"
	case LangNode:
		return "js"
	default:
		return "sh"
	}
}

// BuildPrompt constructs the AI prompt for test generation.
// Exported for independent testing.
func BuildPrompt(task *pm.Task, artifactContent string, lang Lang) string {
	var b strings.Builder

	b.WriteString("You are a senior test engineer. Your job is to write a self-contained test suite for the task described below.\n\n")

	b.WriteString(fmt.Sprintf("## TASK\nID: %d\nTitle: %s\n", task.ID, task.Title))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	b.WriteString("\n")

	if artifactContent != "" {
		content := artifactContent
		if len(content) > 3000 {
			content = content[:1200] + "\n...(truncated)...\n" + content[len(content)-1200:]
		}
		b.WriteString("## TASK OUTPUT (what the AI reported doing)\n")
		b.WriteString(content)
		b.WriteString("\n\n")
	}

	switch lang {
	case LangGo:
		b.WriteString("## INSTRUCTIONS\n")
		b.WriteString("Write Go unit and/or integration tests using the standard `testing` package.\n")
		b.WriteString("Requirements:\n")
		b.WriteString("- Use `package <pkg>_test` naming where appropriate\n")
		b.WriteString("- Cover the main behaviour described by the task (happy path + at least one error case)\n")
		b.WriteString("- Use table-driven tests where it makes the intent clearer\n")
		b.WriteString("- Import only the standard library and packages already present in the project\n")
		b.WriteString("- Do NOT use external test frameworks (no testify, no gomock)\n")
		b.WriteString("- Each test function must start with `Test`\n\n")
		b.WriteString("Output ONLY a single Go source file wrapped in a ```go code block.\n")
		b.WriteString("Do not include any explanation outside the code block.\n")
	case LangPython:
		b.WriteString("## INSTRUCTIONS\n")
		b.WriteString("Write Python tests using the built-in `unittest` module (no pytest required).\n")
		b.WriteString("Requirements:\n")
		b.WriteString("- Subclass `unittest.TestCase`\n")
		b.WriteString("- Cover the main behaviour described by the task (happy path + at least one error case)\n")
		b.WriteString("- Import only the standard library\n")
		b.WriteString("- Include `if __name__ == '__main__': unittest.main()` at the bottom\n\n")
		b.WriteString("Output ONLY a single Python source file wrapped in a ```python code block.\n")
		b.WriteString("Do not include any explanation outside the code block.\n")
	case LangNode:
		b.WriteString("## INSTRUCTIONS\n")
		b.WriteString("Write Node.js tests using the built-in `node:test` runner (available from Node 18+).\n")
		b.WriteString("Requirements:\n")
		b.WriteString("- Use `import { test, describe } from 'node:test'` and `import assert from 'node:assert'`\n")
		b.WriteString("- Cover the main behaviour described by the task (happy path + at least one error case)\n")
		b.WriteString("- Import only built-in Node.js modules\n\n")
		b.WriteString("Output ONLY a single JavaScript source file wrapped in a ```javascript code block.\n")
		b.WriteString("Do not include any explanation outside the code block.\n")
	default: // shell
		b.WriteString("## INSTRUCTIONS\n")
		b.WriteString("Write a bash acceptance test script.\n")
		b.WriteString("Requirements:\n")
		b.WriteString("- Each test is a shell function prefixed with `test_`\n")
		b.WriteString("- Use `assert_eq` and `assert_contains` helper functions (define them at the top)\n")
		b.WriteString("- Exit 0 if all tests pass, non-zero on first failure\n")
		b.WriteString("- Print a pass/fail summary at the end\n")
		b.WriteString("- Use only standard Unix tools (bash, test, grep, ls, etc.)\n\n")
		b.WriteString("Output ONLY the shell script wrapped in a ```bash code block.\n")
		b.WriteString("Do not include any explanation outside the code block.\n")
	}

	return b.String()
}

// extractCode strips the fenced code block markers from AI output.
// Accepts ```go, ```python, ```javascript, ```bash, or ``` (plain).
var fenceRe = regexp.MustCompile("(?s)```[a-zA-Z]*\n(.*?)```")

func extractCode(raw string) string {
	if m := fenceRe.FindStringSubmatch(raw); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return strings.TrimSpace(raw)
}

// Generate calls the AI provider to produce a test suite, writes it to
// .cloop/tests/<task-id>_test.<ext>, and returns a Result.
func Generate(ctx context.Context, prov provider.Provider, opts provider.Options, workDir string, task *pm.Task, lang Lang) (*Result, error) {
	// Read artifact content if available.
	var artifactContent string
	if task.ArtifactPath != "" {
		absArtifact := filepath.Join(workDir, task.ArtifactPath)
		data, err := os.ReadFile(absArtifact)
		if err == nil {
			artifactContent = string(data)
		}
	}

	prompt := BuildPrompt(task, artifactContent, lang)

	resp, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("AI call failed: %w", err)
	}
	raw := resp.Output

	code := extractCode(raw)
	if code == "" {
		return nil, fmt.Errorf("AI returned no code block — raw response: %s", truncate(raw, 300))
	}

	// Write to .cloop/tests/<id>_test.<ext>
	testsDir := filepath.Join(workDir, ".cloop", "tests")
	if err := os.MkdirAll(testsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create tests dir: %w", err)
	}

	ext := TestFileExt(lang)
	filename := fmt.Sprintf("%d_test.%s", task.ID, ext)
	absPath := filepath.Join(testsDir, filename)

	if err := os.WriteFile(absPath, []byte(code+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("write test file: %w", err)
	}

	return &Result{
		Lang:     lang,
		FilePath: absPath,
		Code:     code,
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
