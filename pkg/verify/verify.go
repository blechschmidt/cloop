// Package verify generates and runs AI-produced shell verification scripts
// after each PM task completes. The script checks observable artifacts—new
// files, successful command exit codes, expected output—to confirm the task
// was genuinely accomplished rather than merely claimed done.
package verify

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
)

// Result holds the outcome of a verification run.
type Result struct {
	Script   string // the shell script that was generated
	Output   string // combined stdout+stderr from the script
	ExitCode int    // 0 = pass
	Passed   bool   // true when ExitCode == 0
}

// GenerateScriptPrompt builds the prompt sent to the AI to produce the
// verification script. Exported so it can be tested independently.
func GenerateScriptPrompt(task *pm.Task, taskOutput string) string {
	var b strings.Builder
	b.WriteString("You are a QA engineer writing a concise shell verification script.\n")
	b.WriteString("Your script must confirm that a software task was genuinely accomplished.\n\n")

	b.WriteString(fmt.Sprintf("## TASK\nID: %d\nTitle: %s\n", task.ID, task.Title))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	b.WriteString("\n")

	b.WriteString("## TASK OUTPUT (what the AI reported doing)\n")
	output := taskOutput
	if len(output) > 2000 {
		output = output[:800] + "\n...(truncated)...\n" + output[len(output)-800:]
	}
	b.WriteString(output)
	b.WriteString("\n\n")

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Write a bash verification script (5-15 lines) that:\n")
	b.WriteString("- Checks for concrete evidence the task was done (files exist, tests pass, commands succeed)\n")
	b.WriteString("- Exits with code 0 if verification passes, non-zero if it fails\n")
	b.WriteString("- Uses only standard Unix tools (bash, test, grep, ls, go, etc.)\n")
	b.WriteString("- Prints a short human-readable message before exiting\n")
	b.WriteString("- Does NOT modify any files or run destructive commands\n\n")
	b.WriteString("Output ONLY the shell script, wrapped in a ```bash code block.\n")
	b.WriteString("Do not include any explanation outside the code block.\n")

	return b.String()
}

// ParseScript extracts the shell script from the AI response.
// It looks for a ```bash ... ``` block. If none is found it attempts
// to use the entire response as-is (trimmed).
func ParseScript(response string) string {
	// Try to find a ```bash block.
	const startMarker = "```bash"
	const endMarker = "```"

	start := strings.Index(response, startMarker)
	if start != -1 {
		start += len(startMarker)
		// Skip optional newline immediately after marker.
		if start < len(response) && response[start] == '\n' {
			start++
		}
		end := strings.Index(response[start:], endMarker)
		if end != -1 {
			return strings.TrimSpace(response[start : start+end])
		}
	}

	// Fallback: try generic ``` block.
	const genericMarker = "```"
	start = strings.Index(response, genericMarker)
	if start != -1 {
		start += len(genericMarker)
		if start < len(response) && response[start] == '\n' {
			start++
		}
		end := strings.Index(response[start:], genericMarker)
		if end != -1 {
			return strings.TrimSpace(response[start : start+end])
		}
	}

	// Last resort: use trimmed response.
	return strings.TrimSpace(response)
}

// GenerateAndRun asks the provider to generate a verification script for the
// given task, writes it to a temp file, executes it in workDir, and returns
// the result. The caller is responsible for persisting the result as an
// artifact and for triggering failure diagnosis when Passed == false.
func GenerateAndRun(
	ctx context.Context,
	p provider.Provider,
	model string,
	timeout time.Duration,
	workDir string,
	task *pm.Task,
	taskOutput string,
) (*Result, error) {
	// 1. Generate the script via the AI provider.
	prompt := GenerateScriptPrompt(task, taskOutput)
	genCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	genResult, err := p.Complete(genCtx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("verify: generate script: %w", err)
	}

	script := ParseScript(genResult.Output)
	if script == "" {
		return nil, fmt.Errorf("verify: AI returned an empty script")
	}

	// 2. Write script to a temp file.
	tmpFile, err := os.CreateTemp("", "cloop-verify-*.sh")
	if err != nil {
		return nil, fmt.Errorf("verify: create temp script: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n\n" + script + "\n"); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("verify: write script: %w", err)
	}
	tmpFile.Close()

	if err := os.Chmod(tmpPath, 0o700); err != nil {
		return nil, fmt.Errorf("verify: chmod script: %w", err)
	}

	// 3. Execute the script with a reasonable timeout.
	execTimeout := timeout
	if execTimeout <= 0 {
		execTimeout = 60 * time.Second
	}
	execCtx, execCancel := context.WithTimeout(ctx, execTimeout)
	defer execCancel()

	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		absWorkDir = workDir
	}

	cmd := exec.CommandContext(execCtx, "bash", tmpPath)
	cmd.Dir = absWorkDir

	out, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			// Non-exit error (timeout, signal, etc.)
			exitCode = 1
			if outStr == "" {
				outStr = runErr.Error()
			}
		}
	}

	return &Result{
		Script:   script,
		Output:   outStr,
		ExitCode: exitCode,
		Passed:   exitCode == 0,
	}, nil
}
