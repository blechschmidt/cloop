// Package tdd provides AI-generated acceptance criteria and post-execution
// test verification for cloop PM tasks.
//
// The workflow is two-phase:
//  1. GenerateCriteria (--generate mode): before task execution the AI writes
//     acceptance criteria (criteria.md) and a runnable test script (test.sh)
//     stored under .cloop/tdd/<task-id>/.
//  2. RunTests (--verify mode): after task execution the stored test.sh is
//     executed; the exit code and output are used to update TDDStatus on the
//     task and append a result section to the task artifact.
package tdd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// TestResult holds the outcome of running the test script.
type TestResult struct {
	ExitCode int
	Output   string
	Passed   bool
	Elapsed  time.Duration
}

// TDDDir returns the directory where TDD artifacts for a task are stored.
func TDDDir(workDir string, taskID int) string {
	return filepath.Join(workDir, ".cloop", "tdd", fmt.Sprintf("%d", taskID))
}

// CriteriaPath returns the path to the acceptance criteria Markdown file.
func CriteriaPath(workDir string, taskID int) string {
	return filepath.Join(TDDDir(workDir, taskID), "criteria.md")
}

// TestScriptPath returns the path to the runnable test script.
func TestScriptPath(workDir string, taskID int) string {
	return filepath.Join(TDDDir(workDir, taskID), "test.sh")
}

// GenerateCriteriaPrompt builds the AI prompt that produces acceptance criteria
// and a runnable test script for the given task.
func GenerateCriteriaPrompt(task *pm.Task) string {
	var b strings.Builder

	b.WriteString("You are a QA engineer writing acceptance criteria and a verification test script.\n")
	b.WriteString("Your goal: define BEFORE execution what 'done' looks like for this task,\n")
	b.WriteString("then produce a bash script that can be run AFTER execution to confirm it.\n\n")

	b.WriteString(fmt.Sprintf("## TASK\nID: %d\nTitle: %s\n", task.ID, task.Title))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	if task.Role != "" {
		b.WriteString(fmt.Sprintf("Role: %s\n", task.Role))
	}
	b.WriteString("\n")

	b.WriteString("## OUTPUT FORMAT\n\n")
	b.WriteString("Produce TWO sections, in this exact order:\n\n")
	b.WriteString("### SECTION 1 — ACCEPTANCE CRITERIA\n")
	b.WriteString("Open with exactly: ```criteria\n")
	b.WriteString("List 3-7 concrete, testable criteria, one per line, starting with '- '.\n")
	b.WriteString("Each criterion must be objectively verifiable (files exist, commands succeed,\n")
	b.WriteString("output matches pattern, tests pass, etc.).\n")
	b.WriteString("Close with: ```\n\n")
	b.WriteString("### SECTION 2 — TEST SCRIPT\n")
	b.WriteString("Open with exactly: ```bash\n")
	b.WriteString("Write a bash verification script (8-20 lines) that:\n")
	b.WriteString("- Checks each acceptance criterion with a concrete shell command\n")
	b.WriteString("- Prints a short message before each check (e.g. 'Checking: <criterion>')\n")
	b.WriteString("- Exits 0 if ALL checks pass, non-zero if any fail\n")
	b.WriteString("- Uses only standard Unix tools (bash, test, grep, ls, go, etc.)\n")
	b.WriteString("- Does NOT modify any files or run destructive commands\n")
	b.WriteString("Close with: ```\n\n")
	b.WriteString("Output ONLY these two code blocks. No extra explanation.\n")

	return b.String()
}

// VerifyPrompt builds the AI prompt used to interpret test script output and
// assign a quality score. It is used in the optional AI-narration step.
func VerifyPrompt(task *pm.Task, testOutput string) string {
	var b strings.Builder

	b.WriteString("You are a QA engineer reviewing whether a software task passed its acceptance tests.\n\n")

	b.WriteString(fmt.Sprintf("## TASK\nID: %d\nTitle: %s\n", task.ID, task.Title))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	b.WriteString("\n")

	b.WriteString("## TEST OUTPUT\n```\n")
	output := testOutput
	if len(output) > 3000 {
		output = output[:1200] + "\n...(truncated)...\n" + output[len(output)-1200:]
	}
	b.WriteString(output)
	if !strings.HasSuffix(output, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("```\n\n")

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Based on the test output above, respond with a JSON object (no markdown fences):\n")
	b.WriteString(`{"status":"pass"|"fail","score":0-100,"summary":"one sentence"}`)
	b.WriteString("\n\n")
	b.WriteString("- status: 'pass' if all checks succeeded, 'fail' otherwise\n")
	b.WriteString("- score: percentage (0-100) of acceptance criteria that passed\n")
	b.WriteString("- summary: brief human-readable verdict\n")
	b.WriteString("Respond with JSON ONLY, no other text.\n")

	return b.String()
}

// extractCriteria pulls the content of the first ```criteria ... ``` block.
func extractCriteria(raw string) string {
	re := regexp.MustCompile("(?s)```criteria\r?\n(.*?)```")
	m := re.FindStringSubmatch(raw)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// extractBashScript pulls the content of the first ```bash ... ``` block.
func extractBashScript(raw string) string {
	re := regexp.MustCompile("(?s)```bash\r?\n(.*?)```")
	m := re.FindStringSubmatch(raw)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// GenerateCriteria calls the AI provider to produce acceptance criteria and a
// test script for the task. Returns (criteriaMarkdown, shellScript, error).
func GenerateCriteria(ctx context.Context, prov provider.Provider, opts provider.Options, task *pm.Task) (string, string, error) {
	prompt := GenerateCriteriaPrompt(task)

	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return "", "", fmt.Errorf("provider error: %w", err)
	}
	resp := result.Output

	criteria := extractCriteria(resp)
	script := extractBashScript(resp)

	if criteria == "" {
		// Fallback: treat entire response as criteria if blocks weren't found
		criteria = strings.TrimSpace(resp)
	}
	if script == "" {
		script = "#!/usr/bin/env bash\nset -e\necho \"No test script was generated for this task.\"\nexit 0\n"
	}

	// Ensure script has shebang
	if !strings.HasPrefix(script, "#!") {
		script = "#!/usr/bin/env bash\nset -e\n" + script
	}

	// Build criteria markdown
	var criteriaDoc strings.Builder
	criteriaDoc.WriteString(fmt.Sprintf("# Acceptance Criteria — Task %d: %s\n\n", task.ID, task.Title))
	if task.Description != "" {
		criteriaDoc.WriteString(fmt.Sprintf("**Description:** %s\n\n", task.Description))
	}
	criteriaDoc.WriteString("## Criteria\n\n")
	criteriaDoc.WriteString(criteria)
	criteriaDoc.WriteString("\n\n---\n")
	criteriaDoc.WriteString(fmt.Sprintf("_Generated at %s_\n", time.Now().UTC().Format(time.RFC3339)))

	return criteriaDoc.String(), script, nil
}

// SaveCriteria writes the criteria.md and test.sh files to .cloop/tdd/<taskID>/.
// The test script is made executable (0755).
func SaveCriteria(workDir string, taskID int, criteria, testScript string) error {
	dir := TDDDir(workDir, taskID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create tdd dir: %w", err)
	}

	if err := os.WriteFile(CriteriaPath(workDir, taskID), []byte(criteria), 0o644); err != nil {
		return fmt.Errorf("write criteria.md: %w", err)
	}

	if err := os.WriteFile(TestScriptPath(workDir, taskID), []byte(testScript), 0o755); err != nil {
		return fmt.Errorf("write test.sh: %w", err)
	}

	return nil
}

// RunTests executes the test script for a task and returns the result.
// The script is run from workDir so relative paths resolve correctly.
// Returns an error only when the script cannot be found or started; a
// non-zero exit code is reported via TestResult.ExitCode, not as an error.
func RunTests(workDir string, taskID int) (TestResult, error) {
	scriptPath := TestScriptPath(workDir, taskID)
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return TestResult{}, fmt.Errorf("test script not found at %s — run 'cloop task tdd %d --generate' first", scriptPath, taskID)
	}

	// Ensure script is executable
	if err := os.Chmod(scriptPath, 0o755); err != nil {
		return TestResult{}, fmt.Errorf("chmod test script: %w", err)
	}

	start := time.Now()
	cmd := exec.Command("bash", scriptPath)
	cmd.Dir = workDir

	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out

	runErr := cmd.Run()
	elapsed := time.Since(start)

	exitCode := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return TestResult{}, fmt.Errorf("run test script: %w", runErr)
		}
	}

	return TestResult{
		ExitCode: exitCode,
		Output:   out.String(),
		Passed:   exitCode == 0,
		Elapsed:  elapsed,
	}, nil
}

// AppendResultToArtifact appends TDD result information to the task artifact file.
// It is a best-effort operation; errors are returned but callers may ignore them.
func AppendResultToArtifact(workDir string, task *pm.Task, result TestResult) error {
	if task.ArtifactPath == "" {
		return nil
	}

	absPath := filepath.Join(workDir, task.ArtifactPath)
	f, err := os.OpenFile(absPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open artifact: %w", err)
	}
	defer f.Close()

	verdict := "PASS"
	if !result.Passed {
		verdict = "FAIL"
	}

	var b strings.Builder
	b.WriteString("\n---\n\n")
	b.WriteString("## TDD Verification\n\n")
	b.WriteString(fmt.Sprintf("**Verdict:** %s  \n", verdict))
	b.WriteString(fmt.Sprintf("**Exit code:** %d  \n", result.ExitCode))
	b.WriteString(fmt.Sprintf("**Elapsed:** %s  \n", result.Elapsed.Round(time.Millisecond)))
	b.WriteString(fmt.Sprintf("**Score:** %d%%  \n\n", task.TDDScore))
	b.WriteString("### Test Output\n\n```\n")
	output := result.Output
	if output == "" {
		output = "(no output)\n"
	}
	b.WriteString(output)
	if !strings.HasSuffix(output, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("```\n")

	_, err = f.WriteString(b.String())
	return err
}
