// Package testrun detects the project test framework, runs tests, and pipes
// failures to the AI provider for root-cause diagnosis and fix suggestions.
package testrun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// Framework describes a detected test framework and how to run it.
type Framework struct {
	Name    string   // human-readable name, e.g. "go test", "pytest"
	Command []string // executable + args, e.g. ["go", "test", "./..."]
	Lang    string   // "go", "python", "node", "rust", "shell"
}

// TestFailure holds the details of a single failing test.
type TestFailure struct {
	Name    string // test function/case name
	Message string // failure output excerpt (stacktrace, assertion)
}

// Result holds the combined output and counts from a test run.
type Result struct {
	Framework Framework
	Passed    int
	Failed    int
	Skipped   int
	Failures  []TestFailure
	RawOutput string // combined stdout + stderr
	ExitCode  int
}

// Diagnosis is the AI-generated root-cause + fix strategy for one failure.
type Diagnosis struct {
	TestName    string `json:"test_name"`
	RootCause   string `json:"root_cause"`
	FixStrategy string `json:"fix_strategy"`
}

// Report is the final output of the test command.
type Report struct {
	Framework  string
	Passed     int
	Failed     int
	Skipped    int
	Diagnoses  []Diagnosis
	RawOutput  string
	AISummary  string
}

// Detect probes workDir for known project files and returns the best matching
// Framework. It checks in priority order:
//  1. Go (go.mod)
//  2. Rust (Cargo.toml)
//  3. Python (pytest via pyproject.toml / setup.cfg / requirements / .py files)
//  4. Node with vitest (package.json + vitest)
//  5. Node with jest (package.json + jest)
//  6. Node with npm test (package.json fallback)
func Detect(workDir string) (*Framework, error) {
	// Go
	if _, err := os.Stat(filepath.Join(workDir, "go.mod")); err == nil {
		goExe := resolveGo()
		return &Framework{Name: "go test", Command: []string{goExe, "test", "./..."}, Lang: "go"}, nil
	}

	// Rust
	if _, err := os.Stat(filepath.Join(workDir, "Cargo.toml")); err == nil {
		return &Framework{Name: "cargo test", Command: []string{"cargo", "test"}, Lang: "rust"}, nil
	}

	// Python: check for pytest in multiple locations
	if hasPytest(workDir) {
		return &Framework{Name: "pytest", Command: []string{"python", "-m", "pytest", "-v"}, Lang: "python"}, nil
	}

	// Node.js: inspect package.json for test framework
	if f := detectNodeFramework(workDir); f != nil {
		return f, nil
	}

	return nil, fmt.Errorf("could not detect a test framework in %s — no go.mod, Cargo.toml, package.json, or Python project files found", workDir)
}

// hasPytest returns true when a pytest setup or test file is discoverable.
func hasPytest(workDir string) bool {
	// Marker files that strongly indicate Python project
	markers := []string{"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "requirements-dev.txt"}
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(workDir, m)); err == nil {
			return true
		}
	}
	// Any .py test file in root?
	entries, _ := os.ReadDir(workDir)
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "test_") && strings.HasSuffix(e.Name(), ".py") {
			return true
		}
	}
	// Any tests/ or test/ directory?
	for _, d := range []string{"tests", "test"} {
		if info, err := os.Stat(filepath.Join(workDir, d)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

// detectNodeFramework reads package.json and returns the appropriate Framework.
func detectNodeFramework(workDir string) *Framework {
	data, err := os.ReadFile(filepath.Join(workDir, "package.json"))
	if err != nil {
		return nil
	}

	var pkg struct {
		Scripts      map[string]string            `json:"scripts"`
		Dependencies map[string]string            `json:"dependencies"`
		DevDeps      map[string]string            `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		// package.json present but unparseable — fall back to npm test
		return &Framework{Name: "npm test", Command: []string{"npm", "test"}, Lang: "node"}
	}

	hasVitest := hasKey(pkg.Dependencies, "vitest") || hasKey(pkg.DevDeps, "vitest") || hasScript(pkg.Scripts, "vitest")
	hasJest := hasKey(pkg.Dependencies, "jest") || hasKey(pkg.DevDeps, "jest") || hasScript(pkg.Scripts, "jest")

	if hasVitest {
		return &Framework{Name: "vitest", Command: []string{"npx", "vitest", "run"}, Lang: "node"}
	}
	if hasJest {
		return &Framework{Name: "jest", Command: []string{"npx", "jest"}, Lang: "node"}
	}
	if _, ok := pkg.Scripts["test"]; ok {
		return &Framework{Name: "npm test", Command: []string{"npm", "test"}, Lang: "node"}
	}
	return nil
}

// resolveGo returns the path to the Go executable. It checks known installation
// paths before falling back to "go" (relies on PATH).
func resolveGo() string {
	candidates := []string{
		"/usr/local/go/bin/go",
		"/usr/lib/go/bin/go",
		"/opt/homebrew/bin/go",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "go" // fallback: rely on PATH
}

func hasKey(m map[string]string, key string) bool { _, ok := m[key]; return ok }

func hasScript(scripts map[string]string, substr string) bool {
	for _, v := range scripts {
		if strings.Contains(v, substr) {
			return true
		}
	}
	return false
}

// Run executes the framework's test command in workDir and returns a Result.
// A non-zero exit code is not an error — it is reflected in Result.ExitCode.
func Run(ctx context.Context, workDir string, fw *Framework) (*Result, error) {
	if len(fw.Command) == 0 {
		return nil, fmt.Errorf("empty command for framework %s", fw.Name)
	}

	cmd := exec.CommandContext(ctx, fw.Command[0], fw.Command[1:]...) //nolint:gosec
	cmd.Dir = workDir

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	runErr := cmd.Run()

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("running %s: %w", fw.Name, runErr)
		}
	}

	rawOutput := buf.String()
	result := &Result{
		Framework: *fw,
		RawOutput: rawOutput,
		ExitCode:  exitCode,
	}

	// Parse counts + failures based on framework language
	switch fw.Lang {
	case "go":
		parseGoResults(rawOutput, result)
	case "python":
		parsePytestResults(rawOutput, result)
	case "node":
		parseNodeResults(rawOutput, result)
	case "rust":
		parseCargoResults(rawOutput, result)
	default:
		parseGenericResults(rawOutput, result)
	}

	return result, nil
}

// --- Go test parser ---

var (
	goFailRe  = regexp.MustCompile(`(?m)^--- FAIL: (\S+)`)
	goPassRe  = regexp.MustCompile(`(?m)^--- PASS: (\S+)`)
	goSkipRe  = regexp.MustCompile(`(?m)^--- SKIP: (\S+)`)
	goFailBlk = regexp.MustCompile(`(?s)(--- FAIL: \S+ \([^)]+\)\n.*?)(?:--- (?:FAIL|PASS|SKIP):|^(?:ok|FAIL)\s)`)
)

func parseGoResults(output string, r *Result) {
	r.Passed = len(goPassRe.FindAllString(output, -1))
	r.Failed = len(goFailRe.FindAllStringSubmatch(output, -1))
	r.Skipped = len(goSkipRe.FindAllString(output, -1))

	// Extract per-failure blocks
	failMatches := goFailRe.FindAllStringSubmatchIndex(output, -1)
	for _, loc := range failMatches {
		name := output[loc[2]:loc[3]]
		// Grab up to 40 lines after the FAIL: header
		start := loc[0]
		excerpt := extractLines(output[start:], 40)
		r.Failures = append(r.Failures, TestFailure{Name: name, Message: excerpt})
	}
}

// --- pytest parser ---

var (
	pytestFailRe     = regexp.MustCompile(`(?m)^FAILED (.+)`)
	pytestPassRe     = regexp.MustCompile(`(?m) (\d+) passed`)
	pytestFailCntRe  = regexp.MustCompile(`(?m) (\d+) failed`)
	pytestSkipRe     = regexp.MustCompile(`(?m) (\d+) skipped`)
	pytestShortReRe  = regexp.MustCompile(`(?m)^_{5,}\n(.+)\n_{5,}`)
)

func parsePytestResults(output string, r *Result) {
	if m := pytestPassRe.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &r.Passed)
	}
	if m := pytestFailCntRe.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &r.Failed)
	}
	if m := pytestSkipRe.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &r.Skipped)
	}

	// Extract failure sections between "________" separators
	sections := pytestShortReRe.FindAllStringSubmatchIndex(output, -1)
	for _, loc := range sections {
		name := strings.TrimSpace(output[loc[2]:loc[3]])
		// Find the body until the next separator or end
		bodyStart := loc[1]
		bodyEnd := len(output)
		if next := strings.Index(output[bodyStart:], "\n_____"); next != -1 {
			bodyEnd = bodyStart + next
		}
		excerpt := extractLines(output[bodyStart:bodyEnd], 30)
		r.Failures = append(r.Failures, TestFailure{Name: name, Message: excerpt})
	}

	// Fallback: use FAILED lines if no sections found
	if len(r.Failures) == 0 {
		for _, m := range pytestFailRe.FindAllStringSubmatch(output, -1) {
			r.Failures = append(r.Failures, TestFailure{Name: strings.TrimSpace(m[1])})
		}
	}
}

// --- Jest / Vitest / npm test parser ---

var (
	jestFailRe     = regexp.MustCompile(`(?m)^\s*● (.+)`)
	jestPassCntRe  = regexp.MustCompile(`(?m)Tests:\s+(?:\d+ skipped, )?(?:(\d+) passed)?`)
	jestFailCntRe  = regexp.MustCompile(`(?m)Tests:\s+(\d+) failed`)
	jestSkipCntRe  = regexp.MustCompile(`(?m)Tests:\s+(\d+) skipped`)
	vitestPassRe   = regexp.MustCompile(`(?m)(\d+) passed`)
	vitestFailRe   = regexp.MustCompile(`(?m)(\d+) failed`)
)

func parseNodeResults(output string, r *Result) {
	// Try Jest format first
	if m := jestFailCntRe.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &r.Failed)
	}
	if m := jestPassCntRe.FindStringSubmatch(output); len(m) > 1 && m[1] != "" {
		fmt.Sscanf(m[1], "%d", &r.Passed)
	}
	// Try vitest / generic pattern
	if r.Passed == 0 && r.Failed == 0 {
		if m := vitestPassRe.FindStringSubmatch(output); len(m) > 1 {
			fmt.Sscanf(m[1], "%d", &r.Passed)
		}
		if m := vitestFailRe.FindStringSubmatch(output); len(m) > 1 {
			fmt.Sscanf(m[1], "%d", &r.Failed)
		}
	}

	// Extract failure blocks: lines starting with "●"
	for _, m := range jestFailRe.FindAllStringSubmatchIndex(output, -1) {
		name := strings.TrimSpace(output[m[2]:m[3]])
		start := m[0]
		excerpt := extractLines(output[start:], 30)
		r.Failures = append(r.Failures, TestFailure{Name: name, Message: excerpt})
	}

	// If we found no explicit counts, infer from failures
	if r.Failed == 0 && len(r.Failures) > 0 {
		r.Failed = len(r.Failures)
	}
}

// --- Cargo test parser ---

var (
	cargoFailRe    = regexp.MustCompile(`(?m)^test (.+) \.\.\. FAILED`)
	cargoPassCntRe = regexp.MustCompile(`(?m)test result: (?:ok|FAILED)\. (\d+) passed`)
	cargoFailCntRe = regexp.MustCompile(`(?m)test result: (?:ok|FAILED)\. \d+ passed; (\d+) failed`)
	cargoSkipCntRe = regexp.MustCompile(`(?m)\d+ failed; (\d+) ignored`)
)

func parseCargoResults(output string, r *Result) {
	if m := cargoPassCntRe.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &r.Passed)
	}
	if m := cargoFailCntRe.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &r.Failed)
	}
	if m := cargoSkipCntRe.FindStringSubmatch(output); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &r.Skipped)
	}
	for _, m := range cargoFailRe.FindAllStringSubmatchIndex(output, -1) {
		name := output[m[2]:m[3]]
		start := m[0]
		excerpt := extractLines(output[start:], 20)
		r.Failures = append(r.Failures, TestFailure{Name: name, Message: excerpt})
	}
}

// --- Generic fallback ---

func parseGenericResults(output string, r *Result) {
	lower := strings.ToLower(output)
	// Count lines containing "pass" and "fail"
	for _, line := range strings.Split(output, "\n") {
		ll := strings.ToLower(line)
		if strings.Contains(ll, "pass") {
			r.Passed++
		} else if strings.Contains(ll, "fail") || strings.Contains(ll, "error") {
			r.Failed++
		}
	}
	_ = lower
}

// extractLines returns at most n lines from the beginning of s.
func extractLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// DiagnosePrompt builds the AI prompt for analyzing test failures.
func DiagnosePrompt(fw *Framework, failures []TestFailure, taskContext string) string {
	var b strings.Builder

	b.WriteString("You are a senior software engineer diagnosing test failures.\n\n")

	if taskContext != "" {
		b.WriteString("## TASK CONTEXT\n")
		b.WriteString(taskContext)
		b.WriteString("\n\n")
	}

	b.WriteString(fmt.Sprintf("## TEST FRAMEWORK\n%s\n\n", fw.Name))

	b.WriteString("## FAILING TESTS\n\n")
	for i, f := range failures {
		b.WriteString(fmt.Sprintf("### Failure %d: %s\n", i+1, f.Name))
		if f.Message != "" {
			b.WriteString("```\n")
			msg := f.Message
			if len(msg) > 2000 {
				msg = msg[:2000] + "\n...(truncated)"
			}
			b.WriteString(msg)
			b.WriteString("\n```\n\n")
		}
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("For each failing test produce a JSON object in an array with these fields:\n")
	b.WriteString("- test_name: exact test name from above\n")
	b.WriteString("- root_cause: 1-2 sentence concise root cause analysis\n")
	b.WriteString("- fix_strategy: 1-3 sentence concrete fix suggestion (code changes, not just 'fix the bug')\n\n")
	b.WriteString("After the JSON array write a one-paragraph executive summary of overall themes.\n")
	b.WriteString("Format exactly as:\n")
	b.WriteString("```json\n[...]\n```\n\nSUMMARY: <paragraph>\n")

	return b.String()
}

// parseAIResponse extracts the JSON diagnosis array and summary from the AI output.
func parseAIResponse(raw string) ([]Diagnosis, string) {
	// Extract JSON block
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start != -1 && end != -1 && end > start {
		jsonStr := raw[start : end+1]
		var diags []Diagnosis
		if err := json.Unmarshal([]byte(jsonStr), &diags); err == nil {
			// Extract summary after JSON block
			after := raw[end+1:]
			summary := ""
			if idx := strings.Index(after, "SUMMARY:"); idx != -1 {
				summary = strings.TrimSpace(after[idx+8:])
				// Trim to first double newline
				if nl := strings.Index(summary, "\n\n"); nl != -1 {
					summary = strings.TrimSpace(summary[:nl])
				}
			}
			return diags, summary
		}
	}
	// Fallback: no JSON found
	return nil, strings.TrimSpace(raw)
}

// Diagnose calls the AI provider to analyze the test failures and returns a Report.
func Diagnose(ctx context.Context, prov provider.Provider, opts provider.Options, result *Result, taskContext string) (*Report, error) {
	report := &Report{
		Framework: result.Framework.Name,
		Passed:    result.Passed,
		Failed:    result.Failed,
		Skipped:   result.Skipped,
		RawOutput: result.RawOutput,
	}

	if len(result.Failures) == 0 {
		return report, nil
	}

	prompt := DiagnosePrompt(&result.Framework, result.Failures, taskContext)
	resp, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("AI diagnosis failed: %w", err)
	}

	diags, summary := parseAIResponse(resp.Output)
	report.Diagnoses = diags
	report.AISummary = summary

	return report, nil
}

// FormatReport renders a human-readable test report.
func FormatReport(r *Report) string {
	var b strings.Builder

	totalRun := r.Passed + r.Failed + r.Skipped

	b.WriteString(fmt.Sprintf("Framework: %s\n", r.Framework))
	b.WriteString(fmt.Sprintf("Results:   %d passed, %d failed, %d skipped (total: %d)\n",
		r.Passed, r.Failed, r.Skipped, totalRun))
	b.WriteString("\n")

	if r.Failed == 0 {
		b.WriteString("All tests passed.\n")
		return b.String()
	}

	b.WriteString(fmt.Sprintf("%d test(s) failed\n\n", r.Failed))

	if len(r.Diagnoses) > 0 {
		b.WriteString("## AI Root-Cause Analysis\n\n")
		for i, d := range r.Diagnoses {
			b.WriteString(fmt.Sprintf("### %d. %s\n", i+1, d.TestName))
			b.WriteString(fmt.Sprintf("**Root cause:** %s\n\n", d.RootCause))
			b.WriteString(fmt.Sprintf("**Fix strategy:** %s\n\n", d.FixStrategy))
		}
	}

	if r.AISummary != "" {
		b.WriteString("## Summary\n\n")
		b.WriteString(r.AISummary)
		b.WriteString("\n")
	}

	return b.String()
}

// WriteReportArtifact persists the test report to .cloop/tasks/<taskID>-test-report.md.
// If taskID is 0 the filename is test-report-<timestamp>.md.
func WriteReportArtifact(workDir string, taskID int, report *Report) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create artifact dir: %w", err)
	}

	var filename string
	if taskID > 0 {
		filename = fmt.Sprintf("%d-test-report.md", taskID)
	} else {
		filename = "test-report.md"
	}
	absPath := filepath.Join(dir, filename)

	content := "# Test Report\n\n" + FormatReport(report)
	if len(report.RawOutput) > 0 {
		content += "\n## Raw Test Output\n\n```\n"
		raw := report.RawOutput
		if len(raw) > 4000 {
			raw = raw[:4000] + "\n...(truncated)\n"
		}
		content += raw + "\n```\n"
	}

	if err := os.WriteFile(absPath, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}

	rel, err := filepath.Rel(workDir, absPath)
	if err != nil {
		rel = absPath
	}
	return rel, nil
}

// FixPrompt builds the task-add description for the --fix remediation task.
func FixPrompt(fw *Framework, diags []Diagnosis, summary string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Fix %d failing %s test(s): ", len(diags), fw.Name))
	for i, d := range diags {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(d.TestName)
	}
	if summary != "" {
		b.WriteString(". Root cause: ")
		if len(summary) > 200 {
			b.WriteString(summary[:200] + "...")
		} else {
			b.WriteString(summary)
		}
	}
	return b.String()
}
