// Package e2e_test contains end-to-end integration tests for the cloop binary.
// Each test invokes the real binary via os/exec against a temporary working
// directory, checks structural output correctness, and compares deterministic
// output against golden files in testdata/*.golden.
//
// To regenerate golden files after intentional output changes:
//
//	go test ./tests/e2e/ -update
package e2e_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────
// 1. cloop init + cloop status
// ─────────────────────────────────────────────

func TestE2EInitAndStatus(t *testing.T) {
	dir := newWorkDir(t)

	// Run init.
	out := mustRun(t, dir, "init", "Build a test API")
	assertContains(t, out, "cloop initialized")
	assertContains(t, out, "Build a test API")
	assertContains(t, out, "State:")
	assertContains(t, out, "Config:")

	// State file must exist.
	statePath := filepath.Join(dir, ".cloop", "state.json")
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		t.Fatalf("state.json not created after init")
	}

	// Config file must exist.
	cfgPath := filepath.Join(dir, ".cloop", "config.yaml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Fatalf("config.yaml not created after init")
	}

	// .gitignore should contain .cloop/env.yaml.
	giData, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatalf("reading .gitignore: %v", err)
	}
	if !strings.Contains(string(giData), ".cloop/env.yaml") {
		t.Errorf(".gitignore should contain .cloop/env.yaml, got:\n%s", string(giData))
	}

	// Run status.
	statusOut := mustRun(t, dir, "status")
	assertContains(t, statusOut, "Build a test API")
	assertContains(t, statusOut, "initialized")
	assertContains(t, statusOut, "Provider:")
	assertContains(t, statusOut, "Created:")

	// Golden comparison on normalized status output.
	normalized := normalizeOutput(statusOut, dir)
	assertGolden(t, "init_status", normalized)
}

func TestE2EInitWithProvider(t *testing.T) {
	dir := newWorkDir(t)
	out := mustRun(t, dir, "init", "--provider", "anthropic", "Test goal")
	assertContains(t, out, "anthropic")
	assertContains(t, out, "cloop initialized")

	// Verify config.yaml records the provider.
	cfgData, err := os.ReadFile(filepath.Join(dir, ".cloop", "config.yaml"))
	if err != nil {
		t.Fatalf("reading config.yaml: %v", err)
	}
	if !strings.Contains(string(cfgData), "anthropic") {
		t.Errorf("config.yaml should contain provider=anthropic, got:\n%s", string(cfgData))
	}
}

func TestE2EInitPMMode(t *testing.T) {
	dir := newWorkDir(t)
	out := mustRun(t, dir, "init", "--pm", "Build with PM mode")
	assertContains(t, out, "PM mode enabled")

	// Status should reflect PM mode.
	statusOut := mustRun(t, dir, "status")
	assertContains(t, statusOut, "product manager")
}

func TestE2EInitRequiresGoal(t *testing.T) {
	dir := newWorkDir(t)
	out, err := run(t, dir, "init")
	if err == nil {
		t.Fatalf("expected error when no goal provided, got: %s", out)
	}
	assertContains(t, out, "goal")
}

func TestE2EStatusNoProject(t *testing.T) {
	dir := newWorkDir(t)
	out, err := run(t, dir, "status")
	if err == nil {
		t.Fatalf("expected error without project, got success: %s", out)
	}
	assertContains(t, out, "cloop init")
}

func TestE2EStatusJSON(t *testing.T) {
	dir := newWorkDir(t)
	mustRun(t, dir, "init", "JSON status test")

	out := mustRun(t, dir, "status", "--json")
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("status --json output is not valid JSON: %v\nOutput:\n%s", err, out)
	}
	if parsed["goal"] != "JSON status test" {
		t.Errorf("expected goal 'JSON status test', got %v", parsed["goal"])
	}
	if parsed["status"] != "initialized" {
		t.Errorf("expected status 'initialized', got %v", parsed["status"])
	}
}

// ─────────────────────────────────────────────
// 2. cloop task bulk done
// ─────────────────────────────────────────────

func TestE2ETaskBulkDone(t *testing.T) {
	dir := newWorkDir(t)
	mustRun(t, dir, "init", "--pm", "Task bulk test")

	// Inject a pre-built plan with 3 tasks via fixture state.
	writeFixtureState(t, dir, pmFixtureState("Task bulk test"))

	// Mark tasks 1 and 2 as done.
	out := mustRun(t, dir, "task", "bulk", "done", "1", "2")
	assertContains(t, out, "Bulk done")
	assertContains(t, out, "2 task(s)")
	assertContains(t, out, "First task")
	assertContains(t, out, "Second task")

	// Verify state updated on disk.
	statusOut := mustRun(t, dir, "status")
	assertContains(t, statusOut, "2/3")
}

func TestE2ETaskBulkDoneCommaSeparated(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Bulk comma test"))

	out := mustRun(t, dir, "task", "bulk", "done", "1,2,3")
	assertContains(t, out, "3 task(s)")
}

func TestE2ETaskBulkDoneAll(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Bulk all test"))

	out := mustRun(t, dir, "task", "bulk", "done", "--all")
	assertContains(t, out, "3 task(s)")
}

func TestE2ETaskBulkDoneNoProject(t *testing.T) {
	dir := newWorkDir(t)
	mustRun(t, dir, "init", "No plan test") // init without --pm

	out, err := run(t, dir, "task", "bulk", "done", "1")
	if err == nil {
		t.Fatalf("expected error when no plan: %s", out)
	}
	assertContains(t, out, "no task plan found")
}

func TestE2ETaskBulkSkipFail(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Bulk skip/fail test"))

	skipOut := mustRun(t, dir, "task", "bulk", "skip", "1")
	assertContains(t, skipOut, "skipped")

	failOut := mustRun(t, dir, "task", "bulk", "fail", "2")
	assertContains(t, failOut, "failed")
}

func TestE2ETaskBulkReset(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Bulk reset test"))

	// First mark done, then reset.
	mustRun(t, dir, "task", "bulk", "done", "1")
	out := mustRun(t, dir, "task", "bulk", "reset", "1")
	assertContains(t, out, "reset to pending")
}

// ─────────────────────────────────────────────
// 3. cloop export --format json
// ─────────────────────────────────────────────

func TestE2EExportJSON(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Export JSON test"))

	out := mustRun(t, dir, "export", "--format", "json")

	// Must be valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("export --format json output is not valid JSON: %v\nOutput:\n%s", err, out)
	}

	// Check key fields are present.
	if parsed["goal"] == nil {
		t.Error("export JSON missing 'goal' field")
	}
	if parsed["status"] == nil {
		t.Error("export JSON missing 'status' field")
	}
	if parsed["plan"] == nil {
		t.Error("export JSON missing 'plan' field (PM mode)")
	}
}

func TestE2EExportMarkdown(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Export markdown test"))

	out := mustRun(t, dir, "export", "--format", "markdown")
	assertContains(t, out, "# cloop Session Report")
	assertContains(t, out, "Export markdown test")
	assertContains(t, out, "## Task Plan")
	assertContains(t, out, "First task")
}

func TestE2EExportCSV(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Export CSV test"))

	out := mustRun(t, dir, "export", "--format", "csv")
	// First line must be the header.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 1 {
		t.Fatalf("CSV output is empty")
	}
	if lines[0] != "id,title,status,priority,role,estimated_minutes,actual_minutes,variance_pct" {
		t.Errorf("unexpected CSV header: %q", lines[0])
	}
	// Should have 3 data rows (one per task).
	if len(lines) != 4 { // header + 3 tasks
		t.Errorf("expected 4 CSV lines (header + 3 tasks), got %d", len(lines))
	}
}

func TestE2EExportToFile(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Export to file test"))

	outFile := filepath.Join(dir, "report.json")
	out := mustRun(t, dir, "export", "--format", "json", "-o", outFile)
	assertContains(t, out, "Report written to")

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output file is not valid JSON: %v", err)
	}
}

func TestE2EExportInvalidFormat(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Export invalid format"))

	out, err := run(t, dir, "export", "--format", "xml")
	if err == nil {
		t.Fatalf("expected error for invalid format, got: %s", out)
	}
	assertContains(t, out, "unknown format")
}

// ─────────────────────────────────────────────
// 4. cloop report --format markdown
// ─────────────────────────────────────────────

func TestE2EReportMarkdown(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Report markdown test"))

	out := mustRun(t, dir, "report", "--format", "markdown")
	assertContains(t, out, "Report markdown test")
	assertContains(t, out, "First task")
	assertContains(t, out, "Second task")
	assertContains(t, out, "Third task")
}

func TestE2EReportTerminal(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Report terminal test"))

	out := mustRun(t, dir, "report")
	assertContains(t, out, "Report terminal test")
}

func TestE2EReportHTML(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Report HTML test"))

	out := mustRun(t, dir, "report", "--format", "html")
	assertContains(t, out, "<!DOCTYPE html>")
	assertContains(t, out, "Report HTML test")
}

func TestE2EReportToFile(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Report to file test"))

	outFile := filepath.Join(dir, "report.md")
	out := mustRun(t, dir, "report", "--format", "markdown", "-o", outFile)
	assertContains(t, out, "Report saved to")

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("report file not created: %v", err)
	}
	if !strings.Contains(string(data), "Report to file test") {
		t.Errorf("report file doesn't contain expected content")
	}
}

func TestE2EReportInvalidFormat(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Report invalid format"))

	out, err := run(t, dir, "report", "--format", "pdf")
	if err == nil {
		t.Fatalf("expected error for invalid format, got: %s", out)
	}
	assertContains(t, out, "invalid format")
}

// ─────────────────────────────────────────────
// 5. cloop viz
// ─────────────────────────────────────────────

func TestE2EVizMermaid(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, vizFixtureState())

	out := mustRun(t, dir, "viz", "--format", "mermaid")
	assertContains(t, out, "```mermaid")
	assertContains(t, out, "flowchart TD")
	assertContains(t, out, "First task")
	assertContains(t, out, "Second task")

	// Golden comparison — mermaid output is deterministic.
	normalized := normalizeOutput(out, dir)
	assertGolden(t, "viz_mermaid", normalized)
}

func TestE2EVizDOT(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, vizFixtureState())

	out := mustRun(t, dir, "viz", "--format", "dot")
	assertContains(t, out, "digraph")
	assertContains(t, out, "First task")

	normalized := normalizeOutput(out, dir)
	assertGolden(t, "viz_dot", normalized)
}

func TestE2EVizASCII(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, vizFixtureState())

	out := mustRun(t, dir, "viz", "--format", "ascii")
	// ASCII output contains task titles.
	assertContains(t, out, "First task")
	assertContains(t, out, "Second task")
}

func TestE2EVizToFile(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, vizFixtureState())

	outFile := filepath.Join(dir, "graph.mmd")
	_, err := run(t, dir, "viz", "--format", "mermaid", "-o", outFile)
	// The command writes to stderr "wrote <file>" and exits 0.
	if err != nil {
		t.Fatalf("viz -o failed: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("viz output file not created: %v", err)
	}
	if !strings.Contains(string(data), "flowchart TD") {
		t.Errorf("viz output file missing mermaid content")
	}
}

func TestE2EVizNoPlan(t *testing.T) {
	dir := newWorkDir(t)
	mustRun(t, dir, "init", "No plan")

	out, err := run(t, dir, "viz")
	if err == nil {
		t.Fatalf("expected error when no plan: %s", out)
	}
	assertContains(t, out, "no active plan")
}

// ─────────────────────────────────────────────
// 6. cloop rollback
// ─────────────────────────────────────────────

func TestE2ERollbackList(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Rollback list test"))

	// Write a snapshot so rollback has something to list.
	writeFixtureSnapshot(t, dir, 1)

	out := mustRun(t, dir, "rollback")
	assertContains(t, out, "ID")
	assertContains(t, out, "Timestamp")
	assertContains(t, out, "Tasks")
	assertContains(t, out, "v1")
}

func TestE2ERollbackNoSnapshots(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("No snapshots test"))

	out := mustRun(t, dir, "rollback")
	assertContains(t, out, "No plan snapshots found")
}

func TestE2ERollbackRestoreYes(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Rollback restore test"))
	writeFixtureSnapshot(t, dir, 1)

	// Use --yes to skip confirmation prompt.
	out := mustRun(t, dir, "rollback", "1", "--yes")
	assertContains(t, out, "restored")
}

func TestE2ERollbackInvalidID(t *testing.T) {
	dir := newWorkDir(t)
	writeFixtureState(t, dir, pmFixtureState("Rollback invalid ID"))
	writeFixtureSnapshot(t, dir, 1)

	out, err := run(t, dir, "rollback", "99", "--yes")
	if err == nil {
		t.Fatalf("expected error for non-existent snapshot: %s", out)
	}
	assertContains(t, out, "not found")
}

// ─────────────────────────────────────────────
// 7. cloop doctor
// ─────────────────────────────────────────────

func TestE2EDoctorBasic(t *testing.T) {
	dir := newWorkDir(t)
	// Init so config.yaml exists.
	mustRun(t, dir, "init", "Doctor test")

	out, _ := run(t, dir, "doctor") // may exit non-zero if checks fail
	assertContains(t, out, "cloop doctor")
	assertContains(t, out, "passed")
	// Should show result summary line.
	assertContains(t, out, "Result:")
}

func TestE2EDoctorNoProject(t *testing.T) {
	dir := newWorkDir(t)
	// No init — doctor should still run but warn about missing config.
	out, _ := run(t, dir, "doctor")
	assertContains(t, out, "cloop doctor")
	assertContains(t, out, "Result:")
}

func TestE2EDoctorChecksPresent(t *testing.T) {
	dir := newWorkDir(t)
	mustRun(t, dir, "init", "Doctor checks test")

	out, _ := run(t, dir, "doctor")
	// Doctor should list individual check results.
	assertContains(t, out, "PASS")
}

// ─────────────────────────────────────────────
// Helpers: fixture state builders
// ─────────────────────────────────────────────

// pmFixtureState builds a minimal PM-mode state with 3 tasks.
func pmFixtureState(goal string) map[string]interface{} {
	ts := fixedTime()
	return map[string]interface{}{
		"goal":         goal,
		"workdir":      "",
		"max_steps":    0,
		"current_step": 0,
		"status":       "initialized",
		"steps":        []interface{}{},
		"created_at":   ts,
		"updated_at":   ts,
		"pm_mode":      true,
		"plan": map[string]interface{}{
			"goal":    goal,
			"version": 0,
			"tasks": []interface{}{
				map[string]interface{}{
					"id":          1,
					"title":       "First task",
					"description": "Description of first task",
					"priority":    1,
					"status":      "pending",
					"role":        "backend",
				},
				map[string]interface{}{
					"id":          2,
					"title":       "Second task",
					"description": "Description of second task",
					"priority":    2,
					"status":      "pending",
					"role":        "backend",
				},
				map[string]interface{}{
					"id":          3,
					"title":       "Third task",
					"description": "Description of third task",
					"priority":    3,
					"status":      "pending",
					"role":        "frontend",
				},
			},
		},
	}
}

// vizFixtureState builds a state where task 2 depends on task 1.
func vizFixtureState() map[string]interface{} {
	ts := fixedTime()
	return map[string]interface{}{
		"goal":         "Viz test goal",
		"workdir":      "",
		"max_steps":    0,
		"current_step": 0,
		"status":       "initialized",
		"steps":        []interface{}{},
		"created_at":   ts,
		"updated_at":   ts,
		"pm_mode":      true,
		"plan": map[string]interface{}{
			"goal":    "Viz test goal",
			"version": 0,
			"tasks": []interface{}{
				map[string]interface{}{
					"id":          1,
					"title":       "First task",
					"description": "First",
					"priority":    1,
					"status":      "done",
					"role":        "backend",
					"depends_on":  []interface{}{},
				},
				map[string]interface{}{
					"id":          2,
					"title":       "Second task",
					"description": "Second",
					"priority":    2,
					"status":      "pending",
					"role":        "backend",
					"depends_on":  []interface{}{1},
				},
			},
		},
	}
}

// writeFixtureSnapshot writes a snapshot JSON file to .cloop/plan-history/.
func writeFixtureSnapshot(t *testing.T, workDir string, version int) {
	t.Helper()
	histDir := filepath.Join(workDir, ".cloop", "plan-history")
	if err := os.MkdirAll(histDir, 0o755); err != nil {
		t.Fatalf("mkdir plan-history: %v", err)
	}
	ts := time.Date(2026, 1, 10, 9, 0, 0, 0, time.UTC)
	fname := ts.UTC().Format("20060102-150405") + "-v1.json"
	snap := map[string]interface{}{
		"version":   version,
		"timestamp": ts.Format(time.RFC3339),
		"plan": map[string]interface{}{
			"goal":    "Snapshot goal",
			"version": version,
			"tasks": []interface{}{
				map[string]interface{}{
					"id":       1,
					"title":    "Snap task 1",
					"priority": 1,
					"status":   "done",
				},
			},
		},
	}
	data, _ := json.MarshalIndent(snap, "", "  ")
	if err := os.WriteFile(filepath.Join(histDir, fname), data, 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
}

// ─────────────────────────────────────────────
// Binary availability guard
// ─────────────────────────────────────────────

// TestMain ensures the binary exists before running any test.
func TestMain(m *testing.M) {
	// Parse flags so -update works.
	// testing.Init() is called automatically; we just call flag.Parse to catch -update.
	// Note: we do this manually since TestMain replaces the default main.

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		os.Stderr.WriteString("could not determine caller path\n")
		os.Exit(1)
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	bin := filepath.Join(repoRoot, "cloop")
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		os.Stderr.WriteString("cloop binary not found — run 'go build -o cloop .' first\n")
		os.Exit(1)
	}

	os.Exit(m.Run())
}
