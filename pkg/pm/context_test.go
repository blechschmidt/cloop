package pm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// --- EstimateTokens ---

func TestEstimateTokens_Empty(t *testing.T) {
	if got := EstimateTokens(""); got != 0 {
		t.Errorf("EstimateTokens(\"\") = %d, want 0", got)
	}
}

func TestEstimateTokens_FourChars(t *testing.T) {
	// "abcd" = 4 chars → 1 token
	if got := EstimateTokens("abcd"); got != 1 {
		t.Errorf("EstimateTokens(4 chars) = %d, want 1", got)
	}
}

func TestEstimateTokens_Rounding(t *testing.T) {
	// 5 chars → ceil(5/4) = 2
	if got := EstimateTokens("abcde"); got != 2 {
		t.Errorf("EstimateTokens(5 chars) = %d, want 2", got)
	}
}

// --- PruneToTokenBudget ---

func TestPruneToTokenBudget_NoBudget(t *testing.T) {
	steps := []string{"a", "b", "c", "d"}
	got := PruneToTokenBudget(steps, 0)
	if len(got) != len(steps) {
		t.Errorf("budget=0 should disable pruning, got %d steps", len(got))
	}
}

func TestPruneToTokenBudget_FitsNoPrune(t *testing.T) {
	steps := []string{"a", "b", "c", "d"}
	// Each "a","b","c","d" = 1 token. Total = 4. Budget = 10.
	got := PruneToTokenBudget(steps, 10)
	if len(got) != len(steps) {
		t.Errorf("should not prune when total fits, got %d steps", len(got))
	}
}

func TestPruneToTokenBudget_TooFewSteps(t *testing.T) {
	steps := []string{"first", "last"}
	// Even if total > budget, ≤3 steps are never pruned.
	got := PruneToTokenBudget(steps, 1)
	if len(got) != len(steps) {
		t.Errorf("≤3 steps should not be pruned, got %d", len(got))
	}
}

func TestPruneToTokenBudget_KeepsFirstAndLast2(t *testing.T) {
	// Build 6 steps where total > budget.
	// Each step is 40 chars → 10 tokens. 6 steps = 60 tokens total.
	// Budget = 32 tokens → keep first (10) + last2 (20) + some middle.
	// 32 - 30 = 2 tokens left for middle; each middle step = 10 tokens → no middle fits.
	step := strings.Repeat("x", 40) // 40 chars = 10 tokens
	steps := []string{step, step, step, step, step, step}
	got := PruneToTokenBudget(steps, 32)
	// Should keep 3: first + last2
	if len(got) != 3 {
		t.Errorf("expected 3 steps (first+last2), got %d", len(got))
	}
	if got[0] != steps[0] {
		t.Error("first step must be retained")
	}
	if got[1] != steps[len(steps)-2] || got[2] != steps[len(steps)-1] {
		t.Error("last two steps must be retained")
	}
}

func TestPruneToTokenBudget_KeepsNewestMiddle(t *testing.T) {
	// 5 steps: first(10tok), middle1(10tok), middle2(10tok), last2a(10tok), last2b(10tok)
	// Budget = 40 tokens → first(10) + last2(20) = 30 fixed.
	// Remaining for middle = 10 → one middle step fits. Should keep middle2 (newest).
	small := strings.Repeat("x", 40) // 10 tokens
	steps := []string{small, small, small, small, small}
	got := PruneToTokenBudget(steps, 40)
	if len(got) != 4 {
		t.Errorf("expected 4 steps, got %d", len(got))
	}
	if got[0] != steps[0] {
		t.Error("first step must be retained")
	}
	if got[len(got)-2] != steps[len(steps)-2] || got[len(got)-1] != steps[len(steps)-1] {
		t.Error("last two steps must be retained")
	}
}

func TestPruneToTokenBudget_LogMessage(t *testing.T) {
	// Ensure pruned count < original when over budget
	step := strings.Repeat("x", 400) // 100 tokens each
	steps := make([]string, 10)
	for i := range steps {
		steps[i] = step
	}
	// Budget = 300 tokens: first(100) + last2(200) = 300, no middle
	got := PruneToTokenBudget(steps, 300)
	if len(got) >= len(steps) {
		t.Errorf("expected pruning, got %d (orig %d)", len(got), len(steps))
	}
}

// --- ProjectContext.Format ---

func TestFormat_NilContext(t *testing.T) {
	var c *ProjectContext
	if got := c.Format(); got != "" {
		t.Errorf("nil context Format() = %q, want empty string", got)
	}
}

func TestFormat_EmptyContext(t *testing.T) {
	c := &ProjectContext{}
	if got := c.Format(); got != "" {
		t.Errorf("empty context Format() = %q, want empty string", got)
	}
}

func TestFormat_OnlyFileTree(t *testing.T) {
	c := &ProjectContext{FileTree: "cmd/\npkg/"}
	out := c.Format()
	if !strings.Contains(out, "## PROJECT CONTEXT") {
		t.Error("expected PROJECT CONTEXT header")
	}
	if !strings.Contains(out, "### File Tree") {
		t.Error("expected File Tree section")
	}
	if !strings.Contains(out, "cmd/") {
		t.Error("expected file tree content")
	}
	if strings.Contains(out, "### Git Status") {
		t.Error("Git Status should be absent when empty")
	}
	if strings.Contains(out, "### Recent Commits") {
		t.Error("Recent Commits should be absent when empty")
	}
}

func TestFormat_OnlyGitStatus(t *testing.T) {
	c := &ProjectContext{GitStatus: "M  main.go\n?? untracked.go"}
	out := c.Format()
	if !strings.Contains(out, "### Git Status") {
		t.Error("expected Git Status section")
	}
	if !strings.Contains(out, "M  main.go") {
		t.Error("expected git status content")
	}
	if strings.Contains(out, "### File Tree") {
		t.Error("File Tree should be absent when empty")
	}
}

func TestFormat_OnlyRecentLog(t *testing.T) {
	c := &ProjectContext{RecentLog: "abc1234 Add feature X\ndef5678 Fix bug Y"}
	out := c.Format()
	if !strings.Contains(out, "### Recent Commits") {
		t.Error("expected Recent Commits section")
	}
	if !strings.Contains(out, "abc1234 Add feature X") {
		t.Error("expected log content")
	}
}

func TestFormat_AllFields(t *testing.T) {
	c := &ProjectContext{
		FileTree:  "cmd/\npkg/",
		GitStatus: "M  go.mod",
		RecentLog: "a1b2c3 initial commit",
		WorkDir:   "/tmp/myproject",
	}
	out := c.Format()
	for _, want := range []string{
		"## PROJECT CONTEXT",
		"### File Tree",
		"cmd/",
		"### Git Status",
		"M  go.mod",
		"### Recent Commits",
		"a1b2c3 initial commit",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Format() output missing %q", want)
		}
	}
}

func TestFormat_SectionsWrappedInCodeBlocks(t *testing.T) {
	c := &ProjectContext{
		FileTree:  "main.go",
		GitStatus: "M  main.go",
		RecentLog: "abc fix",
	}
	out := c.Format()
	// Each section should be in a fenced code block
	if strings.Count(out, "```") < 6 {
		t.Errorf("expected at least 6 backtick fences (open+close for 3 sections), got %d in:\n%s",
			strings.Count(out, "```"), out)
	}
}

// --- buildFileTree ---

func TestBuildFileTree_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	tree := buildFileTree(dir)
	// Empty dir should return empty string
	if tree != "" {
		t.Errorf("empty dir tree = %q, want empty string", tree)
	}
}

func TestBuildFileTree_SimpleStructure(t *testing.T) {
	dir := t.TempDir()
	// Create a simple structure
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(""), 0644)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte(""), 0644)
	os.MkdirAll(filepath.Join(dir, "pkg", "foo"), 0755)
	os.WriteFile(filepath.Join(dir, "pkg", "foo", "foo.go"), []byte(""), 0644)

	tree := buildFileTree(dir)
	if !strings.Contains(tree, "main.go") {
		t.Error("expected main.go in file tree")
	}
	if !strings.Contains(tree, "README.md") {
		t.Error("expected README.md in file tree")
	}
	if !strings.Contains(tree, "pkg/") {
		t.Error("expected pkg/ directory in file tree")
	}
	if !strings.Contains(tree, "foo.go") {
		t.Error("expected foo.go in file tree")
	}
}

func TestBuildFileTree_SkipsHiddenDirs(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(""), 0644)

	tree := buildFileTree(dir)
	if strings.Contains(tree, ".git") {
		t.Error(".git directory should be skipped")
	}
	if !strings.Contains(tree, "main.go") {
		t.Error("main.go should be present")
	}
}

func TestBuildFileTree_SkipsNodeModulesVendor(t *testing.T) {
	dir := t.TempDir()
	for _, skipDir := range []string{"node_modules", "vendor", ".cloop", "__pycache__"} {
		os.MkdirAll(filepath.Join(dir, skipDir), 0755)
		os.WriteFile(filepath.Join(dir, skipDir, "file.txt"), []byte(""), 0644)
	}
	os.WriteFile(filepath.Join(dir, "app.go"), []byte(""), 0644)

	tree := buildFileTree(dir)
	for _, skip := range []string{"node_modules", "vendor", ".cloop", "__pycache__"} {
		if strings.Contains(tree, skip) {
			t.Errorf("directory %q should be skipped in file tree", skip)
		}
	}
	if !strings.Contains(tree, "app.go") {
		t.Error("app.go should appear in tree")
	}
}

func TestBuildFileTree_LimitsTo60Lines(t *testing.T) {
	dir := t.TempDir()
	// Create 70 uniquely-named files
	for i := 0; i < 70; i++ {
		name := filepath.Join(dir, fmt.Sprintf("file%03d.go", i))
		os.WriteFile(name, []byte(""), 0644)
	}

	tree := buildFileTree(dir)
	lines := strings.Split(tree, "\n")
	// Should have at most 61 lines (60 entries + 1 "omitted" line)
	if len(lines) > 61 {
		t.Errorf("file tree has %d lines, want <= 61", len(lines))
	}
	if !strings.Contains(tree, "omitted") {
		t.Error("truncated tree should contain 'omitted' marker")
	}
}

// --- skipDir ---

func TestSkipDir(t *testing.T) {
	shouldSkip := []string{".git", "node_modules", "vendor", ".cloop", "__pycache__", ".venv", "venv", "dist", "build", ".idea", ".vscode", ".hidden"}
	for _, name := range shouldSkip {
		if !skipDir(name) {
			t.Errorf("skipDir(%q) = false, want true", name)
		}
	}
	shouldNotSkip := []string{"cmd", "pkg", "src", "main.go", "README.md"}
	for _, name := range shouldNotSkip {
		if skipDir(name) {
			t.Errorf("skipDir(%q) = true, want false", name)
		}
	}
}

// --- BuildProjectContext integration (uses real git) ---

func TestBuildProjectContext_ReturnsContext(t *testing.T) {
	// A repository built here rather than the checkout this test happens to be
	// running from. The previous version pointed at a hardcoded
	// /root/Projects/cloop, so it asserted nothing anywhere except on the one
	// machine that path exists on — on CI it read a directory that is not
	// there, got an empty RecentLog, and failed every run.
	dir := newTestGitRepo(t)

	ctx := BuildProjectContext(dir)
	if ctx == nil {
		t.Fatal("BuildProjectContext returned nil")
	}
	if ctx.WorkDir != dir {
		t.Errorf("WorkDir = %q, want %q", ctx.WorkDir, dir)
	}
	// One commit exists, so the log is non-empty; the file it touched is
	// untracked-free but present, so the tree is non-empty too.
	if ctx.RecentLog == "" {
		t.Error("expected non-empty RecentLog in a git repository")
	}
	if ctx.FileTree == "" {
		t.Error("expected non-empty FileTree for a directory with files in it")
	}
	if ctx.Format() == "" {
		t.Error("Format() should render a context that has content")
	}
}

// newTestGitRepo creates a git repository with a single commit and returns its
// path. Skips the test if git is unavailable, matching how the rest of the
// suite treats an external tool it does not own.
func newTestGitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "test@example.invalid"},
		{"config", "user.name", "cloop test"},
		{"add", "main.go"},
		{"commit", "-q", "-m", "initial commit"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		// A developer's global git config can set commit.gpgsign or a hook
		// path; neither is this test's business.
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v failed (%v): %s", args, err, out)
		}
	}
	return dir
}

func TestBuildProjectContext_NonExistentDir(t *testing.T) {
	ctx := BuildProjectContext("/nonexistent/path/xyz")
	if ctx == nil {
		t.Fatal("BuildProjectContext should not return nil even for bad dir")
	}
	// File tree and git output should be empty for a non-existent dir
	if ctx.FileTree != "" {
		t.Errorf("FileTree should be empty for non-existent dir, got %q", ctx.FileTree)
	}
	// Format should return empty since all fields are empty
	if ctx.Format() != "" {
		t.Error("Format() should return empty for a context with all empty fields")
	}
}
