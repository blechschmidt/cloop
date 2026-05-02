package pm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

// --- BuildProjectContext integration (uses real git on the cloop repo) ---

func TestBuildProjectContext_ReturnsContext(t *testing.T) {
	// Use the actual project working directory; we just verify the struct is populated
	// (we don't assert on exact git output since it changes)
	ctx := BuildProjectContext("/root/Projects/cloop")
	if ctx == nil {
		t.Fatal("BuildProjectContext returned nil")
	}
	if ctx.WorkDir != "/root/Projects/cloop" {
		t.Errorf("WorkDir = %q", ctx.WorkDir)
	}
	// In a git repo we expect at least some output
	if ctx.RecentLog == "" {
		t.Error("expected non-empty RecentLog in a git repository")
	}
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
