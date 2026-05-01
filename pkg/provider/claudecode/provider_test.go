package claudecode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// --- Name / DefaultModel ---

func TestName(t *testing.T) {
	if got := New().Name(); got != ProviderName {
		t.Errorf("expected %q, got %q", ProviderName, got)
	}
}

func TestDefaultModel(t *testing.T) {
	if got := New().DefaultModel(); got != "" {
		t.Errorf("expected empty default model, got %q", got)
	}
}

// --- loadEnvFile ---

func TestLoadEnvFile_ParsesKeyValue(t *testing.T) {
	k1, k2 := "CLOOP_TEST_K1", "CLOOP_TEST_K2"
	os.Unsetenv(k1)
	os.Unsetenv(k2)
	t.Cleanup(func() { os.Unsetenv(k1); os.Unsetenv(k2) })

	loadEnvFile(writeTempEnv(t, k1+"=bar\n"+k2+"=qux\n"))

	if got := os.Getenv(k1); got != "bar" {
		t.Errorf("%s: expected bar, got %q", k1, got)
	}
	if got := os.Getenv(k2); got != "qux" {
		t.Errorf("%s: expected qux, got %q", k2, got)
	}
}

func TestLoadEnvFile_SkipsComments(t *testing.T) {
	key := "CLOOP_TEST_COMMENT"
	os.Unsetenv(key)
	t.Cleanup(func() { os.Unsetenv(key) })

	loadEnvFile(writeTempEnv(t, "# this is a comment\n"+key+"=set\n"))

	if got := os.Getenv(key); got != "set" {
		t.Errorf("expected set, got %q", got)
	}
}

func TestLoadEnvFile_SkipsBlankLines(t *testing.T) {
	key := "CLOOP_TEST_BLANK"
	os.Unsetenv(key)
	t.Cleanup(func() { os.Unsetenv(key) })

	loadEnvFile(writeTempEnv(t, "\n   \n"+key+"=hello\n\n"))

	if got := os.Getenv(key); got != "hello" {
		t.Errorf("expected hello, got %q", got)
	}
}

func TestLoadEnvFile_DoesNotOverrideExisting(t *testing.T) {
	key := "CLOOP_TEST_EXISTING"
	os.Setenv(key, "original")
	t.Cleanup(func() { os.Unsetenv(key) })

	loadEnvFile(writeTempEnv(t, key+"=replaced\n"))

	if got := os.Getenv(key); got != "original" {
		t.Errorf("should not override existing env var, got %q", got)
	}
}

func TestLoadEnvFile_MissingFile(t *testing.T) {
	// Must not panic or error.
	loadEnvFile("/nonexistent/__cloop_test_missing.env")
}

func TestLoadEnvFile_ValueContainsEquals(t *testing.T) {
	key := "CLOOP_TEST_URL"
	os.Unsetenv(key)
	t.Cleanup(func() { os.Unsetenv(key) })

	loadEnvFile(writeTempEnv(t, key+"=http://example.com?a=b\n"))

	if got := os.Getenv(key); got != "http://example.com?a=b" {
		t.Errorf("expected full URL value, got %q", got)
	}
}

func TestLoadEnvFile_EmptyFile(t *testing.T) {
	// Must not panic on empty file.
	loadEnvFile(writeTempEnv(t, ""))
}

// --- Complete ---

func TestComplete_ReturnsFakeOutput(t *testing.T) {
	binDir := fakeClaudeScript(t, "#!/bin/sh\necho 'hello from fake claude'\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test prompt", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "hello from fake claude") {
		t.Errorf("unexpected output: %q", result.Output)
	}
	if result.Provider != ProviderName {
		t.Errorf("expected provider %q, got %q", ProviderName, result.Provider)
	}
	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
}

func TestComplete_UsesWorkDir(t *testing.T) {
	// Fake claude echoes its working directory via pwd.
	binDir := fakeClaudeScript(t, "#!/bin/sh\npwd\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	workDir := t.TempDir()
	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{WorkDir: workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Output should contain the work directory path.
	if !strings.Contains(result.Output, workDir) {
		t.Errorf("expected workdir %q in output, got %q", workDir, result.Output)
	}
}

func TestComplete_FallsBackToStderr(t *testing.T) {
	// When stdout is empty and stderr has content, output should use stderr.
	binDir := fakeClaudeScript(t, "#!/bin/sh\necho 'stderr content' >&2\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "stderr content") {
		t.Errorf("expected stderr fallback in output, got %q", result.Output)
	}
}

func TestComplete_PassesModelFlag(t *testing.T) {
	// Fake claude echoes its arguments so we can verify --model is passed.
	binDir := fakeClaudeScript(t, "#!/bin/sh\necho \"$@\"\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{Model: "claude-opus-4-6"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "--model") || !strings.Contains(result.Output, "claude-opus-4-6") {
		t.Errorf("expected --model flag in args, got output: %q", result.Output)
	}
}

func TestComplete_OutputTrimmed(t *testing.T) {
	// Provider trims whitespace from output.
	binDir := fakeClaudeScript(t, "#!/bin/sh\nprintf '  trimmed output  '\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output != "trimmed output" {
		t.Errorf("expected trimmed output, got %q", result.Output)
	}
}

// --- helpers ---

// writeTempEnv writes content to a temp .env file and returns its path.
func writeTempEnv(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	return f
}

// fakeClaudeScript creates a 'claude' executable in a temp dir with the given
// script content, and returns the directory path (suitable for prepending to PATH).
func fakeClaudeScript(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "claude")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude script: %v", err)
	}
	return dir
}
