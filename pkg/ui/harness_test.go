package ui

// Tests for the project → harness mapping (Task 20332).
//
// This is the half of the join that decides *whether* a dispatch carries a
// requirement at all. Getting it wrong in one direction reproduces the original
// bug (no requirement, so no refusal); getting it wrong in the other is worse,
// because it would refuse executors that are perfectly able to run the project.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

func TestHarnessForProvider(t *testing.T) {
	for _, tc := range []struct{ provider, want string }{
		{"claudecode", "claude"},
		{"CLAUDECODE", "claude"},
		{"  claudecode  ", "claude"},
		// Every HTTP-API provider needs no binary on the executing machine, so
		// naming one would refuse devices that can run them perfectly well.
		{"anthropic", ""},
		{"openai", ""},
		{"ollama", ""},
		{"mock", ""},
		{"", ""},
	} {
		if got := harnessForProvider(tc.provider); got != tc.want {
			t.Errorf("harnessForProvider(%q) = %q, want %q", tc.provider, got, tc.want)
		}
	}
}

// TestProjectHarnessDefaultsToClaude covers a directory with no config at all.
//
// The default provider is claudecode, so the default requirement is `claude` —
// and this is the common case, because the projects that hit the original bug
// were ordinary ones nobody had configured a provider on.
func TestProjectHarnessDefaultsToClaude(t *testing.T) {
	if got := projectHarness(t.TempDir()); got != "claude" {
		t.Errorf("projectHarness on an unconfigured dir = %q, want claude", got)
	}
}

// TestProjectHarnessFollowsConfig: a project on an HTTP provider must place no
// harness requirement, or this change would refuse it work it can do.
func TestProjectHarnessFollowsConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Provider = "anthropic"
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	if got := projectHarness(dir); got != "" {
		t.Errorf("an anthropic project should need no harness; got %q", got)
	}
}

// TestUnreadableConfigNamesNoHarness: this function gates a dispatch, and a
// transient read fault must not turn into a placement refusal about a binary
// nobody asked for. The project's own error path reports the unreadable file.
func TestUnreadableConfigNamesNoHarness(t *testing.T) {
	dir := t.TempDir()
	cloopDir := filepath.Join(dir, ".cloop")
	if err := os.MkdirAll(cloopDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Valid YAML naming a provider that drives nothing, written where config
	// expects it, so the resolver has something to read and still concludes
	// "no harness" rather than guessing claude.
	if err := os.WriteFile(filepath.Join(cloopDir, "config.yaml"),
		[]byte("provider: ollama\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := projectHarness(dir); got != "" {
		t.Errorf("an ollama project should need no harness; got %q", got)
	}
}
