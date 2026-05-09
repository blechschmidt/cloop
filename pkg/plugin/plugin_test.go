package plugin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeScript writes a shell script that's executable and returns its path.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRunCtx_TimeoutKillsHungPlugin: without the CommandContext timeout in
// RunCtx, a plugin that blocks (sleep 5) would pin the orchestrator until the
// process exited on its own. The context deadline must propagate the kill.
func TestRunCtx_TimeoutKillsHungPlugin(t *testing.T) {
	dir := t.TempDir()
	pluginsDir := filepath.Join(dir, ".cloop", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeScript(t, pluginsDir, "hang", "sleep 5")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := RunCtx(ctx, dir, "hang", nil, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected RunCtx to return error after timeout, got nil")
	}
	if elapsed > 4*time.Second {
		t.Errorf("plugin took %v to terminate, expected <4s", elapsed)
	}
}

// TestRunCtx_HappyPath ensures normal plugins still work with the new
// context-aware codepath.
func TestRunCtx_HappyPath(t *testing.T) {
	dir := t.TempDir()
	pluginsDir := filepath.Join(dir, ".cloop", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeScript(t, pluginsDir, "ok", "exit 0")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := RunCtx(ctx, dir, "ok", nil, nil); err != nil {
		t.Fatalf("happy-path plugin returned error: %v", err)
	}
}

// TestDescribe_TimeoutOnHungScript: a plugin's describe subcommand must not
// be allowed to block indefinitely — that would freeze plugin enumeration
// (Discover → describe per file).
func TestDescribe_TimeoutOnHungScript(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "hang.sh", `if [ "$1" = "describe" ]; then sleep 30; fi`)
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}

	// Tighten the package-level timeout for the duration of this test so we
	// don't block the suite for the full 10s production default.
	prev := describeTimeout
	describeTimeout = 200 * time.Millisecond
	defer func() { describeTimeout = prev }()

	start := time.Now()
	_, err := describe(script)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected describe to error on hung script, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout error, got: %v", err)
	}
	if elapsed > 4*time.Second {
		t.Errorf("describe took %v to terminate, expected ~timeout+grace", elapsed)
	}
}
