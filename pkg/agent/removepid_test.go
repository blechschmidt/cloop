package agent_test

// Pin the error-returning contract of RemovePID. The previous signature was
// `func RemovePID(workdir string)` — it silently swallowed os.Remove errors,
// which masked a real operational footgun: if the worker exits but cannot
// remove its PID file (perms changed under it, busy filesystem), the file is
// left behind and the next `agent start` sees IsRunning() return true and
// refuses to launch. The user has to manually `rm .cloop/agent.pid` with no
// log to point them at it. Returning the error lets callers log the failure
// so the cause is at least visible in the agent log.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/agent"
)

func TestRemovePID_ReturnsNilWhenFileExisted(t *testing.T) {
	tmp := t.TempDir()
	if err := agent.WritePID(tmp, 4242); err != nil {
		t.Fatalf("seeding PID file: %v", err)
	}
	if err := agent.RemovePID(tmp); err != nil {
		t.Fatalf("RemovePID after WritePID should succeed, got %v", err)
	}
	if _, statErr := os.Stat(agent.PIDPath(tmp)); !os.IsNotExist(statErr) {
		t.Errorf("PID file should be gone after RemovePID, got stat err %v", statErr)
	}
}

func TestRemovePID_ReturnsNotExistWhenAbsent(t *testing.T) {
	tmp := t.TempDir()
	err := agent.RemovePID(tmp)
	if err == nil {
		t.Fatal("RemovePID on missing file should return ENOENT")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("RemovePID on missing file should wrap ErrNotExist; got %v", err)
	}
	// The contract is that callers filter ENOENT with os.IsNotExist — verify
	// that filter works against this error so the cmd/agent_cmd.go shutdown
	// hook does not log spurious "PID file vanished" warnings.
	if !os.IsNotExist(err) {
		t.Errorf("os.IsNotExist must accept the returned error; got %v", err)
	}
}

func TestRemovePID_PropagatesPermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root bypasses unix permission checks")
	}
	tmp := t.TempDir()
	if err := agent.WritePID(tmp, 4242); err != nil {
		t.Fatalf("seeding PID file: %v", err)
	}
	cloopDir := filepath.Join(tmp, ".cloop")
	if err := os.Chmod(cloopDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(cloopDir, 0o755) })

	err := agent.RemovePID(tmp)
	if err == nil {
		t.Fatal("RemovePID against read-only parent should fail")
	}
	if os.IsNotExist(err) {
		t.Errorf("perm error must not look like ENOENT; got %v", err)
	}
}
