package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// branchAgent is just enough agent to receive shipped branches.
func branchAgent(t *testing.T) (*Agent, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	a := &Agent{
		root:      t.TempDir(),
		branches:  map[string]*branchTransfer{},
		workloads: map[string]*workload{},
		cfg:       Config{Now: func() time.Time { return now }, Logf: t.Logf},
	}
	a.vault = newVault()
	return a, &now
}

func chunk(t *testing.T, handle string, offset int64, data string, total int64) remote.Frame {
	t.Helper()
	f, err := remote.NewFrame(remote.TypeBranchChunk, "", handle, remote.BranchChunkPayload{
		Offset: offset, Data: []byte(data), Total: total,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestBranchTransferAssemblesInOrder(t *testing.T) {
	a, _ := branchAgent(t)
	a.receiveBranchChunk(chunk(t, "h1", 0, "hello ", 11))
	a.receiveBranchChunk(chunk(t, "h1", 6, "world", 11))
	path, err := a.takeBranchBundle("h1")
	if err != nil {
		t.Fatalf("takeBranchBundle: %v", err)
	}
	defer os.Remove(path)
	if b, _ := os.ReadFile(path); string(b) != "hello world" {
		t.Errorf("assembled %q", b)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the bundle on the device is not 0600: %v %v", info, err)
	}
	if !strings.HasPrefix(path, filepath.Join(a.root, branchIncomingDir)) {
		t.Errorf("the bundle was written outside the agent's root: %s", path)
	}
}

func TestBranchTransferRefusesWhatDidNotArriveWhole(t *testing.T) {
	cases := map[string]func(a *Agent){
		"a gap": func(a *Agent) {
			a.receiveBranchChunk(chunk(t, "h", 0, "abc", 10))
			a.receiveBranchChunk(chunk(t, "h", 5, "fgh", 10))
		},
		"a short transfer": func(a *Agent) {
			a.receiveBranchChunk(chunk(t, "h", 0, "abc", 10))
		},
		"a changing total": func(a *Agent) {
			a.receiveBranchChunk(chunk(t, "h", 0, "abc", 10))
			a.receiveBranchChunk(chunk(t, "h", 3, "def", 12))
		},
		"nothing at all": func(a *Agent) {},
		"a chunk before the first": func(a *Agent) {
			a.receiveBranchChunk(chunk(t, "h", 3, "def", 10))
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			a, _ := branchAgent(t)
			run(a)
			if path, err := a.takeBranchBundle("h"); err == nil {
				os.Remove(path)
				t.Fatal("an incomplete transfer was handed to provisioning")
			}
			if entries, _ := os.ReadDir(filepath.Join(a.root, branchIncomingDir)); len(entries) != 0 {
				t.Errorf("a refused transfer left files behind: %v", entries)
			}
		})
	}
}

func TestBranchTransfersAreBounded(t *testing.T) {
	a, now := branchAgent(t)
	for i := 0; i < maxBranchTransfers; i++ {
		a.receiveBranchChunk(chunk(t, "h"+string(rune('a'+i)), 0, "x", 5))
	}
	a.receiveBranchChunk(chunk(t, "overflow", 0, "x", 1))
	if path, err := a.takeBranchBundle("overflow"); err == nil {
		os.Remove(path)
		t.Fatal("a transfer past the in-flight limit was accepted")
	}

	// An unclaimed transfer goes stale and is swept by the next one.
	*now = now.Add(branchTransferTTL + time.Minute)
	a.receiveBranchChunk(chunk(t, "fresh", 0, "x", 1))
	a.branchMu.Lock()
	n := len(a.branches)
	a.branchMu.Unlock()
	if n != 1 {
		t.Errorf("%d transfers held after the stale ones expired, want only the fresh one", n)
	}
}

func TestForgettingAWorkloadDropsItsTransfer(t *testing.T) {
	a, _ := branchAgent(t)
	a.receiveBranchChunk(chunk(t, "h", 0, "abc", 10))
	a.forget("h")
	if entries, _ := os.ReadDir(filepath.Join(a.root, branchIncomingDir)); len(entries) != 0 {
		t.Errorf("a forgotten workload's transfer was kept: %v", entries)
	}
}

func TestStartingClearsTransfersAPreviousAgentLeft(t *testing.T) {
	a, _ := branchAgent(t)
	dir := filepath.Join(a.root, branchIncomingDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "branch-old.bundle"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.clearBranchIncoming()
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a previous run's transfers survived: %v", entries)
	}
}
