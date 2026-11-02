package worktree

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestAddProofLeavesTheCheckoutAloneAndRemovesItself: a proof checkout is a
// locked, detached worktree beside the parallel tasks' ones; the main
// checkout's HEAD and files stay as they are; Remove takes the directory and
// git's record of it.
func TestAddProofLeavesTheCheckoutAloneAndRemovesItself(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	base, err := taskGit(repo, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	base = strings.TrimSpace(base)
	if err := os.WriteFile(repo+"/README.md", []byte("uncommitted\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	co, err := AddProof(context.Background(), repo, base, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(co.Path, repo+"/.cloop/worktrees/proof-") {
		t.Fatalf("the proof checkout is at %s", co.Path)
	}
	if b, _ := os.ReadFile(co.Path + "/README.md"); string(b) != "# test\n" {
		t.Fatalf("the checkout holds %q, want the base's README", b)
	}
	if b, _ := os.ReadFile(repo + "/README.md"); string(b) != "uncommitted\n" {
		t.Fatalf("the main checkout's work changed: %q", b)
	}
	list, _ := taskGit(repo, "worktree", "list", "--porcelain")
	if !strings.Contains(list, "locked cloop: requirement proof (pid ") {
		t.Fatalf("the checkout is not locked:\n%s", list)
	}
	// A sweep leaves a live proof's checkout alone.
	if removed, err := SweepProofs(context.Background(), repo, time.Now()); err != nil || len(removed) != 0 {
		t.Fatalf("a sweep removed %v (%v)", removed, err)
	}
	if err := co.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(co.Path); !os.IsNotExist(err) {
		t.Fatalf("the checkout survived its removal: %v", err)
	}
	if list, _ := taskGit(repo, "worktree", "list", "--porcelain"); strings.Contains(list, "proof-") {
		t.Fatalf("git still records the checkout:\n%s", list)
	}
	// Past its deadline a proof's checkout is a leftover, whoever holds it.
	stale, err := AddProof(context.Background(), repo, base, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if removed, err := SweepProofs(context.Background(), repo, time.Now()); err != nil || len(removed) != 1 {
		t.Fatalf("a sweep past the deadline removed %v (%v)", removed, err)
	}
	if _, err := os.Stat(stale.Path); !os.IsNotExist(err) {
		t.Fatalf("the stale checkout survived the sweep: %v", err)
	}
}

func TestAddProofTakesOnlyACommitID(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	for _, rev := range []string{"HEAD", "--orphan=x", "main", "abc", strings.Repeat("a", 65)} {
		if co, err := AddProof(context.Background(), repo, rev, time.Now().Add(time.Hour)); err == nil {
			_ = co.Remove()
			t.Errorf("AddProof(%q) succeeded", rev)
		}
	}
}
