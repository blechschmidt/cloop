package gitwriteback_test

// The write-back runs git in a tree the sandbox could write, .git included —
// on a device in container mode, as the agent, on the device's host. Nothing
// the workload configured there may run (Task 20367).

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
)

func hgit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestProduceRunsNothingTheWorkloadConfigured(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := filepath.Join(t.TempDir(), "tree")
	hgit(t, filepath.Dir(dir), "init", "-q", "-b", "main", dir)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hgit(t, dir, "add", "-A")
	hgit(t, dir, "commit", "-qm", "base")
	base := hgit(t, dir, "rev-parse", "HEAD")

	// What a workload could leave behind in its own .git.
	marker := filepath.Join(t.TempDir(), "ran")
	for _, h := range []string{"post-commit", "pre-commit", "reference-transaction", "post-checkout"} {
		p := filepath.Join(dir, ".git", "hooks", h)
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho "+h+" >> "+marker+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	monitor := filepath.Join(t.TempDir(), "fsmonitor")
	if err := os.WriteFile(monitor, []byte("#!/bin/sh\necho fsmonitor >> "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	hgit(t, dir, "config", "core.fsmonitor", monitor)
	hgit(t, dir, "config", "filter.sneaky.clean", "sh -c 'echo filter >> "+marker+"; cat'")
	hgit(t, dir, "config", "commit.gpgSign", "true")
	hgit(t, dir, "config", "gpg.program", monitor)
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("*.txt filter=sneaky\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("work\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := gitwriteback.Produce(context.Background(), gitwriteback.Request{
		Dir:       dir,
		WriteBack: executor.WriteBack{Mode: executor.WriteBackBundle, Branch: "cloop/feature/widget"},
		BaseSHA:   base,
	})
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	defer os.Remove(res.BundlePath)
	if !res.Delivered() {
		t.Fatalf("nothing was written back: %+v", res.WriteBackResult)
	}
	if b, err := os.ReadFile(marker); err == nil {
		t.Errorf("the write-back ran what the workload configured: %s", b)
	}
}
