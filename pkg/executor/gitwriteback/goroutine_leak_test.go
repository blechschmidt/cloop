package gitwriteback_test

// Goroutine-leak regression test for the write-back lifecycle.
//
// Produce runs six to eight git children per call, each read through
// CombinedOutput, which os/exec services with goroutines copying the pipes. It
// also derives its own context — Request.Timeout — from the caller's, so a
// missing cancel would leak the timer's goroutine on every write-back rather
// than only on the ones that time out.
//
// The exposure is the same shape as gitprovision's and worse in degree: a
// write-back runs once per completed task on a hub that is never restarted, and
// twice that on an edge agent that both provisions and writes back. See the
// twin in pkg/executor/gitprovision for the measurement rationale.

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
)

// writebackLeakSlack absorbs runtime and scheduler flapping. With N cycles a
// real per-call leak produces a delta of at least N, so the slack sits below
// that and above idle noise.
const writebackLeakSlack = 12

func settle() int {
	best := 1 << 30
	for i := 0; i < 5; i++ {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(120 * time.Millisecond)
		runtime.GC()
		if n := runtime.NumGoroutine(); n < best {
			best = n
		}
	}
	return best
}

// TestProduceDoesNotLeakGoroutines exercises all three exits: a bundle that is
// delivered, a push that fails without a remote answering, and a skip that
// never starts a child at all.
//
// Bundle mode contacts nothing, so the measurement is of this package rather
// than of an httptest server's per-connection goroutines; the push case uses a
// dead port for the same reason.
func TestProduceDoesNotLeakGoroutines(t *testing.T) {
	f := newLocal(t)
	root := t.TempDir()

	cycle := func(i int) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		// A delivered bundle.
		f.dirty("iteration.txt", time.Duration(i).String()+"\n")
		res, err := gitwriteback.Produce(ctx, gitwriteback.Request{
			Dir: f.dir, Workspace: f.ws, WriteBack: f.wb, OnlyOnSuccess: true,
			BundlePath: filepath.Join(root, "b-"+time.Duration(i).String()+".bundle"),
		})
		if err != nil {
			t.Fatalf("cycle %d: bundle Produce: %v", i, err)
		}
		if res.Skipped {
			t.Fatalf("cycle %d: bundle Produce skipped: %s", i, res.SkipReason)
		}

		// A push that cannot reach its remote. It commits first, so the child
		// processes really run before the failure.
		f.dirty("iteration.txt", time.Duration(i).String()+"-push\n")
		pushWS := f.ws
		pushWS.Repo = "https://127.0.0.1:1/" + owner + "/" + repo + ".git"
		if _, err := gitwriteback.Produce(ctx, gitwriteback.Request{
			Dir: f.dir, Workspace: pushWS, OnlyOnSuccess: true,
			WriteBack:  executor.WriteBack{Mode: executor.WriteBackPush, Branch: branch},
			Credential: executor.GitCredential{Username: credUser, Password: credToken},
		}); err == nil {
			t.Fatalf("cycle %d: push Produce succeeded against a dead port", i)
		}

		// A skip: the tree is clean now, so nothing is committed.
		if res, err := gitwriteback.Produce(ctx, gitwriteback.Request{
			Dir: f.dir, Workspace: f.ws, WriteBack: f.wb, OnlyOnSuccess: true,
			BundlePath: filepath.Join(root, "skip.bundle"),
		}); err != nil {
			t.Fatalf("cycle %d: skip Produce: %v", i, err)
		} else if !res.Skipped {
			t.Fatalf("cycle %d: a clean tree was not skipped", i)
		}
	}

	cycle(0) // warm up, so one-time git initialisation stays out of the baseline
	baseline := settle()

	const N = 6
	for i := 1; i <= N; i++ {
		cycle(i)
	}

	post := settle()
	if delta := post - baseline; delta > writebackLeakSlack {
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Fatalf("goroutine leak in Produce: baseline=%d post=%d delta=%d (>%d) after %d cycles\n%s",
			baseline, post, delta, writebackLeakSlack, N, buf)
	}
}

// TestProduceRefusalsDoNotLeakGoroutines covers the exits taken before any
// child starts. A hub validating specs takes them far more often than it takes
// the delivery path.
func TestProduceRefusalsDoNotLeakGoroutines(t *testing.T) {
	dir := t.TempDir()
	ws := executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://h/o/r.git"}
	reqs := []gitwriteback.Request{
		// Not a repository.
		{Dir: dir, Workspace: ws, WriteBack: executor.WriteBack{
			Mode: executor.WriteBackBundle, Branch: branch}},
		// Not an absolute path.
		{Dir: "relative", Workspace: ws, WriteBack: executor.WriteBack{
			Mode: executor.WriteBackPush, Branch: branch}},
		// A branch outside the namespace the hub may force-update.
		{Dir: dir, Workspace: ws, WriteBack: executor.WriteBack{
			Mode: executor.WriteBackPush, Branch: "main"}},
	}

	run := func() {
		for _, r := range reqs {
			if _, err := gitwriteback.Produce(context.Background(), r); err == nil {
				t.Fatalf("Produce accepted %+v", r.WriteBack)
			}
		}
	}
	run()
	baseline := settle()

	for i := 0; i < 50; i++ {
		run()
	}

	post := settle()
	if delta := post - baseline; delta > writebackLeakSlack {
		t.Fatalf("goroutine leak on the refusal paths: baseline=%d post=%d delta=%d (>%d)",
			baseline, post, delta, writebackLeakSlack)
	}
}
