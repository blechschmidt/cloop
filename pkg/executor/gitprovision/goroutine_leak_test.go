package gitprovision_test

// Goroutine-leak regression test for the provisioning lifecycle.
//
// Provision spawns up to four git children per call and reads each one through
// CombinedOutput, which os/exec services with goroutines copying the pipes. It
// also runs every child under a context the caller owns. Both are shapes that
// leak quietly: a child whose pipes are never drained, a context whose cancel
// is never called, or a rollback that starts a walk it does not wait for would
// all leave goroutines behind at a rate of one or two per provisioning.
//
// That matters here more than the absolute numbers suggest. A hub provisions
// once per dispatched task and a long-lived edge agent provisions for the
// lifetime of the device, so a per-call leak is unbounded in exactly the
// processes that are never restarted — and it is invisible in every functional
// test, because a leaked goroutine does not change what Provision returns.
//
// The measurement follows the pattern shared by the other *_goroutine_leak_test
// .go files in cloop (pkg/statedb and pkg/ui among them): warm up, sample a
// baseline, run N cycles, resample and compare against a small slack.

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/internal/gitforge"
)

// provisionLeakSlack absorbs ambient flapping: the Go runtime's own background
// goroutines, and net/http's per-connection server goroutines, which outlive
// the request that created them until the client's socket is reaped.
//
// With N cycles a real per-call leak produces a delta of at least N, so the
// slack is chosen below that and above what idle flapping produces.
const provisionLeakSlack = 12

// settle gives finalisers, the scheduler and net/http's connection reaper time
// to run before sampling, and resamples rather than trusting one reading: a
// server goroutine that is on its way out would otherwise be counted as a leak.
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

// TestProvisionDoesNotLeakGoroutines runs both exit paths, because they leave
// through different code: the success path returns after the last checkout, and
// the failure path returns through rollback, which is where a stray walk or an
// unclosed handle would live.
func TestProvisionDoesNotLeakGoroutines(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	root := t.TempDir()

	cycle := func(i int, fail bool) {
		ws := f.ws
		if fail {
			// A dead port rather than a bad ref: the fetch fails without the
			// forge serving a request, so no server-side goroutine is created
			// and the measurement is of this package alone.
			ws.Repo = "https://127.0.0.1:1/" + owner + "/" + repo + ".git"
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := gitprovision.Provision(ctx, gitprovision.Request{
			Dir:        filepath.Join(root, "ws", time.Duration(i).String()),
			Workspace:  ws,
			Credential: f.cred,
			Host:       "this leak test",
		})
		if fail && err == nil {
			t.Fatalf("cycle %d: Provision succeeded against a dead port", i)
		}
		if !fail && err != nil {
			t.Fatalf("cycle %d: Provision: %v", i, err)
		}
	}

	// Warm up so one-time initialisation — TLS session state, the http
	// transport's idle pool, git's own object cache — does not land in the
	// baseline.
	cycle(0, false)
	cycle(1, true)

	baseline := settle()

	const N = 8
	for i := 0; i < N; i++ {
		cycle(2*i+2, false)
		cycle(2*i+3, true)
	}

	post := settle()
	if delta := post - baseline; delta > provisionLeakSlack {
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Fatalf("goroutine leak in Provision: baseline=%d post=%d delta=%d (>%d) after %d "+
			"success and %d failure cycles\n%s",
			baseline, post, delta, provisionLeakSlack, N, N, buf)
	}
}

// TestProvisionRefusalsDoNotLeakGoroutines covers the exits that happen before
// any child process starts. They are the cheapest paths and therefore the ones
// most likely to be taken thousands of times by a hub rejecting misconfigured
// specs.
func TestProvisionRefusalsDoNotLeakGoroutines(t *testing.T) {
	dir := t.TempDir()
	reqs := []gitprovision.Request{
		{Dir: dir, Workspace: executor.Workspace{Kind: executor.WorkspaceBind}},
		{Dir: dir, Workspace: executor.Workspace{Kind: executor.WorkspaceNone}},
		{Dir: dir, Workspace: executor.Workspace{Kind: executor.WorkspaceGit, Repo: "http://insecure/o/r"}},
		{
			Dir:        dir,
			Workspace:  executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://h/o/r", Ref: "main"},
			Credential: executor.GitCredential{Password: "expired-lease-value", ExpiresAt: time.Unix(1, 0)},
		},
	}

	run := func() {
		for _, r := range reqs {
			if err := gitprovision.Provision(context.Background(), r); err == nil {
				t.Fatalf("Provision accepted %+v", r.Workspace)
			}
		}
	}
	run()
	baseline := settle()

	for i := 0; i < 50; i++ {
		run()
	}

	post := settle()
	if delta := post - baseline; delta > provisionLeakSlack {
		t.Fatalf("goroutine leak on the refusal paths: baseline=%d post=%d delta=%d (>%d)",
			baseline, post, delta, provisionLeakSlack)
	}
}
