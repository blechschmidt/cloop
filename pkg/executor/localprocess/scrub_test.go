package localprocess

// Tests for taking an environment-borne credential back out of the driver's
// retained state after a workload has started.

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// startSleeper starts a long-running workload carrying a credential, and
// returns the driver and its handle.
func startSleeper(t *testing.T) (*Executor, string) {
	t.Helper()
	allowHost(t)

	e := New("scrub-test")
	h, err := e.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"sleep", "30"},
		Env: []string{
			"PATH=/usr/bin:/bin",
			"GITHUB_TOKEN=ghp_secret_value",
			"KUBECONFIG=/dev/shm/cloop-lease-x/kubeconfig",
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = e.Signal(context.Background(), h.ID, executor.SignalKill) })
	return e, h.ID
}

// TestScrubEnvDropsOnlyTheNamedVariables checks that a revocation removes what
// the lease delivered and nothing else. Over-scrubbing would break a task that
// still holds an unrelated credential from a grant nobody revoked.
func TestScrubEnvDropsOnlyTheNamedVariables(t *testing.T) {
	e, id := startSleeper(t)

	found := e.ScrubEnv(id, []string{"GITHUB_TOKEN", "NEVER_SET", "  "})
	if len(found) != 1 || found[0] != "GITHUB_TOKEN" {
		t.Fatalf("ScrubEnv reported %v, want only the key it actually found", found)
	}

	env := retainedEnv(t, e, id)
	if strings.Contains(strings.Join(env, "\n"), "ghp_secret_value") {
		t.Errorf("the revoked credential is still reachable in the driver: %v", env)
	}
	// The variable stays, with its value replaced. "This was taken away" and
	// "this was never set" call for different operator responses, and a bare
	// deletion cannot tell them apart.
	if !containsEntry(env, "GITHUB_TOKEN="+scrubbedValue) {
		t.Errorf("GITHUB_TOKEN should remain, marked revoked; env = %v", env)
	}
	// Everything else is untouched.
	if !containsEntry(env, "PATH=/usr/bin:/bin") {
		t.Errorf("an unrelated variable was scrubbed; env = %v", env)
	}
	if !containsEntry(env, "KUBECONFIG=/dev/shm/cloop-lease-x/kubeconfig") {
		t.Errorf("a variable from another grant was scrubbed; env = %v", env)
	}
}

// TestScrubEnvSliceLeavesMalformedEntriesAlone covers the defensive branch that
// Spec.Validate normally makes unreachable.
//
// A spec with an entry lacking "=" is rejected before it reaches the driver,
// so this cannot arrive over the wire — but scrubEnvSlice also runs against
// exec.Cmd.Env, which os/exec permits a caller to shape freely, and a
// panicking scrub would be a far worse failure than an ignored entry.
func TestScrubEnvSliceLeavesMalformedEntriesAlone(t *testing.T) {
	env := []string{"MALFORMED_NO_EQUALS", "GITHUB_TOKEN=secret", "=novalue"}
	found := map[string]struct{}{}
	got := scrubEnvSlice(env, map[string]struct{}{"GITHUB_TOKEN": {}}, found)

	if got[0] != "MALFORMED_NO_EQUALS" {
		t.Errorf("entry with no '=' should be untouched, got %q", got[0])
	}
	if got[1] != "GITHUB_TOKEN="+scrubbedValue {
		t.Errorf("the targeted key should be scrubbed, got %q", got[1])
	}
	if got[2] != "=novalue" {
		t.Errorf("an empty key should be untouched, got %q", got[2])
	}
	if _, ok := found["GITHUB_TOKEN"]; !ok || len(found) != 1 {
		t.Errorf("found = %v, want exactly GITHUB_TOKEN", found)
	}
}

// TestScrubEnvClearsBothRetainedCopies: the driver holds the environment twice
// (exec.Cmd.Env and the recorded Spec), and a scrub that missed either would
// leave the credential reachable in the agent's heap for as long as the handle
// is retained — up to maxRetainedHandles workloads after the run ended.
func TestScrubEnvClearsBothRetainedCopies(t *testing.T) {
	e, id := startSleeper(t)
	e.ScrubEnv(id, []string{"GITHUB_TOKEN"})

	e.mu.Lock()
	rec := e.handles[id]
	e.mu.Unlock()
	if rec == nil {
		t.Fatal("handle vanished")
	}

	rec.mu.Lock()
	cmdEnv := strings.Join(rec.cmd.Env, "\n")
	specEnv := strings.Join(rec.spec.Env, "\n")
	rec.mu.Unlock()

	if strings.Contains(cmdEnv, "ghp_secret_value") {
		t.Error("cmd.Env still holds the revoked credential")
	}
	if strings.Contains(specEnv, "ghp_secret_value") {
		t.Error("the recorded Spec still holds the revoked credential")
	}
}

// TestScrubEnvUnknownHandleAndKeysAreNotErrors: both mean "that material is
// not here", which is the end state a revocation wants.
func TestScrubEnvUnknownHandleAndKeysAreNotErrors(t *testing.T) {
	e, id := startSleeper(t)

	if got := e.ScrubEnv("no-such-handle", []string{"GITHUB_TOKEN"}); len(got) != 0 {
		t.Errorf("an unknown handle should report nothing scrubbed, got %v", got)
	}
	if got := e.ScrubEnv(id, nil); len(got) != 0 {
		t.Errorf("an empty key list should report nothing scrubbed, got %v", got)
	}
	// Idempotent: a replayed revocation reports the key again (it is still
	// present, now holding the placeholder) without failing.
	e.ScrubEnv(id, []string{"GITHUB_TOKEN"})
	if got := e.ScrubEnv(id, []string{"GITHUB_TOKEN"}); len(got) != 1 {
		t.Errorf("a repeated scrub should stay idempotent, got %v", got)
	}
}

// TestScrubSpecSecretsUsesBindings checks the convenience path drivers take
// when they hold the spec rather than a key list.
func TestScrubSpecSecretsUsesBindings(t *testing.T) {
	e, id := startSleeper(t)
	found := e.ScrubSpecSecrets(id, []executor.SecretBinding{
		{LeaseID: "lease_a", EnvKeys: []string{"GITHUB_TOKEN"}},
		{LeaseID: "lease_b", EnvKeys: []string{"KUBECONFIG"}},
	})
	if len(found) != 2 {
		t.Fatalf("ScrubSpecSecrets = %v, want both leases' keys", found)
	}
	env := strings.Join(retainedEnv(t, e, id), "\n")
	if strings.Contains(env, "ghp_secret_value") || strings.Contains(env, "cloop-lease-x") {
		t.Errorf("both bindings' material should be gone; env = %q", env)
	}
}

// TestScrubEnvConcurrentWithStatusAndSignal is the race-detector test for the
// driver half of revocation.
//
// A revocation is by definition concurrent with the work it interrupts, so the
// scrub has to be safe against every other operation on the same handle at the
// same moment — the status polls the control plane makes while a task runs,
// and the signal a kill-action revocation sends immediately afterwards.
func TestScrubEnvConcurrentWithStatusAndSignal(t *testing.T) {
	allowHost(t)
	e := New("scrub-race")

	const handles = 4
	ids := make([]string, 0, handles)
	for i := 0; i < handles; i++ {
		h, err := e.Start(context.Background(), executor.Spec{
			WorkDir: t.TempDir(),
			Argv:    []string{"sleep", "30"},
			Env:     []string{"PATH=/usr/bin:/bin", "GITHUB_TOKEN=ghp_secret_value"},
		})
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		ids = append(ids, h.ID)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_ = e.Signal(context.Background(), id, executor.SignalKill)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var scrubs atomic.Int64
	var wg sync.WaitGroup
	for _, id := range ids {
		for w := 0; w < 3; w++ {
			wg.Add(1)
			go func(id string, w int) {
				defer wg.Done()
				for ctx.Err() == nil {
					switch w {
					case 0:
						if len(e.ScrubEnv(id, []string{"GITHUB_TOKEN"})) > 0 {
							scrubs.Add(1)
						}
					case 1:
						_, _ = e.Status(ctx, id)
					case 2:
						_, _ = e.HandleStatuses(ctx)
					}
				}
			}(id, w)
		}
	}
	wg.Wait()

	if scrubs.Load() == 0 {
		t.Error("no scrub ever landed; the test did not exercise the race it claims to")
	}
	for _, id := range ids {
		if env := strings.Join(retainedEnv(t, e, id), "\n"); strings.Contains(env, "ghp_secret_value") {
			t.Errorf("handle %s still holds the credential after the race: %q", id, env)
		}
	}
}

// allowHost permits un-isolated host execution for the duration of one test,
// restoring whatever the policy was before. Another test in this package
// deliberately turns it off, and inheriting that would make these fail for a
// reason that has nothing to do with scrubbing.
func allowHost(t *testing.T) {
	t.Helper()
	prev := executor.SetAllowHostExecution(true)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })
}

// retainedEnv reads the driver's retained environment for a handle.
func retainedEnv(t *testing.T, e *Executor, id string) []string {
	t.Helper()
	e.mu.Lock()
	rec := e.handles[id]
	e.mu.Unlock()
	if rec == nil {
		t.Fatalf("no handle %s", id)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]string(nil), rec.cmd.Env...)
}

func containsEntry(env []string, want string) bool {
	for _, kv := range env {
		if kv == want {
			return true
		}
	}
	return false
}
