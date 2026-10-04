package quotastore

// Shared counters (Task 20354): several hub processes, each with its own
// enforcer and its own database handle, enforce one set of caps.

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func sharedEnforcer(t *testing.T, path string, resolver *quota.Resolver) *quota.Enforcer {
	t.Helper()
	statedbtest.Seed(t, path)
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	e := quota.NewEnforcer(resolver, s, quota.WithSharedCounters())
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestSharedCapHoldsAcrossProcesses: eight processes racing to admit against
// a cap of three admit exactly three. Without shared counters each process
// checks the cap against its own memory, and eight processes admit up to
// twenty-four.
func TestSharedCapHoldsAcrossProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	resolver, err := quota.New(quota.Config{Defaults: quota.Limits{quota.ResConcurrentTasks: 3}})
	if err != nil {
		t.Fatal(err)
	}
	const procs = 8
	enforcers := make([]*quota.Enforcer, procs)
	for i := range enforcers {
		enforcers[i] = sharedEnforcer(t, path, resolver)
	}
	subj := quota.SubjectForIdentity("tenant@example.com")

	var admitted atomic.Int32
	var wg sync.WaitGroup
	for _, e := range enforcers {
		for j := 0; j < 3; j++ {
			wg.Add(1)
			go func(e *quota.Enforcer) {
				defer wg.Done()
				if _, err := e.Admit(subj, quota.ResConcurrentTasks, 1); err == nil {
					admitted.Add(1)
				}
			}(e)
		}
	}
	wg.Wait()
	if got := admitted.Load(); got != 3 {
		t.Fatalf("admitted %d runs across %d processes, want the cap of 3", got, procs)
	}

	// Releases from any process free the shared slots.
	for i := 0; i < 3; i++ {
		enforcers[i].Release(subj.Label(), quota.ResConcurrentTasks, 1)
	}
	if _, err := enforcers[7].Admit(subj, quota.ResConcurrentTasks, 1); err != nil {
		t.Fatalf("admission after releases elsewhere: %v", err)
	}
	// And a double release does not mint headroom.
	enforcers[0].Release(subj.Label(), quota.ResConcurrentTasks, 5)
	if u := enforcers[1].Usage(subj.Label()); u[quota.ResConcurrentTasks] != 0 {
		t.Fatalf("usage after over-release = %v, want 0", u)
	}
}

// TestSharedSpendIsSummedAcrossProcesses: daily spend booked by two processes
// adds up, where absolute writes from memory would each overwrite the other.
func TestSharedSpendIsSummedAcrossProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	resolver, err := quota.New(quota.Config{Defaults: quota.Limits{quota.ResDailyCostUSD: 10}})
	if err != nil {
		t.Fatal(err)
	}
	a := sharedEnforcer(t, path, resolver)
	b := sharedEnforcer(t, path, resolver)
	a.Spend("tenant@example.com", 0, 6)
	b.Spend("tenant@example.com", 0, 6)
	if err := a.CheckSpendIdentity("tenant@example.com"); err == nil {
		t.Fatal("12 USD of spend across two processes passed a 10 USD budget")
	}
}

// TestOverridesReloadFromTheStore: an override one process writes is what
// another enforces once told to reload.
func TestOverridesReloadFromTheStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	resolver, err := quota.New(quota.Config{Defaults: quota.Limits{quota.ResConcurrentTasks: 5}})
	if err != nil {
		t.Fatal(err)
	}
	a := sharedEnforcer(t, path, resolver)
	b := sharedEnforcer(t, path, resolver)
	if err := a.SetOverride("tenant@example.com", quota.Limits{quota.ResConcurrentTasks: 0}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := b.ReloadOverrides(); err != nil {
		t.Fatal(err)
	}
	subj := quota.SubjectForIdentity("tenant@example.com")
	if _, err := b.Admit(subj, quota.ResConcurrentTasks, 1); err == nil {
		t.Fatal("B admitted against a limit A lowered to zero")
	}
}
