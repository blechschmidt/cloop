package reconcile

import (
	"context"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// TestReconcileHandsExecutorsToTheIsolationProbe: the preflight pass — the one
// a hub's Bootstrap runs in the background — hands each configured container
// executor to the probe hook (Task 20439), and the registration-only pass a
// CLI command makes hands it nothing.
func TestReconcileHandsExecutorsToTheIsolationProbe(t *testing.T) {
	fakeRuntime(t, healthyRuntime)
	permissive(t)

	var (
		mu  sync.Mutex
		got []string
	)
	hook := func(ex executor.IsolationProber) {
		rt, _ := ex.IsolationRuntime()
		mu.Lock()
		got = append(got, ex.ID()+"/"+rt)
		mu.Unlock()
	}
	cfg := containerConfig("sandbox")
	cfg.Executors.Container.OCIRuntime = "kata"

	reg := executor.NewRegistry()
	opts := isolatedOpts(reg)
	opts.DisableHandleStore = true
	opts.IsolationProbe = hook
	opts.SkipPreflight = true
	FromConfig(context.Background(), t.TempDir(), cfg, opts)
	if len(got) != 0 {
		t.Fatalf("a registration-only pass probed %v", got)
	}

	opts.SkipPreflight = false
	FromConfig(context.Background(), t.TempDir(), cfg, opts)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "sandbox/kata" {
		t.Fatalf("probed %v, want sandbox/kata", got)
	}
}
