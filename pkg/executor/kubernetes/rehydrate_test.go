package kubernetes

// rehydrate_test.go simulates the failure Task 20191 removes: the control
// plane process goes away and comes back while the cluster keeps running the
// Pods it dispatched.
//
// It does that literally — build a driver, dispatch, throw the driver away,
// build a second one from the same store against the same fake API server —
// because the bug being fixed is not in any single function. It is in what
// survives the boundary between two processes, and the only way to test a
// boundary is to cross it.
//
// Two fixture details are deliberate and load-bearing:
//
//   - The Pods are left Pending across the restart. The log follower opens
//     only once a Pod reports Running, so a Pending Pod means the first driver
//     never holds the fake's log stream, and the chunk emitted after the
//     restart can only have been read by a follower the *second* driver
//     opened. With the Pod already Running, two followers would briefly
//     compete for one channel and the assertion would be about the fixture
//     rather than about the driver.
//   - The first driver is Closed rather than abandoned. That is what a
//     graceful restart does, and it is the harder case: Close finishes every
//     live handle, so every "only when terminal" guard in the driver — the
//     Pod delete, the NetworkPolicy delete, the row delete — is exercised on
//     the one path where getting it wrong destroys the work in flight.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// newRestartedExecutor builds a second driver against the same fake API, the
// same credential source and the same handle store: the hub coming back up.
func newRestartedExecutor(t *testing.T, api *fakeAPI, src *fakeSource, store executor.HandleStore) *Executor {
	t.Helper()
	ex, err := New(Options{
		ID:          "k8s-test",
		Namespace:   "cloop",
		Image:       "ghcr.io/example/harness@sha256:" + strings.Repeat("a", 64),
		Credentials: src,
		HandleStore: store,
	})
	if err != nil {
		t.Fatalf("New (restarted): %v", err)
	}
	t.Cleanup(ex.Close)
	return ex
}

// otherPodName returns the one Pod name that is not `known`, waiting for it to
// appear. Pod names are server-generated, so this is how a test that started
// two workloads tells them apart without reaching into the fake's map.
func otherPodName(t *testing.T, api *fakeAPI, known string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, name := range api.podNames() {
			if name != known {
				return name
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected a second pod alongside %s, got %v", known, api.podNames())
	return ""
}

// waitStoreLen polls until the store holds want rows. The delete happens on a
// finishing handle's own goroutine, so an immediate assertion would be racing
// the driver rather than testing it.
func waitStoreLen(t *testing.T, store *executor.MemoryHandleStore, want int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if store.Len() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("handle store holds %d rows after %s, want %d", store.Len(), d, want)
}

// waitAcquired polls until the credential source has issued want leases. Every
// adoption acquires exactly one, so this is how a test knows a rehydrated
// handle has finished reattaching — and, when want is asserted to hold, that a
// second adoption never happened.
func waitAcquired(t *testing.T, src *fakeSource, want int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if acquired, _, _ := src.counts(); acquired >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	acquired, _, _ := src.counts()
	t.Fatalf("credential source issued %d leases after %s, want %d", acquired, d, want)
}

// TestStart_PersistsTheHandleRow pins the shape of what Start writes. The
// fields are a contract with pkg/executorstore and with adopt(): an
// ExternalID in any other shape is a Pod that can never be found again.
func TestStart_PersistsTheHandleRow(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	ex, api, _ := newTestExecutor(t, func(o *Options) {
		o.HandleStore = store
		o.EgressFilter = EgressFilter{Enabled: true}
	})

	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)

	rows, err := store.ListHandles("k8s-test")
	if err != nil {
		t.Fatalf("ListHandles: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("store holds %d rows, want 1", len(rows))
	}
	rec := rows[0]
	if rec.HandleID != handle.ID {
		t.Errorf("HandleID = %q, want %q", rec.HandleID, handle.ID)
	}
	if rec.Driver != executor.KindKubernetes {
		t.Errorf("Driver = %q, want %q", rec.Driver, executor.KindKubernetes)
	}
	if want := "cloop/" + name; rec.ExternalID != want {
		t.Errorf("ExternalID = %q, want %q — adoption resolves the Pod from this and nothing else",
			rec.ExternalID, want)
	}
	if rec.ProjectPath != "/srv/app" {
		t.Errorf("ProjectPath = %q, want the project the kubeconfig was leased for", rec.ProjectPath)
	}
	if rec.TaskID != 42 {
		t.Errorf("TaskID = %d, want 42", rec.TaskID)
	}
	if rec.Image != handle.Image || rec.Image == "" {
		t.Errorf("Image = %q, want the scheduled reference %q", rec.Image, handle.Image)
	}
	if rec.StartedAt.IsZero() {
		t.Error("StartedAt is zero; the orphan sweep compares it against a grace period")
	}
	// The NetworkPolicy name is the one piece of cleanup state no API query
	// can reconstruct, because the policy selects the Pod rather than the
	// other way round.
	policies := api.policyNames()
	if len(policies) != 1 {
		t.Fatalf("egress policies = %v, want exactly one", policies)
	}
	if got := rec.Meta[metaNetworkPolicy]; got != policies[0] {
		t.Errorf("Meta[%q] = %q, want %q", metaNetworkPolicy, got, policies[0])
	}
}

// TestRehydrate_ReattachesAfterAControlPlaneRestart is the whole point: after
// a restart, Stream, Status and Signal must answer for a Pod this process
// never started.
func TestRehydrate_ReattachesAfterAControlPlaneRestart(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	ex1, api, src := newTestExecutor(t, func(o *Options) { o.HandleStore = store })

	running, err := ex1.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	runningPod := api.onlyPodName(t)
	stopped, err := ex1.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start (second): %v", err)
	}
	stoppedPod := otherPodName(t, api, runningPod)
	if store.Len() != 2 {
		t.Fatalf("store holds %d rows after two dispatches, want 2", store.Len())
	}

	// --- the hub goes down ---------------------------------------------
	ex1.Close()
	waitStatus(t, ex1, running.ID, 5*time.Second)
	src.waitOutstandingEmpty(t, 3*time.Second)

	// Close must leave work in flight alone; that is the premise everything
	// below rests on. The settle window matters: a regression here would
	// delete the Pod from the pump goroutine Close cancels, not from Close
	// itself, so an immediate assertion would pass against the bug.
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if dels := api.deleteRecords(); len(dels) != 0 {
			t.Fatalf("shutting down deleted running Pods: %v — a hub restarting for an upgrade would "+
				"destroy every run in flight and then rehydrate handles whose Pods it had just removed", dels)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if store.Len() != 2 {
		t.Fatalf("store holds %d rows after a graceful shutdown, want 2 — StateUnknown is not terminal "+
			"and the workloads are still running", store.Len())
	}

	// --- and comes back ------------------------------------------------
	ex2 := newRestartedExecutor(t, api, src, store)
	if got := len(ex2.Handles()); got != 2 {
		t.Fatalf("the restarted executor knows %d handles, want 2", got)
	}

	st, err := ex2.Status(context.Background(), running.ID)
	if err != nil {
		t.Fatalf("Status after restart: %v (ErrHandleNotFound=%v)", err, errors.Is(err, executor.ErrHandleNotFound))
	}
	if st.State.Terminal() {
		t.Errorf("state after restart = %q, want a live state — the Pod is still running", st.State)
	}
	if !st.StartedAt.Equal(running.StartedAt.Truncate(0)) && st.StartedAt.IsZero() {
		t.Error("StartedAt was lost across the restart")
	}

	streamCtx, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()
	lines, err := ex2.Stream(streamCtx, running.ID)
	if err != nil {
		t.Fatalf("Stream after restart: %v (ErrHandleNotFound=%v)", err, errors.Is(err, executor.ErrHandleNotFound))
	}
	collected := make(chan string, 1)
	go func() {
		var sb strings.Builder
		for line := range lines {
			sb.WriteString(line.Text)
		}
		collected <- sb.String()
	}()

	// Signal is the one that needed a credential this process never had: the
	// only way to stop a Pod is to delete it.
	if err := ex2.Signal(context.Background(), stopped.ID, executor.SignalKill); err != nil {
		t.Fatalf("Signal after restart: %v (ErrHandleNotFound=%v)", err, errors.Is(err, executor.ErrHandleNotFound))
	}
	killed := waitStatus(t, ex2, stopped.ID, 5*time.Second)
	if killed.State != executor.StateKilled {
		t.Errorf("state after Signal = %q (%s), want killed", killed.State, killed.Error)
	}
	var sawDelete bool
	for _, d := range api.deleteRecords() {
		if d.Name == stoppedPod {
			sawDelete = true
			if d.Grace != int64(DefaultKillGracePeriod/time.Second) {
				t.Errorf("kill grace = %ds, want %ds", d.Grace, int64(DefaultKillGracePeriod/time.Second))
			}
		}
	}
	if !sawDelete {
		t.Errorf("Signal did not delete %s; deletes = %v", stoppedPod, api.deleteRecords())
	}

	// The other handle runs to completion under the new process, producing
	// output that only a re-opened log follower can have collected.
	api.run(runningPod)
	api.emitLog(runningPod, "back after the restart\n")
	api.terminate(runningPod, 0, "Completed")

	final := waitStatus(t, ex2, running.ID, 5*time.Second)
	if final.State != executor.StateExited || final.ExitCode != 0 {
		t.Errorf("state = %q exit = %d (%s), want exited 0", final.State, final.ExitCode, final.Error)
	}

	select {
	case out := <-collected:
		for _, want := range []string{"reattaching to pod cloop/" + runningPod, "back after the restart"} {
			if !strings.Contains(out, want) {
				t.Errorf("stream output %q is missing %q", out, want)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reattached log stream never closed")
	}

	// Both handles are terminal now, so both rows must be gone: a row that
	// outlives its workload is adopted again on the next boot, fails to find
	// its Pod, and reports a failure that already happened.
	waitStoreLen(t, store, 0, 3*time.Second)
	src.waitOutstandingEmpty(t, 3*time.Second)
}

// TestRehydrate_MissingPodFinishesFailedAndDropsTheRow covers the Pod deleted
// while the hub was down. The handle must not come back as a permanently
// "running" ghost, and its row must not survive to fail the same way on every
// subsequent boot.
func TestRehydrate_MissingPodFinishesFailedAndDropsTheRow(t *testing.T) {
	api := newFakeAPI(t)
	src := newFakeSource(api.restConfig())
	store := executor.NewMemoryHandleStore()

	// The policy outlived its Pod, which is exactly what a hub killed between
	// creating the two leaves behind.
	api.seedNetworkPolicy("cloop-egress-k-ghost", map[string]string{LabelManaged: "true"}, time.Minute)
	if err := store.PutHandle(executor.HandleRecord{
		HandleID:    "k-ghost",
		ExecutorID:  "k8s-test",
		Driver:      executor.KindKubernetes,
		ExternalID:  "cloop/cloop-app-k8s-test00042",
		ProjectPath: "/srv/app",
		TaskID:      7,
		StartedAt:   time.Now().Add(-time.Minute),
		Meta:        map[string]string{metaNetworkPolicy: "cloop-egress-k-ghost"},
	}); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := newRestartedExecutor(t, api, src, store)

	st := waitStatus(t, ex, "k-ghost", 5*time.Second)
	if st.State != executor.StateFailed {
		t.Errorf("state = %q (%s), want failed — the Pod is gone and the outcome is unrecoverable",
			st.State, st.Error)
	}
	if !strings.Contains(st.Error, "no longer exists") {
		t.Errorf("error = %q, want it to say the Pod is gone", st.Error)
	}
	waitStoreLen(t, store, 0, 3*time.Second)

	// The policy the row remembered is dropped with it. Without the Meta
	// round-trip there would be no name to delete, and the firewall would sit
	// in the namespace until the next orphan sweep.
	var sawPolicyDelete bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !sawPolicyDelete {
		for _, name := range api.policyDeleteNames() {
			if name == "cloop-egress-k-ghost" {
				sawPolicyDelete = true
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !sawPolicyDelete {
		t.Errorf("the adopted handle's egress NetworkPolicy was not deleted; deletes = %v",
			api.policyDeleteNames())
	}
	src.waitOutstandingEmpty(t, 3*time.Second)
}

// TestRehydrate_IsIdempotent: a driver constructed with a store and then
// handed the same store again — which is what boot order produces, since the
// state database opens after the drivers are built — must adopt each Pod once.
// A second adoption would mean a second pump, a second log follower and a
// second lease against one Pod.
func TestRehydrate_IsIdempotent(t *testing.T) {
	api := newFakeAPI(t)
	src := newFakeSource(api.restConfig())
	store := executor.NewMemoryHandleStore()

	api.seedPod("cloop-app-k8s-test00001", map[string]string{
		LabelManaged:    "true",
		LabelExecutorID: "k8s-test",
		LabelTaskID:     "42",
		LabelHandleID:   "k-adopted",
	}, phasePending, time.Minute)
	if err := store.PutHandle(executor.HandleRecord{
		HandleID:   "k-adopted",
		ExecutorID: "k8s-test",
		Driver:     executor.KindKubernetes,
		ExternalID: "cloop/cloop-app-k8s-test00001",
		StartedAt:  time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	// New rehydrates once...
	ex := newRestartedExecutor(t, api, src, store)
	// ...and this must not rehydrate again.
	ex.AttachHandleStore(store)
	ex.AttachHandleStore(store)

	waitAcquired(t, src, 1, 3*time.Second)
	// Settle, so a duplicate adoption's lease has time to show up rather than
	// being counted after the assertion. The adopted goroutine acquires as its
	// first action, so this is generous by orders of magnitude.
	time.Sleep(150 * time.Millisecond)

	if got := ex.Handles(); len(got) != 1 {
		t.Errorf("handles = %v, want exactly one adopted record", got)
	}
	if acquired, _, _ := src.counts(); acquired != 1 {
		t.Errorf("credential source issued %d leases, want 1 — a second adoption ran a second pump, "+
			"log follower and renewer against the same Pod", acquired)
	}
	statuses, err := ex.HandleStatuses(context.Background())
	if err != nil {
		t.Fatalf("HandleStatuses: %v", err)
	}
	if len(statuses) != 1 {
		t.Errorf("HandleStatuses returned %d entries, want 1", len(statuses))
	}

	// Adopting must also mark the Pod tracked, or the orphan sweep collects
	// the very workload rehydration just recovered.
	if _, ours := ex.trackedPodNames()["cloop-app-k8s-test00001"]; !ours {
		t.Error("the adopted Pod is not tracked; ReconcileOrphans would delete it")
	}
	removed, err := ex.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("the orphan sweep removed %v; an adopted Pod is not an orphan", removed)
	}
}

// TestRehydrate_DropsAnUnusableRow: a row whose ExternalID is not a
// namespace/pod reference can never be resolved to a Pod, so keeping it would
// leave a permanent adoption failure in the table. Nothing is lost — the Pod
// it meant, if any, still carries this executor's labels and is collected by
// the orphan sweep.
func TestRehydrate_DropsAnUnusableRow(t *testing.T) {
	api := newFakeAPI(t)
	src := newFakeSource(api.restConfig())
	store := executor.NewMemoryHandleStore()
	for _, external := range []string{"just-a-pod-name", "cloop/", "/pod"} {
		if err := store.PutHandle(executor.HandleRecord{
			HandleID:   "k-" + strings.NewReplacer("/", "-", " ", "-").Replace(external),
			ExecutorID: "k8s-test",
			Driver:     executor.KindKubernetes,
			ExternalID: external,
			StartedAt:  time.Now(),
		}); err != nil {
			t.Fatalf("PutHandle(%q): %v", external, err)
		}
	}

	ex := newRestartedExecutor(t, api, src, store)
	if got := ex.Handles(); len(got) != 0 {
		t.Errorf("handles = %v, want none adopted from unusable rows", got)
	}
	if store.Len() != 0 {
		t.Errorf("store holds %d unusable rows, want them dropped", store.Len())
	}
	if acquired, _, _ := src.counts(); acquired != 0 {
		t.Errorf("credential source issued %d leases for rows that name no Pod", acquired)
	}
}

// TestRehydrate_WithoutACredentialFinishesFailed: a kubeconfig grant revoked
// while the hub was down must not produce a handle that claims to be running
// while holding nothing that can observe or stop its Pod.
func TestRehydrate_WithoutACredentialFinishesFailed(t *testing.T) {
	api := newFakeAPI(t)
	src := newFakeSource(api.restConfig())
	src.setAcquireErr(errors.New("the grant for executor:k8s-test was revoked"))
	store := executor.NewMemoryHandleStore()
	if err := store.PutHandle(executor.HandleRecord{
		HandleID:   "k-orphan",
		ExecutorID: "k8s-test",
		Driver:     executor.KindKubernetes,
		ExternalID: "cloop/cloop-app-k8s-test00001",
		StartedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := newRestartedExecutor(t, api, src, store)
	st := waitStatus(t, ex, "k-orphan", 5*time.Second)
	if st.State != executor.StateFailed {
		t.Errorf("state = %q (%s), want failed", st.State, st.Error)
	}
	if !strings.Contains(st.Error, "revoked") {
		t.Errorf("error = %q, want it to name the cause", st.Error)
	}
	// Signal must answer rather than panic on the client the record never got.
	if err := ex.Signal(context.Background(), "k-orphan", executor.SignalKill); err != nil {
		t.Errorf("Signal on a handle that could not reattach: %v", err)
	}
	waitStoreLen(t, store, 0, 3*time.Second)
}

// TestRehydrate_NilStoreKeepsThePreviousBehaviour: the driver must still
// construct and run with no store at all, which is what every embedder without
// a state database has.
func TestRehydrate_NilStoreKeepsThePreviousBehaviour(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.run(name)
	api.terminate(name, 0, "Completed")
	if st := waitStatus(t, ex, handle.ID, 5*time.Second); st.State != executor.StateExited {
		t.Errorf("state = %q (%s), want exited", st.State, st.Error)
	}
	// And attaching nothing is a no-op rather than a nil-store panic.
	ex.AttachHandleStore(nil)
}
