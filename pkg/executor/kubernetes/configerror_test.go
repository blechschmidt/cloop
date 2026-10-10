package kubernetes

// configerror_test.go covers the two halves of Task 20401's trap: the hub must
// not delete a per-run Secret before the container that reads it has started,
// and a container the kubelet cannot create — because a Secret is gone anyway —
// must fail the run by name instead of leaving it pending forever.
//
// The fake API server does not run containers, so these tests model the one
// kubelet behaviour that matters here with kubeletCreate: resolve a container's
// secretKeyRefs against the Secrets the server holds, and either start it or
// hold it in CreateContainerConfigError with the message a real kubelet writes.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// kubeletCreate models the kubelet creating one of a Pod's containers. Every
// secretKeyRef in the container's environment is resolved against the Secrets
// the fake holds; one that does not resolve holds the container in
// CreateContainerConfigError with the kubelet's own wording, and the Pod stays
// Pending. It reports whether the container started.
func (f *fakeAPI) kubeletCreate(t *testing.T, podName, containerName string) bool {
	t.Helper()
	f.mu.Lock()
	p, ok := f.pods[podName]
	if !ok {
		f.mu.Unlock()
		t.Fatalf("kubeletCreate: no pod %s", podName)
	}
	var c *container
	for i := range p.Spec.InitContainers {
		if p.Spec.InitContainers[i].Name == containerName {
			c = &p.Spec.InitContainers[i]
		}
	}
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == containerName {
			c = &p.Spec.Containers[i]
		}
	}
	if c == nil {
		f.mu.Unlock()
		t.Fatalf("kubeletCreate: pod %s has no container %s", podName, containerName)
	}
	missing := ""
	for _, e := range c.Env {
		if e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
			continue
		}
		ref := e.ValueFrom.SecretKeyRef
		s, ok := f.secrets[ref.Name]
		if !ok {
			missing = fmt.Sprintf("secret %q not found", ref.Name)
			break
		}
		_, inData := s.Data[ref.Key]
		_, inString := s.StringData[ref.Key]
		if !inData && !inString {
			missing = fmt.Sprintf("couldn't find key %s in Secret %s/%s", ref.Key, p.Metadata.Namespace, ref.Name)
			break
		}
	}
	f.mu.Unlock()

	f.setPhase(podName, func(p *pod) {
		state := containerState{Running: &stateRunning{StartedAt: time.Now().UTC().Format(time.RFC3339)}}
		if missing != "" {
			state = containerState{Waiting: &stateWaiting{Reason: reasonCreateContainerConfigError, Message: missing}}
		}
		cs := containerStatus{Name: containerName, State: state}
		if containerName == InitContainerName {
			p.Status.InitContainerStatuses = []containerStatus{cs}
			return
		}
		if missing == "" {
			p.Status.Phase = phaseRunning
		}
		p.Status.ContainerStatuses = []containerStatus{cs}
	})
	return missing == ""
}

// deleteSecretOutOfBand removes a Secret without the driver asking — an
// operator with kubectl, or an older hub that cleaned up on its way down.
func (f *fakeAPI) deleteSecretOutOfBand(name string) {
	f.mu.Lock()
	delete(f.secrets, name)
	f.mu.Unlock()
}

// testClock is a settable clock for Options.now.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock(t time.Time) *testClock { return &testClock{t: t} }

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// envSpec is a run whose whole environment travels in the lease Secret, behind
// a credentialed workspace fetch: the shape that strands a harness when the
// Secret goes during the fetch.
func envSpec() executor.Spec {
	spec := testSpec()
	spec.Workspace = gitWorkspace()
	spec.Env = leasedEnv()
	return spec
}

// waitRecord polls a record until cond holds.
func waitRecord(t *testing.T, ex *Executor, id string, what string, cond func(*record) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rec, err := ex.lookup(id); err == nil {
			rec.mu.Lock()
			ok := cond(rec)
			rec.mu.Unlock()
			if ok {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the driver never observed %s", what)
}

// --- the trap: keep the Secret until its reader started ---------------

// TestClose_MidFetchLeavesTheLeaseSecretForTheHarness is the trap, end to end.
//
// A hub restarts while the workspace provisioner is still fetching. The
// provisioner has read its own credential, so that Secret may go; the harness
// has not been created yet, and its whole environment is a reference into the
// lease Secret — so that one must stay, or the kubelet holds the harness in
// CreateContainerConfigError for good. The hub that comes back adopts the run,
// the fetch finishes, and the harness starts with its environment intact.
func TestClose_MidFetchLeavesTheLeaseSecretForTheHarness(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	ex1, api, src := newTestExecutor(t, func(o *Options) {
		o.Workspace = workingSource()
		o.HandleStore = store
	})
	spec := envSpec()
	handle, err := ex1.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	lease, ws := leaseSecretName(handle.ID), workspaceSecretName(handle.ID)

	if !api.kubeletCreate(t, podName, InitContainerName) {
		t.Fatal("the provisioner could not be created although its Secret exists")
	}
	waitRecord(t, ex1, handle.ID, "the provisioner start", func(r *record) bool { return r.initStarted })

	// --- the hub goes down mid-fetch ---------------------------------
	ex1.Close()
	src.waitOutstandingEmpty(t, 3*time.Second)
	if containsString(api.secretDeleteNames(), lease) || api.secretObject(lease) == nil {
		t.Fatalf("Close deleted %s while the harness had not been created; its environment is read "+
			"from that Secret, so the harness would be stranded (deletes: %v)", lease, api.secretDeleteNames())
	}
	if !containsString(api.secretDeleteNames(), ws) {
		t.Errorf("Close left %s although the provisioner had already read it (deletes: %v)",
			ws, api.secretDeleteNames())
	}

	// --- and comes back ------------------------------------------------
	ex2 := newRestartedExecutor(t, api, src, store)
	api.finishInitContainer(podName, 0, "Completed")
	if !api.kubeletCreate(t, podName, ContainerName) {
		t.Fatalf("the harness could not be created after the restart: %v", describePodStatus(api, podName))
	}
	api.mu.Lock()
	created := *api.pods[podName]
	sec := api.secrets[lease]
	api.mu.Unlock()
	got := resolveEnv(t, created.Spec.Containers[0], map[string]map[string][]byte{lease: sec.Data})
	for k, v := range envMap(spec.Env) {
		if got[k] != v {
			t.Errorf("after the restart the harness sees %s=%q, want %q", k, got[k], v)
		}
	}

	api.terminate(podName, 0, "Completed")
	if st := waitStatus(t, ex2, handle.ID, 5*time.Second); st.State != executor.StateExited {
		t.Fatalf("state after the restart = %q (%s), want exited", st.State, st.Error)
	}
	// The adopted record holds no state for the Secret; the ownerReference is
	// what takes it, with the Pod.
	waitFor(t, 3*time.Second, func() bool { return api.secretObject(lease) == nil })
}

// TestClose_LeavesEveryUnreadSecret: a Pod nothing has started in — still
// pulling its image, say — keeps both Secrets, and the workspace credential's
// lease is not released: releasing a GitHub App lease destroys the token the
// Secret holds for a provisioner that has not read it yet.
func TestClose_LeavesEveryUnreadSecret(t *testing.T) {
	wsSource := workingSource()
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = wsSource })
	handle, err := ex.Start(context.Background(), envSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	api.onlyPodName(t)

	ex.Close()
	if dels := api.secretDeleteNames(); len(dels) != 0 {
		t.Errorf("Close deleted %v from a Pod none of whose containers had started", dels)
	}
	for _, name := range []string{leaseSecretName(handle.ID), workspaceSecretName(handle.ID)} {
		if api.secretObject(name) == nil {
			t.Errorf("%s is gone; the Pod cannot start without it", name)
		}
	}
	if _, released := wsSource.counts(); released != 0 {
		t.Errorf("the workspace lease was released %d time(s) while its Secret was left for the "+
			"provisioner; for a GitHub App that destroys the token the Secret holds", released)
	}
}

// TestClose_TakesTheLeaseSecretOnceTheHarnessStarted: once the harness has
// read its environment and the files are projected, deleting the Secret takes
// nothing from the workload, and the durable copy in etcd should not outlive a
// hub that is walking away from it.
func TestClose_TakesTheLeaseSecretOnceTheHarnessStarted(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	spec := secretFileSpec()
	spec.Env = append(spec.Env, leasedEnv()...)
	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	if !api.kubeletCreate(t, podName, ContainerName) {
		t.Fatal("the harness could not be created although its Secret exists")
	}
	waitRecord(t, ex, handle.ID, "the harness start", func(r *record) bool { return r.harnessStarted })

	ex.Close()
	if !containsString(api.secretDeleteNames(), leaseSecretName(handle.ID)) {
		t.Errorf("Close left %s after the harness had read it (deletes: %v)",
			leaseSecretName(handle.ID), api.secretDeleteNames())
	}
	if len(api.deleteRecords()) != 0 {
		t.Errorf("Close deleted the running Pod: %v", api.deleteRecords())
	}
}

// TestClose_KeepsTheWorkspaceSecretForAWriteBackHarness: a push write-back's
// harness reads the workspace credential too, after the fetch. A hub that stops
// following the run between the two must leave it.
func TestClose_KeepsTheWorkspaceSecretForAWriteBackHarness(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = workingSource() })
	spec := testSpec()
	spec.Workspace = gitWorkspace()
	spec.Workspace.Ref = strings.Repeat("c", 40)
	spec.WriteBack = executor.WriteBack{Mode: executor.WriteBackPush, Branch: "cloop/task-42"}
	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	api.kubeletCreate(t, podName, InitContainerName)
	api.finishInitContainer(podName, 0, "Completed")
	waitRecord(t, ex, handle.ID, "the provisioner finish", func(r *record) bool { return r.initStarted })

	ex.Close()
	ws := workspaceSecretName(handle.ID)
	if containsString(api.secretDeleteNames(), ws) {
		t.Errorf("Close deleted %s although the write-back harness that reads it had not started", ws)
	}
	if !api.kubeletCreate(t, podName, ContainerName) {
		t.Errorf("the write-back harness could not be created: %v", describePodStatus(api, podName))
	}
}

// --- the fail-fast ------------------------------------------------------

// TestConfigError_MissingLeaseSecretFailsTheRunByName: whatever removed the
// Secret, a harness the kubelet cannot create is a failed run whose error names
// the Secret, not a run that reads "pending" until a deadline nobody set.
func TestConfigError_MissingLeaseSecretFailsTheRunByName(t *testing.T) {
	clock := newTestClock(time.Now())
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.now = clock.now })
	spec := testSpec()
	spec.Env = leasedEnv()
	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	lease := leaseSecretName(handle.ID)
	sub, cancel := context.WithCancel(context.Background())
	defer cancel()
	lines, err := ex.Stream(sub, handle.ID)
	if err != nil {
		t.Fatal(err)
	}

	api.deleteSecretOutOfBand(lease)
	clock.advance(time.Hour) // well past the creation race
	if api.kubeletCreate(t, podName, ContainerName) {
		t.Fatal("the fake kubelet created a container whose Secret is gone")
	}

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateFailed {
		t.Fatalf("state = %q (%s), want failed", st.State, st.Error)
	}
	for _, want := range []string{"cloop/" + lease, "no longer exists", "environment", "dispatch the task again"} {
		if !strings.Contains(st.Error, want) {
			t.Errorf("error %q does not contain %q", st.Error, want)
		}
	}
	assertNoLeakedEnv(t, "the run's error", st.Error)
	// The Pod goes: it is Pending, and would start unfollowed — and, its
	// policy removed, unfiltered — the moment the Secret reappeared.
	waitFor(t, 3*time.Second, func() bool { return len(api.deleteRecords()) == 1 })

	var log strings.Builder
	for l := range lines {
		log.WriteString(l.Text)
	}
	if !strings.Contains(log.String(), lease) {
		t.Errorf("the run's log never named the missing Secret:\n%s", log.String())
	}
}

// TestConfigError_InsideTheGraceIsTheCreationRace: the Pod is created before
// its Secret, so a fast kubelet can report the Secret missing for an instant.
// Its next sync starts the container, and the run must still be there to see
// it.
func TestConfigError_InsideTheGraceIsTheCreationRace(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	spec := testSpec()
	spec.Env = leasedEnv()
	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	lease := leaseSecretName(handle.ID)

	// What the kubelet posted before the Secret landed.
	api.setPhase(podName, func(p *pod) {
		p.Status.ContainerStatuses = []containerStatus{{Name: ContainerName, State: containerState{
			Waiting: &stateWaiting{Reason: reasonCreateContainerConfigError, Message: fmt.Sprintf("secret %q not found", lease)},
		}}}
	})
	time.Sleep(100 * time.Millisecond)
	if st, _ := ex.Status(context.Background(), handle.ID); st.State.Terminal() {
		t.Fatalf("the run failed on the creation race: %q (%s)", st.State, st.Error)
	}

	// The kubelet's next sync.
	if !api.kubeletCreate(t, podName, ContainerName) {
		t.Fatal("the harness could not be created although its Secret exists")
	}
	api.terminate(podName, 0, "Completed")
	if st := waitStatus(t, ex, handle.ID, 5*time.Second); st.State != executor.StateExited {
		t.Errorf("state = %q (%s), want exited", st.State, st.Error)
	}
}

// TestConfigError_RecheckFailsAContainerThatStaysStuck: a kubelet that keeps
// failing posts no new status, so nothing would wake the watcher before its own
// five-minute timeout. The error seen inside the grace arms a second look.
func TestConfigError_RecheckFailsAContainerThatStaysStuck(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.configErrorGraceOverride = 150 * time.Millisecond })
	spec := testSpec()
	spec.Env = leasedEnv()
	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	api.deleteSecretOutOfBand(leaseSecretName(handle.ID))
	api.kubeletCreate(t, podName, ContainerName)

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateFailed || !strings.Contains(st.Error, leaseSecretName(handle.ID)) {
		t.Errorf("state = %q (%s), want failed naming %s", st.State, st.Error, leaseSecretName(handle.ID))
	}
}

// TestConfigError_StuckPodGoesEvenWhenKeepingCompletedPods: keep_completed_pods
// keeps finished Pods for their logs. A stuck one is not finished — it would
// start the moment its Secret reappeared — and has no logs to keep.
func TestConfigError_StuckPodGoesEvenWhenKeepingCompletedPods(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) {
		o.KeepCompletedPods = true
		o.configErrorGraceOverride = time.Nanosecond
	})
	spec := testSpec()
	spec.Env = leasedEnv()
	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	api.deleteSecretOutOfBand(leaseSecretName(handle.ID))
	api.kubeletCreate(t, podName, ContainerName)

	if st := waitStatus(t, ex, handle.ID, 5*time.Second); st.State != executor.StateFailed {
		t.Fatalf("state = %q (%s), want failed", st.State, st.Error)
	}
	waitFor(t, 3*time.Second, func() bool { return len(api.podNames()) == 0 })
}

// TestConfigError_StuckProvisionerNamesTheWorkspaceSecret: the same failure
// one container earlier names the other Secret, and what it carries.
func TestConfigError_StuckProvisionerNamesTheWorkspaceSecret(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) {
		o.Workspace = workingSource()
		o.configErrorGraceOverride = time.Nanosecond
	})
	spec := testSpec()
	spec.Workspace = gitWorkspace()
	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	ws := workspaceSecretName(handle.ID)
	api.deleteSecretOutOfBand(ws)
	api.kubeletCreate(t, podName, InitContainerName)

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateFailed {
		t.Fatalf("state = %q (%s), want failed", st.State, st.Error)
	}
	for _, want := range []string{"workspace provisioner", ws, "git workspace credential"} {
		if !strings.Contains(st.Error, want) {
			t.Errorf("error %q does not contain %q", st.Error, want)
		}
	}
}

// TestConfigError_AnyConfigErrorFailsTheRun: the kubelet reports more than a
// missing Secret under this reason, and none of it is something a waiting run
// can change.
func TestConfigError_AnyConfigErrorFailsTheRun(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.configErrorGraceOverride = time.Nanosecond })
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	api.setPhase(podName, func(p *pod) {
		p.Status.ContainerStatuses = []containerStatus{{Name: ContainerName, State: containerState{
			Waiting: &stateWaiting{Reason: reasonCreateContainerConfigError,
				Message: `failed to prepare subPath for volumeMount "workspace" of container "harness"`},
		}}}
	})
	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateFailed || !strings.Contains(st.Error, "failed to prepare subPath") {
		t.Errorf("state = %q (%s), want failed relaying the kubelet's message", st.State, st.Error)
	}
}

// TestRehydrate_StrandedHarnessFailsOnTheFirstLook: a run adopted after a
// restart started long ago, so a harness already stranded — by a hub that, like
// the ones before this fix, deleted the Secret on its way down — fails at once
// instead of waiting out a grace meant for the creation race.
func TestRehydrate_StrandedHarnessFailsOnTheFirstLook(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	clock := newTestClock(time.Now().Add(-time.Hour))
	ex1, api, src := newTestExecutor(t, func(o *Options) {
		o.HandleStore = store
		o.now = clock.now
	})
	spec := testSpec()
	spec.Env = leasedEnv()
	handle, err := ex1.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	ex1.Close()
	api.deleteSecretOutOfBand(leaseSecretName(handle.ID))
	api.kubeletCreate(t, podName, ContainerName)

	ex2 := newRestartedExecutor(t, api, src, store)
	st := waitStatus(t, ex2, handle.ID, 5*time.Second)
	if st.State != executor.StateFailed || !strings.Contains(st.Error, leaseSecretName(handle.ID)) {
		t.Errorf("adopted state = %q (%s), want failed naming the missing Secret", st.State, st.Error)
	}
}

// TestSecretNamedIn pins the two kubelet wordings the explanation depends on.
func TestSecretNamedIn(t *testing.T) {
	for msg, want := range map[string]string{
		`secret "cloop-lease-k-1" not found`:                               "cloop-lease-k-1",
		`secrets "cloop-ws-k-1" not found`:                                 "cloop-ws-k-1",
		`couldn't find key env.FOO in Secret cloop/cloop-lease-k-1`:        "cloop-lease-k-1",
		`failed to prepare subPath for volumeMount "workspace"`:            "",
		`container has runAsNonRoot and image will run as root (pod: "x")`: "",
	} {
		if got := secretNamedIn(msg); got != want {
			t.Errorf("secretNamedIn(%q) = %q, want %q", msg, got, want)
		}
	}
}

// describePodStatus renders a Pod's container statuses for a failure message.
func describePodStatus(api *fakeAPI, name string) string {
	api.mu.Lock()
	defer api.mu.Unlock()
	p, ok := api.pods[name]
	if !ok {
		return "pod gone"
	}
	return fmt.Sprintf("phase=%s init=%+v containers=%+v", p.Status.Phase,
		p.Status.InitContainerStatuses, p.Status.ContainerStatuses)
}
