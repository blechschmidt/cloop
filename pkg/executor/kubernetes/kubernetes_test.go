package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// newTestExecutor wires an executor to a fake API server and returns both,
// plus the credential source so tests can assert lease accounting.
func newTestExecutor(t *testing.T, mutate func(*Options)) (*Executor, *fakeAPI, *fakeSource) {
	t.Helper()
	api := newFakeAPI(t)
	src := newFakeSource(api.restConfig())
	opts := Options{
		ID:          "k8s-test",
		Namespace:   "cloop",
		Image:       "ghcr.io/example/harness@sha256:" + strings.Repeat("a", 64),
		Credentials: src,
	}
	if mutate != nil {
		mutate(&opts)
	}
	ex, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(ex.Close)
	return ex, api, src
}

func testSpec() executor.Spec {
	return executor.Spec{
		WorkDir: "/srv/app",
		Argv:    []string{"cloop", "run"},
		Labels:  map[string]string{"project": "/srv/app", "task_id": "42"},
	}
}

// waitStatus polls until the handle reaches a terminal state.
func waitStatus(t *testing.T, ex *Executor, id string, d time.Duration) executor.Status {
	t.Helper()
	deadline := time.Now().Add(d)
	var last executor.Status
	for time.Now().Before(deadline) {
		st, err := ex.Status(context.Background(), id)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		last = st
		if st.State.Terminal() || st.State == executor.StateUnknown {
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("handle %s never reached a terminal state (last: %+v)", id, last)
	return last
}

// TestStart_HappyPath walks a Pod through the whole lifecycle: created,
// scheduled, running, log output, clean exit — and asserts the driver
// reported each part and cleaned up after itself.
func TestStart_HappyPath(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)

	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if handle.ExecutorID != "k8s-test" || handle.ID == "" {
		t.Fatalf("handle = %+v", handle)
	}
	if handle.PID != 0 {
		t.Errorf("handle.PID = %d; a Pod's PID lives in another namespace and must not be reported", handle.PID)
	}

	stream, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	collected := make(chan string, 1)
	go func() {
		var sb strings.Builder
		for line := range stream {
			sb.WriteString(line.Text)
		}
		collected <- sb.String()
	}()

	name := api.onlyPodName(t)
	api.run(name)
	api.emitLog(name, "building...\n")
	api.emitLog(name, "TASK_DONE\n")
	api.terminate(name, 0, "Completed")

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateExited {
		t.Errorf("state = %q (%s), want exited", st.State, st.Error)
	}
	if st.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", st.ExitCode)
	}
	if st.FinishedAt.IsZero() {
		t.Error("FinishedAt was never set")
	}

	select {
	case out := <-collected:
		for _, want := range []string{"pod cloop/cloop-app-k8s-test", "building...", "TASK_DONE"} {
			if !strings.Contains(out, want) {
				t.Errorf("stream output %q is missing %q", out, want)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the log stream never closed after the Pod terminated")
	}

	// A completed Pod must be deleted, or the namespace fills with
	// Terminated Pods and hits its ResourceQuota pod count.
	if got := api.podNames(); len(got) != 0 {
		t.Errorf("pods left behind after completion: %v", got)
	}
	src.waitOutstandingEmpty(t, 3*time.Second)
}

// TestStart_ReleasesLeaseOnSuccess and its failure sibling are the tests the
// task's security requirement turns on: a lease that outlives its handle is a
// credential the broker still believes is in use.
func TestStart_ReleasesLeaseOnSuccess(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)

	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	acquired, released, _ := src.counts()
	if acquired != 1 {
		t.Fatalf("acquired %d leases during Start, want 1", acquired)
	}
	if released != 0 {
		t.Fatalf("released a lease during Start; the driver still needs it to delete the Pod")
	}

	name := api.onlyPodName(t)
	api.run(name)
	api.terminate(name, 0, "Completed")
	waitStatus(t, ex, handle.ID, 5*time.Second)
	src.waitOutstandingEmpty(t, 3*time.Second)
}

func TestStart_ReleasesLeaseOnWorkloadFailure(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)

	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.run(name)
	api.terminate(name, 3, "Error")

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateExited || st.ExitCode != 3 {
		t.Errorf("state=%q exit=%d, want exited/3", st.State, st.ExitCode)
	}
	src.waitOutstandingEmpty(t, 3*time.Second)
}

// TestStart_ReleasesLeaseWhenCreateIsRejected covers the path with no pump to
// clean up after it: a refused create must release the lease inline.
func TestStart_ReleasesLeaseWhenCreateIsRejected(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)
	api.failAlways("POST /pods", apiFailure{
		Code: 403, Reason: "Forbidden",
		Message: `pods is forbidden: User "system:serviceaccount:cloop:runner" cannot create resource "pods"`,
	})

	_, err := ex.Start(context.Background(), testSpec())
	if err == nil {
		t.Fatal("Start succeeded against an API server that refuses to create Pods")
	}
	if !strings.Contains(err.Error(), "not allowed to create Pods") {
		t.Errorf("error %q does not explain the RBAC failure", err)
	}
	if out := src.outstanding(); len(out) != 0 {
		t.Errorf("a refused Start leaked leases: %v", out)
	}
}

// TestStart_ReleasesLeaseWhenSpecIsInvalid: the Spec is validated after the
// lease is acquired (the namespace comes from the grant), so this path must
// release too.
func TestStart_ReleasesLeaseWhenSpecIsInvalid(t *testing.T) {
	ex, _, src := newTestExecutor(t, nil)

	spec := testSpec()
	spec.ResourceLimits.PIDs = 100 // a Pod cannot express a PID cap
	_, err := ex.Start(context.Background(), spec)
	if err == nil {
		t.Fatal("Start accepted a PID limit a Pod cannot carry")
	}
	if !errors.Is(err, executor.ErrUnsupported) {
		t.Errorf("error %v does not wrap ErrUnsupported", err)
	}
	if out := src.outstanding(); len(out) != 0 {
		t.Errorf("a rejected Spec leaked leases: %v", out)
	}
}

func TestStart_FailsWhenCredentialsAreUnavailable(t *testing.T) {
	ex, _, src := newTestExecutor(t, nil)
	src.setAcquireErr(fmt.Errorf("%w: no grant", ErrNoKubeconfigGrant))

	_, err := ex.Start(context.Background(), testSpec())
	if err == nil {
		t.Fatal("Start succeeded with no kubeconfig; it must fail closed")
	}
	if !errors.Is(err, ErrNoKubeconfigGrant) {
		t.Errorf("error %v does not wrap ErrNoKubeconfigGrant", err)
	}
}

// TestNew_RequiresCredentialSource is the structural guarantee behind "never
// a file on the control-plane host": there is no code path that constructs
// this executor without a broker.
func TestNew_RequiresCredentialSource(t *testing.T) {
	_, err := New(Options{ID: "k8s", Namespace: "cloop"})
	if err == nil {
		t.Fatal("New succeeded with no credential source")
	}
	if !strings.Contains(err.Error(), "brokered kubeconfig lease") {
		t.Errorf("error %q does not explain that credentials must be brokered", err)
	}
}

// TestSignal_DeletesPodWithGracePeriod checks the mapping from cloop's
// signal vocabulary onto the only lever Kubernetes offers.
func TestSignal_DeletesPodWithGracePeriod(t *testing.T) {
	cases := map[string]struct {
		sig       executor.Signal
		wantGrace int64
	}{
		"kill is a short grace":     {executor.SignalKill, int64(DefaultKillGracePeriod / time.Second)},
		"terminate is the pod's":    {executor.SignalTerminate, int64(DefaultTerminationGracePeriod / time.Second)},
		"interrupt is also SIGTERM": {executor.SignalInterrupt, int64(DefaultTerminationGracePeriod / time.Second)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ex, api, src := newTestExecutor(t, nil)
			handle, err := ex.Start(context.Background(), testSpec())
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			podName := api.onlyPodName(t)
			api.run(podName)

			if err := ex.Signal(context.Background(), handle.ID, tc.sig); err != nil {
				t.Fatalf("Signal: %v", err)
			}
			st := waitStatus(t, ex, handle.ID, 5*time.Second)
			if st.State != executor.StateKilled {
				t.Errorf("state = %q (%s), want killed", st.State, st.Error)
			}
			if !strings.Contains(st.Error, string(tc.sig)) {
				t.Errorf("status error %q does not name the requested signal", st.Error)
			}

			recs := api.deleteRecords()
			if len(recs) == 0 {
				t.Fatal("no DELETE was issued")
			}
			if recs[0].Grace != tc.wantGrace {
				t.Errorf("gracePeriodSeconds = %d, want %d", recs[0].Grace, tc.wantGrace)
			}
			src.waitOutstandingEmpty(t, 3*time.Second)
		})
	}
}

func TestSignal_Rejects(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)

	if err := ex.Signal(context.Background(), "nope", executor.SignalKill); !errors.Is(err, executor.ErrHandleNotFound) {
		t.Errorf("Signal on unknown handle = %v, want ErrHandleNotFound", err)
	}
	if err := ex.Signal(context.Background(), "nope", executor.Signal("hup")); !errors.Is(err, executor.ErrInvalidSignal) {
		t.Errorf("Signal with a bogus signal = %v, want ErrInvalidSignal", err)
	}
}

// TestSignal_AfterExitIsSuccess: the caller asked for it to be stopped and it
// is stopped. Returning an error would make every stop-after-completion race
// look like a failure in the UI.
func TestSignal_AfterExitIsSuccess(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.run(name)
	api.terminate(name, 0, "Completed")
	waitStatus(t, ex, handle.ID, 5*time.Second)

	if err := ex.Signal(context.Background(), handle.ID, executor.SignalKill); err != nil {
		t.Errorf("Signal on a finished handle = %v, want nil", err)
	}
}

// TestExternalDelete_IsReportedAsKilled: an eviction or a `kubectl delete`
// must not look like a clean exit, because the task's work did not finish.
func TestExternalDelete_IsReportedAsKilled(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.run(name)

	// Delete it behind the driver's back.
	api.handleDeleteDirect(name)

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateKilled {
		t.Errorf("state = %q, want killed", st.State)
	}
	if !strings.Contains(st.Error, "deleted out from under this run") {
		t.Errorf("status error %q does not explain the external deletion", st.Error)
	}
	src.waitOutstandingEmpty(t, 3*time.Second)
}

// TestLogFollow_RetriesWhileContainerIsStarting: the API server answers a log
// request with 400 until the container is up, and giving up on that first
// rejection would silently drop the whole run's output.
func TestLogFollow_RetriesWhileContainerIsStarting(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	stream, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	collected := make(chan string, 1)
	go func() {
		var sb strings.Builder
		for line := range stream {
			sb.WriteString(line.Text)
		}
		collected <- sb.String()
	}()

	name := api.onlyPodName(t)
	// Reject the first log attempt the way a not-yet-started container does.
	api.failNext("GET /log", apiFailure{
		Code: 400, Reason: "BadRequest",
		Message: fmt.Sprintf("container %q in pod %q is waiting to start: ContainerCreating", ContainerName, name),
	})
	api.run(name)
	// Give the retry loop time to come back.
	time.Sleep(50 * time.Millisecond)
	api.emitLog(name, "recovered output\n")
	api.terminate(name, 0, "Completed")

	waitStatus(t, ex, handle.ID, 5*time.Second)
	select {
	case out := <-collected:
		if !strings.Contains(out, "recovered output") {
			t.Errorf("output %q lost the log the driver should have retried for", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream never closed")
	}
}

// TestPodFailsBeforeContainerStarts: an ImagePullBackOff produces no logs at
// all, so the phase narration is the only thing telling the operator why.
func TestPodFailsBeforeContainerStarts(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	stream, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	collected := make(chan string, 1)
	go func() {
		var sb strings.Builder
		for line := range stream {
			sb.WriteString(line.Text)
		}
		collected <- sb.String()
	}()

	name := api.onlyPodName(t)
	api.setPhase(name, func(p *pod) {
		p.Status.Phase = phaseFailed
		p.Status.ContainerStatuses = []containerStatus{{
			Name: ContainerName,
			State: containerState{Waiting: &stateWaiting{
				Reason: "ImagePullBackOff", Message: "manifest unknown",
			}},
		}}
	})

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateFailed {
		t.Errorf("state = %q, want failed", st.State)
	}
	if !strings.Contains(st.Error, "ImagePullBackOff") {
		t.Errorf("status error %q does not name the pull failure", st.Error)
	}
	select {
	case <-collected:
	case <-time.After(5 * time.Second):
		t.Fatal("stream never closed for a Pod that never started")
	}
	src.waitOutstandingEmpty(t, 3*time.Second)
}

// TestRun_CollectsOutputAndExitCode exercises the shared executor.Run helper
// against this driver, which is the path `cloop executor test` takes.
func TestRun_CollectsOutputAndExitCode(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)

	done := make(chan executor.RunResult, 1)
	errc := make(chan error, 1)
	go func() {
		res, err := executor.Run(context.Background(), ex, testSpec())
		done <- res
		errc <- err
	}()

	name := api.onlyPodName(t)
	api.run(name)
	api.emitLog(name, "cloop v1.2.3\n")
	api.terminate(name, 0, "Completed")

	select {
	case res := <-done:
		if err := <-errc; err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !strings.Contains(string(res.Output), "cloop v1.2.3") {
			t.Errorf("output %q does not contain the workload's log", res.Output)
		}
		if res.Status.State != executor.StateExited {
			t.Errorf("state = %q", res.Status.State)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("executor.Run never returned")
	}
	src.waitOutstandingEmpty(t, 3*time.Second)
}

// TestRenewFailureTerminatesTheWorkload: revoking a kubeconfig grant must
// take effect within one lease period, which means killing the Pod that is
// running on the authority just withdrawn.
func TestRenewFailureTerminatesTheWorkload(t *testing.T) {
	// A tiny lease window drives renewInterval to its floor, and the floor
	// is still 30s — too slow for a test. Cross the seam directly instead:
	// this is exactly what renewLoop does when Renew returns an error.
	ex, api, src := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.run(name)

	src.setRenewErr(errors.New("grant revoked"))
	rec, err := ex.lookup(handle.ID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	renewCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, rerr := src.Renew(renewCtx, rec.leaseIDValue()); rerr == nil {
		t.Fatal("the fake source was supposed to refuse the renewal")
	}
	ex.terminate(rec, "the kubeconfig grant behind this run was revoked or expired", 0)

	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateKilled {
		t.Errorf("state = %q, want killed", st.State)
	}
	if !strings.Contains(st.Error, "revoked") {
		t.Errorf("status error %q does not explain the revocation", st.Error)
	}
	if len(api.deleteRecords()) == 0 {
		t.Error("the Pod was not deleted after its credential was withdrawn")
	}
	src.waitOutstandingEmpty(t, 3*time.Second)
}

// TestReconcileOrphans is the garbage collector: Pods this executor owns but
// no longer tracks, which is every Pod created before a control-plane
// restart.
func TestReconcileOrphans(t *testing.T) {
	ex, api, src := newTestExecutor(t, func(o *Options) {
		o.OrphanGracePeriod = 10 * time.Minute
	})

	ourLabels := map[string]string{
		LabelManaged:    "true",
		LabelExecutorID: "k8s-test",
		LabelTaskID:     "7",
		LabelHandleID:   "k-old",
	}
	api.seedPod("orphan-terminal", ourLabels, phaseSucceeded, time.Minute)
	api.seedPod("orphan-running-old", ourLabels, phaseRunning, time.Hour)
	api.seedPod("orphan-running-young", ourLabels, phaseRunning, time.Second)

	// Not ours: a different executor's Pod, and one with no task label at
	// all (which is how a hand-made Pod looks).
	api.seedPod("other-executor", map[string]string{
		LabelManaged: "true", LabelExecutorID: "other", LabelTaskID: "1",
	}, phaseRunning, time.Hour)
	api.seedPod("no-task-label", map[string]string{
		LabelManaged: "true", LabelExecutorID: "k8s-test",
	}, phaseRunning, time.Hour)

	// A live handle of ours must survive even though it is young.
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	livePod := ""
	for _, n := range api.podNames() {
		if strings.HasPrefix(n, "cloop-") {
			livePod = n
		}
	}
	if livePod == "" {
		t.Fatal("the live Pod was not created")
	}

	removed, err := ex.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}

	gotRemoved := map[string]bool{}
	for _, n := range removed {
		gotRemoved[strings.TrimPrefix(n, "cloop/")] = true
	}
	for _, want := range []string{"orphan-terminal", "orphan-running-old"} {
		if !gotRemoved[want] {
			t.Errorf("orphan %q was not collected (removed: %v)", want, removed)
		}
	}
	for _, mustSurvive := range []string{
		"orphan-running-young", // inside the grace period
		"other-executor",       // another executor's
		"no-task-label",        // not created by this driver
		livePod,                // a live handle of ours
	} {
		if gotRemoved[mustSurvive] {
			t.Errorf("Pod %q was collected but must not have been", mustSurvive)
		}
	}

	// Reconciliation must not leak the lease it took to do the sweep.
	api.run(livePod)
	api.terminate(livePod, 0, "Completed")
	waitStatus(t, ex, handle.ID, 5*time.Second)
	src.waitOutstandingEmpty(t, 3*time.Second)
}

func TestReconcileOrphans_SurfacesAPIFailure(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)
	api.failAlways("GET /pods", apiFailure{
		Code: 403, Reason: "Forbidden", Message: "cannot list pods",
	})

	_, err := ex.ReconcileOrphans(context.Background())
	if err == nil {
		t.Fatal("ReconcileOrphans reported success against an API server that refused the list")
	}
	if !strings.Contains(err.Error(), "list pods for reconciliation") {
		t.Errorf("error %q does not say what failed", err)
	}
	if out := src.outstanding(); len(out) != 0 {
		t.Errorf("a failed sweep leaked leases: %v", out)
	}
}

func TestHealthCheck(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)

	if err := ex.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck against a healthy fake: %v", err)
	}
	if out := src.outstanding(); len(out) != 0 {
		t.Errorf("HealthCheck leaked leases: %v", out)
	}

	api.setUnauthorized(true)
	err := ex.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("HealthCheck succeeded against an API server rejecting the credential")
	}
	if !strings.Contains(err.Error(), "cannot reach") {
		t.Errorf("error %q does not say the cluster is unreachable", err)
	}
	if out := src.outstanding(); len(out) != 0 {
		t.Errorf("a failed HealthCheck leaked leases: %v", out)
	}
}

func TestHealthCheck_FailsWhenCredentialsAreGone(t *testing.T) {
	ex, _, src := newTestExecutor(t, nil)
	src.setAcquireErr(ErrNoKubeconfigGrant)

	if err := ex.HealthCheck(context.Background()); !errors.Is(err, ErrNoKubeconfigGrant) {
		t.Errorf("HealthCheck = %v, want ErrNoKubeconfigGrant", err)
	}
}

func TestCapabilities(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)
	caps := ex.Capabilities()

	if caps.Isolation == executor.IsolationNone {
		t.Error("a Kubernetes executor must not report IsolationNone; strict no-host-execution mode would refuse it")
	}
	if caps.SharesHostFilesystem {
		t.Error("SharesHostFilesystem must be false: there is no bind mount, so Spec.WorkDir is a path inside the Pod")
	}
	if !caps.SupportsStream || !caps.SupportsSignal || !caps.SupportsResourceLimits {
		t.Errorf("capabilities understate the driver: %+v", caps)
	}
	if !caps.NetworkEgress {
		t.Error("NetworkEgress must be true: cloop does not enforce a NetworkPolicy, and claiming " +
			"an isolation it does not provide is the failure mode that matters")
	}
	if ex.Kind() != executor.KindKubernetes {
		t.Errorf("Kind = %q, want %q", ex.Kind(), executor.KindKubernetes)
	}
}

// TestLister reports live handles through the optional executor.Lister
// interface, which the Executors panel reads for its load column.
func TestLister(t *testing.T) {
	ex, api, _ := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.run(name)

	live, ok := executor.LiveHandles(context.Background(), ex)
	if !ok {
		t.Fatal("the driver does not implement executor.Lister")
	}
	if len(live) != 1 || live[0].HandleID != handle.ID {
		t.Errorf("LiveHandles = %+v, want the one running handle", live)
	}

	api.terminate(name, 0, "Completed")
	waitStatus(t, ex, handle.ID, 5*time.Second)
	live, _ = executor.LiveHandles(context.Background(), ex)
	if len(live) != 0 {
		t.Errorf("LiveHandles after completion = %+v, want none", live)
	}
}

func TestMaxConcurrent(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.MaxConcurrent = 1 })

	if _, err := ex.Start(context.Background(), testSpec()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	_, err := ex.Start(context.Background(), testSpec())
	if err == nil {
		t.Fatal("second Start succeeded despite max_concurrent=1")
	}
	if !strings.Contains(err.Error(), "max_concurrent") {
		t.Errorf("error %q does not name the limit that refused it", err)
	}
	// Exactly one Pod: the refused Start must not have created one.
	if names := api.podNames(); len(names) != 1 {
		t.Errorf("pods = %v, want exactly the one that was admitted", names)
	}
}

func TestStreamAndStatus_UnknownHandle(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)
	if _, err := ex.Stream(context.Background(), "nope"); !errors.Is(err, executor.ErrHandleNotFound) {
		t.Errorf("Stream = %v, want ErrHandleNotFound", err)
	}
	if _, err := ex.Status(context.Background(), "nope"); !errors.Is(err, executor.ErrHandleNotFound) {
		t.Errorf("Status = %v, want ErrHandleNotFound", err)
	}
}

// TestKeepCompletedPods leaves a finished Pod in place for debugging.
func TestKeepCompletedPods(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.KeepCompletedPods = true })
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.run(name)
	api.terminate(name, 0, "Completed")
	waitStatus(t, ex, handle.ID, 5*time.Second)

	if len(api.deleteRecords()) != 0 {
		t.Error("keep_completed_pods is on, but the driver deleted the Pod anyway")
	}
	if got := api.podNames(); len(got) != 1 {
		t.Errorf("pods = %v, want the completed one retained", got)
	}
}

func TestClose_ReleasesEverything(t *testing.T) {
	ex, api, src := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	api.run(api.onlyPodName(t))

	ex.Close()

	st, err := ex.Status(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Status after Close: %v", err)
	}
	if st.State != executor.StateUnknown {
		t.Errorf("state after Close = %q, want unknown — the Pod may still be running", st.State)
	}
	// Close must not destroy work in flight: a control plane restarting for
	// an upgrade should leave running Pods alone.
	if len(api.deleteRecords()) != 0 {
		t.Errorf("Close deleted running Pods: %v", api.deleteRecords())
	}
	src.waitOutstandingEmpty(t, 3*time.Second)

	if _, err := ex.Start(context.Background(), testSpec()); err == nil {
		t.Error("Start succeeded on a closed executor")
	}
}

func TestNamespaceResolution(t *testing.T) {
	// Configured namespace wins over anything a credential carries: it is
	// the value an operator can actually see in their config file.
	ex, _, _ := newTestExecutor(t, func(o *Options) { o.Namespace = "explicit" })
	if got := ex.namespaceFor(&Credentials{Namespace: "from-grant"}); got != "explicit" {
		t.Errorf("namespaceFor = %q, want the configured value", got)
	}

	unset, _, _ := newTestExecutor(t, func(o *Options) { o.Namespace = "" })
	if got := unset.namespaceFor(&Credentials{Namespace: "from-grant"}); got != "from-grant" {
		t.Errorf("namespaceFor = %q, want the grant's namespace", got)
	}
	if got := unset.namespaceFor(&Credentials{Rest: &RESTConfig{Namespace: "from-kubeconfig"}}); got != "from-kubeconfig" {
		t.Errorf("namespaceFor = %q, want the kubeconfig's namespace", got)
	}
	if got := unset.namespaceFor(nil); got != DefaultNamespace {
		t.Errorf("namespaceFor(nil) = %q, want %q", got, DefaultNamespace)
	}
}

func TestPodWorkDir(t *testing.T) {
	cases := map[string]string{
		// A control-plane path has no meaning inside a Pod, so it becomes
		// the workspace rather than failing the run.
		"/srv/app":              PodWorkspace,
		"":                      PodWorkspace,
		PodWorkspace:            PodWorkspace,
		PodWorkspace + "/sub":   PodWorkspace + "/sub",
		"/workspace-not-really": PodWorkspace,
	}
	for in, want := range cases {
		if got := podWorkDir(in); got != want {
			t.Errorf("podWorkDir(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOptionsNormalize(t *testing.T) {
	src := newFakeSource(&RESTConfig{Server: "https://example:6443"})
	ok := map[string]Options{
		"minimal":     {Credentials: src},
		"namespace":   {Namespace: "cloop-jobs", Credentials: src},
		"quantities":  {CPULimit: "2", MemoryLimit: "4Gi", CPURequest: "500m", Credentials: src},
		"pull policy": {ImagePullPolicy: "IfNotPresent", Credentials: src},
		"tolerations": {Tolerations: []Toleration{{Key: "k", Operator: "Exists"}}, Credentials: src},
	}
	for name, o := range ok {
		t.Run(name, func(t *testing.T) {
			if _, err := o.Normalize(); err != nil {
				t.Fatalf("Normalize(%+v) = %v, want nil", o, err)
			}
		})
	}

	bad := map[string]struct {
		o    Options
		want string
	}{
		"reserved namespace": {Options{Namespace: "kube-system"}, "reserved"},
		"bad namespace":      {Options{Namespace: "Not A Namespace"}, "RFC 1123"},
		"bad pull policy":    {Options{ImagePullPolicy: "sometimes"}, "image_pull_policy"},
		"bad quantity":       {Options{MemoryLimit: "4 gigs"}, "memory_limit"},
		"zero quantity":      {Options{CPULimit: "0"}, "greater than zero"},
		"bad image":          {Options{Image: "-rm"}, "must not begin with '-'"},
		"bad toleration":     {Options{Tolerations: []Toleration{{Operator: "Matches"}}}, "tolerations[0]"},
		"negative deadline":  {Options{ActiveDeadlineSeconds: -1}, "active_deadline_seconds"},
		"negative uid":       {Options{RunAsUser: -1}, "run_as_user"},
		"negative parallel":  {Options{MaxConcurrent: -1}, "max_concurrent"},
		"bad pull secret":    {Options{ImagePullSecrets: []string{"Bad Name"}}, "image_pull_secrets"},
	}
	for name, tc := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := tc.o.Normalize()
			if err == nil {
				t.Fatalf("Normalize(%+v) = nil, want an error", tc.o)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	// Defaults must be the confining ones.
	norm, err := Options{Credentials: src}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if norm.ID != DefaultID || norm.Image != DefaultImage {
		t.Errorf("defaults = %s/%s", norm.ID, norm.Image)
	}
	if norm.TerminationGracePeriod != DefaultTerminationGracePeriod ||
		norm.KillGracePeriod != DefaultKillGracePeriod ||
		norm.OrphanGracePeriod != DefaultOrphanGracePeriod {
		t.Errorf("grace periods not defaulted: %+v", norm)
	}
	if norm.ActiveDeadlineSeconds != 0 {
		t.Errorf("activeDeadlineSeconds defaulted to %d; cloop runs are long-lived by design (Task 20148)",
			norm.ActiveDeadlineSeconds)
	}
}

// TestSpecTimeoutBecomesActiveDeadline: server-side enforcement survives a
// control-plane restart, where a client-side timer would not.
func TestSpecTimeoutBecomesActiveDeadline(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)
	spec := testSpec()
	spec.TimeoutMinutes = 5

	p, err := ex.buildPodFor(context.Background(), spec, "k-test", "cloop")
	if err != nil {
		t.Fatalf("buildPodFor: %v", err)
	}
	if p.Spec.ActiveDeadlineSeconds == nil || *p.Spec.ActiveDeadlineSeconds != 300 {
		t.Errorf("activeDeadlineSeconds = %v, want 300", p.Spec.ActiveDeadlineSeconds)
	}
}

// TestSpecLimitsOverrideExecutorDefaults matches the container driver's
// precedence: the per-run request is more specific than the per-executor
// policy.
func TestSpecLimitsOverrideExecutorDefaults(t *testing.T) {
	ex, _, _ := newTestExecutor(t, func(o *Options) {
		o.CPULimit = "1"
		o.MemoryLimit = "1Gi"
	})
	spec := testSpec()
	spec.ResourceLimits = executor.ResourceLimits{CPUMillis: 2500, MemoryMB: 4096, DiskMB: 8192}

	p, err := ex.buildPodFor(context.Background(), spec, "k-test", "cloop")
	if err != nil {
		t.Fatalf("buildPodFor: %v", err)
	}
	limits := p.Spec.Containers[0].Resources.Limits
	if limits["cpu"] != "2500m" {
		t.Errorf("cpu limit = %q, want the Spec's 2500m", limits["cpu"])
	}
	if limits["memory"] != "4096Mi" {
		t.Errorf("memory limit = %q, want the Spec's 4096Mi", limits["memory"])
	}
	if limits["ephemeral-storage"] != "8192Mi" {
		t.Errorf("ephemeral-storage limit = %q", limits["ephemeral-storage"])
	}
}
