package kubernetes

// workspace_adopt_test.go: a Pod's workspace credential outlives the hub
// process that minted it (Task 20455) — the driver's half. The driver says
// which credential a Pod may still present, records on the handle row which
// containers read the workspace Secret, never ends the credential when it
// walks away from a live Pod, and runs the release a hub process hands it for
// an adopted Pod where its dispatcher would have run its own. pkg/ui
// TestAPodsWorkspaceSessionSurvivesARestart is the hub's half, and tests/kube
// TestAPodsWorkspaceSurvivesItsHubBeingKilled runs both on a cluster.

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// sessionSource hands out a git proxy session as the workspace credential, as
// gitproxycreds does: its username is the session's id.
func sessionSource() *fakeWorkspaceSource {
	src := workingSource()
	src.cred.Username = "gps_session-1"
	src.cred.SessionID = "gps_session-1"
	return src
}

var heldSession = executor.HeldWorkspaceCredential{LeaseID: "ws-lease-1", GrantID: "grant-1", SessionID: "gps_session-1"}

// pushSpec is a run whose harness pushes its work back with the workspace
// credential once the work is done.
func pushSpec() executor.Spec {
	spec := testSpec()
	spec.Workspace = gitWorkspace()
	spec.Workspace.Ref = strings.Repeat("c", 40)
	spec.WriteBack = executor.WriteBack{Mode: executor.WriteBackPush, Branch: "cloop/task-42"}
	return spec
}

func fetchSpec() executor.Spec {
	spec := testSpec()
	spec.Workspace = gitWorkspace()
	return spec
}

func storedMeta(t *testing.T, store executor.HandleStore, handleID string) map[string]string {
	t.Helper()
	for _, row := range executor.LoadHandles(store, "k8s-test") {
		if row.HandleID == handleID {
			return row.Meta
		}
	}
	t.Fatalf("no handle row for %s", handleID)
	return nil
}

// TestHeldWorkspaceCredential_NamesTheSessionUntilTheFetchIsConfirmed: from
// Start until the init container's fetch is seen to end, the driver names the
// lease and the session the Pod may present — which the hub writes into the
// run's owner row — and then ends the credential and stops naming it.
func TestHeldWorkspaceCredential_NamesTheSessionUntilTheFetchIsConfirmed(t *testing.T) {
	wsSrc := sessionSource()
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = wsSrc })
	handle, err := ex.Start(context.Background(), fetchSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if held, ok := ex.HeldWorkspaceCredential(handle.ID); !ok || held != heldSession {
		t.Fatalf("held after Start = %+v (%v), want %+v", held, ok, heldSession)
	}
	podName := api.onlyPodName(t)
	api.kubeletCreate(t, podName, InitContainerName)
	if _, ok := ex.HeldWorkspaceCredential(handle.ID); !ok {
		t.Fatal("the credential is no longer named while the provisioner is fetching")
	}
	api.finishInitContainer(podName, 0, "Completed")
	waitFor(t, 3*time.Second, func() bool { _, released := wsSrc.counts(); return released == 1 })
	if held, ok := ex.HeldWorkspaceCredential(handle.ID); ok {
		t.Fatalf("the credential is still named after the fetch ended: %+v", held)
	}
	if _, ok := ex.HeldWorkspaceCredential("no-such-handle"); ok {
		t.Fatal("an unknown handle names a credential")
	}
}

// TestHeldWorkspaceCredential_APushWriteBackKeepsItUntilTheWorkloadEnds: the
// harness presents the credential again for its push, so the fetch ending
// changes nothing; the workload ending does.
func TestHeldWorkspaceCredential_APushWriteBackKeepsItUntilTheWorkloadEnds(t *testing.T) {
	wsSrc := sessionSource()
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = wsSrc })
	handle, err := ex.Start(context.Background(), pushSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	api.kubeletCreate(t, podName, InitContainerName)
	api.finishInitContainer(podName, 0, "Completed")
	waitRecord(t, ex, handle.ID, "the provisioner finish", func(r *record) bool { return r.initStarted })
	time.Sleep(50 * time.Millisecond)
	if _, released := wsSrc.counts(); released != 0 {
		t.Fatal("the credential a push write-back presents was ended when the fetch did")
	}
	if held, ok := ex.HeldWorkspaceCredential(handle.ID); !ok || held != heldSession {
		t.Fatalf("held after the fetch = %+v (%v), want %+v", held, ok, heldSession)
	}
	api.run(podName)
	api.terminate(podName, 0, "Completed")
	waitStatus(t, ex, handle.ID, 5*time.Second)
	waitFor(t, 3*time.Second, func() bool { _, released := wsSrc.counts(); return released == 1 })
}

// TestWorkspaceMeta_TheRowSaysWhoReadsTheSecret: the handle row records which
// containers read the workspace Secret, and a run that leased no credential
// records nothing.
func TestWorkspaceMeta_TheRowSaysWhoReadsTheSecret(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec executor.Spec
		src  *fakeWorkspaceSource
		want string
	}{
		{"fetch", fetchSpec(), sessionSource(), workspaceSecretFetch},
		{"push write-back", pushSpec(), sessionSource(), workspaceSecretPush},
		{"public repository", fetchSpec(), &fakeWorkspaceSource{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := executor.NewMemoryHandleStore()
			ex, _, _ := newTestExecutor(t, func(o *Options) { o.Workspace = tc.src; o.HandleStore = store })
			handle, err := ex.Start(context.Background(), tc.spec)
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			meta := storedMeta(t, store, handle.ID)
			if got := meta[metaWorkspaceSecret]; got != tc.want {
				t.Fatalf("%s = %q, want %q (meta %v)", metaWorkspaceSecret, got, tc.want, meta)
			}
			for k, v := range meta {
				if strings.Contains(v, fakeWorkspaceToken) {
					t.Fatalf("the row's %s carries the credential", k)
				}
			}
		})
	}
}

// TestClose_LeavesTheCredentialOfAFetchInProgress: a hub that stops following
// a Pod whose provisioner is fetching drops the Secret — its reader has it —
// but must not end the credential the fetch is presenting: the process that
// adopts the run takes it over.
func TestClose_LeavesTheCredentialOfAFetchInProgress(t *testing.T) {
	wsSrc := sessionSource()
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = wsSrc })
	handle, err := ex.Start(context.Background(), fetchSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	api.kubeletCreate(t, podName, InitContainerName)
	waitRecord(t, ex, handle.ID, "the provisioner start", func(r *record) bool { return r.initStarted })

	ex.Close()
	if _, released := wsSrc.counts(); released != 0 {
		t.Fatal("Close ended the credential a fetch in progress presents")
	}
	if !containsString(api.secretDeleteNames(), workspaceSecretName(handle.ID)) {
		t.Errorf("Close left %s although its only reader had started (deletes: %v)",
			workspaceSecretName(handle.ID), api.secretDeleteNames())
	}
}

// TestClose_LeavesAWriteBackCredentialWhoseHarnessStarted: the harness pushes
// with the credential when it finishes, after this process is gone.
func TestClose_LeavesAWriteBackCredentialWhoseHarnessStarted(t *testing.T) {
	wsSrc := sessionSource()
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = wsSrc })
	handle, err := ex.Start(context.Background(), pushSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	api.kubeletCreate(t, podName, InitContainerName)
	api.finishInitContainer(podName, 0, "Completed")
	api.kubeletCreate(t, podName, ContainerName)
	waitRecord(t, ex, handle.ID, "the harness start", func(r *record) bool { return r.harnessStarted })

	ex.Close()
	if _, released := wsSrc.counts(); released != 0 {
		t.Fatal("Close ended the credential the harness's write-back presents")
	}
	if !containsString(api.secretDeleteNames(), workspaceSecretName(handle.ID)) {
		t.Errorf("Close left %s although both its readers had started", workspaceSecretName(handle.ID))
	}
}

// adoptAfterClose starts spec, stops the first driver before anything in the
// Pod has started, and brings up a second one on the same store: the hub
// restarting while the Pod waits for the kubelet.
func adoptAfterClose(t *testing.T, spec executor.Spec) (*Executor, *fakeAPI, string, string, *fakeWorkspaceSource) {
	t.Helper()
	store := executor.NewMemoryHandleStore()
	wsSrc := sessionSource()
	ex1, api, src := newTestExecutor(t, func(o *Options) { o.Workspace = wsSrc; o.HandleStore = store })
	handle, err := ex1.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	ex1.Close()
	if _, released := wsSrc.counts(); released != 0 {
		t.Fatal("Close ended the credential of a Pod that has not fetched yet")
	}
	ex2 := newRestartedExecutor(t, api, src, store)
	waitFor(t, 3*time.Second, func() bool { _, err := ex2.lookup(handle.ID); return err == nil })
	return ex2, api, handle.ID, podName, wsSrc
}

// TestAdoptedPod_EndsTheTakenOverCredentialWhenTheFetchEnds: the hub process
// that adopted the Pod hands the driver the release of the lease it took
// over; the adopted record names it while the Pod may present it, runs it once
// the fetch ends — not before, and not again when the workload ends — and
// drops the Secret as the dispatcher would have.
func TestAdoptedPod_EndsTheTakenOverCredentialWhenTheFetchEnds(t *testing.T) {
	ex, api, handleID, podName, _ := adoptAfterClose(t, fetchSpec())
	var ended atomic.Int32
	if !ex.AdoptWorkspaceCredential(handleID, heldSession, func() { ended.Add(1) }) {
		t.Fatal("the adopted record refused the workspace credential")
	}
	if held, ok := ex.HeldWorkspaceCredential(handleID); !ok || held != heldSession {
		t.Fatalf("the adopted record names %+v (%v), want %+v", held, ok, heldSession)
	}
	api.kubeletCreate(t, podName, InitContainerName)
	time.Sleep(50 * time.Millisecond)
	if ended.Load() != 0 {
		t.Fatal("the credential was ended while the provisioner was fetching")
	}
	api.finishInitContainer(podName, 0, "Completed")
	waitFor(t, 3*time.Second, func() bool { return ended.Load() == 1 })
	waitFor(t, 3*time.Second, func() bool {
		return containsString(api.secretDeleteNames(), workspaceSecretName(handleID))
	})
	if _, ok := ex.HeldWorkspaceCredential(handleID); ok {
		t.Fatal("the adopted record still names the credential after the fetch ended")
	}
	api.run(podName)
	api.terminate(podName, 0, "Completed")
	waitStatus(t, ex, handleID, 5*time.Second)
	if got := ended.Load(); got != 1 {
		t.Fatalf("the credential was ended %d times, want once", got)
	}
}

// TestAdoptedPod_APushWriteBackEndsItWithTheWorkload: the adopted record of a
// push write-back keeps the credential past the fetch, for the harness's push.
func TestAdoptedPod_APushWriteBackEndsItWithTheWorkload(t *testing.T) {
	ex, api, handleID, podName, _ := adoptAfterClose(t, pushSpec())
	var ended atomic.Int32
	if !ex.AdoptWorkspaceCredential(handleID, heldSession, func() { ended.Add(1) }) {
		t.Fatal("the adopted record refused the workspace credential")
	}
	api.kubeletCreate(t, podName, InitContainerName)
	api.finishInitContainer(podName, 0, "Completed")
	waitRecord(t, ex, handleID, "the provisioner finish", func(r *record) bool { return r.initStarted })
	time.Sleep(50 * time.Millisecond)
	if ended.Load() != 0 {
		t.Fatal("the credential a push write-back presents was ended when the fetch did")
	}
	if containsString(api.secretDeleteNames(), workspaceSecretName(handleID)) {
		t.Fatal("the adopted record dropped the Secret the write-back harness reads")
	}
	api.run(podName)
	api.terminate(podName, 0, "Completed")
	waitStatus(t, ex, handleID, 5*time.Second)
	waitFor(t, 3*time.Second, func() bool { return ended.Load() == 1 })
}

// TestAdoptWorkspaceCredential_AfterTheFetchEndedEndsItAtOnce: the takeover
// waits on the store, and the adopted record can see the fetch end first —
// the credential is then ended as soon as it is handed over.
func TestAdoptWorkspaceCredential_AfterTheFetchEndedEndsItAtOnce(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "succeeded"
		if failed {
			name = "failed"
		}
		t.Run(name, func(t *testing.T) {
			ex, api, handleID, podName, _ := adoptAfterClose(t, fetchSpec())
			api.kubeletCreate(t, podName, InitContainerName)
			code := 0
			if failed {
				code = 128
			}
			api.finishInitContainer(podName, code, "Completed")
			waitFor(t, 3*time.Second, func() bool {
				return containsString(api.secretDeleteNames(), workspaceSecretName(handleID))
			})
			var ended atomic.Int32
			if !ex.AdoptWorkspaceCredential(handleID, heldSession, func() { ended.Add(1) }) {
				t.Fatal("the adopted record refused the workspace credential")
			}
			if ended.Load() != 1 {
				t.Fatalf("the credential of a fetch that already ended was ended %d times, want once at once", ended.Load())
			}
		})
	}
}

// TestAdoptWorkspaceCredential_RefusesWhatItDoesNotHold: a handle it does not
// know, one it dispatched itself, and an adopted one whose row records no
// workspace Secret are refused, so the hub ends the credential with the
// workload instead.
func TestAdoptWorkspaceCredential_RefusesWhatItDoesNotHold(t *testing.T) {
	ex, _, _ := newTestExecutor(t, func(o *Options) { o.Workspace = sessionSource() })
	handle, err := ex.Start(context.Background(), fetchSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	for _, id := range []string{"no-such-handle", handle.ID} {
		if ex.AdoptWorkspaceCredential(id, heldSession, func() { t.Errorf("%s ran the release", id) }) {
			t.Errorf("AdoptWorkspaceCredential(%s) = true", id)
		}
	}

	store := executor.NewMemoryHandleStore()
	ex1, api1, src := newTestExecutor(t, func(o *Options) { o.Workspace = &fakeWorkspaceSource{}; o.HandleStore = store })
	public, err := ex1.Start(context.Background(), fetchSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	ex1.Close()
	ex2 := newRestartedExecutor(t, api1, src, store)
	waitFor(t, 3*time.Second, func() bool { _, err := ex2.lookup(public.ID); return err == nil })
	if ex2.AdoptWorkspaceCredential(public.ID, heldSession, func() { t.Error("ran the release") }) {
		t.Error("an adopted Pod whose row records no workspace Secret took a workspace credential")
	}
}
