package kubernetes

// revoke_test.go covers taking a secret lease back from a Pod that is already
// running: the Secrets that stop existing, the Pod that has to go with them,
// and the bookkeeping that decides which runs a revocation reaches.
//
// Every assertion is against what the fake API server was actually asked to
// delete, never against the driver's own view of what it did. The two
// disagreeing is the entire failure mode this path exists to remove — a hub
// that reports a GitHub PAT as revoked while the Secret holding it is still
// readable by anyone with `get secrets` in the namespace. A test that trusted
// the driver's self-report could not tell those apart.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// revokedLeaseID is the broker lease under test. It deliberately does not look
// like the "lease-N" IDs fakeSource mints for the driver's own kubeconfig: a
// revocation that conflated the two would delete the client it needs to carry
// the revocation out.
const revokedLeaseID = "lease-github-ci"

// leasedSpec is a run whose credential files came from a broker lease, carrying
// the attribution a revocation needs to find the Pod again.
//
// Both halves are present because the hub sends both and they serve different
// lifetimes: SecretFiles carries the bytes and is dropped the moment the Secret
// is created, while Secrets carries only names and paths and is what the driver
// retains for as long as the Pod can use the material.
func leasedSpec() executor.Spec {
	spec := secretFileSpec()
	for i := range spec.SecretFiles {
		spec.SecretFiles[i].LeaseID = revokedLeaseID
	}
	spec.Secrets = []executor.SecretBinding{{
		LeaseID:    revokedLeaseID,
		GrantID:    "grant-1",
		SecretName: "github-ci",
		Kind:       "github_pat",
		Dir:        leaseDir,
		Files:      []string{leaseDir + "/gitconfig", leaseDir + "/github-token"},
		EnvKeys:    []string{"GIT_CONFIG_GLOBAL"},
	}}
	return spec
}

// startLeasedPod starts a leased workload and brings its Pod to Running, which
// is the only state where a revocation has anything left to take back: before
// it the material is still in etcd alone, and after it the run's own cleanup
// has already removed it.
func startLeasedPod(t *testing.T) (*Executor, *fakeAPI, executor.Handle, string) {
	t.Helper()
	ex, api, _ := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), leasedSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	api.run(podName)
	return ex, api, handle, podName
}

// waitLeaseReleased polls until the executor stops claiming the lease, since
// finish() releases it on the watcher goroutine a moment after the status turns
// terminal.
func waitLeaseReleased(t *testing.T, ex *Executor, leaseID string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !ex.HoldsLease(leaseID) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("lease %s is still held %s after the run finished (holding %v)", leaseID, d, ex.Leases())
}

// TestRevokeLease_DeletesTheLeasedSecrets is the durable half of the promise:
// once the call returns, the material the lease delivered is no longer an object
// in the cluster.
//
// It matters beyond the running Pod. A Secret is what survives the hub — nothing
// renews or expires it once this process is gone — so a revocation that stopped
// at the driver's own bookkeeping would leave a credential in etcd with no owner
// and no TTL, recoverable by anyone who can read the namespace long after the
// run it belonged to is forgotten.
func TestRevokeLease_DeletesTheLeasedSecrets(t *testing.T) {
	ex, api, handle, _ := startLeasedPod(t)

	out := ex.RevokeLease(context.Background(), executor.RevokeRequest{
		LeaseID: revokedLeaseID,
		Reason:  "the PAT turned up in a public gist",
	})

	if out.State != executor.RevokeStateRevoked {
		t.Fatalf("state = %q (%s), want %q", out.State, out.Error, executor.RevokeStateRevoked)
	}
	if out.Ack == nil {
		t.Fatal("no report: the caller cannot distinguish material that was destroyed from material " +
			"the driver merely stopped tracking")
	}
	if !out.Ack.Known {
		t.Error("Known is false for a lease this executor started a Pod with; an operator chasing a " +
			"leaked credential would read that as 'it was never here' and look somewhere else")
	}
	if out.Ack.FilesRemoved == 0 {
		t.Error("FilesRemoved is 0, which reports a scrub that did not happen")
	}

	// Both names, not just the one this particular run created. Each is a pure
	// function of the handle ID, so covering the pair costs one extra call and
	// removes the need to know which credential shapes a run was given — which
	// a record adopted after a hub restart no longer remembers.
	deleted := api.secretDeleteNames()
	for _, want := range []string{secretFilesSecretName(handle.ID), workspaceSecretName(handle.ID)} {
		if !containsString(deleted, want) {
			t.Errorf("Secret %q was never deleted; the deletes were %v", want, deleted)
		}
	}
	if names := api.secretNames(); len(names) != 0 {
		t.Errorf("brokered material is still sitting in the cluster: %v", names)
	}

	// The outcome is also in the log the Secrets panel reads. An operator who
	// revoked a credential during an incident is asked afterwards when it
	// happened, and an answer that lives only in the caller's return value is no
	// answer at all.
	logged := ex.Revocations()
	if len(logged) != 1 || logged[0].LeaseID != revokedLeaseID {
		t.Fatalf("Revocations() = %+v, want the one lease that was revoked", logged)
	}
	if logged[0].State != executor.RevokeStateRevoked || logged[0].AckedAt.IsZero() {
		t.Errorf("logged outcome = %+v, want a settled entry with an acknowledgement time", logged[0])
	}
}

// TestRevokeLease_EvictsThePodBecauseTheMaterialIsAlreadyInside proves the
// escalation, which is the part of this backend's revocation that is easy to
// get wrong by being too polite.
//
// Deleting the Secret is necessary and not sufficient. The kubelet serves a
// projected secret volume from the copy it last synchronised and does not blank
// that tmpfs when the source object disappears, so a container that has the
// volume mounted keeps reading the credential out of a deleted Secret. Worse, a
// value delivered through secretKeyRef was copied into the container's
// environment at start, and no API server can reach into another process's
// memory to take it out again. Removing the workload is therefore the only
// operation on this backend that actually withdraws material already inside a
// container — so the Pod goes, and the kill is reported rather than dressed up
// as a scrub.
func TestRevokeLease_EvictsThePodBecauseTheMaterialIsAlreadyInside(t *testing.T) {
	ex, api, handle, podName := startLeasedPod(t)

	out := ex.RevokeLease(context.Background(), executor.RevokeRequest{
		LeaseID: revokedLeaseID,
		Reason:  "the grant was wider than the task needed",
	})
	if out.Ack == nil {
		t.Fatalf("no report: %+v", out)
	}
	if !containsString(out.Ack.Killed, handle.ID) {
		t.Errorf("Killed = %v, want the handle %s; a revocation that reports success without naming "+
			"the eviction it required overstates what the operator got", out.Ack.Killed, handle.ID)
	}

	var evicted bool
	for _, rec := range api.deleteRecords() {
		if rec.Name == podName {
			evicted = true
		}
	}
	if !evicted {
		t.Fatalf("Pod %s was never deleted (deletes: %v); the container still holds the projected "+
			"credential the revocation claimed to take back", podName, api.deleteRecords())
	}

	// And the run's own transcript says why it died. "Stopped by a request" —
	// what the operator's Stop button records — would leave whoever reads the
	// task afterwards unable to connect the death to the revocation.
	st := waitStatus(t, ex, handle.ID, 5*time.Second)
	if st.State != executor.StateKilled {
		t.Errorf("state = %q (%s), want killed", st.State, st.Error)
	}
	if !strings.Contains(st.Error, "revoked") {
		t.Errorf("status error %q does not say a revoked credential was the cause", st.Error)
	}
}

// TestRevokeLease_LeaseThisExecutorNeverHadIsNotAFailure. "The material is not
// here" is precisely the end state a revocation asks for, so answering a lease
// this driver never saw with a failure would paint a permanent red entry in the
// Secrets panel and keep the hub retrying a revocation that has already
// succeeded. Known carries the real distinction — "deleted it" versus "there was
// nothing to delete" — which is the question an incident actually turns on.
//
// The executor is holding a different lease throughout, so this proves the index
// discriminates rather than proving an empty executor deletes nothing.
func TestRevokeLease_LeaseThisExecutorNeverHadIsNotAFailure(t *testing.T) {
	ex, api, _, _ := startLeasedPod(t)

	out := ex.RevokeLease(context.Background(), executor.RevokeRequest{
		LeaseID: "lease-belonging-to-another-executor",
		Reason:  "swept on reconnect",
	})

	if out.State != executor.RevokeStateRevoked {
		t.Errorf("state = %q (%s), want %q — not holding it is a success", out.State, out.Error,
			executor.RevokeStateRevoked)
	}
	if out.Ack == nil {
		t.Fatalf("no report: %+v", out)
	}
	if out.Ack.Known {
		t.Error("Known is true for a lease this executor never held, which claims a deletion that " +
			"never happened and points an investigation at the wrong host")
	}
	if got := api.secretDeleteNames(); len(got) != 0 {
		t.Errorf("deleted Secrets %v for a lease it does not hold; the revocation reached into a run "+
			"the operator did not revoke", got)
	}
	if got := api.deleteRecords(); len(got) != 0 {
		t.Errorf("deleted Pods %v for a lease it does not hold", got)
	}
}

// TestHoldsLease_TracksTheBindingForAsLongAsThePodCanUseIt guards the index that
// decides what a revocation can reach. A Pod missing from it is a Pod every
// revocation silently skips — the credential stays live and the outcome still
// says "revoked", which is the worst shape a security failure can take.
//
// The release half fails in the opposite direction and is just as load-bearing:
// a finished handle left bound makes the panel show a dead Pod as a live holder
// and sends every later revocation chasing a workload that no longer exists.
func TestHoldsLease_TracksTheBindingForAsLongAsThePodCanUseIt(t *testing.T) {
	ex, api, handle, podName := startLeasedPod(t)

	if !ex.HoldsLease(revokedLeaseID) {
		t.Errorf("HoldsLease(%s) is false while the Pod is running; a revocation would find nothing "+
			"to do and report success", revokedLeaseID)
	}
	if got := ex.Leases(); len(got) != 1 || got[0] != revokedLeaseID {
		t.Errorf("Leases() = %v, want exactly [%s]", got, revokedLeaseID)
	}

	api.terminate(podName, 0, "Completed")
	if st := waitStatus(t, ex, handle.ID, 5*time.Second); st.State != executor.StateExited {
		t.Fatalf("state = %q (%s), want exited", st.State, st.Error)
	}

	waitLeaseReleased(t, ex, revokedLeaseID, 3*time.Second)
	if got := ex.Leases(); len(got) != 0 {
		t.Errorf("Leases() = %v once the run finished, want empty", got)
	}
}

// TestRevokeLease_BlankLeaseIDIsRefused. Failure is not a terminal revocation
// state and the log replays what is not terminal, so an entry keyed on an empty
// lease would be retried forever and could never settle. Refusing before the
// request is recorded keeps a malformed call from becoming a permanent item of
// work — and keeps the Secrets panel from showing an outstanding revocation
// against no credential.
func TestRevokeLease_BlankLeaseIDIsRefused(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)

	out := ex.RevokeLease(context.Background(), executor.RevokeRequest{
		LeaseID: "   ",
		Reason:  "a caller that lost the lease ID",
	})

	if out.State != executor.RevokeStateFailed {
		t.Errorf("state = %q, want %q", out.State, executor.RevokeStateFailed)
	}
	if out.Error == "" {
		t.Error("a failed revocation with no error leaves the caller nothing to act on")
	}
	if got := ex.Revocations(); len(got) != 0 {
		t.Errorf("the refused request was logged as %+v; being non-terminal it would be replayed "+
			"forever against a lease that does not exist", got)
	}
}
