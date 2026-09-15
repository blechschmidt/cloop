package kubernetes

// ownerref_test.go covers Task 20281: the per-run objects this driver creates
// must not outlive the hub that created them.
//
// The gap it closes is narrow and was documented rather than fixed for a long
// time. Both per-run Secrets hold live credential material and were deleted
// only by this process — so a hub killed between creating one and seeing the
// init container finish left it in the namespace forever, with nothing on
// either side able to notice. The sweep could not find it (that needs `list
// secrets`, which this driver deliberately does not hold) and the driver that
// created it was gone.
//
// An ownerReference inverts the responsibility: the Secret names its Pod, and
// the cluster's own collector reaps it when the Pod goes. The assertions below
// are therefore mostly about *ordering* and *shape*, because those are the two
// things that decide whether the real collector will do anything at all:
//
//   - the Pod must be created before the Secrets, or there is no UID to name;
//   - the reference must name the Pod's real UID, not its name;
//   - blockOwnerDeletion must stay false, or the API server starts demanding
//     `update` on pods/finalizers and the create fails on a correctly-scoped
//     Role.
//
// The cascade itself is exercised against the fake's collectGarbage, which is
// a model. TestOwnerReference_RealClusterGarbageCollection checks the same
// shape against a real API server when one is available, because a model of a
// garbage collector agreeing with the code that drives it proves less than it
// appears to.

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ownedSpec is a run that produces both per-run Secrets at once: a git
// workspace whose credential is leased, and a set of lease credential files.
// Testing them together is deliberate — they are created by two different
// functions and a fix applied to only one of them would pass every test that
// looked at either in isolation.
func ownedSpec() executor.Spec {
	spec := secretFileSpec()
	spec.Workspace = gitWorkspace()
	return spec
}

// startOwnedRun starts a run with both Secrets and returns the executor, the
// fake, the handle and the Pod's name.
func startOwnedRun(t *testing.T) (*Executor, *fakeAPI, executor.Handle, string) {
	t.Helper()
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = workingSource() })
	handle, err := ex.Start(context.Background(), ownedSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return ex, api, handle, api.onlyPodName(t)
}

// TestOwnerReference_BothSecretsNameTheOwningPod is the shape assertion.
//
// It reads the objects as the API server received them, not as the driver
// believes it sent them, because the whole mechanism is the server's to honour
// and a reference the server would reject is worth nothing.
func TestOwnerReference_BothSecretsNameTheOwningPod(t *testing.T) {
	_, api, handle, podName := startOwnedRun(t)

	api.mu.Lock()
	wantUID := api.pods[podName].Metadata.UID
	api.mu.Unlock()
	if wantUID == "" {
		t.Fatal("the fake created a Pod with no UID; the rest of this test would be vacuous")
	}

	for _, name := range []string{workspaceSecretName(handle.ID), secretFilesSecretName(handle.ID)} {
		sec := api.secretObject(name)
		if sec == nil {
			t.Fatalf("Secret %q was never created", name)
		}
		refs := sec.Metadata.OwnerReferences
		if len(refs) != 1 {
			t.Fatalf("Secret %q carries %d ownerReferences, want exactly 1: %+v", name, len(refs), refs)
		}
		ref := refs[0]
		if ref.UID != wantUID {
			t.Errorf("Secret %q owner UID = %q, want the Pod's %q — a reference naming anything "+
				"else is silently ignored by the collector", name, ref.UID, wantUID)
		}
		if ref.Name != podName {
			t.Errorf("Secret %q owner name = %q, want %q", name, ref.Name, podName)
		}
		if ref.Kind != "Pod" || ref.APIVersion != "v1" {
			t.Errorf("Secret %q owner = %s/%s, want v1/Pod", name, ref.APIVersion, ref.Kind)
		}
		// The RBAC-relevant one. blockOwnerDeletion=true makes the
		// OwnerReferencesPermissionEnforcement admission plugin require
		// `update` on pods/finalizers, which this driver's Role does not grant
		// and must not — so a regression here turns every Secret create into a
		// 403 on exactly the clusters that are locked down properly.
		if ref.BlockOwnerDeletion {
			t.Errorf("Secret %q sets blockOwnerDeletion; that needs update on pods/finalizers, "+
				"which this driver deliberately does not hold", name)
		}
		if ref.Controller {
			t.Errorf("Secret %q claims to be controller-managed; nothing here adopts objects", name)
		}
	}
}

// TestOwnerReference_PodIsCreatedBeforeItsSecrets locks the ordering that makes
// the reference possible at all.
//
// This inverts what the driver used to do, and the reversal is safe for one
// specific reason worth recording next to the assertion: the Pod is unscheduled
// when it is created, and the kubelet cannot resolve a secretKeyRef or mount a
// Secret volume before the scheduler has bound it — which is far slower than
// the two API calls that follow. Losing that race costs a kubelet retry, not a
// failed run, where the old ordering cost a permanently orphaned credential.
func TestOwnerReference_PodIsCreatedBeforeItsSecrets(t *testing.T) {
	_, api, _, _ := startOwnedRun(t)

	order := api.creates()
	podAt := -1
	for i, kind := range order {
		if kind == "pod" {
			podAt = i
			break
		}
	}
	if podAt < 0 {
		t.Fatalf("no Pod was created: %v", order)
	}
	secrets := 0
	for i, kind := range order {
		if kind != "secret" {
			continue
		}
		secrets++
		if i < podAt {
			t.Errorf("create order = %v; a Secret was created before the Pod it must name as owner", order)
		}
	}
	if secrets != 2 {
		t.Errorf("got %d Secret creates, want 2 (workspace + lease files): %v", secrets, order)
	}

	// The policy still comes first, and that has not changed. Its failure mode
	// is the opposite of a Secret's: a Pod that starts before its policy has a
	// window of unfiltered egress, where a Pod that starts before its Secret
	// simply waits.
	if order[0] != "networkpolicy" && api.policyCreateCount() > 0 {
		t.Errorf("create order = %v; the egress policy must still precede the Pod", order)
	}
}

// TestOwnerReference_DeletingThePodCollectsBothSecrets is the payoff.
//
// It deletes the Pod directly — as a node eviction, an operator with kubectl, or
// the orphan sweep would — without going through the driver at all, and then
// asserts the Secrets are gone. Nothing in this test asks the driver to clean
// up; that is the point. The path being proven is the one that still works when
// the process that created the Secrets no longer exists.
func TestOwnerReference_DeletingThePodCollectsBothSecrets(t *testing.T) {
	_, api, handle, podName := startOwnedRun(t)

	want := []string{workspaceSecretName(handle.ID), secretFilesSecretName(handle.ID)}
	sort.Strings(want)
	got := api.secretNames()
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("secrets before the Pod is deleted = %v, want %v", got, want)
	}

	// Straight to the store, bypassing the driver entirely.
	api.handleDeleteDirect(podName)

	if left := api.secretNames(); len(left) != 0 {
		t.Errorf("secrets surviving their owner = %v; a hub that never came back would leave "+
			"these holding live credentials forever", left)
	}
	collected := api.garbageCollected()
	wantCollected := []string{"secret/" + want[0], "secret/" + want[1]}
	if !reflect.DeepEqual(collected, wantCollected) {
		t.Errorf("garbage collected = %v, want %v", collected, wantCollected)
	}
	// And the driver did not do it: no DELETE reached the Secret endpoint.
	if dels := api.secretDeleteNames(); len(dels) != 0 {
		t.Errorf("secret deletes = %v; this test asserts the *cluster* collected them, so any "+
			"driver-issued delete means it is proving the wrong path", dels)
	}
}

// TestOwnerReference_HubKilledMidProvisionLeavesNothing is the crash the whole
// change exists for.
//
// A hub that dies after creating the Pod but before creating the Secrets used to
// be the bad case in the other direction — it left a Secret with no reaper. Now
// the Pod comes first, so the same crash leaves at most a Pod, which the orphan
// sweep collects by label, and collecting it takes any Secret that did land with
// it.
//
// The crash is modelled by making every Secret delete fail before the hub goes
// away. That is what "killed" means here in the only respect that matters: the
// hub's own cleanup did not happen. Modelling it by simply dropping the
// executor would not work — Close runs the graceful path and deletes the
// Secrets itself, so the test would pass with the ownerReferences removed and
// prove nothing.
//
// The load-bearing assertion is therefore on garbageCollected(), which records
// what the *collector* reaped. "No Secrets are left" is too weak: a Secret the
// driver deleted and one the cluster collected leave the same empty namespace,
// and only the second survives the hub being gone.
func TestOwnerReference_HubKilledMidProvisionLeavesNothing(t *testing.T) {
	ex, api, handle, podName := startOwnedRun(t)

	// The workload is live and everything it needs is in the cluster.
	if n := len(api.secretNames()); n != 2 {
		t.Fatalf("got %d secrets before the crash, want 2", n)
	}
	api.run(podName)

	// From here the hub can no longer take its credentials back.
	api.failAlways("DELETE /secrets", apiFailure{
		Code: 403, Reason: "Forbidden", Message: "the hub is gone",
	})
	ex.Close()
	if n := len(api.secretNames()); n != 2 {
		t.Fatalf("got %d secrets after the simulated crash, want both still present — the "+
			"fixture is not modelling a hub that failed to clean up", n)
	}

	// A replacement hub comes up with the same executor ID and no handles, and
	// the Pod is old enough to be past the grace period.
	ex2, _, _ := newTestExecutor(t, func(o *Options) {
		o.ID = "k8s-test"
		o.Credentials = newFakeSource(api.restConfig())
		o.OrphanGracePeriod = time.Nanosecond
	})
	removed, err := ex2.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if len(removed) == 0 {
		t.Fatalf("the sweep removed nothing; the orphaned Pod is still running: pods=%v", api.podNames())
	}

	// The credentials went with the Pod, collected by the cluster rather than by
	// anything in this process.
	want := []string{
		"secret/" + secretFilesSecretName(handle.ID),
		"secret/" + workspaceSecretName(handle.ID),
	}
	sort.Strings(want)
	if got := api.garbageCollected(); !reflect.DeepEqual(got, want) {
		t.Errorf("garbage collected = %v, want %v — nothing else will ever reap these, because "+
			"finding them would need `list secrets` and this driver holds no read access at all", got, want)
	}
	if left := api.secretNames(); len(left) != 0 {
		t.Errorf("secrets left after the sweep = %v; these hold live credentials", left)
	}
	if got := api.requestsMatching("GET /api/v1/namespaces/cloop/secrets"); len(got) != 0 {
		t.Errorf("the sweep read Secrets: %v — it has no RBAC to do that, and the ownerReference "+
			"exists precisely so it never needs to", got)
	}
}

// TestOwnerReference_NetworkPolicyIsDeliberatelyNotOwned records a decision that
// would otherwise look like an oversight.
//
// The NetworkPolicy cannot carry an ownerReference, and the reason is the
// ordering: it must exist *before* the Pod, because a Pod that starts before its
// policy has a window of unfiltered egress. There is no ordering that gives it
// both a UID to name and a guarantee of preceding the workload, and the only
// way to have both would be to patch the policy after the fact — which needs
// `patch` on networkpolicies, the one verb the chart argues at length must never
// be granted, since it is also the authority to widen a running sandbox's
// firewall.
//
// It does not need one. Unlike a Secret, a policy is listable by this driver, so
// the orphan sweep can and does collect it — which is why Task 20281 pairs the
// ownerReferences with making that sweep periodic instead of startup-only.
func TestOwnerReference_NetworkPolicyIsDeliberatelyNotOwned(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) {
		o.Workspace = workingSource()
		o.EgressFilter = filteredExecutor()
	})
	if _, err := ex.Start(context.Background(), ownedSpec()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	names := api.policyNames()
	if len(names) != 1 {
		t.Fatalf("got %d policies, want 1: %v", len(names), names)
	}
	if refs := api.policyOwnerRefs(names[0]); len(refs) != 0 {
		t.Errorf("NetworkPolicy %q carries ownerReferences %+v; it is created before the Pod and "+
			"therefore cannot name one, and adding it later would need the `patch` verb this "+
			"driver must not hold", names[0], refs)
	}

	// Deleting the Pod must therefore *not* collect it — the sweep is what does.
	api.handleDeleteDirect(api.onlyPodName(t))
	for _, entry := range api.garbageCollected() {
		if strings.HasPrefix(entry, "networkpolicy/") {
			t.Errorf("the collector reaped %s; this test exists to record that it cannot", entry)
		}
	}
}

// TestOwnerReference_SecretsAreUnownedRatherThanRefusedWithoutAUID covers the
// degenerate response.
//
// A Pod the API server accepted always has a UID, so this should be
// unreachable — but "should be unreachable" is a bad reason to fail a run. The
// driver falls back to the behaviour it had before ownerReferences existed:
// create the Secret unowned and rely on the explicit deletes. A refused Start
// would be the worse outcome, because it is not recoverable, where an unowned
// Secret is.
func TestOwnerReference_SecretsAreUnownedRatherThanRefusedWithoutAUID(t *testing.T) {
	ref, ok := podOwnerReference(&pod{})
	if ok {
		t.Errorf("podOwnerReference accepted a Pod with no UID and returned %+v", ref)
	}
	if _, ok := podOwnerReference(nil); ok {
		t.Error("podOwnerReference accepted a nil Pod")
	}
	withUID := &pod{}
	withUID.Metadata.Name = "p"
	withUID.Metadata.UID = "u"
	got, ok := podOwnerReference(withUID)
	if !ok {
		t.Fatal("podOwnerReference rejected a Pod that has both a name and a UID")
	}
	if got.UID != "u" || got.Name != "p" {
		t.Errorf("owner = %+v, want name=p uid=u", got)
	}
}

// TestOwnerReference_MarshalsTheFieldsTheAPIServerRequires guards the wire
// shape.
//
// apiVersion, kind, name and uid are all required by the API server, and a
// struct tag carrying omitempty on any of them would drop a field on a
// zero value and produce a 422 that names a field path rather than the cause.
func TestOwnerReference_MarshalsTheFieldsTheAPIServerRequires(t *testing.T) {
	raw, err := json.Marshal(ownerReference{
		APIVersion: "v1", Kind: "Pod", Name: "p", UID: "u",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{
		`"apiVersion":"v1"`, `"kind":"Pod"`, `"name":"p"`, `"uid":"u"`,
		`"controller":false`, `"blockOwnerDeletion":false`,
	} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("marshalled ownerReference %s is missing %s", raw, field)
		}
	}
}
