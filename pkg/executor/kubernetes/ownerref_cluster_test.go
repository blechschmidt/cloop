package kubernetes

// ownerref_cluster_test.go proves the claim the unit tests can only model: that
// a real Kubernetes garbage collector actually reaps a Secret carrying the
// ownerReference this driver emits.
//
// The fake API server in ownerref_test.go has a collectGarbage of its own, and
// it is written against the same field names the driver sets — so it agrees
// with the driver by construction and would keep agreeing with it if both were
// wrong together. Every interesting way to get this wrong is invisible to that
// fixture:
//
//   - naming the Pod instead of its UID (the collector silently ignores it and
//     the Secret lives forever);
//   - setting blockOwnerDeletion, which makes the API server demand `update` on
//     pods/finalizers and reject the create with a 403 on exactly the clusters
//     that are hardened properly;
//   - an apiVersion or kind the server does not resolve to a real type.
//
// None of those produce an error the driver would see. They produce a Secret
// that is created successfully and then never collected, which is precisely the
// leak Task 20281 exists to close — so this is the one check that can fail for
// the right reason.
//
// Opt-in, like tests/flagship: it needs a cluster, and a developer without one
// must not see a red suite.
//
//	kind create cluster --name cloop-gc
//	CLOOP_K8S_GC_E2E=1 go test ./pkg/executor/kubernetes/ -run RealCluster -v
//
// KUBECONTEXT overrides the context; the default is whatever kubectl is
// pointed at.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// gcTestNamespace is unique per run. A fixed name looked fine until two runs
// happened in a row: namespace deletion is asynchronous, the cleanup below does
// not block on it, and the second run was refused with "namespace is being
// terminated" — a failure that has nothing to do with what is under test.
func gcTestNamespace() string {
	return fmt.Sprintf("cloop-gc-%d-%d", os.Getpid(), time.Now().UnixNano()%1e6)
}

// kubectlAvailable reports whether this test can run at all.
func requireCluster(t *testing.T) string {
	t.Helper()
	if os.Getenv("CLOOP_K8S_GC_E2E") == "" {
		t.Skip("set CLOOP_K8S_GC_E2E=1 and point kubectl at a cluster to run the real-cluster " +
			"garbage-collection check")
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl is not on PATH")
	}
	ctxName := strings.TrimSpace(os.Getenv("KUBECONTEXT"))
	if out, err := kubectl(t, ctxName, nil, "version", "-o", "json"); err != nil {
		t.Skipf("no reachable cluster: %v (%s)", err, out)
	}
	return ctxName
}

// kubectl runs one command against the cluster and returns its combined output.
func kubectl(t *testing.T, ctxName string, stdin []byte, args ...string) (string, error) {
	t.Helper()
	full := args
	if ctxName != "" {
		full = append([]string{"--context", ctxName}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", full...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestOwnerReference_RealClusterGarbageCollection is the end-to-end proof.
//
// It builds the Secret with the driver's own types and the driver's own
// podOwnerReference, so what is applied to the cluster is the shape the driver
// emits rather than a hand-written copy that could drift from it.
func TestOwnerReference_RealClusterGarbageCollection(t *testing.T) {
	ctxName := requireCluster(t)

	// A namespace of this test's own, torn down at the end whatever happens.
	ns := gcTestNamespace()
	if out, err := kubectl(t, ctxName, nil, "create", "namespace", ns); err != nil &&
		!strings.Contains(out, "AlreadyExists") {
		t.Fatalf("create namespace: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_, _ = kubectl(t, ctxName, nil, "delete", "namespace", ns,
			"--wait=false", "--ignore-not-found")
	})

	const podName = "cloop-gc-owner"
	// The Pod is only ever an owner here; it does not have to run, and using
	// pause keeps the test from depending on an image pull that could fail for
	// reasons unrelated to what is being checked.
	podYAML := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + podName +
		"\n  namespace: " + ns +
		"\nspec:\n  restartPolicy: Never\n  containers:\n  - name: pause\n" +
		"    image: registry.k8s.io/pause:3.9\n"
	if out, err := kubectl(t, ctxName, []byte(podYAML), "apply", "-f", "-"); err != nil {
		t.Fatalf("create owner pod: %v\n%s", err, out)
	}

	// Read the Pod back exactly as the driver does: into its own pod type, from
	// the API server's response.
	raw, err := kubectl(t, ctxName, nil, "get", "pod", podName, "-n", ns, "-o", "json")
	if err != nil {
		t.Fatalf("get owner pod: %v\n%s", err, raw)
	}
	var owner pod
	if err := json.Unmarshal([]byte(raw), &owner); err != nil {
		t.Fatalf("decode owner pod: %v", err)
	}
	ref, ok := podOwnerReference(&owner)
	if !ok {
		t.Fatalf("podOwnerReference rejected a Pod a real API server created: %+v", owner.Metadata)
	}
	if ref.UID == "" {
		t.Fatal("the owner reference carries no UID")
	}

	// The Secret, built the way workspace.go and secretfiles.go build theirs.
	const secretName = "cloop-gc-dependent"
	obj := &secret{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: objectMeta{
			Name:            secretName,
			Namespace:       ns,
			Labels:          map[string]string{LabelManaged: "true"},
			OwnerReferences: []ownerReference{ref},
		},
		Type:       "Opaque",
		StringData: map[string]string{"token": "not-a-real-credential"},
	}
	body, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	// A failure here is itself a finding: it is what blockOwnerDeletion=true
	// would produce on a cluster running the OwnerReferencesPermissionEnforcement
	// admission plugin.
	if out, err := kubectl(t, ctxName, body, "apply", "-f", "-"); err != nil {
		t.Fatalf("the API server refused the Secret this driver emits: %v\n%s\nobject: %s",
			err, out, body)
	}

	// The server must have kept the reference. A malformed one is dropped or
	// rejected, and a dropped one produces exactly the silent leak being tested.
	stored, err := kubectl(t, ctxName, nil, "get", "secret", secretName, "-n", ns,
		"-o", "jsonpath={.metadata.ownerReferences[0].uid}")
	if err != nil {
		t.Fatalf("read back the secret: %v\n%s", err, stored)
	}
	if strings.TrimSpace(stored) != ref.UID {
		t.Fatalf("the stored ownerReference UID is %q, want %q — the API server did not keep "+
			"the reference, so nothing will ever collect this Secret", strings.TrimSpace(stored), ref.UID)
	}

	// Before deleting anything: the Secret must *survive* while its owner is
	// alive. This is not a formality. Kubernetes also collects a dependent
	// whose owner does not exist, so a reference naming a UID that was never
	// real — the exact bug of writing the Pod's name into the uid field —
	// produces a Secret that is deleted almost immediately. Without this check
	// that bug would make the test below pass faster, not fail.
	time.Sleep(10 * time.Second)
	alive, err := kubectl(t, ctxName, nil, "get", "secret", secretName, "-n", ns,
		"--ignore-not-found", "-o", "name")
	if err != nil {
		t.Fatalf("check the secret survives its live owner: %v\n%s", err, alive)
	}
	if strings.TrimSpace(alive) == "" {
		t.Fatalf("the Secret was collected while its owner Pod was still running. The " +
			"ownerReference does not resolve to a live object — check that it carries the " +
			"Pod's uid and not its name.")
	}

	// Now the actual question: delete the owner and see whether the cluster
	// collects the dependent without anyone asking it to.
	if out, err := kubectl(t, ctxName, nil, "delete", "pod", podName, "-n", ns,
		"--grace-period=0", "--force"); err != nil {
		t.Fatalf("delete owner pod: %v\n%s", err, out)
	}

	// The real collector is asynchronous, unlike the fake's. Polling is the
	// honest way to wait for it; a fixed sleep would either be flaky or slow.
	deadline := time.Now().Add(90 * time.Second)
	for {
		out, err := kubectl(t, ctxName, nil, "get", "secret", secretName, "-n", ns,
			"--ignore-not-found", "-o", "name")
		if err == nil && strings.TrimSpace(out) == "" {
			return // collected
		}
		if time.Now().After(deadline) {
			t.Fatalf("the Secret outlived its owner Pod by 90s and is still present (%q). The "+
				"ownerReference this driver emits is not causing collection: %s",
				strings.TrimSpace(out), body)
		}
		time.Sleep(time.Second)
	}
}
