package kubernetes

// A lease carrying two kubeconfig grants into a Pod (Task 20413). Before the
// broker merged their documents the spec carried two files at one path and
// Start refused it; no Pod was created.

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// TestStart_TwoKubeconfigGrantsTravelAsOneDocument: the merged kubeconfig is
// one key of the lease Secret, projected at the lease directory under the
// name KUBECONFIG gives; revoking the monitored grant leaves the Pod and the
// document — its session closing on the hub is its withdrawal — and revoking
// the unmonitored one, whose cluster credential is in the document, takes the
// Pod.
func TestStart_TwoKubeconfigGrantsTravelAsOneDocument(t *testing.T) {
	guard := &secretbrokertest.KubeGuard{BaseURL: "https://monitor.example.test:8444",
		Decline: map[string]bool{"beta-kube": true}}
	_, lease := secretbrokertest.KubeLease(t, guard,
		secretbrokertest.KubeGrant{Secret: "alpha-kube",
			Kubeconfig:  secretbrokertest.Kubeconfig("https://alpha.example.test", "alpha-cluster-token-03", "default"),
			Constraints: secretbroker.Constraints{Namespaces: []string{"team-a"}}},
		secretbrokertest.KubeGrant{Secret: "beta-kube",
			Kubeconfig:  secretbrokertest.Kubeconfig("https://beta.example.test", "beta-cluster-token-03", "default"),
			Constraints: secretbroker.Constraints{Namespaces: []string{"team-b"}, Verbs: []string{"get", "create"}}},
	)
	grants := map[string]string{}
	for _, m := range lease.Materials {
		grants[m.SecretName] = m.GrantID
	}
	dir := secretbroker.SandboxLeaseDir(lease.ID)
	d, err := lease.Deliver(dir)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer d.Close()
	spec := testSpec()
	spec.Env = d.Env()
	spec.Secrets = secretbroker.ExecutorBindings(lease.ID, lease.ExpiresAt, d.Bindings())
	spec.SecretFiles = secretbroker.ExecutorSecretFiles(lease.ID, d.Files())
	if err := spec.Validate(); err != nil {
		t.Fatalf("Spec.Validate refuses the merged lease: %v", err)
	}

	ex, api, _ := newTestExecutor(t, nil)
	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	podName := api.onlyPodName(t)
	api.run(podName)
	sec := api.secretObject(leaseSecretName(handle.ID))
	if sec == nil {
		t.Fatal("no lease Secret was created")
	}
	key := secretFileKey(0, "kubeconfig")
	doc := string(sec.Data[key])
	for _, want := range []string{"name: alpha-kube", "name: beta-kube", "beta-cluster-token-03", guard.Sessions()[0].Token} {
		if !strings.Contains(doc, want) {
			t.Errorf("the lease Secret's %s lacks %q:\n%s", key, want, doc)
		}
	}
	var docs int
	for k := range sec.Data {
		if !strings.HasPrefix(k, envSecretKeyPrefix) {
			docs++
		}
	}
	if docs != 1 {
		t.Errorf("the lease Secret carries %d files, want the one document: %v", docs, keysOf(sec.Data))
	}
	if got := string(sec.Data[envSecretKeyPrefix+"KUBECONFIG"]); got != dir+"/kubeconfig" {
		t.Errorf("KUBECONFIG = %q, want %s/kubeconfig", got, dir)
	}

	api.mu.Lock()
	created := *api.pods[podName]
	api.mu.Unlock()
	vols := secretFileVolumesOf(&created)
	if len(vols) != 1 || len(vols[0].Secret.Items) != 1 || vols[0].Secret.Items[0].Key != key ||
		vols[0].Secret.Items[0].Path != "kubeconfig" {
		t.Fatalf("lease volumes = %+v, want the document projected as kubeconfig", vols)
	}
	if !hasSecretFileMount(created.Spec.Containers[0], dir) {
		t.Errorf("the harness does not mount the lease directory %s", dir)
	}

	out := ex.RevokeLease(context.Background(), executor.RevokeRequest{
		LeaseID: lease.ID, GrantID: grants["alpha-kube"], Reason: "the monitored grant was revoked",
	})
	if out.State != executor.RevokeStateRevoked || out.Ack == nil || len(out.Ack.Killed) != 0 ||
		out.Ack.FilesRemoved != 0 {
		t.Fatalf("revoking the monitored grant: %+v / %+v; its binding names nothing in the Pod", out, out.Ack)
	}
	if after := api.secretObject(leaseSecretName(handle.ID)); after == nil || string(after.Data[key]) != doc {
		t.Fatal("revoking the monitored grant changed the document the other grant still reads")
	}
	out = ex.RevokeLease(context.Background(), executor.RevokeRequest{
		LeaseID: lease.ID, GrantID: grants["beta-kube"], Reason: "the unmonitored grant was revoked",
	})
	if out.Ack == nil || !containsString(out.Ack.Killed, handle.ID) {
		t.Errorf("revoking the grant whose cluster credential is in the document left the Pod: %+v", out.Ack)
	}
}
