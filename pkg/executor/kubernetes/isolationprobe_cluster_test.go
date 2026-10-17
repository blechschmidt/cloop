package kubernetes

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// isolationRuntimeClass is a RuntimeClass named for Kata whose handler is runc:
// the misconfiguration Task 20439 exists to catch, staged on a test cluster
// rather than on any cluster that runs work.
const isolationRuntimeClass = "kata-runc-t20439"

// TestIsolationProbe_RealClusterRuntimeClassHandledByRunc runs the probe on a
// real API server and kubelet, against the RuntimeClass the task names: one
// called kata, handled by runc. The executor claims a VM; the probe Pod under
// the class and the reference Pod bound to its node read the same boot ID, and
// placement refuses a workload requiring a hypervisor there.
//
// Opt-in like the package's other real-cluster tests (CLOOP_K8S_GC_E2E=1), and
// it needs an image whose cloop has the probe — CI loads the hub image it
// built from the same tree (CLOOP_K8S_PROBE_E2E_IMAGE=cloop-hub:ci).
func TestIsolationProbe_RealClusterRuntimeClassHandledByRunc(t *testing.T) {
	ctxName := requireCluster(t)
	image := strings.TrimSpace(os.Getenv("CLOOP_K8S_PROBE_E2E_IMAGE"))
	if image == "" {
		t.Skip("set CLOOP_K8S_PROBE_E2E_IMAGE to an image whose cloop has the isolation probe")
	}
	ns := envE2ENamespace(t, ctxName)

	manifest := "apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: " +
		isolationRuntimeClass + "\nhandler: runc\n"
	if out, err := kubectl(t, ctxName, []byte(manifest), "apply", "-f", "-"); err != nil {
		t.Fatalf("create the RuntimeClass: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_, _ = kubectl(t, ctxName, nil, "delete", "runtimeclass", isolationRuntimeClass, "--ignore-not-found")
	})

	raw, err := kubectl(t, ctxName, nil, "config", "view", "--raw", "--minify", "--flatten")
	if err != nil {
		t.Fatalf("kubectl config view: %v\n%s", err, raw)
	}
	rest, err := ParseKubeconfig([]byte(raw), "")
	if err != nil {
		t.Fatalf("ParseKubeconfig: %v", err)
	}
	ex, err := New(Options{
		ID: "e2e-isolation", Namespace: ns, Image: image, ImagePullPolicy: "IfNotPresent",
		RuntimeClass: isolationRuntimeClass, Credentials: newFakeSource(rest),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(ex.Close)
	if !ex.Capabilities().Virtualized {
		t.Fatal("a RuntimeClass named kata-* no longer claims a VM; this test is about that claim")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	probe, err := ex.ProbeIsolation(ctx)
	if err != nil {
		t.Fatalf("ProbeIsolation: %v", err)
	}
	v := probe.Verdict()
	if v.Kind != isolationprobe.KindHostKernel || !strings.Contains(v.Detail, "boot ID") {
		t.Fatalf("verdict = %s (%s), want the host kernel by boot ID", v.Kind, v.Detail)
	}
	if probe.Reference.Source != isolationprobe.SourceClusterNode || probe.Reference.Kernel == nil {
		t.Fatalf("reference = %+v, want the node's kernel from the reference Pod", probe.Reference)
	}

	rec := executor.IsolationRecord{ExecutorID: ex.ID(), Runtime: isolationRuntimeClass,
		Claim: executor.IsolationClaim(isolationRuntimeClass), Verdict: v.Kind, Detail: v.Detail, ProbedAt: time.Now()}
	prev := executor.SetIsolationEvidenceSource(func(id, runtime string) (executor.IsolationRecord, bool) {
		return rec, id == rec.ExecutorID && runtime == rec.Runtime
	})
	t.Cleanup(func() { executor.SetIsolationEvidenceSource(prev) })
	_, err = executor.Select([]executor.Candidate{{Executor: ex, Health: executor.Health{State: executor.NodeReady}}},
		executor.Requirements{RequireVirtualization: true})
	if err == nil || !strings.Contains(err.Error(), string(executor.ConstraintIsolationEvidence)) {
		t.Fatalf("Select = %v, want the isolation_evidence refusal", err)
	}

	// Nothing of the probe's outlives it.
	waitE2E(t, "the probe's Pods to be deleted", time.Minute, func() (bool, string) {
		out, _ := kubectl(t, ctxName, nil, "get", "pods", "-n", ns, "-l", labelIsolationProbe, "-o", "name")
		return strings.TrimSpace(out) == "", out
	})
}
