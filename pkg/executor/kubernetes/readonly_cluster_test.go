package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// TestReadOnly_RealClusterRefusesTheHarnessAWrite (Task 20501) runs the Pod
// buildPod renders for a run given another project to read on a real kubelet:
// the workspace container fills the read-only projects' volume — a stand-in
// for `cloop workspace provision`, which the test image does not hold — and
// the harness, running as the same uid that wrote the files, reads them and
// is refused every write there with EROFS.
func TestReadOnly_RealClusterRefusesTheHarnessAWrite(t *testing.T) {
	ctxName := requireCluster(t)
	ns := envE2ENamespace(t, ctxName)
	handle := "k-e2e-readonly"
	probe := `cat /readonly/api/src/api.go
for p in /readonly/api/src/api.go /readonly/api/new /readonly/new; do
  if (echo x > "$p") 2>/tmp/err; then echo "WROTE $p"; else echo "refused $p: $(cat /tmp/err)"; fi
done
if (rm -f /readonly/api/src/api.go) 2>/tmp/err; then echo "REMOVED"; else echo "remove refused: $(cat /tmp/err)"; fi`
	req := envE2ERequest(ns, handle, []string{readOnlyTokenEnv + "=cloop_know1_0123456789abcdef01234567.secret"}, probe)
	req.Workspace = executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://example.invalid/acme/app.git"}
	req.ReadOnly = []executor.ReadOnlyProject{{Slug: "api", Project: "/srv/projects/api",
		Snapshot: &executor.ReadOnlySnapshotRef{URL: "https://hub.example/snapshot", TokenEnv: readOnlyTokenEnv}}}
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	init := findContainer(p.Spec.InitContainers, InitContainerName)
	if init == nil || mountOf(init, readOnlyVolume) == nil {
		t.Fatal("the rendered Pod has no workspace container writing the read-only volume")
	}
	// Everything but what the workspace container runs is the driver's.
	init.Command = []string{"/bin/sh", "-c"}
	init.Args = []string{"mkdir -p /readonly/api/src && echo 'package api' > /readonly/api/src/api.go && " +
		"chmod -R a-w /readonly/api"}
	body, _ := json.Marshal(p)
	out, err := kubectl(t, ctxName, body, "create", "-f", "-", "-o", "jsonpath={.metadata.name}")
	if err != nil {
		t.Fatalf("create pod: %v\n%s", err, out)
	}
	podName := strings.TrimSpace(out)
	createE2ELeaseSecret(t, ctxName, req, podName, nil)
	waitE2E(t, "the Pod to succeed", 3*time.Minute, func() (bool, string) {
		phase, _ := kubectl(t, ctxName, nil, "get", "pod", podName, "-n", ns, "-o", "jsonpath={.status.phase}")
		return strings.TrimSpace(phase) == phaseSucceeded, phase
	})
	logs, err := kubectl(t, ctxName, nil, "logs", podName, "-n", ns, "-c", ContainerName)
	if err != nil {
		t.Fatalf("logs: %v\n%s", err, logs)
	}
	t.Logf("harness said:\n%s", logs)
	for _, want := range []string{"package api", "refused /readonly/api/src/api.go", "refused /readonly/api/new",
		"refused /readonly/new", "remove refused", "Read-only file system"} {
		if !strings.Contains(logs, want) {
			t.Errorf("want %q from the harness:\n%s", want, logs)
		}
	}
	for _, bad := range []string{"WROTE", "REMOVED"} {
		if strings.Contains(logs, bad) {
			t.Errorf("the harness changed the read-only projects:\n%s", logs)
		}
	}
}
