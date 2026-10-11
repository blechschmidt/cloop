package agent

// A lease carrying two kubeconfig grants on an edge device (Task 20413). Before
// the broker merged their documents the start frame carried two files at one
// path and was refused at decode ("secret_files[N] repeats path …/kubeconfig");
// a device never ran the workload at all.
//
// The frame here is a real one, built and decoded by pkg/executor/remote, so
// the placement under test is fed exactly what a device receives.

import (
	"os"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// TestTwoKubeconfigGrantsReachADevice: the frame decodes, the device places one
// kubeconfig, KUBECONFIG is moved onto it with the rest of the lease, and
// revoking one grant takes exactly what that grant's binding names — nothing
// for the monitored grant, whose session closing on the hub is its withdrawal,
// and the whole document for the unmonitored one, whose cluster credential is
// in it.
func TestTwoKubeconfigGrantsReachADevice(t *testing.T) {
	guard := &secretbrokertest.KubeGuard{BaseURL: "https://monitor.example.test:8444",
		Decline: map[string]bool{"beta-kube": true}}
	_, lease := secretbrokertest.KubeLease(t, guard,
		secretbrokertest.KubeGrant{Secret: "alpha-kube",
			Kubeconfig:  secretbrokertest.Kubeconfig("https://alpha.example.test", "alpha-cluster-token-01", "default"),
			Constraints: secretbroker.Constraints{Namespaces: []string{"team-a"}}},
		secretbrokertest.KubeGrant{Secret: "beta-kube",
			Kubeconfig:  secretbrokertest.Kubeconfig("https://beta.example.test", "beta-cluster-token-01", "default"),
			Constraints: secretbroker.Constraints{Namespaces: []string{"team-b"}, Verbs: []string{"get", "create"}}},
	)
	var alpha, beta string
	for _, m := range lease.Materials {
		switch m.SecretName {
		case "alpha-kube":
			alpha = m.GrantID
		case "beta-kube":
			beta = m.GrantID
		}
	}
	if alpha == "" || beta == "" {
		t.Fatalf("lease carries %v", lease.SecretNames())
	}
	d, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer d.Close()
	spec := executor.Spec{
		WorkDir: "/tmp/does-not-matter", Argv: []string{"/bin/sh", "-c", "true"}, Env: d.Env(),
		Secrets:     secretbroker.ExecutorBindings(lease.ID, lease.ExpiresAt, d.Bindings()),
		SecretFiles: secretbroker.ExecutorSecretFiles(lease.ID, d.Files()),
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("Spec.Validate refuses the merged lease: %v", err)
	}

	frame, err := remote.NewFrame(remote.TypeStart, "f1", "", remote.StartPayload{
		Spec: spec, HandleID: "h-kube", SecretFiles: remote.NewSecretFiles(spec.SecretFiles),
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	start, err := remote.DecodeStart(frame)
	if err != nil {
		t.Fatalf("the device refuses the start frame: %v", err)
	}
	files := start.CredentialFiles()
	if len(files) != 1 || files[0].Name != "kubeconfig" {
		t.Fatalf("the frame carries %v, want the one merged kubeconfig", files)
	}

	a := secretTestAgent(t)
	got := start.Spec
	if len(got.Secrets) != 2 {
		t.Fatalf("the frame carries %d bindings, want one per grant", len(got.Secrets))
	}
	placed, err := a.materializeSecretFiles(&got, files)
	if err != nil {
		t.Fatalf("materializeSecretFiles: %v", err)
	}
	t.Cleanup(func() { placed.wipe(nil) })

	var kubeconfig string
	for _, kv := range got.Env {
		if v, ok := strings.CutPrefix(kv, "KUBECONFIG="); ok {
			kubeconfig = v
		}
	}
	if kubeconfig == "" || !strings.HasPrefix(kubeconfig, placed.dirs[0]+"/") {
		t.Fatalf("KUBECONFIG = %q, want it moved onto the device's own directory %s", kubeconfig, placed.dirs[0])
	}
	raw, err := os.ReadFile(kubeconfig)
	if err != nil {
		t.Fatalf("KUBECONFIG names nothing on the device: %v", err)
	}
	for _, want := range []string{"name: alpha-kube", "name: beta-kube", "current-context: alpha-kube",
		"beta-cluster-token-01", guard.Sessions()[0].Token} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the placed kubeconfig lacks %q:\n%s", want, raw)
		}
	}
	if strings.Contains(string(raw), "alpha-cluster-token-01") {
		t.Error("the monitored grant's cluster credential reached the device")
	}

	v := newVault()
	v.bind("h-kube", got.Secrets)
	if report := v.scrub(lease.ID, alpha, nil); !report.Known || report.FilesRemoved != 0 || len(report.Errors) != 0 {
		t.Errorf("revoking the monitored grant scrubbed %+v; its binding names no file", report)
	}
	if _, err := os.Stat(kubeconfig); err != nil {
		t.Fatalf("revoking the monitored grant took the document the other grant still needs: %v", err)
	}
	if report := v.scrub(lease.ID, beta, nil); report.FilesRemoved != 1 || len(report.Errors) != 0 {
		t.Errorf("revoking the unmonitored grant scrubbed %+v, want its document", report)
	}
	if _, err := os.Stat(kubeconfig); !os.IsNotExist(err) {
		t.Errorf("the document holding the revoked grant's cluster credential survived: %v", err)
	}
}
