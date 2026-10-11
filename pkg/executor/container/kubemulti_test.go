package container

// A lease carrying two kubeconfig grants on the container driver (Task 20413).
// The broker merges their documents into one file several grants own; this
// driver attributes a staged file to one grant, so revoking any other owner has
// to find the file through the path its binding names.

import (
	"os"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// kubeLeaseSpec delivers a two-kubeconfig lease the way the hub hands it to
// this driver, and returns the spec and each grant by secret name.
func kubeLeaseSpec(t *testing.T, guard secretbroker.KubeGuard) (executor.Spec, map[string]string) {
	t.Helper()
	_, lease := secretbrokertest.KubeLease(t, guard,
		secretbrokertest.KubeGrant{Secret: "alpha-kube",
			Kubeconfig:  secretbrokertest.Kubeconfig("https://alpha.example.test", "alpha-cluster-token-02", "default"),
			Constraints: secretbroker.Constraints{Namespaces: []string{"team-a"}}},
		secretbrokertest.KubeGrant{Secret: "beta-kube",
			Kubeconfig:  secretbrokertest.Kubeconfig("https://beta.example.test", "beta-cluster-token-02", "default"),
			Constraints: secretbroker.Constraints{Namespaces: []string{"team-b"}, Verbs: []string{"get", "create"}}},
	)
	grants := map[string]string{}
	for _, m := range lease.Materials {
		grants[m.SecretName] = m.GrantID
	}
	d, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	spec := executor.Spec{
		WorkDir: t.TempDir(), Argv: []string{"true"}, Env: d.Env(),
		Secrets:     secretbroker.ExecutorBindings(lease.ID, lease.ExpiresAt, d.Bindings()),
		SecretFiles: secretbroker.ExecutorSecretFiles(lease.ID, d.Files()),
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("Spec.Validate refuses the merged lease: %v", err)
	}
	return spec, grants
}

// revokeGrant revokes one grant from stage the way revokeHandle does, with
// the files that grant's binding names.
func revokeGrant(t *testing.T, stage *secretStage, spec executor.Spec, grantID string) int {
	t.Helper()
	req := executor.RevokeRequest{LeaseID: spec.Secrets[0].LeaseID, GrantID: grantID}
	var bindings []executor.SecretBinding
	for _, b := range spec.Secrets {
		if req.Matches(b) {
			bindings = append(bindings, b)
		}
	}
	removed, err := stage.revoke(req, bindingFiles(bindings)...)
	if err != nil {
		t.Fatalf("revoke %s: %v", grantID, err)
	}
	return removed
}

func TestTwoKubeconfigGrantsStageAsOneFile(t *testing.T) {
	t.Run("both unmonitored: either grant's revocation takes the document", func(t *testing.T) {
		spec, grants := kubeLeaseSpec(t, nil)
		stage, err := stageSecretFiles(spec, "")
		if err != nil {
			t.Fatalf("stageSecretFiles: %v", err)
		}
		defer stage.remove()
		if len(stage.files) != 1 {
			t.Fatalf("staged %d files, want the one merged kubeconfig", len(stage.files))
		}
		path := hostPathFor(t, stage, "kubeconfig")
		raw, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(raw), "alpha-cluster-token-02") ||
			!strings.Contains(string(raw), "beta-cluster-token-02") {
			t.Fatalf("the staged kubeconfig does not hold both grants: %v\n%s", err, raw)
		}
		// The file is attributed to alpha, the first owner; beta owns it too,
		// and only its binding can say so.
		if stage.files[0].grantID != grants["alpha-kube"] {
			t.Fatalf("staged file attributed to %s", stage.files[0].grantID)
		}
		if removed := revokeGrant(t, stage, spec, grants["beta-kube"]); removed != 1 {
			t.Errorf("revoking beta removed %d files, want the document holding its credential", removed)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("the document holding beta's cluster credential survived its revocation: %v", err)
		}
	})

	t.Run("monitored beside unmonitored: the monitored grant's revocation leaves it", func(t *testing.T) {
		guard := &secretbrokertest.KubeGuard{BaseURL: "https://monitor.example.test:8444",
			Decline: map[string]bool{"beta-kube": true}}
		spec, grants := kubeLeaseSpec(t, guard)
		stage, err := stageSecretFiles(spec, "")
		if err != nil {
			t.Fatalf("stageSecretFiles: %v", err)
		}
		defer stage.remove()
		path := hostPathFor(t, stage, "kubeconfig")
		if removed := revokeGrant(t, stage, spec, grants["alpha-kube"]); removed != 0 {
			t.Errorf("revoking the monitored grant removed %d files", removed)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("revoking the monitored grant took the document: %v", err)
		}
		if removed := revokeGrant(t, stage, spec, grants["beta-kube"]); removed != 1 {
			t.Errorf("revoking the unmonitored grant removed %d files, want 1", removed)
		}
	})
}
