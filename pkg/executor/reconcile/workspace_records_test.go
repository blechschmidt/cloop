package reconcile

// A Kubernetes Pod's workspace session does not survive the hub process that
// minted it (Task 20451). Pinned here, so the residual risk docs/security/model.md
// states for it cites a test — and the change that retires it has to change
// this one.
//
// A Pod's workspace is fetched by its init container through a pinned git
// proxy session, minted over the workspace credential source this package
// builds for the Kubernetes driver. That source's broker keeps no lease
// records: nothing names the lease in secret_leases, gitproxycreds therefore
// never records the session as durable, and no owner row names either — so a
// hub process adopting the Pod after the one that minted the session died has
// nothing to take over or restore, and an init container that fetches after
// that gets a 401. A device workspace's lease is recorded and restored with
// its run (pkg/ui TestAWorkspaceSessionSurvivesARestart); a Pod's is not.

import (
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

func TestAPodsWorkspaceSourceKeepsNoLeaseRecords(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "reconcile-workspace-records-unit-passphrase")
	dir := statedbtest.Dir(t)
	cfg := &config.Config{}
	cfg.Executors.Kubernetes.KubeconfigSecret = "prod-kubeconfig"
	id, cleanup, err := BrokerCredentials(dir, cfg, "k8s-prod")
	if err != nil {
		t.Fatalf("BrokerCredentials: %v", err)
	}
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	src, ok := id.Workspace.(*gitcreds.BrokerSource)
	if !ok || src == nil {
		t.Fatalf("the Kubernetes driver's workspace source is %T, want the broker's", id.Workspace)
	}
	if src.LeasesRecorded() {
		t.Fatal("a Pod's workspace leases are recorded now, so a hub process adopting the Pod could take the " +
			"lease over and restore its pinned session: prove the restore, and retire the residual risk " +
			"docs/security/model.md states for it (\"A Kubernetes Pod's workspace session\")")
	}
}
