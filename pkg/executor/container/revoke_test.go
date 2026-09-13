package container

// revoke_test.go proves the half of the revocation guarantee that does not
// need a container runtime: that the bytes of a revoked credential stop
// existing on the host.
//
// That is the whole of the file-backed guarantee for this driver. The staging
// directory is bind-mounted into the sandbox, so the container's view is the
// same inode as the host's — unlinking here is exactly what makes the next
// read inside the sandbox fail. A test that asserts the file is gone from disk
// is therefore asserting the property the sandbox experiences, not a proxy for
// it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// leasedFilesSpec builds a spec delivering one credential file per lease, each
// into its own directory — the shape the broker produces for two grants on one
// workload.
func leasedFilesSpec(t *testing.T) executor.Spec {
	t.Helper()
	return executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"true"},
		SecretFiles: []executor.SecretFile{
			{
				LeaseID: "lease_pat", GrantID: "grant_pat",
				Dir: "/run/cloop/cloop-lease-pat", Name: "gitcredentials",
				Content: []byte("https://x-access-token:ghp_canary_pat@github.com\n"),
			},
			{
				LeaseID: "lease_kube", GrantID: "grant_kube",
				Dir: "/run/cloop/cloop-lease-kube", Name: "kubeconfig",
				Content: []byte("token: sha256~canary_kubeconfig\n"),
			},
		},
	}
}

// hostPathFor finds the staged copy of one lease's file.
func hostPathFor(t *testing.T, stage *secretStage, name string) string {
	t.Helper()
	for _, f := range stage.files {
		if filepath.Base(f.host) == name {
			return f.host
		}
	}
	t.Fatalf("no staged file named %q; staged %d", name, len(stage.files))
	return ""
}

// TestRevokeWipesOnlyTheNamedLease is the property the whole design turns on.
//
// A revocation must be exact in both directions, and the two failures are
// equally bad: too narrow leaves a withdrawn credential readable, while too
// wide takes away a kubeconfig because a GitHub PAT was revoked — breaking a
// run for a reason the operator never asked for. The assertion is on the bytes
// rather than on a return count, because a function that reported "1 removed"
// while leaving the file behind would pass any weaker check.
func TestRevokeWipesOnlyTheNamedLease(t *testing.T) {
	spec := leasedFilesSpec(t)
	stage, err := stageSecretFiles(spec, "")
	if err != nil {
		t.Fatalf("stageSecretFiles: %v", err)
	}
	defer stage.remove()

	pat := hostPathFor(t, stage, "gitcredentials")
	kube := hostPathFor(t, stage, "kubeconfig")

	// Staging is a precondition, not the thing under test: if the credential
	// was never written, "it is gone afterwards" proves nothing.
	if got, err := os.ReadFile(pat); err != nil || !strings.Contains(string(got), "ghp_canary_pat") {
		t.Fatalf("precondition: staged PAT unreadable or wrong: %v / %q", err, got)
	}

	removed, err := stage.revoke(executor.RevokeRequest{LeaseID: "lease_pat"})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if removed != 1 {
		t.Errorf("revoke removed %d files, want 1", removed)
	}

	if _, err := os.Stat(pat); !os.IsNotExist(err) {
		raw, _ := os.ReadFile(pat)
		t.Errorf("the revoked credential is still on disk at %s (%q).\n"+
			"  The sandbox reads this inode through a bind mount, so it can still use it.", pat, raw)
	}
	// The directory goes too: an empty directory named after a revoked lease
	// is a needless hint about what was granted.
	if _, err := os.Stat(filepath.Dir(pat)); !os.IsNotExist(err) {
		t.Errorf("the revoked lease's directory %s survived with nothing in it", filepath.Dir(pat))
	}

	got, err := os.ReadFile(kube)
	if err != nil || !strings.Contains(string(got), "canary_kubeconfig") {
		t.Errorf("revoking lease_pat took lease_kube's credential with it: %v / %q.\n"+
			"  A revocation must withdraw exactly what was revoked.", err, got)
	}
}

// TestRevokeByGrantNarrowsWithinALease pins the grant filter.
//
// A request naming a grant covers that grant; one naming only a lease covers
// everything under it. Getting this backwards is silent in both directions,
// which is why it is asserted rather than assumed.
func TestRevokeByGrantNarrowsWithinALease(t *testing.T) {
	spec := executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"true"},
		SecretFiles: []executor.SecretFile{
			{LeaseID: "l1", GrantID: "g_repo", Dir: "/run/cloop/cloop-lease-l1", Name: "repo.token",
				Content: []byte("repo-canary")},
			{LeaseID: "l1", GrantID: "g_pkg", Dir: "/run/cloop/cloop-lease-l1", Name: "pkg.token",
				Content: []byte("pkg-canary")},
		},
	}
	stage, err := stageSecretFiles(spec, "")
	if err != nil {
		t.Fatalf("stageSecretFiles: %v", err)
	}
	defer stage.remove()

	repo := hostPathFor(t, stage, "repo.token")
	pkg := hostPathFor(t, stage, "pkg.token")

	if _, err := stage.revoke(executor.RevokeRequest{LeaseID: "l1", GrantID: "g_repo"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := os.Stat(repo); !os.IsNotExist(err) {
		t.Errorf("the revoked grant's file %s survived", repo)
	}
	if _, err := os.ReadFile(pkg); err != nil {
		t.Errorf("revoking one grant took the other's file: %v", err)
	}
	// Both grants share a directory here, so it must survive while the second
	// file does. Removing it would take a credential nobody revoked.
	if _, err := os.Stat(filepath.Dir(pkg)); err != nil {
		t.Errorf("the shared lease directory was removed while a live grant still used it: %v", err)
	}

	if _, err := stage.revoke(executor.RevokeRequest{LeaseID: "l1"}); err != nil {
		t.Fatalf("revoke whole lease: %v", err)
	}
	if _, err := os.Stat(pkg); !os.IsNotExist(err) {
		t.Errorf("a lease-wide revocation left %s behind", pkg)
	}
	if _, err := os.Stat(filepath.Dir(pkg)); !os.IsNotExist(err) {
		t.Errorf("the lease directory survived a lease-wide revocation")
	}
}

// TestRevokeIsIdempotentAndRemoveStillWorksAfterIt guards the interaction
// between a revocation and the teardown that follows it.
//
// finish() calls remove() on every terminal path, and a workload whose lease
// was revoked mid-run still reaches one. If revoke left the stage in a state
// remove could not handle — a stale path it tried to wipe again, a double
// unlink reported as an error — the failure would land on the teardown path,
// where there is nobody to hand it to.
func TestRevokeIsIdempotentAndRemoveStillWorksAfterIt(t *testing.T) {
	stage, err := stageSecretFiles(leasedFilesSpec(t), "")
	if err != nil {
		t.Fatalf("stageSecretFiles: %v", err)
	}

	if _, err := stage.revoke(executor.RevokeRequest{LeaseID: "lease_pat"}); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	removed, err := stage.revoke(executor.RevokeRequest{LeaseID: "lease_pat"})
	if err != nil {
		t.Errorf("second revoke of the same lease errored: %v.\n"+
			"  An operator who clicks twice must not see a failure for material already gone.", err)
	}
	if removed != 0 {
		t.Errorf("second revoke reported %d files removed, want 0", removed)
	}

	kube := hostPathFor(t, stage, "kubeconfig")
	stage.remove()
	if _, err := os.Stat(kube); !os.IsNotExist(err) {
		t.Errorf("teardown after a revocation left %s behind", kube)
	}
	stage.remove() // must not panic on the emptied stage
}

// TestRevokeOnNilStageIsSafe covers the common workload.
//
// Most runs carry no file-backed grant at all, so rec.secretStage is nil. The
// revocation path walks every handle holding a lease and calls through to the
// stage without checking, exactly as the teardown path does — so nil has to be
// a no-op rather than a panic in the middle of an operator's revocation.
func TestRevokeOnNilStageIsSafe(t *testing.T) {
	var stage *secretStage
	removed, err := stage.revoke(executor.RevokeRequest{LeaseID: "anything"})
	if err != nil || removed != 0 {
		t.Errorf("nil stage revoke = (%d, %v), want (0, nil)", removed, err)
	}
}

// TestStagedFilesAreAttributedToTheirLease pins the bookkeeping revocation
// depends on.
//
// Without per-file attribution a stage is an anonymous set of paths, and the
// only revocation expressible is "wipe everything this workload holds". The
// attribution is copied from executor.SecretFile at write time, so this also
// guards against a future refactor that stages files without recording where
// they came from — which would compile, run, and silently widen every
// revocation to the whole workload.
func TestStagedFilesAreAttributedToTheirLease(t *testing.T) {
	stage, err := stageSecretFiles(leasedFilesSpec(t), "")
	if err != nil {
		t.Fatalf("stageSecretFiles: %v", err)
	}
	defer stage.remove()

	if len(stage.files) != 2 {
		t.Fatalf("staged %d files, want 2", len(stage.files))
	}
	for _, f := range stage.files {
		if f.leaseID == "" || f.grantID == "" {
			t.Errorf("staged file %s carries no lease attribution (%q/%q); "+
				"a revocation could only take it by taking everything", f.host, f.leaseID, f.grantID)
		}
	}
	// Distinct leases must not share a directory, or revoking either would
	// take both — the invariant stageSecretFiles' own comment states.
	dirs := map[string]string{}
	for _, f := range stage.files {
		dir := filepath.Dir(f.host)
		if prev, seen := dirs[dir]; seen && prev != f.leaseID {
			t.Errorf("leases %s and %s share staging directory %s", prev, f.leaseID, dir)
		}
		dirs[dir] = f.leaseID
	}
}
