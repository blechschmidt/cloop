package localprocess

// revoke_test.go covers the part of this driver's revocation that touches the
// filesystem. The environment half is covered by scrub_test.go.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/securewipe"
)

// TestWipeBindingFilesRefusesPathsOutsideALeaseDirectory is the confinement
// check, and it is the reason this function is not three lines long.
//
// A binding is a list of paths and a revocation unlinks them, which is an
// arbitrary-file-deletion primitive wearing a domain name. The bindings are
// hub-built today, but the same struct crosses a process boundary on the remote
// path and this driver is what the agent runs on the far side of it — so the
// rule the agent's vault enforces has to hold here too, or the guarantee
// depends on which code path reached the disk.
//
// The refusal is also asserted to be *reported*. Skipping quietly would leave
// an operator believing a credential file was destroyed when the driver
// declined to touch it.
func TestWipeBindingFilesRefusesPathsOutsideALeaseDirectory(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "not-a-lease.conf")
	if err := os.WriteFile(outside, []byte("innocent bystander"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	removed, err := wipeBindingFiles([]executor.SecretBinding{{
		LeaseID: "l1",
		Files:   []string{outside},
	}}, true)

	if err == nil {
		t.Fatal("a path outside a lease directory was accepted silently.\n" +
			"  A binding is attacker-influenceable on the remote path, so this is an " +
			"arbitrary-unlink primitive aimed at whatever host the driver runs on.")
	}
	if !strings.Contains(err.Error(), "refusing to unlink") {
		t.Errorf("the refusal does not say it refused: %v", err)
	}
	if removed != 0 {
		t.Errorf("reported %d files removed while refusing them all", removed)
	}
	if _, statErr := os.Stat(outside); statErr != nil {
		t.Errorf("the refused path was deleted anyway: %v", statErr)
	}
}

// TestWipeBindingFilesRemovesLeaseMaterial is the positive case, so the test
// above cannot pass by refusing everything.
func TestWipeBindingFilesRemovesLeaseMaterial(t *testing.T) {
	dir := filepath.Join(t.TempDir(), securewipe.LeaseDirPrefix+"abc")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("ghp_canary"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	removed, err := wipeBindingFiles([]executor.SecretBinding{{
		LeaseID: "l1",
		Files:   []string{token},
		Dir:     dir,
	}}, true)
	if err != nil {
		t.Fatalf("wipeBindingFiles: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if _, statErr := os.Stat(token); !os.IsNotExist(statErr) {
		t.Errorf("the revoked credential is still readable at %s", token)
	}
	// The directory goes too: an empty directory named after a revoked lease
	// is a needless hint about what was granted.
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("the lease directory %s survived with nothing in it", dir)
	}
}

// TestRevokingOneGrantKeepsTheOtherGrantsFiles pins the narrowing on a host
// workload (Task 20403). Every grant of a lease writes into the one lease
// directory, and each binding names that directory, so a revocation of one
// grant that also removed the directory took the other grants' credentials
// with it — a workload still entitled to its kubeconfig lost it because a PAT
// was withdrawn.
func TestRevokingOneGrantKeepsTheOtherGrantsFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), securewipe.LeaseDirPrefix+"two")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pat := filepath.Join(dir, "github-token")
	kube := filepath.Join(dir, "kubeconfig")
	for path, body := range map[string]string{pat: "ghp_canary", kube: "token: kube_canary"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}
	bindings := []executor.SecretBinding{
		{LeaseID: "l1", GrantID: "grant_pat", Files: []string{pat}, Dir: dir},
		{LeaseID: "l1", GrantID: "grant_kube", Files: []string{kube}, Dir: dir},
	}

	e := New("test-host")
	e.leases.Bind("h1", bindings)
	out := e.RevokeLease(t.Context(), executor.RevokeRequest{LeaseID: "l1", GrantID: "grant_pat"})
	if out.State != executor.RevokeStateRevoked {
		t.Fatalf("State = %q (%s), want revoked", out.State, out.Error)
	}
	if out.Ack == nil || out.Ack.FilesRemoved != 1 {
		t.Errorf("ack = %+v, want exactly the revoked grant's one file removed", out.Ack)
	}
	if _, err := os.Stat(pat); !os.IsNotExist(err) {
		t.Errorf("the revoked grant's token survived at %s", pat)
	}
	if got, err := os.ReadFile(kube); err != nil || string(got) != "token: kube_canary" {
		t.Errorf("revoking grant_pat took grant_kube's kubeconfig with it: %v / %q", err, got)
	}

	// The lease-wide revocation that follows takes everything, the directory
	// included.
	out = e.RevokeLease(t.Context(), executor.RevokeRequest{LeaseID: "l1"})
	if out.State != executor.RevokeStateRevoked {
		t.Fatalf("lease-wide State = %q (%s)", out.State, out.Error)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("a lease-wide revocation left the lease directory %s", dir)
	}
}

// TestRevokeLeaseOnAnUnheldLeaseIsNotAFailure pins the "not here" outcome.
//
// A driver asked about a lease it never had must report success with Known
// false. Reporting a failure would make a fleet-wide revocation look partially
// broken every time it swept an executor that was simply not involved, and an
// operator who learns to ignore that state will ignore it when it is real.
func TestRevokeLeaseOnAnUnheldLeaseIsNotAFailure(t *testing.T) {
	e := New("test-host")

	out := e.RevokeLease(t.Context(), executor.RevokeRequest{LeaseID: "never_issued"})
	if out.State != executor.RevokeStateRevoked {
		t.Errorf("State = %q, want %q", out.State, executor.RevokeStateRevoked)
	}
	if out.Ack == nil || out.Ack.Known {
		t.Errorf("Ack.Known should be false for a lease this executor never held: %+v", out.Ack)
	}

	// A blank lease ID is a caller error, not a no-op: honouring it would make
	// every binding in the index a match.
	blank := e.RevokeLease(t.Context(), executor.RevokeRequest{})
	if blank.State != executor.RevokeStateFailed {
		t.Errorf("a blank lease id returned %q, want %q", blank.State, executor.RevokeStateFailed)
	}
}
