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
	}})

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
	}})
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
