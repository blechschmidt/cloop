package security

// Guarantee 12: brokered credential material is destroyed, not merely
// forgotten — on the ordinary exit as well as on an explicit revocation.
//
// Guarantee 11 (revocation_test.go) asserts that material can be *taken back*.
// This one asserts that it goes away on its own, which is a different property
// with a different failure mode. Revocation is an event somebody triggers and
// then watches; destruction on exit is the silent path that runs thousands of
// times a day with nobody looking. When it does not run, nothing fails, no
// alert fires, and the only symptom is plaintext accumulating on a disk.
//
// That is not hypothetical. Every piece asserted below was broken at once:
//
//   - the agent's wipe was reachable only from the revoke frame handler, so a
//     task that simply finished left its credential files on the device — and
//     because the lease was then forgotten, a later revoke answered "not held"
//     and still wiped nothing;
//   - the hub's cleanup rode an unguarded goroutine with no durable record, so
//     a restart between materialisation and wipe orphaned a directory that
//     nothing could even name, let alone remove;
//   - the wipe primitive itself discarded every error from the overwrite and
//     returned nil, so a caller was told a secret was destroyed when only its
//     name had been unlinked.
//
// The three assertions here are deliberately of different kinds, because the
// three failures were of different kinds. Reachability is structural and no
// behavioural test would have caught it (the wipe worked perfectly — nothing
// called it). The contract is behavioural. The durable record is a schema fact.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/securewipe"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	agentPkg      = ModulePath + "/pkg/executor/agent"
	uiPkg         = ModulePath + "/pkg/ui"
	securewipePkg = ModulePath + "/pkg/securewipe"
)

// TestCredentialDestructionIsReachableFromTheNormalExitPath is the structural
// assertion, and the one that would have caught the original defect.
//
// wipeCredentialFile was reached from exactly one place — vault.scrub — called
// only from the hub-initiated revoke frame handler. The ordinary exit was
// deliverFinal -> forget -> vault.release, and release deleted map entries and
// nothing else. The zeroing machinery was correct, tested, and confined; it was
// simply not on the path every workload takes.
//
// No behavioural test of the wipe could have found that, because the wipe was
// not the thing that was broken. What was broken was which paths reach it, and
// that is a property of the call graph.
func TestCredentialDestructionIsReachableFromTheNormalExitPath(t *testing.T) {
	g, err := LoadGraph()
	if err != nil {
		t.Fatalf("load call graph: %v", err)
	}

	wipe, ok := g.FindFunc(securewipePkg, "File")
	if !ok {
		t.Fatal("securewipe.File not found in the graph; this test cannot be meaningful")
	}

	for _, tc := range []struct {
		name    string
		pkg     string
		fn      string
		because string
	}{
		{
			name: "agent: a workload's ordinary finish",
			pkg:  agentPkg, fn: "deliverFinal",
			because: "deliverFinal reports a finished workload's terminal status. If the " +
				"credential wipe is not downstream of it, every task that simply ends " +
				"leaves its plaintext on the device.",
		},
		{
			name: "agent: every exit, including refused starts and kills",
			pkg:  agentPkg, fn: "forget",
			because: "forget is the one exit every workload passes through — refused start, " +
				"killed run, disowned handle, ordinary finish. It is where 'an edge device " +
				"does not accumulate the plaintext of every credential it has held' is made true.",
		},
		{
			name: "agent: the vault's own release path",
			pkg:  agentPkg, fn: "release",
			because: "release used to delete map entries and nothing else. Once a lease was " +
				"released the vault no longer knew it, so a later revoke reported 'not known' " +
				"and the files stayed on disk forever.",
		},
		{
			name: "hub: the startup sweep",
			pkg:  uiPkg, fn: "sweepOrphanedLeaseDirs",
			because: "a hub killed between materialising a lease and wiping it leaves plaintext " +
				"in /dev/shm, which is tmpfs and survives a process restart. The sweep is the " +
				"only thing that collects it.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, ok := g.FindFunc(tc.pkg, tc.fn)
			if !ok {
				t.Fatalf("%s.%s not found (renamed?); this guarantee needs a live anchor", tc.pkg, tc.fn)
			}
			path, reachable := g.Reaches(start, wipe)
			if !reachable {
				t.Fatalf("credential destruction is NOT reachable from %s.%s\n\n%s",
					tc.pkg, tc.fn, tc.because)
			}
			t.Logf("destruction path: %s", strings.Join(path, "\n  -> "))
		})
	}
}

// TestNormalExitDestructionDoesNotDependOnRevocation states the distinction the
// original code collapsed.
//
// If the only route from the exit path to the wipe ran through the revoke frame
// handler, the guarantee would hold only for workloads somebody revoked. The
// exit path must reach destruction without any hub-initiated frame in the
// chain.
func TestNormalExitDestructionDoesNotDependOnRevocation(t *testing.T) {
	g, err := LoadGraph()
	if err != nil {
		t.Fatalf("load call graph: %v", err)
	}
	forget, ok := g.FindFunc(agentPkg, "forget")
	if !ok {
		t.Fatal("agent.forget not found")
	}
	wipe, _ := g.FindFunc(securewipePkg, "File")
	path, reachable := g.Reaches(forget, wipe)
	if !reachable {
		t.Fatal("the exit path does not reach the wipe at all")
	}
	if revoke, ok := g.FindFunc(agentPkg, "handleRevoke"); ok {
		for _, hop := range path {
			if hop == revoke {
				t.Errorf("the only route from the normal exit to the wipe runs through the "+
					"revoke frame handler:\n  %s\n\nA task nobody revokes would keep its "+
					"credentials.", strings.Join(path, "\n  -> "))
			}
		}
	}
}

// TestWipeReportsAFailureRatherThanClaimingSuccess is the behavioural half.
//
// The primitive's doc comment promised "overwrites a file's contents with
// zeros, syncs, and removes it" while discarding the error from every one of
// those steps. Only the unlink was guaranteed, so the caller was told the
// secret was destroyed when its bytes had merely been made unreachable through
// that name — which on the os.TempDir() fallback path, used wherever /dev/shm
// is absent, is a recoverable secret.
//
// A wipe that cannot happen must say so. Anything else makes every audit line
// and every operator-facing "credential revoked" a claim the system cannot
// support.
func TestWipeReportsAFailureRatherThanClaimingSuccess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), securewipe.LeaseDirPrefix+"conformance")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	t.Run("a path that cannot be overwritten", func(t *testing.T) {
		// A directory is the root-safe case: file permissions do not constrain
		// root, so a chmod-based test would silently pass for the wrong reason
		// wherever CI runs privileged.
		sub := filepath.Join(dir, "not-a-file")
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := securewipe.File(sub); err == nil {
			t.Error("securewipe.File returned nil for something it could not wipe")
		}
	})

	t.Run("a lease directory that cannot be emptied", func(t *testing.T) {
		if err := securewipe.Dir(dir); err == nil {
			t.Error("securewipe.Dir returned nil while the directory was still on disk")
		}
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("the directory should still be there — that is what makes it worth reporting: %v", err)
		}
	})

	t.Run("a successful wipe leaves no plaintext", func(t *testing.T) {
		clean := filepath.Join(t.TempDir(), securewipe.LeaseDirPrefix+"clean")
		if err := os.Mkdir(clean, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		file := filepath.Join(clean, "token")
		if err := os.WriteFile(file, []byte(leasedCredential), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		// A handle held across the wipe sees what is genuinely left on the
		// filesystem after the directory entry goes.
		witness, err := os.Open(file)
		if err != nil {
			t.Fatalf("open witness: %v", err)
		}
		defer witness.Close()

		if err := securewipe.Dir(clean); err != nil {
			t.Fatalf("Dir: %v", err)
		}
		buf := make([]byte, len(leasedCredential))
		if _, err := witness.ReadAt(buf, 0); err != nil {
			t.Fatalf("read through witness: %v", err)
		}
		if strings.Contains(string(buf), "ghp_") {
			t.Errorf("the credential is still readable after the wipe: %q", buf)
		}
	})
}

// TestMaterializedLeaseLeavesADurableTraceForTheNextHub is the third failure
// mode: cleanup that only exists in the memory of the process that scheduled it.
//
// The hub's wipe rode an unguarded `go` statement and the TTL janitor swept an
// in-memory registry. Both die with the process. A hub killed between
// materialising a lease and wiping it — a deploy, an OOM kill, a panic — left a
// credential directory that its successor could not even enumerate. /dev/shm is
// tmpfs and clears on reboot, but a process restart is the common case and
// clears nothing.
//
// The fix is a write-ahead row: the directory is *named* before it is created,
// the row goes in, and only then does plaintext appear. This asserts the
// ordering holds — that a path can be recorded before anything exists at it.
func TestMaterializedLeaseLeavesADurableTraceForTheNextHub(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer db.Close()

	leaseDir, err := secretbroker.NewLeaseDirPath(dir)
	if err != nil {
		t.Fatalf("NewLeaseDirPath: %v", err)
	}
	// The whole point of splitting naming from creation: at this instant there
	// is a path and no plaintext, which is the only ordering in which the
	// record can be guaranteed to precede the secret.
	if _, err := os.Stat(leaseDir); !os.IsNotExist(err) {
		t.Fatalf("%s already exists; the record could not precede the plaintext", leaseDir)
	}
	if !securewipe.IsLeaseDir(leaseDir) {
		t.Fatalf("%s does not carry the lease prefix, so no wipe path would recognise it", leaseDir)
	}

	if err := db.PutSecretLeaseDir(statedb.SecretLeaseDirRow{
		Dir:       leaseDir,
		LeaseID:   "lease_conformance",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("record lease dir: %v", err)
	}

	// A fresh handle stands in for the successor process: it shares no memory
	// with whatever recorded the row, which is precisely the condition under
	// which the old code was blind.
	successor, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("reopen state db: %v", err)
	}
	defer successor.Close()

	rows, err := successor.ListSecretLeaseDirs()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found bool
	for _, row := range rows {
		if row.Dir == leaseDir {
			found = true
			if row.LeaseID != "lease_conformance" {
				t.Errorf("lease id = %q, want lease_conformance", row.LeaseID)
			}
		}
	}
	if !found {
		t.Fatalf("a restarted hub cannot see the credential directory its predecessor created;\n"+
			"there is nothing to reconcile %s against and the plaintext is unreachable forever", leaseDir)
	}

	// And the record carries no credential. It says where plaintext is, never
	// what it is — otherwise the trace fixing one leak would open another.
	for _, row := range rows {
		blob := row.Dir + row.LeaseID + row.ExecutorID + row.ProjectPath
		if strings.Contains(blob, "ghp_") || strings.Contains(blob, leasedCredential) {
			t.Errorf("the lease-directory record contains credential material: %+v", row)
		}
	}
}
