package agent

// Vault tests: attribution, confinement, idempotence, and the race between a
// task reading its credential and the control plane taking it away.
//
// The race is the interesting one. Revocation is by definition concurrent with
// the work it interrupts — that is the entire point of pushing it instead of
// waiting for the task to exit — so every path that touches held material has
// to be safe against every other one. These run under `go test -race`.

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// leaseDir creates a directory named the way secretbroker.Materialize names
// one, with a credential file in it. Anything else is outside the vault's
// confinement rule and would be refused — which is the subject of its own
// test, not an accident to stumble into here.
func leaseDir(t *testing.T, name string) (dir, file string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), leaseDirPrefix+name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir lease dir: %v", err)
	}
	file = filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("ghp_secret"), 0o600); err != nil {
		t.Fatalf("write credential: %v", err)
	}
	return dir, file
}

func binding(leaseID, dir, file string) executor.SecretBinding {
	return executor.SecretBinding{
		LeaseID:    leaseID,
		GrantID:    "grant_1",
		SecretName: "github-ci",
		Kind:       "github_pat",
		EnvKeys:    []string{"GITHUB_TOKEN", "GITHUB_TOKEN_FILE"},
		Files:      []string{file},
		Dir:        dir,
	}
}

// TestVaultScrubRemovesCredentialFile is the base case: the material named by
// a binding is gone from disk after a scrub, and the ack says so.
func TestVaultScrubRemovesCredentialFile(t *testing.T) {
	dir, file := leaseDir(t, "abc")
	v := newVault()
	v.bind("handle-1", []executor.SecretBinding{binding("lease_abc", dir, file)})

	report := v.scrub("lease_abc", "", func(_ string, keys []string) []string { return keys })

	if !report.Known {
		t.Fatal("the vault was holding this lease and must say so")
	}
	if report.FilesRemoved != 1 {
		t.Errorf("files_removed = %d, want 1 (errors: %v)", report.FilesRemoved, report.Errors)
	}
	if len(report.Errors) != 0 {
		t.Errorf("unexpected scrub errors: %v", report.Errors)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("credential file should be unlinked; Stat err = %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("emptied lease directory should be removed; Stat err = %v", err)
	}
	if !contains(report.EnvKeys, "GITHUB_TOKEN") {
		t.Errorf("env keys = %v, want GITHUB_TOKEN", report.EnvKeys)
	}
}

// TestVaultScrubZeroesBeforeUnlinking checks that the bytes are overwritten
// rather than merely unlinked.
//
// On a tmpfs the pages are freed either way, but a lease directory falls back
// to os.TempDir() where it is not, and there an unlinked credential survives
// in whatever blocks are reused next. The zeroing is verified through a second
// hard link, which is the only way to look at the bytes after the name is gone.
func TestVaultScrubZeroesBeforeUnlinking(t *testing.T) {
	dir, file := leaseDir(t, "zero")
	peek := filepath.Join(t.TempDir(), "peek")
	if err := os.Link(file, peek); err != nil {
		t.Skipf("hard links unavailable here: %v", err)
	}

	v := newVault()
	v.bind("handle-1", []executor.SecretBinding{binding("lease_zero", dir, file)})
	v.scrub("lease_zero", "", nil)

	body, err := os.ReadFile(peek)
	if err != nil {
		t.Fatalf("read through the surviving link: %v", err)
	}
	if strings.Contains(string(body), "ghp_secret") {
		t.Errorf("the credential's bytes survived the scrub: %q", body)
	}
}

// TestVaultRefusesPathsOutsideALeaseDirectory is the confinement rule.
//
// The paths in a binding come from the control plane, which this system's
// threat model treats as a party that can be compromised. Honouring them
// literally would make the revoke frame an arbitrary-unlink primitive on every
// enrolled device.
func TestVaultRefusesPathsOutsideALeaseDirectory(t *testing.T) {
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "shadow")
	if err := os.WriteFile(victim, []byte("root:x:"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	v := newVault()
	v.bind("handle-1", []executor.SecretBinding{{
		LeaseID: "lease_evil",
		EnvKeys: []string{"X"},
		Files:   []string{victim, "/etc/shadow", "relative/path", ""},
		Dir:     victimDir,
	}})

	report := v.scrub("lease_evil", "", nil)

	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("a path outside a lease directory was unlinked: %v", err)
	}
	if report.FilesRemoved != 0 {
		t.Errorf("files_removed = %d, want 0", report.FilesRemoved)
	}
	// Reported, not silently skipped: an operator who thinks a credential file
	// was removed and finds out otherwise during an incident is worse off than
	// one who was told.
	if len(report.Errors) == 0 {
		t.Error("refusals must be reported in the ack")
	}
	for _, e := range report.Errors {
		if !strings.Contains(e, "refused") {
			t.Errorf("refusal should say so: %q", e)
		}
	}
}

// TestVaultDoesNotFollowSymlinks: a link planted inside a lease directory must
// not redirect the wipe through it onto the target.
func TestVaultDoesNotFollowSymlinks(t *testing.T) {
	dir, file := leaseDir(t, "link")
	_ = os.Remove(file)

	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, file); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	v := newVault()
	v.bind("handle-1", []executor.SecretBinding{binding("lease_link", dir, file)})
	v.scrub("lease_link", "", nil)

	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("the symlink target was destroyed: %v", err)
	}
	if string(body) != "untouched" {
		t.Errorf("the wipe was redirected through a symlink; target = %q", body)
	}
	if _, err := os.Lstat(file); !os.IsNotExist(err) {
		t.Errorf("the link itself should be removed; Lstat err = %v", err)
	}
}

// TestVaultScrubIsIdempotent: a revocation replayed after a reconnect must
// report the same outcome rather than a hollow second success.
func TestVaultScrubIsIdempotent(t *testing.T) {
	dir, file := leaseDir(t, "twice")
	v := newVault()
	v.bind("handle-1", []executor.SecretBinding{binding("lease_twice", dir, file)})

	first := v.scrub("lease_twice", "", nil)
	second := v.scrub("lease_twice", "", nil)

	if first.FilesRemoved != 1 {
		t.Errorf("first scrub removed %d files, want 1", first.FilesRemoved)
	}
	if !second.Known {
		t.Error("a replayed revocation must still report the lease as known")
	}
	if len(second.Errors) != 0 {
		t.Errorf("a replayed revocation must not report errors: %v", second.Errors)
	}
}

// TestVaultRebindAfterScrubIsLiveAgain: a renewal legitimately re-issues the
// same lease ID with fresh material, and the next revocation must actually
// scrub it rather than short-circuit on a stale flag.
func TestVaultRebindAfterScrubIsLiveAgain(t *testing.T) {
	dir, file := leaseDir(t, "renew")
	v := newVault()
	b := binding("lease_renew", dir, file)

	v.bind("handle-1", []executor.SecretBinding{b})
	v.scrub("lease_renew", "", nil)

	// Renewal: the same lease, freshly materialised.
	dir2, file2 := leaseDir(t, "renew2")
	b2 := binding("lease_renew", dir2, file2)
	v.bind("handle-1", []executor.SecretBinding{b2})

	report := v.scrub("lease_renew", "", nil)
	if report.FilesRemoved == 0 {
		t.Errorf("a re-delivered lease must be scrubbable again; report = %+v", report)
	}
	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Errorf("the renewed credential should be unlinked; Stat err = %v", err)
	}
}

// TestVaultUnknownLeaseIsNotAnError: "the material is not here" is the end
// state a revocation wants, so it reports success with Known=false rather than
// failing and inviting a retry.
func TestVaultUnknownLeaseIsNotAnError(t *testing.T) {
	v := newVault()
	report := v.scrub("lease_nobody_has", "", nil)
	if report.Known {
		t.Error("an unheld lease must report Known=false")
	}
	if len(report.Errors) != 0 {
		t.Errorf("an unheld lease is not an error condition: %v", report.Errors)
	}
}

// TestVaultReleaseDropsLeaseWithLastHandle checks the bookkeeping that stops a
// revocation from waiting on an ack about a credential that went with the
// process holding it.
func TestVaultReleaseDropsLeaseWithLastHandle(t *testing.T) {
	dir, file := leaseDir(t, "release")
	v := newVault()
	b := binding("lease_rel", dir, file)
	v.bind("handle-1", []executor.SecretBinding{b})
	v.bind("handle-2", []executor.SecretBinding{b})

	if got := v.handlesFor("lease_rel"); len(got) != 2 {
		t.Fatalf("handlesFor = %v, want two holders", got)
	}
	v.release("handle-1")
	if got := v.handlesFor("lease_rel"); len(got) != 1 || got[0] != "handle-2" {
		t.Errorf("handlesFor = %v, want [handle-2]", got)
	}
	v.release("handle-2")
	if got := v.handlesFor("lease_rel"); len(got) != 0 {
		t.Errorf("a lease with no holders should be dropped entirely; got %v", got)
	}
	if v.scrub("lease_rel", "", nil).Known {
		t.Error("a fully released lease must no longer be reported as held")
	}
}

// TestVaultConcurrentReadAndScrub is the race-detector test.
//
// It models what actually happens in production: tasks starting and finishing
// while an operator (or the TTL janitor, or a cordon) revokes the same lease
// underneath them. Every combination of bind, read, release, and scrub runs
// concurrently against one lease, and the file wipe runs for real so the
// unlink path is inside the critical section under test rather than mocked out
// of it.
//
// Run with -race, this is what catches the failure mode the design has to
// avoid: two revocations both deciding the files exist, or a start binding
// fresh material into a lease that is mid-scrub.
func TestVaultConcurrentReadAndScrub(t *testing.T) {
	const (
		workers = 8
		rounds  = 60
	)
	v := newVault()
	base := t.TempDir()

	// Each round gets its own lease directory, so the wipe has real files to
	// unlink every time rather than short-circuiting on "already gone".
	makeBinding := func(round int) executor.SecretBinding {
		dir := filepath.Join(base, leaseDirPrefix+"race", strings.Repeat("d", 1)+itoa(round))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Errorf("mkdir: %v", err)
			return executor.SecretBinding{}
		}
		// The parent must itself be a lease dir for confinement to accept it.
		leaseSub := filepath.Join(dir, leaseDirPrefix+itoa(round))
		if err := os.MkdirAll(leaseSub, 0o700); err != nil {
			t.Errorf("mkdir: %v", err)
			return executor.SecretBinding{}
		}
		file := filepath.Join(leaseSub, "token")
		if err := os.WriteFile(file, []byte("ghp_secret"), 0o600); err != nil {
			t.Errorf("write: %v", err)
			return executor.SecretBinding{}
		}
		return executor.SecretBinding{
			LeaseID: "lease_race",
			EnvKeys: []string{"GITHUB_TOKEN"},
			Files:   []string{file},
			Dir:     leaseSub,
		}
	}

	// reads counts credential lookups that ran concurrently with a scrub. A
	// non-zero count is what makes this a race test rather than a sequential
	// one that happens to use goroutines.
	var reads atomic.Int64
	scrubEnv := func(handleID string, keys []string) []string {
		reads.Add(1)
		return keys
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				handle := "handle-" + itoa(w)
				switch (w + i) % 4 {
				case 0:
					v.bind(handle, []executor.SecretBinding{makeBinding(w*rounds + i)})
				case 1:
					_ = v.handlesFor("lease_race")
				case 2:
					v.scrub("lease_race", "", scrubEnv)
				case 3:
					v.release(handle)
				}
			}
		}(w)
	}
	wg.Wait()

	// A final scrub must leave nothing behind regardless of how the
	// interleaving fell out.
	v.scrub("lease_race", "", scrubEnv)
	if got := v.handlesFor("lease_race"); len(got) > 0 {
		// Not a failure: a bind may legitimately have won the last race. What
		// matters is that a scrub of it still works and reports cleanly.
		if report := v.scrub("lease_race", "", scrubEnv); len(report.Errors) > 0 {
			t.Errorf("final scrub reported errors: %v", report.Errors)
		}
	}
	if reads.Load() == 0 {
		t.Error("no credential reads were observed; the test did not exercise the race it claims to")
	}
}

// TestPartitionLeaseFilesSplitsByConfinement pins the rule down directly, so a
// future change to the matcher fails here rather than in an e2e test whose
// message would not name the cause.
func TestPartitionLeaseFilesSplitsByConfinement(t *testing.T) {
	accepted, refused := partitionLeaseFiles([]string{
		"/dev/shm/cloop-lease-abc/token",
		"/tmp/cloop-lease-xyz/kubeconfig",
		"/etc/shadow",
		"/tmp/not-a-lease/token",
		// The bare prefix with nothing after it is not a lease directory —
		// otherwise a hub could name /tmp/cloop-lease-/x and slip through.
		"/tmp/cloop-lease-/token",
		"relative/token",
		"",
	})
	if len(accepted) != 2 {
		t.Errorf("accepted = %v, want the two paths inside lease directories", accepted)
	}
	if len(refused) != 4 {
		t.Errorf("refused = %v, want the four outside them", refused)
	}
}

// contains is a local helper; the package targets edge devices and pulls in as
// little as it can get away with.
func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// itoa avoids importing strconv into a test file that needs one integer.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestVaultReleaseWipesCredentialFilesOnNormalExit is the regression test for
// the destruction hole.
//
// wipeCredentialFile was reachable from exactly one place: vault.scrub, called
// only from the hub-initiated revoke frame handler. The normal exit —
// deliverFinal -> forget -> release — deleted map entries and nothing else, so
// a task that simply *finished*, which is what almost every task does, left its
// credential files on the device. Worse, the lease was then forgotten, so a
// later revoke reported "not known" and still wiped nothing: the plaintext of
// every credential the device had ever been handed accumulated in /dev/shm
// until the machine rebooted.
//
// No revoke frame appears anywhere in this test. That is the point.
func TestVaultReleaseWipesCredentialFilesOnNormalExit(t *testing.T) {
	dir, file := leaseDir(t, "normal-exit")
	v := newVault()
	v.bind("handle-1", []executor.SecretBinding{binding("lease_exit", dir, file)})

	reports := v.release("handle-1")

	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the credential file survived a normal task exit: %v\n"+
			"only an explicit revocation used to destroy it, so a device accumulated "+
			"the plaintext of every credential it had ever run with", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the lease directory survived a normal task exit: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("release reported %d leases, want 1: the caller has to be able to log a failed wipe", len(reports))
	}
	if reports[0].LeaseID != "lease_exit" {
		t.Errorf("report names lease %q, want lease_exit", reports[0].LeaseID)
	}
	if reports[0].FilesRemoved != 1 {
		t.Errorf("FilesRemoved = %d, want 1", reports[0].FilesRemoved)
	}
	if len(reports[0].Errors) != 0 {
		t.Errorf("unexpected errors: %v", reports[0].Errors)
	}
}

// TestVaultReleaseWipesOnlyWhenTheLastHolderGoes guards against the opposite
// mistake. Two workloads can share one lease, and destroying its files when the
// first finishes would pull the credential out from under the second.
func TestVaultReleaseWipesOnlyWhenTheLastHolderGoes(t *testing.T) {
	dir, file := leaseDir(t, "shared")
	v := newVault()
	b := binding("lease_shared", dir, file)
	v.bind("handle-1", []executor.SecretBinding{b})
	v.bind("handle-2", []executor.SecretBinding{b})

	if reports := v.release("handle-1"); len(reports) != 0 {
		t.Errorf("release of one of two holders destroyed material: %+v", reports)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("the credential must survive while another workload holds it: %v", err)
	}

	v.release("handle-2")
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the credential survived the last holder's exit: %v", err)
	}
}

// TestVaultReleaseAndScrubAreIdempotentInBothOrders is the "make release
// idempotent with scrub" half of the fix. The two paths run the same
// scrubLocked body, so neither can double-wipe, report a hollow success, or
// leave the other with work it silently skips.
func TestVaultReleaseAndScrubAreIdempotentInBothOrders(t *testing.T) {
	t.Run("scrub then release", func(t *testing.T) {
		dir, file := leaseDir(t, "scrub-first")
		v := newVault()
		v.bind("handle-1", []executor.SecretBinding{binding("lease_a", dir, file)})

		if report := v.scrub("lease_a", "", nil); report.FilesRemoved != 1 {
			t.Fatalf("scrub removed %d files, want 1: %v", report.FilesRemoved, report.Errors)
		}
		// The files are already gone, so release has nothing to destroy and
		// must not claim otherwise.
		for _, r := range v.release("handle-1") {
			if r.FilesRemoved != 0 {
				t.Errorf("release re-counted %d already-destroyed files", r.FilesRemoved)
			}
			if len(r.Errors) != 0 {
				t.Errorf("release errored over an already-scrubbed lease: %v", r.Errors)
			}
		}
	})

	t.Run("release then scrub", func(t *testing.T) {
		dir, file := leaseDir(t, "release-first")
		v := newVault()
		v.bind("handle-1", []executor.SecretBinding{binding("lease_b", dir, file)})

		v.release("handle-1")
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatalf("release left the credential behind: %v", err)
		}
		// The ack stays Known=false — the hub relies on that to distinguish
		// "this agent never had it" from "this agent scrubbed it" — but the
		// device must be able to say which happened in its own log.
		report := v.scrub("lease_b", "", nil)
		if report.Known {
			t.Error("a released lease must not be reported as still held")
		}
		if !v.wasRetired("lease_b") {
			t.Error("the device should remember it destroyed this lease, so a later " +
				"revoke is logged as a no-op rather than as one that found nothing")
		}
	})
}

// TestVaultRetiredTombstonesAreBounded keeps a long-lived agent from leaking.
// A device runs thousands of tasks over months; remembering every lease it has
// ever destroyed would be an unbounded map on a machine chosen for being small.
func TestVaultRetiredTombstonesAreBounded(t *testing.T) {
	v := newVault()
	for i := 0; i < maxRetiredLeases*3; i++ {
		id := "lease_" + itoa(i)
		handle := "handle-" + itoa(i)
		v.bind(handle, []executor.SecretBinding{{LeaseID: id, GrantID: "g"}})
		v.release(handle)
	}
	v.mu.Lock()
	got := len(v.retired)
	v.mu.Unlock()
	if got > maxRetiredLeases {
		t.Errorf("retired list holds %d entries, cap is %d", got, maxRetiredLeases)
	}
	if !v.wasRetired("lease_" + itoa(maxRetiredLeases*3-1)) {
		t.Error("the most recent destruction should still be remembered")
	}
}

// TestVaultRenewalClearsTheTombstone covers the case that would make the
// diagnostic lie: a renewal legitimately re-issues the same lease ID, and a
// stale tombstone would make a genuine revocation of live material read as
// "already destroyed".
func TestVaultRenewalClearsTheTombstone(t *testing.T) {
	dir, file := leaseDir(t, "renewed")
	v := newVault()
	v.bind("handle-1", []executor.SecretBinding{binding("lease_renew", dir, file)})
	v.release("handle-1")
	if !v.wasRetired("lease_renew") {
		t.Fatal("expected a tombstone after the first exit")
	}

	dir2, file2 := leaseDir(t, "renewed-again")
	v.bind("handle-2", []executor.SecretBinding{binding("lease_renew", dir2, file2)})
	if v.wasRetired("lease_renew") {
		t.Error("re-delivered material is live again; the tombstone must be cleared")
	}
	if report := v.scrub("lease_renew", "", nil); !report.Known {
		t.Error("a renewed lease must be revocable")
	}
	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Errorf("the renewed credential survived revocation: %v", err)
	}
}

// TestVaultReleaseSurfacesAWipeItCouldNotPerform is the "stop swallowing wipe
// errors" contract at the vault level: a credential still on disk must reach
// the caller, which logs it. Silence here is the failure mode the whole task
// exists to remove.
func TestVaultReleaseSurfacesAWipeItCouldNotPerform(t *testing.T) {
	dir, file := leaseDir(t, "unwipeable")
	// A subdirectory inside the lease directory cannot be removed by the
	// confined wipe, which refuses to recurse. It is a deterministic,
	// root-safe way to make the destruction genuinely fail.
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	v := newVault()
	v.bind("handle-1", []executor.SecretBinding{binding("lease_stuck", dir, file)})
	reports := v.release("handle-1")

	if len(reports) != 1 || len(reports[0].Errors) == 0 {
		t.Fatalf("a failed lease-directory wipe was not reported: %+v", reports)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("the directory should still be there — that is what makes it worth reporting: %v", err)
	}
}
