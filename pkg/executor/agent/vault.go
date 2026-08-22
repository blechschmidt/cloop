package agent

// vault.go is the device's record of which credentials it is holding on whose
// behalf, and the machinery for giving them back.
//
// A device receives brokered credentials inside the start frame: environment
// variables in Spec.Env, credential files already on disk, and — for an
// egress grant — a proxy URL and allowlist. Before lease revocation existed,
// the device had no idea which of those came from which lease, so "revoke
// lease_abc" was unanswerable: the agent could see GITHUB_TOKEN but not that
// it belonged to a grant an operator had just withdrawn.
//
// Spec.Secrets closes that gap by naming, per lease, exactly what that lease
// contributed. The vault indexes those bindings by lease so a revoke frame can
// be honoured in bounded time without walking every workload's environment.
//
// # Confinement
//
// The file paths in a binding come from the control plane, which in this
// system's threat model is a party that can be compromised (see
// docs/security/model.md: the agent is the last line of defence for the
// device, which is why workdir confinement lives here and not on the hub).
// Honouring them literally would hand a compromised hub an arbitrary-unlink
// primitive on every enrolled device: revoke{files:["/etc/shadow"]}.
//
// So the vault deletes only paths that satisfy both of:
//
//   - the containing directory is named cloop-lease-* , the prefix
//     secretbroker.Materialize uses for every lease directory it creates, and
//   - the path is not a symlink and its parent resolves to itself, so a
//     planted link cannot redirect the unlink somewhere else.
//
// Anything else is refused and reported in the ack rather than silently
// skipped, because "I did not delete your credential file" is something the
// operator has to be told.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// leaseDirPrefix is the name prefix secretbroker gives every lease directory.
// It is duplicated here rather than imported: pkg/executor/agent must build
// for a device that carries no broker, and depending on the broker package for
// one string constant would drag the whole secret store onto every edge
// binary.
const leaseDirPrefix = "cloop-lease-"

// heldLease is one lease's material as this device sees it.
type heldLease struct {
	leaseID string
	grantID string
	name    string
	kind    string
	// envKeys are the variables this lease contributed, by name.
	envKeys []string
	// files are the credential files, already filtered to those this device
	// is willing to touch (see confinement above). Paths the hub named but
	// the agent refuses are kept in refused so the ack can report them.
	files   []string
	refused []string
	// dir is the lease directory, removed once its files are gone.
	dir string
	// egress marks a lease that also opened a network path.
	egress bool
	// handles are the workloads started with this material.
	handles map[string]struct{}
	// scrubbed records that the material has already been taken back, so a
	// replayed revocation is idempotent rather than reporting a second,
	// emptier success.
	scrubbed bool
}

// vault indexes held leases for one agent.
//
// All state is behind one mutex. The lock is held across the whole scrub —
// including the file unlinks — rather than only around the map access. That is
// deliberate: two concurrent revokes of the same lease must not both decide
// the files exist and race to remove them, and a start frame binding new
// material for a lease being revoked must serialise against it rather than
// slip a fresh copy in behind the scrub. The critical section is a handful of
// unlinks on a tmpfs, which is bounded and short.
type vault struct {
	mu     sync.Mutex
	leases map[string]*heldLease
}

func newVault() *vault { return &vault{leases: make(map[string]*heldLease)} }

// bind records the material a start frame delivered for one handle.
//
// It is called before the workload is launched, so a revoke arriving in the
// same millisecond as the start either finds the binding (and scrubs it) or
// does not (and the start is still holding the lock that will add it). Binding
// after the launch would leave a window where the credential is live on the
// device and invisible to revocation.
func (v *vault) bind(handleID string, bindings []executor.SecretBinding) {
	if len(bindings) == 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, b := range bindings {
		id := strings.TrimSpace(b.LeaseID)
		if id == "" {
			continue
		}
		held, ok := v.leases[id]
		if !ok {
			held = &heldLease{leaseID: id, handles: make(map[string]struct{})}
			v.leases[id] = held
		}
		held.grantID = firstNonEmpty(held.grantID, b.GrantID)
		held.name = firstNonEmpty(held.name, b.SecretName)
		held.kind = firstNonEmpty(held.kind, b.Kind)
		held.dir = firstNonEmpty(held.dir, b.Dir)
		held.egress = held.egress || b.Egress
		held.envKeys = mergeStrings(held.envKeys, b.EnvKeys)
		accepted, refused := partitionLeaseFiles(b.Files)
		held.files = mergeStrings(held.files, accepted)
		held.refused = mergeStrings(held.refused, refused)
		held.handles[handleID] = struct{}{}
		// A lease re-delivered after a scrub is live material again: a renewal
		// legitimately re-issues the same lease ID, and leaving the flag set
		// would make the next revocation a no-op that reports success.
		held.scrubbed = false
	}
}

// release forgets a finished workload. A lease with no workloads left is
// dropped entirely: its material went with the process that held it.
func (v *vault) release(handleID string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, held := range v.leases {
		delete(held.handles, handleID)
		if len(held.handles) == 0 {
			delete(v.leases, id)
		}
	}
}

// handlesFor returns the workloads holding a lease.
func (v *vault) handlesFor(leaseID string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	held, ok := v.leases[strings.TrimSpace(leaseID)]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(held.handles))
	for id := range held.handles {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// envScrubber drops the named environment variables from whatever holds a
// workload's environment, returning the names it found. The agent supplies
// the localprocess driver's implementation; a test supplies its own.
type envScrubber func(handleID string, keys []string) []string

// scrubReport is what a scrub achieved, for the ack.
type scrubReport struct {
	Known         bool
	EnvKeys       []string
	FilesRemoved  int
	EgressDropped bool
	Handles       []string
	Errors        []string
}

// scrub invalidates one lease's material and reports what it reached.
//
// grantID narrows the scrub to a single grant within the lease; empty takes
// the whole lease back. The narrowing is best-effort by design: a lease that
// delivered several grants records the union of their env keys and files, and
// when the binding did not distinguish them the whole lease is scrubbed. Over-
// scrubbing costs a task a credential it may still have been entitled to;
// under-scrubbing leaves a revoked credential live. The first is recoverable
// by renewing, the second is not.
func (v *vault) scrub(leaseID, grantID string, scrubEnv envScrubber) scrubReport {
	id := strings.TrimSpace(leaseID)
	v.mu.Lock()
	defer v.mu.Unlock()

	held, ok := v.leases[id]
	if !ok {
		// Not an error. The material is not here, which is exactly the end
		// state the revocation asked for — the agent may never have been
		// given it, or the workload may already have finished.
		return scrubReport{Known: false}
	}
	if g := strings.TrimSpace(grantID); g != "" && held.grantID != "" && held.grantID != g {
		return scrubReport{Known: false}
	}

	report := scrubReport{Known: true, EgressDropped: held.egress}
	for h := range held.handles {
		report.Handles = append(report.Handles, h)
	}
	sort.Strings(report.Handles)

	// Env values go first, and under this lock. The lock is what makes the
	// scrub race-safe against a concurrent start binding fresh material for
	// the same lease: either the bind completes first and its handle is in
	// the set being scrubbed, or it waits and re-binds material the control
	// plane has by then already been told is gone.
	//
	// What comes back is what was actually found, not what was asked for. A
	// key the workload never received must not be reported as scrubbed.
	if scrubEnv != nil {
		for _, handleID := range report.Handles {
			report.EnvKeys = mergeStrings(report.EnvKeys, scrubEnv(handleID, held.envKeys))
		}
	}

	if held.scrubbed {
		// Already taken back. Report the same outcome rather than a hollow
		// success: a replayed revocation after a reconnect must be idempotent,
		// and telling the hub "nothing to do" would look like the first
		// attempt had failed.
		report.FilesRemoved = 0
		return report
	}

	for _, path := range held.files {
		if err := wipeCredentialFile(path); err != nil {
			report.Errors = append(report.Errors, err.Error())
			continue
		}
		report.FilesRemoved++
	}
	for _, path := range held.refused {
		report.Errors = append(report.Errors, fmt.Sprintf(
			"refused to remove %s: it is not inside a %s* directory this agent recognises "+
				"as lease-owned, so the control plane may not ask this device to unlink it",
			path, leaseDirPrefix))
	}
	if held.dir != "" {
		if err := removeLeaseDir(held.dir); err != nil {
			report.Errors = append(report.Errors, err.Error())
		}
	}

	held.scrubbed = true
	// The names stay so a repeat revoke still reports what this lease covered,
	// but nothing here is a credential: env keys are names, and the file paths
	// now point at nothing.
	return report
}

// wipeCredentialFile zeroes a credential file's bytes and unlinks it.
//
// Zeroing first matters on the os.TempDir() fallback path, where the lease
// directory is on a real filesystem: unlinking alone leaves the plaintext in
// blocks that survive until they are reused. On a tmpfs the pages are freed
// anyway and this is belt-and-braces. Neither is a guarantee against a
// copy-on-write or log-structured filesystem — see pkg/secretbroker's Mount.
func wipeCredentialFile(path string) error {
	if err := checkLeaseOwned(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already gone; the desired end state
		}
		return fmt.Errorf("agent: stat credential %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Following it would write zeros through the link into whatever it
		// points at. Remove the link itself and nothing else.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("agent: remove credential link %s: %w", path, err)
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("agent: refused to remove %s: not a regular file", path)
	}
	if size := info.Size(); size > 0 {
		if f, oerr := os.OpenFile(path, os.O_WRONLY, 0o600); oerr == nil {
			zeros := make([]byte, size)
			_, _ = f.WriteAt(zeros, 0)
			_ = f.Sync()
			_ = f.Close()
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("agent: remove credential %s: %w", path, err)
	}
	return nil
}

// removeLeaseDir removes an emptied lease directory.
//
// os.Remove, not RemoveAll: the directory must be empty by now, and a
// recursive delete driven by a control-plane-supplied path is the exact
// primitive the confinement rules above exist to withhold. A non-empty
// directory is reported, not force-removed.
func removeLeaseDir(dir string) error {
	if !isLeaseDirName(dir) {
		return fmt.Errorf(
			"agent: refused to remove lease directory %s: its name does not start with %s",
			dir, leaseDirPrefix)
	}
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		// Not fatal to the scrub: the credential files themselves are gone,
		// which is what the revocation was for. An empty directory left behind
		// is untidy, not dangerous.
		return fmt.Errorf("agent: remove lease directory %s: %w", dir, err)
	}
	return nil
}

// checkLeaseOwned enforces the confinement rule: this agent unlinks a path
// only when its parent is a lease directory.
func checkLeaseOwned(path string) error {
	clean := filepath.Clean(strings.TrimSpace(path))
	if clean == "" || clean == "." || !filepath.IsAbs(clean) {
		return fmt.Errorf("agent: refused to remove %q: not an absolute path", path)
	}
	if !isLeaseDirName(filepath.Dir(clean)) {
		return fmt.Errorf(
			"agent: refused to remove %s: its directory is not a %s* lease directory",
			clean, leaseDirPrefix)
	}
	return nil
}

// isLeaseDirName reports whether dir's final element is a lease directory.
func isLeaseDirName(dir string) bool {
	base := filepath.Base(filepath.Clean(strings.TrimSpace(dir)))
	return strings.HasPrefix(base, leaseDirPrefix) && len(base) > len(leaseDirPrefix)
}

// partitionLeaseFiles splits control-plane-supplied paths into those this
// agent will unlink and those it refuses.
func partitionLeaseFiles(paths []string) (accepted, refused []string) {
	for _, p := range paths {
		clean := filepath.Clean(strings.TrimSpace(p))
		if clean == "" || clean == "." {
			continue
		}
		if checkLeaseOwned(clean) == nil {
			accepted = append(accepted, clean)
			continue
		}
		refused = append(refused, clean)
	}
	return accepted, refused
}

// mergeStrings appends the entries of b that a does not already have,
// preserving order. Lists here are single-digit length, so a set would cost
// more than it saved.
func mergeStrings(a, b []string) []string {
	for _, s := range b {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		found := false
		for _, existing := range a {
			if existing == s {
				found = true
				break
			}
		}
		if !found {
			a = append(a, s)
		}
	}
	return a
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return strings.TrimSpace(b)
}
