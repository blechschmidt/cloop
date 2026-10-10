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
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/securewipe"
)

// leaseDirPrefix is the name prefix secretbroker gives every lease directory.
//
// It comes from pkg/securewipe rather than from the broker: pkg/executor/agent
// must build for a device that carries no secret store, and importing the
// broker for one string constant would drag the whole thing onto every edge
// binary. A leaf package both sides can depend on gets the shared constant
// without the shared weight — and without the risk that two hand-copied
// literals drift, which would silently turn every revocation on this device
// into a refusal.
const leaseDirPrefix = securewipe.LeaseDirPrefix

// heldLease is one lease's material as this device sees it.
//
// The material is kept per grant (Task 20403). A lease carries every grant its
// project holds, and a revocation can name one of them: an operator revoking a
// GitHub PAT has not revoked the kubeconfig delivered beside it. The vault used
// to fold every grant into one record that remembered only the first grant's
// ID, so a revocation naming the first grant took back all of them and one
// naming any other was answered "not held" — leaving the revoked credential on
// the device while the hub was told it was not there.
type heldLease struct {
	leaseID string
	// grants is the material, by grant ID. A binding that named no grant —
	// sent by a hub that predates per-grant attribution — is filed under "",
	// and makes any revocation of the lease take all of it back: material that
	// cannot be told apart cannot be returned in part.
	grants map[string]*heldGrant
	// dir is the lease directory, removed once its files are gone.
	dir string
	// handles are the workloads started with this material.
	handles map[string]struct{}
}

// heldGrant is one grant's share of a held lease.
type heldGrant struct {
	grantID string
	name    string
	kind    string
	// envKeys are the variables this grant contributed, by name.
	envKeys []string
	// files are the credential files, already filtered to those this device
	// is willing to touch (see confinement above). Paths the hub named but
	// the agent refuses are kept in refused so the ack can report them.
	files   []string
	refused []string
	// egress marks a grant that also opened a network path.
	egress bool
	// scrubbed records that the material has already been taken back, so a
	// replayed revocation is idempotent rather than reporting a second,
	// emptier success.
	scrubbed bool
}

// liveFiles returns the credential files of the grants not yet taken back.
func (h *heldLease) liveFiles() []string {
	var out []string
	for _, g := range h.sortedGrants() {
		if !g.scrubbed {
			out = append(out, g.files...)
		}
	}
	return out
}

// allScrubbed reports whether every grant of the lease was taken back.
func (h *heldLease) allScrubbed() bool {
	for _, g := range h.grants {
		if !g.scrubbed {
			return false
		}
	}
	return true
}

// sortedGrants returns the grants in grant-ID order, so a scrub walks them
// deterministically.
func (h *heldLease) sortedGrants() []*heldGrant {
	ids := make([]string, 0, len(h.grants))
	for id := range h.grants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*heldGrant, 0, len(ids))
	for _, id := range ids {
		out = append(out, h.grants[id])
	}
	return out
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
	// owned is, per handle, the credential files this agent itself placed for
	// it (materializeSecretFiles). A refresh may replace only these: a binding
	// is the hub's claim about which paths a lease covers, and a hub that is
	// compromised could claim another workload's files (Task 20375).
	owned map[string]map[string]struct{}
	// retired is a bounded FIFO of lease IDs whose material this agent has
	// already destroyed, so a later revocation can be logged as the no-op it
	// genuinely is rather than as one that found nothing. See retire.
	retired []string
}

func newVault() *vault {
	return &vault{leases: make(map[string]*heldLease), owned: make(map[string]map[string]struct{})}
}

// own records the files this agent placed for handleID.
func (v *vault) own(handleID string, paths []string) {
	if len(paths) == 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	set := v.owned[handleID]
	if set == nil {
		set = make(map[string]struct{}, len(paths))
		v.owned[handleID] = set
	}
	for _, p := range paths {
		set[filepath.Clean(p)] = struct{}{}
	}
}

// ownsLocked reports whether path is a file this agent placed for one of
// held's workloads. Callers hold v.mu.
func (v *vault) ownsLocked(held *heldLease, path string) bool {
	clean := filepath.Clean(path)
	for h := range held.handles {
		if _, ok := v.owned[h][clean]; ok {
			return true
		}
	}
	return false
}

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
			held = &heldLease{leaseID: id, grants: make(map[string]*heldGrant), handles: make(map[string]struct{})}
			v.leases[id] = held
		}
		grantID := strings.TrimSpace(b.GrantID)
		g, ok := held.grants[grantID]
		if !ok {
			g = &heldGrant{grantID: grantID}
			held.grants[grantID] = g
		}
		g.name = firstNonEmpty(g.name, b.SecretName)
		g.kind = firstNonEmpty(g.kind, b.Kind)
		g.egress = g.egress || b.Egress
		g.envKeys = mergeStrings(g.envKeys, b.EnvKeys)
		accepted, refused := partitionLeaseFiles(b.Files)
		g.files = mergeStrings(g.files, accepted)
		g.refused = mergeStrings(g.refused, refused)
		// A grant re-delivered after a scrub is live material again: a
		// renewal legitimately re-issues the same lease ID, and leaving the
		// flag set would make the next revocation a no-op that reports
		// success.
		g.scrubbed = false
		held.dir = firstNonEmpty(held.dir, b.Dir)
		held.handles[handleID] = struct{}{}
		v.unretire(id)
	}
}

// release retires a finished workload and destroys any material that went with
// it. A lease with no workloads left is wiped and dropped.
//
// The wipe is the point, and its absence was a real hole. "Its material went
// with the process that held it" was true of environment variables and false
// of files: release used to delete map entries and nothing else, so the only
// path that ever reached wipeCredentialFile was an explicit revoke frame. A
// task that simply *finished* — overwhelmingly the common case — left its
// credential files on the device, and because the lease was then forgotten a
// later revoke answered "not known" and still wiped nothing. The plaintext of
// every credential the device had ever been handed accumulated in /dev/shm
// until the machine rebooted.
//
// Destruction goes through the same scrubLocked as revocation, so the two are
// idempotent with respect to each other in both orders: a revoke that already
// wiped leaves scrubbed set and this does nothing, and a release that wiped
// first means a later revoke has nothing left to find.
//
// The returned reports name what was destroyed, so the caller can log a
// failure. Callers must not ignore them — a wipe that failed is a credential
// still on disk, and that is precisely the thing this system may not discover
// silently.
func (v *vault) release(handleID string) []scrubReport {
	v.mu.Lock()
	defer v.mu.Unlock()

	var reports []scrubReport
	delete(v.owned, handleID)
	for id, held := range v.leases {
		delete(held.handles, handleID)
		if len(held.handles) > 0 {
			continue
		}
		// Last holder gone: the credential has no legitimate reader left, so
		// take it back now rather than waiting for a revocation that may never
		// come. scrubEnv is nil because the workload is finished — there is no
		// live environment to scrub, and the driver's copy goes with the
		// handle.
		report := v.scrubLocked(held, held.sortedGrants(), true, nil)
		report.LeaseID = id
		if report.FilesRemoved > 0 || len(report.Errors) > 0 {
			reports = append(reports, report)
		}
		delete(v.leases, id)
		v.retire(id)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].LeaseID < reports[j].LeaseID })
	return reports
}

// maxRetiredLeases bounds the memory the tombstone list can take. A long-lived
// agent runs thousands of tasks, and remembering every lease it has ever
// destroyed would be an unbounded leak in a process that is meant to sit on a
// small device for months.
const maxRetiredLeases = 64

// retire records that a lease's material was destroyed here.
//
// It exists for the diagnostic, not for the protocol. A revoke for a lease that
// finished normally is answered Known=false, which the hub relies on to
// distinguish "this agent never had it" from "this agent scrubbed it" (see
// pkg/executor/remote/revoke.go) — so that answer must not change. What the
// tombstone buys is an accurate line in the device's own log: "already
// destroyed when its workload exited" rather than "not held by this agent",
// which reads like the revocation missed.
//
// Caller holds v.mu.
func (v *vault) retire(leaseID string) {
	for _, id := range v.retired {
		if id == leaseID {
			return
		}
	}
	v.retired = append(v.retired, leaseID)
	if len(v.retired) > maxRetiredLeases {
		v.retired = v.retired[len(v.retired)-maxRetiredLeases:]
	}
}

// wasRetired reports whether this agent destroyed the lease's material on the
// normal exit path. Best-effort: the list is bounded, so a false answer means
// "not recently", not "never".
func (v *vault) wasRetired(leaseID string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, id := range v.retired {
		if id == leaseID {
			return true
		}
	}
	return false
}

// unretire drops a tombstone because the lease is live material again. A
// renewal legitimately re-issues the same lease ID, and a stale tombstone would
// make the device log a genuine revocation as a no-op.
//
// Caller holds v.mu.
func (v *vault) unretire(leaseID string) {
	for i, id := range v.retired {
		if id == leaseID {
			v.retired = append(v.retired[:i], v.retired[i+1:]...)
			return
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
	// LeaseID is set by release, which scrubs leases the caller did not name.
	// A revoke already knows which lease it asked about.
	LeaseID       string
	Known         bool
	EnvKeys       []string
	FilesRemoved  int
	EgressDropped bool
	Handles       []string
	Errors        []string
}

// scrub invalidates one lease's material and reports what it reached.
//
// grantID narrows the scrub to a single grant within the lease; empty takes the
// whole lease back. The narrowing is exact (Task 20403): only that grant's
// files are wiped and only its variables dropped, and the lease directory stays
// while another grant's files are still in it. A lease that does not carry the
// named grant is answered Known=false — its material is not here — unless some
// of its material was bound without a grant ID, which cannot be told apart from
// the revoked grant's and is taken back whole: over-scrubbing costs a task a
// credential it may still have been entitled to, and under-scrubbing leaves a
// revoked one live. The first is recoverable by the next dispatch, the second
// is not.
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
	g := strings.TrimSpace(grantID)
	if g == "" {
		return v.scrubLocked(held, held.sortedGrants(), true, scrubEnv)
	}
	if target, ok := held.grants[g]; ok {
		return v.scrubLocked(held, []*heldGrant{target}, false, scrubEnv)
	}
	if _, unattributed := held.grants[""]; unattributed {
		return v.scrubLocked(held, held.sortedGrants(), true, scrubEnv)
	}
	return scrubReport{Known: false}
}

// scrubLocked destroys targets — grants of one held lease — and reports what
// it reached. Caller holds v.mu.
//
// It is shared by scrub (an operator or the TTL janitor taking a credential
// back) and release (a workload finishing normally), which is the whole reason
// it is a separate function: those two were different code paths, only one of
// them wiped anything, and the one that ran on every task was the one that did
// not. A single body means a future change to what "destroyed" means cannot
// apply to revocation and miss the ordinary exit.
//
// wholeLease removes the lease directory too. Otherwise it goes only once no
// grant's file is left in it.
func (v *vault) scrubLocked(held *heldLease, targets []*heldGrant, wholeLease bool, scrubEnv envScrubber) scrubReport {
	report := scrubReport{Known: true}
	for h := range held.handles {
		report.Handles = append(report.Handles, h)
	}
	sort.Strings(report.Handles)

	var envKeys []string
	for _, g := range targets {
		report.EgressDropped = report.EgressDropped || g.egress
		envKeys = mergeStrings(envKeys, g.envKeys)
	}

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
			report.EnvKeys = mergeStrings(report.EnvKeys, scrubEnv(handleID, envKeys))
		}
	}

	for _, g := range targets {
		if g.scrubbed {
			// Already taken back. Report the same outcome rather than a
			// hollow success: a replayed revocation after a reconnect must be
			// idempotent, and telling the hub "nothing to do" would look like
			// the first attempt had failed.
			continue
		}
		for _, path := range g.files {
			if err := wipeCredentialFile(path); err != nil {
				report.Errors = append(report.Errors, err.Error())
				continue
			}
			report.FilesRemoved++
		}
		for _, path := range g.refused {
			report.Errors = append(report.Errors, fmt.Sprintf(
				"refused to remove %s: it is not inside a %s* directory this agent recognises "+
					"as lease-owned, so the control plane may not ask this device to unlink it",
				path, leaseDirPrefix))
		}
		g.scrubbed = true
	}
	if held.dir != "" && (wholeLease || held.allScrubbed()) {
		if err := removeLeaseDir(held.dir); err != nil {
			report.Errors = append(report.Errors, err.Error())
		}
	}
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
// The overwrite itself lives in pkg/securewipe, shared with the hub's
// secretbroker. It used to be duplicated verbatim in both, and both copies
// discarded every error the overwrite could produce: an open, WriteAt or Sync
// failure still returned nil, so a caller was told the bytes were zeroed when
// only the name had been removed. What stays here is the confinement — the
// part that is this device's own policy and must not be shared with the party
// supplying the paths.
func wipeCredentialFile(path string) error {
	if err := checkLeaseOwned(path); err != nil {
		return err
	}
	if err := securewipe.File(path); err != nil {
		return fmt.Errorf("agent: wipe credential %s: %w", path, err)
	}
	return nil
}

// removeLeaseDir wipes and removes a lease directory.
//
// securewipe.Dir zeroes any file still in it before unlinking the directory —
// which matters because the tracked file list covers what the *hub* delivered,
// and a harness that wrote its own credential there (a git helper's scratch
// file, a kubectl cache) is exactly the material nothing else would catch. It
// refuses to recurse and refuses a directory not named cloop-lease-*, so a
// control plane still cannot turn this into a recursive-delete primitive.
func removeLeaseDir(dir string) error {
	if err := securewipe.Dir(dir); err != nil {
		return fmt.Errorf("agent: clear lease directory %s: %w", dir, err)
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
func isLeaseDirName(dir string) bool { return securewipe.IsLeaseDir(dir) }

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
