package agent

// secretfiles.go places a secret lease's credential files on this device.
//
// # What arrives, and what does not
//
// A lease delivers three shapes of material. Environment variables ride in
// Spec.Env and need nothing done to them. Host paths to bind are meaningless
// here — this device shares no filesystem with the control plane. Files were
// the gap: until protocol v6 the hub wrote them into its own /dev/shm and put
// the resulting paths into Spec.Env, which is a delivery only for a workload
// running on the hub. On an edge device the harness started with
// GIT_CONFIG_GLOBAL, KUBECONFIG and CLOOP_LEASE_DIR all naming a directory
// nothing had ever created, and a repository-scoped github_pat — whose whole
// enforcement *is* those files — arrived with no token behind it.
//
// So the bytes now travel in the start frame (see remote.StartPayload
// .SecretFiles) and this file writes them.
//
// # Why the hub's directory is a declaration, not an instruction
//
// The Dir the hub sends is where the *workload* expects the file, because the
// broker has already baked it into the environment. It is emphatically not a
// place this device agrees to write to. In this system's threat model the
// control plane is a party that can be compromised (see the confinement note at
// the top of vault.go: the agent is the last line of defence for the device),
// and honouring an arbitrary absolute path from a frame would hand a
// compromised hub a file-write primitive on every enrolled machine —
// start{secret_files:[{dir:"/etc", name:"ld.so.preload"}]}.
//
// So the agent picks a directory of its own, under a tmpfs where one exists,
// named with the cloop-lease- prefix, and then calls Spec.RelocateSecrets to
// move the environment onto it. Relocation is not cosmetic: vault.bind indexes
// Spec.Secrets[].Dir and .Files for revocation, and a revoke naming a path this
// agent never wrote is a revoke that silently does nothing.
//
// # What the device ends up with
//
//	/dev/shm/cloop-lease-XXXXXX/            0700, this agent's own
//	                          └── token     0600 (or whatever the grant said)
//
//	Spec.Env:            CLOOP_LEASE_DIR=/dev/shm/cloop-lease-XXXXXX
//	Spec.Secrets[0].Dir: /dev/shm/cloop-lease-XXXXXX
//
// rather than the hub's nominal /run/cloop/cloop-lease-<hex>, which exists on
// no machine at all.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// secretTmpfsCandidates are checked in order for a memory-backed directory to
// hold credential files.
//
// The probe mirrors pkg/secretbroker's leaseBaseDir deliberately rather than
// calling it: that package must not be dragged onto an edge binary (see the
// note on leaseDirPrefix in vault.go — a device carries no secret store, and
// importing the broker for a directory-selection helper would ship the whole
// thing). The reasoning it encodes is worth repeating: on tmpfs the plaintext
// never reaches a block device, so it cannot survive into a block some later
// reader sees. os.TempDir() is the fallback for macOS and for containers with
// no /dev/shm, where the wipe is the only thing carrying the guarantee.
var secretTmpfsCandidates = []string{"/dev/shm"}

// placedSecrets is what one workload's credential files became on this device,
// and the means to take them back.
type placedSecrets struct {
	// dirs are the lease directories this agent created, for teardown.
	dirs []string
	// files are the absolute paths written, in the order they were written.
	files []string
}

// paths returns what was written, for a test or a diagnostic. Nil-safe so it
// can be called on a workload that leased nothing.
func (p *placedSecrets) paths() []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.files...)
}

// wipe zeroes and unlinks everything this placement created.
//
// It reuses vault.go's wipeCredentialFile and removeLeaseDir rather than
// reimplementing the unlink, so the confinement rule ("only inside a
// cloop-lease-* directory, never through a symlink") has one implementation on
// this device and applies whether the material is being taken back by a
// revocation or dropped because the workload finished.
//
// Errors are reported through logf and not returned: every caller is a teardown
// path with nobody left to hand a failure to, and the one thing worse than a
// noisy wipe failure is a silent one. It is idempotent and safe on nil, so it
// can sit in a defer beside an explicit call.
func (p *placedSecrets) wipe(logf func(string, ...any)) {
	if p == nil {
		return
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	for _, path := range p.files {
		if err := wipeCredentialFile(path); err != nil {
			logf("warning: %v", err)
		}
	}
	for _, dir := range p.dirs {
		if err := removeLeaseDir(dir); err != nil {
			logf("warning: %v", err)
		}
	}
	p.files = nil
	p.dirs = nil
}

// materializeSecretFiles writes a start frame's credential files into
// directories this agent owns and points the Spec at them.
//
// spec is rewritten in place: Env values, Secrets[].Dir and Secrets[].Files all
// move from the hub's nominal directory to the real one. The caller must do
// this *before* vault.bind, or the vault indexes paths that do not exist and a
// later revoke reports success having deleted nothing.
//
// A failure part-way through wipes what was already written before returning,
// so a refused start never leaves plaintext on the device.
func (a *Agent) materializeSecretFiles(spec *executor.Spec, files []executor.SecretFile) (*placedSecrets, error) {
	if len(files) == 0 {
		return nil, nil
	}
	// Re-validate on this side of the link. remote.DecodeStart has already
	// checked, but this is the function that turns a name from a frame into a
	// filesystem write, and a check at the point of the write is the one that
	// cannot be skipped by a future call path — or by a hub that is not the one
	// we think it is.
	if err := executor.ValidateSecretFiles(files); err != nil {
		return nil, fmt.Errorf("agent: refusing this workload's credential files: %w", err)
	}

	placed := &placedSecrets{}
	base := secretFileBase()
	// One directory per distinct declared directory. A lease produces exactly
	// one; two leases on one workload produce two, and they must stay separate
	// or revoking either would take both.
	actual := make(map[string]string, len(files))
	for _, declared := range executor.SecretFileDirs(files) {
		dir, err := os.MkdirTemp(base, leaseDirPrefix)
		if err != nil {
			placed.wipe(a.cfg.logf)
			return nil, fmt.Errorf("agent: create lease directory under %s: %w", base, err)
		}
		placed.dirs = append(placed.dirs, dir)
		actual[declared] = dir
		// 0700 asserted rather than assumed: MkdirTemp already creates it that
		// way, but a directory that is traversable for even an instant is one in
		// which a file created inside it is reachable, whatever the file's own
		// mode.
		if err := os.Chmod(dir, 0o700); err != nil {
			placed.wipe(a.cfg.logf)
			return nil, fmt.Errorf("agent: secure lease directory %s: %w", dir, err)
		}
	}

	for _, f := range files {
		path := filepath.Join(actual[f.Dir], f.Name)
		// O_EXCL through WriteFile's create: the directory was made by
		// MkdirTemp a moment ago and is 0700, so nothing can be there already,
		// and a name that collided would mean two files claiming one path —
		// which ValidateSecretFiles has already refused.
		if err := os.WriteFile(path, f.Content, f.FileMode()); err != nil {
			placed.wipe(a.cfg.logf)
			return nil, fmt.Errorf("agent: write credential file %s: %w", f.Name, err)
		}
		// Recorded before the mode is asserted so a failure below still wipes a
		// file that exists.
		placed.files = append(placed.files, path)
		// WriteFile honours the mode only when it creates the file, and the
		// process umask trims it either way — so the mode the grant asked for is
		// asserted afterwards rather than trusted to the create.
		if err := os.Chmod(path, f.FileMode()); err != nil {
			placed.wipe(a.cfg.logf)
			return nil, fmt.Errorf("agent: set mode on credential file %s: %w", f.Name, err)
		}
	}

	// Move the workload's view onto what was actually written. Without this the
	// harness reads the hub's nominal path — the exact failure this whole file
	// exists to remove, moved one hop — and the vault indexes it for a
	// revocation that could never find anything.
	for declared, dir := range actual {
		spec.RelocateSecrets(declared, dir)
	}
	return placed, nil
}

// secretFileBase picks the parent directory for lease directories, preferring a
// tmpfs. See secretTmpfsCandidates for why, and for why this is a copy of the
// broker's probe rather than a call to it.
func secretFileBase() string {
	for _, cand := range secretTmpfsCandidates {
		info, err := os.Stat(cand)
		if err != nil || !info.IsDir() {
			continue
		}
		// Confirm writability rather than assuming it: a hardened image may
		// mount /dev/shm read-only or noexec.
		probe, err := os.CreateTemp(cand, ".cloop-probe-")
		if err != nil {
			continue
		}
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
		return cand
	}
	return os.TempDir()
}

// describeSecretFiles summarises a placement for the device's own log.
//
// It names paths and counts and nothing else. A device journal is exactly the
// kind of place a credential outlives everything that was supposed to bound its
// lifetime, so the log line that proves the files landed must not be the thing
// that publishes them.
func describeSecretFiles(placed *placedSecrets) string {
	if placed == nil || len(placed.files) == 0 {
		return "no credential files"
	}
	names := make([]string, 0, len(placed.files))
	for _, p := range placed.files {
		names = append(names, filepath.Base(p))
	}
	return fmt.Sprintf("%d credential file(s) [%s] in %s",
		len(placed.files), strings.Join(names, ", "), strings.Join(placed.dirs, ", "))
}
