package executor

// secretfile.go carries the *contents* of a secret lease's credential files to
// a driver that has to place them somewhere the control plane cannot reach.
//
// # Why this exists
//
// A lease delivers three shapes of material: environment variables, host paths
// to bind, and files. The first two already had a delivery path for every
// backend. Files did not: the hub wrote them into its own /dev/shm and put the
// resulting paths into Spec.Env and Spec.Secrets[].Dir, which is correct only
// for a workload that runs on the hub's filesystem. A container never mounted
// that directory; the Kubernetes driver ignored it; the remote protocol had no
// frame that could carry a byte of it. So a repo-scoped github_pat — whose
// whole enforcement *is* files (a credential helper, a token file, a gitconfig
// exported through GIT_CONFIG_GLOBAL) — reached an isolated sandbox as an
// environment variable naming a path that did not exist there, with no token
// and no error. git then failed to authenticate for a reason nothing named.
//
// SecretFile is the missing half. A driver that cannot read hub paths is
// handed the bytes and is responsible for placing them at Dir, which is the
// path the environment already points at.
//
// # Why the content is not in SecretBinding
//
// SecretBinding is names and paths only, on purpose: pkg/executorstore
// persists the dispatched Spec, the audit trail echoes it, and reconcile
// re-reads it after a restart. A credential in there would be durable in three
// places within a second of being minted. SecretFile is the opposite kind of
// value — it exists between the broker and one driver call — so it is carried
// on a field tagged json:"-" and every fmt verb on it is redacted. The wire
// formats that legitimately need the bytes (the remote protocol's start frame)
// opt in explicitly with a type of their own, exactly as WorkspaceCredential
// does.

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// MaxSecretFileBytes bounds one credential file. Everything a grant produces
// is a token, a script or a kubeconfig — kilobytes at most. The cap exists so
// a malformed or hostile secret store cannot make a driver allocate, or a
// remote frame carry, an unbounded payload.
const MaxSecretFileBytes = 256 << 10 // 256 KiB

// SecretFile is one credential file plus the directory the workload expects to
// find it in.
//
// Dir is the path *as the workload sees it*, which the broker has already
// baked into the environment (GIT_CONFIG_GLOBAL, KUBECONFIG, CLOOP_LEASE_DIR).
// A driver that can honour it verbatim — a bind mount, a projected volume —
// leaves the environment alone. A driver that must place the files somewhere
// else calls Spec.RelocateSecrets so the environment follows them.
type SecretFile struct {
	// LeaseID and GrantID attribute the file, so a driver can tie what it
	// wrote back to the binding that must later scrub it.
	LeaseID string
	GrantID string
	// Dir is the absolute directory the workload expects the file in.
	Dir string
	// Name is a bare file name: no separators, no "." or "..".
	Name string
	// Mode is the permission bits to create it with. Zero means 0600.
	Mode fs.FileMode
	// Content is the plaintext. This is the credential; everything else in
	// this struct is bookkeeping.
	Content []byte
}

// Path is where this file belongs, as the workload sees it.
func (f SecretFile) Path() string {
	if f.Dir == "" {
		return f.Name
	}
	return filepath.Join(f.Dir, f.Name)
}

// FileMode returns the mode to create the file with, defaulting to 0600.
func (f SecretFile) FileMode() fs.FileMode {
	if f.Mode == 0 {
		return 0o600
	}
	return f.Mode
}

// String renders the file without its content, so a `%v` on a Spec — or on a
// driver's own debug log — cannot write a live credential into a transcript.
// Marshalling is unaffected; only fmt goes through here.
func (f SecretFile) String() string {
	return fmt.Sprintf("secret file %s (%d bytes) [redacted]", f.Path(), len(f.Content))
}

// GoString mirrors String so %#v cannot print the content either.
func (f SecretFile) GoString() string { return f.String() }

// Validate checks the invariants a driver relies on before it writes anything.
//
// The name check is the important one and it is duplicated from
// secretbroker.Mount.writeFile deliberately: this struct crosses a process
// boundary on the remote path, so the receiving agent must re-derive the
// guarantee rather than inherit the sender's word for it. A name that is not a
// bare file name is an arbitrary-file-write primitive aimed at whatever host
// the driver runs on.
func (f SecretFile) Validate() error {
	if strings.TrimSpace(f.Dir) == "" || !filepath.IsAbs(f.Dir) {
		return fmt.Errorf("%w: secret file %q has no absolute directory", ErrInvalidSpec, f.Name)
	}
	if f.Dir != filepath.Clean(f.Dir) {
		return fmt.Errorf("%w: secret file directory %q is not clean", ErrInvalidSpec, f.Dir)
	}
	name := strings.TrimSpace(f.Name)
	if name == "" || name == "." || name == ".." ||
		name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("%w: unsafe secret file name %q", ErrInvalidSpec, f.Name)
	}
	if len(f.Content) > MaxSecretFileBytes {
		return fmt.Errorf("%w: secret file %s is %d bytes, over the %d-byte ceiling",
			ErrInvalidSpec, name, len(f.Content), MaxSecretFileBytes)
	}
	if mode := f.FileMode(); mode&^fs.FileMode(0o777) != 0 {
		return fmt.Errorf("%w: secret file %s has non-permission mode bits %v", ErrInvalidSpec, name, mode)
	}
	// A credential readable by every user on the executor is not a credential
	// this system delivered, whatever the grant said.
	if mode := f.FileMode(); mode&0o077 != 0 {
		return fmt.Errorf("%w: secret file %s would be created group/world-accessible (%04o)",
			ErrInvalidSpec, name, mode.Perm())
	}
	return nil
}

// ValidateSecretFiles checks a whole set, including the cross-entry invariant
// no single file can see: two files claiming the same path would mean the
// workload reads whichever the driver happened to write last.
func ValidateSecretFiles(files []SecretFile) error {
	if len(files) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(files))
	for i, f := range files {
		if err := f.Validate(); err != nil {
			return fmt.Errorf("secret_files[%d]: %w", i, err)
		}
		p := f.Path()
		if _, dup := seen[p]; dup {
			return fmt.Errorf("%w: secret_files[%d] repeats path %s", ErrInvalidSpec, i, p)
		}
		seen[p] = struct{}{}
	}
	return nil
}

// SecretFileDirs returns the distinct directories a set of files needs, in
// first-appearance order. A driver creates one mount, volume or directory per
// entry; in practice a lease produces exactly one.
func SecretFileDirs(files []SecretFile) []string {
	var out []string
	seen := make(map[string]struct{}, len(files))
	for _, f := range files {
		if _, dup := seen[f.Dir]; dup {
			continue
		}
		seen[f.Dir] = struct{}{}
		out = append(out, f.Dir)
	}
	return out
}

// NeedsSecretFiles reports whether this Spec depends on credential files
// reaching the workload — either because the hub already wrote them and the
// bindings name them, or because the bytes are travelling with the Spec.
//
// It is what SandboxRequirements derives RequireSecretFiles from, so both
// delivery modes are gated by the same question.
func (s Spec) NeedsSecretFiles() bool {
	if len(s.SecretFiles) > 0 {
		return true
	}
	for _, b := range s.Secrets {
		if len(b.Files) > 0 {
			return true
		}
	}
	return false
}

// RelocateSecrets rewrites every reference to the lease directory from so it
// names to instead: the environment the broker built, the bindings the vault
// indexes, and the files themselves.
//
// A driver needs this when it cannot place the files where the hub said. The
// remote agent is the case: the hub has no idea what is writable on an edge
// device, so it declares a nominal directory, and the agent picks a real one
// under its own tmpfs and calls this. Without it the workload would find
// GIT_CONFIG_GLOBAL pointing at a path the agent never created — the exact
// failure the whole file exists to remove, moved one hop.
//
// Prefix matching is safe because a lease directory name carries 96 bits of
// randomness: no unrelated value in the environment can begin with it.
func (s *Spec) RelocateSecrets(from, to string) {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if s == nil || from == "" || to == "" || from == to {
		return
	}
	move := func(p string) string {
		switch {
		case p == from:
			return to
		case strings.HasPrefix(p, from+"/"):
			return to + p[len(from):]
		default:
			return p
		}
	}
	for i, kv := range s.Env {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		if moved := move(kv[eq+1:]); moved != kv[eq+1:] {
			s.Env[i] = kv[:eq+1] + moved
		}
	}
	for i := range s.Secrets {
		s.Secrets[i].Dir = move(s.Secrets[i].Dir)
		for j, f := range s.Secrets[i].Files {
			s.Secrets[i].Files[j] = move(f)
		}
	}
	for i := range s.SecretFiles {
		s.SecretFiles[i].Dir = move(s.SecretFiles[i].Dir)
	}
}
