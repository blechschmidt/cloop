package secretbroker

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Material is one grant's credentials, already minimized against that
// grant's constraints and ready to hand to an executor.
//
// The plaintext lives here and only here. A Material is short-lived by
// construction: it exists between Lease and Materialize, and the Mount that
// results is wiped when the workload exits.
type Material struct {
	GrantID     string      `json:"grant_id"`
	SecretID    string      `json:"secret_id"`
	SecretName  string      `json:"secret_name"`
	Kind        Kind        `json:"kind"`
	Constraints Constraints `json:"constraints"`
	// Env are variables to inject, already narrowed. Values are
	// credentials; this field is json:"-" so a Material cannot be
	// serialised into an API response by accident.
	Env map[string]string `json:"-"`
	// Files are written into the lease's tmpfs directory.
	Files []File `json:"-"`
	// Summary is the audit-safe description of what was delivered
	// (surviving kubeconfig contexts, allowed registries, env key names).
	Summary string `json:"summary,omitempty"`
}

// File is one credential file to place in the lease directory.
type File struct {
	// Name is a bare file name — no directory separators. Materialize
	// re-checks this before writing, so a crafted name cannot escape the
	// lease directory.
	Name    string
	Content []byte
	Mode    os.FileMode
	// EnvVar, when set, receives the file's absolute path after
	// materialisation (KUBECONFIG, GIT_CONFIG_GLOBAL, DOCKER_CONFIG).
	EnvVar string
	// EnvIsDir points EnvVar at the containing directory rather than the
	// file, which is what DOCKER_CONFIG expects.
	EnvIsDir bool
}

// Lease is a time-boxed bundle of materials issued to one requester.
//
// TTL is the point of the type. A grant may last 24 hours, but the
// credentials an executor holds should not: a lease expires in minutes and
// is renewed while the work continues, so a compromised executor's window is
// bounded by the lease rather than by the grant.
type Lease struct {
	ID         string    `json:"id"`
	ExecutorID string    `json:"executor_id,omitempty"`
	ProjectID  string    `json:"project_id,omitempty"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	// Materials carries the credentials. json:"-" on the sensitive fields
	// of Material keeps a marshalled Lease audit-safe.
	Materials []Material `json:"materials"`
}

// Expired reports whether the lease is past its TTL at now.
func (l *Lease) Expired(now time.Time) bool {
	return l == nil || !now.Before(l.ExpiresAt)
}

// TTL returns the remaining lifetime at now, clamped at zero.
func (l *Lease) TTL(now time.Time) time.Duration {
	if l == nil {
		return 0
	}
	d := l.ExpiresAt.Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// Empty reports whether the lease carries no credentials. An empty lease is
// a legitimate outcome — a project with no grants gets one — and callers
// should treat it as "run with no secrets", not as an error.
func (l *Lease) Empty() bool { return l == nil || len(l.Materials) == 0 }

// SecretNames lists the delivered secrets by name, for logging.
func (l *Lease) SecretNames() []string {
	if l == nil {
		return nil
	}
	names := make([]string, 0, len(l.Materials))
	for _, m := range l.Materials {
		names = append(names, m.SecretName)
	}
	sort.Strings(names)
	return names
}

// Mount is a materialised lease on a filesystem: a private directory holding
// the credential files, plus the environment to hand the workload.
//
// Close wipes it. The zero value is not usable; get one from
// Lease.Materialize.
type Mount struct {
	// Dir is the lease directory. Mode 0700, on a tmpfs where one is
	// available.
	Dir string

	mu       sync.Mutex
	env      []string
	files    []string
	bindings []LeaseBinding
	closed   bool
}

// LeaseBinding attributes part of a materialised lease to the grant that
// produced it: which environment variables it set, and which files it wrote.
//
// It carries names and paths, never values. The point is revocation — an
// executor holding GITHUB_TOKEN cannot otherwise tell that the variable came
// from a grant an operator has just withdrawn, so "revoke this lease" could
// only be honoured by killing the whole workload. With the attribution, a
// driver scrubs exactly what the lease delivered and leaves the rest alone.
//
// See pkg/executor.SecretBinding, the driver-facing shape this maps onto, and
// pkg/executor/remote/revoke.go for what a driver does with it.
type LeaseBinding struct {
	// GrantID is the grant this material came from.
	GrantID string
	// SecretID and SecretName identify the stored secret, for diagnostics.
	SecretID   string
	SecretName string
	// Kind is the credential kind.
	Kind Kind
	// EnvKeys are the variables this grant contributed, by name.
	EnvKeys []string
	// Files are the absolute paths written for this grant.
	Files []string
	// Dir is the lease directory holding Files.
	Dir string
}

// tmpfsCandidates are checked in order for a memory-backed directory to hold
// credential files.
//
// /dev/shm is tmpfs on every mainstream Linux distribution, so files written
// there never reach a disk and cannot survive into a block that some later
// forensic tool — or the next tenant of a recycled volume — reads back.
// Falling back to os.TempDir() keeps this working on macOS and in
// containers with no /dev/shm; the wipe in Close is what carries the
// guarantee there, which is weaker against a journalling filesystem and is
// why the tmpfs path is preferred rather than optional-by-default.
var tmpfsCandidates = []string{"/dev/shm"}

// leaseBaseDir picks the parent directory for lease mounts.
func leaseBaseDir(override string) string {
	if override != "" {
		return override
	}
	for _, cand := range tmpfsCandidates {
		info, err := os.Stat(cand)
		if err != nil || !info.IsDir() {
			continue
		}
		// Confirm writability rather than assuming it: a hardened image
		// may mount /dev/shm read-only or noexec.
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

// Materialize writes the lease's credentials into a private directory and
// returns the Mount describing it. baseDir may be empty to use a tmpfs.
//
// The caller must Close the Mount when the workload exits. Failure partway
// through cleans up what was already written rather than leaving credential
// files behind.
func (l *Lease) Materialize(baseDir string) (*Mount, error) {
	if l == nil {
		return nil, wrapf(ErrLeaseNotFound, "nil lease")
	}
	dir, err := os.MkdirTemp(leaseBaseDir(baseDir), "cloop-lease-")
	if err != nil {
		return nil, fmt.Errorf("secretbroker: create lease dir: %w", err)
	}
	// MkdirTemp already creates 0700, but say so explicitly: the guarantee
	// that no other user on the host can read these files is the reason the
	// directory exists at all, and it should not rest on a default.
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("secretbroker: secure lease dir: %w", err)
	}

	m := &Mount{Dir: dir}
	envMap := make(map[string]string)

	for _, mat := range l.Materials {
		binding := LeaseBinding{
			GrantID:    mat.GrantID,
			SecretID:   mat.SecretID,
			SecretName: mat.SecretName,
			Kind:       mat.Kind,
			Dir:        dir,
		}
		for k, v := range mat.Env {
			envMap[k] = v
			binding.EnvKeys = append(binding.EnvKeys, k)
		}
		for _, f := range mat.Files {
			path, werr := m.writeFile(f)
			if werr != nil {
				_ = m.Close()
				return nil, werr
			}
			binding.Files = append(binding.Files, path)
			if f.EnvVar != "" {
				if f.EnvIsDir {
					envMap[f.EnvVar] = filepath.Dir(path)
				} else {
					envMap[f.EnvVar] = path
				}
				binding.EnvKeys = append(binding.EnvKeys, f.EnvVar)
			}
		}
		// Sorted so the binding — which ends up in an audit row and in a
		// revoke frame — is stable across runs rather than reflecting Go's
		// randomised map order.
		sort.Strings(binding.EnvKeys)
		m.bindings = append(m.bindings, binding)
	}

	// CLOOP_LEASE_DIR lets a workload find its own credential directory
	// without having to be told out of band.
	envMap["CLOOP_LEASE_DIR"] = dir
	if !l.ExpiresAt.IsZero() {
		envMap["CLOOP_LEASE_EXPIRES_AT"] = l.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if l.ID != "" {
		envMap["CLOOP_LEASE_ID"] = l.ID
	}

	keys := make([]string, 0, len(envMap))
	for k := range envMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	m.env = make([]string, 0, len(keys))
	for _, k := range keys {
		m.env = append(m.env, k+"="+envMap[k])
	}
	return m, nil
}

// writeFile places one credential file in the mount directory.
func (m *Mount) writeFile(f File) (string, error) {
	name := strings.TrimSpace(f.Name)
	// A file name is attacker-influenced only if a stored constraint is,
	// but the cost of checking is a strings.Contains and the cost of not
	// checking is an arbitrary-file-write primitive.
	//
	// "." needs its own clause: filepath.Base(".") is ".", so it slips past
	// the Base comparison, and Join(dir, ".") is the lease directory itself.
	// Nothing escapes, but without the check the rejection arrives as a raw
	// "is a directory" I/O error rather than ErrInvalidSecret, and a caller
	// switching on the sentinel would misclassify a malformed name as a
	// disk problem.
	if name == "" || name == "." || name == ".." ||
		name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		return "", wrapf(ErrInvalidSecret, "unsafe lease file name %q", f.Name)
	}
	mode := f.Mode
	if mode == 0 {
		mode = 0o600
	}
	path := filepath.Join(m.Dir, name)
	if err := os.WriteFile(path, f.Content, mode); err != nil {
		return "", fmt.Errorf("secretbroker: write lease file %s: %w", name, err)
	}
	// Track the file the moment it exists, before anything else can fail.
	// Registering it after the chmod would mean a chmod error left a
	// credential file on disk that Close would delete but never overwrite.
	m.mu.Lock()
	m.files = append(m.files, path)
	m.mu.Unlock()

	// WriteFile honours the mode only when it creates the file; chmod
	// covers the case where a previous lease left one behind.
	if err := os.Chmod(path, mode); err != nil {
		return "", fmt.Errorf("secretbroker: chmod lease file %s: %w", name, err)
	}
	return path, nil
}

// Bindings returns the per-grant attribution for this mount: which variables
// and files each grant contributed. Names and paths only — no values.
//
// A driver uses it to build executor.SecretBinding, which is what makes a
// mid-run revocation targetable at one credential instead of at the whole
// workload.
func (m *Mount) Bindings() []LeaseBinding {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LeaseBinding, len(m.bindings))
	for i, b := range m.bindings {
		// Deep-copy the slices: a caller that appends to the returned
		// binding's EnvKeys must not mutate the mount's own record of what
		// it wrote, which is what Close reads to clean up.
		copied := b
		copied.EnvKeys = append([]string(nil), b.EnvKeys...)
		copied.Files = append([]string(nil), b.Files...)
		out[i] = copied
	}
	return out
}

// Env returns the environment additions in "K=V" form, sorted, ready to
// append to an executor.Spec's Env.
func (m *Mount) Env() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.env...)
}

// Close wipes and removes the mount. It is idempotent and safe to call from
// a defer alongside an explicit call.
//
// Each file is overwritten with zeros before removal. On a tmpfs that is
// belt-and-braces, since the pages are freed anyway; on the os.TempDir()
// fallback it is the only thing standing between an unlinked credential and
// whoever reads the underlying blocks next. It is not a guarantee against a
// copy-on-write or log-structured filesystem, which is why tmpfs is
// preferred rather than merely convenient.
func (m *Mount) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true

	var firstErr error
	for _, path := range m.files {
		if err := wipeFile(path); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	m.files = nil
	m.env = nil
	m.bindings = nil
	if m.Dir != "" {
		if err := os.RemoveAll(m.Dir); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// wipeFile overwrites a file's contents with zeros, syncs, and removes it.
// A missing file is not an error: something else having already cleaned up
// is the desired end state.
func wipeFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if size := info.Size(); size > 0 {
		f, oerr := os.OpenFile(path, os.O_WRONLY, 0o600)
		if oerr == nil {
			zeros := make([]byte, size)
			_, _ = f.WriteAt(zeros, 0)
			_ = f.Sync()
			_ = f.Close()
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// newLeaseID returns a lease identifier. Leases are shorter-lived than
// grants but are quoted in audit rows, so they get the same 96 bits.
func newLeaseID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("secretbroker: generate lease id: %w", err)
	}
	return "lease_" + encodeHex(buf), nil
}
