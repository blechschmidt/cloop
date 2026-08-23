package secretbroker

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/securewipe"
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
	// Mounts are host paths the grant opens to the workload. Unlike Files
	// they are not written anywhere: the path already exists and the grant
	// is permission to reach it, so materialisation validates it and the
	// driver binds it.
	//
	// This one is not json:"-", because a mount carries no secret — a source
	// path and a read-only flag are exactly what an operator inspecting a
	// lease needs to see, and hiding them would make the one material kind
	// with no credential in it the hardest to audit.
	Mounts []RepoMount `json:"mounts,omitempty"`
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
	mounts   []RepoMount
	bindings []LeaseBinding
	closed   bool
}

// Mounts returns the host repositories this lease opens, in the order the
// materials were processed. The caller binds them into the sandbox; there is
// nothing on disk here to clean up, so Close does not touch them.
func (m *Mount) Mounts() []RepoMount {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	return append([]RepoMount(nil), m.mounts...)
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
	// Mounts are the host paths this grant opened, recorded for the audit
	// trail rather than for revocation.
	//
	// The distinction matters and is a real limitation: a revoked lease's
	// files are wiped and its variables scrubbed, but a bind already in a
	// running sandbox's mount namespace cannot be taken back from outside it.
	// A local_repo grant therefore lapses when the workload exits, not when
	// the grant is revoked. Narrowing that window means stopping the workload.
	Mounts []RepoMount
}

// RepoMount is one local git repository a grant opens to a workload.
//
// It names paths on two different machines' terms: Source is on the host the
// executor runs on, Target is inside the sandbox. They are equal only for a
// driver that shares the host filesystem, which is why the distinction is in
// the type rather than left to the driver to remember.
type RepoMount struct {
	// Name is the repository's directory name under the granted root, and
	// the handle a workload refers to it by.
	Name string `json:"name"`
	// Source is the absolute host path. Always inside the granted root:
	// selectRepos resolves symlinks before accepting one, so a symlink
	// planted under the root cannot redirect the bind out of it.
	Source string `json:"source"`
	// Target is the absolute path the repository appears at in the sandbox.
	Target string `json:"target"`
	// ReadOnly mirrors the grant's Writable constraint, inverted, because
	// read-only is the default and a zero value should mean the safe thing.
	ReadOnly bool `json:"read_only,omitempty"`
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

// render lays the lease out against dir without touching a filesystem: which
// environment variables it produces, which files belong where, and how each
// grant is attributed.
//
// It is shared by Materialize and Deliver so the two delivery paths cannot
// disagree about what a lease means. That mattered the moment a second path
// existed: an isolated executor computes its environment from a directory it
// will create itself, and a second implementation of "what does GIT_CONFIG_GLOBAL
// point at" is how the sandbox ends up with a variable naming nothing.
func (l *Lease) render(dir string) (env []string, files []placedFile, bindings []LeaseBinding, mounts []RepoMount, err error) {
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
			name, nerr := leaseFileName(f)
			if nerr != nil {
				return nil, nil, nil, nil, nerr
			}
			path := filepath.Join(dir, name)
			files = append(files, placedFile{
				GrantID:    mat.GrantID,
				SecretName: mat.SecretName,
				Kind:       mat.Kind,
				Name:       name,
				Path:       path,
				Mode:       leaseFileMode(f),
				Content:    f.Content,
			})
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
		// Mounts need no writing — the path is already there and the grant
		// is the right to reach it — but they are re-validated here rather
		// than trusted from the Material. materialFor and this call can be
		// separated by a store round trip, and a bind is the one material
		// that hands over a host path verbatim.
		for _, rm := range mat.Mounts {
			if verr := rm.validate(); verr != nil {
				return nil, nil, nil, nil, verr
			}
			binding.Mounts = append(binding.Mounts, rm)
			mounts = append(mounts, rm)
		}
		// Sorted so the binding — which ends up in an audit row and in a
		// revoke frame — is stable across runs rather than reflecting Go's
		// randomised map order.
		sort.Strings(binding.EnvKeys)
		bindings = append(bindings, binding)
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
	env = make([]string, 0, len(keys))
	for _, k := range keys {
		env = append(env, k+"="+envMap[k])
	}
	return env, files, bindings, mounts, nil
}

// placedFile is one credential file after render has decided where it goes.
type placedFile struct {
	GrantID    string
	SecretName string
	Kind       Kind
	Name       string
	Path       string
	Mode       os.FileMode
	Content    []byte
}

// leaseFileName validates and returns the bare name a credential file gets.
//
// A file name is attacker-influenced only if a stored constraint is, but the
// cost of checking is a strings.Contains and the cost of not checking is an
// arbitrary-file-write primitive — on whichever host ends up materialising the
// lease, which since Deliver exists may not be this one.
//
// "." needs its own clause: filepath.Base(".") is ".", so it slips past the
// Base comparison, and Join(dir, ".") is the lease directory itself. Nothing
// escapes, but without the check the rejection arrives as a raw "is a
// directory" I/O error rather than ErrInvalidSecret, and a caller switching on
// the sentinel would misclassify a malformed name as a disk problem.
func leaseFileName(f File) (string, error) {
	name := strings.TrimSpace(f.Name)
	if name == "" || name == "." || name == ".." ||
		name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		return "", wrapf(ErrInvalidSecret, "unsafe lease file name %q", f.Name)
	}
	return name, nil
}

// leaseFileMode is the mode a credential file is created with. 0600 is the
// default and the only sane one; a grant that asked for anything group- or
// world-readable is narrowed rather than honoured.
func leaseFileMode(f File) os.FileMode {
	mode := f.Mode
	if mode == 0 {
		return 0o600
	}
	return mode &^ os.FileMode(0o077)
}

// Materialize writes the lease's credentials into a private directory and
// returns the Mount describing it. baseDir may be empty to use a tmpfs.
//
// Call it only for a workload that will read this host's filesystem — see
// executor.Capabilities.SecretFilesFromHostPath. For anything isolated, use
// Deliver: writing plaintext here for a sandbox that cannot open it creates a
// credential file on the control plane that nothing ever reads.
//
// The caller must Close the Mount when the workload exits. Failure partway
// through cleans up what was already written rather than leaving credential
// files behind.
func (l *Lease) Materialize(baseDir string) (*Mount, error) {
	dir, err := NewLeaseDirPath(baseDir)
	if err != nil {
		return nil, err
	}
	return l.MaterializeAt(dir)
}

// NewLeaseDirPath returns an unused lease-directory path under baseDir —
// without creating it, and without writing anything.
//
// It exists so a caller can record its intent to materialise *before* any
// plaintext lands on disk. Materialize used to pick the directory itself with
// MkdirTemp, which left no way to write a durable "a lease directory is about
// to exist at this path" row first: a hub killed between the mkdir and the row
// came back up with a credential directory nothing knew about, and the startup
// sweep had nothing to reconcile it against. /dev/shm is a tmpfs and clears on
// reboot, but a hub *process* restart is the common case and clears nothing.
//
// Splitting the naming from the creation makes the ordering possible:
//
//	dir, _ := NewLeaseDirPath("")   // nothing on disk yet
//	db.PutSecretLeaseDir(...)       // intent recorded
//	lease.MaterializeAt(dir)        // plaintext appears
//
// A crash after the row exists leaves a trace the sweep can act on; a crash
// before it leaves nothing at all. There is no window in between.
//
// baseDir may be empty to use a tmpfs. The 96-bit suffix matches lease IDs, so
// two hubs sharing one /dev/shm cannot collide.
func NewLeaseDirPath(baseDir string) (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("secretbroker: generate lease dir name: %w", err)
	}
	return filepath.Join(leaseBaseDir(baseDir), leaseDirPrefix+encodeHex(buf)), nil
}

// MaterializeAt writes the lease's credentials into dir, which it creates.
//
// dir must be absolute and its final element must carry leaseDirPrefix: the
// prefix is what every wipe path in this system uses to recognise a directory
// as lease-owned, and one created without it could never be swept. Creation is
// exclusive — a directory that already exists is refused rather than reused,
// so two leases cannot land in one directory and have the first Close take the
// second's files.
func (l *Lease) MaterializeAt(dir string) (*Mount, error) {
	if l == nil {
		return nil, wrapf(ErrLeaseNotFound, "nil lease")
	}
	clean := filepath.Clean(strings.TrimSpace(dir))
	if clean == "" || clean == "." || !filepath.IsAbs(clean) {
		return nil, wrapf(ErrInvalidSecret, "lease directory %q is not an absolute path", dir)
	}
	if !securewipe.IsLeaseDir(clean) {
		return nil, wrapf(ErrInvalidSecret,
			"lease directory %s does not carry the %s prefix, so nothing would recognise it as lease-owned",
			clean, leaseDirPrefix)
	}
	// 0700 from the start rather than created-then-chmodded: a directory that
	// is traversable for even an instant is one in which a file created inside
	// it is reachable, whatever the file's own mode. os.Mkdir applies the
	// process umask, so the explicit Chmod below is what actually guarantees it.
	if err := os.Mkdir(clean, 0o700); err != nil {
		return nil, fmt.Errorf("secretbroker: create lease dir: %w", err)
	}
	if err := os.Chmod(clean, 0o700); err != nil {
		_ = os.RemoveAll(clean)
		return nil, fmt.Errorf("secretbroker: secure lease dir: %w", err)
	}
	dir = clean

	env, files, bindings, mounts, err := l.render(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	m := &Mount{Dir: dir, env: env, bindings: bindings, mounts: mounts}
	for _, f := range files {
		if werr := m.writeFile(f); werr != nil {
			_ = m.Close()
			return nil, werr
		}
	}
	return m, nil
}

// Deliver renders the lease for a workload that will find its credentials at
// dir on a filesystem this process does not own, without writing anything.
//
// The Delivery holds the plaintext in memory for the driver to place —
// staged into a container's own tmpfs, projected as a Kubernetes Secret, or
// sent to an edge agent that writes it through its confined vault path. That
// is the whole difference from Materialize: the control plane never has a file
// to leak for a credential it is only relaying.
func (l *Lease) Deliver(dir string) (*Delivery, error) {
	if l == nil {
		return nil, wrapf(ErrLeaseNotFound, "nil lease")
	}
	clean := filepath.Clean(strings.TrimSpace(dir))
	if clean == "" || clean == "." || !filepath.IsAbs(clean) {
		return nil, wrapf(ErrInvalidSecret, "delivery directory %q is not an absolute path", dir)
	}
	env, files, bindings, mounts, err := l.render(clean)
	if err != nil {
		return nil, err
	}
	return &Delivery{Dir: clean, env: env, files: files, bindings: bindings, mounts: mounts}, nil
}

// Delivery is a lease rendered for someone else's filesystem: the environment
// to hand the workload, the per-grant attribution, and the file bytes the
// driver must place at Dir.
//
// It is the Mount's counterpart, with the same accessors and one difference
// that is the point of the type: nothing here has touched a disk, so Close
// zeroes buffers rather than unlinking files.
type Delivery struct {
	// Dir is where the workload will find the files. It is a path on the
	// executor, not on this host.
	Dir string

	mu       sync.Mutex
	env      []string
	files    []placedFile
	bindings []LeaseBinding
	mounts   []RepoMount
	closed   bool
}

// Env returns the environment additions in "K=V" form, sorted.
func (d *Delivery) Env() []string {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.env...)
}

// Mounts returns the host repositories this lease opens.
func (d *Delivery) Mounts() []RepoMount {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	return append([]RepoMount(nil), d.mounts...)
}

// Bindings returns the per-grant attribution: names and paths, never values.
func (d *Delivery) Bindings() []LeaseBinding {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]LeaseBinding, len(d.bindings))
	for i, b := range d.bindings {
		copied := b
		copied.EnvKeys = append([]string(nil), b.EnvKeys...)
		copied.Files = append([]string(nil), b.Files...)
		out[i] = copied
	}
	return out
}

// Files returns the credential files for the driver to place, with their
// contents. Nil after Close.
//
// The content is copied per call rather than aliased: a driver that base64s it
// into a frame must not be handed the buffer Close will zero underneath it.
func (d *Delivery) Files() []DeliveredFile {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	out := make([]DeliveredFile, 0, len(d.files))
	for _, f := range d.files {
		out = append(out, DeliveredFile{
			GrantID:    f.GrantID,
			SecretName: f.SecretName,
			Kind:       f.Kind,
			Dir:        d.Dir,
			Name:       f.Name,
			Mode:       f.Mode,
			Content:    append([]byte(nil), f.Content...),
		})
	}
	return out
}

// Close zeroes the buffers holding the plaintext and drops the rest. It is
// idempotent, so it is safe in a defer beside an explicit call.
//
// Zeroing is not a guarantee — Go's garbage collector may already have copied
// the bytes during a slice growth, and nothing here can reach that copy — but
// it bounds the window in which a heap dump of a long-lived control plane
// contains a credential it relayed hours ago.
func (d *Delivery) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	for i := range d.files {
		for j := range d.files[i].Content {
			d.files[i].Content[j] = 0
		}
		d.files[i].Content = nil
	}
	d.files = nil
	d.env = nil
	d.bindings = nil
	return nil
}

// DeliveredFile is one credential file a Delivery is handing to a driver.
type DeliveredFile struct {
	GrantID    string
	SecretName string
	Kind       Kind
	// Dir is the directory on the executor, mirroring Delivery.Dir so a
	// caller can build one flat list from several leases.
	Dir  string
	Name string
	Mode os.FileMode
	// Content is the plaintext.
	Content []byte
}

// String redacts the content, so a `%v` on a delivery cannot log a credential.
func (f DeliveredFile) String() string {
	return fmt.Sprintf("credential file %s (%d bytes) [redacted]", filepath.Join(f.Dir, f.Name), len(f.Content))
}

// GoString mirrors String so %#v is redacted too.
func (f DeliveredFile) GoString() string { return f.String() }

// leaseDirPrefix names every directory a lease's files live in, on the hub and
// inside a sandbox alike.
//
// It is load-bearing rather than cosmetic: pkg/executor/agent refuses to
// unlink any path whose parent is not named this way, which is what stops a
// compromised control plane from turning revocation into an arbitrary-unlink
// primitive on every enrolled device. A directory chosen for a sandbox must
// therefore carry the prefix too — see SandboxLeaseDir.
//
// Defined in pkg/securewipe so the hub and the agent cannot drift apart on it:
// they are separate binaries enforcing one rule, and a prefix that disagreed
// would make every revocation on an edge device a silent no-op.
const leaseDirPrefix = securewipe.LeaseDirPrefix

// SandboxLeaseRoot is the parent directory a lease's files are delivered under
// inside an executor that does not share the hub's filesystem.
//
// /run is the conventional place for ephemeral runtime state and is a tmpfs on
// every systemd host, which is the same property the hub's /dev/shm is chosen
// for. A driver that cannot write there relocates and rewrites the
// environment; see executor.Spec.RelocateSecrets.
const SandboxLeaseRoot = "/run/cloop"

// SandboxLeaseDir returns the directory a lease's credential files take inside
// a sandbox. The final element carries leaseDirPrefix so the agent's
// confinement rule recognises it as lease-owned.
func SandboxLeaseDir(leaseID string) string {
	slug := strings.TrimPrefix(strings.TrimSpace(leaseID), "lease_")
	var b strings.Builder
	for _, r := range strings.ToLower(slug) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		}
	}
	name := b.String()
	if name == "" {
		// A lease with no usable ID still needs a directory whose name the
		// agent will accept; "unknown" is distinguishable in a log and cannot
		// collide with a real 96-bit identifier.
		name = "unknown"
	}
	return path.Join(SandboxLeaseRoot, leaseDirPrefix+name)
}

// writeFile places one already-rendered credential file on disk.
func (m *Mount) writeFile(f placedFile) error {
	path := f.Path
	mode := f.Mode
	if err := os.WriteFile(path, f.Content, mode); err != nil {
		return fmt.Errorf("secretbroker: write lease file %s: %w", f.Name, err)
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
		return fmt.Errorf("secretbroker: chmod lease file %s: %w", f.Name, err)
	}
	return nil
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

	var errs []error
	for _, path := range m.files {
		if err := wipeFile(path); err != nil {
			errs = append(errs, err)
		}
	}
	m.files = nil
	m.env = nil
	m.bindings = nil
	if m.Dir != "" {
		// securewipe.Dir rather than os.RemoveAll, and the difference is not
		// tidiness: RemoveAll unlinks whatever the workload left in the lease
		// directory without overwriting it, so a kubectl cache or a git
		// credential helper's scratch file — written by the workload, never
		// tracked in m.files — would leave its bytes on the device. Dir
		// enumerates and zeroes everything it finds.
		if err := securewipe.Dir(m.Dir); err != nil {
			errs = append(errs, err)
		}
	}
	// Joined rather than first-wins: a caller deciding whether to tell an
	// operator "this credential is destroyed" needs every reason it might not
	// be, and the first failure is not reliably the worst one.
	return errors.Join(errs...)
}

// wipeFile overwrites a file's contents with zeros, syncs, and removes it.
// A missing file is not an error: something else having already cleaned up
// is the desired end state.
// It is a thin alias for securewipe.File, kept so the call sites here read in
// this package's terms. The implementation moved out because an identical copy
// lived in pkg/executor/agent and both had discarded every error from the
// overwrite — the doc comment above promised a wipe and the code delivered an
// unlink. See pkg/securewipe.
func wipeFile(path string) error { return securewipe.File(path) }

// newLeaseID returns a lease identifier. Leases are shorter-lived than
// grants but are quoted in audit rows, so they get the same 96 bits.
func newLeaseID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("secretbroker: generate lease id: %w", err)
	}
	return "lease_" + encodeHex(buf), nil
}
