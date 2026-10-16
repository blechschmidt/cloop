// Package rootkey resolves the hub's root secret — CLOOP_SECRET_KEY, and during
// a change of root the key it replaces — from the one place every reader asks
// (Task 20425).
//
// # Why one resolver
//
// Every key-encryption key the secret broker seals under, every audit
// checkpoint seal, every backup sidecar seal, the key escrow and the legacy
// .cloop/secrets.enc derive from this one value. It used to be read by a dozen
// direct os.Getenv calls, each its own idea of where the key lives, so the key
// could live in exactly one place: the process environment. That is the worst
// of the places on offer. An environment variable is in /proc/<pid>/environ for
// anyone who can read it, in `docker inspect` and `kubectl get pod -o yaml`, in
// `systemctl show`, and in the environment of every child the process starts
// without scrubbing it.
//
// Resolve reads each slot from three sources, in this order:
//
//  1. a file named by CLOOP_SECRET_KEY_FILE (CLOOP_SECRET_KEY_PREVIOUS_FILE):
//     an absolute path to a regular file this process owns, mode 0400 or 0600,
//     outside every .cloop/ directory;
//  2. a systemd credential, cloop-secret-key (cloop-secret-key-previous), in
//     $CREDENTIALS_DIRECTORY — which is how LoadCredentialEncrypted= with
//     systemd-creds, and a TPM, reaches the hub without the key ever being
//     written to disk in the clear;
//  3. the environment variable itself.
//
// Two sources that both hold a value must hold the same one. Disagreeing
// sources are refused rather than ranked: an operator who moved the key into a
// file and left a different one in hub.env has two keys, and which one the hub
// silently picked would decide whether it opens anything.
//
// # Why there is a previous key
//
// The keyring holds a current root, which mints new key-encryption keys and
// opens, and optionally a previous one, which only opens. That is what turns
// changing the root from a re-mint of every credential into a rolling restart
// followed by `cloop hub key rotate --retire-previous`; see
// pkg/secretbroker/keyring.go.
//
// # The hub pins what it started with
//
// A serving hub resolves once, at startup, and Pin makes every later Resolve in
// the process return that answer. Its cluster peers are told the fingerprints
// it started with, and a key file that changes under a running process — a
// Kubernetes Secret update arrives in a mounted file within a minute — would
// otherwise change the root mid-flight, under work that already resolved the
// old one. A new root takes effect at a restart, which is the procedure.
package rootkey

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
)

// The variables and credential names each slot is read from.
const (
	// EnvKey is the current root, read from the environment.
	EnvKey = "CLOOP_SECRET_KEY"
	// EnvKeyFile names a file holding the current root.
	EnvKeyFile = "CLOOP_SECRET_KEY_FILE"
	// EnvPrevious is the root being replaced, read from the environment. It
	// only opens: nothing new is ever derived from it.
	EnvPrevious = "CLOOP_SECRET_KEY_PREVIOUS"
	// EnvPreviousFile names a file holding the previous root.
	EnvPreviousFile = "CLOOP_SECRET_KEY_PREVIOUS_FILE"
	// EnvCredentialsDirectory is where systemd puts a service's credentials
	// (LoadCredential=, LoadCredentialEncrypted=, SetCredential=).
	EnvCredentialsDirectory = "CREDENTIALS_DIRECTORY"
	// Credential is the systemd credential holding the current root.
	Credential = "cloop-secret-key"
	// PreviousCredential is the systemd credential holding the previous root.
	PreviousCredential = "cloop-secret-key-previous"
)

// Member meta keys under which a hub cluster member advertises the
// fingerprints of the roots it holds (hub_members.meta). `cloop hub key rotate
// --retire-previous` refuses until every live member advertises the new root
// as its current one.
const (
	EndpointCurrent  = "root_key"
	EndpointPrevious = "root_key_previous"
)

// maxFileSize bounds what a key file may hold. `cloop hub bootstrap` writes 43
// characters; a file past this is not a key, and reading it whole would be a
// way to make the hub allocate whatever a file holds.
const maxFileSize = 4096

// Source is where a root was read from.
type Source string

const (
	SourceFile        Source = "file"
	SourceCredential  Source = "credential"
	SourceEnvironment Source = "environment"
)

// Root is one root secret and where it came from.
type Root struct {
	// Value is the secret itself. It is never printed, logged or marshalled.
	Value string `json:"-"`
	// Source is where it was read from; "" when the slot is not configured.
	Source Source `json:"source,omitempty"`
	// Path is the file a file or credential source read.
	Path string `json:"path,omitempty"`
	// Variable names the setting that selected the source: the environment
	// variable, or the credential name.
	Variable string `json:"variable,omitempty"`
	// Also lists the further sources holding the same value. They agree, so
	// nothing is ambiguous — but a copy left in the environment keeps every
	// exposure the file was meant to end, which `cloop hub doctor` says.
	Also []Source `json:"also,omitempty"`
}

// Set reports whether the slot holds a key.
func (r Root) Set() bool { return r.Value != "" }

// Describe names where the root came from, for a message. It never includes
// the value.
func (r Root) Describe() string {
	switch r.Source {
	case SourceFile:
		return fmt.Sprintf("the file %s (%s)", r.Path, r.Variable)
	case SourceCredential:
		// systemd's protocol, which a Kubernetes Pod can speak as well: the
		// chart mounts its Secret as a credentials directory.
		return fmt.Sprintf("the credential %s in %s (%s)", r.Variable, EnvCredentialsDirectory, r.Path)
	case SourceEnvironment:
		return "the environment variable " + r.Variable
	}
	return "nothing"
}

// Roots is the current root and, while the root is being changed, the
// previous one.
type Roots struct {
	Current  Root
	Previous Root
}

// Values returns the configured roots, current first: what a keyring derives
// from, in the order it tries them.
func (r Roots) Values() []string {
	var out []string
	if r.Current.Set() {
		out = append(out, r.Current.Value)
	}
	if r.Previous.Set() {
		out = append(out, r.Previous.Value)
	}
	return out
}

// Changing reports whether a previous root is configured: a change of root is
// in progress until `cloop hub key rotate --retire-previous` has run and the
// previous root has been removed from every member.
func (r Roots) Changing() bool { return r.Previous.Set() }

// Sentinels. Every error Resolve returns wraps one of them.
var (
	// ErrConflict: two sources of one slot hold different keys.
	ErrConflict = errors.New("rootkey: sources disagree")
	// ErrRefused: a key file failed a check — its path, type, owner or mode.
	ErrRefused = errors.New("rootkey: key file refused")
	// ErrUnreadable: a configured file could not be read.
	ErrUnreadable = errors.New("rootkey: key file unreadable")
	// ErrPreviousAlone: a previous root with no current one.
	ErrPreviousAlone = errors.New("rootkey: a previous key without a current one")
	// ErrSameKey: the previous root is the current one.
	ErrSameKey = errors.New("rootkey: the previous key is the current key")
)

// slot is one of the two roots and everything it is read from.
type slot struct {
	name       string // the variable an operator thinks of it as
	env        string
	fileEnv    string
	credential string
}

var (
	currentSlot  = slot{name: EnvKey, env: EnvKey, fileEnv: EnvKeyFile, credential: Credential}
	previousSlot = slot{name: EnvPrevious, env: EnvPrevious, fileEnv: EnvPreviousFile, credential: PreviousCredential}
)

// pinned is the answer a serving hub resolved at startup; nil when unpinned.
var pinned atomic.Pointer[Roots]

// Pin makes every later Resolve in this process return r, and returns a
// function that undoes it. `cloop ui` pins what it resolved at startup; see the
// package comment.
func Pin(r Roots) (unpin func()) {
	cp := r
	prev := pinned.Swap(&cp)
	return func() { pinned.Store(prev) }
}

// Pinned reports whether this process pinned its roots.
func Pinned() bool { return pinned.Load() != nil }

// Resolve returns the hub's roots: the pinned ones in a serving hub, otherwise
// read from the sources now. A slot nothing configures is returned unset with
// no error — a hub with no key is a supported, degraded state — but a source
// that is configured and wrong is an error, never an empty slot.
func Resolve() (Roots, error) {
	if p := pinned.Load(); p != nil {
		return *p, nil
	}
	return defaultResolver().resolve()
}

// Current returns the current root's value, "" when none is configured.
func Current() (string, error) {
	r, err := Resolve()
	if err != nil {
		return "", err
	}
	return r.Current.Value, nil
}

// resolver carries what resolution reads from the system, so tests can stand
// in for the process's identity.
type resolver struct {
	getenv func(string) string
	euid   int
	gid    int
	groups []int
}

func defaultResolver() resolver {
	groups, _ := os.Getgroups()
	return resolver{getenv: os.Getenv, euid: os.Geteuid(), gid: os.Getegid(), groups: groups}
}

func (rv resolver) resolve() (Roots, error) {
	cur, err := rv.slot(currentSlot)
	if err != nil {
		return Roots{}, err
	}
	prev, err := rv.slot(previousSlot)
	if err != nil {
		return Roots{}, err
	}
	switch {
	case prev.Set() && !cur.Set():
		return Roots{}, fmt.Errorf("%w: %s is set by %s but %s is not — the previous key only opens what "+
			"it sealed; a hub needs a current key to seal anything new under", ErrPreviousAlone,
			EnvPrevious, prev.Describe(), EnvKey)
	case prev.Set() && subtle.ConstantTimeCompare([]byte(prev.Value), []byte(cur.Value)) == 1:
		return Roots{}, fmt.Errorf("%w: %s (%s) holds the same key as %s (%s); a change of root needs the "+
			"new key as current and the old one as previous", ErrSameKey, EnvPrevious, prev.Describe(),
			EnvKey, cur.Describe())
	}
	return Roots{Current: cur, Previous: prev}, nil
}

// slot reads one root from every source, and refuses sources that disagree.
func (rv resolver) slot(s slot) (Root, error) {
	var found []Root
	if path := rv.getenv(s.fileEnv); path != "" {
		v, err := rv.readFile(path, s.fileEnv)
		if err != nil {
			return Root{}, err
		}
		found = append(found, Root{Value: v, Source: SourceFile, Path: path, Variable: s.fileEnv})
	}
	if dir := rv.getenv(EnvCredentialsDirectory); dir != "" {
		if !filepath.IsAbs(dir) {
			return Root{}, fmt.Errorf("%w: %s=%q is not an absolute path", ErrRefused, EnvCredentialsDirectory, dir)
		}
		path := filepath.Join(dir, s.credential)
		switch _, err := os.Lstat(path); {
		case err == nil:
			v, rerr := rv.readFile(path, "the systemd credential "+s.credential)
			if rerr != nil {
				return Root{}, rerr
			}
			found = append(found, Root{Value: v, Source: SourceCredential, Path: path, Variable: s.credential})
		case errors.Is(err, fs.ErrNotExist):
			// The unit loads other credentials, or none of this one: not
			// configured here, which is not an error.
		default:
			return Root{}, fmt.Errorf("%w: the systemd credential %s: %v", ErrUnreadable, s.credential, err)
		}
	}
	if v := rv.getenv(s.env); v != "" {
		found = append(found, Root{Value: v, Source: SourceEnvironment, Variable: s.env})
	}
	if len(found) == 0 {
		return Root{}, nil
	}
	first := found[0]
	for _, other := range found[1:] {
		if subtle.ConstantTimeCompare([]byte(other.Value), []byte(first.Value)) != 1 {
			return Root{}, fmt.Errorf("%w: %s and %s both set %s, to different keys — remove the one the "+
				"hub is not meant to run on", ErrConflict, first.Describe(), other.Describe(), s.name)
		}
		first.Also = append(first.Also, other.Source)
	}
	return first, nil
}

// readFile reads a key file after checking that nobody but this process — or
// root — can have put the key there or read it back. what names the setting
// that pointed at it, for messages.
func (rv resolver) readFile(path, what string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: %s=%q is not an absolute path", ErrRefused, what, path)
	}
	if InsideCloopDir(path) {
		return "", fmt.Errorf("%w: %s is inside a .cloop/ directory, which backups, snapshots and a seeded "+
			"sandbox carry with the database — keep the key apart from what it protects", ErrRefused, path)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%w: %s (%s): %v", ErrUnreadable, path, what, err)
	}
	if InsideCloopDir(real) {
		return "", fmt.Errorf("%w: %s resolves to %s, inside a .cloop/ directory", ErrRefused, path, real)
	}
	// The checks are made on the descriptor that is read, not on the name, so
	// a file swapped between the check and the read is checked as itself.
	f, err := os.Open(real)
	if err != nil {
		return "", fmt.Errorf("%w: %s (%s): %v", ErrUnreadable, path, what, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrUnreadable, path, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s is not a regular file (%s)", ErrRefused, path, fi.Mode().Type())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%w: %s: cannot read its owner", ErrRefused, path)
	}
	// A root-owned file another user reads may be readable through an ACL,
	// which its mode bits do not show; see acl.go.
	var acl []aclEntry
	if st.Uid == 0 && rv.euid != 0 {
		if acl, err = readACL(f); err != nil {
			return "", fmt.Errorf("%w: %s: cannot read its ACL: %v", ErrRefused, path, err)
		}
	}
	if err := rv.checkAccess(path, int(st.Uid), int(st.Gid), fi.Mode().Perm(), acl); err != nil {
		return "", err
	}

	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	defer zero(data)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrUnreadable, path, err)
	}
	if len(data) > maxFileSize {
		return "", fmt.Errorf("%w: %s holds more than %d bytes, which is not a key", ErrRefused, path, maxFileSize)
	}
	// One trailing newline is what `echo` and most editors add, and is not part
	// of the key; nothing else is stripped, so a key whose value really ends in
	// a space reads back as itself.
	key := bytes.TrimSuffix(data, []byte("\n"))
	key = bytes.TrimSuffix(key, []byte("\r"))
	switch {
	case len(key) == 0:
		return "", fmt.Errorf("%w: %s is empty", ErrRefused, path)
	case bytes.IndexByte(key, 0) >= 0:
		return "", fmt.Errorf("%w: %s holds a NUL byte, which no environment variable can — "+
			"it would be a different key there", ErrRefused, path)
	}
	return string(key), nil
}

// checkAccess is the owner and mode rule: a key file belongs to this process
// and is readable by nobody else (0400 or 0600).
//
// Two shapes owned by root are accepted as well, because they are the ones
// Kubernetes and systemd make and cannot be asked to make differently. A
// Secret volume's files are owned by root and, with the Pod's fsGroup set —
// which a hub needs for its own volume — readable through that group, 0440
// from a defaultMode of 0400: the process reads it as a member of the group,
// and nobody outside the Pod's group can. A systemd credential is owned by
// root and readable through an ACL entry naming the unit's user (acl, the
// file's extended ACL, nil when it has none), judged by checkACL. Root owning
// a file grants nothing root did not have already.
func (rv resolver) checkAccess(path string, uid, gid int, perm fs.FileMode, acl []aclEntry) error {
	switch {
	case perm&0o022 != 0:
		return fmt.Errorf("%w: %s can be written by users other than its owner (mode %04o); chmod 0400 it",
			ErrRefused, path, perm)
	case perm&0o007 != 0:
		return fmt.Errorf("%w: %s can be read by every user on the host (mode %04o); chmod 0400 it",
			ErrRefused, path, perm)
	case perm&0o111 != 0:
		return fmt.Errorf("%w: %s is executable (mode %04o); a key file is 0400 or 0600", ErrRefused, path, perm)
	}
	switch {
	case uid == rv.euid:
		if perm&0o070 != 0 {
			return fmt.Errorf("%w: %s can be read by its group (mode %04o); chmod 0400 it", ErrRefused, path, perm)
		}
		return nil
	case uid == 0 && acl != nil:
		// The group bits are the ACL's mask here, not the group's permission.
		return rv.checkACL(path, gid, acl)
	case uid == 0 && perm&0o070 == 0o040 && rv.inGroup(gid):
		return nil
	case uid == 0:
		return fmt.Errorf("%w: %s is owned by root and this process (uid %d) reads it only through a group it "+
			"is not in, or through no group at all (mode %04o); chown it to the hub's user, mode 0400",
			ErrRefused, path, rv.euid, perm)
	}
	return fmt.Errorf("%w: %s is owned by uid %d, not by this process (uid %d) — another user could replace "+
		"the key; chown it to the hub's user, mode 0400", ErrRefused, path, uid, rv.euid)
}

func (rv resolver) inGroup(gid int) bool {
	if gid == rv.gid {
		return true
	}
	for _, g := range rv.groups {
		if g == gid {
			return true
		}
	}
	return false
}

// InsideCloopDir reports whether path has a .cloop component. A key file, like
// an escrow, has to be kept apart from the directory a database backup, a
// snapshot or a seeded sandbox carries: the key protects that directory's
// contents, and kept inside it, it protects nothing from whoever gets a copy.
func InsideCloopDir(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(filepath.Clean(path)), "/") {
		if part == ".cloop" {
			return true
		}
	}
	return false
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
