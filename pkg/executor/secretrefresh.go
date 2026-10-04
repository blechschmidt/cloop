package executor

// secretrefresh.go rewrites credential files a lease already delivered to a
// workload that is still running (Task 20375).
//
// # Why a running workload's files change at all
//
// A lease's files were written once, at dispatch, and nothing changed them
// until the workload exited and they were wiped. That was right for every
// credential the hub does not mint. A GitHub App installation token is the
// exception: GitHub honours it for an hour, and a run still using git after
// that met a dead token in its own github-token file. The hub re-mints it
// before then (pkg/secretbroker/apprefresh.go); this is how the new token
// reaches the file git's credential helper reads on every call.
//
// # What a driver promises
//
// Only files the lease already delivered are rewritten — a name the workload
// was never given is refused, so a refresh cannot become a way to plant a new
// file in a sandbox — and each is replaced atomically: a new file is written
// beside it and renamed over it, so a reader sees the old content or the new,
// never half of each. The rename is also what makes the change visible inside
// a container: the lease directory is bind-mounted whole, and a directory
// mount follows a rename inside it. (A *single-file* bind mount would not —
// it pins the inode it was given — which is why no driver mounts lease files
// one by one.)
//
// And the new content joins the holder's output redaction, so a workload that
// prints its token after a refresh has it scrubbed exactly as it would have
// been before one.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/securewipe"
)

// SecretRefreshRequest replaces files one lease already placed for the
// workloads holding it.
type SecretRefreshRequest struct {
	// LeaseID is the lease whose files change. Required.
	LeaseID string
	// Files carry the replacements: Dir is the directory as the workload's
	// environment names it (the lease's declared directory), Name the bare
	// name the file was delivered under, Content the new plaintext.
	Files []SecretFile
	// Reason is operator-facing, for the driver's log.
	Reason string
}

// Validate checks the request before a driver writes anything.
func (r SecretRefreshRequest) Validate() error {
	if strings.TrimSpace(r.LeaseID) == "" {
		return fmt.Errorf("%w: a secret refresh names no lease", ErrInvalidSpec)
	}
	if len(r.Files) == 0 {
		return fmt.Errorf("%w: a secret refresh for lease %s carries no files", ErrInvalidSpec, r.LeaseID)
	}
	for i, f := range r.Files {
		if lid := strings.TrimSpace(f.LeaseID); lid != "" && lid != strings.TrimSpace(r.LeaseID) {
			return fmt.Errorf("%w: secret refresh file %d belongs to lease %s, not %s",
				ErrInvalidSpec, i, lid, r.LeaseID)
		}
	}
	return ValidateSecretFiles(r.Files)
}

// Values returns the plaintext the request carries, for the holder's output
// redaction.
func (r SecretRefreshRequest) Values() []string {
	var out []string
	for _, f := range r.Files {
		out = append(out, redact.Values(f.Content)...)
	}
	return out
}

// SecretRefreshReport is what one executor did with a refresh.
type SecretRefreshReport struct {
	LeaseID string `json:"lease_id"`
	// Known reports whether the executor holds the lease at all. False with no
	// Error is "nothing here to refresh", not a failure.
	Known bool `json:"known"`
	// FilesRewritten counts files replaced, across every workload holding the
	// lease.
	FilesRewritten int `json:"files_rewritten,omitempty"`
	// Handles names the workloads reached.
	Handles []string `json:"handles,omitempty"`
	// Eventual: the files went to something that delivers them later — the
	// kubelet syncing a Secret volume — so the workload reads the new content
	// within that sync, not at once. The hub then leaves the superseded
	// credential to lapse on its own rather than destroying it early.
	Eventual bool `json:"eventual,omitempty"`
	// Unsupported: the executor cannot rewrite files in a running workload at
	// all — a remote agent speaking too old a protocol. The workload keeps the
	// credential it was given until that lapses; Error says why.
	Unsupported bool `json:"unsupported,omitempty"`
	// Error is non-empty when part of the refresh failed.
	Error string `json:"error,omitempty"`
}

// Delivered reports whether every holder on this executor has the new files.
func (r SecretRefreshReport) Delivered() bool {
	return r.Error == "" && !r.Unsupported
}

// SecretRefresher is an executor that can rewrite a lease's files inside
// workloads it already started.
//
// Optional: a driver that does not implement it keeps the files it delivered
// for the life of the workload, and a token among them lapses when GitHub says
// so — the behaviour every driver had before Task 20375.
type SecretRefresher interface {
	Executor
	// RefreshSecretFiles rewrites req's files in every workload holding
	// req.LeaseID and extends each holder's output redaction to the new
	// content. A driver holding nothing for the lease answers Known false.
	RefreshSecretFiles(ctx context.Context, req SecretRefreshRequest) SecretRefreshReport
}

// AsSecretRefresher returns ex as a SecretRefresher, reporting whether it is
// one.
func AsSecretRefresher(ex Executor) (SecretRefresher, bool) {
	sr, ok := ex.(SecretRefresher)
	return sr, ok
}

// FileOwner is who a replaced credential file belongs to.
type FileOwner struct{ UID, GID int }

// FileIdentity names one directory on one filesystem, so a replacement can
// insist that the directory it writes into is still the one the lease created.
type FileIdentity struct{ Dev, Ino uint64 }

// ReplaceOptions shapes a ReplaceSecretFile.
type ReplaceOptions struct {
	// Mode of the new file. Zero means 0600; group or world bits are refused.
	Mode fs.FileMode
	// Owner, when set, is given the new file — through its descriptor, never
	// by path. Nil leaves it owned by this process.
	Owner *FileOwner
	// Dir, when set, is the identity the lease directory must still have.
	// A directory renamed away and replaced — by anyone able to rename an
	// entry in its parent, such as the sandbox user who owns it in a sticky
	// /dev/shm — is refused rather than written into.
	Dir *FileIdentity
}

// ReplaceSecretFile atomically replaces the credential file at path, which
// must already exist as a regular file inside a lease-owned directory.
//
// Everything is done relative to the directory, opened once without following
// a symlink in its place: the new content is written to a fresh file created
// exclusively in it, given its mode and owner through its own descriptor, and
// renamed over the old name in it. Nothing is ever done by path to a name
// someone else could have swapped — which matters because a container's lease
// directory belongs to the sandbox user, and a hub running as root that chowned
// "the temp file" by path could be steered into chowning /etc/shadow. rename(2)
// replaces a symlink planted at the old name rather than writing through it, and
// a reader sees the old content or the new, never a mixture. A failure zeroes
// and removes the new file.
//
// The old content is not overwritten: a process may be reading it at this
// moment, and the credential it holds is destroyed at its source once the
// workload has had time to move to the new one, which is what makes the stale
// bytes worthless.
func ReplaceSecretFile(path string, content []byte, opts ReplaceOptions) error {
	clean := filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("%w: secret file %q is not an absolute path", ErrInvalidSpec, path)
	}
	dir, name := filepath.Dir(clean), filepath.Base(clean)
	if !securewipe.IsLeaseDir(dir) {
		return fmt.Errorf("%w: refusing to rewrite %s: %s is not a lease directory", ErrInvalidSpec, clean, dir)
	}
	mode := opts.Mode
	if mode == 0 {
		mode = 0o600
	}
	if mode&^fs.FileMode(0o777) != 0 || mode&0o077 != 0 {
		return fmt.Errorf("%w: secret file %s would be created with mode %v", ErrInvalidSpec, clean, mode)
	}
	return replaceInDir(dir, name, content, mode, opts)
}

// errReplaceUnsupported is what a platform without directory-relative file
// operations answers.
var errReplaceUnsupported = errors.New("executor: replacing a credential file in place is not supported on this platform")
