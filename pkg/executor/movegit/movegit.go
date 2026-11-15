// Package movegit is the git half of a project move (Task 20494): it captures
// what a repository holds — every local branch and tag, and the working
// tree's uncommitted state — into one bundle without touching the user's
// branch or index, rebuilds a working copy from that bundle elsewhere, and
// reads a working copy back so the two can be compared.
//
// # Capture
//
// The working tree's state is recorded the way `git stash` records it, and
// with none of what `git stash` does besides: two commits written into the
// repository's object store and one hidden ref, refs/cloop/move/<id>,
// pointing at them.
//
//   - the index commit's tree is the index as it is — what is staged —
//     written from a copy of the index file, so the real one is never
//     rewritten (not even its cache-tree);
//   - the working-tree commit's tree is the files on disk, including
//     untracked ones that .gitignore does not exclude, built in a second
//     copy of the index with `git add -A`; its parents are HEAD and the
//     index commit.
//
// The project's own .cloop directory is left out of the working-tree state:
// it is the hub's bookkeeping, and pkg/projectmove accounts for its files
// separately. Every linked worktree inside the project (a feature's, a kept
// task worktree) is recorded the same way on refs/cloop/move-worktree/<id>/<n>
// when it holds changes, and each stash entry on refs/cloop/move-stash/<id>/<n>,
// since a bundle carries refs and no reflog. The bundle then holds every
// local branch, every tag and those refs: a clone of it is the repository.
//
// A device keeps each of a project's features in a working copy of its own,
// beside the project's rather than inside it (Task 20495). Such a repository
// is captured as an external tree: its working-tree state recorded the same
// way, in its own object store, then its branches and that snapshot fetched
// into the project's repository under refs/cloop/move-feature/<id>/<n>/, so
// the one bundle carries it too.
//
// A capture of a tree a workload could write checks every path git is about
// to work in with CaptureOptions.Confine first: a linked worktree that git's
// own records place inside the project but that a symbolic link leads out of
// is refused, not followed.
//
// # Restore
//
// Restore fetches every ref of the bundle into a repository, puts HEAD back
// on the original branch, and replays the snapshot as uncommitted changes:
// `read-tree -u --reset` of the working-tree tree (which writes the files,
// untracked ones included, and removes what the snapshot deleted), then
// `read-tree` of the index tree (which restores what was staged without
// touching a file). The bytes on disk are the blobs the capture hashed:
// renames, deletions, binary files, symbolic links and the executable bit
// come back as they were.
//
// # Hardening
//
// Every command runs like pkg/executor/gitstate's and featurehub's: no system
// or global configuration, no hook, filter, fsmonitor or signing program from
// the repository's own configuration, safe.directory for a tree a sandbox
// owns, and a ceiling at the project so git never answers for an enclosing
// repository. It lives under pkg/executor for the reason gitstate gives: it
// starts git, and tests/security allows processes to be started only from
// this tree.
package movegit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
)

// ManifestVersion is the version of the manifest this build writes and reads.
const ManifestVersion = 1

// EmptyTree is git's empty tree, the snapshot of a repository with nothing in
// it.
const EmptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// Ref namespaces a move writes into the source repository.
const (
	// SnapshotRefPrefix + id is the main worktree's snapshot.
	SnapshotRefPrefix = "refs/cloop/move/"
	// WorktreeRefPrefix + id + "/" + n is a linked worktree's snapshot.
	WorktreeRefPrefix = "refs/cloop/move-worktree/"
	// StashRefPrefix + id + "/" + n is stash entry n.
	StashRefPrefix = "refs/cloop/move-stash/"
	// ExternalRefPrefix + id + "/" + n + "/" holds external tree n: its
	// branches under heads/ and its snapshot as snapshot.
	ExternalRefPrefix = "refs/cloop/move-feature/"
)

// Defaults for the options' zero values.
const (
	// DefaultCommandTimeout bounds one git command.
	DefaultCommandTimeout = 10 * time.Minute
	// maxOutput bounds what one git command may print.
	maxOutput = 16 << 20
	// MaxRefs bounds how many branches and tags a capture records.
	MaxRefs = 20000
	// MaxWorktrees bounds how many linked worktrees a capture records.
	MaxWorktrees = 256
	// MaxStash bounds how many stash entries a capture records.
	MaxStash = 1000
)

// Identity is who the capture's commits are attributed to: the same identity
// a provisioned tree commits as (gitprovision.CommitIdentity*).
const (
	identityName  = gitprovision.CommitIdentityName
	identityEmail = gitprovision.CommitIdentityEmail
)

// ErrTooLarge is returned when a bundle would be larger than its bound.
var ErrTooLarge = errors.New("movegit: the bundle is larger than the move allows")

// ErrNotARepository is returned by Restore and Inspect for a directory that
// holds no repository where one is required.
var ErrNotARepository = errors.New("movegit: not a git repository")

// Manifest is what a capture recorded: enough to rebuild the repository from
// the bundle and to check a rebuilt one against it.
type Manifest struct {
	Version int    `json:"version"`
	MoveID  string `json:"move_id"`
	// Repository is false for a project with no .git: nothing of git was
	// captured, and the rest of the manifest is empty.
	Repository bool `json:"repository"`
	// Head is where the main worktree's HEAD was.
	Head Head `json:"head"`
	// Branches and Tags are every local branch and tag, by full ref name.
	Branches []Ref `json:"branches"`
	Tags     []Ref `json:"tags,omitempty"`
	// Snapshot is the main worktree's uncommitted state.
	Snapshot *Snapshot `json:"snapshot,omitempty"`
	// Worktrees are the linked worktrees inside the project.
	Worktrees []Worktree `json:"worktrees,omitempty"`
	// Stash are the stash entries, newest first, each on its own ref.
	Stash []Ref `json:"stash,omitempty"`
	// Carried are the branches of the external trees, each on a hidden ref
	// under ExternalRefPrefix: what the bundle carries of repositories that
	// are not this one (a device's features' working copies).
	Carried []Ref `json:"carried,omitempty"`
	// Remotes are the configured remotes, their URLs with any user
	// information (a token in an https URL) removed.
	Remotes []Remote `json:"remotes,omitempty"`
	// Bundle is the bundle file's size and digest.
	Bundle *Digest `json:"bundle,omitempty"`
	// Notes say what the capture could not keep exactly.
	Notes []string `json:"notes,omitempty"`
}

// Head is where a worktree's HEAD is.
type Head struct {
	// Branch is the checked-out branch's full ref name; "" when detached.
	Branch string `json:"branch,omitempty"`
	// Commit is the commit HEAD resolves to; "" while the branch is unborn.
	Commit   string `json:"commit,omitempty"`
	Detached bool   `json:"detached,omitempty"`
	Unborn   bool   `json:"unborn,omitempty"`
}

// Ref is one ref and what it names.
type Ref struct {
	// Name is the full ref name.
	Name string `json:"name"`
	// Object is what the ref points at: a commit, or a tag object.
	Object string `json:"object"`
	// Commit and Tree are the commit the ref peels to and its tree, when it
	// peels to a commit.
	Commit string `json:"commit,omitempty"`
	Tree   string `json:"tree,omitempty"`
	// Pushed reports, for a branch, that a remote-tracking branch contains
	// it, as of the repository's last fetch or push.
	Pushed bool `json:"pushed,omitempty"`
}

// Snapshot is one worktree's uncommitted state.
type Snapshot struct {
	// Ref is the hidden ref the snapshot commit was written to; "" for a
	// linked worktree with nothing to record.
	Ref string `json:"ref,omitempty"`
	// Commit is the working-tree commit (parents: Base, the index commit).
	Commit string `json:"commit,omitempty"`
	// Base and BaseTree are HEAD and its tree; empty while unborn (the tree
	// is then EmptyTree).
	Base     string `json:"base,omitempty"`
	BaseTree string `json:"base_tree"`
	// IndexTree is the index; WorktreeTree the files on disk.
	IndexTree    string `json:"index_tree"`
	WorktreeTree string `json:"worktree_tree"`
	// Dirty reports that the index or the files differ from HEAD.
	Dirty bool `json:"dirty"`
	// IndexNote says why the index was not recorded as it was, when it was
	// not (it held unresolved conflicts, which no tree can hold).
	IndexNote string `json:"index_note,omitempty"`
}

// Worktree is a linked worktree inside the project.
type Worktree struct {
	// Rel is the worktree's path relative to the project.
	Rel  string `json:"rel"`
	Head Head   `json:"head"`
	Snapshot
}

// Remote is a configured remote.
type Remote struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Digest is a file's size and SHA-256.
type Digest struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Dirty reports whether any worktree the manifest records holds changes.
func (m Manifest) Dirty() bool {
	if m.Snapshot != nil && m.Snapshot.Dirty {
		return true
	}
	for _, w := range m.Worktrees {
		if w.Dirty {
			return true
		}
	}
	return false
}

// UnpushedCarried returns the branches of the external trees the manifest
// carries that no remote-tracking branch of their repository contains, and
// their stash entries: work a target built from the forge would not see.
func (m Manifest) UnpushedCarried() []Ref {
	var out []Ref
	for _, c := range m.Carried {
		rest := strings.TrimPrefix(c.Name, ExternalRefPrefix+m.MoveID+"/")
		_, kind, _ := strings.Cut(rest, "/")
		switch {
		case strings.HasPrefix(kind, "heads/") && !c.Pushed, strings.HasPrefix(kind, "stash/"):
			out = append(out, c)
		}
	}
	return out
}

// CarriedName is a carried ref's name as its own repository knows it:
// refs/heads/main for ExternalRefPrefix<id>/0/heads/main.
func (m Manifest) CarriedName(c Ref) string {
	rest := strings.TrimPrefix(c.Name, ExternalRefPrefix+m.MoveID+"/")
	if _, name, ok := strings.Cut(rest, "/"); ok {
		return "refs/" + name
	}
	return c.Name
}

// Unpushed returns the branches no remote-tracking branch contains.
func (m Manifest) Unpushed() []Ref {
	var out []Ref
	for _, b := range m.Branches {
		if !b.Pushed {
			out = append(out, b)
		}
	}
	return out
}

// CaptureOptions configure Capture.
type CaptureOptions struct {
	// MoveID names the move; it becomes part of the hidden refs' names.
	MoveID string
	// Dir is the project's directory, the top of its repository.
	Dir string
	// BundlePath is where the bundle is written. Its directory must exist.
	BundlePath string
	// MaxBundleBytes bounds the bundle; zero means no bound.
	MaxBundleBytes int64
	// Exclude lists paths, relative to each worktree, that are not part of
	// its working-tree state. Nil means ".cloop".
	Exclude []string
	// CommandTimeout bounds each git command; zero means the default.
	CommandTimeout time.Duration
	// Now stamps the snapshot commits; nil means time.Now.
	Now func() time.Time
	// Confine, when set, is asked about every directory git is about to work
	// in besides Dir itself — each linked worktree and each external tree —
	// and an error refuses the capture. A capture of a tree a workload could
	// write sets it, so that a worktree a symbolic link leads out of is never
	// read.
	Confine func(dir string) error
	// External are repositories outside Dir the capture carries as hidden
	// refs: a device's features' working copies, which it keeps beside the
	// project's. One with no repository is skipped, with a note.
	External []ExternalTree
	// Credential, when set, runs every git command of the capture in Dir as
	// that user: the working copy's owner, for an agent running as root, so
	// what git writes into the repository is the workload's own and what it
	// could read is no more than the workload could.
	Credential *syscall.Credential
}

// ExternalTree is a repository outside the project's directory that a
// capture carries.
type ExternalTree struct {
	// Rel is how the manifest names it: the feature's path inside the
	// project, .cloop/features/<slug>.
	Rel string
	// Dir is the repository's directory.
	Dir string
	// Credential is CaptureOptions.Credential for this repository.
	Credential *syscall.Credential
}

// ValidMoveID reports whether id may name a move's refs: letters, digits and
// '-', at most 64 characters, starting with a letter or digit.
func ValidMoveID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}

// Capture records the repository at opts.Dir into a bundle at
// opts.BundlePath. A directory with no .git is not an error: the manifest
// says Repository false and no bundle is written.
func Capture(ctx context.Context, opts CaptureOptions) (Manifest, error) {
	m := Manifest{Version: ManifestVersion, MoveID: opts.MoveID, Branches: []Ref{}}
	if !ValidMoveID(opts.MoveID) {
		return m, fmt.Errorf("movegit: %q cannot name a move", opts.MoveID)
	}
	dir, err := checkDir(opts.Dir)
	if err != nil {
		return m, err
	}
	present, err := hasDotGit(dir)
	if err != nil || !present {
		return m, err
	}
	if strings.TrimSpace(opts.BundlePath) == "" {
		return m, errors.New("movegit: no bundle path")
	}
	g, err := newRunner(ctx, dir, opts.CommandTimeout)
	if err != nil {
		return m, err
	}
	g.now = opts.Now
	g.isolate(opts.Credential)
	if err := g.checkTop(ctx, dir); err != nil {
		return m, err
	}
	m.Repository = true
	exclude := opts.Exclude
	if exclude == nil {
		exclude = []string{".cloop"}
	}

	if m.Head, err = g.head(ctx, dir); err != nil {
		return m, err
	}
	if m.Branches, err = g.refs(ctx, dir, "refs/heads/", true); err != nil {
		return m, err
	}
	if m.Tags, err = g.refs(ctx, dir, "refs/tags/", false); err != nil {
		return m, err
	}
	if m.Remotes, err = g.remotes(ctx, dir); err != nil {
		return m, err
	}

	// Every linked worktree is listed, and confined, before git reads any
	// working tree: the main one's `add -A` already looks into a directory
	// a worktree's gitfile names.
	wts, err := g.linkedWorktrees(ctx, dir)
	if err != nil {
		return m, err
	}
	if opts.Confine != nil {
		for _, wt := range wts {
			if err := opts.Confine(wt.path); err != nil {
				return m, fmt.Errorf("movegit: the worktree %s: %w", wt.rel, err)
			}
		}
		for _, ext := range opts.External {
			if err := opts.Confine(ext.Dir); err != nil {
				return m, fmt.Errorf("movegit: %s: %w", ext.Rel, err)
			}
		}
	}

	tmp, err := os.MkdirTemp("", "cloop-move-index-*")
	if err != nil {
		return m, fmt.Errorf("movegit: %w", err)
	}
	defer os.RemoveAll(tmp)
	if err := handTo(tmp, opts.Credential); err != nil {
		return m, err
	}

	snap, err := g.snapshot(ctx, dir, m.Head, exclude, tmp, "main")
	if err != nil {
		return m, fmt.Errorf("movegit: record the working tree of %s: %w", dir, err)
	}
	snap.Ref = SnapshotRefPrefix + opts.MoveID
	if snap.Commit, err = g.snapshotCommit(ctx, dir, opts.MoveID, "the project", snap); err != nil {
		return m, err
	}
	if _, err := g.run(ctx, dir, nil, "update-ref", "-m", "cloop move "+opts.MoveID, snap.Ref, snap.Commit); err != nil {
		return m, fmt.Errorf("movegit: write %s: %w", snap.Ref, err)
	}
	m.Snapshot = &snap
	if snap.IndexNote != "" {
		m.Notes = append(m.Notes, "the project: "+snap.IndexNote)
	}

	for i, wt := range wts {
		w := Worktree{Rel: wt.rel, Head: wt.head}
		s, err := g.snapshot(ctx, wt.path, wt.head, exclude, tmp, strconv.Itoa(i))
		if err != nil {
			return m, fmt.Errorf("movegit: record the worktree %s: %w", wt.rel, err)
		}
		w.Snapshot = s
		if s.Dirty {
			w.Ref = fmt.Sprintf("%s%s/%d", WorktreeRefPrefix, opts.MoveID, i)
			if w.Commit, err = g.snapshotCommit(ctx, wt.path, opts.MoveID, wt.rel, s); err != nil {
				return m, err
			}
			if _, err := g.run(ctx, dir, nil, "update-ref", "-m", "cloop move "+opts.MoveID, w.Ref, w.Commit); err != nil {
				return m, fmt.Errorf("movegit: write %s: %w", w.Ref, err)
			}
		}
		if s.IndexNote != "" {
			m.Notes = append(m.Notes, wt.rel+": "+s.IndexNote)
		}
		m.Worktrees = append(m.Worktrees, w)
	}

	if m.Stash, err = g.stash(ctx, dir, opts.MoveID); err != nil {
		return m, err
	}

	for i, ext := range opts.External {
		ws, carried, note, err := g.captureExternal(ctx, dir, opts, exclude, tmp, i, ext)
		if err != nil {
			return m, err
		}
		if note != "" {
			m.Notes = append(m.Notes, note)
		}
		for _, w := range ws {
			if w.IndexNote != "" {
				m.Notes = append(m.Notes, w.Rel+": "+w.IndexNote)
			}
		}
		m.Worktrees = append(m.Worktrees, ws...)
		m.Carried = append(m.Carried, carried...)
	}

	refs := []string{"--branches", "--tags", m.Snapshot.Ref}
	for _, w := range m.Worktrees {
		if w.Ref != "" {
			refs = append(refs, w.Ref)
		}
	}
	for _, s := range m.Stash {
		refs = append(refs, s.Name)
	}
	for _, c := range m.Carried {
		refs = append(refs, c.Name)
	}
	digest, err := g.bundle(ctx, dir, opts.BundlePath, opts.MaxBundleBytes, refs)
	if err != nil {
		return m, err
	}
	m.Bundle = &digest
	return m, nil
}

// Bounds ValidateManifest holds a manifest to, beyond the capture's own.
const (
	maxManifestNotes    = 256
	maxManifestNoteLen  = 2048
	maxRelLen           = 1024
	maxRefNameLen       = 1024
	maxRemoteURLLen     = 4096
	maxManifestExternal = 256
)

// ErrInvalidManifest is a manifest ValidateManifest refuses.
var ErrInvalidManifest = errors.New("movegit: invalid manifest")

// ValidateManifest checks a manifest before anything acts on it: that every
// object id is hexadecimal, every ref a well-formed name in the namespace its
// field belongs to, every remote a plain name with a URL that cannot be read
// as an option, every path plainly relative, and every list within the
// capture's bounds. Restore runs git with these values as arguments, so a
// manifest from a device the hub does not trust (Task 20495) — or a carrier
// it did not build — is refused here rather than handed to git.
func ValidateManifest(m Manifest, moveID string) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalidManifest}, a...)...)
	}
	if m.Version != ManifestVersion {
		return bad("version %d, this build reads %d", m.Version, ManifestVersion)
	}
	if !ValidMoveID(m.MoveID) || (moveID != "" && m.MoveID != moveID) {
		return bad("it is for move %q, not %q", m.MoveID, moveID)
	}
	if len(m.Notes) > maxManifestNotes {
		return bad("%d notes, at most %d", len(m.Notes), maxManifestNotes)
	}
	for _, n := range m.Notes {
		if len(n) > maxManifestNoteLen {
			return bad("a note of %d bytes, at most %d", len(n), maxManifestNoteLen)
		}
	}
	if !m.Repository {
		if len(m.Branches)+len(m.Tags)+len(m.Stash)+len(m.Carried)+len(m.Worktrees) > 0 || m.Snapshot != nil || m.Bundle != nil {
			return bad("it records no repository and still names refs or a bundle")
		}
		return nil
	}
	if err := validHead(m.Head); err != nil {
		return bad("HEAD: %v", err)
	}
	if len(m.Branches)+len(m.Tags) > MaxRefs || len(m.Stash) > MaxStash ||
		len(m.Worktrees) > MaxWorktrees+maxManifestExternal || len(m.Carried) > MaxRefs {
		return bad("it names more refs or worktrees than a capture records")
	}
	refLists := []struct {
		what, prefix string
		refs         []Ref
	}{
		{"branch", "refs/heads/", m.Branches},
		{"tag", "refs/tags/", m.Tags},
		{"stash ref", StashRefPrefix + m.MoveID + "/", m.Stash},
		{"carried ref", ExternalRefPrefix + m.MoveID + "/", m.Carried},
	}
	for _, l := range refLists {
		for _, r := range l.refs {
			if err := validRef(r, l.prefix); err != nil {
				return bad("%s %q: %v", l.what, r.Name, err)
			}
		}
	}
	if m.Snapshot == nil {
		return bad("it records a repository and no snapshot")
	}
	if m.Snapshot.Ref != SnapshotRefPrefix+m.MoveID {
		return bad("the snapshot is on %q, not %s", m.Snapshot.Ref, SnapshotRefPrefix+m.MoveID)
	}
	if err := validSnapshot(*m.Snapshot, true); err != nil {
		return bad("the snapshot: %v", err)
	}
	for _, w := range m.Worktrees {
		if !validRel(w.Rel) {
			return bad("a worktree at %q, which is not a plain relative path", w.Rel)
		}
		if err := validHead(w.Head); err != nil {
			return bad("the worktree %s's HEAD: %v", w.Rel, err)
		}
		if w.Ref != "" && (!validRefName(w.Ref) || (!strings.HasPrefix(w.Ref, WorktreeRefPrefix+m.MoveID+"/") &&
			!strings.HasPrefix(w.Ref, ExternalRefPrefix+m.MoveID+"/"))) {
			return bad("the worktree %s is on %q, outside the move's namespaces", w.Rel, w.Ref)
		}
		if err := validSnapshot(w.Snapshot, w.Ref != ""); err != nil {
			return bad("the worktree %s: %v", w.Rel, err)
		}
	}
	for _, r := range m.Remotes {
		if !validRemoteName(r.Name) {
			return bad("a remote named %q", r.Name)
		}
		if len(r.URL) > maxRemoteURLLen || strings.HasPrefix(r.URL, "-") || strings.ContainsFunc(r.URL, isControl) {
			return bad("remote %s's URL is not one a capture records", r.Name)
		}
	}
	if m.Bundle == nil || m.Bundle.Bytes < 0 || !validSHA256(m.Bundle.SHA256) {
		return bad("its bundle's size or digest is missing or malformed")
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// validObject reports whether s is a full object id, SHA-1 or SHA-256.
func validObject(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validSHA256(s string) bool { return len(s) == 64 && validObject(s) }

// validRefName reports whether s is a ref name git accepts, under refs/: no
// component starting with a dot or ending in .lock, no "..", no "@{", none of
// git's forbidden characters, nothing a shell or an option parser would read
// as more than a name.
func validRefName(s string) bool {
	if len(s) > maxRefNameLen || !strings.HasPrefix(s, "refs/") || strings.HasSuffix(s, "/") ||
		strings.HasSuffix(s, ".") || strings.Contains(s, "..") || strings.Contains(s, "@{") || strings.Contains(s, "//") {
		return false
	}
	for _, r := range s {
		switch {
		case isControl(r), r == ' ', r == '~', r == '^', r == ':', r == '?', r == '*', r == '[', r == '\\':
			return false
		}
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

func validRef(r Ref, prefix string) error {
	if !validRefName(r.Name) || !strings.HasPrefix(r.Name, prefix) {
		return fmt.Errorf("not a ref under %s", prefix)
	}
	if !validObject(r.Object) {
		return errors.New("its object id is malformed")
	}
	if (r.Commit != "" && !validObject(r.Commit)) || (r.Tree != "" && !validObject(r.Tree)) {
		return errors.New("its commit or tree id is malformed")
	}
	return nil
}

func validHead(h Head) error {
	if h.Branch != "" && (!validRefName(h.Branch) || !strings.HasPrefix(h.Branch, "refs/heads/")) {
		return fmt.Errorf("%q is not a branch", h.Branch)
	}
	if h.Commit != "" && !validObject(h.Commit) {
		return errors.New("its commit id is malformed")
	}
	if h.Detached && h.Commit == "" {
		return errors.New("it is detached at nothing")
	}
	return nil
}

// validSnapshot checks a snapshot's object ids; committed says it was
// written as commits, which then must be named.
func validSnapshot(s Snapshot, committed bool) error {
	for _, id := range []string{s.BaseTree, s.IndexTree, s.WorktreeTree} {
		if id != "" && !validObject(id) {
			return errors.New("a tree id is malformed")
		}
	}
	if (s.Base != "" && !validObject(s.Base)) || (s.Commit != "" && !validObject(s.Commit)) {
		return errors.New("a commit id is malformed")
	}
	if committed && (s.Commit == "" || s.IndexTree == "" || s.WorktreeTree == "") {
		return errors.New("it names no commit or no trees")
	}
	if len(s.IndexNote) > maxManifestNoteLen {
		return errors.New("its note is too long")
	}
	return nil
}

// validRel reports whether rel is a plain relative slash path.
func validRel(rel string) bool {
	if rel == "" || len(rel) > maxRelLen || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") ||
		strings.ContainsFunc(rel, isControl) {
		return false
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// EstimateBytes is what the repository at dir holds in its object store: an
// upper bound on a bundle of everything in it. Zero for a directory with no
// repository.
func EstimateBytes(ctx context.Context, dir string) (int64, error) {
	dir, err := checkDir(dir)
	if err != nil {
		return 0, err
	}
	present, err := hasDotGit(dir)
	if err != nil || !present {
		return 0, err
	}
	g, err := newRunner(ctx, dir, 0)
	if err != nil {
		return 0, err
	}
	g.isolate(nil)
	out, err := g.run(ctx, dir, nil, "count-objects", "-v")
	if err != nil {
		return 0, fmt.Errorf("movegit: count objects in %s: %w", dir, err)
	}
	var kib int64
	for _, line := range nonEmptyLines(out) {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "size", "size-pack":
			n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err == nil && n > 0 {
				kib += n
			}
		}
	}
	return kib << 10, nil
}

// RestoreOptions configure Restore.
type RestoreOptions struct {
	// Dir is where the working copy is built: an empty or absent directory,
	// or a repository the caller provisioned (whose refs the bundle's
	// replace).
	Dir string
	// BundlePath is the bundle a capture wrote, checked against
	// Manifest.Bundle before git reads it.
	BundlePath string
	Manifest   Manifest
	// Upstream, when set, is recorded as the checkout's upstream repository
	// (cloop.upstream), and set as the URL of the remote named "origin": the
	// route the hub dispatches the project's runs with, so the next run's
	// provisioning recognises the checkout as the project's.
	Upstream string
	// CommandTimeout bounds each git command; zero means the default.
	CommandTimeout time.Duration
	// Reserve, when set, is a directory of the target the restore may not
	// write into beyond the files it allows; see Reserved.
	Reserve *Reserved
}

// Reserved is a directory at the top of a working tree that the place a
// capture is restored into keeps for itself — the hub's .cloop, for a working
// copy built in the hub's own directory for the project from a device's
// capture (Task 20495) — and the regular files beneath it, relative to it, a
// capture may still carry: those a project commits by design. A snapshot
// whose working tree, index or HEAD holds anything else there — another file,
// a link, a submodule, or the directory itself as a file — is refused with
// ErrForbiddenPath: restoring it would write over what the target keeps
// there.
type Reserved struct {
	Dir   string
	Allow []string
}

// ErrForbiddenPath refuses a capture whose working tree or index holds a
// path the place it is restored into keeps for itself.
var ErrForbiddenPath = errors.New("movegit: the capture holds a path its target keeps for itself")

// upstreamConfigKey is gitprovision's record of which repository a checkout
// is of; see gitprovision.Provision.
const upstreamConfigKey = "cloop.upstream"

// Restore builds the working copy the manifest describes in opts.Dir.
func Restore(ctx context.Context, opts RestoreOptions) error {
	m := opts.Manifest
	if !m.Repository {
		return nil
	}
	if err := ValidateManifest(m, ""); err != nil {
		return err
	}
	if err := VerifyFile(opts.BundlePath, *m.Bundle); err != nil {
		return err
	}
	dir := filepath.Clean(opts.Dir)
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("movegit: %q is not an absolute path", opts.Dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("movegit: %w", err)
	}
	present, err := hasDotGit(dir)
	if err != nil {
		return err
	}
	if !present {
		g, err := newRunner(ctx, dir, opts.CommandTimeout)
		if err != nil {
			return err
		}
		if _, err := g.run(ctx, dir, nil, "-c", "init.defaultBranch=cloop-move", "init", "--quiet", "--", dir); err != nil {
			return fmt.Errorf("movegit: init %s: %w", dir, err)
		}
	}
	g, err := newRunner(ctx, dir, opts.CommandTimeout)
	if err != nil {
		return err
	}
	if err := g.checkTop(ctx, dir); err != nil {
		return err
	}
	// Every ref the bundle carries, forced: whatever a provisioning left
	// under the same names is replaced by the capture's.
	if _, err := g.run(ctx, dir, nil, "fetch", "--quiet", "--no-tags", "--update-head-ok", "--",
		opts.BundlePath, "+refs/*:refs/*"); err != nil {
		return fmt.Errorf("movegit: fetch the bundle into %s: %w", dir, err)
	}
	if err := g.reserved(ctx, dir, opts.Reserve, m.Snapshot.WorktreeTree, m.Snapshot.IndexTree, m.Snapshot.BaseTree); err != nil {
		return err
	}
	// HEAD first: read-tree then records the snapshot against the branch the
	// changes were made on.
	h := m.Head
	switch {
	case h.Detached:
		if _, err := g.run(ctx, dir, nil, "update-ref", "--no-deref", "HEAD", h.Commit); err != nil {
			return fmt.Errorf("movegit: detach HEAD at %s: %w", short(h.Commit), err)
		}
	case strings.HasPrefix(h.Branch, "refs/heads/"):
		if _, err := g.run(ctx, dir, nil, "symbolic-ref", "HEAD", h.Branch); err != nil {
			return fmt.Errorf("movegit: put HEAD on %s: %w", h.Branch, err)
		}
	default:
		return fmt.Errorf("movegit: the manifest's HEAD names no branch and no commit")
	}
	s := m.Snapshot
	if _, err := g.run(ctx, dir, nil, "read-tree", "--reset", "-u", s.WorktreeTree); err != nil {
		return fmt.Errorf("movegit: write the working tree: %w", err)
	}
	if _, err := g.run(ctx, dir, nil, "read-tree", s.IndexTree); err != nil {
		return fmt.Errorf("movegit: restore the index: %w", err)
	}
	for _, r := range m.Remotes {
		if !validRemoteName(r.Name) || strings.TrimSpace(r.URL) == "" {
			continue
		}
		url := r.URL
		if r.Name == "origin" && strings.TrimSpace(opts.Upstream) != "" {
			url = strings.TrimSpace(opts.Upstream)
		}
		if _, err := g.run(ctx, dir, nil, "config", "--local", "remote."+r.Name+".url", url); err != nil {
			return fmt.Errorf("movegit: set remote %s: %w", r.Name, err)
		}
		if _, err := g.run(ctx, dir, nil, "config", "--local", "--replace-all", "remote."+r.Name+".fetch",
			"+refs/heads/*:refs/remotes/"+r.Name+"/*"); err != nil {
			return fmt.Errorf("movegit: set remote %s: %w", r.Name, err)
		}
	}
	if up := strings.TrimSpace(opts.Upstream); up != "" {
		if _, err := g.run(ctx, dir, nil, "config", "--local", upstreamConfigKey, up); err != nil {
			return fmt.Errorf("movegit: record the upstream: %w", err)
		}
	}
	return nil
}

// reserved holds trees to r: nothing beneath r.Dir but the regular files it
// allows. Paths are named quoted and cut short — they are the source's.
func (g *runner) reserved(ctx context.Context, dir string, r *Reserved, trees ...string) error {
	if r == nil || r.Dir == "" {
		return nil
	}
	allow := map[string]bool{}
	for _, a := range r.Allow {
		allow[r.Dir+"/"+a] = true
	}
	for _, tree := range trees {
		if tree == "" || tree == EmptyTree {
			continue
		}
		out, err := g.run(ctx, dir, nil, "ls-tree", "-r", "-t", "-z", "--full-tree", tree, "--", r.Dir)
		if err != nil {
			return fmt.Errorf("movegit: list tree %s: %w", short(tree), err)
		}
		for _, entry := range strings.Split(out, "\x00") {
			if entry == "" {
				continue
			}
			meta, path, ok := strings.Cut(entry, "\t")
			f := strings.Fields(meta)
			if !ok || len(f) != 3 {
				return fmt.Errorf("movegit: list tree %s: an entry git did not describe", short(tree))
			}
			if path != r.Dir && !strings.HasPrefix(path, r.Dir+"/") {
				continue
			}
			mode, kind := f[0], f[1]
			switch {
			case kind == "tree" && mode == "040000":
				// The directory, or one beneath it: its entries are listed
				// too.
				continue
			case allow[path] && kind == "blob" && (mode == "100644" || mode == "100755"):
				continue
			}
			return fmt.Errorf("%w: its tree %s holds %s (%s), which the target keeps for itself; only %s may be carried there",
				ErrForbiddenPath, short(tree), quotePath(path), kindOfMode(mode), allowedList(r))
		}
	}
	return nil
}

// quotePath is a path a source chose, for a message: quoted, so nothing in it
// acts on a terminal, and cut short.
func quotePath(p string) string {
	const most = 160
	if len(p) > most {
		p = p[:most] + "…"
	}
	return strconv.Quote(p)
}

func kindOfMode(mode string) string {
	switch mode {
	case "120000":
		return "a symbolic link"
	case "160000":
		return "a submodule"
	case "040000":
		return "a directory"
	}
	return "a file"
}

func allowedList(r *Reserved) string {
	if len(r.Allow) == 0 {
		return "nothing"
	}
	var names []string
	for _, a := range r.Allow {
		names = append(names, r.Dir+"/"+a)
	}
	return strings.Join(names, " and ")
}

// BundleCheck configures CheckBundle.
type BundleCheck struct {
	// BundlePath is the bundle, Manifest what its capture recorded.
	BundlePath string
	Manifest   Manifest
	// Scratch is a directory CheckBundle makes its repository in, and
	// removes it from.
	Scratch string
	// Reserve, when set, holds the snapshot's working tree, its index and
	// HEAD's tree to a directory the target keeps; see Reserved.
	Reserve *Reserved
	// Object, when set, is handed every object the bundle carries, whole —
	// a delta resolved against its base — with its type and id. An error
	// stops the check and is returned.
	Object func(kind, id string, size int64, r io.Reader) error
	// Locate, when set, is asked once Object has seen every object which of
	// them to name; Located is handed the path a ref's history reaches each
	// one at, for a refusal a person can act on.
	Locate  func() []string
	Located func(id, path string)
	// CommandTimeout bounds each git command; zero means the default.
	CommandTimeout time.Duration
}

// CheckBundle reads a bundle a device sent into a scratch repository and
// holds it to its manifest (Task 20495): every ref the manifest names, at its
// object, and no ref it does not; through Object, every object, so a value a
// scan looks for is found even where a delta built it from parts no single
// insert holds; and the snapshot's trees to Reserve. git checks each object as
// it indexes it (fetch.fsckObjects). Nothing outside Scratch is written.
//
// Objects are handed to Object before a path is held to Reserve, and a ref
// the manifest does not name is not named: an error names only what the
// manifest — which the caller has scanned — or a scanned object carries.
func CheckBundle(ctx context.Context, c BundleCheck) error {
	m := c.Manifest
	if !m.Repository {
		return nil
	}
	if err := ValidateManifest(m, ""); err != nil {
		return err
	}
	if err := VerifyFile(c.BundlePath, *m.Bundle); err != nil {
		return err
	}
	repo, err := os.MkdirTemp(c.Scratch, "check-*.git")
	if err != nil {
		return fmt.Errorf("movegit: %w", err)
	}
	defer os.RemoveAll(repo)
	g, err := newBareRunner(ctx, repo)
	if err != nil {
		return err
	}
	if c.CommandTimeout > 0 {
		g.timeout = c.CommandTimeout
	}
	g.env = append(g.env, "GIT_NO_LAZY_FETCH=1")
	format := "sha1"
	if len(m.Snapshot.Commit) == 64 {
		format = "sha256"
	}
	if _, err := g.run(ctx, repo, nil, "init", "--quiet", "--bare", "--object-format="+format, "--", repo); err != nil {
		return fmt.Errorf("movegit: init the check repository: %w", err)
	}
	// The bundle is the one thing read, as a file.
	if _, err := g.run(ctx, repo, nil, "-c", "protocol.allow=never", "-c", "protocol.file.allow=always",
		"-c", "fetch.fsckObjects=true", "fetch", "--quiet", "--no-tags", "--", c.BundlePath, "+refs/*:refs/*"); err != nil {
		return fmt.Errorf("movegit: read the bundle: %w", err)
	}
	out, err := g.run(ctx, repo, nil, "for-each-ref", "--format=%(refname)%00%(objectname)")
	if err != nil {
		return fmt.Errorf("movegit: list the bundle's refs: %w", err)
	}
	have := map[string]string{}
	for _, line := range nonEmptyLines(out) {
		name, obj, _ := strings.Cut(line, "\x00")
		have[name] = obj
	}
	want := map[string]string{m.Snapshot.Ref: m.Snapshot.Commit}
	for _, list := range [][]Ref{m.Branches, m.Tags, m.Stash, m.Carried} {
		for _, r := range list {
			want[r.Name] = r.Object
		}
	}
	for _, w := range m.Worktrees {
		if w.Ref != "" {
			want[w.Ref] = w.Commit
		}
	}
	for name, obj := range want {
		if have[name] != obj {
			return fmt.Errorf("movegit: the bundle holds %s at %s, its manifest %s", name, orNone(have[name]), obj)
		}
	}
	extra := 0
	for name := range have {
		if _, ok := want[name]; !ok {
			extra++
		}
	}
	if extra > 0 {
		return fmt.Errorf("movegit: the bundle holds %d refs its manifest does not name", extra)
	}
	if c.Object != nil {
		err := g.eachObject(ctx, repo, c.Object)
		if c.Locate != nil && c.Located != nil {
			if ids := c.Locate(); len(ids) > 0 {
				g.locate(ctx, repo, ids, c.Located)
			}
		}
		if err != nil {
			return err
		}
	}
	return g.reserved(ctx, repo, c.Reserve, m.Snapshot.WorktreeTree, m.Snapshot.IndexTree, m.Snapshot.BaseTree)
}

// locate hands fn the path at which the history of the repository at dir
// reaches each of ids, as far as it can tell: best effort, for a message.
func (g *runner) locate(ctx context.Context, dir string, ids []string, fn func(id, path string)) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := g.command(cctx, dir, nil, "rev-list", "--objects", "--all")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() && len(want) > 0 {
		id, path, ok := strings.Cut(sc.Text(), " ")
		if ok && want[id] && path != "" {
			delete(want, id)
			fn(id, path)
		}
	}
	cancel()
	_ = cmd.Wait()
}

// eachObject streams every object of the repository at dir to fn.
func (g *runner) eachObject(ctx context.Context, dir string, fn func(kind, id string, size int64, r io.Reader) error) error {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := g.command(cctx, dir, nil, "cat-file", "--batch-all-objects", "--batch", "--unordered")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("movegit: %w", err)
	}
	var stderr cappedBuffer
	stderr.max = 64 << 10
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("movegit: git cat-file: %w", err)
	}
	br := bufio.NewReaderSize(stdout, 64<<10)
	var fnErr error
	for {
		header, err := br.ReadString('\n')
		if err == io.EOF && header == "" {
			break
		}
		if err != nil {
			fnErr = fmt.Errorf("movegit: read an object's header: %w", err)
			break
		}
		f := strings.Fields(strings.TrimSpace(header))
		if len(f) != 3 {
			fnErr = fmt.Errorf("movegit: an object's header %q", strings.TrimSpace(header))
			break
		}
		size, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil || size < 0 {
			fnErr = fmt.Errorf("movegit: an object's size %q", f[2])
			break
		}
		body := io.LimitReader(br, size)
		if err := fn(f[1], f[0], size, body); err != nil {
			fnErr = err
			break
		}
		// Whatever fn left unread, then the newline after the object.
		if _, err := io.Copy(io.Discard, body); err != nil {
			fnErr = fmt.Errorf("movegit: read object %s: %w", f[0], err)
			break
		}
		if _, err := br.ReadByte(); err != nil {
			fnErr = fmt.Errorf("movegit: read object %s: %w", f[0], err)
			break
		}
	}
	if fnErr != nil {
		cancel()
		_ = cmd.Wait()
		return fnErr
	}
	if err := cmd.Wait(); err != nil {
		return &gitError{args: []string{"cat-file"}, stderr: gitprovision.Collapse(stderr.String()), raw: stderr.String(), err: err}
	}
	return nil
}

// Observed is what a working copy holds now, read by Inspect.
type Observed struct {
	Repository bool `json:"repository"`
	Head       Head `json:"head"`
	// Refs maps every ref's full name to its object, and Trees each ref that
	// peels to a commit to the commit's tree.
	Refs  map[string]string `json:"refs"`
	Trees map[string]string `json:"trees"`
	// IndexTree and WorktreeTree are the main worktree's state now, recorded
	// as a capture would record it.
	IndexTree    string `json:"index_tree,omitempty"`
	WorktreeTree string `json:"worktree_tree,omitempty"`
	// IndexNote says why the index could not be recorded.
	IndexNote string `json:"index_note,omitempty"`
}

// InspectOptions configure Inspect.
type InspectOptions struct {
	// Exclude is as CaptureOptions.Exclude.
	Exclude        []string
	CommandTimeout time.Duration
}

// Inspect reads what the repository at dir holds now. A directory with no
// .git is reported as Repository false.
//
// It writes nothing a reader would notice: the index is read from a copy, and
// the only writes are the blob and tree objects recording the working tree
// takes, which nothing names.
func Inspect(ctx context.Context, dir string, opts InspectOptions) (Observed, error) {
	o := Observed{Refs: map[string]string{}, Trees: map[string]string{}}
	dir, err := checkDir(dir)
	if err != nil {
		return o, err
	}
	present, err := hasDotGit(dir)
	if err != nil || !present {
		return o, err
	}
	g, err := newRunner(ctx, dir, opts.CommandTimeout)
	if err != nil {
		return o, err
	}
	g.isolate(nil)
	if err := g.checkTop(ctx, dir); err != nil {
		return o, err
	}
	o.Repository = true
	if o.Head, err = g.head(ctx, dir); err != nil {
		return o, err
	}
	out, err := g.run(ctx, dir, nil, "for-each-ref", "--format=%(refname)%00%(objectname)%00%(*objectname)%00%(objecttype)")
	if err != nil {
		return o, fmt.Errorf("movegit: list refs in %s: %w", dir, err)
	}
	var commits []string
	for _, line := range nonEmptyLines(out) {
		f := strings.Split(line, "\x00")
		if len(f) != 4 {
			continue
		}
		o.Refs[f[0]] = f[1]
		commit := f[1]
		if f[3] == "tag" {
			commit = f[2]
		}
		if commit != "" {
			commits = append(commits, f[0]+"\x00"+commit)
		}
	}
	if err := g.treesOf(ctx, dir, commits, o.Trees); err != nil {
		return o, err
	}
	exclude := opts.Exclude
	if exclude == nil {
		exclude = []string{".cloop"}
	}
	tmp, err := os.MkdirTemp("", "cloop-move-index-*")
	if err != nil {
		return o, fmt.Errorf("movegit: %w", err)
	}
	defer os.RemoveAll(tmp)
	s, err := g.snapshot(ctx, dir, o.Head, exclude, tmp, "inspect")
	if err != nil {
		return o, fmt.Errorf("movegit: read the working tree of %s: %w", dir, err)
	}
	o.IndexTree, o.WorktreeTree, o.IndexNote = s.IndexTree, s.WorktreeTree, s.IndexNote
	return o, nil
}

// ValidObject reports whether s is a full object id, SHA-1 or SHA-256: what a
// caller passing one on to git as a revision checks first.
func ValidObject(s string) bool { return validObject(s) }

// ReadSnapshot reads back the snapshot move moveID's capture recorded as
// commit in the repository at dir (Task 20496): the commit HEAD was on (Base,
// "" while it was unborn) and its tree, and the trees of the index and of the
// files on disk. Only a commit of a snapshot's shape is read as one — the
// working-tree commit's parents Base and the index commit, whose own parent is
// Base, each saying in its message which move wrote it — so a copy holding
// some other commit under the snapshot's ref is never mistaken for the copy
// that was captured.
func ReadSnapshot(ctx context.Context, dir, moveID, commit string) (Snapshot, error) {
	s := Snapshot{Commit: commit, BaseTree: EmptyTree}
	if !ValidMoveID(moveID) {
		return s, fmt.Errorf("movegit: %q is not a move id", moveID)
	}
	if !validObject(commit) {
		return s, fmt.Errorf("movegit: %q is not a commit id", commit)
	}
	dir, err := checkDir(dir)
	if err != nil {
		return s, err
	}
	present, err := hasDotGit(dir)
	if err != nil {
		return s, err
	}
	if !present {
		return s, fmt.Errorf("%w: %s has no .git", ErrNotARepository, dir)
	}
	g, err := newRunner(ctx, dir, 0)
	if err != nil {
		return s, err
	}
	g.isolate(nil)
	if err := g.checkTop(ctx, dir); err != nil {
		return s, err
	}
	parents := func(c string) ([]string, error) {
		out, err := g.run(ctx, dir, nil, "rev-list", "--parents", "--max-count=1", c)
		if err != nil {
			return nil, fmt.Errorf("movegit: read commit %s in %s: %w", c, dir, err)
		}
		f := strings.Fields(out)
		if len(f) == 0 || f[0] != c {
			return nil, fmt.Errorf("movegit: %s in %s is not a commit", c, dir)
		}
		return f[1:], nil
	}
	ps, err := parents(commit)
	if err != nil {
		return s, err
	}
	var index string
	switch len(ps) {
	case 1:
		index = ps[0]
	case 2:
		s.Base, index = ps[0], ps[1]
	default:
		return s, fmt.Errorf("movegit: %s in %s has %d parents, which no snapshot has", commit, dir, len(ps))
	}
	ips, err := parents(index)
	if err != nil {
		return s, err
	}
	if (s.Base == "" && len(ips) != 0) || (s.Base != "" && (len(ips) != 1 || ips[0] != s.Base)) {
		return s, fmt.Errorf("movegit: %s in %s is not a snapshot: its index commit does not stand on its base", commit, dir)
	}
	// The messages snapshotCommit writes.
	for c, says := range map[string]string{commit: "the working tree of ", index: "the index of "} {
		subject, err := g.run(ctx, dir, nil, "log", "--max-count=1", "--format=%s", c)
		if err != nil {
			return s, fmt.Errorf("movegit: read commit %s in %s: %w", c, dir, err)
		}
		if !strings.HasPrefix(strings.TrimSpace(subject), "cloop move "+moveID+": "+says) {
			return s, fmt.Errorf("movegit: %s in %s is not a snapshot move %s wrote", commit, dir, moveID)
		}
	}
	tree := func(c string) (string, error) {
		out, err := g.run(ctx, dir, nil, "rev-parse", "--verify", c+"^{tree}")
		if err != nil {
			return "", fmt.Errorf("movegit: read the tree of %s in %s: %w", c, dir, err)
		}
		return strings.TrimSpace(out), nil
	}
	if s.WorktreeTree, err = tree(commit); err != nil {
		return s, err
	}
	if s.IndexTree, err = tree(index); err != nil {
		return s, err
	}
	if s.Base != "" {
		if s.BaseTree, err = tree(s.Base); err != nil {
			return s, err
		}
	}
	s.Dirty = s.IndexTree != s.BaseTree || s.WorktreeTree != s.BaseTree
	return s, nil
}

// IgnoredPaths lists what the working tree at dir holds that git ignores —
// files and, collapsed, whole directories — outside the excluded paths (nil
// means ".cloop"), at most max of them (Task 20496). A capture never carries
// these: they are what a cleanup that removes the working copy would lose
// without anyone having moved them. more reports that there were more than
// max.
func IgnoredPaths(ctx context.Context, dir string, exclude []string, max int) (paths []string, more bool, err error) {
	dir, err = checkDir(dir)
	if err != nil {
		return nil, false, err
	}
	present, err := hasDotGit(dir)
	if err != nil || !present {
		return nil, false, err
	}
	g, err := newRunner(ctx, dir, 0)
	if err != nil {
		return nil, false, err
	}
	g.isolate(nil)
	if err := g.checkTop(ctx, dir); err != nil {
		return nil, false, err
	}
	if exclude == nil {
		exclude = []string{".cloop"}
	}
	args := []string{"ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory", "--no-empty-directory", "--", "."}
	for _, ex := range exclude {
		ex = strings.Trim(filepath.ToSlash(ex), "/")
		if ex != "" {
			args = append(args, ":(top,exclude,literal)"+ex)
		}
	}
	out, err := g.run(ctx, dir, nil, args...)
	if err != nil {
		return nil, false, fmt.Errorf("movegit: list the ignored files of %s: %w", dir, err)
	}
	for _, p := range strings.Split(out, "\x00") {
		if p == "" {
			continue
		}
		if len(paths) == max {
			return paths, true, nil
		}
		paths = append(paths, p)
	}
	return paths, false, nil
}

// Mismatch is one way a working copy differs from a manifest.
type Mismatch struct {
	What string `json:"what"`
	Want string `json:"want"`
	Got  string `json:"got"`
}

func (m Mismatch) String() string {
	return fmt.Sprintf("%s: want %s, got %s", m.What, orNone(m.Want), orNone(m.Got))
}

func orNone(s string) string {
	if s == "" {
		return "nothing"
	}
	return s
}

// Compare checks a working copy against the manifest of the capture it was
// built from: every branch and tag at its object (and each branch's tree),
// the hidden refs present, HEAD on the same branch, and the index and the
// files on disk as they were recorded.
func Compare(m Manifest, o Observed) []Mismatch {
	var out []Mismatch
	add := func(what, want, got string) {
		if want != got {
			out = append(out, Mismatch{What: what, Want: want, Got: got})
		}
	}
	if !m.Repository {
		return nil
	}
	if !o.Repository {
		return []Mismatch{{What: "repository", Want: "a git repository", Got: ""}}
	}
	for _, b := range m.Branches {
		add("branch "+b.Name, b.Object, o.Refs[b.Name])
		if b.Tree != "" && o.Refs[b.Name] != "" {
			add("tree of branch "+b.Name, b.Tree, o.Trees[b.Name])
		}
	}
	for _, t := range m.Tags {
		add("tag "+t.Name, t.Object, o.Refs[t.Name])
	}
	if s := m.Snapshot; s != nil {
		add("snapshot ref "+s.Ref, s.Commit, o.Refs[s.Ref])
		add("the index", s.IndexTree, o.IndexTree)
		add("the working tree", s.WorktreeTree, o.WorktreeTree)
	}
	for _, w := range m.Worktrees {
		if w.Ref != "" {
			add("snapshot ref "+w.Ref, w.Commit, o.Refs[w.Ref])
		}
	}
	for _, s := range m.Stash {
		add("stash ref "+s.Name, s.Object, o.Refs[s.Name])
	}
	for _, c := range m.Carried {
		add("carried ref "+c.Name, c.Object, o.Refs[c.Name])
	}
	want, got := describeHead(m.Head), describeHead(o.Head)
	add("HEAD", want, got)
	return out
}

func describeHead(h Head) string {
	if h.Detached {
		return "detached at " + h.Commit
	}
	return h.Branch
}

// VerifyFile checks that path is a regular file of d's size and digest.
func VerifyFile(path string, d Digest) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("movegit: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("movegit: %s is not a regular file", path)
	}
	if info.Size() != d.Bytes {
		return fmt.Errorf("movegit: %s is %d bytes, the capture wrote %d", path, info.Size(), d.Bytes)
	}
	got, err := FileDigest(path)
	if err != nil {
		return err
	}
	if got.SHA256 != d.SHA256 {
		return fmt.Errorf("movegit: %s does not match the capture (digest %s, want %s)", path, prefix(got.SHA256), prefix(d.SHA256))
	}
	return nil
}

// FileDigest returns a regular file's size and SHA-256.
func FileDigest(path string) (Digest, error) {
	f, err := os.Open(path)
	if err != nil {
		return Digest{}, fmt.Errorf("movegit: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return Digest{}, fmt.Errorf("movegit: read %s: %w", path, err)
	}
	return Digest{Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func prefix(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// ── carrier ────────────────────────────────────────────────────────────────

// CarrierFile is one file a carrier commit holds.
type CarrierFile struct {
	// Name is its name in the carrier's tree: one path element.
	Name string
	// Path is where it is on this machine.
	Path string
}

// Carrier is a carrier branch written into a bundle.
type Carrier struct {
	Branch string
	Head   string
	Digest Digest
}

// BuildCarrier writes a bundle holding one branch whose single commit's tree
// is files: how a move's bundle, manifest and .cloop files travel to an
// executor through the branch-bundle workspace a feature uses
// (executor.BranchBundle). work is a scratch directory the caller removes.
func BuildCarrier(ctx context.Context, work, branch string, files []CarrierFile, out string, maxBytes int64) (Carrier, error) {
	c := Carrier{Branch: branch}
	if err := executor.ValidateWriteBackBranch(branch); err != nil {
		return c, fmt.Errorf("movegit: %w", err)
	}
	repo := filepath.Join(work, "carrier.git")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		return c, fmt.Errorf("movegit: %w", err)
	}
	g, err := newBareRunner(ctx, repo)
	if err != nil {
		return c, err
	}
	if _, err := g.run(ctx, repo, nil, "init", "--quiet", "--bare", "--", repo); err != nil {
		return c, fmt.Errorf("movegit: init the carrier: %w", err)
	}
	var tree strings.Builder
	sorted := append([]CarrierFile(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, f := range sorted {
		if f.Name == "" || strings.ContainsAny(f.Name, "/\x00\n\t") || f.Name == "." || f.Name == ".." {
			return c, fmt.Errorf("movegit: %q cannot name a file in a carrier", f.Name)
		}
		blob, err := g.run(ctx, repo, nil, "hash-object", "-w", "--no-filters", "--", f.Path)
		if err != nil {
			return c, fmt.Errorf("movegit: store %s in the carrier: %w", f.Name, err)
		}
		fmt.Fprintf(&tree, "100644 blob %s\t%s\n", strings.TrimSpace(blob), f.Name)
	}
	treeSHA, err := g.runInput(ctx, repo, strings.NewReader(tree.String()), "mktree")
	if err != nil {
		return c, fmt.Errorf("movegit: write the carrier's tree: %w", err)
	}
	commit, err := g.runInput(ctx, repo, strings.NewReader("cloop move carrier\n"), "commit-tree", strings.TrimSpace(treeSHA))
	if err != nil {
		return c, fmt.Errorf("movegit: write the carrier's commit: %w", err)
	}
	c.Head = strings.TrimSpace(commit)
	if _, err := g.run(ctx, repo, nil, "update-ref", "refs/heads/"+branch, c.Head); err != nil {
		return c, fmt.Errorf("movegit: name the carrier's branch: %w", err)
	}
	d, err := g.bundle(ctx, repo, out, maxBytes, []string{"refs/heads/" + branch})
	if err != nil {
		return c, err
	}
	c.Digest = d
	return c, nil
}

// ReadCarrierFile copies the file name from the tree of commit in the
// repository at dir to dst, refusing one larger than maxBytes.
func ReadCarrierFile(ctx context.Context, dir, commit, name, dst string, maxBytes int64) error {
	g, err := newRunner(ctx, dir, 0)
	if err != nil {
		return err
	}
	spec := commit + ":" + name
	size, err := g.run(ctx, dir, nil, "cat-file", "-s", spec)
	if err != nil {
		return fmt.Errorf("movegit: the carrier holds no %s: %w", name, err)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(size), 10, 64)
	if err != nil {
		return fmt.Errorf("movegit: size of %s: %w", name, err)
	}
	if maxBytes > 0 && n > maxBytes {
		return fmt.Errorf("%w: %s is %d bytes, at most %d", ErrTooLarge, name, n, maxBytes)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("movegit: %w", err)
	}
	werr := g.runTo(ctx, dir, f, "cat-file", "blob", spec)
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("movegit: read %s from the carrier: %w", name, werr)
	}
	return cerr
}

// DeleteRef removes ref from the repository at dir; one that is absent is not
// an error.
func DeleteRef(ctx context.Context, dir, ref string) error {
	g, err := newRunner(ctx, dir, 0)
	if err != nil {
		return err
	}
	if _, err := g.run(ctx, dir, nil, "rev-parse", "--verify", "--quiet", ref); err != nil {
		return nil
	}
	if _, err := g.run(ctx, dir, nil, "update-ref", "-d", ref); err != nil {
		return fmt.Errorf("movegit: delete %s: %w", ref, err)
	}
	return nil
}

// CurrentBranch returns the full name of the branch HEAD is on in the
// repository at dir, and "" when HEAD is detached.
func CurrentBranch(ctx context.Context, dir string) (string, error) {
	g, err := newRunner(ctx, dir, 0)
	if err != nil {
		return "", err
	}
	h, err := g.head(ctx, dir)
	if err != nil {
		return "", err
	}
	return h.Branch, nil
}

// ── runner ─────────────────────────────────────────────────────────────────

// runner runs hardened git for one repository.
type runner struct {
	env     []string
	timeout time.Duration
	now     func() time.Time
	// isolated: no transport, no lazy fetch — what a capture or a reading
	// of a tree needs, and all a tree a workload wrote may get (Task 20495).
	isolated bool
	// cred, when set, runs every command as that user.
	cred *syscall.Credential
}

// isolate keeps every command from reaching anything but the repository: no
// transport — not even a local path, which a workload's configuration could
// name another project's repository through (url.insteadOf, a partial
// clone's promisor remote, remote.<name>.uploadpack) — and no lazy fetch;
// and runs them as cred, when set.
func (g *runner) isolate(cred *syscall.Credential) {
	g.isolated = true
	g.cred = cred
	g.env = append(g.env, "GIT_NO_LAZY_FETCH=1")
}

// handTo gives dir to cred's user, so git running as that user can write
// its scratch files there. Nil hands nothing over.
func handTo(dir string, cred *syscall.Credential) error {
	if cred == nil {
		return nil
	}
	if err := os.Chown(dir, int(cred.Uid), int(cred.Gid)); err != nil {
		return fmt.Errorf("movegit: hand %s to uid %d: %w", dir, cred.Uid, err)
	}
	return nil
}

// hubOwnership lets git work in a tree another account owns: a container
// sandbox's, or a device's for a workload that runs as another user.
var hubOwnership = [2]string{"safe.directory", "*"}

func newRunner(ctx context.Context, dir string, timeout time.Duration) (*runner, error) {
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	fctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	drivers, err := gitprovision.FilterDrivers(fctx, dir, nil, hubOwnership)
	if err != nil {
		return nil, fmt.Errorf("movegit: %w", err)
	}
	pairs := append(executor.HardenedGitConfig(drivers), hubOwnership,
		// The bytes as they are: a line-ending conversion would make the
		// working tree that comes back differ from the one captured.
		[2]string{"core.autocrlf", "false"},
		[2]string{"core.safecrlf", "false"},
		[2]string{"advice.detachedHead", "false"},
		[2]string{"advice.addEmbeddedRepo", "false"},
	)
	env := append(executor.GitEnv(pairs...),
		"GIT_OPTIONAL_LOCKS=0",
		"LC_ALL=C",
		"GIT_AUTHOR_NAME="+identityName, "GIT_AUTHOR_EMAIL="+identityEmail,
		"GIT_COMMITTER_NAME="+identityName, "GIT_COMMITTER_EMAIL="+identityEmail,
	)
	if parent := filepath.Dir(dir); !strings.Contains(parent, ":") {
		env = append(env, "GIT_CEILING_DIRECTORIES="+parent)
	}
	return &runner{env: env, timeout: timeout}, nil
}

// newBareRunner is newRunner for a scratch bare repository of the hub's own,
// which configures no filter to neutralise.
func newBareRunner(_ context.Context, dir string) (*runner, error) {
	env := append(executor.GitEnv(append(executor.HardenedGitConfig(nil), hubOwnership)...),
		"LC_ALL=C",
		"GIT_AUTHOR_NAME="+identityName, "GIT_AUTHOR_EMAIL="+identityEmail,
		"GIT_COMMITTER_NAME="+identityName, "GIT_COMMITTER_EMAIL="+identityEmail,
		// A fixed date: the carrier of the same files is the same commit.
		"GIT_AUTHOR_DATE=2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2000-01-01T00:00:00Z",
	)
	if parent := filepath.Dir(dir); !strings.Contains(parent, ":") {
		env = append(env, "GIT_CEILING_DIRECTORIES="+parent)
	}
	return &runner{env: env, timeout: DefaultCommandTimeout}, nil
}

// gitError is a failed git invocation with git's own words.
type gitError struct {
	args   []string
	stderr string
	// raw is stderr as git wrote it, lines and all.
	raw string
	err error
}

func (e *gitError) Error() string {
	name := "git"
	if len(e.args) > 0 {
		name += " " + e.args[0]
	}
	if e.stderr != "" {
		return name + ": " + e.stderr
	}
	return fmt.Sprintf("%s: %v", name, e.err)
}

func (e *gitError) Unwrap() error { return e.err }

// run executes git in dir with extra environment and returns its output.
func (g *runner) run(ctx context.Context, dir string, extraEnv []string, args ...string) (string, error) {
	var out cappedBuffer
	out.max = maxOutput
	if err := g.exec(ctx, dir, extraEnv, nil, &out, args...); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

// runInput is run with stdin.
func (g *runner) runInput(ctx context.Context, dir string, in io.Reader, args ...string) (string, error) {
	var out cappedBuffer
	out.max = maxOutput
	if err := g.exec(ctx, dir, nil, in, &out, args...); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

// runTo is run writing the output to w.
func (g *runner) runTo(ctx context.Context, dir string, w io.Writer, args ...string) error {
	return g.exec(ctx, dir, nil, nil, w, args...)
}

func (g *runner) exec(ctx context.Context, dir string, extraEnv []string, in io.Reader, out io.Writer, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	cmd := g.command(ctx, dir, extraEnv, args...)
	var stderr cappedBuffer
	stderr.max = 64 << 10
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("git %s: %w", args[0], ctxErr)
		}
		return &gitError{args: args, stderr: gitprovision.Collapse(stderr.String()), raw: stderr.String(), err: err}
	}
	return nil
}

// command builds one git command in dir, as the runner runs it.
func (g *runner) command(ctx context.Context, dir string, extraEnv []string, args ...string) *exec.Cmd {
	full := append([]string{"-C", dir}, args...)
	if g.isolated {
		full = append([]string{"-c", "protocol.allow=never"}, full...)
	}
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = append(append([]string(nil), g.env...), extraEnv...)
	if g.now != nil {
		at := g.now().UTC().Format(time.RFC3339)
		cmd.Env = append(cmd.Env, "GIT_AUTHOR_DATE="+at, "GIT_COMMITTER_DATE="+at)
	}
	cmd.Dir = dir
	gitprovision.BoundChild(cmd)
	if g.cred != nil {
		cmd.SysProcAttr.Credential = g.cred
	}
	return cmd
}

// pipe runs `git from... | git to...`: from's output is to's input, in one
// step that fails when either does.
func pipe(ctx context.Context, from *runner, fromDir string, fromIn io.Reader, fromArgs []string,
	to *runner, toDir string, toArgs []string) error {
	ctx, cancel := context.WithTimeout(ctx, max(from.timeout, to.timeout))
	defer cancel()
	src := from.command(ctx, fromDir, nil, fromArgs...)
	dst := to.command(ctx, toDir, nil, toArgs...)
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("movegit: %w", err)
	}
	var srcErr, dstErr cappedBuffer
	srcErr.max, dstErr.max = 64<<10, 64<<10
	src.Stdin, src.Stdout, src.Stderr = fromIn, w, &srcErr
	dst.Stdin, dst.Stdout, dst.Stderr = r, io.Discard, &dstErr
	if err := dst.Start(); err != nil {
		r.Close()
		w.Close()
		return fmt.Errorf("movegit: git %s: %w", toArgs[0], err)
	}
	r.Close()
	runErr := src.Run()
	w.Close()
	waitErr := dst.Wait()
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("git %s | git %s: %w", fromArgs[0], toArgs[0], ctx.Err())
	case runErr != nil:
		return &gitError{args: fromArgs, stderr: gitprovision.Collapse(srcErr.String()), raw: srcErr.String(), err: runErr}
	case waitErr != nil:
		return &gitError{args: toArgs, stderr: gitprovision.Collapse(dstErr.String()), raw: dstErr.String(), err: waitErr}
	}
	return nil
}

// cappedBuffer keeps the first max bytes written to it.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
	cut bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
			b.cut = true
		} else {
			b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.cut = true
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string { return b.buf.String() }

// ── reading ────────────────────────────────────────────────────────────────

func checkDir(dir string) (string, error) {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("movegit: %q is not an absolute path", dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("movegit: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("movegit: %s is not a directory", dir)
	}
	return dir, nil
}

// hasDotGit reports whether dir has a .git of its own. A symbolic link is
// refused rather than followed: it would point git at a repository elsewhere.
func hasDotGit(dir string) (bool, error) {
	info, err := os.Lstat(filepath.Join(dir, ".git"))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("movegit: %w", err)
	case info.Mode()&os.ModeSymlink != 0:
		return false, fmt.Errorf("%w: %s/.git is a symbolic link, which is not followed", ErrNotARepository, dir)
	}
	return true, nil
}

// checkTop refuses a directory that is inside a repository rather than the top
// of one.
func (g *runner) checkTop(ctx context.Context, dir string) error {
	top, err := g.run(ctx, dir, nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrNotARepository, dir, err)
	}
	if !sameDir(strings.TrimSpace(top), dir) {
		return fmt.Errorf("%w: %s is inside the repository at %s rather than the top of one", ErrNotARepository, dir, strings.TrimSpace(top))
	}
	return nil
}

// head reads where HEAD is in the worktree at dir.
func (g *runner) head(ctx context.Context, dir string) (Head, error) {
	var h Head
	if ref, err := g.run(ctx, dir, nil, "symbolic-ref", "--quiet", "HEAD"); err == nil {
		h.Branch = strings.TrimSpace(ref)
	} else {
		h.Detached = true
	}
	commit, err := g.run(ctx, dir, nil, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
	if err != nil {
		if h.Detached {
			return h, fmt.Errorf("movegit: HEAD in %s is detached at nothing: %w", dir, err)
		}
		h.Unborn = true
		return h, nil
	}
	h.Commit = strings.TrimSpace(commit)
	return h, nil
}

// refs lists the refs under prefix; for branches, whether a remote-tracking
// branch contains each.
func (g *runner) refs(ctx context.Context, dir, prefix string, branches bool) ([]Ref, error) {
	out, err := g.run(ctx, dir, nil, "for-each-ref",
		"--format=%(refname)%00%(objectname)%00%(objecttype)%00%(*objectname)", prefix)
	if err != nil {
		return nil, fmt.Errorf("movegit: list %s in %s: %w", prefix, dir, err)
	}
	refs := []Ref{}
	var commits []string
	for _, line := range nonEmptyLines(out) {
		f := strings.Split(line, "\x00")
		if len(f) != 4 {
			continue
		}
		if len(refs) >= MaxRefs {
			return nil, fmt.Errorf("movegit: %s holds more than %d refs under %s", dir, MaxRefs, prefix)
		}
		r := Ref{Name: f[0], Object: f[1]}
		switch f[2] {
		case "commit":
			r.Commit = f[1]
		case "tag":
			r.Commit = f[3]
		}
		if r.Commit != "" {
			commits = append(commits, r.Name+"\x00"+r.Commit)
		}
		refs = append(refs, r)
	}
	trees := map[string]string{}
	if err := g.treesOf(ctx, dir, commits, trees); err != nil {
		return nil, err
	}
	for i := range refs {
		refs[i].Tree = trees[refs[i].Name]
		if branches && refs[i].Commit != "" {
			n, err := g.count(ctx, dir, refs[i].Name)
			if err != nil {
				return nil, err
			}
			refs[i].Pushed = n == 0
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	return refs, nil
}

// treesOf resolves each "name\x00commit" to the commit's tree, into trees, in
// one cat-file batch.
func (g *runner) treesOf(ctx context.Context, dir string, pairs []string, trees map[string]string) error {
	if len(pairs) == 0 {
		return nil
	}
	var in strings.Builder
	for _, p := range pairs {
		_, commit, _ := strings.Cut(p, "\x00")
		in.WriteString(commit + "^{tree}\n")
	}
	out, err := g.runInput(ctx, dir, strings.NewReader(in.String()), "cat-file", "--batch-check=%(objectname)")
	if err != nil {
		return fmt.Errorf("movegit: read the trees of %s: %w", dir, err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, p := range pairs {
		name, _, _ := strings.Cut(p, "\x00")
		if i < len(lines) && len(strings.TrimSpace(lines[i])) == 40 {
			trees[name] = strings.TrimSpace(lines[i])
		}
	}
	return nil
}

// count returns how many commits rev reaches that no remote-tracking branch
// does.
func (g *runner) count(ctx context.Context, dir, rev string) (int, error) {
	out, err := g.run(ctx, dir, nil, "rev-list", "--count", rev, "--not", "--remotes", "--")
	if err != nil {
		return 0, fmt.Errorf("movegit: count %s's unpushed commits: %w", rev, err)
	}
	return strconv.Atoi(strings.TrimSpace(out))
}

// remotes lists the configured remotes with their first URL, credentials
// removed.
func (g *runner) remotes(ctx context.Context, dir string) ([]Remote, error) {
	out, err := g.run(ctx, dir, nil, "remote")
	if err != nil {
		return nil, fmt.Errorf("movegit: list remotes in %s: %w", dir, err)
	}
	var rs []Remote
	for _, name := range nonEmptyLines(out) {
		if !validRemoteName(name) {
			continue
		}
		u, err := g.run(ctx, dir, nil, "config", "--get", "remote."+name+".url")
		if err != nil {
			continue
		}
		rs = append(rs, Remote{Name: name, URL: StripCredentials(strings.TrimSpace(u))})
	}
	return rs, nil
}

// StripCredentials removes user information from a URL — a token is the
// common case — and returns any other form (scp-like, a path) unchanged.
func StripCredentials(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	if u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

func validRemoteName(name string) bool {
	if name == "" || len(name) > 128 || strings.HasPrefix(name, "-") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// snapshot records the index and the files of the worktree at dir, whose HEAD
// is h, using scratch index files under tmp named by tag.
func (g *runner) snapshot(ctx context.Context, dir string, h Head, exclude []string, tmp, tag string) (Snapshot, error) {
	s := Snapshot{Base: h.Commit, BaseTree: EmptyTree}
	if h.Commit != "" {
		t, err := g.run(ctx, dir, nil, "rev-parse", "--verify", h.Commit+"^{tree}")
		if err != nil {
			return s, err
		}
		s.BaseTree = strings.TrimSpace(t)
	}
	// --git-path answers relative to dir unless the path is absolute; the
	// --path-format=absolute that would say so is newer than the git some
	// sandboxes carry.
	indexPath, err := g.run(ctx, dir, nil, "rev-parse", "--git-path", "index")
	if err != nil {
		return s, err
	}
	indexPath = strings.TrimSpace(indexPath)
	if !filepath.IsAbs(indexPath) {
		indexPath = filepath.Join(dir, indexPath)
	}

	// The index as it is, from a copy: write-tree would otherwise save a
	// cache-tree into the real one.
	idxI := filepath.Join(tmp, "index-"+tag)
	if err := g.copyIfPresent(indexPath, idxI); err != nil {
		return s, err
	}
	tree, err := g.run(ctx, dir, []string{"GIT_INDEX_FILE=" + idxI}, "write-tree")
	switch {
	case err == nil:
		s.IndexTree = strings.TrimSpace(tree)
	case unmerged(err):
		// Unresolved conflicts: no tree holds them. The files are still
		// recorded below, as they are on disk.
		s.IndexTree = s.BaseTree
		s.IndexNote = "the index held unresolved conflicts, which no tree can record; the conflicted files are recorded as they are on disk, and the index as HEAD's"
	default:
		// Anything else is a failure, never recorded as the index's state.
		return s, fmt.Errorf("movegit: record the index: %w", err)
	}

	// The files, in a second copy: `add -A` stages every change and every
	// untracked file .gitignore does not exclude.
	idxW := filepath.Join(tmp, "worktree-"+tag)
	if err := g.copyIfPresent(indexPath, idxW); err != nil {
		return s, err
	}
	args := []string{"add", "-A", "--", "."}
	for _, ex := range exclude {
		ex = strings.Trim(filepath.ToSlash(ex), "/")
		if ex != "" {
			args = append(args, ":(top,exclude,literal)"+ex)
		}
	}
	if _, err := g.run(ctx, dir, []string{"GIT_INDEX_FILE=" + idxW}, args...); err != nil && !onlyExcludedIgnored(err, exclude) {
		return s, err
	}
	tree, err = g.run(ctx, dir, []string{"GIT_INDEX_FILE=" + idxW}, "write-tree")
	if err != nil {
		return s, err
	}
	s.WorktreeTree = strings.TrimSpace(tree)
	s.Dirty = s.IndexTree != s.BaseTree || s.WorktreeTree != s.BaseTree
	return s, nil
}

// ignoredHeader starts git's refusal of a pathspec that names an ignored path.
const ignoredHeader = "The following paths are ignored by one of your .gitignore files:"

// onlyExcludedIgnored reports whether err is `git add` refusing nothing but the
// excluded paths for being ignored. git names an ignored directory a pathspec
// excludes — a provisioned tree ignores .cloop in info/exclude — and exits 1,
// having staged everything else; that refusal is not a failure here, and any
// other is.
func onlyExcludedIgnored(err error, exclude []string) bool {
	var ge *gitError
	if !errors.As(err, &ge) || !strings.Contains(ge.raw, ignoredHeader) {
		return false
	}
	excluded := map[string]bool{}
	for _, ex := range exclude {
		excluded[strings.Trim(filepath.ToSlash(ex), "/")] = true
	}
	_, rest, _ := strings.Cut(ge.raw, ignoredHeader)
	listed := 0
	for _, line := range strings.Split(rest, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "hint:"):
			continue
		case excluded[strings.Trim(line, "/")]:
			listed++
		default:
			return false
		}
	}
	return listed > 0
}

// snapshotCommit writes the stash-like pair of commits for s and returns the
// working-tree commit.
func (g *runner) snapshotCommit(ctx context.Context, dir, moveID, who string, s Snapshot) (string, error) {
	parents := []string{}
	if s.Base != "" {
		parents = append(parents, "-p", s.Base)
	}
	args := append([]string{"commit-tree", s.IndexTree}, parents...)
	idx, err := g.runInput(ctx, dir, strings.NewReader(fmt.Sprintf("cloop move %s: the index of %s\n", moveID, who)), args...)
	if err != nil {
		return "", fmt.Errorf("movegit: record the index of %s: %w", who, err)
	}
	args = append(append([]string{"commit-tree", s.WorktreeTree}, parents...), "-p", strings.TrimSpace(idx))
	w, err := g.runInput(ctx, dir, strings.NewReader(fmt.Sprintf("cloop move %s: the working tree of %s\n", moveID, who)), args...)
	if err != nil {
		return "", fmt.Errorf("movegit: record the working tree of %s: %w", who, err)
	}
	return strings.TrimSpace(w), nil
}

// linked is one linked worktree inside the project.
type linked struct {
	path, rel string
	head      Head
}

// linkedWorktrees lists the repository's linked worktrees that lie inside dir
// and still exist.
func (g *runner) linkedWorktrees(ctx context.Context, dir string) ([]linked, error) {
	out, err := g.run(ctx, dir, nil, "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return nil, fmt.Errorf("movegit: list worktrees in %s: %w", dir, err)
	}
	roots := []string{dir}
	if real, err := filepath.EvalSymlinks(dir); err == nil && real != dir {
		roots = append(roots, real)
	}
	var (
		list []linked
		cur  *linked
		path string
	)
	flush := func() {
		if cur == nil {
			return
		}
		defer func() { cur = nil }()
		for _, root := range roots {
			if sameDir(root, path) {
				return // the main worktree
			}
		}
		for _, root := range roots {
			rel, err := filepath.Rel(root, path)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			if info, err := os.Lstat(path); err != nil || !info.IsDir() {
				return
			}
			cur.path, cur.rel = path, filepath.ToSlash(rel)
			list = append(list, *cur)
			return
		}
	}
	for _, field := range strings.Split(out, "\x00") {
		if field == "" {
			flush()
			continue
		}
		key, value, _ := strings.Cut(field, " ")
		switch key {
		case "worktree":
			flush()
			path = filepath.Clean(value)
			cur = &linked{}
		case "HEAD":
			if cur != nil {
				cur.head.Commit = value
			}
		case "branch":
			if cur != nil {
				cur.head.Branch = value
			}
		case "detached":
			if cur != nil {
				cur.head.Detached = true
			}
		}
	}
	flush()
	for i := range list {
		if list[i].head.Commit == "" || strings.Trim(list[i].head.Commit, "0") == "" {
			list[i].head.Commit = ""
			list[i].head.Unborn = !list[i].head.Detached
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].rel < list[j].rel })
	if len(list) > MaxWorktrees {
		return nil, fmt.Errorf("movegit: %s has more than %d worktrees inside it", dir, MaxWorktrees)
	}
	return list, nil
}

// stash puts each stash entry on a ref of its own: a bundle carries refs, and
// the stash's older entries live only in its reflog.
func (g *runner) stash(ctx context.Context, dir, moveID string) ([]Ref, error) {
	if _, err := g.run(ctx, dir, nil, "rev-parse", "--verify", "--quiet", "refs/stash"); err != nil {
		return nil, nil
	}
	out, err := g.run(ctx, dir, nil, "log", "--walk-reflogs", "--format=%H", "refs/stash", "--")
	if err != nil {
		top, terr := g.run(ctx, dir, nil, "rev-parse", "--verify", "refs/stash")
		if terr != nil {
			return nil, fmt.Errorf("movegit: read the stash: %w", err)
		}
		out = top
	}
	var refs []Ref
	for i, sha := range nonEmptyLines(out) {
		if i >= MaxStash {
			break
		}
		name := fmt.Sprintf("%s%s/%d", StashRefPrefix, moveID, i)
		if _, err := g.run(ctx, dir, nil, "update-ref", "-m", "cloop move "+moveID, name, sha); err != nil {
			return nil, fmt.Errorf("movegit: write %s: %w", name, err)
		}
		refs = append(refs, Ref{Name: name, Object: sha, Commit: sha})
	}
	return refs, nil
}

// captureExternal records external tree i — a repository outside the project's
// directory — and carries it into the project's repository at dir, under
// ExternalRefPrefix<id>/<i>/: its working-tree state as a snapshot commit in
// its own object store (always written, since a detached HEAD's commits
// travel only through it), each linked worktree's the same way when it holds
// changes, its branches, tags and stash entries. It returns the worktrees the
// manifest records and the refs carried; nil and a note for a directory that
// holds no repository.
//
// Nothing is fetched. A fetch would read the project's own configuration —
// which the workload wrote, and which can rewrite where a path leads or run a
// program to reach it — and would run upload-pack where the repository's
// owner is not the agent's, which git refuses. The objects are packed in the
// external repository, as its owner, and indexed into the project's, as its
// owner, and the refs written there.
func (g *runner) captureExternal(ctx context.Context, dir string, opts CaptureOptions, exclude []string, tmp string,
	i int, ext ExternalTree) ([]Worktree, []Ref, string, error) {
	rel := strings.Trim(filepath.ToSlash(strings.TrimSpace(ext.Rel)), "/")
	if rel == "" {
		rel = filepath.Base(ext.Dir)
	}
	if info, err := os.Lstat(ext.Dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil, rel + ": there is no working copy of it here, so nothing of it was captured", nil
	} else if err != nil {
		return nil, nil, "", fmt.Errorf("movegit: %s: %w", rel, err)
	} else if !info.IsDir() {
		return nil, nil, "", fmt.Errorf("movegit: %s: %s is not a directory (a link is not followed)", rel, ext.Dir)
	}
	edir, err := checkDir(ext.Dir)
	if err != nil {
		return nil, nil, "", err
	}
	present, err := hasDotGit(edir)
	if err != nil {
		return nil, nil, "", err
	}
	if !present {
		return nil, nil, rel + ": its working copy holds no repository, so nothing of it was captured", nil
	}
	eg, err := newRunner(ctx, edir, opts.CommandTimeout)
	if err != nil {
		return nil, nil, "", err
	}
	eg.now = g.now
	eg.isolate(ext.Credential)
	if err := eg.checkTop(ctx, edir); err != nil {
		return nil, nil, "", err
	}
	etmp, err := os.MkdirTemp(tmp, "external-*")
	if err != nil {
		return nil, nil, "", fmt.Errorf("movegit: %w", err)
	}
	if err := handTo(etmp, ext.Credential); err != nil {
		return nil, nil, "", err
	}
	base := fmt.Sprintf("%s%s/%d/", ExternalRefPrefix, opts.MoveID, i)
	// carry maps the hidden ref each object lands on in the project's
	// repository to the object.
	type carried struct{ name, object string }
	var carry []carried
	local := func(name string) string { return SnapshotRefPrefix + opts.MoveID + "/" + name }
	snapshotOf := func(wdir, wrel, tag string, h Head) (Snapshot, string, error) {
		snap, err := eg.snapshot(ctx, wdir, h, exclude, etmp, tag)
		if err != nil {
			return snap, "", fmt.Errorf("movegit: record the working tree of %s: %w", wrel, err)
		}
		commit, err := eg.snapshotCommit(ctx, wdir, opts.MoveID, wrel, snap)
		if err != nil {
			return snap, "", err
		}
		// Kept on a ref of its own in the external repository while it is
		// packed: an object nothing names is one gc may drop.
		if _, err := eg.run(ctx, edir, nil, "update-ref", "-m", "cloop move "+opts.MoveID, local(tag), commit); err != nil {
			return snap, "", fmt.Errorf("movegit: write a snapshot ref in %s: %w", wrel, err)
		}
		return snap, commit, nil
	}

	head, err := eg.head(ctx, edir)
	if err != nil {
		return nil, nil, "", err
	}
	snap, commit, err := snapshotOf(edir, rel, "snapshot", head)
	if err != nil {
		return nil, nil, "", err
	}
	w := Worktree{Rel: rel, Head: head, Snapshot: snap}
	w.Ref, w.Commit = base+"snapshot", commit
	trees := []Worktree{w}
	carry = append(carry, carried{base + "snapshot", commit})

	wts, err := eg.linkedWorktrees(ctx, edir)
	if err != nil {
		return nil, nil, "", err
	}
	for j, wt := range wts {
		if opts.Confine != nil {
			if err := opts.Confine(wt.path); err != nil {
				return nil, nil, "", fmt.Errorf("movegit: %s's worktree %s: %w", rel, wt.rel, err)
			}
		}
		ws, wc, err := snapshotOf(wt.path, rel+"/"+wt.rel, "worktree-"+strconv.Itoa(j), wt.head)
		if err != nil {
			return nil, nil, "", err
		}
		lw := Worktree{Rel: rel + "/" + wt.rel, Head: wt.head, Snapshot: ws}
		lw.Ref, lw.Commit = fmt.Sprintf("%sworktree/%d", base, j), wc
		trees = append(trees, lw)
		carry = append(carry, carried{lw.Ref, wc})
	}
	// pushed records, by carried name, the branches a remote-tracking branch
	// of the external repository contains: what a target built from the
	// forge would still see.
	pushed := map[string]bool{}
	for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
		refs, err := eg.refs(ctx, edir, prefix, prefix == "refs/heads/")
		if err != nil {
			return nil, nil, "", err
		}
		for _, r := range refs {
			name := base + strings.TrimPrefix(r.Name, "refs/")
			carry = append(carry, carried{name, r.Object})
			pushed[name] = r.Pushed
		}
	}
	stash, err := eg.stash(ctx, edir, opts.MoveID)
	if err != nil {
		return nil, nil, "", err
	}
	for n, st := range stash {
		carry = append(carry, carried{fmt.Sprintf("%sstash/%d", base, n), st.Object})
	}

	// Every object the carried refs reach, packed in the external repository
	// and indexed into the project's.
	var tips strings.Builder
	seen := map[string]bool{}
	for _, c := range carry {
		if !seen[c.object] {
			seen[c.object] = true
			tips.WriteString(c.object + "\n")
		}
	}
	if err := pipe(ctx, eg, edir, strings.NewReader(tips.String()), []string{"pack-objects", "--revs", "--stdout", "--quiet"},
		g, dir, []string{"index-pack", "--stdin"}); err != nil {
		return nil, nil, "", fmt.Errorf("movegit: carry %s into the project's repository: %w", rel, err)
	}
	for _, c := range carry {
		if _, err := g.run(ctx, dir, nil, "update-ref", "-m", "cloop move "+opts.MoveID, c.name, c.object); err != nil {
			return nil, nil, "", fmt.Errorf("movegit: write %s: %w", c.name, err)
		}
	}
	refs, err := g.refs(ctx, dir, base, false)
	if err != nil {
		return nil, nil, "", err
	}
	// The snapshots are recorded as worktrees, not as carried refs.
	var out []Ref
	for _, r := range refs {
		isTree := false
		for _, t := range trees {
			isTree = isTree || t.Ref == r.Name
		}
		if !isTree {
			r.Pushed = pushed[r.Name]
			out = append(out, r)
		}
	}
	return trees, out, "", nil
}

// bundle writes a bundle of refs to path, bounded by maxBytes, and returns its
// digest. It writes beside path first, so a bundle that is cut short or too
// large never stands at path.
func (g *runner) bundle(ctx context.Context, dir, path string, maxBytes int64, refs []string) (Digest, error) {
	part := path + ".part"
	_ = os.Remove(part)
	args := append([]string{"bundle", "create", part}, refs...)
	if _, err := g.run(ctx, dir, nil, args...); err != nil {
		_ = os.Remove(part)
		return Digest{}, fmt.Errorf("movegit: write the bundle: %w", err)
	}
	info, err := os.Stat(part)
	if err != nil {
		return Digest{}, fmt.Errorf("movegit: %w", err)
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		_ = os.Remove(part)
		return Digest{}, fmt.Errorf("%w: %d bytes, at most %d", ErrTooLarge, info.Size(), maxBytes)
	}
	if err := os.Chmod(part, 0o600); err != nil {
		_ = os.Remove(part)
		return Digest{}, fmt.Errorf("movegit: %w", err)
	}
	if err := syncFile(part); err != nil {
		_ = os.Remove(part)
		return Digest{}, err
	}
	d, err := FileDigest(part)
	if err != nil {
		_ = os.Remove(part)
		return Digest{}, err
	}
	if err := os.Rename(part, path); err != nil {
		_ = os.Remove(part)
		return Digest{}, fmt.Errorf("movegit: %w", err)
	}
	return d, nil
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("movegit: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("movegit: sync %s: %w", path, err)
	}
	return f.Close()
}

// copyIfPresent copies src to dst, for git to work on as g's user; a missing
// src leaves no dst (git then reads an empty index).
func (g *runner) copyIfPresent(src, dst string) error {
	in, err := os.Open(src)
	if errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(dst)
		return nil
	}
	if err != nil {
		return fmt.Errorf("movegit: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("movegit: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("movegit: copy the index: %w", err)
	}
	if g.cred != nil {
		if err := out.Chown(int(g.cred.Uid), int(g.cred.Gid)); err != nil {
			out.Close()
			return fmt.Errorf("movegit: hand the index copy to uid %d: %w", g.cred.Uid, err)
		}
	}
	return out.Close()
}

// unmerged reports whether git failed on an index holding unresolved
// conflicts.
func unmerged(err error) bool {
	var ge *gitError
	return errors.As(err, &ge) && strings.Contains(ge.raw, "unmerged")
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// sameDir reports whether a and b name the same directory.
func sameDir(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}
