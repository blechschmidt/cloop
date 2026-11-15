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

	tmp, err := os.MkdirTemp("", "cloop-move-index-*")
	if err != nil {
		return m, fmt.Errorf("movegit: %w", err)
	}
	defer os.RemoveAll(tmp)

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

	wts, err := g.linkedWorktrees(ctx, dir)
	if err != nil {
		return m, err
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

	refs := []string{"--branches", "--tags", m.Snapshot.Ref}
	for _, w := range m.Worktrees {
		if w.Ref != "" {
			refs = append(refs, w.Ref)
		}
	}
	for _, s := range m.Stash {
		refs = append(refs, s.Name)
	}
	digest, err := g.bundle(ctx, dir, opts.BundlePath, opts.MaxBundleBytes, refs)
	if err != nil {
		return m, err
	}
	m.Bundle = &digest
	return m, nil
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
}

// upstreamConfigKey is gitprovision's record of which repository a checkout
// is of; see gitprovision.Provision.
const upstreamConfigKey = "cloop.upstream"

// Restore builds the working copy the manifest describes in opts.Dir.
func Restore(ctx context.Context, opts RestoreOptions) error {
	m := opts.Manifest
	if !m.Repository {
		return nil
	}
	if m.Version != ManifestVersion {
		return fmt.Errorf("movegit: manifest version %d, this build reads %d", m.Version, ManifestVersion)
	}
	if m.Bundle == nil || m.Snapshot == nil {
		return errors.New("movegit: the manifest names no bundle or no snapshot")
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
	full := append([]string{"-C", dir}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = append(append([]string(nil), g.env...), extraEnv...)
	if g.now != nil {
		at := g.now().UTC().Format(time.RFC3339)
		cmd.Env = append(cmd.Env, "GIT_AUTHOR_DATE="+at, "GIT_COMMITTER_DATE="+at)
	}
	cmd.Dir = dir
	gitprovision.BoundChild(cmd)
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
	if err := copyIfPresent(indexPath, idxI); err != nil {
		return s, err
	}
	tree, err := g.run(ctx, dir, []string{"GIT_INDEX_FILE=" + idxI}, "write-tree")
	if err != nil {
		// Unresolved conflicts: no tree holds them. The files are still
		// recorded below, as they are on disk.
		s.IndexTree = s.BaseTree
		s.IndexNote = "the index held unresolved conflicts, which no tree can record; the conflicted files are recorded as they are on disk, and the index as HEAD's"
	} else {
		s.IndexTree = strings.TrimSpace(tree)
	}

	// The files, in a second copy: `add -A` stages every change and every
	// untracked file .gitignore does not exclude.
	idxW := filepath.Join(tmp, "worktree-"+tag)
	if err := copyIfPresent(indexPath, idxW); err != nil {
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

// copyIfPresent copies src to dst; a missing src leaves no dst (git then reads
// an empty index).
func copyIfPresent(src, dst string) error {
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
	return out.Close()
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
