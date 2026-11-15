// Package gitstate reports what a git repository on the hub holds that none of
// its remotes do: changes in its working trees, and commits that no
// remote-tracking branch contains (Task 20493).
//
// It answers a project move's first question about the source — what would be
// left behind if the project's work stopped happening here — for the one source
// the hub can read itself: a project whose tree is on the hub's filesystem
// (the host driver, or a container that bind-mounts the project). It is a read,
// and only a read:
//
//   - every git command runs with --no-optional-locks, so `git status` neither
//     refreshes the index on disk nor takes index.lock — a run working in the
//     same tree is never made to fail on a lock the preflight held;
//   - nothing is fetched: "on a remote" means on a remote-tracking branch as
//     the hub last fetched or pushed it, and the report says so;
//   - the environment is closed and hardened exactly like pkg/executor/featurehub's
//     (executor.GitEnv + executor.HardenedGitConfig): no system or global
//     configuration, no hook, filter, fsmonitor or signing program configured in
//     the repository runs. That matters because the repository is not always
//     only the hub's to write — a project bound to a container executor has its
//     directory, .git included, mounted into its sandbox.
//
// It lives under pkg/executor because it runs git on the hub, and
// tests/security treats this tree as the one place a process may be started
// from: the same reasoning featurehub gives for running the hub's own git.
package gitstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// Defaults for Options' zero values.
const (
	// DefaultMaxPaths is how many paths each list keeps; the counts beside
	// them are always complete unless the output itself was cut.
	DefaultMaxPaths = 20
	// DefaultMaxBranches bounds how many local branches are counted.
	DefaultMaxBranches = 500
	// DefaultMaxWorktrees bounds how many worktrees are inspected.
	DefaultMaxWorktrees = 64
	// DefaultMaxOutput bounds what one git command may print before its
	// output is cut (and the counts made from it become lower bounds).
	DefaultMaxOutput = 8 << 20
	// DefaultCommandTimeout bounds one git command when the caller's context
	// carries no deadline of its own.
	DefaultCommandTimeout = 30 * time.Second
)

// Options adjusts an inspection. The zero value is usable.
type Options struct {
	// Exclude lists paths, relative to each worktree's root, that status
	// leaves out. A project's .cloop directory is the usual one: its contents
	// are the hub's own bookkeeping and a move accounts for them separately.
	Exclude []string
	// MaxPaths, MaxBranches, MaxWorktrees and MaxOutput override the defaults
	// above when positive.
	MaxPaths     int
	MaxBranches  int
	MaxWorktrees int
	MaxOutput    int
	// CommandTimeout overrides DefaultCommandTimeout when positive.
	CommandTimeout time.Duration
}

func (o Options) maxPaths() int     { return positive(o.MaxPaths, DefaultMaxPaths) }
func (o Options) maxBranches() int  { return positive(o.MaxBranches, DefaultMaxBranches) }
func (o Options) maxWorktrees() int { return positive(o.MaxWorktrees, DefaultMaxWorktrees) }
func (o Options) maxOutput() int    { return positive(o.MaxOutput, DefaultMaxOutput) }

func positive(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// State is what one repository holds that its remotes do not.
type State struct {
	// Dir is the directory inspected.
	Dir string `json:"dir"`
	// Repository reports that Dir is the top of a git working tree. When it
	// is false nothing else is set, and NotARepository says why.
	Repository     bool   `json:"repository"`
	NotARepository string `json:"not_a_repository,omitempty"`
	// Remotes are the configured remotes' names. None means every commit in
	// the repository exists only here.
	Remotes []string `json:"remotes,omitempty"`
	// Worktrees are the main worktree first, then every linked worktree that
	// lies inside Dir — a project's features (.cloop/features/<slug>) and its
	// parallel tasks' worktrees among them — in path order.
	Worktrees []Worktree `json:"worktrees"`
	// WorktreesOutside counts linked worktrees of the repository that lie
	// outside Dir. Their commits are counted under Branches; their working
	// trees are not part of the project and are not inspected.
	WorktreesOutside int `json:"worktrees_outside,omitempty"`
	// WorktreesSkipped counts worktrees inside Dir past MaxWorktrees.
	WorktreesSkipped int `json:"worktrees_skipped,omitempty"`
	// Branches are the local branches, in name order, each with how many of
	// its commits no remote-tracking branch contains.
	Branches []Branch `json:"branches"`
	// BranchesSkipped counts local branches past MaxBranches.
	BranchesSkipped int `json:"branches_skipped,omitempty"`
	// Stash is the number of stash entries. A stash is local by nature: no
	// push carries it.
	Stash int `json:"stash,omitempty"`
}

// Worktree is one working tree of the repository.
type Worktree struct {
	// Path is the worktree's absolute path; Rel is that path relative to the
	// inspected directory ("" for the main worktree).
	Path string `json:"path"`
	Rel  string `json:"rel,omitempty"`
	// Branch is the checked-out branch's short name; empty when Detached.
	Branch   string `json:"branch,omitempty"`
	Head     string `json:"head,omitempty"`
	Detached bool   `json:"detached,omitempty"`
	// Orphaned counts the commits a detached HEAD holds that no branch and no
	// remote-tracking branch contains: work that exists only in this
	// worktree's HEAD.
	Orphaned int `json:"orphaned,omitempty"`
	// Locked carries `git worktree lock`'s reason, when the worktree is
	// locked (cloop locks a task worktree it keeps for a retry).
	Locked string `json:"locked,omitempty"`
	// Missing reports a worktree git still records whose directory is gone.
	Missing bool `json:"missing,omitempty"`
	// Changed counts tracked paths with staged or unstaged changes —
	// modified, added, deleted, renamed or conflicted — and Untracked the
	// untracked entries (a directory of untracked files is one entry, as
	// `git status` shows it). The path lists keep the first MaxPaths.
	Changed        int      `json:"changed"`
	ChangedPaths   []string `json:"changed_paths,omitempty"`
	Untracked      int      `json:"untracked"`
	UntrackedPaths []string `json:"untracked_paths,omitempty"`
	// Truncated reports that git's status output was cut at MaxOutput, so
	// the counts are lower bounds.
	Truncated bool `json:"truncated,omitempty"`
	// Error is why this worktree could not be inspected, when it could not.
	Error string `json:"error,omitempty"`
}

// Dirty reports whether the worktree holds any change status sees.
func (w Worktree) Dirty() bool { return w.Changed > 0 || w.Untracked > 0 }

// Branch is one local branch.
type Branch struct {
	Name string `json:"name"`
	Head string `json:"head"`
	// Upstream is the branch's configured upstream (refs/remotes/...), if any.
	Upstream string `json:"upstream,omitempty"`
	// Unpushed counts the branch's commits that no remote-tracking branch
	// contains, as of the hub's last fetch or push.
	Unpushed int `json:"unpushed"`
	// Error is why the branch could not be counted, when it could not.
	Error string `json:"error,omitempty"`
}

// Unpushed returns the branches with commits no remote holds.
func (s State) Unpushed() []Branch {
	var out []Branch
	for _, b := range s.Branches {
		if b.Unpushed > 0 {
			out = append(out, b)
		}
	}
	return out
}

// ErrNotADirectory is returned when Dir does not name a directory.
var ErrNotADirectory = errors.New("gitstate: not a directory")

// Inspect reports what the repository at dir holds that its remotes do not.
//
// dir must be the top of the working tree: a directory inside someone else's
// repository is reported as not a repository rather than as that repository,
// so a project in a subdirectory is never mistaken for its parent's checkout.
// A directory with no .git at all is not an error either; it is the ordinary
// shape of a project with no repository of its own (Task 20324).
func Inspect(ctx context.Context, dir string, opts Options) (State, error) {
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) {
		return State{}, fmt.Errorf("gitstate: %q is not an absolute path", dir)
	}
	st := State{Dir: dir, Worktrees: []Worktree{}, Branches: []Branch{}}
	info, err := os.Stat(dir)
	if err != nil {
		return st, fmt.Errorf("gitstate: %w", err)
	}
	if !info.IsDir() {
		return st, fmt.Errorf("%w: %s", ErrNotADirectory, dir)
	}
	dotGit, err := os.Lstat(filepath.Join(dir, ".git"))
	switch {
	case errors.Is(err, os.ErrNotExist):
		st.NotARepository = "it has no .git"
		return st, nil
	case err != nil:
		return st, fmt.Errorf("gitstate: %w", err)
	case dotGit.Mode()&os.ModeSymlink != 0:
		// A planted link would point git at a repository elsewhere on the
		// hub; nothing here reads through one.
		st.NotARepository = ".git is a symbolic link, which is not followed"
		return st, nil
	}

	g, err := newRunner(ctx, dir, opts)
	if err != nil {
		return st, err
	}
	top, err := g.run(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return st, fmt.Errorf("gitstate: %s: %w", dir, err)
	}
	if !sameDir(strings.TrimSpace(top), dir) {
		st.NotARepository = fmt.Sprintf("it is inside the repository at %s rather than the top of one", strings.TrimSpace(top))
		return st, nil
	}
	st.Repository = true

	remotes, err := g.run(ctx, dir, "remote")
	if err != nil {
		return st, fmt.Errorf("gitstate: list remotes in %s: %w", dir, err)
	}
	st.Remotes = nonEmptyLines(remotes)

	if err := g.inspectBranches(ctx, &st); err != nil {
		return st, err
	}
	if err := g.inspectWorktrees(ctx, &st); err != nil {
		return st, err
	}
	st.Stash = g.stashEntries(ctx, dir)
	return st, nil
}

// runner runs hardened, lock-free git for one repository.
type runner struct {
	env       []string
	maxOutput int
	timeout   time.Duration
	opts      Options
}

func newRunner(ctx context.Context, dir string, opts Options) (*runner, error) {
	ctx, cancel := context.WithTimeout(ctx, positiveDuration(opts.CommandTimeout, DefaultCommandTimeout))
	defer cancel()
	drivers, err := gitprovision.FilterDrivers(ctx, dir, nil, hubOwnership)
	if err != nil {
		return nil, fmt.Errorf("gitstate: %w", err)
	}
	pairs := append(executor.HardenedGitConfig(drivers), hubOwnership)
	env := append(executor.GitEnv(pairs...),
		// The status of the tree as it is, not as a refresh would leave it:
		// git skips every lock it would only take to save work for later.
		"GIT_OPTIONAL_LOCKS=0",
		"LC_ALL=C")
	// Never look above the project for a repository to answer for it. The
	// variable is a colon-separated list, so a parent whose name holds a colon
	// cannot be named in it; Inspect's own top-level check still refuses to
	// answer for an enclosing repository then.
	if parent := filepath.Dir(dir); !strings.Contains(parent, ":") {
		env = append(env, "GIT_CEILING_DIRECTORIES="+parent)
	}
	return &runner{
		env:       env,
		maxOutput: opts.maxOutput(),
		timeout:   positiveDuration(opts.CommandTimeout, DefaultCommandTimeout),
		opts:      opts,
	}, nil
}

// hubOwnership lets the hub's git read a project its account does not own,
// for the reason pkg/executor/featurehub gives: a container-bound project is
// owned by its sandbox's uid, and every invocation here neutralises the
// repository's configuration anyway.
var hubOwnership = [2]string{"safe.directory", "*"}

func positiveDuration(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

// gitError is a failed git invocation, carrying git's own words.
type gitError struct {
	args   []string
	stderr string
	err    error
}

func (e *gitError) Error() string {
	if e.stderr != "" {
		return fmt.Sprintf("git %s: %s", e.args[0], e.stderr)
	}
	return fmt.Sprintf("git %s: %v", e.args[0], e.err)
}

func (e *gitError) Unwrap() error { return e.err }

// run executes one git command in dir and returns its output.
func (g *runner) run(ctx context.Context, dir string, args ...string) (string, error) {
	out, _, err := g.runCapped(ctx, dir, args...)
	return out, err
}

// runCapped is run that also reports whether the output was cut at maxOutput.
func (g *runner) runCapped(ctx context.Context, dir string, args ...string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	full := append([]string{"--no-optional-locks", "-C", dir}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = g.env
	cmd.Dir = dir
	gitprovision.BoundChild(cmd)
	stdout := &cappedBuffer{max: g.maxOutput}
	var stderr cappedBuffer
	stderr.max = 64 << 10
	cmd.Stdout = stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", false, fmt.Errorf("git %s: %w", args[0], ctxErr)
		}
		return stdout.String(), stdout.cut, &gitError{args: args, stderr: gitprovision.Collapse(stderr.String()), err: err}
	}
	return stdout.String(), stdout.cut, nil
}

// cappedBuffer keeps the first max bytes written to it and discards the rest,
// still accepting them so the child never blocks on a full pipe.
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

// inspectBranches counts, per local branch, the commits no remote-tracking
// branch contains.
func (g *runner) inspectBranches(ctx context.Context, st *State) error {
	out, err := g.run(ctx, st.Dir, "for-each-ref", "--format=%(refname)%00%(objectname)%00%(upstream)", "refs/heads/")
	if err != nil {
		return fmt.Errorf("gitstate: list branches in %s: %w", st.Dir, err)
	}
	for _, line := range nonEmptyLines(out) {
		fields := strings.Split(line, "\x00")
		if len(fields) != 3 {
			continue
		}
		ref := fields[0]
		name, ok := strings.CutPrefix(ref, "refs/heads/")
		if !ok || name == "" {
			continue
		}
		if len(st.Branches) >= g.opts.maxBranches() {
			st.BranchesSkipped++
			continue
		}
		b := Branch{Name: name, Head: fields[1], Upstream: fields[2]}
		// The full refname, so a branch named like an option or a revision
		// expression is only ever this branch.
		n, err := g.count(ctx, st.Dir, ref, "--remotes")
		if err != nil {
			b.Error = err.Error()
		}
		b.Unpushed = n
		st.Branches = append(st.Branches, b)
	}
	sort.Slice(st.Branches, func(i, j int) bool { return st.Branches[i].Name < st.Branches[j].Name })
	return nil
}

// count returns how many commits rev reaches that none of the excluded ref
// sets (--remotes, --branches) do.
func (g *runner) count(ctx context.Context, dir, rev string, exclude ...string) (int, error) {
	args := append([]string{"rev-list", "--count", rev, "--not"}, exclude...)
	args = append(args, "--")
	out, err := g.run(ctx, dir, args...)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("git rev-list printed %q, not a count", strings.TrimSpace(out))
	}
	return n, nil
}

// inspectWorktrees lists the repository's worktrees and inspects each one
// inside the project directory.
func (g *runner) inspectWorktrees(ctx context.Context, st *State) error {
	out, err := g.run(ctx, st.Dir, "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return fmt.Errorf("gitstate: list worktrees in %s: %w", st.Dir, err)
	}
	listed := parseWorktreeList(out)
	// git records worktrees by their resolved paths, so a project reached
	// through a symbolic link is compared by both names.
	roots := []string{st.Dir}
	if real, err := filepath.EvalSymlinks(st.Dir); err == nil && real != st.Dir {
		roots = append(roots, real)
	}
	var inside []Worktree
	for _, w := range listed {
		rel, within := "", false
		for _, root := range roots {
			if rel, within = relWithin(root, w.Path); within {
				break
			}
		}
		if !within {
			st.WorktreesOutside++
			continue
		}
		w.Rel = rel
		inside = append(inside, w)
	}
	// The main worktree first (it is git's first record, and its Rel is ""),
	// then the rest by path.
	sort.SliceStable(inside, func(i, j int) bool {
		if (inside[i].Rel == "") != (inside[j].Rel == "") {
			return inside[i].Rel == ""
		}
		return inside[i].Rel < inside[j].Rel
	})
	for i, w := range inside {
		if i >= g.opts.maxWorktrees() {
			st.WorktreesSkipped = len(inside) - i
			break
		}
		g.inspectWorktree(ctx, &w)
		st.Worktrees = append(st.Worktrees, w)
	}
	return nil
}

// inspectWorktree fills in one worktree's changes, and what its detached HEAD
// alone holds.
func (g *runner) inspectWorktree(ctx context.Context, w *Worktree) {
	if info, err := os.Lstat(w.Path); err != nil || !info.IsDir() {
		w.Missing = true
		return
	}
	args := []string{"status", "--porcelain=v2", "-z", "--untracked-files=normal", "--ignore-submodules=all",
		"--", "."}
	for _, ex := range g.opts.Exclude {
		ex = strings.Trim(filepath.ToSlash(ex), "/")
		if ex == "" {
			continue
		}
		args = append(args, ":(top,exclude,literal)"+ex)
	}
	out, cut, err := g.runCapped(ctx, w.Path, args...)
	if err != nil {
		w.Error = err.Error()
		return
	}
	w.Truncated = cut
	changed, untracked := parseStatus(out, cut)
	w.Changed, w.Untracked = len(changed), len(untracked)
	w.ChangedPaths = firstN(changed, g.opts.maxPaths())
	w.UntrackedPaths = firstN(untracked, g.opts.maxPaths())
	if w.Detached && w.Head != "" {
		n, err := g.count(ctx, w.Path, "HEAD", "--branches", "--remotes")
		if err != nil {
			w.Error = err.Error()
			return
		}
		w.Orphaned = n
	}
}

// stashEntries counts the stash's entries; any failure reads as none, since a
// repository without a stash answers with an error too.
func (g *runner) stashEntries(ctx context.Context, dir string) int {
	if _, err := g.run(ctx, dir, "rev-parse", "--verify", "--quiet", "refs/stash"); err != nil {
		return 0
	}
	out, err := g.run(ctx, dir, "log", "--walk-reflogs", "--format=%H", "refs/stash", "--")
	if err != nil {
		// The stash ref exists; its reflog could not be walked. One entry is
		// the least it holds.
		return 1
	}
	return len(nonEmptyLines(out))
}

// parseWorktreeList parses `git worktree list --porcelain -z`.
func parseWorktreeList(out string) []Worktree {
	var (
		list []Worktree
		cur  *Worktree
	)
	for _, field := range strings.Split(out, "\x00") {
		if field == "" {
			// A blank record ends a worktree.
			if cur != nil {
				list = append(list, *cur)
				cur = nil
			}
			continue
		}
		key, value, _ := strings.Cut(field, " ")
		switch key {
		case "worktree":
			if cur != nil {
				list = append(list, *cur)
			}
			cur = &Worktree{Path: filepath.Clean(value)}
		case "HEAD":
			if cur != nil {
				cur.Head = value
			}
		case "branch":
			if cur != nil {
				cur.Branch = strings.TrimPrefix(value, "refs/heads/")
			}
		case "detached":
			if cur != nil {
				cur.Detached = true
			}
		case "locked":
			if cur != nil {
				cur.Locked = value
				if cur.Locked == "" {
					cur.Locked = "locked"
				}
			}
		case "prunable":
			if cur != nil {
				cur.Missing = true
			}
		}
	}
	if cur != nil {
		list = append(list, *cur)
	}
	return list
}

// parseStatus splits `git status --porcelain=v2 -z` into the tracked paths
// with changes and the untracked entries. A record cut short by the output cap
// is dropped rather than half-read.
func parseStatus(out string, cut bool) (changed, untracked []string) {
	records := strings.Split(out, "\x00")
	if cut && len(records) > 0 {
		records = records[:len(records)-1]
	}
	for i := 0; i < len(records); i++ {
		rec := records[i]
		if len(rec) < 2 {
			continue
		}
		switch rec[0] {
		case '1':
			if p := field(rec, 8); p != "" {
				changed = append(changed, p)
			}
		case '2':
			if p := field(rec, 9); p != "" {
				changed = append(changed, p)
			}
			// A rename's original path follows as a record of its own.
			i++
		case 'u':
			if p := field(rec, 10); p != "" {
				changed = append(changed, p)
			}
		case '?':
			untracked = append(untracked, rec[2:])
		}
	}
	return changed, untracked
}

// field returns the path that follows n space-separated fields of a status
// record: paths may themselves contain spaces, so it is everything after them.
func field(rec string, n int) string {
	parts := strings.SplitN(rec, " ", n+1)
	if len(parts) != n+1 {
		return ""
	}
	return parts[n]
}

func firstN(paths []string, n int) []string {
	if len(paths) <= n {
		return paths
	}
	return append([]string(nil), paths[:n]...)
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

// relWithin returns p relative to dir, and whether p is dir or lies below it.
func relWithin(dir, p string) (string, bool) {
	if sameDir(dir, p) {
		return "", true
	}
	rel, err := filepath.Rel(dir, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// sameDir reports whether a and b name the same directory, by path or, failing
// that, by identity (a symlinked project path, /tmp on a platform that links
// it).
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
