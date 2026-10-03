// Package donecheck is the git half of "done means committed" (Task 20370):
// what did one attempt at a task change in its repository and leave behind
// uncommitted — or commit without pushing?
//
// # Why the symptom is the signal
//
// Task 20349 taught the orchestrator to hand a turn back when the agent's
// final message says it is waiting on its own work ("the suite is still
// running; I'll commit once it reports"). That is phrase matching, and new
// wordings keep slipping past it: Task 20368 ended "The only thing still
// running is the adversarial review agent. I'll address what it finds, re-run
// -race on the touched packages, then commit and push." — nothing matched, the
// task was recorded done, and 24 changed paths sat uncommitted for the next
// task to trip over. Nor can the background-work check see the cause: Claude
// Code's background subagents run inside the CLI process, not as processes of
// their own.
//
// What every one of those turns has in common is not a phrase but a state: the
// working tree still holds the task's changes. So the check reads the state.
//
// # Baseline and blame
//
// A repository is rarely clean when a task starts. An operator's own edits, a
// stranded tree from an earlier run, generated files nobody ignored — none of
// it is this task's, and blaming it would send every task back for work it
// never touched. So Take records, as an attempt starts, every path `git status`
// reports and a fingerprint of each: its status line (which carries the index
// entry) and its working-tree content. Check then blames exactly the paths that
// are dirty now and were either clean then or have changed since.
//
// The exception is the task's own earlier attempt. An attempt that is aborted
// for uncommitted work leaves that work in the tree, by design: nothing here
// reverts or stashes an agent's changes. The next attempt's baseline would then
// count them as already there and let them through. A Carry, written when an
// attempt is blamed and read when the next one starts, keeps them the task's.
//
// # Pushed
//
// With Pushed, the commits the attempt made on HEAD that HEAD's upstream lacks
// are reported too: commits not reachable from the upstream and not from the
// HEAD the attempt started at. Commits that were already local when it started
// are not its to publish. A branch with no upstream — a task worktree, a
// detached HEAD — is noted rather than failed, because there is nowhere to
// push to; and a push the review gate is holding counts as pending, since the
// gate publishes it once the reviewer approves.
//
// # What this package will not do
//
// It never writes to the repository: git runs with optional locks off, so even
// `git status` does not refresh the index behind the agent's back. It never
// runs the repository's filesystem monitor. Everything it reads is bounded,
// because the repository is in the agent's reach: a status listing past
// maxStatusBytes is cut and noted, large files are fingerprinted by size and
// modification time rather than read, and a directory walk stops at
// maxDirEntries.
package donecheck

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Bounds on what one baseline or check reads.
const (
	// MaxListed bounds how many paths and commits a report names. The counts
	// beside them are exact.
	MaxListed = 40
	// maxHashFileBytes is the largest file fingerprinted by its content. A
	// larger one is fingerprinted by size and modification time.
	maxHashFileBytes = 8 << 20
	// maxHashBytes bounds the content hashed while taking one baseline.
	maxHashBytes = 256 << 20
	// maxDirEntries bounds the walk that fingerprints a directory entry: an
	// untracked nested repository, or a submodule.
	maxDirEntries = 20000
	// gitTimeout bounds one git invocation.
	gitTimeout = 2 * time.Minute
)

// maxStatusBytes bounds one `git status` listing. A variable so a test can
// reach the truncated path without writing 32 MiB of file names.
var maxStatusBytes = 32 << 20

// ErrNotRepository reports that the directory is not inside a git working
// tree, so there is nothing to check.
var ErrNotRepository = errors.New("donecheck: not a git working tree")

// Baseline is a repository as an attempt found it.
type Baseline struct {
	// Dir is the directory checked: the task's working directory. Only paths
	// under it are considered, and its .cloop/ never is.
	Dir string
	// Top is the repository's top-level directory, and Prefix is Dir relative
	// to it ("" when Dir is the top level, else "sub/dir/").
	Top    string
	Prefix string
	// Head is the commit HEAD named when the attempt started — or, for a
	// retry, when the first attempt the carry describes started. "" before
	// the first commit.
	Head string
	// Taken is when the baseline was recorded.
	Taken time.Time

	// dirty maps each path that was already dirty, relative to Top, to its
	// fingerprint.
	dirty map[string]string
	// own are paths an earlier attempt of the same task was blamed for. They
	// are this task's even though they were dirty when this attempt started.
	own map[string]bool
	// truncated reports that the listing was cut, so a dirty path missing
	// from dirty may still have been dirty already.
	truncated bool
}

// Options says what a check requires beyond a committed tree.
type Options struct {
	// Pushed also requires the attempt's commits on HEAD's upstream.
	Pushed bool
	// Held are the commits of pushes the review gate is holding. Commits
	// they contain are pending, not missing: the gate publishes them after
	// the reviewer approves. Anything that is not a full commit name is
	// ignored — the list comes from a file the agent can write to.
	Held []string
	// NoPush, when set, says why pushing is not expected here; the push is
	// then not checked and the reason is noted instead.
	NoPush string
}

// Change is one path the attempt left uncommitted.
type Change struct {
	// Path is relative to the checked directory, with a trailing slash for a
	// directory.
	Path string
	// Code is the two-letter status `git status --short` would print:
	// "??" untracked, " M" modified, "A " added, " D" deleted, "UU" conflicted.
	Code string
}

// Commit is one commit the attempt made that its upstream lacks.
type Commit struct {
	SHA     string
	Subject string
}

// Short is the abbreviated commit name.
func (c Commit) Short() string {
	if len(c.SHA) > 12 {
		return c.SHA[:12]
	}
	return c.SHA
}

// Report is what an attempt has left outstanding.
type Report struct {
	// Uncommitted lists up to MaxListed of the paths the attempt changed and
	// left uncommitted; UncommittedCount counts all of them.
	Uncommitted      []Change
	UncommittedCount int
	// Unpushed lists up to MaxListed of the commits the attempt made that are
	// on HEAD but not on its upstream, and that no held push covers;
	// UnpushedCount counts all of them.
	Unpushed      []Commit
	UnpushedCount int
	// Pending counts the attempt's commits that a held push covers.
	Pending int
	// Branch is the checked-out branch ("" when HEAD is detached) and
	// Upstream its upstream ("origin/main"), when the push was checked.
	Branch   string
	Upstream string
	// Notes say what could not be checked, and why.
	Notes []string

	// blamed is every path blamed, relative to the repository's top level,
	// for the carry the next attempt reads.
	blamed []string
}

// Outstanding reports whether the attempt left anything that "done" requires
// to be finished.
func (r *Report) Outstanding() bool {
	return r != nil && (r.UncommittedCount > 0 || r.UnpushedCount > 0)
}

// Summary says in one line what is outstanding, naming the first few paths
// and the upstream: "3 uncommitted paths (a.go, b.go, c.md) and 1 commit not
// on origin/main".
func (r *Report) Summary() string {
	if !r.Outstanding() {
		return "nothing outstanding"
	}
	var parts []string
	if r.UncommittedCount > 0 {
		var names []string
		for i, c := range r.Uncommitted {
			if i == 3 {
				break
			}
			names = append(names, c.Path)
		}
		more := ""
		if r.UncommittedCount > len(names) {
			more = ", …"
		}
		parts = append(parts, fmt.Sprintf("%s (%s%s)", plural(r.UncommittedCount, "uncommitted path"),
			strings.Join(names, ", "), more))
	}
	if r.UnpushedCount > 0 {
		parts = append(parts, fmt.Sprintf("%s not on %s", plural(r.UnpushedCount, "commit"), r.Upstream))
	}
	return strings.Join(parts, " and ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// Take records the repository containing dir as an attempt at a task starts.
// carry, when not nil, is what an earlier aborted attempt at the same task
// left on record; see Carry. It returns ErrNotRepository when dir is not
// inside a git working tree.
func Take(ctx context.Context, dir string, carry *Carry) (*Baseline, error) {
	top, err := gitLine(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil || top == "" {
		if err == nil {
			err = errors.New("no top-level directory")
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrNotRepository, dir, err)
	}
	prefix, err := gitLine(ctx, dir, "rev-parse", "--show-prefix")
	if err != nil {
		return nil, fmt.Errorf("donecheck: %s: %w", dir, err)
	}
	b := &Baseline{
		Dir:    dir,
		Top:    top,
		Prefix: prefix,
		Head:   revParse(ctx, dir, "HEAD"),
		Taken:  time.Now(),
		dirty:  map[string]string{},
		own:    map[string]bool{},
	}
	if carry != nil && carry.Top == top {
		for _, p := range carry.Paths {
			b.own[p] = true
		}
		// The first attempt's HEAD, so the commits an aborted attempt made
		// stay this task's to push — as long as this HEAD still descends
		// from it. A history the agent rewrote since starts the count again.
		if carry.Head != "" && b.Head != "" && carry.Head != b.Head && isAncestor(ctx, dir, carry.Head, b.Head) {
			b.Head = carry.Head
		}
	}

	entries, truncated, err := listDirty(ctx, dir)
	if err != nil {
		return nil, err
	}
	b.truncated = truncated
	budget := int64(maxHashBytes)
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if b.own[e.path] {
			continue
		}
		b.dirty[e.path] = fingerprint(ctx, top, e, "", &budget)
	}
	return b, nil
}

// Check reports what the attempt has left outstanding since b was taken.
func Check(ctx context.Context, b *Baseline, opts Options) (*Report, error) {
	if b == nil {
		return nil, errors.New("donecheck: no baseline to compare with")
	}
	entries, truncated, err := listDirty(ctx, b.Dir)
	if err != nil {
		return nil, err
	}
	rep := &Report{}
	if truncated {
		rep.Notes = append(rep.Notes, fmt.Sprintf("the working tree lists more than %d MiB of changed paths; only those listed first were checked",
			maxStatusBytes>>20))
	}
	unknown := 0
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !b.blames(ctx, e) {
			if _, known := b.dirty[e.path]; !known && !b.own[e.path] {
				unknown++
			}
			continue
		}
		rep.UncommittedCount++
		rep.blamed = append(rep.blamed, e.path)
		if len(rep.Uncommitted) < MaxListed {
			rep.Uncommitted = append(rep.Uncommitted, Change{Path: b.display(e.path), Code: e.code})
		}
	}
	if unknown > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d changed path(s) were not judged: the listing taken when the attempt started was cut short, so they may have been there already", unknown))
	}
	if opts.Pushed {
		if err := b.checkPushed(ctx, opts, rep); err != nil {
			rep.Notes = append(rep.Notes, "the push could not be checked: "+err.Error())
		}
	}
	return rep, nil
}

// blames reports whether e is the attempt's to commit.
func (b *Baseline) blames(ctx context.Context, e entry) bool {
	if b.own[e.path] {
		return true
	}
	was, known := b.dirty[e.path]
	if !known {
		// Clean when the attempt started — unless the listing then was cut
		// short, when nobody can say.
		return !b.truncated
	}
	_, content, _ := strings.Cut(was, "\x00")
	return fingerprint(ctx, b.Top, e, content, nil) != was
}

// display renders a top-level-relative path relative to the checked
// directory.
func (b *Baseline) display(p string) string {
	if b.Prefix != "" && strings.HasPrefix(p, b.Prefix) {
		return p[len(b.Prefix):]
	}
	return p
}

// checkPushed fills in the commits the attempt made that HEAD's upstream lacks.
func (b *Baseline) checkPushed(ctx context.Context, opts Options, rep *Report) error {
	if opts.NoPush != "" {
		rep.Notes = append(rep.Notes, opts.NoPush)
		return nil
	}
	head := revParse(ctx, b.Dir, "HEAD")
	if head == "" {
		rep.Notes = append(rep.Notes, "nothing has been committed yet, so there is nothing to push")
		return nil
	}
	rep.Branch, _ = gitLine(ctx, b.Dir, "symbolic-ref", "--short", "-q", "HEAD")
	upstream, err := gitLine(ctx, b.Dir, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
	if err != nil || upstream == "" {
		if rep.Branch == "" {
			rep.Notes = append(rep.Notes, "HEAD is detached, so it has no upstream: the push was not checked")
		} else {
			rep.Notes = append(rep.Notes, fmt.Sprintf("branch %s has no upstream: the push was not checked", rep.Branch))
		}
		return nil
	}
	upstreamSHA := revParse(ctx, b.Dir, "@{upstream}")
	if upstreamSHA == "" {
		return fmt.Errorf("upstream %s does not resolve to a commit", upstream)
	}
	rep.Upstream = upstream

	revs := []string{head, "^" + upstreamSHA}
	if b.Head != "" {
		// Commits that were already local when the attempt started are not
		// its to publish.
		revs = append(revs, "^"+b.Head)
	}
	made, err := revListCount(ctx, b.Dir, revs)
	if err != nil || made == 0 {
		return err
	}
	for _, h := range opts.Held {
		if isCommitName(h) {
			revs = append(revs, "^"+h)
		}
	}
	missing, err := revListCount(ctx, b.Dir, revs)
	if err != nil {
		return err
	}
	rep.Pending = made - missing
	rep.UnpushedCount = missing
	if missing == 0 {
		return nil
	}
	out, _, err := runGit(ctx, b.Dir, 1<<20, append([]string{"log", "--no-decorate", "--format=%H%x09%s",
		"--max-count=" + strconv.Itoa(MaxListed), "--ignore-missing"}, append(revs, "--")...)...)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		sha, subject, ok := strings.Cut(line, "\t")
		if ok && isCommitName(sha) {
			rep.Unpushed = append(rep.Unpushed, Commit{SHA: sha, Subject: truncateRunes(subject, 120)})
		}
	}
	return nil
}

// revListCount counts the commits revs select. Every revision passed here is
// HEAD, @{upstream} or a validated object name, so none can read as an option
// — which is why no --end-of-options, which gits older than 2.24 refuse.
func revListCount(ctx context.Context, dir string, revs []string) (int, error) {
	out, err := gitLine(ctx, dir, append([]string{"rev-list", "--count", "--ignore-missing"}, append(revs, "--")...)...)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(out)
	if err != nil {
		return 0, fmt.Errorf("rev-list --count printed %q", out)
	}
	return n, nil
}

// isCommitName reports whether s is a full SHA-1 or SHA-256 object name.
func isCommitName(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isAncestor reports whether a is an ancestor of (or equal to) b.
func isAncestor(ctx context.Context, dir, a, b string) bool {
	if !isCommitName(a) || !isCommitName(b) {
		return false
	}
	_, _, err := runGit(ctx, dir, 1024, "merge-base", "--is-ancestor", a, b)
	return err == nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// sortedPaths returns the keys of m, sorted.
func sortedPaths(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// cleanRelPath reports whether p is a clean, relative, slash-separated path
// that stays inside the directory it is relative to.
func cleanRelPath(p string) bool {
	if p == "" || len(p) > 4096 || strings.ContainsRune(p, 0) || strings.HasPrefix(p, "/") {
		return false
	}
	trimmed := strings.TrimSuffix(p, "/")
	if trimmed == "" || path.Clean(trimmed) != trimmed {
		return false
	}
	return trimmed != ".." && !strings.HasPrefix(trimmed, "../")
}
