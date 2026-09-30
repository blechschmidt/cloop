package reviewgate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Bounds on what a review reads. A task can leave anything in its working
// directory, and the review prompt is sent to a model with a finite context,
// so every read here is capped and says when it was cut.
const (
	// maxRepos bounds how many repositories one review covers.
	maxRepos = 16
	// maxWalkDirs and maxWalkDepth bound the walk that finds repositories the
	// task cloned inside the project.
	maxWalkDirs  = 20000
	maxWalkDepth = 4
	// maxDiffBytes is the diff budget shared by every repository in a review.
	maxDiffBytes = 60_000
	// maxUntrackedFiles and maxUntrackedFileBytes bound new files rendered
	// into the diff; larger or binary ones are listed by name.
	maxUntrackedFiles     = 200
	maxUntrackedFileBytes = 16_000
	// maxCommitLines bounds the commit list shown per repository.
	maxCommitLines = 50
	// gitTimeout bounds one git invocation.
	gitTimeout = 60 * time.Second
)

// skipDirs are never searched for nested repositories. .cloop holds cloop's
// own state — and its task worktrees and feature worktrees, which are
// separate checkouts of the project that a review of this task must not
// mistake for work the task did.
var skipDirs = map[string]bool{
	".git": true, ".cloop": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, ".cache": true, ".terraform": true, ".tox": true,
	".mypy_cache": true, ".pytest_cache": true, ".gradle": true,
}

// Snapshot records the repositories under a project before a task runs, so a
// review can tell what the task changed from what was already there.
type Snapshot struct {
	// Root is the directory the task works in.
	Root string
	// Heads maps each repository's top-level directory to its HEAD commit
	// ("" for a repository with no commits yet).
	Heads map[string]string
}

// TakeSnapshot records the repositories under root and their HEADs.
func TakeSnapshot(ctx context.Context, root string) *Snapshot {
	root = absClean(root)
	s := &Snapshot{Root: root, Heads: map[string]string{}}
	for _, repo := range discoverRepos(ctx, root) {
		s.Heads[repo] = revParse(ctx, repo, "HEAD")
	}
	return s
}

// Head returns the HEAD the repository at dir had when the snapshot was
// taken, and whether the snapshot saw that repository at all.
func (s *Snapshot) Head(dir string) (string, bool) {
	if s == nil {
		return "", false
	}
	h, ok := s.Heads[absClean(dir)]
	return h, ok
}

// Changes is what a task changed, per repository.
type Changes struct {
	Root  string
	Repos []RepoChanges
}

// RepoChanges is one repository's contribution to a review.
type RepoChanges struct {
	// Dir is the repository's top-level directory; Rel the same relative to
	// the project ("." for the project's own repository).
	Dir string
	Rel string
	// Base is the commit the diff starts from ("" means the empty tree: the
	// whole repository is new). Head is HEAD when the changes were collected
	// ("" before the first commit).
	Base string
	Head string
	// Branch is the checked-out branch ("" when HEAD is detached).
	Branch string
	// Tree is the tree `git add -A` would commit from the working state. It
	// is what a merge performed after the review must match.
	Tree string
	// Commits lists Base..Head, newest first ("<short sha> <subject>");
	// CommitCount is the full count.
	Commits     []string
	CommitCount int
	// Files, Insertions and Deletions summarise the diff, untracked files
	// included.
	Files      int
	Insertions int
	Deletions  int
	// Uncommitted reports changes in the working tree that are not in Head.
	Uncommitted bool
	// CloopFiles lists changed paths under .cloop/, which are cloop's own
	// bookkeeping and shown by name only.
	CloopFiles []string
	// Diff is the unified diff of the working tree against Base, with new
	// untracked files rendered as additions. Truncated reports it was cut.
	Diff      string
	Truncated bool
	// Held are the pushes the agent attempted from this repository.
	Held []HeldPush
}

// changed reports whether the repository has anything to review.
func (r *RepoChanges) changed() bool {
	return r.Files > 0 || r.CommitCount > 0 || len(r.CloopFiles) > 0 || len(r.Held) > 0
}

// Empty reports whether no repository has anything to review.
func (c *Changes) Empty() bool {
	if c == nil {
		return true
	}
	for i := range c.Repos {
		if c.Repos[i].changed() {
			return false
		}
	}
	return true
}

// Repo returns the entry for the repository at dir, or nil.
func (c *Changes) Repo(dir string) *RepoChanges {
	if c == nil {
		return nil
	}
	dir = absClean(dir)
	for i := range c.Repos {
		if c.Repos[i].Dir == dir {
			return &c.Repos[i]
		}
	}
	return nil
}

// Collect gathers what changed since snap in every repository under the
// project, including repositories the task created or cloned. held are the
// pushes the agent attempted; they widen a repository's range to everything
// that push would publish.
func Collect(ctx context.Context, snap *Snapshot, held []HeldPush) (*Changes, error) {
	if snap == nil {
		return nil, errors.New("reviewgate: no snapshot to compare with")
	}
	c := &Changes{Root: snap.Root}
	budget := maxDiffBytes
	all := discoverRepos(ctx, snap.Root)
	for _, dir := range all {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		prev, existed := snap.Heads[dir]
		rc := collectRepo(ctx, snap.Root, dir, prev, existed, heldFor(held, dir), nestedUnder(all, dir), &budget)
		if rc.changed() {
			c.Repos = append(c.Repos, rc)
		}
	}
	return c, nil
}

// collectRepo builds one repository's entry. budget is the diff allowance
// still unspent across the whole review, and is decremented.
func collectRepo(ctx context.Context, root, dir, prevHead string, existed bool, held []HeldPush, nested []string, budget *int) RepoChanges {
	rc := RepoChanges{Dir: dir, Rel: relTo(root, dir), Held: held}
	rc.Head = revParse(ctx, dir, "HEAD")
	if b, err := gitOut(ctx, dir, "symbolic-ref", "--short", "-q", "HEAD"); err == nil {
		rc.Branch = strings.TrimSpace(b)
	}
	rc.Base = chooseBase(ctx, dir, rc.Head, prevHead, existed, held)
	rc.Tree = workTree(ctx, dir, rc.Head)

	from := rc.Base
	if from == "" {
		from = emptyTree(ctx, dir)
	}
	exclude := []string{"--", ".", ":(exclude).cloop"}
	for _, n := range nested {
		exclude = append(exclude, ":(exclude)"+n)
	}

	// Tracked changes: the working tree against the base, which folds the
	// task's commits, staged and unstaged edits into one net diff.
	if out, err := gitOut(ctx, dir, append([]string{"diff", "--numstat", "--no-renames", from}, exclude...)...); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			f := strings.SplitN(line, "\t", 3)
			if len(f) < 3 {
				continue
			}
			rc.Files++
			a, _ := strconv.Atoi(f[0])
			d, _ := strconv.Atoi(f[1])
			rc.Insertions += a
			rc.Deletions += d
		}
	}
	if *budget > 0 {
		out, cut, err := gitOutLimit(ctx, dir, *budget, append([]string{"diff", "--no-color", "--no-ext-diff",
			"--no-textconv", "--find-renames", from}, exclude...)...)
		if err == nil {
			rc.Diff = out
			rc.Truncated = cut
			*budget -= len(out)
		}
	} else {
		rc.Truncated = true
	}

	// cloop's own files, by name.
	if out, err := gitOut(ctx, dir, "diff", "--name-only", "-z", from, "--", ".cloop"); err == nil {
		for _, p := range strings.Split(out, "\x00") {
			if p != "" && len(rc.CloopFiles) < 20 {
				rc.CloopFiles = append(rc.CloopFiles, p)
			}
		}
	}

	// Untracked files, which no diff against a commit shows.
	untracked := untrackedFiles(ctx, dir, nested)
	var extra strings.Builder
	for i, p := range untracked {
		if i >= maxUntrackedFiles {
			fmt.Fprintf(&extra, "# … and %d more new files\n", len(untracked)-maxUntrackedFiles)
			rc.Truncated = true
			break
		}
		rc.Files++
		body, lines, ok := readNewFile(filepath.Join(dir, p))
		rc.Insertions += lines
		if !ok || *budget-extra.Len() <= len(body)+200 {
			fmt.Fprintf(&extra, "# new file %s (%s)\n", p, map[bool]string{true: "not shown: over the review's size budget", false: "not shown: binary or larger than 16 KB"}[ok])
			if ok {
				rc.Truncated = true
			}
			continue
		}
		fmt.Fprintf(&extra, "diff --git a/%s b/%s\nnew file (untracked)\n--- /dev/null\n+++ b/%s\n@@ -0,0 +1,%d @@\n", p, p, p, lines)
		extra.WriteString(body)
	}
	if extra.Len() > 0 {
		if rc.Diff != "" && !strings.HasSuffix(rc.Diff, "\n") {
			rc.Diff += "\n"
		}
		rc.Diff += extra.String()
		*budget -= extra.Len()
	}

	if st, err := gitOut(ctx, dir, append([]string{"status", "--porcelain", "--untracked-files=normal"}, exclude...)...); err == nil {
		rc.Uncommitted = strings.TrimSpace(st) != ""
	}

	// The commits the range holds.
	if rc.Head != "" {
		rng := rc.Head
		if rc.Base != "" {
			rng = rc.Base + ".." + rc.Head
		}
		if n, err := gitOut(ctx, dir, "rev-list", "--count", rng); err == nil {
			rc.CommitCount, _ = strconv.Atoi(strings.TrimSpace(n))
		}
		if rc.CommitCount > 0 {
			if out, err := gitOut(ctx, dir, "log", "--no-color", "-n", strconv.Itoa(maxCommitLines),
				"--format=%h %s", rng); err == nil {
				for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
					if l = strings.TrimSpace(l); l != "" {
						rc.Commits = append(rc.Commits, clip(l, 200))
					}
				}
			}
		}
	}
	return rc
}

// chooseBase picks the commit a repository's review starts from.
//
// Without a held push it is where the task started: the diff is the task's own
// work. With one, it widens to where the remote's copy of each pushed branch
// forks from HEAD, because that push would publish every commit after that
// point — including any that were already sitting unpushed before the task —
// and the reviewer has to have seen all of them. A repository that did not
// exist when the task started is compared with where it came from.
func chooseBase(ctx context.Context, dir, head, prevHead string, existed bool, held []HeldPush) string {
	if head == "" {
		return ""
	}
	var candidates []string
	addMB := func(ref string) {
		if sha := revParse(ctx, dir, ref); sha != "" {
			if mb := mergeBase(ctx, dir, head, sha); mb != "" {
				candidates = append(candidates, mb)
			}
		}
	}
	if existed && prevHead != "" {
		addMB(prevHead)
	}
	for _, h := range held {
		if tr := trackingRef(h.Remote, h.Dst); tr != "" {
			addMB(tr)
		}
	}
	if !existed {
		if revParse(ctx, dir, "@{upstream}") != "" {
			addMB("@{upstream}")
		} else if revParse(ctx, dir, "refs/remotes/origin/HEAD") != "" {
			addMB("refs/remotes/origin/HEAD")
		}
	}
	if len(candidates) == 0 {
		// A repository that had no commits when the task started, one the
		// task created from nothing, or history the task rewrote so that it
		// shares nothing with where it started: all of it is the task's.
		return ""
	}
	best, bestN := candidates[0], -1
	for _, c := range candidates {
		n := 0
		if out, err := gitOut(ctx, dir, "rev-list", "--count", c+".."+head); err == nil {
			n, _ = strconv.Atoi(strings.TrimSpace(out))
		}
		if n > bestN {
			best, bestN = c, n
		}
	}
	return best
}

// trackingRef returns the remote-tracking ref that mirrors dst on remote, or
// "" when there is none to consult (a URL rather than a named remote, a tag).
func trackingRef(remote, dst string) string {
	if !strings.HasPrefix(dst, "refs/heads/") || !validRemoteName(remote) {
		return ""
	}
	return "refs/remotes/" + remote + "/" + strings.TrimPrefix(dst, "refs/heads/")
}

// validRemoteName reports whether s is a configured remote's name rather than
// a URL or path, and is safe to splice into a ref name and an argv.
func validRemoteName(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, ".") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// heldFor returns the held pushes made from the repository at dir.
func heldFor(held []HeldPush, dir string) []HeldPush {
	var out []HeldPush
	for _, h := range held {
		if absClean(h.Repo) == dir {
			out = append(out, h)
		}
	}
	return out
}

// discoverRepos returns the repository containing root, then every repository
// nested below it, bounded.
func discoverRepos(ctx context.Context, root string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = absClean(p)
		if !seen[p] && len(out) < maxRepos {
			seen[p] = true
			out = append(out, p)
		}
	}
	if top, err := gitOut(ctx, root, "rev-parse", "--show-toplevel"); err == nil && strings.TrimSpace(top) != "" {
		add(strings.TrimSpace(top))
	}
	visited := 0
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxWalkDepth || visited >= maxWalkDirs || len(out) >= maxRepos || ctx.Err() != nil {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			// IsDir is false for a symbolic link, so a link out of the
			// project is never followed.
			if !e.IsDir() || skipDirs[e.Name()] {
				continue
			}
			visited++
			p := filepath.Join(dir, e.Name())
			if isRepoDir(p) {
				add(p)
			}
			walk(p, depth+1)
		}
	}
	walk(root, 1)
	return out
}

// isRepoDir reports whether dir is the top of a git checkout: it has a .git
// directory, or a .git file as linked worktrees and submodules do.
func isRepoDir(dir string) bool {
	fi, err := os.Lstat(filepath.Join(dir, ".git"))
	return err == nil && (fi.IsDir() || fi.Mode().IsRegular())
}

// nestedUnder returns, relative to dir, the repositories in all that lie
// inside it, so its own diff and status leave their contents to their own
// entries.
func nestedUnder(all []string, dir string) []string {
	var out []string
	for _, r := range all {
		if r == dir {
			continue
		}
		if rel, err := filepath.Rel(dir, r); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			out = append(out, filepath.ToSlash(rel))
		}
	}
	return out
}

// untrackedFiles lists new files git does not ignore, outside .cloop and the
// nested repositories.
func untrackedFiles(ctx context.Context, dir string, nested []string) []string {
	out, err := gitOut(ctx, dir, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil
	}
	var files []string
	for _, p := range strings.Split(out, "\x00") {
		if p == "" || p == ".cloop" || strings.HasPrefix(p, ".cloop/") || strings.HasSuffix(p, "/") {
			continue
		}
		inside := false
		for _, n := range nested {
			if p == n || strings.HasPrefix(p, n+"/") {
				inside = true
				break
			}
		}
		if !inside {
			files = append(files, p)
		}
	}
	sort.Strings(files)
	return files
}

// readNewFile renders a new file's content as added diff lines. ok is false
// for a binary file, one larger than maxUntrackedFileBytes, or one that cannot
// be read; lines is its line count when ok.
func readNewFile(path string) (body string, lines int, ok bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxUntrackedFileBytes {
		return "", 0, false
	}
	data, err := os.ReadFile(path)
	if err != nil || bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return "", 0, false
	}
	var b strings.Builder
	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return "", 0, true
	}
	for _, l := range strings.Split(text, "\n") {
		b.WriteString("+")
		b.WriteString(l)
		b.WriteString("\n")
		lines++
	}
	return b.String(), lines, true
}

// workTree returns the tree `git add -A` would commit from dir's working
// state, computed in a throwaway index so the repository's own is untouched.
func workTree(ctx context.Context, dir, head string) string {
	f, err := os.CreateTemp("", "cloop-review-index-*")
	if err != nil {
		return ""
	}
	idx := f.Name()
	_ = f.Close()
	_ = os.Remove(idx) // git wants to create it; an empty file is not an index
	defer os.Remove(idx)
	env := []string{"GIT_INDEX_FILE=" + idx}
	if head != "" {
		if _, err := gitEnvOut(ctx, dir, env, "read-tree", head); err != nil {
			return ""
		}
	}
	if _, err := gitEnvOut(ctx, dir, env, "add", "-A"); err != nil {
		return ""
	}
	out, err := gitEnvOut(ctx, dir, env, "write-tree")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// TreeOf returns the tree of commit-ish rev in dir, or "".
func TreeOf(ctx context.Context, dir, rev string) string {
	return revParse(ctx, dir, rev+"^{tree}")
}

// emptyTree returns the id of the empty tree in dir's object format.
func emptyTree(ctx context.Context, dir string) string {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "hash-object", "-t", "tree", "--stdin")
	cmd.Env = gitEnv(nil)
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.Output()
	if err != nil {
		return "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	}
	return strings.TrimSpace(string(out))
}

func revParse(ctx context.Context, dir, rev string) string {
	out, err := gitOut(ctx, dir, "rev-parse", "--verify", "-q", "--end-of-options", rev)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func mergeBase(ctx context.Context, dir, a, b string) string {
	out, err := gitOut(ctx, dir, "merge-base", a, b)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func relTo(root, dir string) string {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return dir
	}
	return filepath.ToSlash(rel)
}

func absClean(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return filepath.Clean(p)
}

// gitEnv is the environment for git commands run on the gate's behalf:
// cloop's own, minus anything that would point git at a different
// repository or index than the -C directory names.
func gitEnv(extra []string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		switch k {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR":
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// gitBaseArgs keep a repository's own configuration from running anything
// while it is read: no filesystem monitor, and the pager is irrelevant.
var gitBaseArgs = []string{"-c", "core.fsmonitor=false", "-c", "core.quotepath=off", "--no-pager"}

func gitOut(ctx context.Context, dir string, args ...string) (string, error) {
	return gitEnvOut(ctx, dir, nil, args...)
}

func gitEnvOut(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	out, _, err := gitRun(ctx, dir, env, 8<<20, args...)
	return out, err
}

func gitOutLimit(ctx context.Context, dir string, limit int, args ...string) (string, bool, error) {
	return gitRun(ctx, dir, nil, limit, args...)
}

// gitRun runs git in dir and returns at most limit bytes of its stdout,
// reporting whether there was more. The process is stopped once the limit is
// passed rather than left to write a diff nobody will read.
func gitRun(parent context.Context, dir string, env []string, limit int, args ...string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(parent, gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append(append(append([]string{}, gitBaseArgs...), "-C", dir), args...)...)
	cmd.Env = gitEnv(env)
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", false, err
	}
	if err := cmd.Start(); err != nil {
		return "", false, err
	}
	data, rerr := io.ReadAll(io.LimitReader(stdout, int64(limit)+1))
	cut := len(data) > limit
	if cut {
		data = data[:limit]
		// Cut on a line boundary so the model is not handed half a hunk line.
		if i := bytes.LastIndexByte(data, '\n'); i > 0 {
			data = data[:i+1]
		}
		cancel()
		_ = cmd.Wait()
		return string(data), true, nil
	}
	werr := cmd.Wait()
	if rerr != nil {
		return "", false, rerr
	}
	if werr != nil {
		return string(data), false, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), werr, strings.TrimSpace(stderr.String()))
	}
	return string(data), false, nil
}

// limitedWriter keeps the first n bytes written to it and drops the rest.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := len(p)
		if k > l.n {
			k = l.n
		}
		_, _ = l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}

// clip cuts s to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Toplevel returns the top-level directory of the repository containing dir,
// or "" when dir is not in one.
func Toplevel(ctx context.Context, dir string) string {
	out, err := gitOut(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return ""
	}
	return absClean(strings.TrimSpace(out))
}
