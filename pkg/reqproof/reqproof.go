// Package reqproof runs red-green proofs of requirements' tests (Task 20464)
// where the project's runs run: `cloop requirements prove`, dispatched to the
// project's executor by the hub and run beside a task's work by the
// requirements gate. The model and the rules are pkg/requirements (proof.go);
// this package runs the tests and the git that sets them up.
//
// A proof of a requirement runs its tests on the change — the tree it is
// given, as it is, like a check — and then, when they pass there, on the code
// before the change: a throwaway checkout of the base commit
// (worktree.AddProof), with the change's test files laid over it when the
// tests do not exist at the base as they read in the change. The checkout is
// removed whichever way the proof ends; the project's own checkout is never
// changed — not its files, its index nor its HEAD.
//
// The base is the commit a task's work started from, when the gate proves a
// task's tests; asked for by hand it is the commit before the test's
// implementation: the parent of the newest commit that changed the test's
// files — or of the newest that changed a test the command names, such as
// TestX in `go test -run TestX`; that commit itself when it changed nothing
// but tests — or the checkout's HEAD while those files have uncommitted
// changes. A person may name it (--base).
package reqproof

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/worktree"
)

// Options say where and how Prove runs.
type Options struct {
	// Dir is the change: the project's tree, a git checkout, where the after
	// run happens. Empty is the current directory.
	Dir string
	// Base is the commit the before run uses. Empty finds each requirement's
	// own: the commit before its test's implementation.
	Base string
	// BaseFrom says how Base was chosen (requirements.BaseFromTask or
	// BaseFromGiven); empty is BaseFromGiven.
	BaseFrom string
	// Env is the environment the tests start from; nil is this process's.
	// requirements.Check keeps the hub's root key out of it.
	Env []string
	// OnlyChanged proves only the requirements whose tests the change added
	// or changed — a test file of theirs, or one named in Changed; the rest
	// are reported untouched, and nothing of theirs runs.
	OnlyChanged bool
	// Changed names the requirements whose test commands the change added or
	// changed: they are proved whatever files changed, and their tests count
	// as new.
	Changed map[int]bool
	// BeforeOnly skips the run on the change: the caller ran the same tests on
	// the same tree a moment ago and fills After in itself. Each proof is then
	// decided as though they passed there.
	BeforeOnly bool
	// Deadline is when the proof's checkouts may be taken for leftovers by
	// another proof's sweep. Zero is the context's deadline, or the proofs'
	// budget from now.
	Deadline time.Time
	// OnProof is told each proof as it is made, for a caller printing
	// progress.
	OnProof func(requirements.Proof)
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// maxChanges bounds the files of a change a proof reads. Past it the change
// is taken to hold code as well as tests, and no test file past the bound is
// laid over the base.
const maxChanges = 50000

// maxGitOutput bounds what one git command may print here.
const maxGitOutput = 32 << 20

// gitTimeout bounds one git command of a proof.
const gitTimeout = 5 * time.Minute

// run is one Prove call's shared state.
type run struct {
	opts     Options
	dir      string // the project's root, absolute
	top      string // the repository's top level, absolute
	rel      string // dir relative to top ("." when they are the same)
	head     string // HEAD of the change
	dirty    bool
	deadline time.Time
	now      func() time.Time
	changes  map[string]*changeSet
	cleanup  []error
}

// changeSet is what changed between one base and the change.
type changeSet struct {
	files     []requirements.ProofFile // paths relative to the repository's top
	truncated bool
	err       error
}

// Prove proves each requirement in turn (see the package comment) and returns
// what it found. The error reports a proof checkout that could not be removed:
// the proofs stand, and the next proof's sweep takes the leftover. A context
// that ends stops the proof: the test running is killed, its checkout
// removed, and what was not reached is reported as an error, not as an
// outcome.
func Prove(ctx context.Context, reqs []requirements.Requirement, opts Options) (requirements.ProofReport, error) {
	r := &run{opts: opts, now: opts.Now, changes: map[string]*changeSet{}}
	if r.now == nil {
		r.now = time.Now
	}
	rep := requirements.ProofReport{Results: []requirements.Proof{}}
	fail := func(why string) (requirements.ProofReport, error) {
		for _, q := range reqs {
			p := requirements.Proof{RequirementID: q.ID, Fingerprint: q.Fingerprint(), Outcome: requirements.ProofError,
				Summary: why, StartedAt: r.now().UTC()}
			rep.Results = append(rep.Results, p)
			if opts.OnProof != nil {
				opts.OnProof(p)
			}
		}
		return rep, nil
	}
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fail("the project's directory cannot be resolved: " + err.Error())
	}
	r.dir = abs
	top, err := gitLine(ctx, r.dir, "rev-parse", "--show-toplevel")
	if err != nil || top == "" {
		return fail("the project's tree is not a git checkout, so there is no commit before the change to prove its tests against")
	}
	r.top = filepath.Clean(top)
	if r.rel, err = filepath.Rel(evalPath(r.top), evalPath(r.dir)); err != nil || strings.HasPrefix(r.rel, "..") {
		return fail("the project's directory is not inside its git checkout")
	}
	r.head, r.dirty = requirements.WorkTree(ctx, r.dir)
	if r.head == "" {
		return fail("the project's checkout has no commit yet, so there is nothing before the change to prove its tests against")
	}
	r.deadline = opts.Deadline
	if r.deadline.IsZero() {
		if d, ok := ctx.Deadline(); ok {
			r.deadline = d
		} else {
			r.deadline = r.now().Add(requirements.ProofBudget(reqs, opts.BeforeOnly))
		}
	}
	// What a proof killed outright left behind goes first.
	if _, err := worktree.SweepProofs(ctx, r.dir, r.now()); err != nil {
		r.cleanup = append(r.cleanup, fmt.Errorf("sweep earlier proofs' checkouts: %w", err))
	}
	for _, q := range reqs {
		p, touched := r.prove(ctx, q)
		if !touched {
			rep.Untouched = append(rep.Untouched, q.ID)
			continue
		}
		rep.Results = append(rep.Results, p)
		if opts.OnProof != nil {
			opts.OnProof(p)
		}
	}
	return rep, errors.Join(r.cleanup...)
}

// prove proves one requirement. touched is false for one OnlyChanged passes
// over.
func (r *run) prove(ctx context.Context, req requirements.Requirement) (p requirements.Proof, touched bool) {
	start := r.now()
	p = requirements.Proof{RequirementID: req.ID, Fingerprint: req.Fingerprint(), StartedAt: start.UTC()}
	p.After.Commit, p.After.Dirty = r.head, r.dirty
	defer func() {
		if touched {
			p.DurationMS = r.now().Sub(start).Milliseconds()
			p.Outcome, p.Summary = requirements.DecideProof(p)
		}
	}()
	if !req.Tested() {
		p.After.Skipped = "it has no tests, so there is nothing to prove"
		return p, true
	}
	if ctx.Err() != nil {
		p.After.Skipped = "the proof was stopped before it reached this requirement"
		return p, true
	}

	base, from, baseErr := r.baseFor(ctx, req)
	p.Before.Commit, p.BaseFrom = base, from
	var cs *changeSet
	if baseErr == nil {
		if cs = r.changesSince(ctx, base); cs.err != nil {
			baseErr = cs.err
		}
	}
	var tests []requirements.ProofFile
	if baseErr == nil {
		tests = requirements.TestFilesFor(req.Tests, cs.forProject(r.rel), r.exists)
	}
	if r.opts.OnlyChanged && !r.opts.Changed[req.ID] && len(tests) == 0 {
		// A base this checkout lacks tells nothing about what changed either:
		// a proof of only what the change touched passes over what it cannot
		// see, rather than reporting every requirement it was handed.
		return p, false
	}
	touched = true
	if baseErr != nil {
		p.Before.Skipped = baseErr.Error()
	}
	// TestFilesFor read the paths relative to the project; the base's
	// checkout and the overlay work from the repository's top.
	top := cs.toTop(r.rel, tests)
	p.Fallback = len(top) > 0
	for _, f := range tests {
		if len(p.TestFiles) == requirements.MaxProofFiles {
			break
		}
		p.TestFiles = append(p.TestFiles, f)
	}
	if cs != nil {
		p.CodeChanged = cs.holdsMoreThan(top)
	}
	p.NewTests = r.opts.Changed[req.ID] || r.addsTests(ctx, base, top)

	if !r.opts.BeforeOnly {
		p.After = r.side(ctx, req, r.dir, "after")
		p.After.Commit, p.After.Dirty = r.head, r.dirty
		if afterGreen := allPass(p.After); !afterGreen {
			return p, true
		}
	}
	if baseErr != nil || !p.CodeChanged {
		return p, true
	}
	p.Before = r.beforeRun(ctx, req, base, top)
	return p, true
}

// beforeRun checks base out, lays the test files over it, runs the tests
// there, and removes the checkout — on the way out of a panic too.
func (r *run) beforeRun(ctx context.Context, req requirements.Requirement, base string, overlay []requirements.ProofFile) (side requirements.ProofSide) {
	side.Commit, side.Dirty = base, len(overlay) > 0
	if ctx.Err() != nil {
		side.Skipped = "the proof was stopped before the base run"
		return side
	}
	co, err := worktree.AddProof(ctx, r.dir, base, r.deadline)
	if err != nil {
		side.Skipped = "the base could not be checked out: " + err.Error()
		return side
	}
	defer func() {
		if err := co.Remove(); err != nil {
			r.cleanup = append(r.cleanup, err)
		}
	}()
	if err := layOver(r.top, co.Path, overlay); err != nil {
		side.Skipped = "the change's test files could not be laid over the base: " + err.Error()
		return side
	}
	dir := filepath.Join(co.Path, r.rel)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		side.Skipped = "the project's directory " + r.rel + " does not exist at the base"
		return side
	}
	ran := r.side(ctx, req, dir, "before")
	ran.Commit, ran.Dirty = side.Commit, side.Dirty
	return ran
}

// side runs req's tests in dir.
func (r *run) side(ctx context.Context, req requirements.Requirement, dir, which string) requirements.ProofSide {
	env := r.opts.Env
	if env == nil {
		env = os.Environ()
	}
	env = append(env[:len(env):len(env)], "CLOOP_PROOF="+which)
	res := requirements.Check(ctx, []requirements.Requirement{req}, requirements.Options{Dir: dir, Env: env, Now: r.now})
	if len(res) == 0 {
		return requirements.ProofSide{Skipped: "nothing ran"}
	}
	return requirements.ProofSide{Verdict: res[0].Verdict, Summary: res[0].Summary, Tests: res[0].Tests}
}

func allPass(s requirements.ProofSide) bool {
	if len(s.Tests) == 0 {
		return false
	}
	for _, t := range s.Tests {
		if t.Outcome != requirements.OutcomePass {
			return false
		}
	}
	return true
}

// exists reports whether a path relative to the project names a file or a
// directory of the change.
func (r *run) exists(rel string) bool {
	if rel == "" || filepath.IsAbs(rel) {
		return false
	}
	_, err := os.Lstat(filepath.Join(r.dir, filepath.FromSlash(rel)))
	return err == nil
}

// ── the base ────────────────────────────────────────────────────────────────

// baseFor is the commit req's before run uses, and how it was chosen.
func (r *run) baseFor(ctx context.Context, req requirements.Requirement) (string, string, error) {
	if r.opts.Base != "" {
		from := r.opts.BaseFrom
		if from == "" {
			from = requirements.BaseFromGiven
		}
		sha, err := r.resolve(ctx, r.opts.Base)
		if err != nil {
			return requirements.CleanCommit(r.opts.Base), from, err
		}
		return sha, from, nil
	}
	return r.testBase(ctx, req)
}

// resolve names a commit by its full id, or says it is not in the checkout.
func (r *run) resolve(ctx context.Context, rev string) (string, error) {
	if !hexRe.MatchString(rev) {
		return "", fmt.Errorf("%q is not a commit id", truncate(rev, 64))
	}
	sha, err := gitLine(ctx, r.top, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil || sha == "" {
		return "", fmt.Errorf("the base commit %s is not in this checkout (a shallow clone, or history that was "+
			"rewritten since)", truncate(rev, 12))
	}
	return sha, nil
}

var hexRe = regexp.MustCompile(`^[0-9a-fA-F]{4,64}$`)

// testIdentRe picks the names of tests out of a command: Go's TestX and
// FuzzX, pytest's test_x — and pytest's node ids name them after "::".
var testIdentRe = regexp.MustCompile(`\b(Test[A-Z0-9_][A-Za-z0-9_]*|Fuzz[A-Z][A-Za-z0-9_]*|test_[A-Za-z0-9_]+)\b`)

// testBase is the commit before req's test's implementation: see the
// package comment.
func (r *run) testBase(ctx context.Context, req requirements.Requirement) (string, string, error) {
	specs := r.testPathspecs(ctx, req)
	if len(specs) == 0 {
		return "", requirements.BaseFromTest, errors.New("no file of the change could be told for the requirement's test, " +
			"so the commit before its implementation is unknown: name the base")
	}
	// Uncommitted changes to the test: the change is the working tree.
	if out, err := gitOut(ctx, r.top, append([]string{"status", "--porcelain", "-z", "--untracked-files=all", "--"},
		specs...)...); err == nil && strings.TrimSpace(strings.ReplaceAll(out, "\x00", "")) != "" {
		return r.head, requirements.BaseFromWorktree, nil
	}
	var idents []string
	seen := map[string]bool{}
	for _, t := range req.Tests {
		for _, m := range testIdentRe.FindAllString(t.Command, -1) {
			if !seen[m] {
				seen[m] = true
				idents = append(idents, m)
			}
		}
	}
	find := func(extra ...string) (string, []string) {
		args := append([]string{"log", "-1", "--format=%H %P"}, extra...)
		args = append(append(args, "--"), specs...)
		line, err := gitLine(ctx, r.top, args...)
		if err != nil || line == "" {
			return "", nil
		}
		f := strings.Fields(line)
		return f[0], f[1:]
	}
	var commit string
	var parents []string
	if len(idents) > 0 {
		// The names are letters, digits and underscores: as a regular
		// expression they mean themselves, in every regex flavour git uses.
		commit, parents = find("-G", "("+strings.Join(idents, "|")+")")
	}
	if commit == "" {
		commit, parents = find()
	}
	switch {
	case commit == "":
		return "", requirements.BaseFromTest, errors.New("no commit changed the requirement's test files, so the commit " +
			"before its implementation is unknown: name the base")
	case r.onlyTests(ctx, commit):
		// The test was committed on its own. Written first, its
		// implementation came after: the commit holding the test and not yet
		// the code is the base, and the test is there as it is now. Written
		// for what the code already did, nothing after it changed what it
		// tests — and the proof says it cannot tell.
		return commit, requirements.BaseFromTest, nil
	case len(parents) == 0:
		return "", requirements.BaseFromTest, fmt.Errorf("the test was implemented in the repository's first commit, %s, "+
			"so there is no commit before it: name the base", truncate(commit, 12))
	}
	return parents[0], requirements.BaseFromTest, nil
}

// onlyTests reports whether commit changed nothing but test files.
func (r *run) onlyTests(ctx context.Context, commit string) bool {
	out, err := gitOut(ctx, r.top, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", "--root", commit)
	if err != nil {
		return false
	}
	n := 0
	for _, p := range strings.Split(out, "\x00") {
		if p == "" || underCloop(p) {
			continue
		}
		if !requirements.IsTestFile(p) {
			return false
		}
		n++
	}
	return n > 0
}

// maxPathspecs bounds the pathspecs a base search passes git.
const maxPathspecs = 1000

// testPathspecs are the repository paths (relative to its top) of req's test
// as it stands: the files its commands name, the test files in the
// directories they name, and — when they name no path — every test file.
func (r *run) testPathspecs(ctx context.Context, req requirements.Requirement) []string {
	// Untracked files too: a test still being written is the test.
	out, err := gitOut(ctx, r.dir, "ls-files", "-z", "--full-name", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil
	}
	var tracked []requirements.ProofFile
	for _, p := range strings.Split(out, "\x00") {
		if p != "" && !underCloop(p) {
			tracked = append(tracked, requirements.ProofFile{Path: p, Status: requirements.FileModified})
		}
	}
	// TestFilesFor asks of a project-relative tree; tracked holds top-relative
	// paths.
	var rel []requirements.ProofFile
	for _, f := range tracked {
		if pp, ok := projectPath(f.Path, r.rel); ok {
			rel = append(rel, requirements.ProofFile{Path: pp, Status: f.Status})
		}
	}
	var specs []string
	for _, f := range requirements.TestFilesFor(req.Tests, rel, r.exists) {
		specs = append(specs, topPath(f.Path, r.rel))
		if len(specs) == maxPathspecs {
			break
		}
	}
	return specs
}

// ── the change ──────────────────────────────────────────────────────────────

// changesSince is what changed between base and the change — committed,
// staged, in the working tree, and files git does not track yet — cached per
// base. cloop's own .cloop/ is not part of a change.
func (r *run) changesSince(ctx context.Context, base string) *changeSet {
	if cs, ok := r.changes[base]; ok {
		return cs
	}
	cs := &changeSet{}
	r.changes[base] = cs
	out, err := gitOut(ctx, r.top, "diff", "--name-status", "--no-renames", "-z", base, "--")
	if err != nil {
		cs.err = fmt.Errorf("what changed since the base %s could not be read: %w", truncate(base, 12), err)
		return cs
	}
	fields := strings.Split(out, "\x00")
	for i := 0; i+1 < len(fields); i += 2 {
		status, p := fields[i], fields[i+1]
		if p == "" || underCloop(p) {
			continue
		}
		cs.add(requirements.ProofFile{Path: p, Status: normStatus(status)})
	}
	if out, err := gitOut(ctx, r.top, "ls-files", "--others", "--exclude-standard", "-z", "--full-name"); err == nil {
		for _, p := range strings.Split(out, "\x00") {
			if p != "" && !underCloop(p) {
				cs.add(requirements.ProofFile{Path: p, Status: requirements.FileAdded})
			}
		}
	}
	sort.Slice(cs.files, func(i, j int) bool { return cs.files[i].Path < cs.files[j].Path })
	return cs
}

func (cs *changeSet) add(f requirements.ProofFile) {
	if len(cs.files) >= maxChanges {
		cs.truncated = true
		return
	}
	cs.files = append(cs.files, f)
}

// forProject is the change's files relative to the project at rel within the
// repository; files outside it are left out.
func (cs *changeSet) forProject(rel string) []requirements.ProofFile {
	if cs == nil {
		return nil
	}
	var out []requirements.ProofFile
	for _, f := range cs.files {
		if p, ok := projectPath(f.Path, rel); ok {
			out = append(out, requirements.ProofFile{Path: p, Status: f.Status})
		}
	}
	return out
}

// toTop is files, relative to the project at rel, as paths from the
// repository's top.
func (cs *changeSet) toTop(rel string, files []requirements.ProofFile) []requirements.ProofFile {
	out := make([]requirements.ProofFile, 0, len(files))
	for _, f := range files {
		out = append(out, requirements.ProofFile{Path: topPath(f.Path, rel), Status: f.Status})
	}
	return out
}

// holdsMoreThan reports whether the change holds a file outside tests.
func (cs *changeSet) holdsMoreThan(tests []requirements.ProofFile) bool {
	if cs.truncated {
		return true
	}
	in := make(map[string]bool, len(tests))
	for _, t := range tests {
		in[t.Path] = true
	}
	for _, f := range cs.files {
		if !in[f.Path] {
			return true
		}
	}
	return false
}

// addsTests reports whether the change adds a test among files (relative to
// the repository's top): a file it added, or a test declared in a file it
// modified.
func (r *run) addsTests(ctx context.Context, base string, files []requirements.ProofFile) bool {
	var modified []string
	for _, f := range files {
		switch f.Status {
		case requirements.FileAdded:
			return true
		case requirements.FileModified:
			modified = append(modified, f.Path)
		}
	}
	if len(modified) == 0 || base == "" {
		return false
	}
	if len(modified) > maxPathspecs {
		modified = modified[:maxPathspecs]
	}
	diff, err := gitOut(ctx, r.top, append([]string{"diff", "--no-color", "--no-ext-diff", "-U0", base, "--"}, modified...)...)
	return err == nil && requirements.AddsTestDeclaration(diff)
}

func normStatus(s string) string {
	switch {
	case strings.HasPrefix(s, "A"):
		return requirements.FileAdded
	case strings.HasPrefix(s, "D"):
		return requirements.FileDeleted
	}
	return requirements.FileModified
}

// underCloop reports whether a repository path is cloop's own bookkeeping.
func underCloop(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == ".cloop" {
			return true
		}
	}
	return false
}

// projectPath is a repository path relative to the project at rel, or false
// when it lies outside the project.
func projectPath(p, rel string) (string, bool) {
	if rel == "." || rel == "" {
		return p, true
	}
	prefix := filepath.ToSlash(rel) + "/"
	if !strings.HasPrefix(p, prefix) {
		return "", false
	}
	return strings.TrimPrefix(p, prefix), true
}

// topPath is a project-relative path as a path from the repository's top.
func topPath(p, rel string) string {
	if rel == "." || rel == "" {
		return p
	}
	return path.Join(filepath.ToSlash(rel), p)
}

// ── laying the change's test files over the base ────────────────────────────

// maxOverlayBytes bounds what a proof copies into the base's checkout.
const maxOverlayBytes = 256 << 20

// layOver makes each of files in the checkout at dst what it is in the change
// at src: written where the change added or modified it, removed where the
// change removed it. Both trees are opened as roots, so no path — and no link
// in the change — reaches outside them; a link is copied as a link.
func layOver(src, dst string, files []requirements.ProofFile) error {
	if len(files) == 0 {
		return nil
	}
	from, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer from.Close()
	to, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer to.Close()
	var copied int64
	for _, f := range files {
		name := filepath.FromSlash(f.Path)
		if f.Status == requirements.FileDeleted {
			if err := to.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", f.Path, err)
			}
			continue
		}
		fi, err := from.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			// Listed by git, and gone from the tree since: nothing to copy.
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", f.Path, err)
		}
		if d := filepath.Dir(name); d != "." {
			if err := to.MkdirAll(d, 0o755); err != nil {
				return fmt.Errorf("make the directory of %s: %w", f.Path, err)
			}
		}
		if err := to.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("replace %s: %w", f.Path, err)
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			target, err := from.Readlink(name)
			if err != nil {
				return fmt.Errorf("read the link %s: %w", f.Path, err)
			}
			if err := to.Symlink(target, name); err != nil {
				return fmt.Errorf("link %s: %w", f.Path, err)
			}
		case fi.Mode().IsRegular():
			copied += fi.Size()
			if copied > maxOverlayBytes {
				return fmt.Errorf("the change's test files are larger than %d MiB", maxOverlayBytes>>20)
			}
			if err := copyFile(from, to, name, fi.Mode().Perm()); err != nil {
				return fmt.Errorf("copy %s: %w", f.Path, err)
			}
		}
	}
	return nil
}

func copyFile(from, to *os.Root, name string, perm fs.FileMode) error {
	in, err := from.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := to.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm|0o200)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ── git ─────────────────────────────────────────────────────────────────────

// gitOut runs git in dir and returns what it printed on stdout, bounded. It
// takes no lock a git in the same checkout could be waiting on, runs no hook
// and never prompts.
func gitOut(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	full := append([]string{"-c", "core.hooksPath=" + os.DevNull, "-c", "core.fsmonitor=false", "-c", "core.quotePath=false"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	stdout := &capped{max: maxGitOutput}
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = stdout, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return os.ErrProcessDone
	}
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		why := strings.TrimSpace(stderr.String())
		if len(why) > 400 {
			why = why[:400]
		}
		if why != "" {
			return stdout.String(), fmt.Errorf("git %s: %w: %s", args[0], err, why)
		}
		return stdout.String(), fmt.Errorf("git %s: %w", args[0], err)
	}
	if stdout.over {
		return "", fmt.Errorf("git %s printed more than %d MiB", args[0], maxGitOutput>>20)
	}
	return stdout.String(), nil
}

// gitLine is gitOut's first line, trimmed.
func gitLine(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := gitOut(ctx, dir, args...)
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	return strings.TrimSpace(line), err
}

type capped struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	if room := c.max - c.Len(); len(p) > room {
		c.over = true
		p = p[:max(room, 0)]
	}
	c.Buffer.Write(p)
	return n, nil
}

// evalPath is p with its links resolved, where it exists.
func evalPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
