package taskreplay

// compare.go answers "is this the same change?" without touching the repository
// it is asking about.
//
// # The non-destructive contract
//
// A reproduction is a verification tool, and a verification tool that can
// damage the thing it verifies is worse than no tool: an operator who believes
// reproducing is free will run it on a repository someone is working in. So the
// contract is stronger than "tries not to write":
//
//   - Every mutating git command runs with --git-dir pointed at a scratch
//     repository under os.MkdirTemp. There is no code path here that runs a
//     mutating command against the project.
//   - The project is read through objects/info/alternates — the scratch repo
//     borrows its object store instead of copying from it. Alternates are
//     read-only by construction: git never writes to a borrowed store.
//   - The project's refs are never named as a fetch destination, never reset,
//     never checked out. The original commit is resolved by SHA.
//
// Alternates rather than `git fetch <project>`: fetching from a local path
// requires the source to serve an arbitrary SHA, which upload-pack refuses
// unless uploadpack.allowAnySHA1InWant is set — so the fetch would work on the
// maintainer's box and fail on a fresh clone. Borrowing the store needs no
// cooperation from the source and copies nothing.
//
// # What "the same change" means
//
// Tree hashes, not diffs. Two commits with the same tree are the same content
// no matter what their messages, authors, timestamps or parents say — and those
// all differ between two runs by construction, so comparing commit SHAs would
// report DIVERGENT for every reproduction that ever succeeded.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// replayRef is where a reproduction's returned commit is parked in the scratch
// repository. Under refs/reproduce/ rather than refs/heads/ so that nothing
// here can be mistaken for a branch if a scratch directory is ever kept.
const replayRef = "refs/reproduce/replay"

// maxDiffBytes bounds the diff-of-diffs carried in a verdict.
//
// The diff is attached so a reviewer can see *why* a reproduction diverged, and
// it is the agent's own output — the same untrusted, unbounded source Task
// 20220 bounded every other artifact read against. A megabyte is far more than
// anyone reads and far less than anything that hurts the hub.
const maxDiffBytes = 1 << 20

// Comparison is the git-level answer: same tree or not, and what differs.
type Comparison struct {
	// BaseSHA is the commit both changes are measured from.
	BaseSHA string `json:"base_sha,omitempty"`
	// OriginalCommit and ReplayCommit are the two tips.
	OriginalCommit string `json:"original_commit,omitempty"`
	ReplayCommit   string `json:"replay_commit,omitempty"`
	// OriginalTree and ReplayTree are what actually decides IDENTICAL.
	OriginalTree string `json:"original_tree,omitempty"`
	ReplayTree   string `json:"replay_tree,omitempty"`
	// Identical is OriginalTree == ReplayTree.
	Identical bool `json:"identical"`
	// BaseConfirmed reports that the original commit really is a descendant of
	// BaseSHA. False means the base was inferred and could not be corroborated,
	// which caps how strong a verdict may be.
	BaseConfirmed bool `json:"base_confirmed"`
	// OriginalCommits is how many commits the original write-back carried.
	// More than one on an inferred base means the base is wrong.
	OriginalCommits int `json:"original_commits,omitempty"`
	// DiffStat is the --stat summary of the diff-of-diffs, DiffOfDiffs the
	// patch itself, truncated at maxDiffBytes.
	DiffStat    string `json:"diff_stat,omitempty"`
	DiffOfDiffs string `json:"diff_of_diffs,omitempty"`
	// DiffTruncated reports that DiffOfDiffs hit the cap.
	DiffTruncated bool `json:"diff_truncated,omitempty"`
	// FilesDiffering names the paths the two changes disagree on.
	FilesDiffering []string `json:"files_differing,omitempty"`
}

// scratchRepo is a throwaway git repository that can see the project's objects
// but can never write to them.
type scratchRepo struct {
	dir string
}

// newScratchRepo builds the scratch repository and points it at projectDir's
// object store.
//
// The caller must call Close. A leaked scratch directory is only wasted disk —
// it holds no objects of its own beyond the reproduction's bundle — but it
// holds the agent's returned code, so it is removed rather than left in /tmp.
func newScratchRepo(ctx context.Context, projectDir string) (*scratchRepo, error) {
	objects, err := projectObjectDir(ctx, projectDir)
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp("", "cloop-reproduce-*")
	if err != nil {
		return nil, fmt.Errorf("create scratch dir: %w", err)
	}
	s := &scratchRepo{dir: dir}

	if _, err := s.git(ctx, "init", "--bare", "--quiet", dir); err != nil {
		s.Close()
		return nil, fmt.Errorf("init scratch repo: %w", err)
	}
	// Borrow, do not copy. Written after init so the file lands in the
	// directory git just created.
	alternates := filepath.Join(dir, "objects", "info", "alternates")
	if err := os.MkdirAll(filepath.Dir(alternates), 0o755); err != nil {
		s.Close()
		return nil, fmt.Errorf("create alternates dir: %w", err)
	}
	if err := os.WriteFile(alternates, []byte(objects+"\n"), 0o600); err != nil {
		s.Close()
		return nil, fmt.Errorf("write alternates: %w", err)
	}
	return s, nil
}

func (s *scratchRepo) Close() {
	if s != nil && s.dir != "" {
		os.RemoveAll(s.dir)
	}
}

// git runs a git command that is not scoped to the scratch repository. Used
// only for init and for read-only queries against the project.
func (s *scratchRepo) git(ctx context.Context, args ...string) (string, error) {
	return runGit(ctx, "", args...)
}

// in runs a git command inside the scratch repository. Every mutating command
// in this file goes through it.
func (s *scratchRepo) in(ctx context.Context, args ...string) (string, error) {
	return runGit(ctx, s.dir, args...)
}

// runGit executes git, optionally with --git-dir set to gitDir.
//
// The environment is pinned rather than inherited: a reproduction that behaved
// differently because of the operator's ~/.gitconfig would be reporting on the
// operator, not on the agent. GIT_TERMINAL_PROMPT=0 keeps a misconfigured
// remote from blocking on a credential prompt forever.
func runGit(ctx context.Context, gitDir string, args ...string) (string, error) {
	full := args
	if gitDir != "" {
		full = append([]string{"--git-dir", gitDir}, args...)
	}
	cmd := exec.CommandContext(ctx, "git", full...) //nolint:gosec // args are built here, never from user input
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ATTR_NOSYSTEM=1",
		"HOME="+os.TempDir(),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// projectObjectDir resolves the absolute path of projectDir's object store.
//
// --git-common-dir rather than --git-dir so a project checked out as a linked
// worktree resolves to the shared store where the objects actually are.
func projectObjectDir(ctx context.Context, projectDir string) (string, error) {
	common, err := runGit(ctx, "", "-C", projectDir, "rev-parse", "--git-common-dir")
	if err != nil {
		return "", fmt.Errorf("resolve git dir for %s: %w", projectDir, err)
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(projectDir, common)
	}
	objects := filepath.Join(common, "objects")
	if info, statErr := os.Stat(objects); statErr != nil || !info.IsDir() {
		return "", fmt.Errorf("%s is not a git object store", objects)
	}
	return objects, nil
}

// ResolveBase fills in p.BaseSHA when the original run did not record one.
//
// It must run before the reproduction is dispatched, not at comparison time:
// the sandbox is provisioned by checking out the base, so a base that does not
// exist yet is a run that cannot start.
//
// Three sources, in descending order of how much a verdict computed against
// them is worth — see BaseSource. Whichever is used, a warning is attached
// unless the base was recorded, so a verdict is never read without knowing
// where its base came from.
//
// Reading the repository here is strictly read-only: two rev-parse calls and a
// merge-base, none of which write.
func ResolveBase(ctx context.Context, projectDir string, p *Provenance) error {
	if p == nil {
		return errors.New("resolve base: nil provenance")
	}
	if strings.TrimSpace(p.OriginalCommit) == "" {
		return ErrNoRecordedCommit
	}
	if strings.TrimSpace(p.BaseSHA) != "" {
		return nil // recorded by the original run; nothing to infer
	}

	git := func(args ...string) (string, error) {
		return runGit(ctx, "", append([]string{"-C", projectDir}, args...)...)
	}
	if _, err := git("rev-parse", "--verify", "--quiet", p.OriginalCommit+"^{commit}"); err != nil {
		return fmt.Errorf("the original commit %s is not in this repository: %w",
			shortSHA(p.OriginalCommit), err)
	}

	// The fork point of the write-back branch from mainline. Correct for a
	// write-back of any length, which is why it is tried first.
	if forkPoint, err := git("merge-base", "HEAD", p.OriginalCommit); err == nil &&
		forkPoint != "" && forkPoint != p.OriginalCommit {
		p.BaseSHA, p.BaseSource = forkPoint, BaseForkPoint
		p.warn("the commit this task was based on was not recorded; it was recovered as the point the " +
			"write-back branch forked from the current HEAD")
		return nil
	}

	// Last resort. Correct only for a single-commit write-back, and nothing
	// available here can confirm it was one — so the verdict is capped.
	parent, err := git("rev-parse", "--verify", "--quiet", p.OriginalCommit+"^")
	if err != nil {
		return fmt.Errorf("cannot determine what commit %s was based on: %w",
			shortSHA(p.OriginalCommit), err)
	}
	p.BaseSHA, p.BaseSource = parent, BaseFirstParent
	p.warn("no write_back event records the commit this task was based on, and its branch point could " +
		"not be recovered — the parent of the returned commit is used instead, which is only correct " +
		"for a single-commit write-back, so no verdict stronger than inconclusive will be issued")
	return nil
}

// CompareBundle diffs a reproduction's returned commit against the original.
//
// bundlePath is the git bundle the executor wrote back; branch is the ref
// inside it. Nothing in projectDir is modified — see the contract at the top of
// this file.
func CompareBundle(ctx context.Context, projectDir, bundlePath, branch string, p *Provenance) (*Comparison, error) {
	if p == nil {
		return nil, errors.New("compare: nil provenance")
	}
	if strings.TrimSpace(p.OriginalCommit) == "" {
		return nil, ErrNoRecordedCommit
	}

	s, err := newScratchRepo(ctx, projectDir)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	c := &Comparison{
		OriginalCommit: p.OriginalCommit,
		BaseSHA:        p.BaseSHA,
	}

	// The original side. Resolved by SHA out of the borrowed object store, so
	// it does not matter whether the write-back branch still exists or has
	// moved on since — which it usually has.
	c.OriginalTree, err = s.in(ctx, "rev-parse", "--verify", "--quiet", p.OriginalCommit+"^{tree}")
	if err != nil {
		return nil, fmt.Errorf("the original commit %s is not in this repository: %w",
			shortSHA(p.OriginalCommit), err)
	}
	if c.BaseSHA == "" {
		return nil, fmt.Errorf("cannot compare against %s: no base commit was resolved "+
			"(call ResolveBase before running the reproduction)", shortSHA(p.OriginalCommit))
	}

	// Corroborate the base rather than assume it. Comparing against the wrong
	// base is the one way this harness can quietly measure the wrong thing, so
	// the range is counted and the source is consulted: a first-parent guess
	// yields a count of exactly 1 by construction and therefore corroborates
	// nothing, which is why BaseSource.Trusted() is part of the test.
	if count, cerr := s.in(ctx, "rev-list", "--count", c.BaseSHA+".."+p.OriginalCommit); cerr == nil {
		c.OriginalCommits = atoiSafe(count)
		c.BaseConfirmed = c.OriginalCommits >= 1 && p.BaseSource.Trusted()
	}

	// The replay side, fetched out of the bundle into the scratch repo only.
	if _, err := s.in(ctx, "fetch", "--no-tags", "--quiet", bundlePath,
		"+"+refFor(branch)+":"+replayRef); err != nil {
		return nil, fmt.Errorf("read the reproduction's bundle: %w", err)
	}
	c.ReplayCommit, err = s.in(ctx, "rev-parse", "--verify", "--quiet", replayRef)
	if err != nil {
		return nil, fmt.Errorf("the bundle carries no commit at %s: %w", branch, err)
	}
	c.ReplayTree, err = s.in(ctx, "rev-parse", "--verify", "--quiet", replayRef+"^{tree}")
	if err != nil {
		return nil, fmt.Errorf("resolve the reproduction's tree: %w", err)
	}

	c.Identical = c.OriginalTree == c.ReplayTree
	if c.Identical {
		return c, nil
	}

	// The diff-of-diffs. Both changes start from the same base, so diffing the
	// two tips *is* the difference between the two changes — no three-way
	// reconstruction needed, and none of the noise a diff of two patches
	// would carry from context lines and hunk headers.
	if stat, serr := s.in(ctx, "diff", "--stat", c.OriginalTree, c.ReplayTree); serr == nil {
		c.DiffStat = stat
	}
	if names, nerr := s.in(ctx, "diff", "--name-only", c.OriginalTree, c.ReplayTree); nerr == nil && names != "" {
		c.FilesDiffering = strings.Split(names, "\n")
	}
	if patch, perr := s.in(ctx, "diff", "--no-color", c.OriginalTree, c.ReplayTree); perr == nil {
		if len(patch) > maxDiffBytes {
			c.DiffOfDiffs = patch[:maxDiffBytes]
			c.DiffTruncated = true
		} else {
			c.DiffOfDiffs = patch
		}
	}
	return c, nil
}

// refFor normalizes a branch name to a fully-qualified ref.
func refFor(branch string) string {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return "HEAD"
	}
	if strings.HasPrefix(branch, "refs/") {
		return branch
	}
	return "refs/heads/" + branch
}

// shortSHA abbreviates a SHA for an error message.
func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// atoiSafe parses a small non-negative integer, returning 0 for anything else.
func atoiSafe(s string) int {
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
		if n > 1<<20 {
			return 1 << 20
		}
	}
	return n
}
