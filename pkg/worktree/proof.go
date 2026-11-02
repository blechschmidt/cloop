package worktree

// proof.go: the throwaway checkouts of a requirement proof (Task 20464).
//
// A proof runs a requirement's tests on the code before a change, and the
// project's main checkout is not where that code is — nor may it be made to
// be: checking out another commit there, stashing, resetting, would put a
// person's or an agent's uncommitted work at risk. A proof checks the base
// out somewhere else instead: a detached linked worktree beside the parallel
// tasks' ones, in <repository>/.cloop/worktrees/proof-<random>, which leaves
// the main checkout's files, index and HEAD exactly as they were. Git records
// the worktree in the repository's own bookkeeping (.git/worktrees), and
// removing it takes that record with it.
//
// The worktree is locked while the proof runs, with a reason naming the
// process and a deadline: the hub's sweep (gc.go) leaves a locked worktree
// alone, so it never removes a checkout a test is running in, however long
// the test is quiet. The proof removes the worktree on every way out it has —
// done, failed, cancelled, panicked. A process killed outright has no way
// out, so each proof first sweeps what such a process left (SweepProofs): a
// proof worktree whose process is gone, or whose deadline has passed.
//
// Its git is the project's own, run where the proof runs, in the project's
// sandbox — but without the repository's hooks or fsmonitor: a post-checkout
// hook has no business running for a checkout nobody will work in.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// proofDirPrefix starts the name of every proof worktree.
	proofDirPrefix = "proof-"
	// proofLockReason starts the lock reason of a proof worktree.
	proofLockReason = "cloop: requirement proof"
	// proofUnlockedGrace is how old an unlocked proof worktree must be before
	// a sweep takes it for a leftover: the moment between adding a worktree
	// and locking it.
	proofUnlockedGrace = 10 * time.Minute
	// proofGitTimeout bounds one git command of a proof's bookkeeping. A
	// checkout of a large repository is the slowest of them.
	proofGitTimeout = 10 * time.Minute
)

// proofLockRe reads a proof worktree's lock reason back.
var proofLockRe = regexp.MustCompile(`^` + regexp.QuoteMeta(proofLockReason) + ` \(pid (\d+) on (\S+), until (\S+)\)$`)

// ProofCheckout is a throwaway, detached checkout of one commit for a
// requirement proof. Remove it when done; see the file comment.
type ProofCheckout struct {
	// Path is the checkout's directory.
	Path string
	// Commit is the commit it holds.
	Commit string
	// repo is the repository's main worktree, where its bookkeeping is done.
	repo string
}

// proofGit runs the proof's git in dir: the project's own environment, but no
// hooks, no fsmonitor and never a prompt for credentials.
func proofGit(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, proofGitTimeout)
	defer cancel()
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	full := append([]string{"-c", "core.hooksPath=" + os.DevNull, "-c", "core.fsmonitor=false"}, args...)
	return execGit(ctx, dir, env, full...)
}

// proofRoot is where dir's repository keeps its proof worktrees: the
// .cloop/worktrees of its main worktree — so a proof of a parallel task's
// worktree, or of a feature, lands beside the project's — or "" when the
// repository has no main worktree to hold them.
func proofRoot(ctx context.Context, dir string) (repo, root string, err error) {
	out, err := proofGit(ctx, dir, "rev-parse", "--git-common-dir")
	if err != nil {
		return "", "", fmt.Errorf("worktree: %s is not a git checkout: %w", dir, err)
	}
	common := strings.TrimSpace(out)
	if common == "" {
		return "", "", fmt.Errorf("worktree: git reported no repository for %s", dir)
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(dir, common)
	}
	common = filepath.Clean(common)
	if filepath.Base(common) != ".git" {
		return dir, "", nil
	}
	repo = filepath.Dir(common)
	return repo, filepath.Join(repo, ".cloop", "worktrees"), nil
}

// AddProof checks commit out, detached, into a new proof worktree of the
// repository dir belongs to, locked until deadline (see the file comment).
// dir may be the main checkout or any linked worktree of it; none of them is
// changed. The caller removes the checkout.
func AddProof(ctx context.Context, dir, commit string, deadline time.Time) (*ProofCheckout, error) {
	if !commitNameRe.MatchString(commit) {
		return nil, fmt.Errorf("worktree: %q is not a commit name", commit)
	}
	repo, root, err := proofRoot(ctx, dir)
	if err != nil {
		return nil, err
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, fmt.Errorf("worktree: name a proof checkout: %w", err)
	}
	name := proofDirPrefix + hex.EncodeToString(suffix[:])
	var path string
	if root == "" {
		// No main worktree to put it beside: a temporary directory, which the
		// repository records like any other linked worktree.
		tmp, err := os.MkdirTemp("", "cloop-"+proofDirPrefix+"*")
		if err != nil {
			return nil, fmt.Errorf("worktree: make a proof checkout: %w", err)
		}
		path = filepath.Join(tmp, "tree")
	} else {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return nil, fmt.Errorf("worktree: make %s: %w", root, err)
		}
		path = filepath.Join(root, name)
	}
	p := &ProofCheckout{Path: path, Commit: commit, repo: repo}
	if _, err := proofGit(ctx, repo, "worktree", "add", "--detach", path, commit+"^{commit}"); err != nil {
		_ = p.Remove()
		return nil, fmt.Errorf("worktree: check %s out for the proof: %w", shortName(commit), err)
	}
	host, _ := os.Hostname()
	if host == "" || strings.ContainsAny(host, " \t\n()") {
		host = "unknown"
	}
	reason := fmt.Sprintf("%s (pid %d on %s, until %s)", proofLockReason, os.Getpid(), host,
		deadline.UTC().Format(time.RFC3339))
	if _, err := proofGit(ctx, repo, "worktree", "lock", "--reason", reason, path); err != nil {
		_ = p.Remove()
		return nil, fmt.Errorf("worktree: lock the proof checkout: %w", err)
	}
	return p, nil
}

// commitNameRe is what AddProof accepts as a commit: hex, as a proof's base
// always is — never an option, a range or a ref a repository could define.
var commitNameRe = regexp.MustCompile(`^[0-9a-fA-F]{4,64}$`)

func shortName(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// Remove takes the checkout down — the directory and the repository's record
// of it — and reports whether it is really gone. It needs no context: it runs
// on the way out of a proof that was cancelled, and must not be cut short by
// the cancellation.
func (p *ProofCheckout) Remove() error {
	if p == nil || p.Path == "" {
		return nil
	}
	return removeProof(context.Background(), p.repo, p.Path)
}

// removeProof unlocks, removes and prunes one proof worktree, and checks the
// directory is gone. A temporary parent AddProof made is removed with it.
func removeProof(ctx context.Context, repo, path string) error {
	if repo != "" {
		_, _ = proofGit(ctx, repo, "worktree", "unlock", path)
		_, _ = proofGit(ctx, repo, "worktree", "remove", "--force", path)
	}
	if err := os.RemoveAll(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("worktree: remove the proof checkout %s: %w", path, err)
	}
	if parent := filepath.Dir(path); strings.HasPrefix(filepath.Base(parent), "cloop-"+proofDirPrefix) {
		_ = os.RemoveAll(parent)
	}
	if repo != "" {
		_, _ = proofGit(ctx, repo, "worktree", "prune")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("worktree: the proof checkout %s is still present after its removal", path)
	}
	return nil
}

// SweepProofs removes the proof worktrees of dir's repository that no proof
// is using any more: one whose process is gone (on this host), whose deadline
// has passed, or that was never locked and is older than a few minutes. It
// returns the paths it removed. A proof sweeps before it starts, so what a
// killed proof left behind is gone by the next one.
func SweepProofs(ctx context.Context, dir string, now time.Time) ([]string, error) {
	repo, root, err := proofRoot(ctx, dir)
	if err != nil || root == "" {
		return nil, err
	}
	out, err := proofGit(ctx, repo, "worktree", "list", "--porcelain")
	if err != nil {
		return nil, err
	}
	regs, err := gitWorktreeList(func(string, ...string) (string, error) { return out, nil }, repo)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	var removed []string
	var errs []error
	seen := map[string]bool{}
	for _, r := range regs {
		if !underDir(root, r.path) || !strings.HasPrefix(filepath.Base(r.path), proofDirPrefix) {
			continue
		}
		seen[resolvePath(r.path)] = true
		if !staleProof(r, host, now) {
			continue
		}
		if err := removeProof(ctx, repo, r.path); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, r.path)
	}
	// A directory git no longer records — its registration pruned, or a
	// crash between the directory and the record — is a leftover too, once
	// it is old enough not to be an add in flight.
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		path := filepath.Join(root, e.Name())
		if !e.IsDir() || !strings.HasPrefix(e.Name(), proofDirPrefix) || seen[resolvePath(path)] {
			continue
		}
		if fi, err := os.Stat(path); err != nil || now.Sub(fi.ModTime()) < proofUnlockedGrace {
			continue
		}
		if err := removeProof(ctx, repo, path); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, path)
	}
	return removed, errors.Join(errs...)
}

// staleProof decides whether a registered proof worktree is a leftover.
func staleProof(r registration, host string, now time.Time) bool {
	if !r.locked {
		fi, err := os.Stat(r.path)
		return err != nil || now.Sub(fi.ModTime()) >= proofUnlockedGrace
	}
	m := proofLockRe.FindStringSubmatch(r.lockReason)
	if m == nil {
		// Locked by somebody else, for a reason of their own: theirs to
		// release.
		return false
	}
	if until, err := time.Parse(time.RFC3339, m[3]); err == nil && now.After(until) {
		return true
	}
	pid, err := strconv.Atoi(m[1])
	if err != nil || pid <= 0 {
		return false
	}
	return m[2] == host && !processAlive(pid)
}

// processAlive reports whether a process with this id exists here. A process
// this one may not signal exists too.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
