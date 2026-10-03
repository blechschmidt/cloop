package gitprovision

// branch.go builds a workload's tree from a branch the control plane shipped
// with the Spec (Task 20367) — how a feature, a branch of a repository on the
// hub, gets into a sandbox. See executor/branchbundle.go for the contract.
//
// # Always fresh
//
// A git workspace is reused between dispatches because the checkout on the
// machine may hold the only copy of someone's work. A shipped branch inverts
// that: the authoritative copy of the feature is the branch on the hub, and
// whatever a previous dispatch left in this directory has either been written
// back already or was discarded on purpose (a harness that failed). Reusing it
// would put that leftover — an uncommitted file, a stale branch, a .git that a
// previous sandbox had write access to — under the next run, so the directory is
// emptied and the tree rebuilt from the bundle every time.
//
// # On the branch, attached
//
// The checkout ends on the shipped branch itself rather than detached at its
// head. A harness is told to commit to its feature's branch, and a write-back
// is measured as head..branch; a detached HEAD would leave the harness's
// commits on no branch at all.
//
// # The feature's own state stays out of its commits
//
// The hub keeps a feature's control directory, .cloop/, out of the feature's
// history: it excludes it in the repository's info/exclude and marks any
// .cloop/ files the repository tracks skip-worktree (pkg/featureops). The tree
// built here does the same, because the seed lands in .cloop/ a moment later
// and a write-back that swept the feature's state database into a commit would
// carry it onto the feature's branch — and from there into its pull request.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// baseRef pins the commit a shipped range builds on while its bundle is
// fetched. Some git versions verify a bundle's prerequisites by walking from the
// repository's refs, and a commit held only by FETCH_HEAD is then "missing".
const baseRef = "refs/cloop/provision-base"

// CommitIdentity is who commits made in a provisioned feature tree are
// attributed to when the harness sets no identity of its own. The write-back
// commit uses the same one (pkg/executor/gitwriteback): a commit attributed to
// whichever account a sandbox happens to run as describes the machine, not the
// change.
const (
	CommitIdentityName  = "cloop"
	CommitIdentityEmail = "cloop@localhost"
)

// provisionBranch builds r.Dir from the branch r.Workspace.Branch describes.
func provisionBranch(ctx context.Context, r Request) error {
	emit := r.Emit
	if emit == nil {
		emit = func(string) {}
	}
	w := r.Workspace
	b := w.Branch
	dir := r.Dir
	cred := r.Credential
	hostName := r.host()
	secrets := cred.Secrets()
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", executor.ErrWorkspaceUnavailable,
			executor.RedactSecrets(fmt.Sprintf(format, args...), secrets))
	}

	if err := w.Validate(); err != nil {
		return fail("%v", err)
	}
	if _, err := exec.LookPath("git"); err != nil {
		return fail("%s has no git on its PATH, so it cannot build the tree for %s; install git there",
			hostName, b.Branch)
	}
	if w.Kind == executor.WorkspaceGit && !cred.Empty() && !cred.ExpiresAt.IsZero() && !cred.ExpiresAt.After(time.Now()) {
		return fail("the leased credential expired at %s, before the fetch could start "+
			"(this machine's clock reads %s; check for clock skew if that looks wrong)",
			cred.ExpiresAt.UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	}
	if b.Bytes > 0 {
		if err := b.VerifyFile(r.BranchBundleFile); err != nil {
			return fail("%v", err)
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail("cannot create the workspace directory %s on %s: %v", dir, hostName, err)
	}
	cleared, err := emptyDir(dir)
	if err != nil {
		return fail("cannot clear the previous tree in %s on %s: %v", dir, hostName, err)
	}
	if cleared {
		emit(fmt.Sprintf("workspace: cleared the previous tree in %s; a shipped branch is rebuilt "+
			"from the control plane's copy on every dispatch\n", dir))
	}
	emit(fmt.Sprintf("workspace: provisioning %s into %s on %s\n", w.Describe(), dir, hostName))

	// Anything that fails from here leaves a half-built tree; empty it again
	// so the next attempt does not mistake it for something.
	ok := false
	defer func() {
		if !ok {
			if _, err := emptyDir(dir); err != nil {
				emit(fmt.Sprintf("workspace: could not remove the partial tree: %v\n", err))
			}
		}
	}()

	step := func(name string, authenticated bool, args ...string) error {
		return runStep(ctx, dir, w, cred, executor.GitStep{
			Name:          name,
			Argv:          append([]string{"git", "-C", dir}, args...),
			Authenticated: authenticated,
		}, hostName, secrets, emit)
	}

	// init names its initial branch explicitly: git otherwise prints a
	// paragraph of advice about choosing one into the run's log, and the
	// branch is replaced by the shipped one a moment later anyway.
	if err := runStep(ctx, dir, w, cred, executor.GitStep{Name: "init", Argv: []string{
		"git", "-c", "init.defaultBranch=cloop-provision", "init", "--quiet", "--", dir,
	}}, hostName, secrets, emit); err != nil {
		return fail("%v", err)
	}

	branchRef := "refs/heads/" + b.Branch
	switch w.Kind {
	case executor.WorkspaceGit:
		repo := strings.TrimSpace(w.Repo)
		if err := step("remote", false, "remote", "add", "origin", "--", repo); err != nil {
			return fail("%v", err)
		}
		fetch := []string{"fetch", "--no-tags", "--prune"}
		if w.Depth > 0 {
			fetch = append(fetch, "--depth", strconv.Itoa(w.Depth))
		}
		fetch = append(fetch, "--", "origin", strings.TrimSpace(w.Ref))
		if err := step("fetch", true, fetch...); err != nil {
			return fail("%v", err)
		}
		if err := enforceSize(dir, w, hostName); err != nil {
			return fail("%v", err)
		}
		if b.Bytes == 0 {
			// The feature has no commits of its own yet: its branch is its
			// base, which the fetch just brought.
			if err := step("branch", false, "update-ref", branchRef, strings.TrimSpace(w.Ref)); err != nil {
				return fail("%v", err)
			}
			break
		}
		if err := step("pin", false, "update-ref", baseRef, strings.TrimSpace(w.Ref)); err != nil {
			return fail("%v", err)
		}
		if err := step("unbundle", false, "fetch", "--no-tags", "--",
			r.BranchBundleFile, "+"+branchRef+":"+branchRef); err != nil {
			return fail("%v", err)
		}
		_ = step("unpin", false, "update-ref", "-d", baseRef)

	case executor.WorkspaceBundle:
		if len(b.Shallow) > 0 {
			// The slice's lower edge, recorded before the fetch: git checks
			// that what it receives is connected, and a commit whose parents
			// were left out on purpose is only "connected" once the repository
			// knows they were.
			if err := writeShallow(dir, b.Shallow); err != nil {
				return fail("cannot record the shipped branch's shallow boundary on %s: %v", hostName, err)
			}
		}
		if err := step("unbundle", false, "fetch", "--no-tags", "--",
			r.BranchBundleFile, "+"+branchRef+":"+branchRef); err != nil {
			return fail("%v", err)
		}
	default:
		return fail("workspace kind %q cannot carry a shipped branch", w.Kind)
	}

	if err := step("checkout", false, "checkout", "--quiet", b.Branch, "--"); err != nil {
		return fail("%v", err)
	}
	head, err := gitOutput(ctx, dir, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return fail("cannot read the checked-out commit on %s: %v", hostName, err)
	}
	if head != b.Head {
		// The bundle's branch is not at the commit the control plane said it
		// shipped. Refused rather than run: the hub measures the returned
		// work against Head, and a tree that started anywhere else would
		// return a range the hub cannot place.
		return fail("the shipped branch %s is at %s, but the control plane sent it at %s",
			b.Branch, executor.ShortSHA(head), executor.ShortSHA(b.Head))
	}

	// The identity the harness commits under, unless it brings its own. In a
	// container there is no global git identity at all, and a harness told to
	// commit to its branch would otherwise fail with "please tell me who you
	// are" and leave everything to the write-back.
	if err := gitLocal(ctx, dir, "config", "--local", "user.name", CommitIdentityName); err != nil {
		return fail("%v", err)
	}
	if err := gitLocal(ctx, dir, "config", "--local", "user.email", CommitIdentityEmail); err != nil {
		return fail("%v", err)
	}
	if err := HideControlDir(ctx, dir); err != nil {
		return fail("%v", err)
	}
	if err := enforceSize(dir, w, hostName); err != nil {
		return fail("%v", err)
	}

	ok = true
	emit(fmt.Sprintf("workspace: ready at %s on %s\n", dir, b.Branch))
	return nil
}

// HideControlDir keeps the project's control directory out of the tree's
// commits: .cloop/ is excluded for untracked files, and files the repository
// does track under it are marked skip-worktree, so the seed written over them
// and the state database written beside them never show up as changes.
//
// It is the same treatment the hub gives a feature's own worktree
// (pkg/featureops), applied to the copy a sandbox works in.
func HideControlDir(ctx context.Context, dir string) error {
	gitDir := filepath.Join(dir, ".git")
	info := filepath.Join(gitDir, "info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %v", info, err)
	}
	f, err := os.OpenFile(filepath.Join(info, "exclude"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("cannot open the repository's exclude file: %v", err)
	}
	_, werr := f.WriteString("\n# cloop: the project's control state is never committed\n/.cloop/\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		return fmt.Errorf("cannot write the repository's exclude file: %v", errors.Join(werr, cerr))
	}
	out, err := gitOutput(ctx, dir, "ls-files", "-z", "--", ".cloop")
	if err != nil {
		return fmt.Errorf("cannot list tracked files under .cloop: %v", err)
	}
	var paths []string
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	return gitLocal(ctx, dir, append([]string{"update-index", "--skip-worktree", "--"}, paths...)...)
}

// emptyDir removes everything inside dir and reports whether there was
// anything. A symbolic link among the entries is removed as a link: RemoveAll
// does not follow it.
func emptyDir(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return true, err
		}
	}
	return len(entries) > 0, nil
}

// writeShallow records commits as the repository's shallow boundary.
func writeShallow(dir string, shas []string) error {
	var b strings.Builder
	for _, s := range shas {
		if err := executor.ValidateCommitSHA(s); err != nil {
			return err
		}
		b.WriteString(s)
		b.WriteByte('\n')
	}
	return os.WriteFile(filepath.Join(dir, ".git", "shallow"), []byte(b.String()), 0o644)
}

// gitOutput runs a local git command in dir and returns its trimmed stdout.
func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = executor.GitBaseEnv()
	cmd.Dir = dir
	BoundChild(cmd)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, Collapse(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}
