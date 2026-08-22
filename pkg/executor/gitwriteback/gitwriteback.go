// Package gitwriteback turns the files a harness changed into something the hub
// can merge.
//
// # Why this is its own package
//
// It is gitprovision's mirror image, and it exists for the same reason. Two
// callers have to do exactly the same thing at the other end of a run:
//
//   - the remote agent (pkg/executor/agent), which recovers the work product
//     from an edge device after the harness there exits;
//   - `cloop workspace writeback` (cmd), which the Kubernetes driver runs
//     inside the Pod, because a Pod's /workspace is an emptyDir that stops
//     existing the moment the Pod does.
//
// Two implementations would be two chances to reintroduce the failure this
// subsystem exists to remove — a run that streams a plausible transcript and
// delivers nothing — and the drifted copy would be silent, because a write-back
// that produced no commit looks exactly like a task that changed no files. So
// there is one engine, here, and both callers are thin.
//
// The package depends on nothing but the standard library and pkg/executor, so
// the CLI does not import the agent's transport machinery to make a commit and
// the agent does not import the CLI.
//
// # What it produces
//
// Always a branch at a commit, never a diff. The hub already has a merge story
// for parallel work — a per-task branch merged back through pkg/mergequeue,
// with AI conflict resolution — and remote work has to arrive in a shape that
// story accepts. A patch would have to be turned back into a branch on the hub,
// with a new SHA, and the "hub verifies the branch is at the SHA the sandbox
// reported" check would have nothing left to verify.
//
// # The credential
//
// Push mode reuses the grant that cloned the tree, delivered exactly the way
// gitprovision delivers it: in the environment of the single git child that
// contacts the remote, as a URL-scoped http.extraHeader. It is never written to
// disk, never placed in an argv, and never added to the harness's environment.
// Everything this package emits or returns goes through executor.RedactSecrets
// first, because git quotes headers back in error messages.
//
// # Ordering
//
// Nothing is committed until the harness has exited. The engine runs after the
// workload, against a tree nobody is writing to, so a commit can never capture
// a half-written file — and a failed task writes back nothing at all, which is
// the caller's decision to make and this package's to enforce (see
// Request.OnlyOnSuccess).
package gitwriteback

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
)

// DefaultTimeout bounds the whole write-back when a Request names none.
//
// A write-back runs after the harness has already produced its result, so a
// hang here loses work that exists rather than work that does not — which makes
// a ceiling more important than a generous one, not less. Five minutes covers a
// push of a large tree over a slow link.
const DefaultTimeout = 5 * time.Minute

// commitIdentity is the author and committer recorded on a write-back commit.
//
// It is fixed rather than taken from the machine's git config, and it is
// delivered through the environment rather than written to a config file. A
// commit authored by "root@some-edge-device" is misleading — the change was
// authored by a model running under cloop's supervision — and reading the
// machine's identity would make the same task produce different commits on
// different executors.
const (
	commitAuthorName  = "cloop"
	commitAuthorEmail = "cloop@localhost"
)

// Request is one write-back.
type Request struct {
	// Dir is the absolute path of the provisioned tree. It must be a git
	// repository — gitprovision left one there — and the caller is responsible
	// for having confined it.
	Dir string
	// Workspace is the workspace the tree was provisioned from. It supplies
	// the push remote: a push goes to Workspace.Repo and nowhere else.
	Workspace executor.Workspace
	// WriteBack says which mode to run and what to name the branch.
	WriteBack executor.WriteBack
	// Credential authenticates the push. The zero value means an
	// unauthenticated push, which only works for a repository that accepts
	// anonymous writes — that is, essentially never, so a push mode request
	// without one fails with a legible error rather than a git prompt.
	Credential executor.GitCredential
	// BaseSHA is the commit the workspace was provisioned at. Empty means
	// "read it from the repository", which is right for the ordinary case;
	// a caller that recorded it before the harness ran should pass it, because
	// a harness that moved HEAD itself would otherwise shrink the range and
	// silently drop its own earlier commits.
	BaseSHA string
	// BundlePath is where a bundle-mode write-back writes its file. Empty
	// means a temporary file this package creates and the caller must remove;
	// Result.BundlePath always names the file that exists.
	BundlePath string
	// ExitCode is the harness's exit status, and OnlyOnSuccess decides whether
	// it gates the write-back. See OnlyOnSuccess.
	ExitCode int
	// OnlyOnSuccess refuses to write back the work of a failed task.
	//
	// It defaults to off in the zero Request because a caller has to opt into
	// a policy this consequential, and every caller in the tree opts in. The
	// reasoning: a harness that exited non-zero left the tree in whatever state
	// it was in when it died — a half-applied refactor, a partially generated
	// file — and merging that is worse than losing it, because the loss is
	// visible and the half-change is not.
	OnlyOnSuccess bool
	// Emit receives progress as it completes, already redacted. May be nil.
	Emit func(string)
	// Host is how the machine names itself in a diagnostic. Empty falls back
	// to gitprovision.HostLabel("machine").
	Host string
	// Timeout bounds the whole write-back. 0 means DefaultTimeout.
	Timeout time.Duration
}

// Result is what the write-back produced. It is the same shape the driver
// reports upward, so a caller does not have to translate.
type Result struct {
	executor.WriteBackResult
	// BundlePath names the bundle file on disk, for mode bundle. The caller
	// owns the file and is responsible for removing it.
	BundlePath string
}

// Produce commits the harness's changes to a per-task branch and delivers them.
//
// Every error it returns wraps executor.ErrWriteBackUnavailable and has already
// been through executor.RedactSecrets, so a caller may log it, ship it across
// the remote boundary, or print it to a terminal without further filtering.
//
// A clean tree is not an error. It returns a Result with Skipped set, because
// "the agent changed nothing" is a real outcome that an operator needs to be
// able to tell apart from "the write-back broke".
func Produce(ctx context.Context, r Request) (Result, error) {
	emit := r.Emit
	if emit == nil {
		emit = func(string) {}
	}
	hostName := r.host()
	secrets := r.Credential.Secrets()

	res := Result{WriteBackResult: executor.WriteBackResult{
		Mode:   r.WriteBack.Mode,
		Branch: strings.TrimSpace(r.WriteBack.Branch),
	}}

	// Every exit through fail is redacted and wrapped, so redaction is a
	// property of the exit path rather than of each author remembering.
	fail := func(format string, args ...any) (Result, error) {
		msg := executor.RedactSecrets(fmt.Sprintf(format, args...), secrets)
		res.Err = msg
		return res, fmt.Errorf("%w: %s", executor.ErrWriteBackUnavailable, msg)
	}
	skip := func(reason string) (Result, error) {
		res.Skipped = true
		res.SkipReason = reason
		res.Mode = executor.WriteBackNone
		emit("writeback: " + reason + "\n")
		return res, nil
	}

	if !r.WriteBack.Enabled() {
		return skip("no write-back was requested")
	}
	if err := r.WriteBack.Validate(); err != nil {
		return fail("%v", err)
	}
	if r.OnlyOnSuccess && r.ExitCode != 0 {
		// The refusal is reported, not swallowed: an operator looking at a
		// failed task must be able to see that its edits were deliberately
		// discarded rather than lost.
		return skip(fmt.Sprintf("the harness exited %d, so its partial changes were not written back",
			r.ExitCode))
	}
	dir := strings.TrimSpace(r.Dir)
	if dir == "" || !filepath.IsAbs(dir) {
		return fail("write-back directory %q is not an absolute path", r.Dir)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return fail("%s is not a git repository on %s, so there is nothing to commit: %v",
			dir, hostName, err)
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	g := &gitRunner{dir: dir, host: hostName, secrets: secrets, emit: emit}

	// --- the base --------------------------------------------------------
	base := strings.TrimSpace(r.BaseSHA)
	if base == "" {
		out, err := g.run(ctx, "base", false, r, "rev-parse", "HEAD")
		if err != nil {
			return fail("%v", err)
		}
		base = strings.TrimSpace(out)
	}
	if err := executor.ValidateCommitSHA(base); err != nil {
		return fail("the workspace's base commit is unusable: %v", err)
	}
	res.BaseSHA = base

	// --- anything to do? -------------------------------------------------
	//
	// --porcelain covers tracked modifications and untracked files alike, and
	// it is checked before the branch is created so a clean run leaves no ref
	// behind for someone to wonder about later.
	status, err := g.run(ctx, "status", false, r, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return fail("%v", err)
	}
	if strings.TrimSpace(status) == "" {
		return skip("the harness changed no files")
	}

	// --- commit ----------------------------------------------------------
	branch := res.Branch
	// -B rather than -b: a retried task reuses its branch name, and failing
	// because the previous attempt's ref is still there would make a retry
	// depend on cleanup that may never have run. The branch is namespaced
	// under cloop/ (ValidateWriteBackBranch enforces it) so forcing it can
	// only ever clobber cloop's own ref.
	if _, err := g.run(ctx, "branch", false, r, "checkout", "-B", branch, "--"); err != nil {
		return fail("%v", err)
	}
	if _, err := g.run(ctx, "add", false, r, "add", "--all", "--", "."); err != nil {
		return fail("%v", err)
	}
	// Re-check after staging. `git add -A` can stage nothing when the only
	// dirty paths were ignored ones, and committing then fails with a message
	// about an empty commit that reads like a bug rather than like "nothing
	// changed".
	staged, err := g.run(ctx, "staged", false, r, "diff", "--cached", "--name-only")
	if err != nil {
		return fail("%v", err)
	}
	staged = strings.TrimSpace(staged)
	if staged == "" {
		return skip("the harness changed only ignored files")
	}
	res.FilesChanged = len(strings.Split(staged, "\n"))
	if res.FilesChanged > executor.MaxWriteBackFiles {
		return fail("the harness changed %d files, over the write-back limit of %d",
			res.FilesChanged, executor.MaxWriteBackFiles)
	}

	msg := strings.TrimSpace(r.WriteBack.Message)
	if msg == "" {
		msg = "cloop: work produced by an isolated executor"
	}
	if _, err := g.run(ctx, "commit", false, r, "commit", "--no-verify", "--no-gpg-sign", "-m", msg); err != nil {
		return fail("%v", err)
	}
	head, err := g.run(ctx, "head", false, r, "rev-parse", "HEAD")
	if err != nil {
		return fail("%v", err)
	}
	head = strings.TrimSpace(head)
	if err := executor.ValidateCommitSHA(head); err != nil {
		return fail("the commit this write-back produced is unusable: %v", err)
	}
	res.CommitSHA = head
	res.Commits = 1
	if head == base {
		// Unreachable given the staged check above, but a write-back that
		// reports the base as its tip would make the hub merge a no-op and
		// report success for work that was never delivered.
		return skip("the commit did not advance the branch")
	}
	emit(fmt.Sprintf("writeback: committed %d file(s) to %s at %s\n",
		res.FilesChanged, branch, executor.ShortSHA(head)))

	// --- deliver ---------------------------------------------------------
	switch r.WriteBack.Mode {
	case executor.WriteBackPush:
		if r.Credential.Empty() {
			return fail("mode push needs a credential for %s and none was leased; "+
				"grant one, or use mode bundle for a sandbox with no egress", r.Workspace.Host())
		}
		if !r.Credential.ExpiresAt.IsZero() && !time.Now().Before(r.Credential.ExpiresAt) {
			// Better to say so than to let git report a 401 the operator would
			// read as a permissions problem.
			return fail("the leased credential for %s expired at %s, before the push could run",
				r.Workspace.Host(), r.Credential.ExpiresAt.UTC().Format(time.RFC3339))
		}
		// The refspec is fully qualified on both sides. A bare "branch" would
		// let the remote's push.default and any refspec configured on the
		// origin decide what actually moved.
		refspec := "refs/heads/" + branch + ":refs/heads/" + branch
		// --force-with-lease is deliberately absent: the ref is cloop-owned and
		// namespaced, a retry legitimately replaces its predecessor, and a
		// lease check would need a fetch the sandbox may not be able to make.
		if _, err := g.run(ctx, "push", true, r, "push", "--porcelain", "--force",
			"--", r.Workspace.Repo, refspec); err != nil {
			return fail("%v", err)
		}
		res.Pushed = true
		emit("writeback: pushed " + branch + " to " + quoteRepo(r.Workspace.Repo) + "\n")
		return res, nil

	case executor.WriteBackBundle:
		path := strings.TrimSpace(r.BundlePath)
		if path == "" {
			f, err := os.CreateTemp("", "cloop-writeback-*.bundle")
			if err != nil {
				return fail("cannot create a bundle file on %s: %v", hostName, err)
			}
			path = f.Name()
			_ = f.Close()
		}
		res.BundlePath = path
		// The range, not the branch. `git bundle create out branch` would pack
		// the branch's entire reachable history — on a full clone that is the
		// whole repository, which is both enormous and a way to smuggle
		// rewritten history past an inspection that only looks at new commits.
		if _, err := g.run(ctx, "bundle", false, r, "bundle", "create", path,
			base+".."+branch); err != nil {
			_ = os.Remove(path)
			res.BundlePath = ""
			return fail("%v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return fail("the bundle written on %s cannot be read back: %v", hostName, err)
		}
		limit := r.WriteBack.BundleCap()
		if info.Size() > limit {
			_ = os.Remove(path)
			res.BundlePath = ""
			return fail("the bundle is %d bytes, over this workload's limit of %d; "+
				"the task changed %d files — commit less, or raise the limit",
				info.Size(), limit, res.FilesChanged)
		}
		digest, err := fileSHA256(path)
		if err != nil {
			return fail("cannot digest the bundle on %s: %v", hostName, err)
		}
		res.BundleBytes = info.Size()
		res.BundleSHA256 = digest
		emit(fmt.Sprintf("writeback: bundled %s (%d bytes)\n", branch, info.Size()))
		return res, nil
	}
	return fail("write-back mode %q has no delivery path", r.WriteBack.Mode)
}

// host returns the label used in this request's diagnostics.
func (r Request) host() string {
	if s := strings.TrimSpace(r.Host); s != "" {
		return s
	}
	return gitprovision.HostLabel("machine")
}

// gitRunner runs the write-back's git children with a closed environment.
type gitRunner struct {
	dir     string
	host    string
	secrets []string
	emit    func(string)
}

// run executes one git command in the repository.
//
// authenticated marks the single step that contacts the remote, and is the only
// one whose environment carries the credential — the same rule gitprovision
// applies, for the same reason: a token in the environment of `git commit` is a
// token in the environment of a process that had no need of it.
func (g *gitRunner) run(ctx context.Context, name string, authenticated bool, r Request,
	args ...string) (string, error) {

	env := append(executor.GitBaseEnv(), gitprovision.TransportEnv()...)
	env = append(env,
		"GIT_AUTHOR_NAME="+commitAuthorName,
		"GIT_AUTHOR_EMAIL="+commitAuthorEmail,
		"GIT_COMMITTER_NAME="+commitAuthorName,
		"GIT_COMMITTER_EMAIL="+commitAuthorEmail,
	)
	if authenticated {
		extra, err := executor.GitCredentialEnv(r.Workspace, r.Credential)
		if err != nil {
			return "", err
		}
		env = append(env, extra...)
	}

	argv := append([]string{"-C", g.dir}, args...)
	cmd := exec.CommandContext(ctx, "git", argv...)
	cmd.Env = env
	cmd.Dir = g.dir

	out, err := cmd.CombinedOutput()
	text := executor.RedactSecrets(string(out), g.secrets)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return text, fmt.Errorf("git %s was cancelled on %s: %w", name, g.host, ctxErr)
		}
		return text, fmt.Errorf("git %s failed on %s: %v: %s", name, g.host, err,
			gitprovision.Collapse(text))
	}
	return text, nil
}

// fileSHA256 digests a file without reading it all into memory.
//
// The digest is what lets the hub detect a bundle that was truncated by a
// dropped connection or altered in transit before it hands the file to git.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256 digests a byte slice the same way fileSHA256 digests a file, so the
// hub can compare what it received against what the sandbox reported.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// quoteRepo renders a repository URL for a message without inviting a shell
// reading of it.
func quoteRepo(url string) string { return strconv.Quote(strings.TrimSpace(url)) }
