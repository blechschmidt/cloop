// Package writeback lands the work product of an isolated executor in the
// project's repository on the hub.
//
// It is the receiving half of pkg/executor/gitwriteback, and the trust boundary
// between them is total. Everything it is handed — a branch name, a commit SHA,
// a bundle — was produced inside a sandbox running model-authored code. This
// package's job is to get that work into pkg/mergequeue, which is where local
// parallel work already goes, without letting a sandbox use the trip to write
// somewhere it was never given.
//
// # Quarantine before branch
//
// Objects are fetched into refs/cloop/writeback/<branch>, never straight into
// refs/heads/<branch>, and the ref is only promoted after the commit range has
// passed inspection. The ordering is the point: a ref under refs/heads is a
// branch — it shows up in `git branch`, it can be checked out by a person or by
// the merge queue, and a checkout is what makes a .git/hooks entry execute. A
// ref that has not been vetted must never be reachable by any of that, so it
// spends its whole life somewhere `git checkout` will not find it, and a
// rejection deletes it.
//
// # Two layers of content checks, and where the first one is absent
//
// Every fetch here runs with fetch.fsckObjects and core.protectNTFS/protectHFS
// set, so git refuses malformed objects and — the part that matters — trees
// containing a path named .git in any of the spellings a case-insensitive
// filesystem would fold back to it.
//
// That layer is real on the push path and *absent on the bundle path*. Git runs
// its fsck rules from index-pack, which only executes when objects arrive as a
// pack over a transport; a fetch from a local bundle file unpacks loose objects
// and skips them entirely. Verified against git 2.43: a bundle carrying a tree
// entry named .git fetches cleanly with both fsck settings on.
//
// So executor.InspectWriteBack is not a second opinion, it is the only opinion
// on the transport that needs one most — the one that requires no credential.
// It is also the layer that knows things fsck does not care about: that a
// symlink pointing outside the project root turns every later write through it
// into a write anywhere on the control plane, and that a submodule entry names
// a URL rather than content. tests/security/writeback_bundle_test.go asserts
// the refusals over both transports for exactly this reason — the two paths do
// not have the same defences, so neither may be assumed to cover the other.
//
// # Both transports are inspected
//
// A pushed branch goes through exactly the same vetting as a bundle. A sandbox
// holding a push credential can push a hook as easily as it can bundle one, and
// securing only the path that needs no credential would be securing the wrong
// one.
package writeback

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
	"github.com/blechschmidt/cloop/pkg/mergequeue"
)

// QuarantineRefPrefix is where an unvetted write-back lives between arriving
// and being accepted. Deliberately outside refs/heads: see the package comment.
const QuarantineRefPrefix = "refs/cloop/writeback/"

// DefaultTimeout bounds each git invocation when a Request names none.
const DefaultTimeout = 2 * time.Minute

// Merger is the subset of pkg/mergequeue.Queue this package needs.
//
// It is an interface so a test can prove the handoff happens without starting a
// queue goroutine, and so the caller keeps ownership of the real queue's
// lifecycle — a package that lands one branch has no business deciding when the
// project's merge queue starts and stops.
type Merger interface {
	Submit(req mergequeue.Request) *mergequeue.Result
}

// Request is one write-back to land.
type Request struct {
	// RepoDir is the project's git repository on the hub.
	RepoDir string
	// Reported is what the executor said the sandbox produced.
	Reported executor.WriteBackResult
	// Bundle is the git bundle received for mode bundle. Ignored for push.
	Bundle []byte
	// Remote is the name of the git remote the branch was pushed to, for mode
	// push. Empty means "origin".
	Remote string
	// TaskID and TaskTitle attribute the merge commit. They are the merge
	// queue's, not git's — nothing here trusts them.
	TaskID    int
	TaskTitle string
	// Queue receives the vetted branch. Nil means "land the branch and stop",
	// which is what a caller wants when the operator merges by hand.
	Queue Merger
	// MergeTimeout bounds the wait for the queue's verdict. 0 means ten
	// minutes: a merge may sit behind other tasks' merges.
	MergeTimeout time.Duration
	// Timeout bounds each git invocation. 0 means DefaultTimeout.
	Timeout time.Duration
	// Emit receives progress. May be nil.
	Emit func(string)
}

// Result reports what landed.
type Result struct {
	// Branch and CommitSHA are the vetted ref, once it has been promoted.
	Branch    string
	CommitSHA string
	// Commits and FilesChanged describe the range that was accepted.
	Commits      int
	FilesChanged int
	// Merged and MergeSHA report the merge queue's outcome. Merged is false
	// when no queue was supplied or when the merge conflicted; MergeErr
	// carries the reason in the latter case.
	Merged   bool
	MergeSHA string
	MergeErr error
	// Skipped reports that there was nothing to land.
	Skipped bool
}

// Apply lands a reported write-back in RepoDir and hands the branch to the
// merge queue.
//
// A rejection is a *executor.WriteBackRejection wrapping
// executor.ErrWriteBackRejected, and it leaves nothing behind: the quarantine
// ref is deleted, no branch is created, and the merge queue is never told about
// it. A merge conflict is *not* an error — the branch landed, the merge did not,
// and Result.MergeErr says so — because losing the branch would throw away the
// work the conflict is about.
func Apply(ctx context.Context, req Request) (Result, error) {
	emit := req.Emit
	if emit == nil {
		emit = func(string) {}
	}
	var res Result

	rep := req.Reported
	if rep.Err != "" {
		return res, fmt.Errorf("%w: the executor reported: %s", executor.ErrWriteBackUnavailable, rep.Err)
	}
	if rep.Skipped || !rep.Delivered() {
		res.Skipped = true
		return res, nil
	}

	repo := strings.TrimSpace(req.RepoDir)
	if repo == "" || !filepath.IsAbs(repo) {
		return res, fmt.Errorf("%w: project directory %q is not an absolute path",
			executor.ErrWriteBackUnavailable, req.RepoDir)
	}

	// Validate the sandbox's claims about itself before any of them reaches a
	// git command line. Branch and both SHAs become argv elements and refspec
	// components a moment from now.
	branch := strings.TrimSpace(rep.Branch)
	reject := func(reason string) (Result, error) {
		return res, &executor.WriteBackRejection{
			Branch: branch, CommitSHA: rep.CommitSHA, Reason: reason,
		}
	}
	if err := executor.ValidateWriteBackBranch(branch); err != nil {
		return reject("the reported branch is not acceptable: " + err.Error())
	}
	if err := executor.ValidateCommitSHA(rep.CommitSHA); err != nil {
		return reject("the reported commit is not acceptable: " + err.Error())
	}
	if err := executor.ValidateCommitSHA(rep.BaseSHA); err != nil {
		return reject("the reported base commit is not acceptable: " + err.Error())
	}
	if rep.BaseSHA == rep.CommitSHA {
		return reject("the reported commit is the base it was built on, so nothing was produced")
	}

	g := &gitRunner{dir: repo, timeout: req.Timeout}
	quarantine := QuarantineRefPrefix + branch

	// The base has to be an object this repository already has. It is the
	// anchor for everything below — the inspected range, the ancestry check,
	// the bundle's own prerequisite — so a base the hub has never seen means
	// the sandbox is describing history that did not come from here.
	if _, err := g.run(ctx, "cat-file", "-e", rep.BaseSHA+"^{commit}"); err != nil {
		return reject(fmt.Sprintf("the base commit %s is not in this repository, so the reported "+
			"work is not built on anything the hub knows", executor.ShortSHA(rep.BaseSHA)))
	}

	// Whatever happens below, the unvetted ref does not survive this function.
	// It is deleted on rejection, on error, and on success alike — on success
	// because by then the vetted ref exists under refs/heads and a second name
	// for the same commit is just something to go stale.
	defer func() {
		_, _ = g.run(context.WithoutCancel(ctx), "update-ref", "-d", quarantine)
	}()

	// --- land the objects in quarantine -----------------------------------
	switch rep.Mode {
	case executor.WriteBackBundle:
		if err := fetchFromBundle(ctx, g, req, rep, branch, quarantine, emit); err != nil {
			return res, err
		}
	case executor.WriteBackPush:
		remote := strings.TrimSpace(req.Remote)
		if remote == "" {
			remote = "origin"
		}
		if err := validateRemoteName(remote); err != nil {
			return res, fmt.Errorf("%w: %v", executor.ErrWriteBackUnavailable, err)
		}
		// "--" before the remote so a name that somehow reached here starting
		// with a dash is an unknown remote rather than an unknown flag.
		if out, err := g.untrustedFetch(ctx, "--no-tags", "--", remote,
			"+refs/heads/"+branch+":"+quarantine); err != nil {
			if isFsckRefusal(out) {
				// Git refused the content, not the transfer. That is a
				// rejection and has to carry the rejection sentinel: a caller
				// that retries on ErrWriteBackUnavailable — which is
				// documented as "nothing about the task's code is implicated"
				// — would otherwise retry a hostile write-back on a loop.
				return res, &executor.WriteBackRejection{
					Branch: branch, CommitSHA: rep.CommitSHA,
					Reason: "git refused the pushed objects: " + collapse(out),
				}
			}
			return res, fmt.Errorf("%w: the executor reported pushing %s to %s, but the hub "+
				"cannot fetch it back: %v", executor.ErrWriteBackUnavailable, branch, remote, err)
		}
		emit("writeback: fetched " + branch + " from " + remote + "\n")
	default:
		return res, fmt.Errorf("%w: reported mode %q has no way to reach the hub",
			executor.ErrWriteBackUnavailable, rep.Mode)
	}

	// --- verify it is what the executor said ------------------------------
	landed, err := g.run(ctx, "rev-parse", "--verify", "--end-of-options", quarantine+"^{commit}")
	if err != nil {
		return res, fmt.Errorf("%w: nothing landed under %s: %v",
			executor.ErrWriteBackUnavailable, quarantine, err)
	}
	landed = strings.TrimSpace(landed)
	if landed != rep.CommitSHA {
		// The whole point of reporting a SHA is that this comparison can be
		// made. A mismatch means the ref moved between the sandbox reporting
		// and the hub fetching — someone else pushed over it, or the report is
		// not describing the objects that arrived.
		return reject(fmt.Sprintf("the branch is at %s but the executor reported %s; "+
			"the ref moved between being written and being fetched",
			executor.ShortSHA(landed), executor.ShortSHA(rep.CommitSHA)))
	}

	// Ancestry, so the range base..commit is the whole of what arrived. Without
	// it a bundle could carry a commit that is not descended from the checkout
	// at all — rewritten history whose diff against base looks small while the
	// merge replaces files nobody inspected.
	if _, err := g.run(ctx, "merge-base", "--is-ancestor", rep.BaseSHA, rep.CommitSHA); err != nil {
		return reject(fmt.Sprintf("commit %s is not a descendant of the base %s it claims to "+
			"build on", executor.ShortSHA(rep.CommitSHA), executor.ShortSHA(rep.BaseSHA)))
	}

	count, err := g.run(ctx, "rev-list", "--count", "--end-of-options",
		rep.BaseSHA+".."+rep.CommitSHA)
	if err != nil {
		return res, fmt.Errorf("%w: cannot count the returned commits: %v",
			executor.ErrWriteBackUnavailable, err)
	}
	commits, convErr := strconv.Atoi(strings.TrimSpace(count))
	if convErr != nil || commits <= 0 {
		return reject("the returned range contains no commits")
	}
	if commits > executor.MaxWriteBackCommits {
		return reject(fmt.Sprintf("the returned range contains %d commits, at most %d are allowed",
			commits, executor.MaxWriteBackCommits))
	}
	res.Commits = commits

	// --- inspect every changed path ---------------------------------------
	entries, err := changedEntries(ctx, g, rep.BaseSHA, rep.CommitSHA)
	if err != nil {
		return res, fmt.Errorf("%w: cannot read the returned changes: %v",
			executor.ErrWriteBackUnavailable, err)
	}
	if err := executor.InspectWriteBack(branch, rep.CommitSHA, entries); err != nil {
		return res, err
	}
	res.FilesChanged = len(entries)

	// --- promote ----------------------------------------------------------
	//
	// Only now does a name under refs/heads exist. -m records why in the
	// reflog, which is the trail an operator follows when a branch they did not
	// create shows up in `git branch`.
	if _, err := g.run(ctx, "update-ref", "-m",
		fmt.Sprintf("cloop: write-back from an isolated executor (task %d)", req.TaskID),
		"refs/heads/"+branch, rep.CommitSHA); err != nil {
		return res, fmt.Errorf("%w: cannot create branch %s: %v",
			executor.ErrWriteBackUnavailable, branch, err)
	}
	res.Branch = branch
	res.CommitSHA = rep.CommitSHA
	emit(fmt.Sprintf("writeback: accepted %s at %s (%d commit(s), %d file(s))\n",
		branch, executor.ShortSHA(rep.CommitSHA), commits, len(entries)))

	// --- merge ------------------------------------------------------------
	if req.Queue == nil {
		return res, nil
	}
	mergeTimeout := req.MergeTimeout
	if mergeTimeout <= 0 {
		mergeTimeout = 10 * time.Minute
	}
	handle := req.Queue.Submit(mergequeue.Request{
		Branch: branch, TaskID: req.TaskID, Title: req.TaskTitle,
	})
	if handle == nil {
		res.MergeErr = errors.New("the merge queue accepted no job")
		return res, nil
	}
	select {
	case <-handle.Done:
		if handle.Err != nil {
			// Not an error return. The branch is on disk with the work on it;
			// a conflict is for a human (or the queue's AI resolver on a later
			// attempt) to settle, and failing here would suggest the work was
			// lost when it is sitting in `git branch`.
			res.MergeErr = handle.Err
			emit("writeback: " + branch + " landed but did not merge: " + handle.Err.Error() + "\n")
			return res, nil
		}
		res.Merged = true
		res.MergeSHA = handle.CommitSHA
		emit("writeback: merged " + branch + " as " + executor.ShortSHA(handle.CommitSHA) + "\n")
	case <-time.After(mergeTimeout):
		res.MergeErr = fmt.Errorf("the merge queue did not report a verdict for %s within %s",
			branch, mergeTimeout)
	case <-ctx.Done():
		res.MergeErr = ctx.Err()
	}
	return res, nil
}

// fetchFromBundle writes the received bytes to a temporary file, checks them
// against what the executor reported, and fetches the branch into quarantine.
func fetchFromBundle(ctx context.Context, g *gitRunner, req Request,
	rep executor.WriteBackResult, branch, quarantine string, emit func(string)) error {

	if len(req.Bundle) == 0 {
		return fmt.Errorf("%w: mode bundle reported %d bytes but none arrived",
			executor.ErrWriteBackUnavailable, rep.BundleBytes)
	}
	// The cap is re-checked here even though the transport enforced one while
	// receiving. This function is reachable from a caller that assembled the
	// bytes some other way, and a size limit that only exists in the reader is
	// a limit on one code path rather than on the data.
	if int64(len(req.Bundle)) > executor.MaxWriteBackBundleBytes {
		return fmt.Errorf("%w: the bundle is %d bytes, over the hard limit of %d",
			executor.ErrWriteBackRejected, len(req.Bundle), executor.MaxWriteBackBundleBytes)
	}
	if rep.BundleBytes != 0 && rep.BundleBytes != int64(len(req.Bundle)) {
		return fmt.Errorf("%w: the executor reported a %d-byte bundle and %d bytes arrived",
			executor.ErrWriteBackUnavailable, rep.BundleBytes, len(req.Bundle))
	}
	if want := strings.TrimSpace(rep.BundleSHA256); want != "" {
		if got := gitwriteback.SHA256(req.Bundle); got != want {
			return fmt.Errorf("%w: the bundle's digest is %s but the executor reported %s; "+
				"the stream was truncated or altered in transit",
				executor.ErrWriteBackUnavailable, got[:16], want[:min(16, len(want))])
		}
	}

	// The file lives outside the repository so a crash cannot leave an
	// untracked blob in the operator's working tree, and it is created 0600
	// because a work product is the project's, not the machine's.
	f, err := os.CreateTemp("", "cloop-writeback-*.bundle")
	if err != nil {
		return fmt.Errorf("%w: cannot stage the bundle: %v", executor.ErrWriteBackUnavailable, err)
	}
	path := f.Name()
	defer os.Remove(path)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("%w: cannot secure the staged bundle: %v", executor.ErrWriteBackUnavailable, err)
	}
	if _, err := f.Write(req.Bundle); err != nil {
		_ = f.Close()
		return fmt.Errorf("%w: cannot write the staged bundle: %v", executor.ErrWriteBackUnavailable, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%w: cannot flush the staged bundle: %v", executor.ErrWriteBackUnavailable, err)
	}

	// `git bundle verify` is not a formality. It confirms the file is a bundle
	// at all — before git is asked to fetch from it — and it confirms this
	// repository holds every prerequisite the bundle names, which is what makes
	// the range base..commit the complete description of what arrived.
	if out, err := g.run(ctx, "bundle", "verify", "--", path); err != nil {
		return fmt.Errorf("%w: the returned bundle is not usable here: %v: %s",
			executor.ErrWriteBackRejected, err, collapse(out))
	}
	if _, err := g.untrustedFetch(ctx, "--no-tags", "--", path,
		"+refs/heads/"+branch+":"+quarantine); err != nil {
		return fmt.Errorf("%w: cannot fetch %s out of the returned bundle: %v",
			executor.ErrWriteBackUnavailable, branch, err)
	}
	emit(fmt.Sprintf("writeback: unpacked a %d-byte bundle for %s\n", len(req.Bundle), branch))
	return nil
}

// changedEntries lists every path the range touched, with the mode it ends up
// at and — for a symlink — where it points.
//
// --no-renames is deliberate. A rename record carries two paths in one entry
// and a parser that mishandles the second one silently stops checking it; as
// add+delete pairs every path is its own record and every record is checked.
// -z is equally deliberate: a filename containing a newline would otherwise
// split into two records, and the half that mattered would be the one that
// looked like a path nobody asked about.
func changedEntries(ctx context.Context, g *gitRunner, base, head string) ([]executor.BundleEntry, error) {
	out, err := g.run(ctx, "diff", "--raw", "-z", "--no-renames", "--no-color",
		"--end-of-options", base, head)
	if err != nil {
		return nil, err
	}
	fields := strings.Split(out, "\x00")
	var entries []executor.BundleEntry
	for i := 0; i < len(fields); i++ {
		meta := fields[i]
		if !strings.HasPrefix(meta, ":") {
			continue
		}
		// ":<srcmode> <dstmode> <srcsha> <dstsha> <status>" then a NUL then the
		// path. Anything that does not parse is refused rather than skipped: an
		// unparsed record is an unchecked path.
		parts := strings.Fields(meta[1:])
		if len(parts) < 5 {
			return nil, fmt.Errorf("unparsable diff record %q", meta)
		}
		i++
		if i >= len(fields) {
			return nil, fmt.Errorf("diff record %q has no path", meta)
		}
		e := executor.BundleEntry{Path: fields[i], Mode: parts[1]}
		if e.Mode == executor.ModeSymlink {
			// The blob *is* the target. Reading it is the only way to know
			// where the link goes, and it has to be read from the object store
			// rather than from disk because nothing has been checked out.
			target, err := g.run(ctx, "cat-file", "blob", parts[3])
			if err != nil {
				// A symlink whose target cannot be read is refused, not
				// ignored: "we could not check it" and "it is fine" must not
				// produce the same outcome on this boundary.
				return nil, fmt.Errorf("cannot read the symlink target for %q: %v", e.Path, err)
			}
			e.LinkTarget = strings.TrimRight(target, "\n")
		}
		entries = append(entries, e)
		if len(entries) > executor.MaxWriteBackFiles {
			// Stop early rather than buffering an unbounded diff.
			return entries, nil
		}
	}
	return entries, nil
}

// gitRunner runs the hub's git commands against the project repository.
type gitRunner struct {
	dir     string
	timeout time.Duration
}

func (g *gitRunner) run(ctx context.Context, args ...string) (string, error) {
	timeout := g.timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	argv := append([]string{"-C", g.dir}, args...)
	cmd := exec.CommandContext(ctx, "git", argv...)
	// A closed environment for the same reason gitprovision uses one: a
	// credential helper or an insteadOf rewrite in whoever-owns-this-machine's
	// ~/.gitconfig must not get a say in what a fetch from an untrusted source
	// contacts. The hub's own remote credentials, when it needs them, come from
	// the repository's config, which GIT_CONFIG_NOSYSTEM does not suppress.
	cmd.Env = append(executor.GitBaseEnv(), gitprovision.TransportEnv()...)
	cmd.Dir = g.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return string(out), fmt.Errorf("git %s: %w", args[0], ctxErr)
		}
		return string(out), fmt.Errorf("git %s: %v: %s", args[0], err, collapse(string(out)))
	}
	return string(out), nil
}

// untrustedFetch runs a fetch whose source is under a sandbox's control.
//
// The -c settings are git's own defence. fsckObjects makes git validate every
// object it unpacks instead of trusting the sender, and the rules it turns on
// include hasDotgit — a tree entry named .git in any of the spellings a
// case-insensitive or NTFS filesystem folds back to it; protectHFS and
// protectNTFS extend that to the Unicode and 8.3 forms.
//
// They are set on every fetch and they only fire on some. Git runs fsck from
// index-pack, which handles objects arriving as a pack; a fetch from a local
// bundle unpacks loose objects and never reaches it. So this hardens the push
// path and does nothing for the bundle path, where InspectWriteBack stands
// alone. Setting them anyway is still right — the push path is real, and the
// cost is two -c flags — but nothing here may be relied on as the reason a
// hostile tree cannot land.
func (g *gitRunner) untrustedFetch(ctx context.Context, args ...string) (string, error) {
	pre := []string{
		"-c", "fetch.fsckObjects=true",
		"-c", "transfer.fsckObjects=true",
		"-c", "core.protectHFS=true",
		"-c", "core.protectNTFS=true",
		// A fetch has no business running anything. There is no hook on this
		// path today, and pinning it to nothing means there is none tomorrow
		// either.
		"-c", "core.hooksPath=/dev/null",
		"fetch",
	}
	return g.run(ctx, append(pre, args...)...)
}

// validateRemoteName keeps a remote name from being read as a flag or a URL.
//
// The name arrives from the hub's own configuration rather than from a sandbox,
// but it is concatenated into an argv next to attacker-chosen refspecs, and a
// value like "--upload-pack=sh" would turn a fetch into command execution.
func validateRemoteName(name string) error {
	if name == "" {
		return errors.New("the git remote name is empty")
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("git remote name %q starts with a dash", name)
	}
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("git remote name %q contains %q; use [A-Za-z0-9-_.]", name, r)
		}
	}
	return nil
}

// isFsckRefusal reports whether a failed fetch failed because git objected to
// the *content* rather than to the transfer.
//
// Matching on output text is unpleasant and it is what git offers: fsck
// failures come back as an ordinary non-zero exit, with the rule name in the
// message. The consequence of a false negative is a rejection reported as an
// outage, which is why the markers are the specific ones git emits for this
// class and not a general "error" — and why a miss is survivable: the fetch
// failed either way, no ref was created, and InspectWriteBack would have
// refused the same tree a moment later. This decides which sentinel a caller
// sees, not whether the work lands.
func isFsckRefusal(out string) bool {
	low := strings.ToLower(out)
	for _, marker := range []string{
		"fsck error", "fsck_error", "object corrupt or missing",
		"hasdotgit", "hasdotname", "gitmodulespath", "did not send all necessary objects",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

// collapse folds command output onto one line for an error message, keeping the
// tail — git puts the actual reason last.
func collapse(s string) string {
	joined := strings.Join(strings.Fields(s), " ")
	const max = 400
	if len(joined) > max {
		return "…" + joined[len(joined)-max:]
	}
	return joined
}
