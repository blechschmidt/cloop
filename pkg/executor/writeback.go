// writeback.go is the other half of workspace.go: how the work a harness
// produced gets *out* of the place it ran.
//
// Until this file existed there was no answer. RunResult carried stdout and
// stderr and nothing else, and both isolated drivers discard their filesystem
// when the workload ends — a Kubernetes Pod's /workspace is an emptyDir that
// dies with the Pod, a remote agent's tree stays on a device the hub cannot
// read. So a task that ran on a non-local executor produced a transcript
// describing edits that no longer exist anywhere. The executor architecture
// could dispatch work but could not deliver it.
//
// Both delivery paths here are git-native, for one reason: the hub already has
// a merge story for parallel work (pkg/worktree plus pkg/mergequeue, Task
// 20136), and remote work has to arrive in a shape that story accepts. That
// means a *branch at a commit*, not a diff — so both paths converge on
// "sandbox commits to a per-task branch" and differ only in how the objects
// travel:
//
//   - push: the sandbox pushes the branch to the project's own origin with the
//     same brokered credential that cloned it, and the hub fetches and verifies
//     the branch is at the SHA the sandbox reported. Preferred, because the
//     objects never pass through the control plane at all.
//   - bundle: the sandbox writes `git bundle` of base..branch and streams it
//     back over the remote protocol. For sandboxes with no egress, where a push
//     is not merely disabled but impossible.
//
// # The trust boundary
//
// The sandbox runs model-authored code. Everything it sends back is hostile
// input, and that is true of *both* paths — a compromised sandbox holding a
// push credential can push a branch containing .git/hooks/post-checkout just as
// easily as it can put one in a bundle. So the vetting in this file gates the
// commit range on the way to the merge queue, not the transport: Inspect* is
// called for pushed branches and applied bundles alike. Treating only the
// bundle as dangerous would secure the path that requires no credential and
// leave open the one that does.
//
// The rules are deliberately about *paths and modes*, which is all a git tree
// can express, and they reuse the containment checks in mount.go rather than
// restating them — a second implementation of "does this path escape" is a
// second thing to get wrong, and the one that drifts is always the copy.
package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// WriteBackMode selects how a workload's result travels back to the hub.
type WriteBackMode string

const (
	// WriteBackNone is the zero value: the workload produces no durable file
	// changes, or the executor shares the hub's filesystem and the changes are
	// already there. Nothing is committed and nothing is sent.
	WriteBackNone WriteBackMode = ""
	// WriteBackPush: the sandbox commits to Branch and pushes it to the
	// workspace's own origin. Requires network egress and a credential grant
	// whose scope covers the repository.
	WriteBackPush WriteBackMode = "push"
	// WriteBackBundle: the sandbox commits to Branch and produces a git bundle
	// of the new commits, which travels back over the executor's own transport.
	// Requires a driver that can carry bytes back — today, the remote agent.
	WriteBackBundle WriteBackMode = "bundle"
)

// Valid reports whether m is one of the known modes.
func (m WriteBackMode) Valid() bool {
	switch m {
	case WriteBackNone, WriteBackPush, WriteBackBundle:
		return true
	}
	return false
}

// Bounds. Every one of these is a ceiling on attacker-influenced input: the
// sandbox chooses the tree, the branch name and the bundle contents.
const (
	// MaxWriteBackBranchLen bounds the branch name. It becomes a refspec, an
	// argv element, a label and an audit field.
	MaxWriteBackBranchLen = 200
	// MaxWriteBackMessageLen bounds the commit message. Generous for a subject
	// plus a body; short enough that it cannot be used as a smuggling channel
	// for a megabyte of anything.
	MaxWriteBackMessageLen = 4096
	// DefaultWriteBackBundleBytes is the cap applied when a spec names none.
	// A task's worth of source changes is kilobytes; 32 MiB accommodates a
	// vendored dependency or a checked-in fixture and still cannot exhaust a
	// hub's memory, which is what a stream with no ceiling eventually does.
	DefaultWriteBackBundleBytes int64 = 32 << 20
	// MaxWriteBackBundleBytes is the hard ceiling a spec may not raise past.
	// A spec is derived from repo-committed configuration, so the limit a
	// project can ask for has to be bounded by one it cannot edit.
	MaxWriteBackBundleBytes int64 = 128 << 20
	// MaxWriteBackCommits bounds how many commits one write-back may carry.
	// The inspection walks every changed path in every commit; an unbounded
	// range is an unbounded walk on the control plane.
	MaxWriteBackCommits = 1000
	// MaxWriteBackFiles bounds how many changed paths one write-back may
	// carry, for the same reason.
	MaxWriteBackFiles = 20000
	// MaxWriteBackPathLen bounds a single path inside the commit range.
	MaxWriteBackPathLen = 4096
)

// WriteBack describes how a workload's file changes should be returned.
//
// Like Workspace it names a grant and never carries material, and for the same
// reasons: a Spec is persisted by pkg/executorstore, echoed into audit rows and
// marshalled across the remote boundary. There is deliberately no field here
// that could hold a token.
//
// There is also deliberately no Remote field. A push goes to the workspace's
// own Repo and nowhere else — a sandbox that could name its own push target
// would be able to exfiltrate the tree to a host of its choosing using a
// credential the operator scoped to one repository.
type WriteBack struct {
	// Mode selects the strategy.
	Mode WriteBackMode `json:"mode,omitempty"`
	// Branch is the per-task branch the sandbox commits to, e.g.
	// "cloop/task-42-add-retry". It must not already carry a refs/ prefix.
	Branch string `json:"branch,omitempty"`
	// Message is the commit subject. Empty gets a generated one.
	Message string `json:"message,omitempty"`
	// MaxBundleBytes caps the bundle for Mode bundle. 0 means
	// DefaultWriteBackBundleBytes; values above MaxWriteBackBundleBytes are a
	// validation error rather than being silently clamped, because a project
	// that asked for 1 GiB and got 128 MiB would fail later, further away.
	MaxBundleBytes int64 `json:"max_bundle_bytes,omitempty"`
}

// Enabled reports whether anything is written back at all.
func (w WriteBack) Enabled() bool { return w.Mode == WriteBackPush || w.Mode == WriteBackBundle }

// IsZero reports whether the write-back says nothing.
func (w WriteBack) IsZero() bool { return w == WriteBack{} }

// BundleCap returns the effective byte ceiling for a bundle.
func (w WriteBack) BundleCap() int64 {
	if w.MaxBundleBytes <= 0 {
		return DefaultWriteBackBundleBytes
	}
	if w.MaxBundleBytes > MaxWriteBackBundleBytes {
		return MaxWriteBackBundleBytes
	}
	return w.MaxBundleBytes
}

// Validate checks the driver-independent invariants.
func (w WriteBack) Validate() error {
	if !w.Mode.Valid() {
		return fmt.Errorf("%w: write_back mode %q is not one of push, bundle", ErrInvalidSpec, w.Mode)
	}
	if !w.Enabled() {
		// The mode-specific fields must be empty rather than ignored, for the
		// same reason Workspace enforces it: a spec that names a branch and no
		// mode is not a spec with a harmless extra field, it is one whose
		// author believes the branch will be created.
		switch {
		case strings.TrimSpace(w.Branch) != "":
			return fmt.Errorf("%w: write_back branch is set but no mode is selected", ErrInvalidSpec)
		case strings.TrimSpace(w.Message) != "":
			return fmt.Errorf("%w: write_back message is set but no mode is selected", ErrInvalidSpec)
		case w.MaxBundleBytes != 0:
			return fmt.Errorf("%w: write_back max_bundle_bytes is set but no mode is selected", ErrInvalidSpec)
		}
		return nil
	}
	if err := ValidateWriteBackBranch(w.Branch); err != nil {
		return fmt.Errorf("%w: write_back branch: %w", ErrInvalidSpec, err)
	}
	if len(w.Message) > MaxWriteBackMessageLen {
		return fmt.Errorf("%w: write_back message is %d bytes, at most %d are allowed",
			ErrInvalidSpec, len(w.Message), MaxWriteBackMessageLen)
	}
	if strings.ContainsRune(w.Message, 0) {
		return fmt.Errorf("%w: write_back message contains a NUL byte", ErrInvalidSpec)
	}
	switch {
	case w.MaxBundleBytes < 0:
		return fmt.Errorf("%w: write_back max_bundle_bytes must be >= 0, got %d",
			ErrInvalidSpec, w.MaxBundleBytes)
	case w.MaxBundleBytes > MaxWriteBackBundleBytes:
		return fmt.Errorf("%w: write_back max_bundle_bytes %d exceeds the maximum of %d",
			ErrInvalidSpec, w.MaxBundleBytes, MaxWriteBackBundleBytes)
	}
	if w.Mode == WriteBackPush && w.MaxBundleBytes != 0 {
		return fmt.Errorf("%w: write_back max_bundle_bytes applies to mode bundle, not push", ErrInvalidSpec)
	}
	return nil
}

// Describe renders the write-back for a log line or an audit row. It can never
// contain a credential — WriteBack has no field that could hold one.
func (w WriteBack) Describe() string {
	switch w.Mode {
	case WriteBackPush:
		return "push to branch " + strings.TrimSpace(w.Branch)
	case WriteBackBundle:
		return "bundle branch " + strings.TrimSpace(w.Branch) +
			" (max " + strconv.FormatInt(w.BundleCap()>>20, 10) + " MiB)"
	default:
		return "none"
	}
}

// ValidateWriteBackBranch applies the naming rules a write-back branch must
// satisfy.
//
// It is stricter than git's own check-ref-format in two ways that matter here.
// The name may not start with a dash, because it becomes an argv element in a
// push refspec and git would read it as a flag. And it must live under a
// "cloop/" prefix, because the hub force-updates this ref when the branch
// arrives: without a namespace, a sandbox could name its write-back branch
// "main" and have the hub overwrite the project's trunk with sandbox-authored
// history before anyone looked at it.
func ValidateWriteBackBranch(branch string) error {
	b := strings.TrimSpace(branch)
	switch {
	case b == "":
		return errors.New("branch is empty")
	case len(b) > MaxWriteBackBranchLen:
		return fmt.Errorf("branch is %d bytes, at most %d are allowed", len(b), MaxWriteBackBranchLen)
	case !strings.HasPrefix(b, WriteBackBranchPrefix):
		return fmt.Errorf("branch %q must start with %q so the hub can force-update it without "+
			"being able to overwrite a branch a human owns", b, WriteBackBranchPrefix)
	case strings.HasPrefix(b, "refs/"):
		return fmt.Errorf("branch %q must be a bare branch name, not a full ref", b)
	}
	// git's own refname rules, the subset that is unambiguous. validateGitRef
	// carries them already and is the same check a workspace ref goes through;
	// sharing it means a name git would reject cannot differ between the fetch
	// side and the push side.
	if err := validateGitRef(b); err != nil {
		return err
	}
	for _, elem := range strings.Split(b, "/") {
		if elem == "" {
			return fmt.Errorf("branch %q has an empty path element", b)
		}
		if strings.HasPrefix(elem, ".") {
			return fmt.Errorf("branch %q has an element beginning with a dot, which git forbids", b)
		}
	}
	return nil
}

// WriteBackBranchPrefix namespaces every branch a sandbox may write back to.
// See ValidateWriteBackBranch for why the namespace is not optional.
const WriteBackBranchPrefix = "cloop/"

// --- result -----------------------------------------------------------------

// WriteBackResult is what a driver reports about the work product it recovered.
//
// It is metadata only. The bundle bytes, when there are any, stay in the driver
// and are collected through WriteBackFetcher — a Status is JSON-marshalled into
// audit rows and the executor store, and 32 MiB of base64 in an audit row is
// not a record, it is an outage.
type WriteBackResult struct {
	// Mode is the mode that actually ran, which may be None when the spec
	// asked for one and the tree turned out to be clean.
	Mode WriteBackMode `json:"mode,omitempty"`
	// Branch is the branch the sandbox committed to.
	Branch string `json:"branch,omitempty"`
	// CommitSHA is the tip the sandbox produced. Full 40-hex.
	CommitSHA string `json:"commit_sha,omitempty"`
	// BaseSHA is the commit the sandbox started from — the tip the workspace
	// was provisioned at. The hub verifies the range base..commit rather than
	// the whole branch, so a bundle cannot smuggle history that predates the
	// checkout past the inspection.
	BaseSHA string `json:"base_sha,omitempty"`
	// Pushed reports whether the branch reached the origin.
	Pushed bool `json:"pushed,omitempty"`
	// BundleBytes and BundleSHA256 describe the bundle, for mode bundle. The
	// digest is what lets the hub detect a truncated or altered stream before
	// handing the file to git.
	BundleBytes  int64  `json:"bundle_bytes,omitempty"`
	BundleSHA256 string `json:"bundle_sha256,omitempty"`
	// Commits and FilesChanged are for the operator reading a task record.
	Commits      int `json:"commits,omitempty"`
	FilesChanged int `json:"files_changed,omitempty"`
	// Skipped reports that there was nothing to write back: the harness ran and
	// changed no tracked file. It is distinct from a failure, and distinct from
	// a write-back that never ran, because "the agent produced no edits" is a
	// real and reportable outcome.
	Skipped bool `json:"skipped,omitempty"`
	// SkipReason explains Skipped in one phrase.
	SkipReason string `json:"skip_reason,omitempty"`
	// Err is the failure, already redacted, or "" on success.
	Err string `json:"error,omitempty"`
}

// Delivered reports whether there is a commit the hub can act on.
func (r *WriteBackResult) Delivered() bool {
	return r != nil && r.Err == "" && !r.Skipped &&
		strings.TrimSpace(r.CommitSHA) != "" && strings.TrimSpace(r.Branch) != ""
}

// Describe renders the result for a log line or an event row.
func (r *WriteBackResult) Describe() string {
	switch {
	case r == nil:
		return "no write-back"
	case r.Err != "":
		return "write-back failed: " + r.Err
	case r.Skipped:
		if r.SkipReason != "" {
			return "no changes to write back (" + r.SkipReason + ")"
		}
		return "no changes to write back"
	case !r.Delivered():
		return "no write-back"
	}
	verb := "bundled"
	if r.Pushed {
		verb = "pushed"
	}
	s := fmt.Sprintf("%s %s at %s", verb, r.Branch, ShortSHA(r.CommitSHA))
	if r.FilesChanged > 0 {
		s += fmt.Sprintf(" (%d file", r.FilesChanged)
		if r.FilesChanged != 1 {
			s += "s"
		}
		s += ")"
	}
	return s
}

// ShortSHA abbreviates a commit SHA the way git does, without pretending a
// non-SHA is one.
func ShortSHA(sha string) string {
	s := strings.TrimSpace(sha)
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// ValidateCommitSHA checks that s is a full 40-character lowercase hex object
// name.
//
// Full, not abbreviated: an abbreviation is ambiguous by construction, and the
// hub compares this value against what it actually fetched. A prefix match
// would let a sandbox report a SHA that resolves to a different object than the
// one it pushed.
func ValidateCommitSHA(s string) error {
	v := strings.TrimSpace(s)
	if len(v) != 40 {
		return fmt.Errorf("commit sha %q is %d characters, want 40", v, len(v))
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return fmt.Errorf("commit sha %q contains %q; want lowercase hex", v, r)
		}
	}
	return nil
}

// WriteBackFetcher is the optional interface a driver implements when it can
// hand the hub the bundle bytes it received.
//
// It is separate from Executor for the same reason Lister is: not every driver
// has one. The Kubernetes driver never carries a bundle (its work product goes
// out by push), and the local driver has nothing to carry — its changes are
// already on the hub's filesystem.
type WriteBackFetcher interface {
	// WriteBackBundle returns the bundle received for handleID. It returns
	// ErrHandleNotFound for an unknown handle and ErrWriteBackUnavailable when
	// the handle produced no bundle.
	WriteBackBundle(handleID string) ([]byte, error)
}

// --- the output sentinel ----------------------------------------------------
//
// A driver whose only channel back from the sandbox is the workload's own
// stdout — the Kubernetes one, whose Pod has no API credential and no other way
// to speak to the hub — reports its write-back as a line in that stream.

// WriteBackSentinel prefixes the line a sandbox prints to report its
// write-back. Chosen to be something no compiler, test runner or harness emits.
const WriteBackSentinel = "##cloop-writeback-v1##"

// MaxWriteBackSentinelBytes bounds the encoded line, so a workload cannot use
// the scanner as an unbounded allocator.
const MaxWriteBackSentinelBytes = 8 << 10

// MarshalWriteBackSentinel renders r as the single line a sandbox prints.
func MarshalWriteBackSentinel(r WriteBackResult) (string, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("write-back sentinel: %w", err)
	}
	if len(body) > MaxWriteBackSentinelBytes {
		return "", fmt.Errorf("write-back sentinel is %d bytes, at most %d are allowed",
			len(body), MaxWriteBackSentinelBytes)
	}
	return WriteBackSentinel + " " + string(body), nil
}

// ScanWriteBackSentinel finds a sandbox's reported write-back in a workload's
// output.
//
// It returns the *last* well-formed sentinel, and that is a security decision
// rather than a tie-break. The harness shares this stdout: model-authored code
// can print a line claiming any branch and commit it likes. What it cannot do
// is print one after it has exited — and the wrapper that performs the
// write-back emits its line only then, once the harness's stream is closed. So
// taking the last occurrence means a forged line can only ever be overwritten
// by the real one.
//
// The forgery that survives is a workload with no genuine write-back at all,
// which can name any commit it wants. That is why nothing downstream trusts
// this value: pkg/writeback fetches the named branch, checks it is at the named
// SHA, checks it descends from the base the hub recorded, and inspects every
// path in the range before anything merges. The sentinel says where to look,
// never what is true.
func ScanWriteBackSentinel(output string) (WriteBackResult, bool) {
	var (
		found WriteBackResult
		ok    bool
	)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		rest, isSentinel := strings.CutPrefix(line, WriteBackSentinel)
		if !isSentinel {
			continue
		}
		rest = strings.TrimSpace(rest)
		if rest == "" || len(rest) > MaxWriteBackSentinelBytes {
			continue
		}
		var r WriteBackResult
		if err := json.Unmarshal([]byte(rest), &r); err != nil {
			continue
		}
		found, ok = r, true
	}
	return found, ok
}

// --- path and mode vetting --------------------------------------------------
//
// This is the security-sensitive core. Everything below runs on the hub against
// a commit range a sandbox authored.

// Git file modes, as they appear in `git diff --raw` and `git ls-tree`.
const (
	ModeAbsent    = "000000"
	ModeFile      = "100644"
	ModeExec      = "100755"
	ModeSymlink   = "120000"
	ModeSubmodule = "160000"
	ModeTree      = "040000"
)

// BundleEntry is one changed path in a write-back's commit range, as the hub
// reads it out of git.
type BundleEntry struct {
	// Path is the repository-relative path, slash-separated.
	Path string
	// Mode is the resulting file mode, one of the Mode* constants. ModeAbsent
	// means the path was deleted.
	Mode string
	// LinkTarget is the symlink destination, for Mode ModeSymlink. The caller
	// reads it out of the blob; this package decides whether it is allowed.
	LinkTarget string
}

// ErrWriteBackUnavailable: the work product could not be recovered from the
// executor. Distinct from a harness failure — nothing about the task's code is
// implicated, and the remedy is an operator's, not the model's.
var ErrWriteBackUnavailable = errors.New("executor: work product could not be written back")

// ErrWriteBackRejected: the returned commit range contains something the hub
// refuses to apply. Match the sentinel; read the *WriteBackRejection for which
// path and why.
var ErrWriteBackRejected = errors.New("executor: write-back rejected by the hub's content policy")

// WriteBackRejection names the entry that was refused.
//
// It is typed and it names the path because the operator's first question is
// always "what exactly did the sandbox try to write" — and because a rejection
// here is a security event, not a build failure. A bare "invalid bundle" would
// be indistinguishable from a corrupt download.
type WriteBackRejection struct {
	// Path is the offending repository-relative path.
	Path string
	// Mode is the file mode that was refused, when the mode is the problem.
	Mode string
	// Target is the symlink destination, when that is the problem.
	Target string
	// Reason is the human-readable refusal.
	Reason string
	// Branch and CommitSHA locate the refusal in the sandbox's output.
	Branch    string
	CommitSHA string
}

// Error implements error.
func (e *WriteBackRejection) Error() string {
	var b strings.Builder
	b.WriteString("executor: refusing to apply write-back")
	if e.Branch != "" {
		b.WriteString(" of " + e.Branch)
	}
	if e.CommitSHA != "" {
		b.WriteString(" at " + ShortSHA(e.CommitSHA))
	}
	if e.Path != "" {
		b.WriteString(": path " + strconv.Quote(e.Path))
	} else {
		b.WriteString(":")
	}
	if e.Target != "" {
		b.WriteString(" -> " + strconv.Quote(e.Target))
	}
	b.WriteString(" " + e.Reason)
	return b.String()
}

// Unwrap lets callers match errors.Is(err, ErrWriteBackRejected).
func (e *WriteBackRejection) Unwrap() error { return ErrWriteBackRejected }

// ValidateWriteBackPath reports whether a repository-relative path may be
// written by an applied write-back.
//
// The containment rules are mount.go's, reached through the same hasDotDot
// helper rather than restated, because "does this path escape its root" has one
// correct answer and two implementations of it is one more than the number that
// can be kept right. What this adds on top is the git-specific half: the .git
// directory is not an ordinary path, because writing into it is not writing a
// file — it is editing the configuration of the program that is about to run.
func ValidateWriteBackPath(p string) error {
	switch {
	case p == "":
		return errors.New("is empty")
	case len(p) > MaxWriteBackPathLen:
		return fmt.Errorf("is %d bytes, at most %d are allowed", len(p), MaxWriteBackPathLen)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return errors.New("contains a control character")
		}
	}
	if strings.Contains(p, `\`) {
		// git stores paths with forward slashes. A backslash is either a
		// literal filename character (legal on Linux, and nothing legitimate
		// uses it) or a Windows separator that would defeat the element scan
		// below on a checkout that interprets it.
		return errors.New("contains a backslash; git paths use forward slashes")
	}
	if strings.HasPrefix(p, "/") {
		return errors.New("is absolute; write-back paths are relative to the project root")
	}
	// The ".." scan comes before the cleanliness check so the clearer message
	// wins — path.Clean turns "a/../../b" into "../b", and reporting that as
	// "not clean" would hide that the sandbox tried to climb out. Same ordering
	// and the same reason as SpecMount.Validate.
	if hasDotDot(p) {
		return errors.New(`contains a ".." element, which would escape the project root`)
	}
	if c := path.Clean(p); c != p {
		return fmt.Errorf("is not a clean path (did you mean %q?)", c)
	}
	if p == "." {
		return errors.New("is the project root itself")
	}
	for _, elem := range strings.Split(p, "/") {
		if isDotGit(elem) {
			return errors.New("is inside the .git directory, where a file is not data but " +
				"configuration: a hook there runs on the next checkout and .git/config can " +
				"redirect a fetch or install a credential helper")
		}
	}
	return nil
}

// isDotGit reports whether a single path element names the git directory,
// including the spellings git itself defends against on case-insensitive and
// NTFS filesystems.
//
// Case folding matters because the refusal has to hold for the machine that
// eventually checks the tree out, not only for the one applying it: ".GIT" and
// ".git" are the same directory on macOS and Windows, so a rule that only
// matched the lowercase form would be bypassed by an operator's laptop. The
// trailing-dot and trailing-space forms are how NTFS resolves a name back to
// ".git"; git's own core.protectNTFS refuses them for exactly this reason, and
// ".git~1" is the 8.3 short name.
func isDotGit(elem string) bool {
	e := strings.ToLower(elem)
	e = strings.TrimRight(e, ". ")
	return e == ".git" || e == ".git~1" || e == "git~1"
}

// ValidateBundleEntry vets one changed path in a write-back's commit range: the
// path itself, the file mode, and — for a symlink — where it points.
//
// The three refusals beyond ValidateWriteBackPath are each a way to escape a
// path check that has already passed:
//
//   - a submodule (gitlink) entry names a URL, not a file. Checking it out and
//     running `git submodule update` fetches attacker-chosen code into the
//     tree, and no path rule sees it because the gitlink's own path is benign.
//   - a symlink whose target escapes the project root turns every *subsequent*
//     legitimate-looking write through that link into a write anywhere on the
//     control plane. The path "config/x" is fine; it is fine right up until
//     "config" is a symlink to /etc.
//   - an unexpected mode is refused rather than ignored, because the set of
//     things a git tree can hold is small and closed, and "some mode we did not
//     think about" is not a category worth admitting on this boundary.
func ValidateBundleEntry(e BundleEntry) error {
	if err := ValidateWriteBackPath(e.Path); err != nil {
		return err
	}
	switch e.Mode {
	case ModeAbsent, ModeFile, ModeExec, ModeTree:
		return nil
	case ModeSubmodule:
		return errors.New("is a submodule (gitlink), which names a repository URL rather than " +
			"content; a sandbox that can add one can make the next checkout fetch code of its choosing")
	case ModeSymlink:
		return validateLinkTarget(e.Path, e.LinkTarget)
	default:
		return fmt.Errorf("has unexpected git mode %q", e.Mode)
	}
}

// validateLinkTarget decides whether a symlink stays inside the project root.
//
// It resolves the target against the link's own directory, which is what the
// kernel does, and then applies the same escape rule to the result. A relative
// target that climbs no higher than the root is fine — "docs/../README.md" is
// an ordinary, if pointless, link.
func validateLinkTarget(linkPath, target string) error {
	t := target
	switch {
	case strings.TrimSpace(t) == "":
		return errors.New("is a symlink with an empty target")
	case len(t) > MaxWriteBackPathLen:
		return fmt.Errorf("is a symlink whose target is %d bytes, at most %d are allowed",
			len(t), MaxWriteBackPathLen)
	}
	for _, r := range t {
		if r < 0x20 || r == 0x7f {
			return errors.New("is a symlink whose target contains a control character")
		}
	}
	if strings.HasPrefix(t, "/") {
		return fmt.Errorf("is a symlink to the absolute path %q, which leaves the project root", t)
	}
	// Resolve against the link's directory the way the kernel would, then ask
	// whether the result still names something under the root. path.Join cleans
	// as it goes, so an escape shows up as a leading "..".
	resolved := path.Join(path.Dir(linkPath), t)
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("is a symlink to %q, which resolves to %q — outside the project root", t, resolved)
	}
	for _, elem := range strings.Split(resolved, "/") {
		if isDotGit(elem) {
			return fmt.Errorf("is a symlink to %q, which resolves into the .git directory", t)
		}
	}
	return nil
}

// InspectWriteBack vets a whole commit range's worth of changed entries and
// returns the first refusal, or nil when every entry is acceptable.
//
// It takes the already-extracted entries rather than reading git itself so that
// this package stays free of I/O — pkg/executor is imported by the edge agent,
// which must not grow a dependency on a git binary to satisfy a type — and so
// the rules can be tested exhaustively against a table instead of against a
// repository.
func InspectWriteBack(branch, commitSHA string, entries []BundleEntry) error {
	if len(entries) > MaxWriteBackFiles {
		return &WriteBackRejection{
			Branch:    branch,
			CommitSHA: commitSHA,
			Reason: fmt.Sprintf("changes %d paths, at most %d are allowed",
				len(entries), MaxWriteBackFiles),
		}
	}
	for _, e := range entries {
		if err := ValidateBundleEntry(e); err != nil {
			return &WriteBackRejection{
				Path:      e.Path,
				Mode:      e.Mode,
				Target:    e.LinkTarget,
				Reason:    err.Error(),
				Branch:    branch,
				CommitSHA: commitSHA,
			}
		}
	}
	return nil
}
