// Package gitprovision materialises a workload's source tree where the workload
// is about to run.
//
// # Why this is its own package
//
// Two very different callers have to do exactly the same thing:
//
//   - the remote agent (pkg/executor/agent), which clones onto an edge device
//     before starting a harness there;
//   - `cloop workspace provision` (cmd), which the Kubernetes driver runs as an
//     init container before the harness container starts.
//
// The failure this whole subsystem exists to remove is a run that starts
// cleanly, streams a plausible transcript, and operates on no code at all. Two
// implementations of "how cloop clones a repo into a sandbox" would be two
// chances to reintroduce it — and the second copy would drift silently, because
// the symptom of a drifted provisioner is a run that *looks* fine. So there is
// one engine, here, and both callers are thin.
//
// The package deliberately depends on nothing but the standard library and
// pkg/executor. `cloop workspace provision` must not have to import the edge
// agent (with its transport, vault and session machinery) to clone a
// repository, and the edge agent must not grow a dependency on the CLI.
//
// # What is shared and what is not
//
// executor.Workspace.GitPlan renders the command sequence and is pure: no I/O,
// no clock, no environment. That is what lets a test assert on the sequence
// without a git binary. This package is everything the plan cannot be — which
// directory is safe to write to, whether git exists, how big the disk is — and
// it is shared because those answers are the same wherever the plan runs. The
// only thing a caller contributes is Request.Host: how the machine names itself
// in a diagnostic an operator will read.
//
// # The credential
//
// It arrives out of band (the agent's start frame, the init container's
// environment), never in the Spec, and it leaves this package in exactly one
// place: the environment of the single git child process whose step is marked
// Authenticated. It is never written to disk, never placed in an argv (/proc
// publishes those to every process with the same uid), and never added to the
// harness's own environment — the harness is the untrusted party here, and a
// token it can read is a token it can exfiltrate. Everything this package emits
// or returns is passed through executor.RedactSecrets first, because git is
// perfectly willing to quote a header back in an error message.
package gitprovision

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// MaxWalkEntries bounds the size check's directory walk.
//
// The walk runs over a tree a remote repository just chose the contents of, so
// it is attacker-influenced input on a machine the operator may never touch. A
// repository with ten million tiny files would exceed no byte limit while
// costing minutes of stat() calls. Half a million entries is far more than any
// real source tree and small enough to walk in well under a second.
const MaxWalkEntries = 500_000

// errTooManyEntries stops the walk once the ceiling is reached. It never
// escapes this package; the caller turns it into a legible refusal.
var errTooManyEntries = errors.New("workspace tree has too many entries to measure")

// Request is one provisioning.
type Request struct {
	// Dir is the absolute directory the tree is materialised into. It must
	// already exist, and the caller is responsible for having confined it —
	// only the caller knows what its own confinement boundary is (the agent's
	// root, the Pod's workspace volume).
	Dir string
	// Workspace describes what to fetch. Only Kind git is provisionable.
	Workspace executor.Workspace
	// Credential authenticates the single step that contacts the remote. The
	// zero value means an unauthenticated fetch, which only works for a public
	// repository.
	Credential executor.GitCredential
	// Emit receives the git output as it completes, already redacted, so
	// provisioning shows up in the run's live log rather than as a silent pause
	// before the harness starts. It may be nil.
	Emit func(string)
	// Host is how the machine names itself in a diagnostic: "this device
	// (edge-3)". Empty falls back to HostLabel("machine").
	//
	// It is a caller's choice rather than a lookup because the operator reading
	// the failure is looking at a fleet, and "this device" and "this workspace
	// container" send them to different places.
	Host string
}

// HostLabel renders how the machine provisioning runs on refers to itself.
//
// The hostname is the identifier an operator can act on — an edge device's name
// in the fleet, a Pod's name in the namespace. When it is unavailable the
// phrasing still has to read as a sentence.
func HostLabel(noun string) string {
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return "this " + noun + " (" + strings.TrimSpace(h) + ")"
	}
	return "this " + noun
}

// host returns the label used in this request's diagnostics.
func (r Request) host() string {
	if s := strings.TrimSpace(r.Host); s != "" {
		return s
	}
	return HostLabel("machine")
}

// Provision clones r.Workspace into r.Dir so the harness starts against real
// code.
//
// Every error it returns wraps executor.ErrWorkspaceUnavailable and has already
// been through executor.RedactSecrets, so a caller may log it, ship it across
// the remote boundary, or print it to a terminal without further filtering.
func Provision(ctx context.Context, r Request) error {
	emit := r.Emit
	if emit == nil {
		emit = func(string) {}
	}
	w := r.Workspace
	dir := r.Dir
	cred := r.Credential
	hostName := r.host()

	secrets := cred.Secrets()
	// Every error out of this function goes through fail, so redaction is a
	// property of the exit path rather than of each author remembering.
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", executor.ErrWorkspaceUnavailable,
			executor.RedactSecrets(fmt.Sprintf(format, args...), secrets))
	}

	if !w.NeedsProvisioning() {
		return fail("workspace kind %q is not one this machine provisions", w.Kind)
	}
	if _, err := exec.LookPath("git"); err != nil {
		// Naming the machine matters: something else dispatched this, and the
		// operator reading the failure is looking at a fleet, not at a box.
		return fail("%s has no git on its PATH, so it cannot clone %s; install git there, "+
			"or bind this project to an executor that already holds the tree",
			hostName, w.Repo)
	}
	if !cred.Empty() && !cred.ExpiresAt.IsZero() && !cred.ExpiresAt.After(time.Now()) {
		// Starting a fetch with a credential that has already lapsed produces an
		// opaque 401 halfway through a transfer. Saying so up front points at
		// the lease rather than at the repository — and on an edge device with
		// no RTC, a clock skewed far enough to trip this is itself the finding.
		return fail("the leased credential expired at %s, before the fetch could start "+
			"(this machine's clock reads %s; check for clock skew if that looks wrong)",
			cred.ExpiresAt.UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	}

	plan, err := w.GitPlan(dir)
	if err != nil {
		return fail("%v", err)
	}
	// Create the target here rather than leaving it to each caller. The two
	// production callers reach this from opposite directions — the agent has
	// already made the directory as part of confining it beneath its root, the
	// Kubernetes init container has an empty volume and a workDir that may be a
	// sub-path of it — and a precondition that only one of them satisfies is a
	// precondition that gets forgotten. MkdirAll is idempotent, so the caller
	// that already did the work pays nothing.
	//
	// 0700: the workspace holds a checkout of private source, and both callers
	// run the fetch and the harness as the same uid.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail("cannot create the workspace directory %s on %s: %v", dir, hostName, err)
	}
	reuse, err := inspectDir(dir, w, hostName)
	if err != nil {
		return fail("%v", err)
	}

	emit(fmt.Sprintf("workspace: provisioning %s into %s on %s\n", w.Describe(), dir, hostName))
	if !reuse.fresh {
		emit("workspace: reusing the existing checkout; fetching instead of cloning\n")
	}

	for _, step := range plan {
		if !reuse.fresh && (step.Name == "init" || step.Name == "remote") {
			// The repository is already here and already points at this remote,
			// so only the fetch and the checkout are owed. Skipping rather than
			// re-running is not an optimisation: `git init` over an existing
			// checkout is the shape of the mistake that discards work, and
			// `remote add` would simply fail.
			continue
		}
		if err := runStep(ctx, dir, w, cred, step, hostName, secrets, emit); err != nil {
			reuse.rollback(dir, emit)
			return fail("%v", err)
		}
		// Checked immediately after the fetch, while the objects are on disk
		// and the working tree has not been written yet: that is the earliest
		// point at which an oversized repository is visible, and stopping there
		// costs one checkout's worth of disk the machine does not have.
		if step.Name == "fetch" {
			if err := enforceSize(dir, w, hostName); err != nil {
				reuse.rollback(dir, emit)
				return fail("%v", err)
			}
		}
	}

	// And once more at the end, because the checkout materialises a working
	// tree that the fetched pack only implied.
	if err := enforceSize(dir, w, hostName); err != nil {
		reuse.rollback(dir, emit)
		return fail("%v", err)
	}

	emit(fmt.Sprintf("workspace: ready at %s\n", dir))
	return nil
}

// transportVars are the only variables a provisioning step inherits from the
// machine's own environment.
//
// executor.GitBaseEnv is deliberately closed: a fetch that read the machine's
// ~/.gitconfig could pick up a credential helper, an insteadOf rewrite pointing
// it at another host, or a proxy chosen by whoever last touched the box. None of
// that may influence a fetch the control plane asked for.
//
// Transport is the exception, and it has to be, because it is the one thing the
// control plane cannot know. An edge device is precisely the machine that
// reaches the internet through a corporate proxy and trusts a private CA; a hub
// in another datacentre cannot put that in a Spec, and a machine that cannot
// express it cannot clone at all. Each variable below can only say *how to
// reach* the host already named in the URL: none names a repository, none
// supplies a credential, and none can be set by the workload — they come from
// the operator who owns the machine anyway.
//
// GIT_SSL_NO_VERIFY is pointedly absent. Disabling certificate verification for
// a fetch carrying a brokered token is not a transport preference, it is handing
// the token to whoever answers.
var transportVars = []string{
	"HTTPS_PROXY", "https_proxy",
	"ALL_PROXY", "all_proxy",
	"NO_PROXY", "no_proxy",
	"GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// TransportEnv reads the machine's transport settings, skipping anything unset
// or empty (an empty proxy variable means something different from an absent one
// to libcurl).
//
// It is exported because the write-back engine (pkg/executor/gitwriteback) has
// to reach the same remote through the same proxy a moment later. Two
// allowlists would drift, and the drift would show up as a clone that works and
// a push that hangs on a machine nobody can reproduce.
func TransportEnv() []string { return transportEnv() }

func transportEnv() []string {
	out := make([]string, 0, len(transportVars))
	for _, name := range transportVars {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			out = append(out, name+"="+v)
		}
	}
	return out
}

// runStep runs one command of a plan and reports its output.
func runStep(ctx context.Context, dir string, w executor.Workspace, cred executor.GitCredential,
	step executor.GitStep, hostName string, secrets []string, emit func(string)) error {

	// A closed environment, not an inherited one: see executor.GitBaseEnv, plus
	// the narrow transport allowlist this machine is permitted to contribute.
	// The credential is appended for exactly the step that talks to the remote,
	// so the other three children never hold it at all.
	env := append(executor.GitBaseEnv(), transportEnv()...)
	if step.Authenticated {
		extra, err := executor.GitCredentialEnv(w, cred)
		if err != nil {
			return err
		}
		env = append(env, extra...)
	}

	cmd := exec.CommandContext(ctx, step.Argv[0], step.Argv[1:]...)
	cmd.Env = env
	// Every step addresses the repository by absolute path (`git -C dir`), so
	// the working directory is not load-bearing. It is set anyway so a child
	// never inherits the caller's own cwd, which on a service-managed agent may
	// be "/" or a directory that has since been deleted.
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if text := strings.TrimRight(executor.RedactSecrets(string(out), secrets), "\n"); text != "" {
		emit("workspace: " + step.Name + ": " + text + "\n")
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("git %s was cancelled on %s: %w", step.Name, hostName, ctxErr)
		}
		// The command's own output is the useful part — "Repository not found",
		// "could not read Username" — and it has already been redacted.
		return fmt.Errorf("git %s failed on %s: %v: %s", step.Name, hostName, err,
			executor.RedactSecrets(Collapse(string(out)), secrets))
	}
	return nil
}

// reuseState records what was found in the target directory, which decides both
// whether to clone or merely fetch and whether provisioning may clean up after
// itself.
type reuseState struct {
	// fresh is true when no repository was there and this machine is creating
	// one. It is also the permission to delete again: a tree we did not create
	// may hold work nobody else has a copy of.
	fresh bool
	// empty records that the directory held nothing at all, which is the only
	// case in which removing its whole contents is provably safe.
	empty bool
}

// rollback undoes a failed provisioning, as far as it safely can.
//
// The asymmetry is deliberate. Leaving a half-fetched repository behind would
// make the next attempt take the "reuse" path over a tree in an unknown state.
// But deleting files this machine did not create is unrecoverable, and the whole
// reason an existing checkout is reused rather than re-cloned is that it may
// contain the only copy of somebody's work.
func (r reuseState) rollback(dir string, emit func(string)) {
	if !r.fresh {
		// We did not create this repository; its objects and its working tree
		// are not ours to remove.
		return
	}
	if err := os.RemoveAll(filepath.Join(dir, ".git")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		emit(fmt.Sprintf("workspace: could not remove the partial repository: %v\n", err))
	}
	if !r.empty {
		// Something was already here before the clone. The fetched objects are
		// gone; the files are left alone because we cannot tell ours from
		// whatever was here first.
		emit("workspace: removed the partial repository; " +
			"files that were in the directory beforehand were left alone\n")
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			emit(fmt.Sprintf("workspace: could not remove %s: %v\n", entry.Name(), err))
		}
	}
}

// inspectDir decides whether dir holds a checkout that may be reused.
//
// Re-provisioning over an existing checkout would discard whatever it contains,
// so a directory that already has a .git is never re-initialised. It is either
// the same repository — in which case a fetch brings it up to date, which is
// also much cheaper than a fresh clone on a machine with a slow uplink — or it
// is a different one, which is a refusal naming both URLs rather than a silent
// choice between them.
func inspectDir(dir string, w executor.Workspace, hostName string) (reuseState, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return reuseState{}, fmt.Errorf("cannot read the workspace directory %s: %v", dir, err)
	}
	reuse := reuseState{fresh: true, empty: len(entries) == 0}

	if _, err := os.Lstat(filepath.Join(dir, ".git")); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return reuse, nil
		}
		return reuse, fmt.Errorf("cannot inspect %s: %v", filepath.Join(dir, ".git"), err)
	}
	reuse.fresh = false

	have, err := remoteURL(dir)
	if err != nil {
		return reuse, err
	}
	if !SameRemote(have, w.Repo) {
		return reuse, fmt.Errorf(
			"%s already holds a checkout of %s, but this workload asks for %s; "+
				"refusing to re-clone over it because that would discard whatever is there. "+
				"Use a different workdir, or remove the directory on %s",
			dir, quoteRemote(have), w.Repo, hostName)
	}
	return reuse, nil
}

// remoteURL reads the origin URL of an existing checkout.
func remoteURL(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "config", "--get", "remote.origin.url")
	cmd.Env = executor.GitBaseEnv()
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Exit 1 with no output is git's way of saying "that key is not set",
		// which for our purposes is a repository with no origin — reported as
		// an empty URL so the mismatch message reads sensibly.
		if stdout.Len() == 0 && strings.TrimSpace(stderr.String()) == "" {
			return "", nil
		}
		return "", fmt.Errorf("cannot read the existing checkout's remote in %s: %v: %s",
			dir, err, Collapse(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// SameRemote reports whether two clone URLs name the same repository.
//
// The comparison is deliberately narrow — a trailing slash and a trailing .git
// are noise that GitHub and every other forge treat as equivalent — and
// deliberately stops there. Anything cleverer (case folding a path, resolving a
// redirect) would risk calling two different repositories the same one, and the
// cost of a false match is a fetch into somebody else's working tree.
func SameRemote(a, b string) bool {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, "/")
		s = strings.TrimSuffix(s, ".git")
		return strings.TrimSuffix(s, "/")
	}
	return norm(a) != "" && norm(a) == norm(b)
}

// quoteRemote renders a possibly-empty remote URL for the mismatch message.
func quoteRemote(url string) string {
	if strings.TrimSpace(url) == "" {
		return "a repository with no origin remote"
	}
	return url
}

// EnforceSizeLimit refuses a tree that exceeds the workload's disk budget.
//
// The limit comes from the project's .cloop/sandbox.yaml resources.disk, and on
// a machine with no runtime quota it has to be enforced rather than advertised:
// the disk being filled belongs to whoever owns the machine, not to the operator
// who wrote the spec, and a limit that only the least-trusted party can enforce
// is not a limit. A container driver gets this from the runtime; here there is
// nothing between the fetch and the filesystem except this check.
func EnforceSizeLimit(dir string, w executor.Workspace) error {
	return enforceSize(dir, w, HostLabel("machine"))
}

func enforceSize(dir string, w executor.Workspace, hostName string) error {
	if w.SizeLimitMB <= 0 {
		return nil
	}
	size, entries, err := TreeSize(dir)
	if errors.Is(err, errTooManyEntries) {
		return fmt.Errorf("the fetched tree has more than %d files, which %s will not provision; "+
			"narrow the workspace (a shallower depth or a smaller repository) or raise the machine's limits",
			MaxWalkEntries, hostName)
	}
	if err != nil {
		return fmt.Errorf("cannot measure the provisioned tree in %s: %v", dir, err)
	}
	limit := int64(w.SizeLimitMB) << 20
	if size > limit {
		return fmt.Errorf("the provisioned tree is %d MB across %d files, over this workload's "+
			"limit of %d MB (.cloop/sandbox.yaml resources.disk); raise the limit or fetch less "+
			"of %s (try a shallow depth)",
			size>>20, entries, w.SizeLimitMB, w.Repo)
	}
	return nil
}

// TreeSize sums the regular files under dir, with a bounded walk.
//
// Symlinks are counted as themselves and never followed — filepath.WalkDir does
// not descend into them — so a repository containing a link to / measures as one
// small entry rather than as the whole filesystem.
func TreeSize(dir string) (size int64, entries int, err error) {
	err = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// A file git removed while we walked (a pack being replaced) is not
			// a measurement failure.
			if errors.Is(walkErr, fs.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		entries++
		if entries > MaxWalkEntries {
			return errTooManyEntries
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			if errors.Is(infoErr, fs.ErrNotExist) {
				return nil
			}
			return infoErr
		}
		size += info.Size()
		return nil
	})
	return size, entries, err
}

// Collapse folds command output onto one line for an error message, keeping the
// tail — git puts the actual reason last.
func Collapse(s string) string {
	fields := strings.Fields(s)
	joined := strings.Join(fields, " ")
	const max = 400
	if len(joined) > max {
		return "…" + joined[len(joined)-max:]
	}
	return joined
}
