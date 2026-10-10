// Workspace provisioning from the command line (Task 20179).
//
// `cloop workspace provision` is the executable half of the Kubernetes driver's
// workspace contract. That driver cannot clone a repository itself — it creates
// a Pod and walks away — so it renders an init container whose argv is exactly:
//
//	cloop workspace provision --dir <abs> --repo <https url> [--ref R] [--depth N] [--size-limit-mb N]
//	    [--seed FILE [--seed-copy FILE]]
//
// and this file is what that argv runs. The flags are therefore a wire format,
// not a UI: pkg/executor/kubernetes/pod.go builds the argv and this file parses
// it, and TestWorkspaceProvisionParsesTheKubernetesInitContainerArgv is the gate
// that keeps the two from drifting apart.
//
// # Why the clone itself is not here
//
// It is in pkg/executor/gitprovision, which the remote agent also calls. Two
// implementations of "how cloop clones a repo into a sandbox" would be two
// chances to reintroduce the bug this subsystem exists to remove — a run that
// starts cleanly, streams a plausible transcript, and operates on no code at
// all. A drifted provisioner has no symptom until an incident, so there is one.
//
// # The project (Task 20402)
//
// A clone of a source repository is not a cloop project. With --seed the
// command places the project state the hub sent — read from a file the driver
// projected into this container alone — into the checkout as
// <dir>/.cloop/state.json, exactly as the remote agent does after its own
// checkout (projectseed.Write), and keeps `.cloop/` out of the tree's commits
// the way a shipped branch does (gitprovision.HideControlDir): the harness or
// the push write-back after it runs `git add --all`, and the project's state
// database is not the project's code. --seed-copy leaves the seed's bytes at a
// second path, for `cloop workspace writeback --seed` to measure the run's
// changes against once the harness has exited; the driver mounts that path
// read-only in the harness container.
//
// A seed supersedes whatever `.cloop/` the repository commits: a database
// there is removed from the working tree before the seed is written, so the
// run sees the hub's project and not the repository's copy of it.
//
// # The credential
//
// It arrives in the environment, because that is the only channel a Pod has
// that is neither an argv (/proc publishes those to every process with the same
// uid) nor a file (which outlives the process that needed it). This command
// takes it out of the environment on the first line it runs, hands it to the
// provisioner, and prints nothing that has not been through
// executor.RedactSecrets.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/spf13/cobra"
)

var (
	workspaceProvisionDir         string
	workspaceProvisionRepo        string
	workspaceProvisionRef         string
	workspaceProvisionDepth       int
	workspaceProvisionSizeLimitMB int
	workspaceProvisionSeed        string
	workspaceProvisionSeedCopy    string
)

// workspaceProvisionDirPerm is the mode the target directory is created with.
//
// Not 0o777: the harness that runs next is the untrusted party, and on a
// Kubernetes node the emptyDir is shared with whatever else the Pod contains.
// The provisioner and the harness run as the same uid (see
// kubernetes.DefaultRunAsUser), so owner-only write is all either needs.
const workspaceProvisionDirPerm = 0o755

var workspaceProvisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Clone a project's source tree into a sandbox before its harness starts",
	Long: `Materialise a git workspace into a directory, then exit.

This is what an isolated executor runs before the harness: a Kubernetes init
container, or any other place that has to hold the code before the workload
starts. It is not something you normally type — the driver renders the argv —
but running it by hand is the way to reproduce a workspace failure outside a
cluster.

  cloop workspace provision --dir /workspace/project --repo https://github.com/acme/app.git
  cloop workspace provision --dir /workspace/project --repo https://github.com/acme/app.git \
      --ref main --depth 1 --size-limit-mb 512

With --seed FILE the project state the hub sent is placed into the checkout as
.cloop/state.json once it is fetched, and .cloop/ is kept out of the tree's
commits. A .cloop/ the repository commits is superseded: the hub's project is
the one that runs. --seed-copy FILE also leaves the seed at a second path, for
` + "`cloop workspace writeback --seed`" + ` to read the run's changes back against.

The credential, if the repository needs one, is read from the environment:

  ` + kubernetes.EnvWorkspaceToken + `   the bare token; absent or empty means an unauthenticated fetch
  ` + kubernetes.EnvWorkspaceUser + `    the basic-auth username (default ` + secretbroker.GitHubUsername + `)

Both are removed from this process's environment before anything is spawned,
and no output of this command can contain either.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// First statement in the command, deliberately: everything below this
		// line runs with the credential held in a local variable and nowhere
		// else. See takeWorkspaceCredential.
		cred := takeWorkspaceCredential()
		return runWorkspaceProvision(cmd.Context(), workspaceProvisionOptions{
			Dir:         workspaceProvisionDir,
			Repo:        workspaceProvisionRepo,
			Ref:         workspaceProvisionRef,
			Depth:       workspaceProvisionDepth,
			SizeLimitMB: workspaceProvisionSizeLimitMB,
			Seed:        workspaceProvisionSeed,
			SeedCopy:    workspaceProvisionSeedCopy,
		}, cred, cmd.OutOrStdout())
	},
}

// workspaceProvisionOptions is the parsed flag set.
type workspaceProvisionOptions struct {
	Dir         string
	Repo        string
	Ref         string
	Depth       int
	SizeLimitMB int
	// Seed names the project state to place into the checkout, and SeedCopy
	// where to leave a copy of it for the write-back wrapper. Both are files
	// in the container; SeedCopy needs Seed.
	Seed     string
	SeedCopy string
}

// workspace turns the flags into a validated executor.Workspace.
//
// The flag-shaped checks come first so that a mistake made at the command line
// is reported as the flag that is wrong. executor.Workspace.Validate is the
// authority on everything after that — https only, no userinfo in the URL, no
// ref that git would read as a flag — and reusing it is what keeps this command
// from accepting a workspace the drivers would refuse.
func (o workspaceProvisionOptions) workspace() (executor.Workspace, error) {
	dir := strings.TrimSpace(o.Dir)
	repo := strings.TrimSpace(o.Repo)

	switch {
	case dir == "":
		return executor.Workspace{}, errors.New(
			"--dir is required: name the directory the source tree is provisioned into")
	case !filepath.IsAbs(dir):
		// A relative path would be resolved against a working directory this
		// process does not choose — in a Pod it is the image's WORKDIR, which
		// is the image author's decision, not the driver's. The one caller that
		// matters always passes an absolute path; anything else is a mistake
		// worth naming rather than resolving.
		return executor.Workspace{}, fmt.Errorf(
			"--dir %q must be an absolute path; a relative one would resolve against "+
				"whatever working directory this process happens to have", dir)
	case repo == "":
		return executor.Workspace{}, errors.New(
			"--repo is required: name the https clone URL of the repository to fetch")
	case strings.TrimSpace(o.SeedCopy) != "" && strings.TrimSpace(o.Seed) == "":
		return executor.Workspace{}, errors.New("--seed-copy needs --seed: it is the seed that is copied")
	}
	for flag, p := range map[string]string{"--seed": o.Seed, "--seed-copy": o.SeedCopy} {
		if p = strings.TrimSpace(p); p != "" && !filepath.IsAbs(p) {
			return executor.Workspace{}, fmt.Errorf("%s %q must be an absolute path", flag, p)
		}
	}

	w := executor.Workspace{
		Kind:        executor.WorkspaceGit,
		Repo:        repo,
		Ref:         strings.TrimSpace(o.Ref),
		Depth:       o.Depth,
		SizeLimitMB: o.SizeLimitMB,
	}
	if err := w.Validate(); err != nil {
		return executor.Workspace{}, err
	}
	return w, nil
}

// takeWorkspaceCredential reads the credential out of the environment and
// removes it from the environment in the same breath.
//
// The unset is the point of this function existing at all. Provisioning spawns
// git, and git spawns whatever a hook, a helper or a transport decides to; a
// variable still in os.Environ() is inherited by every one of them, including
// processes nothing in this file knows about. The provisioner already builds a
// closed environment for its own children (executor.GitBaseEnv, which drops
// everything but a transport allowlist), so this is not the primary control —
// it is what makes the primary control unnecessary to trust.
//
// An absent or empty token is a legitimate configuration, not an error: a public
// repository needs no credential, and the Kubernetes driver sets no token
// variable at all when no grant was leased.
func takeWorkspaceCredential() executor.GitCredential {
	token := strings.TrimSpace(os.Getenv(kubernetes.EnvWorkspaceToken))
	user := strings.TrimSpace(os.Getenv(kubernetes.EnvWorkspaceUser))

	// Unconditional, including when they were never set: "clear it if it was
	// there" and "clear it" differ only in a branch that could be got wrong.
	_ = os.Unsetenv(kubernetes.EnvWorkspaceToken)
	_ = os.Unsetenv(kubernetes.EnvWorkspaceUser)

	if token == "" {
		return executor.GitCredential{}
	}
	if user == "" {
		// The same literal the broker pairs with a GitHub PAT, referenced
		// rather than repeated so the two cannot disagree.
		user = secretbroker.GitHubUsername
	}
	return executor.GitCredential{Username: user, Password: token}
}

// runWorkspaceProvision is the command body, factored out so a test can drive it
// without a process.
//
// out receives the provisioning log. Every byte written to it, and every byte of
// the error returned, has been through executor.RedactSecrets — twice, in fact,
// since the provisioner redacts as well. That is not redundant: this command's
// contract is that nothing it emits can carry the token, and a contract that
// depends on a callee keeping its own promise is not one this file can state.
func runWorkspaceProvision(ctx context.Context, o workspaceProvisionOptions,
	cred executor.GitCredential, out io.Writer) error {

	if ctx == nil {
		ctx = context.Background()
	}
	secrets := cred.Secrets()
	say := func(text string) {
		fmt.Fprint(out, executor.RedactSecrets(text, secrets))
	}
	// Every error out of this function is built here, so redaction is a
	// property of the exit path rather than of each author remembering. It
	// redacts the *whole* rendered message, not just the part that came from a
	// callee: the first version of this file interpolated the repository URL
	// unredacted, which a test caught only because the URL happened to contain
	// the token. Formatting first and filtering once leaves no such seam.
	fail := func(cause error, format string, args ...any) error {
		return &workspaceProvisionError{
			msg: executor.RedactSecrets(fmt.Sprintf(format, args...), secrets),
			err: cause,
		}
	}

	w, err := o.workspace()
	if err != nil {
		// A flag error carries no credential by construction, but it goes
		// through the same exit anyway: a future flag whose value came from the
		// environment must not be the exception nobody noticed.
		return fail(err, "%v", err)
	}

	dir := strings.TrimSpace(o.Dir)
	// Created rather than required: the Kubernetes driver mounts an emptyDir at
	// the volume root and points this command at a sub-path of it, so on the
	// first run the target does not exist yet. MkdirAll is a no-op when it does.
	if err := os.MkdirAll(dir, workspaceProvisionDirPerm); err != nil {
		return fail(executor.ErrWorkspaceUnavailable,
			"cannot create the workspace directory %s: %v", dir, err)
	}

	provErr := gitprovision.Provision(ctx, gitprovision.Request{
		Dir:        dir,
		Workspace:  w,
		Credential: cred,
		Emit:       say,
		// "container" rather than "device": this command's caller is an
		// isolated executor, and an operator told "install git on this device"
		// would go and edit a node instead of the image.
		Host: gitprovision.HostLabel("workspace container"),
	})
	if provErr == nil {
		// The checkout is a source tree, not yet a project. Placing the hub's
		// project is part of provisioning rather than of the harness: a
		// workspace without it is one the run cannot start in, and failing
		// here fails the init container — before the harness, naming the seed
		// — rather than leaving `cloop run` to exit on its first line blaming
		// the project.
		if seed := strings.TrimSpace(o.Seed); seed != "" {
			n, err := placeProvisionedSeed(ctx, dir, seed, strings.TrimSpace(o.SeedCopy))
			if err != nil {
				return fail(executor.ErrWorkspaceUnavailable,
					"cannot place the project state the control plane sent into %s: %v", dir, err)
			}
			say(fmt.Sprintf("workspace: placed the project state the control plane sent (%d bytes) "+
				"and kept .cloop/ out of the tree's commits\n", n))
		}
		return nil
	}

	// The provisioner's message already names the machine and the reason; the
	// repository and directory are added here because the operator's first
	// question after a failed init container is which repository it was trying
	// to fetch and where, and the Pod's argv is not in front of them.
	//
	// The sentinel's own text is stripped so the line does not say "workspace
	// could not be provisioned" twice; errors.Is still matches, because
	// workspaceProvisionError unwraps to the original.
	reason := strings.TrimPrefix(provErr.Error(), executor.ErrWorkspaceUnavailable.Error()+": ")
	return fail(provErr, "cannot provision %s into %s: %s", w.Repo, dir, reason)
}

// placeProvisionedSeed places the seed at seedPath into the checkout at dir,
// keeps the project's control directory out of its commits, and — when copyTo
// is set — leaves the seed's bytes there for the write-back wrapper. It returns
// the seed's size.
//
// The order matters for one reason: HideControlDir marks the files the
// repository tracks under .cloop/ skip-worktree, and projectseed.Write deletes
// a committed state.db from the working tree. Either way round, the deletion
// and the seed written in its place never show up as changes; doing the copy
// last means a copy exists only for a seed that was placed.
func placeProvisionedSeed(ctx context.Context, dir, seedPath, copyTo string) (int, error) {
	seed, err := boundedread.ReadFile(seedPath, int64(executor.MaxProjectSeedBytes))
	if err != nil {
		return 0, fmt.Errorf("the project state is unreadable: %w", err)
	}
	if len(seed) == 0 {
		return 0, fmt.Errorf("the project state at %s is empty", seedPath)
	}
	if err := projectseed.Write(dir, seed); err != nil {
		return 0, err
	}
	if err := gitprovision.HideControlDir(ctx, dir); err != nil {
		return 0, fmt.Errorf("cannot keep .cloop/ out of the tree's commits: %w", err)
	}
	if copyTo != "" {
		if err := writeFileAtomic(copyTo, seed, 0o400); err != nil {
			return 0, fmt.Errorf("cannot keep a copy of the project state for the write-back: %w", err)
		}
	}
	return len(seed), nil
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory, so a reader never sees half of it.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".seed-copy-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // after a successful rename there is nothing left to remove
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// workspaceProvisionError is a failure whose text is guaranteed
// credential-free.
//
// It is a type rather than a fmt.Errorf so that the redacted message and the
// original error can both be kept: the message is what reaches a terminal and a
// container log, and the error is what errors.Is(err,
// executor.ErrWorkspaceUnavailable) matches on. Wrapping with %w would have
// pulled the unredacted original back into the rendered text.
type workspaceProvisionError struct {
	// msg is the fully rendered, already-redacted message.
	msg string
	// err is the cause, exposed for errors.Is/As only.
	err error
}

// Error implements error.
func (e *workspaceProvisionError) Error() string { return e.msg }

// Unwrap exposes the sentinel the provisioner wrapped.
func (e *workspaceProvisionError) Unwrap() error { return e.err }

func init() {
	f := workspaceProvisionCmd.Flags()
	f.StringVar(&workspaceProvisionDir, "dir", "",
		"absolute directory to provision the source tree into (required)")
	f.StringVar(&workspaceProvisionRepo, "repo", "",
		"https clone URL of the repository to fetch (required)")
	f.StringVar(&workspaceProvisionRef, "ref", "",
		"branch, tag or commit to check out (default: the remote's default branch)")
	f.IntVar(&workspaceProvisionDepth, "depth", 0,
		"shallow-fetch depth; 0 fetches full history")
	f.IntVar(&workspaceProvisionSizeLimitMB, "size-limit-mb", 0,
		"refuse a provisioned tree larger than this many megabytes; 0 means no limit")
	f.StringVar(&workspaceProvisionSeed, "seed", "",
		"place the project state in this file into the checkout as .cloop/state.json")
	f.StringVar(&workspaceProvisionSeedCopy, "seed-copy", "",
		"also leave the project state at this path, for `cloop workspace writeback --seed` (with --seed)")

	workspaceCmd.AddCommand(workspaceProvisionCmd)
}
