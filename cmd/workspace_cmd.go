// Workspace provisioning from the command line (Task 20179).
//
// `cloop workspace provision` is the executable half of the Kubernetes driver's
// workspace contract. That driver cannot clone a repository itself — it creates
// a Pod and walks away — so it renders an init container whose argv is exactly:
//
//	cloop workspace provision --dir <abs> --repo <https url> [--ref R] [--depth N] [--size-limit-mb N]
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

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/spf13/cobra"
)

var (
	workspaceProvisionDir         string
	workspaceProvisionRepo        string
	workspaceProvisionRef         string
	workspaceProvisionDepth       int
	workspaceProvisionSizeLimitMB int
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

	workspaceCmd.AddCommand(workspaceProvisionCmd)
}
