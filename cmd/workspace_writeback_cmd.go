// Result write-back from the command line (Task 20180).
//
// `cloop workspace writeback` is the executable half of the Kubernetes driver's
// write-back contract, exactly as `cloop workspace provision` is for the
// workspace one — and it exists for the second half of the same bug. A Pod's
// /workspace is an emptyDir: it stops existing when the Pod does, so every file
// the harness wrote is discarded the moment the task ends. Provisioning fixed a
// run that started against no code; without this, the same run ends by throwing
// the code away.
//
// # Why it wraps the harness
//
// A Kubernetes Pod has no "run this afterwards" hook. restartPolicy is Never,
// init containers run before, and a sidecar cannot see another container exit.
// The only place a program can run after the harness and before the workspace
// volume is destroyed is inside the harness container itself — so when a Spec
// asks for a write-back, the driver makes this command the container's entry
// point and passes the harness argv after `--`:
//
//	cloop workspace writeback --dir D --repo U --branch B --base SHA --push \
//	    -- claude --print ...
//
// It runs the harness, forwards its output and its signals, waits, performs the
// write-back, and exits with the harness's own status. The harness cannot tell
// the difference; `kubectl describe pod` still shows the real command in the
// cloop.dev/argv annotation.
//
// # How the result gets home
//
// Printed as one sentinel line on stdout (executor.WriteBackSentinel), because
// a Pod built by this driver has no other channel: its ServiceAccount token is
// deliberately not mounted, so it cannot talk to the API server, and the hub
// reads its output and nothing else. The harness shares that stdout and can
// forge such a line — which is why the line is emitted only after the harness's
// stream has closed (the scanner takes the last one), and why nothing
// downstream trusts it: pkg/writeback re-fetches the named branch, checks the
// SHA, checks the ancestry, and inspects every path before anything merges.
//
// # The credential
//
// Same channel and same handling as provisioning: it arrives in the
// environment, is taken out of the environment on the first line that runs, and
// nothing this command prints has escaped executor.RedactSecrets.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/spf13/cobra"
)

var (
	workspaceWriteBackDir     string
	workspaceWriteBackRepo    string
	workspaceWriteBackBranch  string
	workspaceWriteBackBase    string
	workspaceWriteBackMessage string
	workspaceWriteBackPush    bool
	workspaceWriteBackBundle  string
)

var workspaceWriteBackCmd = &cobra.Command{
	Use:   "writeback [-- command args...]",
	Short: "Return the files a task changed, from inside a sandbox",
	Long: `Commit a sandbox's changes to a per-task branch and deliver them.

This is what an isolated executor runs after the harness, so the work survives
a workspace that does not. It is not something you normally type — the driver
renders the argv — but running it by hand is the way to reproduce a write-back
failure outside a cluster.

With a command after "--" it runs that command first, forwards its output and
signals, and writes back only if it exits zero; the exit status is passed
through unchanged. Without one it writes back whatever is in --dir right now.

  cloop workspace writeback --dir /workspace/project --repo https://github.com/acme/app.git \
      --branch cloop/task-42-add-retry --base <sha> --push -- claude --print "..."

  cloop workspace writeback --dir /workspace/project --repo https://github.com/acme/app.git \
      --branch cloop/task-42-add-retry --base <sha> --bundle /tmp/out.bundle

The credential for --push is read from the environment:

  ` + kubernetes.EnvWorkspaceToken + `   the bare token
  ` + kubernetes.EnvWorkspaceUser + `    the basic-auth username

Both are removed from this process's environment before anything is spawned,
and no output of this command can contain either.`,
	// ArbitraryArgs rather than NoArgs: everything after "--" is the harness's
	// command line and cobra must not interpret any of it.
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// First statement in the command, deliberately: everything below this
		// line runs with the credential held in a local variable and nowhere
		// else. See takeWorkspaceCredential.
		cred := takeWorkspaceCredential()
		return runWorkspaceWriteBack(cmd.Context(), workspaceWriteBackOptions{
			Dir:     workspaceWriteBackDir,
			Repo:    workspaceWriteBackRepo,
			Branch:  workspaceWriteBackBranch,
			Base:    workspaceWriteBackBase,
			Message: workspaceWriteBackMessage,
			Push:    workspaceWriteBackPush,
			Bundle:  workspaceWriteBackBundle,
			Argv:    args,
		}, cred, cmd.OutOrStdout(), cmd.ErrOrStderr())
	},
	// The harness's exit status is this process's exit status, so a non-zero
	// one must not also print a cobra error or a usage block over output the
	// hub is parsing.
	SilenceUsage:  true,
	SilenceErrors: true,
}

// workspaceWriteBackOptions is the parsed flag set.
type workspaceWriteBackOptions struct {
	Dir     string
	Repo    string
	Branch  string
	Base    string
	Message string
	Push    bool
	Bundle  string
	// Argv is the harness command, or empty to write back immediately.
	Argv []string
}

// plan turns the flags into a validated workspace and write-back pair.
//
// The flag-shaped checks come first so a mistake at the command line is
// reported as the flag that is wrong. The contract types are the authority on
// everything after that — https only, a branch under cloop/, a full-hex base —
// and reusing their validation is what keeps this command from accepting a
// write-back the hub would refuse after the work had already been done.
func (o workspaceWriteBackOptions) plan() (executor.Workspace, executor.WriteBack, error) {
	var (
		ws executor.Workspace
		wb executor.WriteBack
	)
	switch {
	case strings.TrimSpace(o.Dir) == "":
		return ws, wb, errors.New("--dir is required: name the tree whose changes are written back")
	case strings.TrimSpace(o.Repo) == "":
		return ws, wb, errors.New("--repo is required: a write-back needs the origin the tree came from")
	case o.Push && strings.TrimSpace(o.Bundle) != "":
		return ws, wb, errors.New("--push and --bundle are alternatives: one sends the commits to " +
			"the origin, the other writes them to a file for a sandbox with no egress")
	case !o.Push && strings.TrimSpace(o.Bundle) == "":
		return ws, wb, errors.New("choose a delivery: --push to send the branch to the origin, " +
			"or --bundle FILE to write the commits out for a sandbox with no egress")
	}

	ws = executor.Workspace{Kind: executor.WorkspaceGit, Repo: strings.TrimSpace(o.Repo)}
	if err := ws.Validate(); err != nil {
		return ws, wb, fmt.Errorf("--repo: %w", err)
	}
	wb = executor.WriteBack{
		Mode:    executor.WriteBackPush,
		Branch:  strings.TrimSpace(o.Branch),
		Message: strings.TrimSpace(o.Message),
	}
	if !o.Push {
		wb.Mode = executor.WriteBackBundle
	}
	if err := wb.Validate(); err != nil {
		return ws, wb, err
	}
	if err := executor.ValidateCommitSHA(o.Base); err != nil {
		return ws, wb, fmt.Errorf("--base: %w; it is the commit the workspace was provisioned "+
			"at, and without it there is nothing to compute the returned changes against", err)
	}
	return ws, wb, nil
}

// runWorkspaceWriteBack runs the harness if there is one, then writes back.
func runWorkspaceWriteBack(ctx context.Context, o workspaceWriteBackOptions,
	cred executor.GitCredential, stdout, stderr io.Writer) error {

	ws, wb, err := o.plan()
	if err != nil {
		return err
	}

	exitCode := 0
	var harnessErr error
	if len(o.Argv) > 0 {
		exitCode, harnessErr = runHarness(ctx, o.Argv, stdout, stderr)
	}

	res, wbErr := gitwriteback.Produce(ctx, gitwriteback.Request{
		Dir:        strings.TrimSpace(o.Dir),
		Workspace:  ws,
		WriteBack:  wb,
		Credential: cred,
		BaseSHA:    strings.TrimSpace(o.Base),
		BundlePath: strings.TrimSpace(o.Bundle),
		ExitCode:   exitCode,
		// A harness that exited non-zero left the tree mid-edit, and a
		// half-applied refactor merged into main is worse than one that was
		// discarded: the loss is visible and the half-change is not.
		OnlyOnSuccess: true,
		// Progress goes to stderr, not stdout. stdout is where the sentinel
		// line lives and where the hub is looking; interleaving git's chatter
		// with it would work but makes the one line that matters harder to
		// find in a Pod log an operator is reading by eye.
		Emit: func(text string) { fmt.Fprint(stderr, text) },
		Host: gitprovision.HostLabel("workspace container"),
	})
	if wbErr != nil && res.Err == "" {
		res.Err = wbErr.Error()
	}

	// The sentinel is printed whatever happened, including for a failure and
	// for a skip. A hub that receives nothing cannot tell "the write-back
	// failed" from "this build does not do write-backs", and those have
	// different remedies.
	if line, err := executor.MarshalWriteBackSentinel(res.WriteBackResult); err == nil {
		fmt.Fprintln(stdout, line)
	} else {
		fmt.Fprintf(stderr, "writeback: cannot report the result: %v\n", err)
	}

	switch {
	case harnessErr != nil:
		// The harness's outcome wins. A write-back failure must not turn a
		// task that failed into one that failed for a different reason, and a
		// task that succeeded is still a task that succeeded even if its
		// output could not be delivered — the sentinel already says so.
		return harnessErr
	case wbErr != nil && len(o.Argv) == 0:
		// Standalone: there is no harness status to preserve, so the
		// write-back's own failure is this command's failure.
		return wbErr
	}
	return nil
}

// runHarness runs the wrapped command, forwarding its output and signals, and
// returns its exit status.
//
// Signals are forwarded rather than left to the process group because the
// kubelet sends SIGTERM to PID 1 — this process — and a harness that never
// received it would be SIGKILLed at the end of the grace period with its work
// uncommitted. Forwarding turns the Pod's shutdown into the harness's shutdown,
// which is what gives the write-back below a tree worth committing.
func runHarness(ctx context.Context, argv []string, stdout, stderr io.Writer) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// The harness inherits this process's environment minus the credential,
	// which takeWorkspaceCredential removed before anything was spawned. The
	// harness is the untrusted party here; a token it can read is a token it
	// can exfiltrate.
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("cannot start the harness %q: %w", argv[0], err)
	}

	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case sig := <-signals:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(sig)
				}
			case <-ctx.Done():
				if cmd.Process != nil {
					_ = cmd.Process.Signal(syscall.SIGTERM)
				}
				return
			case <-done:
				return
			}
		}
	}()

	err := cmd.Wait()
	signal.Stop(signals)

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exitErr):
		// A non-zero exit is the harness's verdict, not this command's error.
		// It comes back as a code so the write-back can decide what to do, and
		// as an errExit so Execute reproduces it as this process's status —
		// which is what the hub reads to decide whether the task failed. A
		// plain error would be printed and become exit 1, collapsing every
		// distinct harness failure into the same one.
		code := exitErr.ExitCode()
		return code, errExit{
			code: code,
			err:  fmt.Errorf("the harness exited with status %d", code),
		}
	default:
		return -1, fmt.Errorf("the harness %q could not be waited on: %w", argv[0], err)
	}
}

func init() {
	f := workspaceWriteBackCmd.Flags()
	f.StringVar(&workspaceWriteBackDir, "dir", "", "absolute path of the tree whose changes are written back")
	f.StringVar(&workspaceWriteBackRepo, "repo", "", "https clone URL the tree came from")
	f.StringVar(&workspaceWriteBackBranch, "branch", "", "branch to commit to (must start with "+executor.WriteBackBranchPrefix+")")
	f.StringVar(&workspaceWriteBackBase, "base", "", "commit the workspace was provisioned at")
	f.StringVar(&workspaceWriteBackMessage, "message", "", "commit message")
	f.BoolVar(&workspaceWriteBackPush, "push", false, "push the branch to the origin")
	f.StringVar(&workspaceWriteBackBundle, "bundle", "", "write the commits to this file instead of pushing")

	workspaceCmd.AddCommand(workspaceWriteBackCmd)
}
