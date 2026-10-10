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
// # The run's project state (Task 20402)
//
// A seeded run records its outcomes in its own copy of the project, inside the
// sandbox, and the hub's dashboard renders the hub's copy. With --seed this
// command reads back what the run changed, measured against the project state
// it was started with, once the harness has exited. Where it goes depends on
// the driver: --project-result FILE writes it to a file the container driver
// collects from its output directory, and --project-result-frame TAG prints it
// as a resultframe block on stdout, after everything else, for a Pod — whose
// log is its only way home. With --seed and no --push or --bundle the command
// returns the project state alone, for a seeded run that asked for no
// write-back.
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
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/resultframe"
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
	workspaceWriteBackMaxB    int64
	workspaceWriteBackSeed    string
	workspaceWriteBackResult  string
	workspaceWriteBackFrame   string
	workspaceWriteBackPlace   bool
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

--repo may be left out with --bundle: a bundle goes nowhere but the file, which
is how a feature built from a branch the hub shipped returns its work. With
--seed and --project-result it also reads back what the run recorded in its
.cloop/ — measured against the project state it was started with — and writes
it to the second file, for the driver to hand to the hub. --project-result-frame
TAG prints the same read-back on stdout instead, as the last thing this command
prints, framed and checksummed, for a sandbox whose output stream is its only
way home (a Kubernetes Pod). With --seed and neither --push nor --bundle, only
the project state is returned.

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
			MaxB:    workspaceWriteBackMaxB,
			Seed:    workspaceWriteBackSeed,
			Result:  workspaceWriteBackResult,
			Frame:   workspaceWriteBackFrame,
			Place:   workspaceWriteBackPlace,
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
	// MaxB caps the bundle; 0 is the write-back default.
	MaxB int64
	// Seed and Result name the project state the run started from and the
	// file its read-back is written to. Frame is Result's alternative: the tag
	// of a resultframe block printed on stdout. Seed goes with exactly one of
	// them.
	Seed   string
	Result string
	Frame  string
	// Place writes Seed into Dir as the project's state before the harness
	// starts — for a driver that keeps project state off its own host.
	Place bool
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
	seed, result, frame := strings.TrimSpace(o.Seed), strings.TrimSpace(o.Result), strings.TrimSpace(o.Frame)
	delivers := o.Push || strings.TrimSpace(o.Bundle) != ""
	switch {
	case strings.TrimSpace(o.Dir) == "":
		return ws, wb, errors.New("--dir is required: name the tree whose changes are written back")
	case strings.TrimSpace(o.Repo) == "" && o.Push:
		return ws, wb, errors.New("--repo is required with --push: a push goes to the origin the tree came from")
	case result != "" && frame != "":
		return ws, wb, errors.New("--project-result and --project-result-frame are alternatives: one writes " +
			"the run's changes to a file, the other prints them on stdout")
	case (seed == "") != (result == "" && frame == ""):
		return ws, wb, errors.New("--seed goes with --project-result or --project-result-frame: the run's " +
			"changes are measured against the state it was started with")
	case frame != "" && !resultframe.ValidTag(frame):
		return ws, wb, fmt.Errorf("--project-result-frame %q is not a valid tag: 1-64 letters, digits, "+
			"'.', '_' or '-'", frame)
	case o.Place && seed == "":
		return ws, wb, errors.New("--place-seed needs --seed: it is the seed that is placed")
	case o.Push && strings.TrimSpace(o.Bundle) != "":
		return ws, wb, errors.New("--push and --bundle are alternatives: one sends the commits to " +
			"the origin, the other writes them to a file for a sandbox with no egress")
	case !delivers && seed == "":
		return ws, wb, errors.New("choose a delivery: --push to send the branch to the origin, " +
			"or --bundle FILE to write the commits out for a sandbox with no egress")
	}

	if !delivers {
		// The project state alone, for a seeded run that asked for no
		// write-back. The write-back's own flags would be ignored here, and a
		// flag that is silently ignored is a delivery somebody believes is
		// happening.
		for flag, set := range map[string]bool{
			"--repo": strings.TrimSpace(o.Repo) != "", "--branch": strings.TrimSpace(o.Branch) != "",
			"--base": strings.TrimSpace(o.Base) != "", "--message": strings.TrimSpace(o.Message) != "",
			"--max-bundle-bytes": o.MaxB != 0,
		} {
			if set {
				return ws, wb, fmt.Errorf("%s applies to a write-back, and none was asked for: add --push or "+
					"--bundle FILE, or leave it out to return only the project state", flag)
			}
		}
		return ws, wb, nil
	}

	if repo := strings.TrimSpace(o.Repo); repo != "" {
		ws = executor.Workspace{Kind: executor.WorkspaceGit, Repo: repo}
		if err := ws.Validate(); err != nil {
			return ws, wb, fmt.Errorf("--repo: %w", err)
		}
	}
	wb = executor.WriteBack{
		Mode:    executor.WriteBackPush,
		Branch:  strings.TrimSpace(o.Branch),
		Message: strings.TrimSpace(o.Message),
	}
	if !o.Push {
		wb.Mode = executor.WriteBackBundle
		wb.MaxBundleBytes = o.MaxB
	} else if o.MaxB != 0 {
		return ws, wb, errors.New("--max-bundle-bytes applies to --bundle, not --push")
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

	dir, seed, frame := strings.TrimSpace(o.Dir), strings.TrimSpace(o.Seed), strings.TrimSpace(o.Frame)

	// The project the harness is about to run, placed here — inside the
	// sandbox — by a driver that does not write project state on its own host.
	// A seed that cannot be placed fails the run before the harness starts: a
	// `cloop run` with no project exits on its first line blaming the project.
	if o.Place {
		if err := placeSeed(dir, seed); err != nil {
			reason := "the project state could not be placed in the workspace, so nothing ran: " + err.Error()
			if wb.Enabled() {
				res := executor.WriteBackResult{Mode: wb.Mode, Branch: wb.Branch, Err: reason}
				if line, lerr := executor.MarshalWriteBackSentinel(res); lerr == nil {
					fmt.Fprintln(stdout, line)
				}
			}
			if frame != "" {
				emitProjectResultFrame(stdout, stderr, frame, nil, reason)
			}
			return err
		}
	}

	exitCode := 0
	var harnessErr error
	if len(o.Argv) > 0 {
		exitCode, harnessErr = runHarness(ctx, o.Argv, stdout, stderr)
	}

	// The run's own account of what it did, read back in here — inside the
	// sandbox — because the database it is read from was written by the
	// workload, and parsing it is a job for something with no more authority
	// than the workload had. Read before the write-back, so it describes the
	// tree the harness left rather than anything after it; printed after, as
	// the last thing on stdout.
	var readBack []byte
	var readBackErr string
	if seed != "" {
		readBack, readBackErr = readBackProjectResult(dir, seed, stderr)
		if frame == "" {
			writeProjectResultFile(strings.TrimSpace(o.Result), readBack, readBackErr, stderr)
		}
	}

	var wbErr error
	if wb.Enabled() {
		wbErr = writeBackAndReport(ctx, o, ws, wb, cred, exitCode, stdout, stderr)
	}

	// Last, after the sentinel: a driver whose only channel home is this
	// stream reads the frame from the end of it (resultframe).
	if frame != "" {
		emitProjectResultFrame(stdout, stderr, frame, readBack, readBackErr)
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

// writeBackAndReport commits and delivers the tree's changes and prints the
// sentinel line reporting what happened. It returns the write-back's own error.
func writeBackAndReport(ctx context.Context, o workspaceWriteBackOptions, ws executor.Workspace,
	wb executor.WriteBack, cred executor.GitCredential, exitCode int, stdout, stderr io.Writer) error {

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
	return wbErr
}

// placeSeed writes the seed at seedPath into dir as the project's state.
func placeSeed(dir, seedPath string) error {
	seed, err := boundedread.ReadFile(seedPath, int64(executor.MaxProjectSeedBytes))
	if err != nil {
		return fmt.Errorf("the project state is unreadable: %w", err)
	}
	return projectseed.Write(dir, seed)
}

// maxReadBackReason bounds the reason sent when there is no result, in bytes:
// the bound the remote agent applies, well inside what every transport carries
// (executor.MaxProjectResultErrBytes).
const maxReadBackReason = 2000

// readBackProjectResult reads back what the run changed in dir/.cloop against
// the seed it started with. It returns the compressed result, or — when it
// cannot — the reason, bounded, never both. Never fatal: the harness's outcome
// and the write-back stand on their own.
func readBackProjectResult(dir, seedPath string, stderr io.Writer) ([]byte, string) {
	fail := func(reason string) ([]byte, string) {
		reason = boundReason(reason)
		fmt.Fprintf(stderr, "writeback: the run's results could not be read back: %s\n", reason)
		return nil, reason
	}
	seed, err := boundedread.ReadFile(seedPath, int64(executor.MaxProjectSeedBytes))
	if err != nil {
		return fail(fmt.Sprintf("the project state the run started from is unreadable: %v", err))
	}
	data, err := projectseed.Harvest(dir, seed, nil)
	if err != nil {
		return fail(err.Error())
	}
	fmt.Fprintf(stderr, "writeback: read back the run's results (%d bytes)\n", len(data))
	return data, ""
}

// boundReason cuts a reason to maxReadBackReason bytes at a character boundary,
// so the bound never produces text that is not UTF-8.
func boundReason(reason string) string {
	reason = strings.ToValidUTF8(strings.TrimSpace(reason), "\uFFFD")
	if reason == "" {
		reason = "no reason was given"
	}
	if len(reason) <= maxReadBackReason {
		return reason
	}
	cut := maxReadBackReason
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut]
}

// writeProjectResultFile writes a read-back to out — or, when there is none,
// the reason to out+".err", so the driver can tell the hub why the dashboard
// will not update.
func writeProjectResultFile(out string, data []byte, reason string, stderr io.Writer) {
	if out == "" {
		return
	}
	if reason == "" {
		err := os.WriteFile(out, data, 0o600)
		if err == nil {
			return
		}
		reason = boundReason(fmt.Sprintf("cannot write the read-back: %v", err))
	}
	if err := os.WriteFile(out+".err", []byte(reason), 0o600); err != nil {
		fmt.Fprintf(stderr, "writeback: cannot record why the run's results were not read back: %v\n", err)
	}
}

// emitProjectResultFrame prints a read-back — or the reason there is none — as
// a resultframe block on stdout. A failure is reported on stderr: the driver
// then finds no frame and says so, which is all that can be done about a
// stdout that cannot be written.
func emitProjectResultFrame(stdout, stderr io.Writer, tag string, data []byte, reason string) {
	kind, payload := resultframe.KindResult, data
	if reason != "" || len(data) == 0 {
		kind, payload = resultframe.KindError, []byte(boundReason(reason))
	}
	if err := resultframe.Write(stdout, tag, kind, payload); err != nil {
		fmt.Fprintf(stderr, "writeback: cannot print the run's results: %v\n", err)
	}
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
	f.Int64Var(&workspaceWriteBackMaxB, "max-bundle-bytes", 0, "refuse a bundle larger than this many bytes (default: the write-back limit)")
	f.StringVar(&workspaceWriteBackSeed, "seed", "", "the project state the run was started with (with --project-result)")
	f.StringVar(&workspaceWriteBackResult, "project-result", "", "write what the run changed in .cloop/ to this file")
	f.StringVar(&workspaceWriteBackFrame, "project-result-frame", "",
		"print what the run changed in .cloop/ on stdout, last, as a frame tagged with this value (with --seed)")
	f.BoolVar(&workspaceWriteBackPlace, "place-seed", false, "place --seed into --dir as the project's state before the command runs")

	workspaceCmd.AddCommand(workspaceWriteBackCmd)
}
