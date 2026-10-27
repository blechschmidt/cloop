// Package agentproc is what the providers that run an agent CLI as a child
// process — claudecode's `claude`, copilot's `copilot` — share about that
// process once it has exited: the work it left running behind it.
//
// It exists because an agent that starts a long job in the background and then
// reports success is indistinguishable, from its output alone, from one that
// finished the job (Task 20205). Both providers start their CLI in a process
// group of its own, so after the CLI is reaped anything still in that group is
// work the task left behind; Settle decides what to do about it. Kept apart
// from either provider so the two cannot come to answer the question
// differently.
package agentproc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/procgroup"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// BackgroundPolicy governs what happens to work the harness leaves running in
// its process group after it exits. The zero value is the recommended
// behaviour: detect it, wait for it, and terminate whatever outlives the wait.
type BackgroundPolicy struct {
	// Disabled turns detection off, restoring the previous behaviour of
	// trusting a harness that reports success while its work is still
	// running. An escape hatch for a deployment where the tradeoff is wrong,
	// not a default.
	Disabled bool
	// Grace is how long a surviving process may live before it counts as
	// background work rather than ordinary teardown. Zero selects
	// DefaultBackgroundGrace.
	Grace time.Duration
	// Wait bounds how long cloop blocks for that work to finish. Zero selects
	// DefaultBackgroundWait; negative means report it without waiting.
	Wait time.Duration
	// TerminateGrace is how long a terminated group has to exit on SIGTERM
	// before SIGKILL. Zero selects DefaultTerminateGrace.
	TerminateGrace time.Duration
	// KeepOrphans leaves work that outlived the budget running instead of
	// terminating it. The task is still reported incomplete either way.
	KeepOrphans bool
}

// Background-policy defaults.
//
// The wait is generous on purpose. Its job is to cover the case this feature
// exists for — a build, a test suite or a training run that the agent started
// and should have waited for — and those finish in minutes, not seconds. The
// cost of waiting too long is a slow task; the cost of waiting too briefly is
// a task marked incomplete and retried when it would have succeeded, which is
// both more expensive and more confusing.
const (
	DefaultBackgroundGrace = 2 * time.Second
	DefaultBackgroundWait  = 30 * time.Minute
	DefaultTerminateGrace  = 5 * time.Second
)

// Resolve fills in defaults for a zero-valued policy.
func (b BackgroundPolicy) Resolve() BackgroundPolicy {
	if b.Grace == 0 {
		b.Grace = DefaultBackgroundGrace
	}
	if b.Wait == 0 {
		b.Wait = DefaultBackgroundWait
	} else if b.Wait < 0 {
		b.Wait = 0 // report without waiting
	}
	if b.TerminateGrace == 0 {
		b.TerminateGrace = DefaultTerminateGrace
	}
	return b
}

// Settle resolves work an agent CLI left running in its process group after it
// exited, and reports what happened. onWait, when set, is told once that the
// wait has begun (provider.Options.OnBackgroundWait).
//
// The problem it solves: an agent asked to train a model may start the
// training with `nohup ... &` and exit immediately, printing TASK_DONE. cloop
// then marks the task complete and runs the next one, which reads a model file
// that is still being written. Nothing errors — the work is just wrong, and no
// log cloop keeps says why. Watching the output pipes cannot catch this,
// because nohup redirects the child's descriptors and the pipes close on time.
//
// Waiting here rather than in the orchestrator is deliberate. It makes a
// provider's contract "when Complete returns, the work the harness started is
// finished", which fixes every caller at once — the sequential path, the
// parallel path, heal retries, evolve, and decompose all consume that result,
// and each would otherwise need the same wait bolted on.
//
// pgid is the CLI's pid: the providers start it with Setpgid.
func Settle(ctx context.Context, pgid int, policy BackgroundPolicy,
	onWait func(provider.BackgroundActivity)) *provider.BackgroundActivity {
	policy = policy.Resolve()
	if policy.Disabled {
		return nil
	}

	// Detach from the caller's deadline for the wait. ctx carries the task
	// timeout, and by this point the CLI has already exited: an expired
	// deadline should not turn "wait for the work to finish" into "return
	// immediately and report it as abandoned", which would mark a task
	// incomplete for the one reason it is not the task's fault.
	//
	// A cancellation is not a deadline (Task 20348). Stop, SIGINT or a manual
	// abort from the dashboard asks for the work to end now, and a wait that
	// ignored it kept a stopped project running for up to the whole budget —
	// the Stop button appeared to do nothing for half an hour. So the wait
	// ends with the request, and what is still running is terminated below
	// like work that outlived its budget: the task is about to be retried,
	// and the retry must not race these leftovers.
	waitCtx, stopWaiting := context.WithCancel(context.WithoutCancel(ctx))
	defer stopWaiting()
	unwatch := context.AfterFunc(ctx, func() {
		if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			stopWaiting()
		}
	})
	defer unwatch()

	out := procgroup.Drain(waitCtx, pgid, procgroup.DrainOptions{
		Grace:  policy.Grace,
		Budget: policy.Wait,
		OnDetect: func(members []procgroup.Process) {
			if onWait == nil {
				return
			}
			names := make([]string, 0, len(members))
			for _, m := range members {
				names = append(names, m.Command)
			}
			onWait(provider.BackgroundActivity{
				Detected: len(members),
				Commands: names,
			})
		},
	})
	if out.Detected == 0 {
		// A stop inside the grace window ends the wait before anything was
		// counted, so whatever the harness left behind is still running.
		// Terminate is a no-op on an empty group — and TerminateOrphaned
		// refuses one whose id has since gone to another process, which an
		// empty group's id is free to do.
		if waitCtx.Err() != nil && !policy.KeepOrphans && procgroup.Supported() {
			if _, err := procgroup.TerminateOrphaned(pgid, policy.TerminateGrace); err != nil {
				fmt.Fprintf(os.Stderr, "cloop: terminating background work from pgid %d: %v\n", pgid, err)
			}
		}
		return nil
	}

	activity := &provider.BackgroundActivity{
		Detected: out.Detected,
		Commands: out.Commands,
		Waited:   out.Waited,
		Drained:  out.Drained,
	}
	if out.Drained {
		return activity
	}

	// The work outlived its budget. Leaving it running is not the neutral
	// option: the processes are orphaned, attributable to no task, and a retry
	// of this task would start a second copy racing the first over the same
	// output files. Operators who want the opposite set KeepOrphans.
	if !policy.KeepOrphans {
		killed, err := procgroup.TerminateOrphaned(pgid, policy.TerminateGrace)
		activity.Terminated = killed
		if err != nil {
			// Report rather than fail: the caller is about to mark this task
			// incomplete anyway, and that is the outcome that matters.
			fmt.Fprintf(os.Stderr, "cloop: terminating background work from pgid %d: %v\n", pgid, err)
		}
	}
	return activity
}
