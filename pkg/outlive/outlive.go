// Package outlive lets a long-running cloop process survive the death of the
// control plane that started it.
//
// # The failure
//
// The hub does not hand a run the terminal's stdout. It creates a pipe, gives
// the run's file descriptors 1 and 2 to the write end, and drains the read end
// into the live-log panel (see pkg/executor/localprocess). That is what makes
// output streamable, and it also couples the run's life to the hub's: when the
// hub dies, the read end dies with it, and the pipe is broken.
//
// A broken pipe is normally an error on a write. On descriptors 1 and 2 it is
// not — the Go runtime treats SIGPIPE there as fatal and unrecoverable, on the
// reasoning that a filter whose consumer has gone away should stop rather than
// shout into a void. That is the right default for `cloop status | head`. It is
// the wrong one for a run, which is not a filter: its output is a side effect
// and its real product is committed to the database.
//
// So the sequence that stalled projects looked like this. The host runs out of
// memory and the kernel kills the hub. The run is orphaned but healthy, and
// keeps working — it holds no reference to the hub, and its writes to state.db
// keep succeeding. Then it finishes a task and logs a line about it, and that
// log line kills it. The work is committed; the outcome that would have named
// the work finished is not. The plan is left with a task nothing will finish
// and a project status that says "running" with nothing behind it.
//
// That is not a hypothetical. It is how the liebid and meta-ai-glasses-linux
// projects both stalled on 2026-09-11, each within three seconds of a
// successful database write, after the hub was OOM-killed out from under them.
// meta-ai-glasses-linux had two tasks left to run and never ran them.
//
// Note that the deployment already intends the opposite. Both hub units set
// systemd's KillMode=process precisely so that "`cloop run` children spawned
// from this dashboard must survive a restart of the dashboard itself", and
// systemd honours it: the journal shows the orphans left alive, by name. They
// died anyway, a little later, of a log line. This package is the half of that
// intent that was missing.
//
// # The fix, and why it is one line
//
// Registering to receive SIGPIPE changes the runtime's disposition for it: a
// write to a broken descriptor 1 or 2 returns EPIPE to the caller instead of
// killing the process. Nothing in cloop's output path checks that error, and
// nothing needs to — fmt.Print to a dead pipe becoming a silent no-op is
// exactly the desired behaviour. The run stops being heard and carries on being
// useful, finishes its task, writes its terminal status, and exits cleanly. A
// hub that restarts then finds a live run, leaves it alone, and picks the
// stream back up.
//
// # What this does not replace
//
// Recovery still matters. A run can still be killed outright — it is a process
// on a host that ran out of memory, and it may be the one the kernel picks.
// pkg/taskrecover repairs the tasks such a run strands and the hub repairs the
// status it leaves behind. The difference is that those become the exception
// they were meant to be, rather than the routine cost of every hub restart.
package outlive

// ControlPlane makes this process survive losing the control plane that
// spawned it, so that work already in flight runs to completion and records
// its outcome.
//
// Call it once, early, from a command that owns durable state and is expected
// to outlive a single connection — `cloop run` above all. Do not call it from a
// short-lived command whose output *is* its result: dying on a broken pipe is
// the correct, and expected, behaviour for a filter.
//
// It is safe to call more than once and never returns an error: there is no
// failure mode worth propagating, and a process that could not arrange to
// survive should still try to do its work.
func ControlPlane() {
	keepStdioWritesNonFatal()
}
