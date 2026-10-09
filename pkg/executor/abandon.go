package executor

import "context"

// Abandoner is implemented by a driver that can give up a workload the control
// plane failed over elsewhere (Task 20396).
//
// When the supervisor declares a node lost it claims the sessions stranded on
// it, and from that moment their workloads are no longer the runs of their
// projects: the tasks they held went back to pending, and a replacement may
// already be running them somewhere else. The stranded workload itself is out
// of reach — that is why it was failed over — but it is not necessarily dead.
// A device that was only cut off comes back with it still running, and a
// driver that resumes it puts a second harness on the same tasks.
//
// Abandon is how the hub says so to the driver: stop the workload now if it
// can still be reached; end its output stream and report it terminal, so that
// everything on the hub waiting on it lets go — the run's own watchers, and
// with them the credential lease it held; and refuse it when its executor
// comes back offering to resume it. reason is operator-facing and ends up in
// the workload's last status.
//
// A driver without it is asked to kill the workload instead, which is all the
// hub can do for one it cannot reach.
type Abandoner interface {
	Abandon(ctx context.Context, handleID, reason string) error
}
