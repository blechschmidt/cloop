// Package procgroup inspects and drains POSIX process groups.
//
// It exists to answer one question the orchestrator could not previously ask:
// when an agent harness exits, did it leave work running behind it?
//
// The failure this addresses is subtle and silent. A harness told to "train the
// model" may start the training in the background and exit immediately —
// `nohup python train.py &` — at which point cloop reads TASK_DONE off its
// stdout, marks the task complete, and starts the next one. The next task then
// operates on a model file that does not exist yet. Nothing errors; the work
// is simply wrong, and the reason is invisible in every log cloop keeps.
//
// The handle that makes detection possible is that the harness is started in
// its own process group (see pkg/provider/claudecode, which sets Setpgid).
// Everything it forks inherits that group ID, so after the harness itself is
// reaped, any process still reporting that PGID is work the task left running.
// That is a far better signal than watching the output pipes: a background
// child that redirects its own stdout — which nohup does by default — closes
// the inherited descriptors immediately and is invisible to a pipe-EOF check.
//
// # Known limits
//
// A child that calls setsid() leaves the group and becomes undetectable here.
// That is deliberate rather than a gap worth closing: setsid is the explicit
// gesture for "I am a daemon and I intend to outlive my parent", and the case
// this package exists to catch is the opposite one, where the work was meant
// to be waited for and simply was not.
//
// Detection is Linux-only, because it reads procfs. On other systems Members
// reports Supported() == false and the callers degrade to their previous
// behaviour rather than guessing; see Drain for what that means in practice.
package procgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Process is one live member of a process group.
type Process struct {
	PID int
	// Command is the executable name from procfs (the "comm" field), which is
	// truncated to 15 characters by the kernel. It is for operator diagnosis
	// only — never for matching, since it is neither unique nor complete.
	Command string
}

// Supported reports whether process-group inspection works on this platform.
// Only Linux is implemented, via procfs.
func Supported() bool { return runtime.GOOS == "linux" }

// procRoot is the procfs mount point. A variable so tests can point it at a
// fixture directory instead of the live kernel — the alternative would be
// tests that can only assert against whatever happens to be running on the
// machine, which is neither deterministic nor able to cover the hostile-comm
// and zombie cases below.
var procRoot = "/proc"

// Members returns the live processes in process group pgid, excluding the
// caller's own process.
//
// Zombies are excluded: a process in state Z has finished its work and is
// waiting only to be reaped, so counting it would make a drain loop wait for
// something that will never change. Orphans are reparented to init, which
// reaps them promptly.
//
// A nil error with an empty slice means the group is empty. On platforms
// without procfs it returns ErrUnsupported.
func Members(pgid int) ([]Process, error) {
	if !Supported() {
		return nil, ErrUnsupported
	}
	if pgid <= 0 {
		return nil, fmt.Errorf("procgroup: invalid pgid %d", pgid)
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("procgroup: read %s: %w", procRoot, err)
	}
	self := os.Getpid()
	var members []Process
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue // not a pid directory
		}
		if pid == self {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "stat"))
		if err != nil {
			// The process exited between ReadDir and ReadFile. That is the
			// common case in a directory listing of live processes, not an
			// error: an exited process is exactly what we are waiting for.
			continue
		}
		comm, state, gotPGID, err := parseStat(string(raw))
		if err != nil || gotPGID != pgid {
			continue
		}
		if state == "Z" {
			continue
		}
		members = append(members, Process{PID: pid, Command: comm})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].PID < members[j].PID })
	return members, nil
}

// parseStat pulls the comm, state and pgrp fields out of one /proc/<pid>/stat
// line.
//
// The parse scans to the *last* ')' rather than splitting on whitespace,
// because the second field is the executable name, is unescaped, and is
// attacker-chosen: a binary named "x ) 0 R 1 1" injects spaces and parentheses
// straight into the line and misaligns every field after it under a naive
// split. Since the misaligned field here decides whether a process counts as
// somebody's background work — and, downstream, whether a group gets
// SIGKILLed — reading a caller-chosen number would be a real bug rather than a
// cosmetic one. Scanning to the last ')' is exact and is what procps does:
// every remaining field is numeric or a single character, so none of them can
// contain a parenthesis.
func parseStat(line string) (comm, state string, pgid int, err error) {
	open := strings.IndexByte(line, '(')
	closeIdx := strings.LastIndexByte(line, ')')
	if open < 0 || closeIdx < 0 || closeIdx < open {
		return "", "", 0, fmt.Errorf("procgroup: malformed stat line")
	}
	comm = line[open+1 : closeIdx]
	// Fields after comm start at field 3 (state); pgrp is field 5.
	rest := strings.Fields(line[closeIdx+1:])
	if len(rest) < 3 {
		return "", "", 0, fmt.Errorf("procgroup: stat line truncated (%d fields after comm)", len(rest))
	}
	state = rest[0]
	pgid, err = strconv.Atoi(rest[2])
	if err != nil {
		return "", "", 0, fmt.Errorf("procgroup: unparsable pgrp %q: %w", rest[2], err)
	}
	return comm, state, pgid, nil
}

// DrainOptions tunes how long Drain is willing to wait.
type DrainOptions struct {
	// Grace is how long a survivor may live before it counts as real
	// background activity. Harnesses routinely leave short-lived children
	// mid-teardown, and reporting those as abandoned work would make the
	// signal useless. Zero disables the grace window.
	Grace time.Duration
	// Budget bounds the total wait. Zero means do not wait at all: detect and
	// report, but return immediately.
	Budget time.Duration
	// Poll is the interval between group scans. Zero selects a default.
	Poll time.Duration
	// OnDetect, if set, is called once when real background work is confirmed
	// — after the grace window, before the wait begins. It exists so callers
	// can surface the wait while it is happening: a task that blocks for
	// twenty minutes on someone else's training run should not look identical
	// to one that is merely slow.
	OnDetect func(members []Process)
}

// Outcome describes what a Drain found and how it ended.
type Outcome struct {
	// Detected is how many processes were still running after the grace
	// window. Zero means the harness left nothing behind.
	Detected int
	// Commands names what was running, for operator diagnosis. Bounded.
	Commands []string
	// Waited is how long Drain actually blocked.
	Waited time.Duration
	// Drained is true when the group emptied on its own. When Detected > 0
	// and Drained is false, work outlived the budget and the task that
	// started it cannot be considered finished.
	Drained bool
	// Survivors are the processes still alive when the budget expired.
	Survivors []Process
}

// Clean reports whether the harness exited without leaving work behind, or
// left work that finished while we waited. Either way the task's output is
// trustworthy.
func (o Outcome) Clean() bool { return o.Detected == 0 || o.Drained }

// maxReportedCommands bounds Outcome.Commands. A runaway fan-out can leave
// hundreds of processes and the list is read by humans; the count in Detected
// carries the magnitude.
const maxReportedCommands = 10

// ErrUnsupported is returned by Members on platforms without procfs.
var ErrUnsupported = fmt.Errorf("procgroup: process-group inspection unsupported on %s", runtime.GOOS)

// Drain waits for process group pgid to empty, and reports what it found.
//
// The sequence is a scan, then — only if that scan finds something — the
// grace window and a second scan, and only if survivors remain after that, a
// polling wait until the group empties (Drained) or the budget expires
// (survivors reported).
//
// Scanning before sleeping is what keeps this affordable. The overwhelmingly
// common case is a harness that left nothing behind, and it costs one procfs
// walk of a few milliseconds; paying the grace window up front instead would
// tax every task in every project for a condition almost none of them are in.
// An empty first scan is conclusive rather than merely likely, because a new
// background process can only be forked by an existing member of the group.
//
// Drain never kills anything — that decision belongs to the caller, which
// knows whether the work is worth preserving. It also never returns an error:
// on a platform or a procfs it cannot read, it reports a zero Outcome, which
// callers correctly read as "nothing detected". Degrading to the previous
// behaviour is the right failure mode for a safety net; refusing to run a task
// because procfs was unreadable would not be.
func Drain(ctx context.Context, pgid int, opts DrainOptions) Outcome {
	if !Supported() || pgid <= 0 {
		return Outcome{}
	}
	poll := opts.Poll
	if poll <= 0 {
		poll = 250 * time.Millisecond
	}
	start := time.Now()

	// Fast path: nothing survived the harness at all.
	members, err := Members(pgid)
	if err != nil || len(members) == 0 {
		return Outcome{}
	}

	// Something is there. Give it the grace window to finish exiting before
	// calling it background work — harnesses routinely leave children a few
	// milliseconds behind them during teardown.
	if opts.Grace > 0 {
		if !sleepCtx(ctx, opts.Grace) {
			return Outcome{Waited: time.Since(start)}
		}
		members, err = Members(pgid)
		if err != nil || len(members) == 0 {
			return Outcome{Waited: time.Since(start)}
		}
	}

	out := Outcome{
		Detected: len(members),
		Commands: commandNames(members),
	}
	if opts.OnDetect != nil {
		opts.OnDetect(members)
	}

	deadline := start.Add(opts.Grace + opts.Budget)
	for {
		if time.Now().After(deadline) {
			break
		}
		if !sleepCtx(ctx, poll) {
			break
		}
		members, err = Members(pgid)
		if err != nil {
			break
		}
		if len(members) == 0 {
			out.Drained = true
			out.Waited = time.Since(start)
			return out
		}
	}

	out.Survivors = members
	out.Waited = time.Since(start)
	return out
}

// commandNames summarises a member list for humans, deduplicated and bounded.
func commandNames(members []Process) []string {
	seen := make(map[string]bool, len(members))
	var names []string
	for _, m := range members {
		name := m.Command
		if name == "" {
			name = "pid " + strconv.Itoa(m.PID)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
		if len(names) >= maxReportedCommands {
			break
		}
	}
	return names
}

// sleepCtx sleeps for d, returning false if ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Terminate signals every member of process group pgid, escalating from
// SIGTERM to SIGKILL after grace, and reports how many processes were alive
// when it started.
//
// Callers use this when background work outlived its budget. Leaving it
// running is not a neutral choice: the processes are orphaned, unattributable
// to any task, and a retry of the same task would start a second copy racing
// the first over the same output files.
//
// It refuses to signal its own process group. That guard is the reason this is
// a function rather than an inline syscall.Kill: cloop's control plane runs as
// a long-lived service, a negative-pid kill is applied to every member of the
// group, and a pgid that had been defaulted or mis-parsed to the caller's own
// group would take down the service and every other project it is running.
func Terminate(pgid int, grace time.Duration) (int, error) {
	if !Supported() {
		return 0, ErrUnsupported
	}
	if pgid <= 1 {
		return 0, fmt.Errorf("procgroup: refusing to signal process group %d", pgid)
	}
	if own, err := syscall.Getpgid(os.Getpid()); err == nil && pgid == own {
		return 0, fmt.Errorf("procgroup: refusing to signal own process group %d", pgid)
	}

	members, err := Members(pgid)
	if err != nil {
		return 0, err
	}
	if len(members) == 0 {
		return 0, nil
	}

	// Signal the group rather than each pid: a member that forks while we are
	// iterating would be missed by a per-pid sweep, and the group is exactly
	// the set we mean.
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
		return len(members), fmt.Errorf("procgroup: SIGTERM group %d: %w", pgid, err)
	}

	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		if remaining, err := Members(pgid); err == nil && len(remaining) == 0 {
			return len(members), nil
		}
	}

	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
		// ESRCH means the group drained between the check and the signal,
		// which is success, not failure.
		if errors.Is(err, syscall.ESRCH) {
			return len(members), nil
		}
		return len(members), fmt.Errorf("procgroup: SIGKILL group %d: %w", pgid, err)
	}
	return len(members), nil
}
