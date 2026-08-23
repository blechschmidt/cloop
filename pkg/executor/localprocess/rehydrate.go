// Reattaching to host processes a previous control plane forked (Task 20191).
//
// # The failure this removes
//
// The handle map is in-memory, so before this file a hub that restarted came
// up believing it had dispatched nothing while its children kept running. A
// forked child is not killed when its parent dies: the kernel reparents it to
// init and it carries on holding the CPU, the network and the project
// directory. Stream, Status and Signal all answered ErrHandleNotFound for it.
// The workload was simultaneously alive and unreachable — no output, no
// status, and no way to stop it short of the operator finding the pid by hand.
//
// # Why this driver recovers less than its siblings
//
// The container and Kubernetes drivers reattach *completely*, because the
// workload is owned by a runtime rather than by a process: `docker logs -f` and
// a Pod log GET attach to a workload nobody in this process started, and
// `docker wait` still yields its exit code. The host offers no equivalent. What
// survives here is only what the kernel tracks independently of parentage:
//
//	Liveness/Status  recoverable. procfs answers for any process, not just
//	                 our children.
//	Signal           recoverable, but only once identity is proven — see below.
//	Stream           NOT recoverable. The child's stdout and stderr were an
//	                 os.Pipe whose read end died with the previous process; the
//	                 write end the child still holds now goes nowhere. There is
//	                 no way to re-open it, so adopt says so in one line and does
//	                 not pretend otherwise.
//	Exit status      NOT recoverable. wait4 reports only to a parent, and this
//	                 process is not one. An adopted workload that exits is
//	                 finished as StateFailed with exit code -1 and an error that
//	                 names the reason, never as StateExited(0): a caller reads
//	                 the exit code to decide whether a task succeeded, and
//	                 guessing zero there would mark failed work as done.
//
// # Pid recycling is the hazard that shapes everything else
//
// A pid is a small recycled integer, not a name. Between the previous control
// plane dying and this one adopting the row, the child may have exited and its
// number been handed to something else — a database, an ssh session, the
// operator's shell. `os.FindProcess` plus `Signal(0)` cannot tell the
// difference, and acting on that answer means delivering SIGKILL to an
// unrelated process. That is not a degraded feature, it is the driver
// destroying something it was never asked to touch, so this file refuses to
// treat a bare pid as identity anywhere.
//
// The identity used instead is a pair, both recorded at dispatch and compared
// exactly at adoption:
//
//	starttime  /proc/<pid>/stat field 22, the process's start time in clock
//	           ticks since boot. It is assigned by the kernel at fork and never
//	           changes, so a recycled pid essentially always carries a different
//	           one. Comparing the raw tick count is deliberate: converting it to
//	           wall-clock to compare against HandleRecord.StartedAt would need
//	           the boot epoch and USER_HZ, and would then need a tolerance
//	           window to absorb both — which is a window in which a recycled pid
//	           is accepted. An opaque token compared for equality needs no
//	           tolerance and cannot be tuned wrong.
//	boot id    /proc/sys/kernel/random/boot_id, regenerated on every boot.
//	           It closes the one hole exact ticks leave: after a reboot the tick
//	           counter restarts from zero, so an early-boot process can hold both
//	           the same pid and the same starttime as a pre-reboot one. It is
//	           also the correct answer on its own — a reboot kills every child of
//	           the previous control plane, so a row from another boot must never
//	           be adopted.
//
// Anything that cannot be checked against that pair is treated as gone: the
// handle is finished as failed and its row deleted, which loses a status
// nobody could trust and keeps a row from being re-adopted and re-failed on
// every boot forever. The alternative — adopting on a weaker check — trades a
// missing status for the possibility of killing a stranger's process, and that
// is not a trade this driver gets to make on an operator's behalf.
//
// The check is re-run immediately before every signal, not only at adoption,
// because the window reopens continuously: an adopted process can exit at any
// time and its pid be reused before the watcher's next poll notices.

package localprocess

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const (
	// metaProcStartTicks is the HandleRecord.Meta key carrying /proc/<pid>/stat
	// field 22 for the dispatched child, rendered as decimal.
	//
	// It lives in Meta rather than in a typed column because it means nothing
	// outside this driver: no other driver has pids, and a sweep only needs to
	// know a row exists. It is not a secret — Meta is persisted verbatim — it
	// is a kernel counter that is public in /proc to every user on the host.
	metaProcStartTicks = "proc_start_ticks"

	// metaBootID is the HandleRecord.Meta key carrying the boot the pid was
	// allocated in. See the file header for why starttime alone is not enough.
	metaBootID = "boot_id"

	// procBootIDPath is the kernel's per-boot UUID. Present on every Linux with
	// procfs mounted, including inside containers, where it correctly reports
	// the *host* boot — which is what we want, since a pid namespace dies with
	// its processes and cannot outlive a reboot either way.
	procBootIDPath = "/proc/sys/kernel/random/boot_id"
)

// adoptPollInterval is how often an adopted record re-checks that its process
// is still there.
//
// Polling at all is forced rather than chosen. The exit of a process that is
// not our child produces no event we can wait for: wait4 answers only for our
// own children, and SIGCHLD is never delivered for one that init inherited.
// Both event-driven alternatives were rejected —
//
//   - the netlink proc connector does deliver real exit events, but opening it
//     requires CAP_NET_ADMIN, so a hub running as an ordinary user would lose
//     rehydration entirely instead of degrading;
//   - pidfd_open(2) yields a descriptor that becomes readable on exit and is
//     immune to pid recycling by construction, which is the right primitive.
//     Reaching it needs either golang.org/x/sys promoted from an indirect to a
//     direct dependency of this module, or raw syscall numbers in a driver that
//     otherwise contains none. It is the obvious follow-up and it is not worth
//     a dependency change here.
//
// One second is then chosen against what an interval costs and buys. A poll is
// one small procfs read (the boot id is read once per process and cached), so
// two hundred adopted handles cost single-digit milliseconds per second —
// under 0.2% of a core — and the number of adopted handles is bounded by how
// many workloads were in flight at the restart, not by uptime. What it buys is
// that an adopted run's stream closes and its status turns terminal within a
// second, comfortably inside the dashboard's own refresh cadence, so an
// operator never watches a process the driver still calls running. Nothing
// pushes the other way: the exit status is unrecoverable however fast we
// notice, so there is no race here worth winning by spinning.
const adoptPollInterval = time.Second

// Identity failures are separated because the caller's situation differs at
// each: gone means the workload is over and the row is spent, mismatch means
// the row now names somebody else's process and must never be acted on, and
// unverifiable means we hold no evidence either way and therefore must assume
// the worst.
var (
	errProcessGone      = errors.New("localprocess: the process is gone")
	errIdentityMismatch = errors.New("localprocess: the pid now belongs to a different process")
	errUnverifiable     = errors.New("localprocess: the process identity cannot be verified")
)

// procIdentity is what distinguishes "pid 1234, the child we forked" from
// "pid 1234, whatever holds that number now". See the file header.
type procIdentity struct {
	bootID     string
	startTicks uint64
}

// warnNoIdentityOnce bounds the "this host cannot support rehydration" warning
// to one line per process.
//
// The condition it reports is systemic rather than per-handle: capturing an
// identity fails when procfs is absent or unreadable, which is a property of
// the host (a non-Linux developer machine, a container with /proc masked) and
// is equally true of every workload the hub will ever start. Warning per Start
// would put a line in the log for every run on those hosts, which trains an
// operator to ignore the channel the warning arrives on.
var warnNoIdentityOnce sync.Once

// bootID reads the current boot's UUID once and memoises it.
//
// The value cannot change while this process lives — a reboot takes the
// process with it — so re-reading it on every poll would be pure syscall
// overhead. Memoising the *error* too is deliberate for the same reason: a
// missing or unreadable /proc/sys/kernel/random/boot_id is a property of the
// host's procfs, not a transient condition that retrying could clear.
var bootID = sync.OnceValues(func() (string, error) {
	raw, err := os.ReadFile(procBootIDPath)
	if err != nil {
		return "", fmt.Errorf("%w: read %s: %w", errUnverifiable, procBootIDPath, err)
	}
	id := strings.TrimSpace(string(raw))
	if id == "" {
		return "", fmt.Errorf("%w: %s is empty", errUnverifiable, procBootIDPath)
	}
	return id, nil
})

// probeProcess reads pid's identity and reports whether it is still executing.
//
// alive is false for a process that exists in the table but has finished: a
// zombie holds its pid until somebody reaps it, and its /proc entry (including
// a matching starttime) is fully readable. In production that state is
// transient — init reaps the children it inherited — but it is the *normal*
// state under test, where the adopting executor shares a process with the one
// that forked the child, so failing to treat Z as dead would leave adopted
// handles running forever in exactly the situation the tests exercise.
func probeProcess(pid int) (id procIdentity, alive bool, err error) {
	if pid <= 0 {
		return procIdentity{}, false, fmt.Errorf("%w: %d is not a pid", errUnverifiable, pid)
	}
	boot, err := bootID()
	if err != nil {
		return procIdentity{}, false, err
	}
	state, ticks, err := readProcStat(pid)
	if err != nil {
		return procIdentity{}, false, err
	}
	return procIdentity{bootID: boot, startTicks: ticks}, aliveState(state), nil
}

// readProcStat returns pid's run state (field 3) and start time (field 22)
// from /proc/<pid>/stat.
func readProcStat(pid int) (state string, startTicks uint64, err error) {
	path := "/proc/" + strconv.Itoa(pid) + "/stat"
	raw, err := os.ReadFile(path)
	if err != nil {
		// Not wrapped in a sentinel: the caller distinguishes "no such process"
		// from "procfs is unreadable" via fs.ErrNotExist, and flattening the two
		// here would turn a missing /proc mount into a claim that every adopted
		// workload had exited.
		return "", 0, fmt.Errorf("read %s: %w", path, err)
	}
	state, startTicks, err = parseProcStat(string(raw))
	if err != nil {
		return "", 0, fmt.Errorf("%w: %s: %w", errUnverifiable, path, err)
	}
	return state, startTicks, nil
}

// parseProcStat pulls fields 3 (state) and 22 (starttime) out of one
// /proc/<pid>/stat line.
//
// The parse looks unusual because the file's second field is the executable
// name in parentheses and is *not* escaped: a program named "evil ) 0 R" puts
// spaces and parentheses straight into the line, so splitting on whitespace
// from the left misaligns every field after it and would read some
// caller-chosen number as the start time — which is the number that authorises
// signalling a pid, so getting it wrong is the one bug in this file with a body
// count. Scanning to the *last* ')' is the documented way to parse this file
// (it is what procps does) and is exact, because every remaining field is
// numeric or a single character and none of them can contain a parenthesis.
//
// Split out from readProcStat purely so this can be tested against a hostile
// comm without having to run a process named after one.
func parseProcStat(line string) (state string, startTicks uint64, err error) {
	end := strings.LastIndexByte(line, ')')
	if end < 0 || end+1 >= len(line) {
		return "", 0, errors.New("not in the expected format: no comm field")
	}
	// Fields after comm are 1-indexed from 3, so field N is at index N-3:
	// state is index 0, starttime (field 22) is index 19.
	fields := strings.Fields(line[end+1:])
	const startTimeIdx = 19
	if len(fields) <= startTimeIdx {
		return "", 0, fmt.Errorf("has %d fields after comm, want more than %d", len(fields), startTimeIdx)
	}
	ticks, err := strconv.ParseUint(fields[startTimeIdx], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("field 22 = %q: %w", fields[startTimeIdx], err)
	}
	return fields[0], ticks, nil
}

// aliveState maps the single-character process state to "still executing".
//
// Z (zombie) and X/x (dead) are the only states that mean the program has
// finished; R, S, D, T, t, I and the rest are all running, sleeping or stopped
// processes that will produce more work. Stopped (T) counts as alive on
// purpose: a workload suspended under a debugger has not exited, and finishing
// its handle would close the stream on a run that can still resume.
func aliveState(state string) bool {
	switch state {
	case "Z", "X", "x":
		return false
	default:
		return state != ""
	}
}

// meta renders the identity for HandleRecord.Meta. It returns nil for a zero
// identity so a row whose identity could not be captured carries no misleading
// empty keys — identityFromMeta then correctly reports it as unverifiable.
func (id procIdentity) meta() map[string]string {
	if id.bootID == "" {
		return nil
	}
	return map[string]string{
		metaBootID:         id.bootID,
		metaProcStartTicks: strconv.FormatUint(id.startTicks, 10),
	}
}

// identityFromMeta parses back what meta wrote. A row missing either half is
// an error rather than a partially-trusted identity: half a token proves
// nothing, and the caller's response to "unverifiable" is the safe one.
func identityFromMeta(meta map[string]string) (procIdentity, error) {
	boot := strings.TrimSpace(meta[metaBootID])
	ticksRaw := strings.TrimSpace(meta[metaProcStartTicks])
	if boot == "" || ticksRaw == "" {
		return procIdentity{}, fmt.Errorf(
			"%w: the persisted row carries no %s/%s pair, so there is no way to tell this pid "+
				"from a recycled one", errUnverifiable, metaBootID, metaProcStartTicks)
	}
	ticks, err := strconv.ParseUint(ticksRaw, 10, 64)
	if err != nil {
		return procIdentity{}, fmt.Errorf("%w: %s=%q: %w", errUnverifiable, metaProcStartTicks, ticksRaw, err)
	}
	return procIdentity{bootID: boot, startTicks: ticks}, nil
}

// verify reports nil only when pid is still executing *and* is still the same
// process the identity was captured from.
//
// The checks are ordered so the error names the most specific true cause: a
// reboot explains everything at once and is reported as such rather than as a
// per-pid mismatch, and a right-process-but-exited zombie is reported as gone
// rather than as somebody else's pid.
func (want procIdentity) verify(pid int) error {
	got, alive, err := probeProcess(pid)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: pid %d is not in the process table", errProcessGone, pid)
		}
		if errors.Is(err, errUnverifiable) {
			return err
		}
		// Anything else — a permission error, a procfs that is not mounted — is
		// a failure to *look*, not evidence that the process ended. Classifying
		// it as unverifiable rather than as gone is what makes the caller's
		// three-way message switch total, and keeps "we could not check" from
		// being reported to an operator as "your run exited".
		return fmt.Errorf("%w: %w", errUnverifiable, err)
	}
	if got.bootID != want.bootID {
		return fmt.Errorf("%w: the host rebooted since dispatch (boot %s, now %s), so every child of "+
			"the previous control plane is gone", errProcessGone, want.bootID, got.bootID)
	}
	if got.startTicks != want.startTicks {
		return fmt.Errorf("%w: pid %d started at %d clock ticks but this handle recorded %d — the pid "+
			"was recycled and now belongs to an unrelated process, which must not be signalled",
			errIdentityMismatch, pid, got.startTicks, want.startTicks)
	}
	if !alive {
		return fmt.Errorf("%w: pid %d has exited and is waiting to be reaped", errProcessGone, pid)
	}
	return nil
}

// AttachHandleStore installs the durable handle store and immediately
// reattaches to whatever it describes.
//
// It is the *primary* wiring path for this driver, not the fallback it is for
// the container and Kubernetes drivers. Those are built from configuration and
// can take an Options.HandleStore at construction; this one is a process-wide
// singleton reached through Shared(), whose New(id) signature is fixed by every
// existing caller and takes no options at all. Adding a store-aware constructor
// beside it would leave two ways to build the same singleton and no way to make
// the Shared() path use the new one, so the store is installed after
// construction instead — which the boot order wanted anyway, since the state
// database that backs the store is opened long after the executor registry is
// built.
//
// Calling it more than once is safe, including with a different store: see
// rehydrate for why re-adoption cannot produce a duplicate watcher.
//
// A nil store is ignored rather than clearing the current one. "Forget how to
// find your processes" is not something a caller should be able to ask for by
// passing a zero value.
func (e *Executor) AttachHandleStore(store executor.HandleStore) {
	if e == nil || store == nil {
		return
	}
	e.mu.Lock()
	e.store = store
	e.mu.Unlock()
	e.rehydrate()
}

// handleStore returns the durable store, or nil when the embedder gave none.
// Every caller goes through this rather than reading e.store directly:
// AttachHandleStore writes the field while pumps and watchers are running.
func (e *Executor) handleStore() executor.HandleStore {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.store
}

// rehydrate rebuilds live bookkeeping for every persisted handle this executor
// is not already tracking.
//
// Idempotence is a requirement rather than a nicety, and it matters more here
// than for the siblings because this driver is a singleton: Shared() is reached
// from the CLI bootstrap, from ui.New and from tests, and any of them may
// attach a store. Two adoptions of one row would mean two watcher goroutines
// polling the same pid and racing to finish the same record — the loser being
// swallowed by finish's closed guard, so the visible symptom would be nothing
// at all until one of them deleted a row the other still needed.
//
// Skipping by handle ID is what makes that safe: a row whose ID is already in
// e.handles either belongs to a workload this process forked or has already
// been adopted, and both are fully tracked already.
//
// Failure to read the store is not propagated — LoadHandles reports it and
// returns nothing — because a hub that refuses to start over an unreadable
// handle table is strictly worse than one that starts having forgotten some
// processes. Forgetting them is the pre-Task-20191 behaviour, which is the
// floor, not a new failure.
func (e *Executor) rehydrate() {
	store := e.handleStore()
	if store == nil {
		return
	}
	for _, saved := range executor.LoadHandles(store, e.id) {
		e.adopt(saved)
	}
}

// adopt rebuilds one record from its persisted identity and puts a liveness
// watcher on it.
//
// Unlike the container driver's adopt, this one verifies *before* it starts
// anything, on the caller's goroutine. It can afford to: the check is a single
// procfs read of a few microseconds, not a runtime round-trip, so it does not
// put I/O on the path a hub must finish before serving. And it must, because
// the result decides what the handle's first line of output says — an adopted
// handle that turns out to name a recycled pid has to say so in the same place
// the operator went looking for its logs, not silently sit in "running" until a
// watcher tick corrects it.
//
// A record is inserted even when verification fails. The alternative — dropping
// the row and letting Status answer ErrHandleNotFound — is what this whole file
// exists to abolish: the caller is holding a handle ID from executor_sessions
// and is entitled to an answer about it, and "failed: the pid was recycled" is
// an answer while "no such handle" is the hub disclaiming a run it dispatched.
func (e *Executor) adopt(saved executor.HandleRecord) {
	if err := saved.Validate(); err != nil {
		// A row with no external ID names no process. Adopting it would create a
		// handle whose every operation fails against pid 0; dropping it loses
		// nothing, because there was never anything it could be resolved to.
		fmt.Fprintf(os.Stderr, "localprocess: ignoring unusable persisted handle: %v\n", err)
		return
	}
	if d := strings.TrimSpace(saved.Driver); d != "" && d != executor.KindLocalProcess {
		// Rows are scoped by executor ID and the registry forbids two executors
		// sharing one, so this should be unreachable. It is checked anyway
		// because the way to reach it — an operator renaming a container
		// executor onto this one's old ID — would have this driver read a
		// container name as a pid, and a failed Atoi is the *lucky* outcome
		// there.
		fmt.Fprintf(os.Stderr, "localprocess: executor %q ignoring handle %s: it belongs to the %s driver\n",
			e.id, saved.HandleID, d)
		return
	}

	pid := saved.PID
	if pid <= 0 {
		// PID is the typed field the liveness check wants, but ExternalID is the
		// one HandleRecord.Validate guarantees is present, and for this driver
		// the two carry the same number. Falling back keeps a row written by a
		// path that populated only the required field adoptable.
		if n, err := strconv.Atoi(strings.TrimSpace(saved.ExternalID)); err == nil {
			pid = n
		}
	}
	if pid <= 0 {
		fmt.Fprintf(os.Stderr, "localprocess: executor %q dropping handle %s: %q is not a pid\n",
			e.id, saved.HandleID, saved.ExternalID)
		executor.ForgetHandle(e.handleStore(), saved.HandleID)
		return
	}

	want, identErr := identityFromMeta(saved.Meta)
	verifyErr := identErr
	if verifyErr == nil {
		verifyErr = want.verify(pid)
	}

	rec := &record{
		id:        saved.HandleID,
		pid:       pid,
		startedAt: saved.StartedAt,
		// Running is a claim, not an observation, only for the instant between
		// here and the finish below; verification has already happened, so a
		// record that is about to be failed is never published as running for
		// long enough for a caller to read it.
		state:       executor.StateRunning,
		subscribers: make(map[*subscriber]struct{}),
		// Non-nil marks this record as adopted, which is what Signal keys its
		// re-verification off. It is set even when the identity could not be
		// parsed: the zero value's empty boot id can never equal a real one, so
		// an unparsable row degrades to a record that refuses to signal rather
		// than to one that signals unchecked.
		adopted: &want,
	}

	e.mu.Lock()
	if _, exists := e.handles[rec.id]; exists {
		// The idempotency guarantee AttachHandleStore documents. It also covers
		// the case that matters more: a handle this process forked itself, whose
		// row a failed delete left behind. Re-adopting it would walk a live
		// record backwards over a fresh one and put a second watcher on a pid
		// the pump is already reaping.
		e.mu.Unlock()
		return
	}
	e.handles[rec.id] = rec
	// Adopted records are running and pruneLocked only evicts terminal ones, so
	// this can trim the finished residue of an earlier run but can never evict
	// the workload just reattached to.
	e.pruneLocked()
	e.mu.Unlock()

	if verifyErr != nil {
		msg := adoptionFailureMessage(pid, verifyErr)
		rec.emit("[cloop] " + msg + "\n")
		// Terminal, so finish drops the row — which is the point. A row nothing
		// can reattach to would otherwise be re-adopted and re-failed on every
		// boot for as long as the database survives.
		e.finish(rec, executor.StateFailed, -1, msg)
		return
	}

	// The one honest line this driver can offer in place of the lost pipe. It
	// goes through emit, so it lands in the replay buffer and is delivered to
	// every subscriber that attaches later, exactly like real output would be —
	// there is no separate "notice" channel to keep in step with the log path.
	rec.emit(fmt.Sprintf("[cloop] the control plane restarted while this workload was running. Its live "+
		"output was lost with the pipe that carried it and cannot be recovered; the process (pid %d) is "+
		"still running and is being watched, and this stream will close when it exits.\n", pid))

	// Re-arm the timeout. The deadline is persisted as an absolute instant, so
	// what resumes is the *remaining* time: a hub down for twenty minutes gives
	// a one-hour workload its last forty rather than restarting the hour, which
	// is what a persisted duration would have done.
	//
	// A deadline already in the past arms at zero and kills on the next tick.
	// That is intended — the timeout expired, and nobody having been there to
	// enforce it is not a reprieve — and it is safe only because verification
	// has already passed above: an unverified row never reaches this line, so
	// the pid this timer will signal is provably still the process that was
	// dispatched and not a stranger that inherited the number.
	if !saved.Deadline.IsZero() {
		e.armKillTimer(rec, time.Until(saved.Deadline),
			fmt.Sprintf("timeout expired at %s (deadline resumed after a control-plane restart)",
				saved.Deadline.UTC().Format(time.RFC3339)))
	}

	go e.watchAdopted(rec)
}

// adoptionFailureMessage turns a verification failure into the sentence an
// operator reads in the run's log and in Status.Error.
//
// The three cases get different text because the operator's next move differs:
// a recycled pid means the run's outcome is lost *and* that something else is
// now using that number, an unverifiable row means the driver declined on
// purpose and nothing is wrong with the host, and a plain absence means the run
// simply ended while nobody was watching.
func adoptionFailureMessage(pid int, err error) string {
	switch {
	case errors.Is(err, errIdentityMismatch):
		return fmt.Sprintf("this workload could not be reattached to after a control-plane restart: %v. "+
			"The original process ended while the control plane was down, so its outcome is unrecoverable; "+
			"nothing was signalled", err)
	case errors.Is(err, errUnverifiable):
		return fmt.Sprintf("this workload could not be reattached to after a control-plane restart: %v. "+
			"Reattaching without that proof could signal an unrelated process that inherited pid %d, so the "+
			"handle is reported failed instead", err, pid)
	default:
		return fmt.Sprintf("this workload could not be reattached to after a control-plane restart: %v. "+
			"It exited while the control plane was not its parent, so its exit status could not be collected", err)
	}
}

// watchAdopted polls an adopted process and finishes its record when it goes
// away. It is the substitute for the cmd.Wait() a forked record gets, and the
// substitute is strictly worse: it learns *that* the process ended, never with
// what status.
func (e *Executor) watchAdopted(rec *record) {
	defer func() {
		if r := recover(); r != nil {
			// A panic here would strand the handle in "running" forever and leak
			// every subscriber channel attached to it — the same failure the
			// output pump's recover exists to prevent.
			fmt.Fprintf(os.Stderr, "localprocess: adopted-process watcher panic recovered (handle %s): %v\n",
				rec.id, r)
			e.finish(rec, executor.StateFailed, -1, fmt.Sprintf("adopted-process watcher panic: %v", r))
		}
	}()

	ticker := time.NewTicker(adoptPollInterval)
	defer ticker.Stop()
	for range ticker.C {
		// Signal's own verification can finish this record between ticks. Exiting
		// on the record rather than on a dedicated channel keeps the adopted path
		// from adding a field every other record would carry unused; the cost is
		// that the goroutine lives up to one extra tick, which is a goroutine
		// bounded by the number of workloads in flight at the restart.
		if rec.finished() {
			return
		}
		if err := rec.adopted.verify(rec.pid); err != nil {
			msg := watchFailureMessage(rec.pid, err)
			rec.emit("[cloop] " + msg + "\n")
			e.finish(rec, executor.StateFailed, -1, msg)
			return
		}
	}
}

// watchFailureMessage explains why a watched process stopped being watchable.
//
// StateFailed with this text is the honest terminal state for a workload that
// may well have succeeded: the exit code is genuinely unknown, and the whole
// scheduling layer reads exit codes to decide whether a task is done. Reporting
// StateExited(0) would be the same lie with a better mood.
func watchFailureMessage(pid int, err error) string {
	if errors.Is(err, errIdentityMismatch) {
		return fmt.Sprintf("this workload's process ended and its pid was reused: %v. The control plane "+
			"had reattached to it after a restart and was never its parent, so no exit status was available", err)
	}
	return fmt.Sprintf("this workload's process (pid %d) has exited: %v. The control plane had reattached "+
		"to it after a restart and was never its parent, so its exit status could not be collected", pid, err)
}

// taskIDFromLabels extracts the cloop task ID a Spec was dispatched for.
//
// executor.Spec has no typed task field — task identity travels in Labels under
// "task_id" — so this is a parse, not a field read. It duplicates the container
// driver's helper of the same name deliberately: importing a sibling driver to
// share six lines would couple two independent executors, and the key list is
// the thing that must stay identical, which a shared comment enforces better
// than a shared function that either driver could change alone.
//
// Zero means "not task-bound", which is the honest answer for a voice-handler
// invocation or a hand-driven run and is exactly what HandleRecord.TaskID
// documents zero to mean.
func taskIDFromLabels(labels map[string]string) int {
	for _, key := range []string{"task_id", "task", "taskid"} {
		if n, err := strconv.Atoi(strings.TrimSpace(labels[key])); err == nil && n > 0 {
			return n
		}
	}
	return 0
}
