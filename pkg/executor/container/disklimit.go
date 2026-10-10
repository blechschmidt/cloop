package container

// disklimit.go holds a container workload to its disk limit (Task 20405).
//
// The image's root filesystem is mounted read-only and /tmp is a tmpfs capped
// by tmpfsScratchMB, so the work lands in the workspace — the project directory
// mounted at /workspace, or a feature's staged checkout and its output
// directory — on the host's own disk. That tree is what resources.disk and the
// operator's disk ceiling bound: the project's .cloop/ counted by what the run
// adds to it, since the sandbox can write there too. No runtime flag bounds a
// bind mount, so the driver measures it (pkg/executor/internal/diskwatch):
//
//   - at Start, before anything is provisioned: a tree already over the limit
//     is refused with both sizes and how to raise the limit, the meaning the
//     provisioner's post-fetch check gives a fetched tree;
//   - while the workload runs, on an interval that adapts to how close the
//     tree is to the limit and is bounded below by the cost of the last walk;
//   - and once a sample is over the limit, the workload is stopped, and its
//     status says so: OutcomeDiskLimit, with the measurement, which the hub
//     turns into the task's reason, a journal row and the run's pause.
//
// It is enforcement by measurement, not a quota: a burst can overshoot by the
// write rate times the interval before the next sample sees it. That is why
// the free-space floor (Task 20381) still matters. Kata and gVisor sandboxes
// write the same bind mount, so a walk from the host stays correct under them.

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/diskwatch"
)

const (
	// metaDiskLimit, metaDiskSource and metaDiskBaseline carry a workload's
	// disk limit with its persisted handle, so a restarted hub resumes
	// sampling the workload it adopts instead of leaving it unbounded — an
	// adopted container is tracked, so the orphan sweep would never collect
	// it either.
	metaDiskLimit    = "disk_limit_mb"
	metaDiskSource   = "disk_limit_source"
	metaDiskBaseline = "disk_state_baseline"
	// metaDiskBreach is the measurement a stop was made at, written before
	// the kill: a hub that dies between the SIGKILL and recording it would
	// otherwise adopt a container that exited 137 for no reason it knows, and
	// call it an out-of-memory kill.
	metaDiskBreach = "disk_breach"

	// startDiskDeadline bounds the measurement Start takes before the
	// container exists. Shorter than a sample's deadline because it sits on
	// the dispatch path; a tree it cannot finish measuring is started anyway,
	// with its usage unknown until the first sample, rather than refused for
	// being large.
	startDiskDeadline = 30 * time.Second

	// stateDir is the project's own state directory at the top of the tree.
	stateDir = ".cloop"
)

// diskLimit is one workload's limit and the trees it covers.
type diskLimit struct {
	mb     int
	source string
	// tree is the directory mounted at /workspace; out is a feature's output
	// directory, empty for any other workload.
	tree string
	out  string
	// stateBaseline is the size of tree/.cloop when the workload started:
	// the hub's bookkeeping, which is not the workload's to pay for. What the
	// run adds to it counts — excluded outright it would be a directory the
	// sandbox can write and no walk counts. math.MaxInt64 when it could not
	// be measured, which excludes it as a whole.
	stateBaseline int64
}

// bytes is the limit in bytes.
func (d *diskLimit) bytes() int64 { return int64(d.mb) << 20 }

// path names the measured tree in messages: the workspace, which for a feature
// is its staged checkout.
func (d *diskLimit) path() string { return d.tree }

// stateRoot is the project's state directory, measured as a root of its own.
func (d *diskLimit) stateRoot(allowance int64) diskwatch.Root {
	return diskwatch.Root{Path: filepath.Join(d.tree, stateDir), Optional: true, Allowance: allowance}
}

// treeRoots is the tree without its state directory, and a feature's output.
func (d *diskLimit) treeRoots() []diskwatch.Root {
	roots := []diskwatch.Root{{Path: d.tree, Exclude: []string{stateDir}}}
	if d.out != "" {
		roots = append(roots, diskwatch.Root{Path: d.out})
	}
	return roots
}

// roots is what a sample walks: treeRoots, and the state directory counted
// beyond its baseline — or not at all when the baseline is unknown.
func (d *diskLimit) roots() []diskwatch.Root {
	roots := d.treeRoots()
	if d.stateBaseline != math.MaxInt64 {
		roots = append(roots, d.stateRoot(d.stateBaseline))
	}
	return roots
}

// breach renders a measurement over the limit.
func (d *diskLimit) breach(u diskwatch.Usage, at time.Time) executor.DiskLimitBreach {
	return executor.DiskLimitBreach{
		UsedBytes:  u.Bytes,
		LimitMB:    d.mb,
		Source:     d.source,
		Path:       d.path(),
		MeasuredAt: at,
	}
}

// describe renders the limit for a log line: "64 MB (from .cloop/sandbox.yaml
// resources.disk)".
func (d *diskLimit) describe() string {
	return executor.FormatMB(d.mb) + " (" + executor.DiskLimitSourcePhrase(d.source) + ")"
}

// newDiskLimit returns the limit req carries over tree, or nil when it carries
// none.
func newDiskLimit(req runRequest, tree string, feature *featureRun) *diskLimit {
	if req.DiskMB <= 0 {
		return nil
	}
	d := &diskLimit{mb: req.DiskMB, source: req.DiskLimitSource, tree: tree, stateBaseline: math.MaxInt64}
	if feature != nil {
		d.out = feature.out
	}
	return d
}

// diskStopReason is the account a stop at the limit leaves on the handle.
func diskStopReason(b executor.DiskLimitBreach) string {
	return "stopped at its disk limit: " + b.Describe()
}

// measureDisk takes one measurement on a low-priority thread, bounded by
// deadline.
func measureDisk(ctx context.Context, roots []diskwatch.Root, deadline time.Duration) (diskwatch.Usage, error) {
	walker := diskwatch.Walker{Deadline: deadline}
	var (
		u   diskwatch.Usage
		err error
	)
	if perr := diskwatch.LowPriority(func() { u, err = walker.Measure(ctx, roots...) }); perr != nil {
		return u, perr
	}
	return u, err
}

// checkDiskAtStart measures the workspace before the container exists, and
// records the size of its state directory as the baseline later samples count
// growth from. A tree already over its limit is refused with a
// *executor.DiskLimitError; otherwise it returns the measurement that
// schedules the first sample — nil when the walk could not finish — and a line
// for the workload's log saying what was found.
func (e *Executor) checkDiskAtStart(ctx context.Context, d *diskLimit) (*diskwatch.Sample, string, error) {
	// The state directory on its own first, so its size becomes the baseline
	// only from a walk of it that finished: a partial one would count the
	// rest of it as the run's growth. Unmeasured, it is excluded as a whole.
	if su, serr := measureDisk(ctx, []diskwatch.Root{d.stateRoot(0)}, startDiskDeadline/3); serr == nil {
		d.stateBaseline = su.Bytes
	}
	// The baseline is the state directory's whole size, so it would add
	// nothing here: the tree is walked without it.
	u, err := measureDisk(ctx, d.treeRoots(), startDiskDeadline)
	if cerr := ctx.Err(); cerr != nil {
		return nil, "", cerr
	}
	at := e.now()
	// Over is over even for a walk that did not finish: its count is a lower
	// bound.
	if u.Bytes > d.bytes() {
		return nil, "", &executor.DiskLimitError{Executor: e.id, Breach: d.breach(u, at)}
	}
	if err != nil {
		return nil, fmt.Sprintf("[cloop] disk limit: this workload's workspace may hold %s; it could not "+
			"be measured before the start (%v), so its usage is unknown until the first sample\n",
			d.describe(), err), nil
	}
	return &diskwatch.Sample{Bytes: u.Bytes, At: at, Cost: u.Elapsed},
		fmt.Sprintf("[cloop] disk limit: this workload's workspace may hold %s and holds %s now; it is "+
			"measured while the workload runs, which is stopped if the workspace grows past the limit\n",
			d.describe(), executor.FormatUsedMB(roundUpMB(u.Bytes))), nil
}

// watchDisk samples rec's workspace until the workload ends — its pump context
// is cancelled by finish — or a breach stops it.
func (e *Executor) watchDisk(ctx context.Context, rec *record, d *diskLimit, initial *diskwatch.Sample) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "container: disk watchdog panic recovered (handle %s): %v\n", rec.id, r)
			rec.bus.Emit(fmt.Sprintf("\n[cloop] disk limit: the watchdog stopped after an internal error (%v); "+
				"this workload's disk use is no longer measured\n", r))
		}
	}()
	w := &diskwatch.Watchdog{
		Roots:      d.roots(),
		LimitBytes: d.bytes(),
		Policy:     e.diskPolicy,
		Initial:    initial,
		OnBreach: func(u diskwatch.Usage, at time.Time) bool {
			return e.stopForDiskLimit(ctx, rec, d.breach(u, at))
		},
		OnUnknown: func(err error, u diskwatch.Usage, next time.Duration) {
			// Logged as unknown, never counted as under the limit: the count is
			// a lower bound, and only "over" can be read from one.
			line := fmt.Sprintf("disk limit: could not measure the workspace (%v); its usage is unknown "+
				"— at least %s of its %s — until the next sample in %s",
				err, executor.FormatUsedMB(roundUpMB(u.Bytes)), d.describe(), next.Round(time.Second))
			rec.bus.Emit("\n[cloop] " + line + "\n")
			fmt.Fprintf(os.Stderr, "container: %s: %s\n", rec.name, line)
		},
	}
	w.Run(ctx)
}

// stopForDiskLimit stops a workload whose workspace is over its limit. It
// reports whether the workload is stopped — or had already ended — so the
// watchdog samples again only for a stop that failed while it kept running.
//
// The stop is recorded on its own field, not as the kill intent a timeout or
// a revocation records: it must neither overwrite their cause nor be cleared
// by their failure, and finish credits it only for the death it causes.
func (e *Executor) stopForDiskLimit(ctx context.Context, rec *record, b executor.DiskLimitBreach) bool {
	if !rec.requestDiskStop(b) {
		return true
	}
	rec.bus.Emit("\n[cloop] disk limit: " + b.Describe() + "; stopping the workload\n")
	killCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shortCmdTimeout)
	defer cancel()
	// Before the kill, so a hub that dies between the two still knows why the
	// container it adopts exited.
	e.persistDiskBreach(rec.id, b)

	rec.mu.Lock()
	ifaces := rec.interfaces
	rec.mu.Unlock()
	if len(ifaces) > 0 {
		// Returned before the kill, as Signal does: the namespace dies with
		// the workload, and a veth left in it is deleted rather than returned.
		detachInterfaces(killCtx, e.recordPID(killCtx, rec.name), ifaces)
	}

	// SIGKILL rather than a polite stop. The workspace is filling, and every
	// second of grace is more of it; nothing inside needs to record the stop,
	// because the hub records it from this handle's status.
	res, err := runCLI(killCtx, e.rt, nil, "kill", "--signal", "SIGKILL", rec.name)
	if err == nil && res.ExitCode == 0 {
		return true
	}
	// The kill failed, or said it did. Ask the runtime rather than read the
	// error — the engines word "already stopped" differently. A container
	// that is not running needs nothing more: finish credits the stop only if
	// it died of the kill. One still running gets the stop again at the next
	// sample; one the runtime cannot answer about keeps the intent, for the
	// same reason.
	running, known := e.containerRunning(killCtx, rec.name)
	if known && !running {
		return true
	}
	if known {
		rec.abandonDiskStop()
	}
	detail := ""
	if err != nil {
		detail = err.Error()
	} else {
		detail = firstLine(res.Stderr)
	}
	fmt.Fprintf(os.Stderr, "container: %s: could not stop the workload at its disk limit: %s\n", rec.name, detail)
	rec.bus.Emit("\n[cloop] disk limit: could not stop the workload (" + detail + "); trying again\n")
	return false
}

// containerRunning asks the runtime whether name is running. known is false
// when the runtime could not say — a daemon that is down — which a caller must
// not read as "stopped".
func (e *Executor) containerRunning(ctx context.Context, name string) (running, known bool) {
	res, err := runCLITimeout(ctx, e.rt, shortCmdTimeout, "inspect", "--format", "{{.State.Running}}", name)
	if err != nil {
		return false, false
	}
	if res.ExitCode != 0 {
		// Gone altogether is an answer: docker says "No such object" or "No
		// such container", podman "no such container".
		if strings.Contains(strings.ToLower(res.Stderr), "no such") {
			return false, true
		}
		return false, false
	}
	switch strings.TrimSpace(res.Stdout) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// persistDiskBreach writes the stop's measurement onto the handle's persisted
// row. Best-effort, like every handle write: a stop that loses this is still a
// stop, reported as one by this process.
func (e *Executor) persistDiskBreach(handleID string, b executor.DiskLimitBreach) {
	store := e.handleStore()
	if store == nil {
		return
	}
	rows, err := store.ListHandles(e.id)
	if err != nil {
		return
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return
	}
	for _, row := range rows {
		if row.HandleID != handleID {
			continue
		}
		meta := make(map[string]string, len(row.Meta)+1)
		for k, v := range row.Meta {
			meta[k] = v
		}
		meta[metaDiskBreach] = string(raw)
		row.Meta = meta
		executor.RecordHandle(store, row)
		return
	}
}

// requestDiskStop records that the disk watchdog is stopping the workload, at
// what measurement, unless the workload is already over. It reports whether it
// recorded.
func (r *record) requestDiskStop(b executor.DiskLimitBreach) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done || r.state.Terminal() {
		return false
	}
	r.diskBreach = &b
	return true
}

// abandonDiskStop withdraws a requestDiskStop whose kill did not happen.
func (r *record) abandonDiskStop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return
	}
	r.diskBreach = nil
}

// applyDiskOutcome reports a disk-limit stop on a status built from rec.
// Caller holds rec.mu. finish keeps diskBreach only when it credited the stop,
// so a killed workload carrying one was killed by it.
func (r *record) applyDiskOutcome(st *executor.Status) {
	if r.diskBreach == nil || r.state != executor.StateKilled {
		return
	}
	b := *r.diskBreach
	st.Outcome = executor.OutcomeDiskLimit
	st.DiskLimit = &b
}

// withDiskMeta adds a workload's disk limit to its persisted handle metadata.
func withDiskMeta(meta map[string]string, d *diskLimit) map[string]string {
	if d == nil {
		return meta
	}
	if meta == nil {
		meta = map[string]string{}
	}
	meta[metaDiskLimit] = strconv.Itoa(d.mb)
	if d.source != "" {
		meta[metaDiskSource] = d.source
	}
	if d.stateBaseline != math.MaxInt64 {
		meta[metaDiskBaseline] = strconv.FormatInt(d.stateBaseline, 10)
	}
	return meta
}

// restoreDiskLimit rebuilds an adopted workload's disk limit from its persisted
// handle: the project directory it was started over, or the feature's staged
// tree. Nil when the workload had none, or its tree cannot be named.
func restoreDiskLimit(saved executor.HandleRecord, feature *featureRun) *diskLimit {
	mb, err := strconv.Atoi(strings.TrimSpace(saved.Meta[metaDiskLimit]))
	if err != nil || mb <= 0 {
		return nil
	}
	tree := saved.ProjectPath
	out := ""
	if feature != nil {
		tree, out = feature.stage, feature.out
	}
	if tree == "" || !filepath.IsAbs(tree) {
		return nil
	}
	d := &diskLimit{mb: mb, source: saved.Meta[metaDiskSource], tree: tree, out: out, stateBaseline: math.MaxInt64}
	if v, err := strconv.ParseInt(strings.TrimSpace(saved.Meta[metaDiskBaseline]), 10, 64); err == nil && v >= 0 {
		d.stateBaseline = v
	}
	return d
}

// restoreDiskBreach reads the measurement a stop was made at, when the hub that
// made it died before recording the death.
func restoreDiskBreach(saved executor.HandleRecord) *executor.DiskLimitBreach {
	raw := strings.TrimSpace(saved.Meta[metaDiskBreach])
	if raw == "" {
		return nil
	}
	var b executor.DiskLimitBreach
	if json.Unmarshal([]byte(raw), &b) != nil || !b.Over() {
		return nil
	}
	return &b
}

// roundUpMB converts bytes to MiB, rounding up.
func roundUpMB(b int64) int64 {
	if b <= 0 {
		return 0
	}
	return b>>20 + min(1, b&(1<<20-1))
}
