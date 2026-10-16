package ui

// denials.go records what a run's sandbox firewall refused (Task 20437).
//
// A sandbox's IP firewall refuses a blocked connection at once and logs it,
// rate-limited, to an NFLOG group under a prefix naming its rule set and its
// deny path. Two readers report what it logged, per workload: the hub itself
// for its own container executor (pkg/denylog, in this process), and each edge
// device's agent for its sandboxes (protocol v24's denials frame). Both arrive
// here through executor.ReportDenials, keyed by executor and handle.
//
// This file turns a handle into a run — the route bound when the hub
// dispatched it, or adopted it — and a refusal into the sentence a developer
// needs: which destination, how often, and which level's rule refused it,
// explained from the levels the run's firewall was composed of. What it
// records:
//
//   - network_denials rows in the project's database (statedb), bounded per
//     run and in all;
//   - a network_blocked row in the run's history the first time a run is
//     refused a destination under a task, and one more when the run ends,
//     with its refusals in all;
//   - one run.firewall_denied audit row per deny path when the run ends —
//     per run and rule, never per packet;
//   - cloop_firewall_denials_total.
//
// Every report goes through one bounded queue and one goroutine, so a device
// that floods reports costs the hub a dropped report, never a stall in the
// session's read loop or a database write per packet.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/denylog"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// denialRoute is what a workload's refusals are recorded against.
type denialRoute struct {
	runID        string
	workDir      string
	executorID   string
	executorKind string
	// levels explain a refusal: the ones the dispatch composed the run's
	// firewall from, outermost first.
	levels  []fwpolicy.Level
	started time.Time
}

var denialRoutes = struct {
	sync.Mutex
	m map[string]*denialRoute
}{m: map[string]*denialRoute{}}

func denialKey(executorID, handleID string) string { return executorID + "\x00" + handleID }

// bindDenialRoute records which run a workload's refusals belong to.
func bindDenialRoute(ex executor.Executor, handleID, runID, workDir string, levels []fwpolicy.Level) {
	if ex == nil || handleID == "" || workDir == "" {
		return
	}
	if runID == "" {
		// Every dispatch mints one; an adopted run whose id the hub cannot
		// recover is still one run, named by its handle.
		runID = "handle:" + handleID
	}
	r := &denialRoute{
		runID: runID, workDir: workDir, executorID: ex.ID(), executorKind: ex.Kind(),
		levels: levels, started: time.Now(),
	}
	denialRoutes.Lock()
	defer denialRoutes.Unlock()
	if len(denialRoutes.m) >= maxDenialRoutes {
		// A route ends with its run in runEnded; a workload dispatched for
		// something that is not a project's run has no such end, so the map
		// is bounded instead: the oldest route goes.
		var oldest *denialRoute
		for _, v := range denialRoutes.m {
			if oldest == nil || v.started.Before(oldest.started) {
				oldest = v
			}
		}
		for k, v := range denialRoutes.m {
			if v == oldest {
				delete(denialRoutes.m, k)
			}
		}
	}
	for _, id := range denialExecutorIDs(ex) {
		denialRoutes.m[denialKey(id, handleID)] = r
	}
}

// maxDenialRoutes bounds the routes one process holds: far more runs than a
// hub has live.
const maxDenialRoutes = 4096

// denialExecutorIDs are the executor ids a workload's reports can arrive
// under: its own, and for a virtual executor its device's — whose session
// carries the frames, and whose handle map the handle is in.
func denialExecutorIDs(ex executor.Executor) []string {
	ids := []string{ex.ID()}
	if v, ok := ex.(interface{ ParentID() string }); ok && v.ParentID() != "" && v.ParentID() != ex.ID() {
		ids = append(ids, v.ParentID())
	}
	return ids
}

func lookupDenialRoute(executorID, handleID string) *denialRoute {
	denialRoutes.Lock()
	defer denialRoutes.Unlock()
	return denialRoutes.m[denialKey(executorID, handleID)]
}

func takeDenialRoute(executorID, handleID string) *denialRoute {
	denialRoutes.Lock()
	defer denialRoutes.Unlock()
	r := denialRoutes.m[denialKey(executorID, handleID)]
	if r == nil {
		return nil
	}
	for k, v := range denialRoutes.m {
		if v == r {
			delete(denialRoutes.m, k)
		}
	}
	return r
}

// denialLevels is what explains a run's refusals: the levels the dispatch
// composed when stored rules shaped it, or else the executor's own — its
// configured filter, a virtual executor's firewall, a repo's egress scope.
func denialLevels(ex executor.Executor, res fwpolicy.Resolution, spec executor.Spec) []fwpolicy.Level {
	if res.Applied() {
		return res.Levels
	}
	if ex == nil {
		return nil
	}
	pos := executor.PostureOf(ex)
	levels := []fwpolicy.Level{{Kind: "config", Name: "executor " + ex.ID() + "'s configuration", Rules: pos.Config}}
	if pos.Own != nil {
		name := pos.OwnName
		if name == "" {
			name = "the executor's own network"
		}
		levels = append(levels, fwpolicy.Level{Kind: "own", Name: name, Rules: pos.Own})
	}
	if spec.EgressScope == executor.EgressScopePublic {
		levels = append(levels, fwpolicy.Level{Kind: "scope",
			Name: "this project's .cloop/sandbox.yaml (egress: public)", Rules: &fwpolicy.Rules{AllowPublicInternet: true}})
	}
	return levels
}

// ─── the recorder ───────────────────────────────────────────────────────────

// denialJob is one report, or the end of a run.
type denialJob struct {
	executorID, handleID string
	batch                denylog.Batch
	end                  bool
	done                 chan struct{}
}

// denialQueueDepth bounds the reports waiting to be recorded. At a device's
// flush interval of two seconds per run it is minutes of a busy fleet's
// reports; a recorder that far behind is better served by dropping than by
// holding more.
const denialQueueDepth = 512

var denialRecorder = struct {
	once   sync.Once
	queue  chan denialJob
	notify atomic.Pointer[func(workDir string)]
}{queue: make(chan denialJob, denialQueueDepth)}

// installDenialRecorder makes this process where refusals go, once: before
// the executors are bootstrapped, so a container sandbox they reattach to is
// attributed again from its handle's row.
func installDenialRecorder() {
	denialRecorder.once.Do(func() {
		executor.SetDenialSink(enqueueDenials)
		// The hub's own container executor reports through the same sink.
		denylog.SetSink(func(r denylog.Run, b denylog.Batch) error {
			executor.ReportDenials(r.Executor, r.ID, b)
			return nil
		})
		go denialWorker()
	})
}

// notifyDenials makes s the server that tells open dashboards a run's history
// grew. The newest server constructed in the process wins.
func (s *Server) notifyDenials() {
	notify := func(workDir string) { s.pushHistory(workDir) }
	denialRecorder.notify.Store(&notify)
}

// enqueueDenials is the executor sink: never blocks the caller, which for a
// device's report is that device's session read loop.
func enqueueDenials(executorID, handleID string, b denylog.Batch) {
	if b.Empty() {
		return
	}
	select {
	case denialRecorder.queue <- denialJob{executorID: executorID, handleID: handleID, batch: b}:
	default:
		hubmetrics.FirewallDenialReportsDropped.Inc("queue_full")
	}
}

func denialWorker() {
	for j := range denialRecorder.queue {
		func() {
			defer recoverGoroutine("firewall refusals")
			if j.end {
				finishDenialRun(j.executorID, j.handleID)
				close(j.done)
				return
			}
			recordDenialBatch(j.executorID, j.handleID, j.batch)
		}()
	}
}

// endRunDenials ends a workload's refusals once it has exited: the hub's own
// container executor's last log lines are flushed, everything queued for the
// run is recorded, and the run's summary and audit rows are written. Safe to
// call more than once, and for a workload with no route.
func endRunDenials(ex executor.Executor, handleID string) {
	if ex == nil || lookupDenialRoute(ex.ID(), handleID) == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// In this process only: a device flushed its own before the status that
	// ended the run, and the monitor knows no remote handle.
	_ = container.FlushDenials(ctx, handleID)
	done := make(chan struct{})
	select {
	case denialRecorder.queue <- denialJob{executorID: ex.ID(), handleID: handleID, end: true, done: done}:
	case <-ctx.Done():
		takeDenialRoute(ex.ID(), handleID)
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// recordDenialBatch records one report on its run.
func recordDenialBatch(executorID, handleID string, b denylog.Batch) {
	r := lookupDenialRoute(executorID, handleID)
	if r == nil {
		hubmetrics.FirewallDenialReportsDropped.Inc("unknown_run")
		return
	}
	now := time.Now()
	task := runningTask(r.workDir)
	w := statedb.DenialWrite{
		RunID: r.runID, TaskID: task.id, ExecutorID: r.executorID, Fingerprint: b.Fingerprint,
		Unitemised: int64(b.Unitemised), At: now,
	}
	for _, e := range b.Entries {
		// The sender's clock is not ours: a device's skewed or hostile one
		// must not file a refusal before its run began or in the future.
		e.Clamp(r.started.Add(-time.Minute), now)
		w.Entries = append(w.Entries, statedb.DenialRow{
			Rule: e.Rule, Dst: e.Dst.String(), Port: int(e.Port), Proto: e.Proto,
			Why:   fwpolicy.Explain(r.levels, e.Rule, e.Dst, e.Port, e.Proto),
			Count: int64(e.Count), FirstSeen: e.First, LastSeen: e.Last,
		})
		hubmetrics.FirewallDenials.Add(float64(e.Count), r.executorKind, denylog.RuleKind(e.Rule))
	}
	if b.Unitemised > 0 {
		hubmetrics.FirewallDenials.Add(float64(b.Unitemised), r.executorKind, statedb.DenialUnitemised)
	}

	db, err := openProjectDB(r.workDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: firewall refusals of run %s: %v\n", r.runID, err)
		return
	}
	defer db.Close()
	res, err := db.RecordDenials(w)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: firewall refusals of run %s: %v\n", r.runID, err)
		return
	}
	for _, row := range res.New {
		recordDenialEvent(db, r, task, blockedMessage(row), map[string]any{
			"run_id": r.runID, "executor_id": r.executorID, "rule": row.Rule, "dst": row.Dst,
			"port": row.Port, "proto": row.Proto, "count": row.Count, "fingerprint": b.Fingerprint,
		})
	}
	if res.FirstUnitemised {
		recordDenialEvent(db, r, task, fmt.Sprintf("the firewall refused this run more destinations than "+
			"the %d a run itemises; the rest are counted, not listed", statedb.MaxDenialRowsPerRun),
			map[string]any{"run_id": r.runID, "executor_id": r.executorID, "unitemised": res.Unitemised})
	}
	if len(res.New) > 0 || res.FirstUnitemised {
		if n := denialRecorder.notify.Load(); n != nil {
			(*n)(r.workDir)
		}
	}
}

// finishDenialRun writes a run's summary and audit rows and forgets its route.
func finishDenialRun(executorID, handleID string) {
	r := takeDenialRoute(executorID, handleID)
	if r == nil {
		return
	}
	db, err := openProjectDB(r.workDir)
	if err != nil {
		return
	}
	defer db.Close()
	totals, err := db.RunDenialTotals(r.runID)
	if err != nil || len(totals) == 0 {
		return
	}
	rows, _ := db.RunDenials(r.runID)
	var count int64
	for _, t := range totals {
		count += t.Count
		statedb.AuditFirewallDenied(db, statedb.FirewallDeniedInput{
			ProjectPath: r.workDir, RunID: r.runID, ExecutorID: r.executorID, Total: t,
			Fingerprint: firstFingerprint(rows),
		})
	}
	recordDenialEvent(db, r, taskRef{}, runSummaryMessage(rows, count), map[string]any{
		"run_id": r.runID, "executor_id": r.executorID, "count": count, "summary": true,
	})
	if n := denialRecorder.notify.Load(); n != nil {
		(*n)(r.workDir)
	}
}

func firstFingerprint(rows []statedb.DenialRow) string {
	for _, r := range rows {
		if r.Fingerprint != "" {
			return r.Fingerprint
		}
	}
	return ""
}

type taskRef struct {
	id    int
	title string
}

// runningTask is the task a refusal happened under: the one in progress, when
// exactly one is. A device's seeded run keeps its plan on the device, so there
// the answer is usually none, and the refusal is matched to a task by time.
func runningTask(workDir string) taskRef {
	// Lite: the plan's statuses are all this reads, never a step's output.
	ps, err := state.LoadLite(workDir)
	if err != nil || ps.Plan == nil {
		return taskRef{}
	}
	var running []*pm.Task
	for _, t := range ps.Plan.Tasks {
		if t.Status == pm.TaskInProgress {
			running = append(running, t)
		}
	}
	if len(running) != 1 {
		return taskRef{}
	}
	return taskRef{id: running[0].ID, title: running[0].Title}
}

func recordDenialEvent(db *statedb.DB, r *denialRoute, t taskRef, msg string, details map[string]any) {
	row := state.EventRow{Type: state.EventNetworkBlocked, Step: state.NoStep, Timestamp: time.Now(),
		TaskID: t.id, TaskTitle: t.title, Message: msg}
	if b, err := json.Marshal(details); err == nil {
		row.Details = string(b)
	}
	if err := db.RecordEvent(row); err != nil {
		fmt.Fprintf(os.Stderr, "ui: firewall refusal event of run %s: %v\n", r.runID, err)
	}
}

// blockedMessage is the history's line for a destination: "blocked
// 203.0.113.7:443/tcp x14, not in the project's allow list".
func blockedMessage(row statedb.DenialRow) string {
	msg := "blocked " + statedb.DenialDestination(row.Dst, row.Port, row.Proto)
	if row.Count > 1 {
		msg += fmt.Sprintf(" x%d", row.Count)
	}
	if row.Why != "" {
		msg += ", " + row.Why
	}
	return msg
}

// runSummaryMessage is the line a run ends with when anything was refused.
func runSummaryMessage(rows []statedb.DenialRow, count int64) string {
	var listed []statedb.DenialRow
	var unitemised int64
	for _, r := range rows {
		if r.Rule == statedb.DenialUnitemised {
			unitemised += r.Count
			continue
		}
		listed = append(listed, r)
	}
	sort.SliceStable(listed, func(i, j int) bool { return listed[i].Count > listed[j].Count })
	var parts []string
	for i, r := range listed {
		if i == 3 {
			break
		}
		parts = append(parts, statedb.DenialDestination(r.Dst, r.Port, r.Proto)+fmt.Sprintf(" x%d", r.Count))
	}
	attempts := "attempts"
	if count == 1 {
		attempts = "attempt"
	}
	msg := fmt.Sprintf("the firewall refused %d connection %s during this run", count, attempts)
	if len(parts) > 0 {
		msg += ": " + strings.Join(parts, ", ")
		if more := len(listed) - len(parts); more > 0 {
			msg += fmt.Sprintf(" and %d more destination", more)
			if more > 1 {
				msg += "s"
			}
		}
	}
	if unitemised > 0 {
		msg += fmt.Sprintf(" (%d not itemised)", unitemised)
	}
	return msg
}

// openProjectDB opens a project's database for the recorder's writes.
func openProjectDB(workDir string) (*statedb.DB, error) {
	path := state.DBPath(workDir)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("project %s has no state.db: %w", workDir, err)
	}
	return statedb.Open(path)
}
