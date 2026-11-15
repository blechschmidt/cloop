package ui

// projectmove_engine.go runs project moves on this hub (Task 20494): the
// pkg/projectmove engine, driven over this hub's dispatch path, databases and
// cluster.
//
//	POST /api/projects/{idx}/move                  start a move
//	GET  /api/projects/{idx}/moves                 the project's moves
//
// A move's own view and its cleanup are projectmove_view.go's (Task 20496).
//
// Each open move is driven by the one hub process holding its lease — a
// hublease row scoped "projectmove:<id>" — and every member looks for open
// moves nobody drives, so a move started on a process that then stopped is
// taken up by the next one: at its next start, or within a sweep by another
// member. A move that has to put work on a device (its seed and its
// verification) is driven by the member holding that device's connection.
//
// While a move is open no run of the project — or of its features — starts:
// startWorkloadAs refuses every dispatch, the Run button's handler refuses
// before it queues for a pool, and a manual rebind is refused too, since a
// move owns the binding until it ends.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Tunables, variables so tests can shorten them.
var (
	// moveQuiesceTimeout bounds how long quiesce waits for a stopped run to
	// exit. A run finishes the step it is in before it pauses, which can be
	// a long provider call.
	moveQuiesceTimeout = 15 * time.Minute
	// moveQuiescePoll is how often quiesce looks.
	moveQuiescePoll = 500 * time.Millisecond
	// moveWorkloadTimeout bounds one workload a move puts on a target.
	moveWorkloadTimeout = 30 * time.Minute
	// moveSweepInterval is how often each member looks for open moves no
	// process is driving.
	moveSweepInterval = 30 * time.Second
	// moveLeaseTTL is how long a move's lease outlives its holder.
	moveLeaseTTL = hublease.DefaultTTL
)

// moveStoreMaxBytes bounds what one move writes into the move store: its
// bundle and its tar together. A target that receives them through a shipped
// branch is held to the branch bundle's own ceiling as well.
const moveStoreMaxBytes int64 = 2 << 30

// moveOutputMax bounds what the hub keeps of a move workload's output.
const moveOutputMax = 4 << 20

// moveLeaseScope is the hublease scope of one move.
func moveLeaseScope(id string) string { return "projectmove:" + id }

// moveStoreRoot is the hub's move store.
func moveStoreRoot() string { return filepath.Join(controlPlaneDir(), ".cloop", "moves") }

// moveStoreDir is one move's directory in the store.
func moveStoreDir(id string) (string, error) {
	if !movegit.ValidMoveID(id) {
		return "", fmt.Errorf("%q is not a move id", id)
	}
	if strings.TrimSpace(controlPlaneDir()) == "" {
		return "", errors.New("the hub has no control-plane directory yet")
	}
	return filepath.Join(moveStoreRoot(), id), nil
}

// ─── the run gate ───────────────────────────────────────────────────────────

// projectMovingError refuses a dispatch of a project a move is moving.
type projectMovingError struct {
	Project string
	Move    projectmove.Move
}

func (e *projectMovingError) Error() string {
	return fmt.Sprintf("project %s is being moved to %s (move %s, at %s), and no run of it starts until the move ends",
		e.Project, projectmove.DescribeTarget(e.Move.Target), e.Move.ID, e.Move.Phase)
}

// Remediation says what to do instead.
func (e *projectMovingError) Remediation() string {
	return "wait for the move to end — the project's moves say how it is going — then start the run; it runs where the move left the project"
}

// openMoveAt reports the open move of the project at workDir: a feature's is
// its parent's, since a feature moves with its project. An error reading the
// journal is returned, not taken as "none": a dispatch the gate cannot check is
// refused.
func openMoveAt(dbPath, workDir string) (projectmove.Move, bool, error) {
	if strings.TrimSpace(workDir) == "" || strings.TrimSpace(dbPath) == "" {
		return projectmove.Move{}, false, nil
	}
	// A control plane with no database yet has recorded no move — and
	// opening one here would create it.
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return projectmove.Move{}, false, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return projectmove.Move{}, false, err
	}
	defer db.Close()
	m, ok, err := projectmove.OpenMove(db, policyProjectPath(workDir))
	if err != nil {
		return projectmove.Move{}, false, fmt.Errorf("read the project's moves: %w", err)
	}
	return m, ok, nil
}

// checkNoOpenMove is the gate every dispatch passes through.
func checkNoOpenMove(workDir string) error {
	dir := controlPlaneDir()
	if dir == "" {
		return nil
	}
	m, ok, err := openMoveAt(state.DBPath(dir), workDir)
	if err != nil {
		return fmt.Errorf("cannot tell whether %s is being moved: %w", workDir, err)
	}
	if ok {
		return &projectMovingError{Project: workDir, Move: m}
	}
	return nil
}

// refuseWhileMoving answers 409 for a project a move is moving, reporting
// whether it did.
func (s *Server) refuseWhileMoving(w http.ResponseWriter, workDir string) bool {
	m, ok, err := openMoveAt(state.DBPath(s.WorkDir), workDir)
	if err != nil {
		jsonErr(w, "cannot tell whether this project is being moved: "+err.Error(), http.StatusServiceUnavailable)
		return true
	}
	if !ok {
		return false
	}
	refused := &projectMovingError{Project: workDir, Move: m}
	writeJSONStatus(w, http.StatusConflict, map[string]any{
		"error": refused.Error(), "code": "project_moving", "remediation": refused.Remediation(),
		"move": m.ID, "phase": m.Phase,
	})
	return true
}

// ─── the engine ─────────────────────────────────────────────────────────────

// moveEngine is the engine over this hub.
func (s *Server) moveEngine() *projectmove.Engine {
	return &projectmove.Engine{
		Store:  projectmove.DBStore{Open: s.controlPlaneDB},
		Driver: &moveDriver{s: s},
		Hooks:  moveHooks{s: s},
		Member: s.hubInstanceID(),
	}
}

// moveRunner tracks the moves this process drives.
type moveRunner struct {
	mu      sync.Mutex
	running map[string]bool
	// ctx is what background moves run under: the server's watchers'.
	ctx context.Context
}

func (s *Server) moveRun() *moveRunner {
	s.moveRunnerOnce.Do(func() { s.moveRunnerState = &moveRunner{running: map[string]bool{}} })
	return s.moveRunnerState
}

func (r *moveRunner) setContext(ctx context.Context) {
	r.mu.Lock()
	r.ctx = ctx
	r.mu.Unlock()
}

func (r *moveRunner) context() context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx != nil {
		return r.ctx
	}
	return context.Background()
}

// claim marks id as driven here, reporting false when it already is.
func (r *moveRunner) claim(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running[id] {
		return false
	}
	r.running[id] = true
	return true
}

func (r *moveRunner) release(id string) {
	r.mu.Lock()
	delete(r.running, id)
	r.mu.Unlock()
}

// driving reports whether this process drives id.
func (r *moveRunner) driving(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running[id]
}

// driveMove drives one move under its lease until it ends, ctx ends, the
// lease is lost, or another process should drive it. It reports how the move
// stands when it stopped driving.
func (s *Server) driveMove(ctx context.Context, id string) (projectmove.Move, error) {
	if !s.moveRun().claim(id) {
		return projectmove.Move{}, errMoveDrivenHere
	}
	return s.driveClaimed(ctx, id)
}

// driveClaimed is driveMove for a move this process has already claimed: the
// claim is taken before a background driver starts, so that "is this process
// driving it" never answers no for a driver about to start.
func (s *Server) driveClaimed(ctx context.Context, id string) (projectmove.Move, error) {
	defer s.moveRun().release(id)
	db, err := s.controlPlaneDB()
	if err != nil {
		return projectmove.Move{}, err
	}
	defer db.Close()
	lease, err := hublease.Acquire(hublease.Options{
		Store: db, Scope: moveLeaseScope(id), TTL: moveLeaseTTL, Interval: moveLeaseTTL / 3,
		InstanceID: s.hubInstanceID(),
	})
	if err != nil {
		return projectmove.Move{}, err
	}
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	lease.Start(dctx)
	defer func() { _ = lease.Release() }()
	go func() {
		select {
		case <-lease.Lost():
			cancel()
		case <-dctx.Done():
		}
	}()
	m, err := s.moveEngine().Drive(dctx, id)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, projectmove.ErrChanged) && !errors.Is(err, errMoveElsewhere) {
		s.log().Warn(logger.EventStateWrite, 0, "a project move stopped before it ended",
			map[string]interface{}{"move": id, "error": err.Error()})
	}
	return m, err
}

// errMoveDrivenHere is driveMove refusing a move this process already drives.
var errMoveDrivenHere = errors.New("the move is already being driven by this hub process")

// errMoveElsewhere is a phase that must run on another member: the one
// holding the target device's connection, or the one running the project.
var errMoveElsewhere = fmt.Errorf("%w: this part of the move runs on the hub member holding the connection it needs", projectmove.ErrHandOff)

// startMoveDriver drives a move in the background.
func (s *Server) startMoveDriver(id string) {
	run := s.moveRun()
	if !run.claim(id) {
		return
	}
	ctx := run.context()
	go func() {
		defer recoverGoroutine("project move " + id)
		_, _ = s.driveClaimed(ctx, id)
	}()
}

// watchProjectMoves drives, on every member, the open moves no process drives:
// at startup — a move this process was driving when it stopped resumes here —
// and on each sweep after.
func (s *Server) watchProjectMoves(ctx context.Context) {
	s.moveRun().setContext(ctx)
	t := time.NewTimer(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.sweepProjectMoves(ctx)
		t.Reset(moveSweepInterval)
	}
}

// sweepProjectMoves starts a driver for every open move this member should
// drive and does not.
func (s *Server) sweepProjectMoves(ctx context.Context) {
	db, err := s.controlPlaneDB()
	if err != nil {
		return
	}
	moves, err := projectmove.ListMoves(db, statedb.ProjectMoveFilter{OpenOnly: true})
	db.Close()
	if err != nil {
		return
	}
	for _, m := range moves {
		if !s.drivesHere(m) || !s.moveRun().claim(m.ID) {
			continue
		}
		id := m.ID
		go func() {
			defer recoverGoroutine("project move " + id)
			_, _ = s.driveClaimed(ctx, id)
		}()
	}
}

// drivesHere reports whether this member should drive m now: any member, but
// the member running the project's run for quiesce, and for the phases that
// put work on a device, the member holding its connection.
func (s *Server) drivesHere(m projectmove.Move) bool {
	if m.Phase == projectmove.PhaseQuiesce {
		return s.runOwnedByPeer(m.Project.Path) == ""
	}
	if m.Phase == projectmove.PhaseCapture && !m.AbandonSource {
		// A device's working copy is asked of the member holding its
		// connection, and a pool's volume of the member holding the runner
		// attached to it (Task 20495).
		return s.capturesHere(m)
	}
	if !m.Phase.Switched() || m.Detail.Capture == nil || m.Detail.Capture.Delivery != projectmove.DeliverDevice {
		return true
	}
	if m.Detail.Rollback != nil && m.Detail.Rollback.Pending {
		return true
	}
	ex, err := executor.Get(m.Target)
	if err != nil {
		return true
	}
	_, held := s.agentHeldByPeer(ex)
	return !held
}

// runOwnedByPeer names the live member, other than this one, running the
// project's run or one of its features'; "" when none does.
func (s *Server) runOwnedByPeer(project string) string {
	paths := []string{project}
	if infos, err := feature.List(project); err == nil {
		for _, in := range infos {
			paths = append(paths, in.Path)
		}
	}
	for _, p := range paths {
		if o, _, found := s.clusterRunOwner(p); found && !o.Self && o.Alive {
			if id := o.Member.ID; id != "" {
				return id
			}
			return "another member"
		}
	}
	return ""
}

// ─── hooks ──────────────────────────────────────────────────────────────────

// moveHooks audits and announces a move's transitions.
type moveHooks struct{ s *Server }

func (h moveHooks) Transitioned(_ context.Context, from, to projectmove.Move) {
	var action auditaction.Action
	switch {
	case from.Phase == "" && to.Phase == projectmove.PhasePreflight:
		action = auditaction.ActionProjectMoveStart
	case from.Phase == projectmove.PhaseSwitch && to.Phase == projectmove.PhaseSeed:
		action = auditaction.ActionProjectMoveSwitch
	case to.Phase == projectmove.PhaseDone && from.Phase != projectmove.PhaseDone:
		action = auditaction.ActionProjectMoveDone
	case to.Phase == projectmove.PhaseFailed && from.Phase != projectmove.PhaseFailed:
		action = auditaction.ActionProjectMoveFail
	case to.Phase == projectmove.PhaseRolledBack && from.Phase != projectmove.PhaseRolledBack:
		action = auditaction.ActionProjectMoveRollback
	}
	if action != "" {
		h.s.auditMove(action, to, nil)
	}
	// Every write is a step the dashboards watching the move draw, and moves
	// the projects list's word for the project (Task 20496).
	h.s.moveChanged(to)
	if !to.Open() || action == auditaction.ActionProjectMoveSwitch {
		h.s.broadcastExecutorUpdate("moved", to.Target)
	}
}

// auditMove writes one project.move row to the control plane's trail.
func (s *Server) auditMove(action auditaction.Action, m projectmove.Move, extra map[string]any) {
	db, err := s.controlPlaneDB()
	if err != nil {
		return
	}
	defer db.Close()
	payload := map[string]any{
		"move": m.ID, "project": m.Project.Name, "project_path": m.Project.Path,
		"source": m.Source, "target": m.Target, "phase": string(m.Phase),
	}
	if m.AbandonSource {
		payload["abandon_source"] = true
	}
	if m.FailedPhase != "" {
		payload["failed_phase"] = string(m.FailedPhase)
	}
	if m.Error != "" {
		payload["error"] = m.Error
	}
	if c := m.Detail.Capture; c != nil && action != auditaction.ActionProjectMoveStart {
		payload["delivery"] = c.Delivery
		payload["captured_bytes"] = c.Bytes
		if c.From != "" {
			payload["captured_from"] = c.From
		}
	}
	if sw := m.Detail.Switch; sw != nil && action == auditaction.ActionProjectMoveSwitch {
		payload["previous_binding"] = sw.PreviousBinding
	}
	for k, v := range extra {
		payload[k] = v
	}
	actor := m.StartedBy
	if v, ok := extra["actor"].(string); ok && v != "" {
		actor = v
		delete(payload, "actor")
	}
	if actor == "" {
		actor = "system"
	}
	_ = db.AppendAuditEvent(&statedb.AuditEvent{
		Actor: actor, EventType: string(action), EntityType: "project_move", EntityID: m.ID,
		Payload: statedb.MarshalAuditPayload(payload),
	})
	s.broadcastAuditAppend(action.String())
}

// ─── the driver ─────────────────────────────────────────────────────────────

// moveDriver is projectmove.Driver over this hub.
type moveDriver struct{ s *Server }

var _ projectmove.Driver = (*moveDriver)(nil)

// paths are the project's directory and its features'.
func (d *moveDriver) paths(m projectmove.Move) []string {
	out := []string{m.Project.Path}
	if infos, err := feature.List(m.Project.Path); err == nil {
		for _, in := range infos {
			out = append(out, in.Path)
		}
	}
	return out
}

func whoOf(project, path string) string {
	if path == project {
		return "the project"
	}
	if _, slug, ok := feature.ParentOf(path); ok {
		return "feature " + slug
	}
	return path
}

// Quiesce stops the project's runs the way Stop does and waits for them to
// end, then puts back to pending any task a run left in progress.
func (d *moveDriver) Quiesce(ctx context.Context, m projectmove.Move) (*projectmove.QuiesceRecord, error) {
	s := d.s
	rec := &projectmove.QuiesceRecord{}
	paths := d.paths(m)
	actor := "project-move:" + m.ID
	if member := s.runOwnedByPeer(m.Project.Path); member != "" {
		// Only the member streaming a run can stop it.
		return rec, errMoveElsewhere
	}
	for _, p := range paths {
		if cancelled, starting := s.cancelQueuedPoolRunAs(actor, p); cancelled {
			rec.Unqueued = append(rec.Unqueued, whoOf(m.Project.Path, p))
		} else if starting {
			return rec, fmt.Errorf("%s's run is being started on an executor pool's runner, which cannot be taken back; stop it once it runs and move the project again", whoOf(m.Project.Path, p))
		}
		if !s.projectExecuting(p) {
			continue
		}
		dl := s.interruptRun(p)
		if msg, failed := dl.failure(); failed {
			return rec, fmt.Errorf("could not stop %s's run: %s", whoOf(m.Project.Path, p), msg)
		}
		rec.Stopped = append(rec.Stopped, whoOf(m.Project.Path, p))
	}
	deadline := time.Now().Add(moveQuiesceTimeout)
	for {
		var still []string
		for _, p := range paths {
			if s.projectExecuting(p) {
				still = append(still, whoOf(m.Project.Path, p))
			}
		}
		if len(still) == 0 {
			break
		}
		if time.Now().After(deadline) {
			return rec, fmt.Errorf("%s still had a run executing %s after it was asked to stop; stop it, then move the project again",
				strings.Join(still, ", "), moveQuiesceTimeout)
		}
		select {
		case <-ctx.Done():
			return rec, ctx.Err()
		case <-time.After(moveQuiescePoll):
		}
	}
	// A run asked to stop puts its task back to pending itself; one that died
	// instead is tidied up the way Stop tidies up after it.
	for _, p := range paths {
		st, err := state.LoadLite(p)
		if err != nil || st == nil || st.Plan == nil {
			continue
		}
		var inProgress []int
		for _, t := range st.Plan.Tasks {
			if t.Status == pm.TaskInProgress {
				inProgress = append(inProgress, t.ID)
			}
		}
		if len(inProgress) == 0 && st.Status != "running" {
			continue
		}
		s.reconcileDeadRun(p, runVerdict{})
		for _, id := range inProgress {
			rec.Requeued = append(rec.Requeued, fmt.Sprintf("%s #%d", whoOf(m.Project.Path, p), id))
		}
	}
	return rec, nil
}

// deliveryFor decides how the target receives what the source holds.
func deliveryFor(m projectmove.Move) (string, executor.Executor, error) {
	if m.AbandonSource {
		return projectmove.DeliverNothing, nil, nil
	}
	if _, isPool := executor.PoolOf(m.Target); isPool {
		return projectmove.DeliverForge, nil, nil
	}
	ex, err := executor.Get(m.Target)
	if err != nil {
		return "", nil, fmt.Errorf("the target executor %s is not registered on this hub: %w", m.Target, err)
	}
	src := sourceEndpoint(m)
	remoteSource := src.Workspace == projectmove.WorkspaceDevice || src.Workspace == projectmove.WorkspacePool
	caps := ex.Capabilities()
	switch {
	case caps.SharesHostFilesystem && remoteSource:
		// The source's working copy was on a device or a runner's volume:
		// the hub's own directory is built from its capture (Task 20495).
		return projectmove.DeliverHubTree, ex, nil
	case caps.SharesHostFilesystem:
		return projectmove.DeliverSameTree, ex, nil
	case caps.SupportsBranchBundle:
		if src.Workspace == projectmove.WorkspaceDevice && sameDevice(src, ex) {
			// A device and its virtual executors keep one working copy.
			return projectmove.DeliverSameDevice, ex, nil
		}
		return projectmove.DeliverDevice, ex, nil
	default:
		return projectmove.DeliverForge, ex, nil
	}
}

// sameDevice reports whether a device source and the target executor work on
// one device.
func sameDevice(src projectmove.Endpoint, target executor.Executor) bool {
	device := strings.TrimSpace(src.Parent)
	if device == "" {
		device = src.ExecutorID
	}
	return device != "" && deviceOfExecutor(target).ID() == device
}

// Capture writes the source's bundle and files into the move store.
func (d *moveDriver) Capture(ctx context.Context, m projectmove.Move) (*projectmove.CaptureRecord, error) {
	delivery, _, err := deliveryFor(m)
	if err != nil {
		return nil, err
	}
	rec := &projectmove.CaptureRecord{Delivery: delivery}
	if m.AbandonSource {
		rec.Abandoned = true
		return rec, nil
	}
	src := sourceEndpoint(m)
	if src.Workspace == projectmove.WorkspaceEphemeral {
		// A Pod keeps nothing between runs: there is nothing to capture, and
		// the hub's own copy of the project stays as it is.
		rec.Delivery = projectmove.DeliverNothing
		return rec, nil
	}
	if delivery == projectmove.DeliverSameDevice {
		// The target works in the very working copy the source does.
		rec.From = "device " + nonEmpty(src.Parent, src.ExecutorID)
		rec.WorkDir = src.WorkDir
		rec.Notes = append(rec.Notes, "the target works in the same working copy on the same device; nothing was captured or moved")
		return rec, nil
	}
	dir, err := moveStoreDir(m.ID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the move store: %w", err)
	}
	rec.Store = dir
	project := m.Project.Path

	switch src.Workspace {
	case projectmove.WorkspaceDevice, projectmove.WorkspacePool:
		// Asked of the device, or of a runner attached to the pool's volume,
		// over the agent protocol (Task 20495).
		if src.Workspace == projectmove.WorkspaceDevice {
			err = d.captureFromDevice(ctx, m, rec)
		} else {
			err = d.captureFromPool(ctx, m, rec)
		}
		if err != nil {
			return nil, err
		}
		if delivery == projectmove.DeliverForge {
			if err := forgeHoldsEverything(rec.Git); err != nil {
				return nil, fmt.Errorf("%s builds every run's tree from the forge, and on %s %w; commit and push it there, then move the project again",
					projectmove.DescribeTarget(m.Target), rec.From, err)
			}
		}
		return rec, nil
	}
	rec.From = "hub"

	// What the capture is about to write, against the hub's free-space floor:
	// nothing is written that would take the hub below it.
	estimate, err := movegit.EstimateBytes(ctx, project)
	if err != nil {
		return nil, err
	}
	inv := projectmove.InventoryFiles(project)
	_, filesBytes := inv.Files()
	estimate += filesBytes
	free, err := diskusage.FreeBytes(dir)
	if err != nil {
		return nil, err
	}
	floorMB, _ := d.s.hubFloorMB()
	floor := int64(floorMB) << 20
	if free-estimate < floor {
		return nil, fmt.Errorf("the hub has %s free where the move store is, the capture needs up to %s, and the hub keeps %s free; free some space, then move the project again",
			humanMiB(free), humanMiB(estimate), humanMiB(floor))
	}
	limit := moveStoreMaxBytes
	if delivery == projectmove.DeliverDevice {
		limit = executor.MaxBranchBundleBytes
	}

	bundle := filepath.Join(dir, projectmove.CarrierBundle)
	man, err := movegit.Capture(ctx, movegit.CaptureOptions{MoveID: m.ID, Dir: project, BundlePath: bundle, MaxBundleBytes: limit})
	if err != nil {
		if errors.Is(err, movegit.ErrTooLarge) {
			return nil, fmt.Errorf("the project's repository does not fit in a move to %s: %w", projectmove.DescribeTarget(m.Target), err)
		}
		return nil, err
	}
	rec.Git = man
	rec.Notes = append(rec.Notes, man.Notes...)
	if man.Repository {
		rec.Bundle = projectmove.CarrierBundle
		rec.Bytes += man.Bundle.Bytes
	}
	if delivery == projectmove.DeliverForge {
		if err := forgeHoldsEverything(man); err != nil {
			return nil, fmt.Errorf("%s builds every run's tree from the forge, and %w; commit and push it, then move the project again",
				projectmove.DescribeTarget(m.Target), err)
		}
	}
	files, kept, sum, err := projectmove.PackFiles(project, filepath.Join(dir, projectmove.CarrierFiles), limit-rec.Bytes)
	if err != nil {
		return nil, err
	}
	rec.Files, rec.KeptOnHub, rec.FilesTar, rec.TarSum = files, kept, projectmove.CarrierFiles, &sum
	rec.Bytes += sum.Bytes
	if rec.Bytes > limit {
		return nil, fmt.Errorf("the project's repository and .cloop files come to %s, more than a move to %s carries (%s)",
			humanMiB(rec.Bytes), projectmove.DescribeTarget(m.Target), humanMiB(limit))
	}
	return rec, nil
}

// forgeHoldsEverything says what a forge-built target would not see.
func forgeHoldsEverything(m movegit.Manifest) error {
	if !m.Repository {
		return nil
	}
	var missing []string
	if m.Dirty() {
		missing = append(missing, "the working tree holds uncommitted changes")
	}
	if u := m.Unpushed(); len(u) > 0 {
		names := make([]string, 0, len(u))
		for _, b := range u {
			names = append(names, strings.TrimPrefix(b.Name, "refs/heads/"))
		}
		missing = append(missing, "branches hold commits no remote has ("+strings.Join(names, ", ")+")")
	}
	if len(m.Stash) > 0 {
		missing = append(missing, fmt.Sprintf("the stash holds %d entr(ies)", len(m.Stash)))
	}
	// A device keeps its features' working copies apart, and the capture
	// carries their branches and stashes (Task 20495).
	var branches []string
	stashed := 0
	for _, c := range m.UnpushedCarried() {
		name := m.CarriedName(c)
		if b, ok := strings.CutPrefix(name, "refs/heads/"); ok {
			branches = append(branches, b)
		} else {
			stashed++
		}
	}
	if len(branches) > 0 {
		missing = append(missing, "features' branches hold commits no remote has ("+strings.Join(branches, ", ")+")")
	}
	if stashed > 0 {
		missing = append(missing, fmt.Sprintf("features' stashes hold %d entr(ies)", stashed))
	}
	if len(missing) == 0 {
		return nil
	}
	return errors.New(strings.Join(missing, ", and "))
}

func humanMiB(n int64) string {
	return strconv.FormatFloat(float64(n)/float64(1<<20), 'f', 1, 64) + " MiB"
}

// Switch binds the project to the target, narrowing its firewall rules to the
// target's as a bind does, in one transaction with the move's phase.
func (d *moveDriver) Switch(ctx context.Context, m projectmove.Move) (projectmove.Move, error) {
	s := d.s
	db, err := s.controlPlaneDB()
	if err != nil {
		return projectmove.Move{}, err
	}
	defer db.Close()
	path := m.Project.Path
	prev, ok, err := db.ProjectExecutor(path)
	if err != nil {
		return projectmove.Move{}, err
	}
	if !ok {
		prev = ""
	}
	sw := &projectmove.SwitchRecord{PreviousBinding: strings.TrimSpace(prev), At: time.Now().UTC()}
	policy := executor.PolicyProjectPath(path)
	if rec, has, err := db.ProjectFirewall(policy); err != nil {
		return projectmove.Move{}, err
	} else if has {
		raw, err := json.Marshal(rec.Rules)
		if err != nil {
			return projectmove.Move{}, err
		}
		sw.PreviousFirewall = raw
	}
	m.Detail.Switch = sw
	key := policy
	if abs, err := filepath.Abs(key); err == nil {
		key = filepath.Clean(abs)
	}
	actor := "project-move:" + m.ID
	var changes []firewallChange
	out, err := projectmove.SwitchOn(db, m, projectmove.PhaseSeed, m.Target, m.StartedBy, func(tx *statedb.FirewallTx) error {
		var err error
		changes, err = constrainProjects(tx, func(p string, _ executor.Executor) bool {
			if abs, err := filepath.Abs(p); err == nil {
				p = filepath.Clean(abs)
			}
			return p == key
		}, nil, nil, actor)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return projectmove.Move{}, err
	}
	// The rule set before the switch is in the record either way; whether
	// the switch narrowed it is read back from the audit trail, not needed
	// by a rollback, which restores the recorded rules whenever they differ.
	s.mirrorBinding(path, m.Target)
	for _, c := range changes {
		statedb.AuditProjectFirewall(db, statedb.ProjectFirewallAuditInput{
			Action: "constrain", ProjectPath: c.Subject, ExecutorID: c.executorID, Actor: actor,
			Detail: map[string]any{"from": c.From, "to": c.To,
				"reason": "the project was moved to " + projectmove.DescribeTarget(m.Target) + ": " + strings.Join(c.Notes, "; ")},
		})
	}
	if len(changes) > 0 {
		s.broadcastAuditAppend(auditaction.ActionProjectFirewall.String())
	}
	return out, nil
}

// mirrorBinding puts a binding the journal holds into this process's registry
// and tells the other members.
func (s *Server) mirrorBinding(path, binding string) {
	if strings.TrimSpace(binding) == "" {
		executor.DefaultRegistry.Unbind(path)
	} else if err := executor.Bind(path, binding); err != nil {
		fmt.Fprintf(os.Stderr, "ui: in-memory bind of %s to %s: %v\n", path, binding, err)
	}
	s.publishBindingChange(path)
}

// Seed gives the target what was captured.
func (d *moveDriver) Seed(ctx context.Context, m projectmove.Move) (*projectmove.SeedRecord, error) {
	// A process that resumed after the switch committed has not mirrored it.
	d.s.mirrorBinding(m.Project.Path, m.Target)
	c := m.Detail.Capture
	if c == nil {
		return nil, errors.New("the move has no capture to seed the target with")
	}
	rec := &projectmove.SeedRecord{Delivery: c.Delivery}
	switch c.Delivery {
	case projectmove.DeliverNothing:
		rec.Note = "nothing was captured to deliver"
		return rec, nil
	case projectmove.DeliverSameTree:
		rec.Note = "the target works in the hub's own directory for the project, which already holds everything"
		return rec, nil
	case projectmove.DeliverForge:
		rec.Note = "the target builds each run's tree from the forge, which holds every captured branch"
		return rec, nil
	case projectmove.DeliverSameDevice:
		rec.Note = "the target works in the same working copy on the same device"
		return rec, nil
	case projectmove.DeliverHubTree:
		// The capture came from a device or a runner's volume (Task 20495):
		// the hub's own directory for the project is built from it.
		if err := projectmove.SeedHubTree(ctx, m.Project.Path, m.ID, c, ""); err != nil {
			return nil, err
		}
		rec.WorkDir, rec.Bytes = m.Project.Path, c.Bytes
		rec.Note = "the hub's own directory for the project was built from what " + nonEmpty(c.From, "the source") + " held"
		return rec, nil
	case projectmove.DeliverDevice:
	default:
		return nil, fmt.Errorf("the capture's delivery %q is not one this build knows", c.Delivery)
	}
	ex, err := executor.Get(m.Target)
	if err != nil {
		return nil, fmt.Errorf("the target executor %s is not registered on this hub: %w", m.Target, err)
	}
	if _, held := d.s.agentHeldByPeer(ex); held {
		return nil, errMoveElsewhere
	}
	rec.Executor, rec.WorkDir = ex.ID(), executor.DeviceWorkDir(m.Project.Path)

	// What the device already holds there: nothing, or this move's own
	// partial seed, or a leftover of a move that never left the project
	// there. Anything else is someone's work, which a move never overwrites.
	probe, err := d.runOnTarget(ctx, ex, m, "move-probe", executor.Workspace{Kind: executor.WorkspaceNone}, "")
	if err != nil {
		return nil, err
	}
	if probe.SeededBy == m.ID && !probe.OnCarrier {
		rec.Note = "the device already held this move's seed"
		return rec, nil
	}
	if !probe.Empty && !probe.OnCarrier && probe.Seeding != m.ID && !d.replaceable(probe.SeededBy, m) {
		return nil, fmt.Errorf("device %s already holds files for this project at %s (%s) that this move did not put there, and a move never overwrites them; move them aside on the device, then move the project again",
			ex.ID(), rec.WorkDir, strings.Join(probe.Examples, ", "))
	}

	carrier, bb, err := d.buildCarrier(ctx, m, c)
	if err != nil {
		return nil, err
	}
	defer os.Remove(carrier)
	rec.Bytes = bb.Bytes
	ws := executor.Workspace{Kind: executor.WorkspaceBundle, Branch: &bb}
	report, err := d.runOnTarget(ctx, ex, m, "move-seed", ws, carrier)
	if err != nil {
		return nil, err
	}
	if mm := projectmove.CompareReport(c, report); len(mm) > 0 {
		return nil, fmt.Errorf("the seeded working copy on %s does not hold what was captured: %s", ex.ID(), strings.Join(mm, "; "))
	}
	return rec, nil
}

// replaceable reports whether a working copy a move seeded may be replaced:
// only when that move was this project's and ended without leaving the
// project there, so no run ever worked in it.
func (d *moveDriver) replaceable(seededBy string, m projectmove.Move) bool {
	if seededBy == "" {
		return false
	}
	prev, err := (projectmove.DBStore{Open: d.s.controlPlaneDB}).Get(context.Background(), seededBy)
	if err != nil {
		return false
	}
	return prev.Project.Path == m.Project.Path && (prev.Phase == projectmove.PhaseRolledBack || prev.Phase == projectmove.PhaseFailed)
}

// buildCarrier writes the seed's carrier bundle into the move store.
func (d *moveDriver) buildCarrier(ctx context.Context, m projectmove.Move, c *projectmove.CaptureRecord) (string, executor.BranchBundle, error) {
	sm := projectmove.SeedManifest{MoveID: m.ID, Git: c.Git, Files: c.Files, FilesTar: c.TarSum}
	if origin, err := readGitOrigin(m.Project.Path); err == nil {
		if repo, err := normalizeRemoteToHTTPS(origin.Remote); err == nil {
			sm.Upstream = repo
		}
	}
	raw, err := json.Marshal(sm)
	if err != nil {
		return "", executor.BranchBundle{}, err
	}
	manifest := filepath.Join(c.Store, projectmove.CarrierManifest)
	if err := os.WriteFile(manifest, raw, 0o600); err != nil {
		return "", executor.BranchBundle{}, err
	}
	files := []movegit.CarrierFile{
		{Name: projectmove.CarrierManifest, Path: manifest},
		{Name: projectmove.CarrierFiles, Path: filepath.Join(c.Store, c.FilesTar)},
	}
	if c.Git.Repository {
		files = append(files, movegit.CarrierFile{Name: projectmove.CarrierBundle, Path: filepath.Join(c.Store, c.Bundle)})
	}
	work, err := os.MkdirTemp(c.Store, "carrier-*")
	if err != nil {
		return "", executor.BranchBundle{}, err
	}
	defer os.RemoveAll(work)
	out := filepath.Join(c.Store, "seed.bundle")
	car, err := movegit.BuildCarrier(ctx, work, projectmove.CarrierBranch(m.ID), files, out, executor.MaxBranchBundleBytes)
	if err != nil {
		return "", executor.BranchBundle{}, err
	}
	return out, executor.BranchBundle{Branch: car.Branch, Head: car.Head, Bytes: car.Digest.Bytes, SHA256: car.Digest.SHA256}, nil
}

// runOnTarget runs one `cloop workspace <command>` of the move on the target
// and returns the report it printed. The workload runs no harness and is
// leased nothing: it only rebuilds or reads the project's working copy.
func (d *moveDriver) runOnTarget(ctx context.Context, ex executor.Executor, m projectmove.Move, command string, ws executor.Workspace, bundle string, extra ...string) (projectmove.WorkingCopyReport, error) {
	path := m.Project.Path
	clear := newLeaseClearance(path, harnessWho{})
	if _, err := clear.settle(ex, path); err != nil {
		return projectmove.WorkingCopyReport{}, err
	}
	spec := executor.Spec{
		WorkDir: path,
		Argv:    append([]string{d.s.selfExe(), "workspace", command, "--move", m.ID}, extra...),
		Labels: map[string]string{
			"project": path, "handler": "project-move", "move": m.ID, "move_step": command,
		},
		Workspace:        ws,
		BranchBundleFile: bundle,
		TimeoutMinutes:   int(moveWorkloadTimeout / time.Minute),
	}
	executor.DeviceArgv(&spec, ex)
	spec.WorkDir = executor.DeviceWorkDir(spec.WorkDir)
	// The firewall levels that govern the target — the device's, a virtual
	// executor's, the project's — bind a move's workloads as they bind a
	// run's: the steps need no network, and get no more of one than a run.
	spec, _, err := applyFirewall(spec, ex, path)
	if err != nil {
		return projectmove.WorkingCopyReport{}, err
	}
	// And the operator's ceilings.
	spec, _ = applyResourceCeiling(spec, path, ex)
	if err := executor.CheckSandboxSupport(ex, spec.SandboxRequirements(), path); err != nil {
		return projectmove.WorkingCopyReport{}, err
	}
	rctx, cancel := context.WithTimeout(ctx, moveWorkloadTimeout)
	defer cancel()
	res, runErr := executor.Run(rctx, ex, spec)
	out := string(res.Output)
	if len(out) > moveOutputMax {
		out = out[len(out)-moveOutputMax:]
	}
	if ctx.Err() != nil {
		return projectmove.WorkingCopyReport{}, ctx.Err()
	}
	if runErr != nil {
		return projectmove.WorkingCopyReport{}, fmt.Errorf("`cloop workspace %s` on %s failed: %v%s", command, ex.ID(), runErr, outputTail(out))
	}
	report, err := projectmove.ParseReport(out)
	if err != nil {
		return projectmove.WorkingCopyReport{}, fmt.Errorf("`cloop workspace %s` on %s: %v (the device's cloop may predate project moves)%s", command, ex.ID(), err, outputTail(out))
	}
	return report, nil
}

// outputTail quotes the end of a workload's output for an error.
func outputTail(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return ""
	}
	if len(out) > 600 {
		out = "…" + out[len(out)-600:]
	}
	return ": " + out
}

// Verify reads the target back and compares it with the capture.
func (d *moveDriver) Verify(ctx context.Context, m projectmove.Move) (*projectmove.VerifyRecord, error) {
	c := m.Detail.Capture
	if c == nil {
		return nil, errors.New("the move has no capture to verify the target against")
	}
	rec := &projectmove.VerifyRecord{Delivery: c.Delivery}
	switch c.Delivery {
	case projectmove.DeliverNothing, projectmove.DeliverSameDevice:
		return rec, nil
	case projectmove.DeliverSameTree, projectmove.DeliverHubTree:
		o, err := movegit.Inspect(ctx, m.Project.Path, movegit.InspectOptions{})
		if err != nil {
			return nil, err
		}
		for _, mm := range movegit.Compare(c.Git, o) {
			rec.Mismatches = append(rec.Mismatches, mm.String())
		}
		rec.Mismatches = append(rec.Mismatches, projectmove.CheckFiles(filepath.Join(m.Project.Path, ".cloop"), c.Files)...)
		rec.Checked = checkedCount(c)
		return rec, nil
	case projectmove.DeliverForge:
		if err := forgeHoldsEverything(c.Git); err != nil {
			rec.Mismatches = append(rec.Mismatches, err.Error())
		}
		// The .cloop files stay in the hub's copy, which seeds every run.
		rec.Mismatches = append(rec.Mismatches, projectmove.CheckFiles(filepath.Join(m.Project.Path, ".cloop"), c.Files)...)
		rec.Checked = checkedCount(c)
		return rec, nil
	case projectmove.DeliverDevice:
	default:
		return nil, fmt.Errorf("the capture's delivery %q is not one this build knows", c.Delivery)
	}
	ex, err := executor.Get(m.Target)
	if err != nil {
		return nil, fmt.Errorf("the target executor %s is not registered on this hub: %w", m.Target, err)
	}
	if _, held := d.s.agentHeldByPeer(ex); held {
		return nil, errMoveElsewhere
	}
	report, err := d.runOnTarget(ctx, ex, m, "move-verify", executor.Workspace{Kind: executor.WorkspaceNone}, "")
	if err != nil {
		return nil, err
	}
	rec.Mismatches = projectmove.CompareReport(c, report)
	rec.Checked = checkedCount(c)
	return rec, nil
}

// checkedCount is how many things verification compared.
func checkedCount(c *projectmove.CaptureRecord) int {
	n := len(c.Files)
	if c.Git.Repository {
		n += len(c.Git.Branches) + len(c.Git.Tags) + len(c.Git.Stash) + len(c.Git.Carried) + 3 // HEAD, the index, the working tree
		for _, w := range c.Git.Worktrees {
			if w.Ref != "" {
				n++
			}
		}
	}
	return n
}

// RollBack restores the binding — and the firewall rules — the switch
// replaced, in one transaction with the move's phase.
func (d *moveDriver) RollBack(ctx context.Context, m projectmove.Move) (projectmove.Move, error) {
	s := d.s
	db, err := s.controlPlaneDB()
	if err != nil {
		return projectmove.Move{}, err
	}
	defer db.Close()
	prev := m.Source
	policy := executor.PolicyProjectPath(m.Project.Path)
	var prevRules *executor.FirewallRules
	if sw := m.Detail.Switch; sw != nil {
		prev = sw.PreviousBinding
		if len(sw.PreviousFirewall) > 0 {
			var r executor.FirewallRules
			if err := json.Unmarshal(sw.PreviousFirewall, &r); err != nil {
				return projectmove.Move{}, fmt.Errorf("read the firewall rules the switch replaced: %w", err)
			}
			// Restored only when the switch narrowed them: rules that are
			// still the recorded ones need no write.
			if cur, ok, err := db.ProjectFirewall(policy); err != nil {
				return projectmove.Move{}, err
			} else if !ok || fwpolicy.Describe(&cur.Rules) != fwpolicy.Describe(&r) {
				prevRules = &r
			}
		}
	}
	if rb := m.Detail.Rollback; rb != nil {
		m.FailedPhase, m.Error = rb.FailedPhase, rb.Reason
		rb.Pending = false
	}
	restore := func(tx *statedb.FirewallTx) error {
		if prevRules == nil {
			return nil
		}
		return tx.SetProjectFirewall(policy, *prevRules, "project-move:"+m.ID)
	}
	out, err := projectmove.SwitchOn(db, m, projectmove.PhaseRolledBack, prev, m.StartedBy, restore)
	if err != nil && prev != "" && (errors.Is(err, statedb.ErrExecutorNotFound) ||
		errors.Is(err, statedb.ErrExecutorPoolNotFound) || errors.Is(err, statedb.ErrExecutorPoolRevoked)) {
		// The executor or pool the switch replaced is gone: there is no
		// binding to put back. Unbound, the project's next run goes to the
		// hub's default executor, which a hub that runs nothing on its own
		// host refuses — and the move says so.
		m.Error = strings.TrimSuffix(m.Error, ".") + fmt.Sprintf("; the binding the move replaced, %s, no longer exists, so the project was left unbound", prev)
		prev = ""
		out, err = projectmove.SwitchOn(db, m, projectmove.PhaseRolledBack, "", m.StartedBy, restore)
	}
	if err != nil {
		return projectmove.Move{}, err
	}
	s.mirrorBinding(m.Project.Path, prev)
	if prevRules != nil {
		statedb.AuditProjectFirewall(db, statedb.ProjectFirewallAuditInput{
			Action: "set", ProjectPath: policy, Actor: "project-move:" + m.ID,
			Detail: map[string]any{"to": fwpolicy.Describe(prevRules), "reason": "the move was rolled back"},
		})
	}
	return out, nil
}

// Retain says what a verified move keeps, and how to clean it up.
func (d *moveDriver) Retain(_ context.Context, m projectmove.Move) *projectmove.Retained {
	c := m.Detail.Capture
	r := &projectmove.Retained{Command: moveCleanupCommand(m)}
	if c != nil {
		r.Store = c.Store
		if c.Git.Snapshot != nil && c.Git.Snapshot.Ref != "" {
			r.Refs = append(r.Refs, c.Git.Snapshot.Ref)
		}
		for _, w := range c.Git.Worktrees {
			if w.Ref != "" {
				r.Refs = append(r.Refs, w.Ref)
			}
		}
		for _, st := range c.Git.Stash {
			r.Refs = append(r.Refs, st.Name)
		}
		for _, cr := range c.Git.Carried {
			r.Refs = append(r.Refs, cr.Name)
		}
	}
	switch {
	case c == nil || c.Delivery == projectmove.DeliverNothing && c.Abandoned:
		r.Source = "the source was abandoned: nothing was captured from it, and nothing of it was removed"
	case c.Delivery == projectmove.DeliverSameDevice:
		r.Source = "the target works in the same working copy, on " + nonEmpty(c.From, "the same device") + "; nothing was captured or moved"
	case c.From != "" && c.From != "hub":
		r.Source = nonEmpty(c.From, "the source") + " keeps its working copy as it was"
		if c.WorkDir != "" {
			r.Source += ", at " + c.WorkDir
		}
		r.Source += ", with the move's hidden refs in its repository; runs now work on " + projectmove.DescribeTarget(m.Target)
	case c.Delivery == projectmove.DeliverSameTree:
		r.Source = "the target works in the same directory on the hub, " + m.Project.Path + ", which is kept as it was"
	default:
		r.Source = "the hub keeps " + m.Project.Path + " as it was: the project's state, its features' worktrees and the working tree the move captured; runs now work on " +
			projectmove.DescribeTarget(m.Target)
	}
	return r
}

// cleanupMove removes what a move kept on the hub: its hidden refs in the
// project's repository and its directory in the move store. The project's
// directory on the hub is its home — its state and its features — and is never
// removed; a device's copy is removed before this, by discardSourceCopy, and
// only for a verified move (Task 20496). keptSource records that the caller
// asked to leave a removable source copy where it is.
func (s *Server) cleanupMove(ctx context.Context, m projectmove.Move, actor string, keptSource bool) (projectmove.Move, error) {
	if m.Open() {
		return m, projectmove.ErrStillOpen
	}
	if m.Detail.Retained != nil && !m.Detail.Retained.CleanedAt.IsZero() {
		return m, nil
	}
	refs := moveRefs(m)
	if len(refs) > 0 {
		if info, err := os.Stat(m.Project.Path); err == nil && info.IsDir() {
			for _, ref := range refs {
				if !strings.HasPrefix(ref, movegit.SnapshotRefPrefix+m.ID) && !strings.HasPrefix(ref, movegit.WorktreeRefPrefix+m.ID+"/") &&
					!strings.HasPrefix(ref, movegit.StashRefPrefix+m.ID+"/") && !strings.HasPrefix(ref, movegit.ExternalRefPrefix+m.ID+"/") {
					continue
				}
				if err := movegit.DeleteRef(ctx, m.Project.Path, ref); err != nil {
					return m, err
				}
			}
		}
	}
	if dir, err := moveStoreDir(m.ID); err == nil {
		if err := os.RemoveAll(dir); err != nil {
			return m, fmt.Errorf("remove the move's store: %w", err)
		}
	}
	if m.Detail.Retained == nil {
		m.Detail.Retained = &projectmove.Retained{Command: moveCleanupCommand(m)}
	}
	m.Detail.Retained.CleanedAt = time.Now().UTC()
	m.Detail.Retained.CleanedBy = actor
	m.Detail.Retained.SourceKept = keptSource
	out, err := (projectmove.DBStore{Open: s.controlPlaneDB}).Advance(ctx, m, m.Phase)
	if err != nil {
		return m, err
	}
	extra := map[string]any{"actor": actor, "refs": refs}
	if r := out.Detail.Retained; r != nil && r.SourceRemoved != "" {
		extra["source_removed"] = r.SourceRemoved
	}
	if keptSource {
		extra["source_kept"] = true
	}
	s.auditMove(auditaction.ActionProjectMoveCleanup, out, extra)
	return out, nil
}

// ─── handlers ───────────────────────────────────────────────────────────────

// handleProjectMoveStart serves POST /api/projects/{idx}/move.
func (s *Server) handleProjectMoveStart(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return
	}
	if entry.IsFeature() {
		jsonErr(w, fmt.Sprintf("feature %s runs where its project is bound and moves with it: move %s", entry.Feature, entry.Parent), http.StatusConflict)
		return
	}
	var req struct {
		Target        string `json:"target"`
		AbandonSource bool   `json:"abandon_source"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	target, err := projectmove.ParseTarget(req.Target)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch {
	case target.ExecutorID != "":
		if !s.admitExecutorAudience(w, r, target.ExecutorID) {
			return
		}
	case target.PoolID != "":
		if !s.admitPoolAudience(w, r, target.PoolID) {
			return
		}
	}
	registerBuiltinExecutors()
	env := &moveEnv{s: s, r: r, now: time.Now()}
	defer env.close()
	m, rep, err := s.moveEngine().Start(r.Context(), env, projectmove.StartRequest{
		Project: projectmove.Project{Name: entry.Name, Path: entry.Path}, Target: target.Binding,
		AbandonSource: req.AbandonSource, StartedBy: s.auditActor(r), Starter: s.harnessWhoFor(r).identity,
	})
	var blocked *projectmove.BlockedError
	switch {
	case errors.As(err, &blocked):
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error": "the preflight blocks the move", "code": "move_blocked", "move": m, "report": rep})
		return
	case errors.Is(err, projectmove.ErrMoveOpen):
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error": "the project already has a move in progress", "code": "move_in_progress", "move": m})
		return
	case errors.Is(err, projectmove.ErrSourceUnsupported):
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error": strings.TrimPrefix(err.Error(), "projectmove: "), "code": "move_source_unsupported", "move": m, "report": rep})
		return
	case errors.Is(err, projectmove.ErrInvalidTarget), errors.Is(err, projectmove.ErrInvalidProject):
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, projectmove.ErrFeature):
		jsonErr(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		jsonErr(w, "cannot move "+entry.Name+" right now: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.startMoveDriver(m.ID)
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"move": m, "report": rep})
}

// handleProjectMoves serves GET /api/projects/{idx}/moves.
func (s *Server) handleProjectMoves(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	moves, err := projectmove.ListMoves(db, statedb.ProjectMoveFilter{ProjectPath: policyProjectPath(entry.Path), Limit: 50})
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if moves == nil {
		moves = []projectmove.Move{}
	}
	jsonOK(w, map[string]any{"moves": moves})
}
