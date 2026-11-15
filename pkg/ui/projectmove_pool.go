package ui

// projectmove_pool.go captures a project whose working copy is on an executor
// pool's runner volume (Task 20495).
//
// A volume is read by a runner attached to it, and runners are the pool
// controller's to start: the hub knows runs, the controller knows volumes
// (pkg/executorpool's tenant.go). So the move asks for one the way a run
// does — an entry in the pool's queue for the project, which the controller's
// feed shows as the project's demand, and which a controller keeping volumes
// answers with a runner on the volume holding the project's tenant — and the
// dispatcher hands that entry only to a runner whose storage holds exactly
// that tenant: never one holding nothing, which has nothing of the project,
// and never another project's. The runner checks the tenant itself before it
// answers (the agent's admitCaptureTenant). Once the entry is assigned, the
// member holding the runner's connection captures from it over the agent
// protocol, as from a device, and retires the runner; the entry closes as
// dispatched. If no runner on the volume comes up within movePoolAttachTimeout
// the capture fails, before anything switches, and says what to do: a pool
// whose controller no longer keeps the project's volume holds nothing to
// capture, and the move goes ahead with abandon_source.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// moveCaptureHandler is the handler of a pool queue entry that asks for a
// runner on the project's volume for a move's capture, not for a run.
const moveCaptureHandler = "project-move-capture"

// Tunables, variables so tests can shorten them.
var (
	// movePoolAttachTimeout bounds how long a capture waits for a runner on
	// the project's volume: a controller starting a Pod and attaching a
	// claim.
	movePoolAttachTimeout = 15 * time.Minute
	// movePoolPoll is how often the capture looks at its queue entry.
	movePoolPoll = time.Second
	// movePoolNudgeAfter is how long a capture's request waits before the
	// hub makes room for a runner on the project's volume, and
	// movePoolNudgeEvery how often it may again.
	movePoolNudgeAfter = 30 * time.Second
	movePoolNudgeEvery = 2 * time.Minute
)

// moveCaptureQueueID is the queue entry a move's capture asks a pool with.
func moveCaptureQueueID(moveID string) string { return "q-move-" + moveID }

// isMoveCapture reports whether a queue entry is a move's capture.
func isMoveCapture(q statedb.PoolQueueRow) bool { return q.Handler == moveCaptureHandler }

// poolVolumes is what a pool's controllers report of its runner volumes:
// VolumesKept when one reports a claim, VolumesNone when the ones reporting
// storage report none, "" when none has said.
func (s *Server) poolVolumes(poolID string) string {
	store, err := s.poolStore()
	if err != nil {
		return ""
	}
	reports, err := store.DB().PoolControllerStatuses(poolID)
	if err != nil {
		return ""
	}
	said := false
	for _, r := range reports {
		u := executorpool.DecodeStorage(r.Storage)
		if u == nil {
			continue
		}
		said = true
		if u.Claims+u.Retained > 0 {
			return projectmove.VolumesKept
		}
	}
	if said {
		return projectmove.VolumesNone
	}
	return ""
}

// capturesHere reports whether this member should run m's capture: a device
// source's on the member holding the device's connection, a pool source's on
// the member holding the runner its queue entry was handed.
func (s *Server) capturesHere(m projectmove.Move) bool {
	src := sourceEndpoint(m)
	switch src.Workspace {
	case projectmove.WorkspaceDevice:
		id := src.ExecutorID
		if id == "" {
			id = m.Source
		}
		_, _, device, err := sourceCapturer(id)
		if err != nil {
			return true // the capture says what is wrong
		}
		_, held := s.agentHeldByPeer(device)
		return !held
	case projectmove.WorkspacePool:
		store, err := s.poolStore()
		if err != nil {
			return true
		}
		q, err := store.DB().GetPoolQueueEntry(moveCaptureQueueID(m.ID))
		if err != nil || q.ExecutorID == "" || (q.State != statedb.PoolQueueAssigned && q.State != statedb.PoolQueueDispatched) {
			return true
		}
		return q.Member == s.hubInstanceID() || !s.poolMemberAlive(q.Member)
	}
	return true
}

// moveOfCaptureEntry is the move a capture's queue entry was queued for.
func moveOfCaptureEntry(q statedb.PoolQueueRow) (string, bool) {
	return strings.CutPrefix(q.ID, "q-move-")
}

// moveCapturing reports whether the move a capture's queue entry was queued
// for is still capturing. A move the hub cannot read is taken to be: nothing
// is taken back from a capture on a guess.
func (s *Server) moveCapturing(q statedb.PoolQueueRow) bool {
	id, ok := moveOfCaptureEntry(q)
	if !ok {
		return false
	}
	m, err := (projectmove.DBStore{Open: s.controlPlaneDB}).Get(context.Background(), id)
	if errors.Is(err, projectmove.ErrNotFound) {
		return false
	}
	if err != nil {
		return true
	}
	return m.Open() && m.Phase == projectmove.PhaseCapture
}

// settleMoveCaptureEntries takes back the waiting or assigned queue entries of
// moves that are no longer capturing, and retires a runner one was handed. A
// capture takes its entry back itself when it ends; one cut short — the hub
// stopped part-way — leaves it behind, and the pool's controller would keep a
// runner up on the project's volume for it. A runner a finished capture left
// busy is retireFinishedPoolRunners'.
func (s *Server) settleMoveCaptureEntries(store *executorpool.Store, now time.Time) {
	db := store.DB()
	for _, state := range []string{statedb.PoolQueueWaiting, statedb.PoolQueueAssigned} {
		rows, err := db.ListPoolQueue("", state)
		if err != nil {
			continue
		}
		for _, q := range rows {
			if !isMoveCapture(q) || s.moveCapturing(q) {
				continue
			}
			const reason = "the project move it was queued for is no longer capturing"
			if moved, _ := db.MovePoolQueueEntry(q.ID, []string{q.State}, statedb.PoolQueueCancelled, reason, now); moved {
				store.AuditQueue(q, "cancelled", "system", reason)
				if q.ExecutorID != "" {
					s.retirePoolRunnerIf(q.ExecutorID, reason, statedb.PoolRunnerBusy, statedb.PoolRunnerIdle)
				}
				s.poolChanged(q.PoolID)
			}
		}
	}
}

// captureFromPool captures the project from the runner volume its pool keeps
// for it, into rec's store.
func (d *moveDriver) captureFromPool(ctx context.Context, m projectmove.Move, rec *projectmove.CaptureRecord) error {
	s := d.s
	poolID, ok := executor.PoolOf(m.Source)
	if !ok {
		return fmt.Errorf("the move's source %q is not a pool binding", m.Source)
	}
	store, err := s.poolStore()
	if err != nil {
		return err
	}
	pool, err := store.Get(poolID)
	if err != nil {
		return fmt.Errorf("executor pool %s: %w", poolID, err)
	}
	if pool.Revoked() {
		return fmt.Errorf("executor pool %s was revoked, and its volumes with it; move the project with abandon_source", pool.Name)
	}
	if pool.Cordoned() {
		return fmt.Errorf("executor pool %s is cordoned, so none of its runners is handed the capture; uncordon it, then move the project again", pool.Name)
	}
	rec.From = "executor pool " + pool.Name
	if s.poolVolumes(pool.ID) == projectmove.VolumesNone {
		// Nothing kept between runs: there is no volume to read.
		rec.Notes = append(rec.Notes, "executor pool "+pool.Name+"'s controller keeps no runner volumes: nothing was captured")
		rec.Git = movegit.Manifest{Version: movegit.ManifestVersion, MoveID: m.ID, Branches: []movegit.Ref{}}
		return writeEmptyFiles(rec)
	}
	access := s.poolAccessFor(store)
	tenant, _, _, known := executorpool.TenantOf(pool.ID, m.Project.Path, access)
	if !known {
		return fmt.Errorf("the hub cannot say whose project %s is, so it cannot tell executor pool %s which volume holds it", m.Project.Name, pool.Name)
	}
	q, err := s.ensureCaptureEntry(m, store, pool)
	if err != nil {
		return err
	}
	actor := "project-move:" + m.ID
	settled := false
	defer func() {
		if !settled {
			// Taken back, so it waits for nothing and no runner stays busy
			// for it: one it was handed in the meantime is retired.
			cur, err := store.DB().GetPoolQueueEntry(q.ID)
			if err != nil {
				return
			}
			if moved, _ := store.DB().MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueWaiting, statedb.PoolQueueAssigned},
				statedb.PoolQueueCancelled, "the project move's capture ended", time.Now()); moved {
				store.AuditQueue(cur, "cancelled", actor, "the project move's capture ended")
				if cur.ExecutorID != "" {
					s.retirePoolRunnerBy(actor, cur.ExecutorID, "the project move's capture ended before it read the runner's volume",
						statedb.PoolRunnerBusy, statedb.PoolRunnerIdle)
				}
				s.poolChanged(pool.ID)
			}
		}
	}()
	s.poolChanged(pool.ID)
	started := time.Now()
	deadline := started.Add(movePoolAttachTimeout)
	var nudged time.Time
	for {
		cur, err := store.DB().GetPoolQueueEntry(q.ID)
		if err != nil {
			return err
		}
		if cur.State == statedb.PoolQueueWaiting && time.Since(started) >= movePoolNudgeAfter &&
			time.Since(nudged) >= movePoolNudgeEvery {
			nudged = time.Now()
			s.makeRoomForCapture(store, pool, cur, actor)
		}
		switch cur.State {
		case statedb.PoolQueueFailed, statedb.PoolQueueCancelled:
			settled = true
			return fmt.Errorf("executor pool %s took back the move's request for the project's volume: %s; move the project again",
				pool.Name, nonEmpty(cur.Reason, cur.State))
		case statedb.PoolQueueAssigned, statedb.PoolQueueDispatched:
			if cur.Member != s.hubInstanceID() && s.poolMemberAlive(cur.Member) {
				// The member holding the runner's connection captures.
				settled = true
				return errMoveElsewhere
			}
			if cur.Member != s.hubInstanceID() || !s.runnerReachableHere(cur.ExecutorID) {
				// A member that went away, or a runner this process no
				// longer holds: the runner goes, the request waits again.
				s.retirePoolRunnerBy(actor, cur.ExecutorID, "the project move's capture lost it", statedb.PoolRunnerBusy, statedb.PoolRunnerIdle)
				if moved, _ := store.DB().MovePoolQueueEntry(cur.ID, []string{statedb.PoolQueueAssigned, statedb.PoolQueueDispatched},
					statedb.PoolQueueWaiting, "its runner was lost; waiting for another", time.Now()); moved {
					s.poolChanged(pool.ID)
				}
				break
			}
			settled = true
			return d.captureOnRunner(ctx, m, rec, store, pool, cur, tenant)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("executor pool %s started no runner on the volume holding %s (tenant %s) within %s: its controller "+
				"keeps no volume for the project any more, or cannot attach it (the pool's status says why); "+
				"if the volume is gone, move the project with abandon_source", pool.Name, m.Project.Name, tenant, movePoolAttachTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(movePoolPoll):
		}
	}
}

// makeRoomForCapture retires one idle runner of the pool that holds nothing,
// when a capture's request waits and no other run does. A controller counts an
// idle runner as meeting the pool's demand whatever its volume holds, so with
// a runner holding nothing kept idle — a pool's minimum — it would start none
// on the project's volume until that one idled out. Retired, it is replaced,
// and the controller starts the replacement on the volume the feed's queued
// tenant names. The hub retires idle runners on its own clock anyway; this
// does it sooner, once per movePoolNudgeEvery.
func (s *Server) makeRoomForCapture(store *executorpool.Store, pool executorpool.Pool, q statedb.PoolQueueRow, actor string) {
	waiting, err := store.DB().ListPoolQueue(pool.ID, statedb.PoolQueueWaiting)
	if err != nil {
		return
	}
	for _, w := range waiting {
		if w.ID != q.ID {
			// Another run waits, and takes the idle runner.
			return
		}
	}
	idle, err := store.DB().ListExecutorPoolRunners(pool.ID, statedb.PoolRunnerIdle)
	if err != nil {
		return
	}
	for _, r := range idle {
		if r.Holds == "" && r.ExecutorID != "" {
			s.retirePoolRunnerBy(actor, r.ExecutorID,
				"it holds nothing of the project a move is capturing, so its pool can start a runner on the project's volume instead",
				statedb.PoolRunnerIdle)
			return
		}
	}
}

// ensureCaptureEntry queues the move's request for a runner on the project's
// volume, or finds the one it queued before — still waiting, handed to a
// runner, or taken back, which it queues again.
func (s *Server) ensureCaptureEntry(m projectmove.Move, store *executorpool.Store, pool executorpool.Pool) (statedb.PoolQueueRow, error) {
	id := moveCaptureQueueID(m.ID)
	reason := "waiting for a runner on the project's volume, for the project move's capture"
	if q, err := store.DB().GetPoolQueueEntry(id); err == nil {
		switch q.State {
		case statedb.PoolQueueWaiting, statedb.PoolQueueAssigned, statedb.PoolQueueDispatched:
			return q, nil
		}
		if moved, err := store.DB().MovePoolQueueEntry(id, []string{statedb.PoolQueueCancelled, statedb.PoolQueueFailed},
			statedb.PoolQueueWaiting, reason, time.Now()); err != nil {
			return statedb.PoolQueueRow{}, err
		} else if moved {
			store.AuditQueue(q, "requeued", "project-move:"+m.ID, reason)
		}
		return store.DB().GetPoolQueueEntry(id)
	}
	entries, err := store.Audience(pool.ID)
	if err != nil {
		return statedb.PoolQueueRow{}, fmt.Errorf("read executor pool %s's access list: %w", pool.Name, err)
	}
	req, err := poolRunRequirements(m.Project.Path)
	if err != nil {
		return statedb.PoolQueueRow{}, err
	}
	encoded, err := executorpool.EncodeRequirements(req)
	if err != nil {
		return statedb.PoolQueueRow{}, err
	}
	row := statedb.PoolQueueRow{
		ID:           id,
		PoolID:       pool.ID,
		ProjectPath:  m.Project.Path,
		Handler:      moveCaptureHandler,
		Starter:      m.Detail.Starter,
		AudienceFP:   executorpool.AudienceFingerprint(entries),
		Requirements: encoded,
		Reason:       reason,
		Member:       s.hubInstanceID(),
	}
	if err := store.DB().EnqueuePoolRun(row); err != nil {
		if errors.Is(err, statedb.ErrPoolRunAlreadyQueued) {
			return statedb.PoolQueueRow{}, errors.New("a run of the project is waiting in the pool's queue, which the move stopped; move the project again")
		}
		return statedb.PoolQueueRow{}, fmt.Errorf("ask executor pool %s for the project's volume: %w", pool.Name, err)
	}
	store.AuditQueue(row, "queued", "project-move:"+m.ID, row.Reason)
	return row, nil
}

// runnerReachableHere reports whether this member can ask runner id for a
// capture: registered here, answering captures, and connected to this member
// rather than to another.
func (s *Server) runnerReachableHere(id string) bool {
	ex, err := executor.Get(id)
	if err != nil {
		return false
	}
	if _, ok := capturerOf(ex); !ok {
		return false
	}
	if _, held := s.agentHeldByPeer(ex); held {
		return false
	}
	if c, ok := ex.(interface{ Connected() bool }); ok && !c.Connected() {
		return false
	}
	return true
}

// captureOnRunner captures from the runner the pool's queue entry was handed,
// and retires it.
func (d *moveDriver) captureOnRunner(ctx context.Context, m projectmove.Move, rec *projectmove.CaptureRecord,
	store *executorpool.Store, pool executorpool.Pool, q statedb.PoolQueueRow, tenant string) error {
	s := d.s
	actor := "project-move:" + m.ID
	defer s.retirePoolRunnerBy(actor, q.ExecutorID, "the project move captured its volume", statedb.PoolRunnerBusy, statedb.PoolRunnerIdle)
	if moved, _ := store.DB().MovePoolQueueEntry(q.ID, []string{statedb.PoolQueueAssigned}, statedb.PoolQueueDispatched,
		"", time.Now()); moved {
		store.AuditQueue(q, "dispatched", actor, "the project move captures the runner's volume")
	}
	ex, err := executor.Get(q.ExecutorID)
	if err != nil {
		return fmt.Errorf("runner %s of executor pool %s is gone: %w", q.ExecutorID, pool.Name, err)
	}
	c, ok := capturerOf(ex)
	if !ok {
		return fmt.Errorf("runner %s of executor pool %s is not an agent the hub can ask", q.ExecutorID, pool.Name)
	}
	rec.From = fmt.Sprintf("runner %s of executor pool %s", q.ExecutorID, pool.Name)
	features, err := captureFeatures(m.Project.Path)
	if err != nil {
		return err
	}
	req := remote.CaptureRequest{Mode: remote.CaptureFull, MoveID: m.ID, WorkDir: executor.DeviceWorkDir(m.Project.Path),
		Features: features, Tenant: tenant}
	return d.collectCapture(ctx, m, rec, c, req, captureScope{executor: ex, poolLabels: pool.Labels})
}

// writeEmptyFiles records that nothing of the source's .cloop was captured,
// with the empty tar the seeds expect.
func writeEmptyFiles(rec *projectmove.CaptureRecord) error {
	_, _, sum, err := projectmove.PackFileSets(filepath.Join(rec.Store, projectmove.CarrierFiles), 0)
	if err != nil {
		return err
	}
	rec.FilesTar, rec.TarSum, rec.Bytes = projectmove.CarrierFiles, &sum, sum.Bytes
	return nil
}

// pickCaptureRunner is pickPoolRunner for a move's capture: only a runner
// holding exactly the project's tenant; -1 while none does.
func pickCaptureRunner(holds []string, tenant string) int {
	if strings.TrimSpace(tenant) == "" {
		return -1
	}
	for i, h := range holds {
		if h == tenant {
			return i
		}
	}
	return -1
}
