// Package watchdog detects in-flight PM tasks that have stalled — a provider
// that never returns, an infinite tool loop, a network partition that hangs
// the request without erroring. It runs as a background goroutine alongside
// the orchestrator and surfaces stuck tasks via three channels:
//
//  1. structured logs (logger.EventTaskStuck)
//  2. a stuck_tasks row in statedb (forensics + UI surfacing)
//  3. an optional per-task callback (used by the UI to push WS events)
//
// A task is considered stuck when:
//
//   - its in-memory status is in_progress
//   - StartedAt is older than StuckThreshold (default 10 min), AND
//   - its live artifact file (.cloop/artifacts/<id>_output.txt) has not been
//     modified in the last ArtifactQuiet window (default 5 min)
//
// The artifact-mtime guard is the false-positive suppressor: a long-running
// task that is still actively producing tokens will keep its live artifact
// growing, so it is not flagged. Only tasks that have *stopped* producing
// output AND have already been running longer than StuckThreshold trip the
// detector.
//
// The optional AutoKillAfter setting cancels a per-task context after a task
// has been continuously stuck for that duration. The orchestrator owns the
// per-task context and registers a cancel function via Register before the
// task starts. The watchdog calls it from the goroutine; the orchestrator's
// existing isTimeoutErr / handleTaskTimeout paths surface the cancellation
// as a normal task failure.
package watchdog

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Defaults applied when the corresponding Watchdog field is zero.
const (
	DefaultInterval        = 30 * time.Second
	DefaultStuckThreshold  = 10 * time.Minute
	DefaultArtifactQuiet   = 5 * time.Minute
)

// PlanProvider yields the current set of in-flight tasks each tick.
// Returning nil is treated as "no plan available — skip this tick".
type PlanProvider func() *pm.Plan

// EventSink receives one StuckEvent per detection. The watchdog calls it
// synchronously from its goroutine; sinks must be non-blocking or do their
// own buffering.
type EventSink func(StuckEvent)

// StuckEvent describes one stuck-task detection.
type StuckEvent struct {
	TaskID            int       `json:"task_id"`
	TaskTitle         string    `json:"task_title"`
	StartedAt         time.Time `json:"started_at"`
	StuckSince        time.Time `json:"stuck_since"`         // when the watchdog first flagged this run
	ArtifactPath      string    `json:"artifact_path"`       // resolved live-artifact path, if any
	ArtifactModTime   time.Time `json:"artifact_mod_time"`   // mtime at detection (zero if missing)
	StuckDuration     string    `json:"stuck_duration"`      // human-readable since StuckSince
	WorkDir           string    `json:"work_dir"`
	WillCancel        bool      `json:"will_cancel"`         // true when AutoKillAfter trips on this tick
	DetectedAt        time.Time `json:"detected_at"`
}

// Watchdog inspects the orchestrator's in-flight tasks every Interval and
// reports any whose StartedAt + ArtifactQuiet windows have both elapsed.
//
// All exported fields may be left zero — defaults are applied at Start time.
// Callers should fully construct the Watchdog (set WorkDir, GetPlan, and at
// least one of {Logger, DB, OnStuck} for visibility), call Register for each
// task before launching it, then Start once before the orchestrator loop.
// Stop the watchdog via context cancellation.
type Watchdog struct {
	// WorkDir is the project root used to resolve live-artifact paths and
	// to record stuck events into the project's statedb. Required.
	WorkDir string

	// GetPlan returns the current plan (called once per tick). When nil, the
	// watchdog falls back to reading state from disk via state.Load — but
	// passing the in-memory plan is preferred so the watchdog reflects what
	// the orchestrator is actually executing, not the persisted snapshot.
	GetPlan PlanProvider

	// Interval is how often the watchdog inspects tasks. Zero -> 30s.
	Interval time.Duration

	// StuckThreshold is the minimum elapsed time since a task's StartedAt
	// before it can be flagged. Zero -> 10m.
	StuckThreshold time.Duration

	// ArtifactQuiet is the minimum time since the live artifact was last
	// written before a task can be flagged. Zero -> 5m. A still-streaming
	// task never trips the detector because its artifact mtime keeps moving.
	ArtifactQuiet time.Duration

	// AutoKillAfter, when > 0, cancels a task's registered context after the
	// task has been continuously flagged stuck for this duration. 0 means
	// "report only; never cancel". Disabled by default — operators opt in.
	AutoKillAfter time.Duration

	// Logger receives structured events. Nil is allowed (no logs emitted).
	Logger logger.Logger

	// DB persists stuck events into the stuck_tasks table for forensic
	// inspection. Nil disables DB writes.
	DB *statedb.DB

	// OnStuck is invoked on every detection (whether the task is newly stuck
	// or still stuck from a prior tick). Used by the UI to push WebSocket
	// events. Nil is allowed.
	OnStuck EventSink

	// Now overrides time.Now for tests. nil -> time.Now.
	Now func() time.Time

	// ─────────────── internal ───────────────

	mu      sync.Mutex
	cancels map[int]context.CancelFunc // per-task cancels registered by orchestrator
	flagged map[int]time.Time          // first time each currently-stuck task was flagged

	wg      sync.WaitGroup
	started bool
}

// Register associates a per-task context cancel function with taskID. The
// orchestrator MUST call this before launching the task and Unregister when
// the task completes (or fails / is cancelled). Registration is required for
// AutoKillAfter to work; without it, stuck tasks are reported but never
// cancelled. Safe to call before Start.
func (w *Watchdog) Register(taskID int, cancel context.CancelFunc) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancels == nil {
		w.cancels = make(map[int]context.CancelFunc)
	}
	w.cancels[taskID] = cancel
}

// Unregister removes the registered cancel for taskID and clears any flagged
// state so a subsequent re-execution of the same task ID starts from a clean
// slate. The orchestrator should call Unregister whenever a task transitions
// out of in_progress.
func (w *Watchdog) Unregister(taskID int) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.cancels, taskID)
	delete(w.flagged, taskID)
}

// Start launches the watchdog goroutine. Returns immediately. The goroutine
// exits when ctx is cancelled; callers should wait via Wait before tearing
// down dependent resources (DB handles, loggers).
//
// Calling Start more than once is a no-op (returns silently); construct a
// fresh Watchdog if you need to restart.
func (w *Watchdog) Start(ctx context.Context) {
	if w == nil {
		return
	}
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return
	}
	w.started = true
	if w.flagged == nil {
		w.flagged = make(map[int]time.Time)
	}
	if w.cancels == nil {
		w.cancels = make(map[int]context.CancelFunc)
	}
	interval := w.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	w.mu.Unlock()

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.tick()
			}
		}
	}()
}

// Wait blocks until the watchdog goroutine has exited. Safe to call even if
// Start was never invoked.
func (w *Watchdog) Wait() {
	if w == nil {
		return
	}
	w.wg.Wait()
}

// tick runs one inspection pass. Exposed for tests.
func (w *Watchdog) tick() {
	now := w.now()
	stuckThreshold := w.StuckThreshold
	if stuckThreshold <= 0 {
		stuckThreshold = DefaultStuckThreshold
	}
	artifactQuiet := w.ArtifactQuiet
	if artifactQuiet <= 0 {
		artifactQuiet = DefaultArtifactQuiet
	}

	plan := w.fetchPlan()
	if plan == nil {
		return
	}

	// Build the set of in-progress task IDs we observe this tick so we can
	// drop entries from `flagged` for tasks that have moved out of
	// in_progress (completed / failed / skipped) since the last tick — that
	// way a re-run of the same ID starts fresh.
	seen := make(map[int]struct{})
	for _, t := range plan.Tasks {
		if t == nil || t.Status != pm.TaskInProgress || t.StartedAt == nil {
			continue
		}
		seen[t.ID] = struct{}{}

		// Has the task been running long enough to be eligible?
		if now.Sub(*t.StartedAt) < stuckThreshold {
			continue
		}

		// False-positive suppression: a task that is actively producing
		// tokens has its live artifact mtime advancing. Only flag when the
		// artifact has been quiet for at least artifactQuiet.
		artPath := artifact.LiveArtifactPath(w.WorkDir, t.ID)
		var artModTime time.Time
		if info, err := os.Stat(artPath); err == nil {
			artModTime = info.ModTime()
			if now.Sub(artModTime) < artifactQuiet {
				// Still streaming — clear any prior flag so the auto-kill
				// timer restarts if the task stalls again later.
				w.mu.Lock()
				delete(w.flagged, t.ID)
				w.mu.Unlock()
				continue
			}
		}
		// If the artifact is missing entirely, treat that as "quiet enough"
		// — a task that never produced any output but has been in_progress
		// for >StuckThreshold is the most suspicious case of all.

		w.handleStuck(now, t, artPath, artModTime)
	}

	// Drop flagged entries — and stale cancel registrations — for tasks
	// that are no longer in_progress. Without the cancels sweep the map
	// grows without bound across the lifetime of a long-running PM session
	// (one entry per executed task), which is harmless functionally but
	// would be a slow leak for forensics-heavy runs.
	w.mu.Lock()
	for id := range w.flagged {
		if _, still := seen[id]; !still {
			delete(w.flagged, id)
		}
	}
	for id := range w.cancels {
		if _, still := seen[id]; !still {
			delete(w.cancels, id)
		}
	}
	w.mu.Unlock()
}

// handleStuck records a stuck-task detection and optionally cancels the task.
// Called once per detected task per tick.
func (w *Watchdog) handleStuck(now time.Time, t *pm.Task, artPath string, artModTime time.Time) {
	w.mu.Lock()
	// Lazy init so tick() (exposed for tests) is safe to call without Start.
	if w.flagged == nil {
		w.flagged = make(map[int]time.Time)
	}
	first, ok := w.flagged[t.ID]
	if !ok {
		first = now
		w.flagged[t.ID] = first
	}
	cancel := w.cancels[t.ID]
	w.mu.Unlock()

	stuckDur := now.Sub(first)
	willCancel := w.AutoKillAfter > 0 && stuckDur >= w.AutoKillAfter && cancel != nil

	evt := StuckEvent{
		TaskID:          t.ID,
		TaskTitle:       t.Title,
		StartedAt:       *t.StartedAt,
		StuckSince:      first,
		ArtifactPath:    artPath,
		ArtifactModTime: artModTime,
		StuckDuration:   stuckDur.Round(time.Second).String(),
		WorkDir:         w.WorkDir,
		WillCancel:      willCancel,
		DetectedAt:      now,
	}

	if w.Logger != nil {
		data := map[string]interface{}{
			"task_id":         t.ID,
			"task_title":      t.Title,
			"started_at":      t.StartedAt.UTC().Format(time.RFC3339),
			"stuck_since":     first.UTC().Format(time.RFC3339),
			"stuck_duration":  evt.StuckDuration,
			"artifact_quiet":  artifactQuietString(now, artModTime),
			"will_cancel":     willCancel,
			"workdir":         w.WorkDir,
		}
		msg := fmt.Sprintf("task %d stuck for %s", t.ID, evt.StuckDuration)
		w.Logger.Warn(logger.EventTaskStuck, t.ID, msg, data)
	}

	if w.DB != nil {
		// DB write failures are non-fatal — log and continue. A flapping DB
		// must not crash the watchdog.
		idleSecs := 0
		if !artModTime.IsZero() {
			idleSecs = int(now.Sub(artModTime) / time.Second)
		}
		if _, err := w.DB.AppendStuck(statedb.StuckEvent{
			TaskID:           t.ID,
			TaskTitle:        t.Title,
			StartedAt:        *t.StartedAt,
			DetectedAt:       now,
			StuckForSeconds:  int(stuckDur / time.Second),
			ArtifactIdleSecs: idleSecs,
			ArtifactPath:     artPath,
			AutoKilled:       willCancel,
			Note:             evt.StuckDuration,
		}); err != nil && w.Logger != nil {
			w.Logger.Warn(logger.EventTaskStuck, t.ID,
				fmt.Sprintf("failed to persist stuck-task row: %v", err), nil)
		}
	}

	if w.OnStuck != nil {
		w.OnStuck(evt)
	}

	if willCancel {
		// Detach the cancel from the registry so a follow-up tick before
		// Unregister doesn't redundantly fire it (and to make the next-tick
		// log clearly say "already cancelled").
		w.mu.Lock()
		delete(w.cancels, t.ID)
		w.mu.Unlock()
		cancel()
	}
}

// fetchPlan returns the current plan, preferring the in-memory GetPlan
// callback. Falls back to reading state from disk so the watchdog still
// works in degraded test scenarios where no callback is wired.
func (w *Watchdog) fetchPlan() *pm.Plan {
	if w.GetPlan != nil {
		return w.GetPlan()
	}
	if w.WorkDir == "" {
		return nil
	}
	s, err := state.Load(w.WorkDir)
	if err != nil || s == nil {
		return nil
	}
	return s.Plan
}

func (w *Watchdog) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func artifactQuietString(now, mod time.Time) string {
	if mod.IsZero() {
		return "missing"
	}
	return now.Sub(mod).Round(time.Second).String()
}
