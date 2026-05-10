// Tests for pkg/watchdog. The watchdog is timing-sensitive in production but
// fully deterministic in tests via two seams it exposes:
//
//   - Now func() time.Time — inject a fake clock so we can assert at exact
//     instants without sleeping.
//   - tick() — drive one inspection pass synchronously; we never let the
//     internal ticker run in unit tests, only in the lifecycle test below.
//
// Real artifact files are created and `os.Chtimes`'d to control mtime, since
// the watchdog reads the filesystem directly. That's a small sacrifice of
// purity in exchange for catching path-resolution bugs that a stat-mock
// wouldn't.
package watchdog

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ─────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────

// fixedClock returns a Now func that always returns the same instant.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// taskAt builds an in_progress task whose StartedAt is `started`.
func taskAt(id int, title string, started time.Time) *pm.Task {
	s := started
	return &pm.Task{
		ID:        id,
		Title:     title,
		Status:    pm.TaskInProgress,
		StartedAt: &s,
	}
}

// writeArtifact creates the live artifact file for taskID under workDir and
// stamps its mtime to `mod`. Returns the resolved path.
func writeArtifact(t *testing.T, workDir string, taskID int, mod time.Time) string {
	t.Helper()
	dir := artifact.LiveArtifactDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	p := artifact.LiveArtifactPath(workDir, taskID)
	if err := os.WriteFile(p, []byte("partial output"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatalf("chtimes artifact: %v", err)
	}
	return p
}

// captureSink is a thread-safe EventSink that records every detection.
type captureSink struct {
	mu     sync.Mutex
	events []StuckEvent
}

func (c *captureSink) sink(e StuckEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) snapshot() []StuckEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]StuckEvent, len(c.events))
	copy(out, c.events)
	return out
}

// captureLogger records Warn calls so we can assert the watchdog emits
// EventTaskStuck rather than asserting on real stdout.
type captureLogger struct {
	mu      sync.Mutex
	entries []logEntry
}

type logEntry struct {
	level   logger.Level
	event   logger.Event
	taskID  int
	message string
	data    map[string]interface{}
}

func (c *captureLogger) Log(l logger.Level, e logger.Event, id int, m string, d map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, logEntry{l, e, id, m, d})
}
func (c *captureLogger) Debug(e logger.Event, id int, m string, d map[string]interface{}) {
	c.Log(logger.LevelDebug, e, id, m, d)
}
func (c *captureLogger) Info(e logger.Event, id int, m string, d map[string]interface{}) {
	c.Log(logger.LevelInfo, e, id, m, d)
}
func (c *captureLogger) Warn(e logger.Event, id int, m string, d map[string]interface{}) {
	c.Log(logger.LevelWarn, e, id, m, d)
}
func (c *captureLogger) Error(e logger.Event, id int, m string, d map[string]interface{}) {
	c.Log(logger.LevelError, e, id, m, d)
}
func (c *captureLogger) With(_ string, _ any) logger.Logger { return c }
func (c *captureLogger) IsJSON() bool                       { return false }

func (c *captureLogger) snapshot() []logEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]logEntry, len(c.entries))
	copy(out, c.entries)
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// tick() behaviour — the heart of the watchdog
// ─────────────────────────────────────────────────────────────────────────

func TestTick_DetectsStuckTask_NoArtifact(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := now.Add(-15 * time.Minute) // older than DefaultStuckThreshold (10m)

	dir := t.TempDir()
	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "stuck task", started)}}

	sink := &captureSink{}
	w := &Watchdog{
		WorkDir: dir,
		GetPlan: func() *pm.Plan { return plan },
		OnStuck: sink.sink,
		Now:     fixedClock(now),
	}

	w.tick()

	evs := sink.snapshot()
	if len(evs) != 1 {
		t.Fatalf("expected 1 stuck event, got %d", len(evs))
	}
	e := evs[0]
	if e.TaskID != 1 || e.TaskTitle != "stuck task" {
		t.Errorf("unexpected event: %+v", e)
	}
	if !e.StuckSince.Equal(now) {
		t.Errorf("StuckSince: want %v, got %v", now, e.StuckSince)
	}
	if !e.StartedAt.Equal(started) {
		t.Errorf("StartedAt: want %v, got %v", started, e.StartedAt)
	}
	if e.WillCancel {
		t.Error("WillCancel should be false when AutoKillAfter is 0")
	}
	if e.ArtifactPath == "" {
		t.Error("ArtifactPath should be populated even when file is missing")
	}
	if !e.ArtifactModTime.IsZero() {
		t.Errorf("ArtifactModTime should be zero when artifact missing, got %v", e.ArtifactModTime)
	}
}

func TestTick_IgnoresShortLivedTask(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := now.Add(-1 * time.Minute) // well below 10m threshold

	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "young", started)}}
	sink := &captureSink{}
	w := &Watchdog{
		WorkDir: t.TempDir(),
		GetPlan: func() *pm.Plan { return plan },
		OnStuck: sink.sink,
		Now:     fixedClock(now),
	}

	w.tick()

	if len(sink.snapshot()) != 0 {
		t.Fatalf("expected no events for young task, got %d", len(sink.snapshot()))
	}
}

func TestTick_IgnoresTaskWithRecentArtifact(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := now.Add(-30 * time.Minute) // way past stuck threshold

	dir := t.TempDir()
	// Artifact was written 1 minute ago — well within DefaultArtifactQuiet (5m)
	writeArtifact(t, dir, 7, now.Add(-1*time.Minute))

	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(7, "streaming", started)}}
	sink := &captureSink{}
	w := &Watchdog{
		WorkDir: dir,
		GetPlan: func() *pm.Plan { return plan },
		OnStuck: sink.sink,
		Now:     fixedClock(now),
	}

	w.tick()

	if got := len(sink.snapshot()); got != 0 {
		t.Fatalf("expected 0 events when artifact is fresh, got %d", got)
	}
}

func TestTick_DetectsStuckTask_StaleArtifact(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := now.Add(-20 * time.Minute)
	artMod := now.Add(-8 * time.Minute) // older than DefaultArtifactQuiet (5m)

	dir := t.TempDir()
	writeArtifact(t, dir, 42, artMod)

	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(42, "stalled", started)}}
	sink := &captureSink{}
	w := &Watchdog{
		WorkDir: dir,
		GetPlan: func() *pm.Plan { return plan },
		OnStuck: sink.sink,
		Now:     fixedClock(now),
	}

	w.tick()

	evs := sink.snapshot()
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if !evs[0].ArtifactModTime.Equal(artMod) {
		t.Errorf("ArtifactModTime: want %v, got %v", artMod, evs[0].ArtifactModTime)
	}
}

func TestTick_SkipsCompletedAndPendingTasks(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := now.Add(-1 * time.Hour)

	plan := &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Title: "pending", Status: pm.TaskPending, StartedAt: &started},
		{ID: 2, Title: "done", Status: pm.TaskDone, StartedAt: &started},
		{ID: 3, Title: "failed", Status: pm.TaskFailed, StartedAt: &started},
		{ID: 4, Title: "skipped", Status: pm.TaskSkipped, StartedAt: &started},
		// in_progress but no StartedAt — must also be skipped to avoid panicking
		// on the *t.StartedAt deref.
		{ID: 5, Title: "no-start", Status: pm.TaskInProgress},
	}}
	sink := &captureSink{}
	w := &Watchdog{
		WorkDir: t.TempDir(),
		GetPlan: func() *pm.Plan { return plan },
		OnStuck: sink.sink,
		Now:     fixedClock(now),
	}

	w.tick()

	if got := len(sink.snapshot()); got != 0 {
		t.Fatalf("expected 0 events, got %d", got)
	}
}

func TestTick_NilTaskInPlan(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	plan := &pm.Plan{Tasks: []*pm.Task{nil, nil}}
	sink := &captureSink{}
	w := &Watchdog{
		WorkDir: t.TempDir(),
		GetPlan: func() *pm.Plan { return plan },
		OnStuck: sink.sink,
		Now:     fixedClock(now),
	}
	// Should not panic.
	w.tick()
	if len(sink.snapshot()) != 0 {
		t.Fatalf("nil tasks should produce no events")
	}
}

func TestTick_NilPlan_NoOp(t *testing.T) {
	t.Parallel()
	sink := &captureSink{}
	w := &Watchdog{
		WorkDir: t.TempDir(),
		GetPlan: func() *pm.Plan { return nil },
		OnStuck: sink.sink,
		Now:     fixedClock(time.Now()),
	}
	w.tick() // must not panic
	if len(sink.snapshot()) != 0 {
		t.Fatal("nil plan must produce no events")
	}
}

// StuckSince is set on the FIRST tick that flags a task and is preserved on
// subsequent ticks; StuckDuration grows; flagged map keeps one entry.
func TestTick_FlaggedSince_PersistsAcrossTicks(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-15 * time.Minute)
	dir := t.TempDir()
	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}

	currentNow := t0
	sink := &captureSink{}
	w := &Watchdog{
		WorkDir: dir,
		GetPlan: func() *pm.Plan { return plan },
		OnStuck: sink.sink,
		Now:     func() time.Time { return currentNow },
	}

	w.tick() // first detection at t0
	currentNow = t0.Add(2 * time.Minute)
	w.tick() // second detection at t0+2m
	currentNow = t0.Add(4 * time.Minute)
	w.tick() // third at t0+4m

	evs := sink.snapshot()
	if len(evs) != 3 {
		t.Fatalf("expected 3 events, got %d", len(evs))
	}
	for i, e := range evs {
		if !e.StuckSince.Equal(t0) {
			t.Errorf("event %d StuckSince: want %v, got %v", i, t0, e.StuckSince)
		}
	}
	wantDur := []string{"0s", "2m0s", "4m0s"}
	for i, e := range evs {
		if e.StuckDuration != wantDur[i] {
			t.Errorf("event %d StuckDuration: want %q, got %q", i, wantDur[i], e.StuckDuration)
		}
	}

	// flagged map still has exactly one entry for taskID 1.
	w.mu.Lock()
	if got := len(w.flagged); got != 1 {
		t.Errorf("flagged map size: want 1, got %d", got)
	}
	w.mu.Unlock()
}

// When a task's artifact starts streaming again after being flagged, the
// flagged entry is cleared so the AutoKillAfter timer restarts.
func TestTick_FlaggedReset_WhenArtifactResumes(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-30 * time.Minute)
	dir := t.TempDir()
	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}

	currentNow := t0
	w := &Watchdog{
		WorkDir: dir,
		GetPlan: func() *pm.Plan { return plan },
		Now:     func() time.Time { return currentNow },
	}

	// Tick 1: no artifact present → flagged.
	w.tick()
	w.mu.Lock()
	if _, ok := w.flagged[1]; !ok {
		t.Fatal("expected task 1 to be flagged after first tick")
	}
	w.mu.Unlock()

	// Tick 2: artifact written 30s ago — well within ArtifactQuiet (5m) →
	// flagged entry cleared.
	currentNow = t0.Add(1 * time.Minute)
	writeArtifact(t, dir, 1, currentNow.Add(-30*time.Second))
	w.tick()
	w.mu.Lock()
	if _, ok := w.flagged[1]; ok {
		t.Errorf("expected flagged entry cleared after artifact resumed")
	}
	w.mu.Unlock()
}

// When a task transitions out of in_progress, its flagged entry and any
// dangling cancel registration must be GC'd.
func TestTick_GCsCompletedTaskState(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-30 * time.Minute)
	dir := t.TempDir()

	tk := taskAt(1, "x", started)
	plan := &pm.Plan{Tasks: []*pm.Task{tk}}

	w := &Watchdog{
		WorkDir: dir,
		GetPlan: func() *pm.Plan { return plan },
		Now:     fixedClock(t0),
	}
	cancelCalled := false
	w.Register(1, func() { cancelCalled = true })

	w.tick() // flag it
	w.mu.Lock()
	_, hadFlag := w.flagged[1]
	_, hadCancel := w.cancels[1]
	w.mu.Unlock()
	if !hadFlag || !hadCancel {
		t.Fatal("expected flagged + registered cancel after first tick")
	}

	// Task completes — orchestrator updates the in-memory plan; the watchdog
	// observes it on its next tick and sweeps both maps. No Unregister is
	// called intentionally; this exercises the sweep path.
	tk.Status = pm.TaskDone
	w.tick()

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.flagged[1]; ok {
		t.Error("flagged map not GC'd after task left in_progress")
	}
	if _, ok := w.cancels[1]; ok {
		t.Error("cancels map not GC'd after task left in_progress")
	}
	if cancelCalled {
		t.Error("cancel must NOT be invoked by GC sweep")
	}
}

// ─────────────────────────────────────────────────────────────────────────
// AutoKillAfter
// ─────────────────────────────────────────────────────────────────────────

func TestAutoKillAfter_FiresWhenStuckLongEnough(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-15 * time.Minute)
	dir := t.TempDir()
	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}

	currentNow := t0
	sink := &captureSink{}
	w := &Watchdog{
		WorkDir:       dir,
		GetPlan:       func() *pm.Plan { return plan },
		AutoKillAfter: 2 * time.Minute,
		OnStuck:       sink.sink,
		Now:           func() time.Time { return currentNow },
	}

	var cancelled atomic.Bool
	w.Register(1, func() { cancelled.Store(true) })

	w.tick() // first flag at t0; stuckDur = 0; should NOT cancel
	if cancelled.Load() {
		t.Fatal("cancel fired prematurely on first tick (stuckDur=0)")
	}

	currentNow = t0.Add(1 * time.Minute) // stuckDur = 1m, < 2m → no fire
	w.tick()
	if cancelled.Load() {
		t.Fatal("cancel fired before AutoKillAfter elapsed")
	}

	currentNow = t0.Add(2 * time.Minute) // stuckDur = 2m, >= 2m → fire
	w.tick()
	if !cancelled.Load() {
		t.Fatal("cancel did NOT fire when AutoKillAfter elapsed")
	}

	// And the cancel must have been removed from the registry to prevent
	// duplicate firing on the next tick.
	w.mu.Lock()
	_, stillReg := w.cancels[1]
	w.mu.Unlock()
	if stillReg {
		t.Error("cancel should be detached from registry after firing")
	}

	// Inspect the events: the third one should be the WillCancel=true
	// detection; the earlier two must have WillCancel=false.
	evs := sink.snapshot()
	if len(evs) != 3 {
		t.Fatalf("expected 3 events, got %d", len(evs))
	}
	if evs[0].WillCancel || evs[1].WillCancel {
		t.Errorf("early events should not WillCancel: %+v %+v", evs[0], evs[1])
	}
	if !evs[2].WillCancel {
		t.Errorf("third event must WillCancel: %+v", evs[2])
	}
}

func TestAutoKillAfter_NeverFiresWhenZero(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-2 * time.Hour)
	dir := t.TempDir()
	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}

	w := &Watchdog{
		WorkDir: dir,
		GetPlan: func() *pm.Plan { return plan },
		// AutoKillAfter not set → 0
		Now: fixedClock(t0),
	}
	var cancelled atomic.Bool
	w.Register(1, func() { cancelled.Store(true) })

	for i := 0; i < 5; i++ {
		w.tick()
	}
	if cancelled.Load() {
		t.Fatal("cancel must never fire when AutoKillAfter=0")
	}
}

// AutoKillAfter must not panic when no cancel is registered for the stuck
// task — it should report-only and leave WillCancel=false.
func TestAutoKillAfter_NoCancelRegistered_ReportOnly(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-30 * time.Minute)

	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}
	sink := &captureSink{}
	currentNow := t0
	w := &Watchdog{
		WorkDir:       t.TempDir(),
		GetPlan:       func() *pm.Plan { return plan },
		AutoKillAfter: 1 * time.Nanosecond, // would always fire if a cancel was set
		OnStuck:       sink.sink,
		Now:           func() time.Time { return currentNow },
	}

	w.tick()
	currentNow = t0.Add(1 * time.Second)
	w.tick() // would fire if cancel was present, but no Register call was made

	for i, e := range sink.snapshot() {
		if e.WillCancel {
			t.Errorf("event %d WillCancel=true with no registered cancel", i)
		}
	}
}

// Concurrent triggers: the cancel function for a single task is invoked at
// most once even if the inspection ticks were interleaved or the same task
// flagged twice in race conditions.
func TestAutoKillAfter_CancelCalledOnce(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-30 * time.Minute)
	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}

	currentNow := t0
	w := &Watchdog{
		WorkDir:       t.TempDir(),
		GetPlan:       func() *pm.Plan { return plan },
		AutoKillAfter: 1 * time.Nanosecond,
		Now:           func() time.Time { return currentNow },
	}
	var calls atomic.Int32
	w.Register(1, func() { calls.Add(1) })

	w.tick() // flags at t0; stuckDur=0, but >= 1ns so fires immediately
	currentNow = t0.Add(1 * time.Second)
	w.tick() // would re-fire if cancel hadn't been detached
	currentNow = t0.Add(2 * time.Second)
	w.tick()

	if got := calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 cancel invocation, got %d", got)
	}
}

// Two concurrently stuck tasks each get their own cancel and both fire.
func TestAutoKillAfter_MultipleTasks_IndependentCancels(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-30 * time.Minute)
	plan := &pm.Plan{Tasks: []*pm.Task{
		taskAt(1, "a", started),
		taskAt(2, "b", started),
	}}

	currentNow := t0
	w := &Watchdog{
		WorkDir:       t.TempDir(),
		GetPlan:       func() *pm.Plan { return plan },
		AutoKillAfter: 1 * time.Nanosecond,
		Now:           func() time.Time { return currentNow },
	}
	var c1, c2 atomic.Int32
	w.Register(1, func() { c1.Add(1) })
	w.Register(2, func() { c2.Add(1) })

	w.tick() // flag both at t0; stuckDur=0 → no fire yet
	currentNow = t0.Add(1 * time.Second)
	w.tick() // stuckDur=1s ≥ 1ns → both fire

	if c1.Load() != 1 || c2.Load() != 1 {
		t.Fatalf("expected each cancel to fire once, got c1=%d c2=%d", c1.Load(), c2.Load())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Register / Unregister
// ─────────────────────────────────────────────────────────────────────────

func TestRegisterUnregister(t *testing.T) {
	t.Parallel()
	w := &Watchdog{}
	w.Register(7, func() {})
	w.mu.Lock()
	if _, ok := w.cancels[7]; !ok {
		t.Fatal("expected cancel registered")
	}
	w.mu.Unlock()

	// Manually plant a flagged entry to verify Unregister sweeps both maps.
	w.mu.Lock()
	if w.flagged == nil {
		w.flagged = make(map[int]time.Time)
	}
	w.flagged[7] = time.Now()
	w.mu.Unlock()

	w.Unregister(7)
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.cancels[7]; ok {
		t.Error("Unregister should remove cancel")
	}
	if _, ok := w.flagged[7]; ok {
		t.Error("Unregister should remove flagged entry")
	}
}

func TestRegisterUnregister_NilWatchdog_NoOp(t *testing.T) {
	t.Parallel()
	var w *Watchdog
	// Must not panic.
	w.Register(1, func() {})
	w.Unregister(1)
	w.Wait()
	w.Start(context.Background())
}

// ─────────────────────────────────────────────────────────────────────────
// Logger / DB / OnStuck plumbing
// ─────────────────────────────────────────────────────────────────────────

func TestTick_EmitsLoggerWarn(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-15 * time.Minute)

	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "stalled", started)}}
	lg := &captureLogger{}
	w := &Watchdog{
		WorkDir: t.TempDir(),
		GetPlan: func() *pm.Plan { return plan },
		Logger:  lg,
		Now:     fixedClock(t0),
	}

	w.tick()

	entries := lg.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	e := entries[0]
	if e.level != logger.LevelWarn {
		t.Errorf("level: want warn, got %s", e.level)
	}
	if e.event != logger.EventTaskStuck {
		t.Errorf("event: want %s, got %s", logger.EventTaskStuck, e.event)
	}
	if e.taskID != 1 {
		t.Errorf("taskID: want 1, got %d", e.taskID)
	}
	if e.data == nil {
		t.Fatal("data should not be nil")
	}
	if got, _ := e.data["task_title"].(string); got != "stalled" {
		t.Errorf("data.task_title: want stalled, got %v", e.data["task_title"])
	}
	if got, _ := e.data["artifact_quiet"].(string); got != "missing" {
		t.Errorf("data.artifact_quiet: want missing, got %v", e.data["artifact_quiet"])
	}
}

func TestTick_PersistsToDB(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-15 * time.Minute)
	dir := t.TempDir()

	dbPath := filepath.Join(dir, "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}
	w := &Watchdog{
		WorkDir: dir,
		GetPlan: func() *pm.Plan { return plan },
		DB:      db,
		Now:     fixedClock(t0),
	}

	w.tick()
	w.tick() // each tick should append a new row by design

	rows, err := db.ReadStuck(0)
	if err != nil {
		t.Fatalf("ReadStuck: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 stuck_tasks rows after 2 ticks, got %d", len(rows))
	}
	for _, r := range rows {
		if r.TaskID != 1 || r.TaskTitle != "x" {
			t.Errorf("unexpected row: %+v", r)
		}
		if r.AutoKilled {
			t.Errorf("AutoKilled should be false (no AutoKillAfter): %+v", r)
		}
	}
}

// A failing DB Append must not bring the watchdog down; OnStuck and Logger
// still fire.
func TestTick_DBFailure_NonFatal(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	started := t0.Add(-15 * time.Minute)
	dir := t.TempDir()

	db, err := statedb.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	// Close the DB so the next AppendStuck call fails — simulates a flapping
	// or torn-down database without depending on driver internals.
	db.Close()

	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}
	sink := &captureSink{}
	lg := &captureLogger{}
	w := &Watchdog{
		WorkDir: dir,
		GetPlan: func() *pm.Plan { return plan },
		DB:      db,
		OnStuck: sink.sink,
		Logger:  lg,
		Now:     fixedClock(t0),
	}

	w.tick() // must not panic

	if got := len(sink.snapshot()); got != 1 {
		t.Errorf("OnStuck should still fire when DB write fails, got %d events", got)
	}
	// Logger should have at least the original Warn plus a follow-up about
	// the DB failure.
	if got := len(lg.snapshot()); got < 2 {
		t.Errorf("expected logger to emit primary warn + db-failure warn, got %d entries", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// fetchPlan fallback
// ─────────────────────────────────────────────────────────────────────────

func TestFetchPlan_NilGetPlan_NoWorkDir(t *testing.T) {
	t.Parallel()
	w := &Watchdog{}
	if got := w.fetchPlan(); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestFetchPlan_NilGetPlan_BadWorkDir(t *testing.T) {
	t.Parallel()
	// state.Load on a directory with no .cloop returns either nil or an
	// error; either way fetchPlan must yield nil rather than panicking.
	w := &Watchdog{WorkDir: t.TempDir()}
	if got := w.fetchPlan(); got != nil {
		t.Fatalf("expected nil from missing state, got %+v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Defaults
// ─────────────────────────────────────────────────────────────────────────

func TestDefaults_Constants(t *testing.T) {
	t.Parallel()
	if DefaultInterval != 30*time.Second {
		t.Errorf("DefaultInterval changed: %v", DefaultInterval)
	}
	if DefaultStuckThreshold != 10*time.Minute {
		t.Errorf("DefaultStuckThreshold changed: %v", DefaultStuckThreshold)
	}
	if DefaultArtifactQuiet != 5*time.Minute {
		t.Errorf("DefaultArtifactQuiet changed: %v", DefaultArtifactQuiet)
	}
}

// When all of StuckThreshold/ArtifactQuiet are zero, the defaults are picked
// up by tick() — verified by simulating a task aged past 10m with a missing
// artifact: the default thresholds should trip the detector.
func TestDefaults_AppliedOnZeroFields(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	// Just past DefaultStuckThreshold of 10m
	started := t0.Add(-(DefaultStuckThreshold + 1*time.Minute))

	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}
	sink := &captureSink{}
	w := &Watchdog{
		WorkDir: t.TempDir(),
		GetPlan: func() *pm.Plan { return plan },
		OnStuck: sink.sink,
		Now:     fixedClock(t0),
	}
	w.tick()
	if got := len(sink.snapshot()); got != 1 {
		t.Fatalf("expected default thresholds to flag aged task, got %d events", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Lifecycle: Start / Wait / cancel
// ─────────────────────────────────────────────────────────────────────────

// Start launches the goroutine; cancelling the context terminates it within
// a small window. Wait must then return promptly.
func TestStart_GracefulShutdownOnCancel(t *testing.T) {
	t.Parallel()
	w := &Watchdog{
		WorkDir:  t.TempDir(),
		GetPlan:  func() *pm.Plan { return nil },
		Interval: 10 * time.Millisecond, // tight enough to take at least one tick before shutdown
	}

	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)

	// Let at least one tick fire so we exercise the live ticker path.
	time.Sleep(40 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() {
		w.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog goroutine did not exit within 2s of context cancel")
	}
}

// Calling Start more than once is documented as a no-op. Verified by the
// observation that Wait returns after a single cancel.
func TestStart_Idempotent(t *testing.T) {
	t.Parallel()
	w := &Watchdog{
		WorkDir:  t.TempDir(),
		GetPlan:  func() *pm.Plan { return nil },
		Interval: 5 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)
	w.Start(ctx) // second call should be a no-op
	w.Start(ctx)

	cancel()
	done := make(chan struct{})
	go func() { w.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("multiple Start calls leaked extra goroutines (Wait blocks)")
	}
}

// During Start with a real ticker, AutoKillAfter must still cancel a stuck
// task. This is the integration-shaped end-to-end happy-path: prove the
// goroutine actually drives tick().
func TestStart_LiveTicker_DrivesAutoKill(t *testing.T) {
	t.Parallel()
	t0 := time.Now()
	started := t0.Add(-1 * time.Hour)

	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}
	w := &Watchdog{
		WorkDir:        t.TempDir(),
		GetPlan:        func() *pm.Plan { return plan },
		Interval:       10 * time.Millisecond,
		StuckThreshold: 1 * time.Minute,
		ArtifactQuiet:  1 * time.Minute,
		AutoKillAfter:  1 * time.Nanosecond, // any positive value; first qualifying tick fires it
	}

	cancelled := make(chan struct{})
	w.Register(1, func() { close(cancelled) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("AutoKillAfter cancel did not fire within 2s under live ticker")
	}
	cancel()
	w.Wait()
}

// ─────────────────────────────────────────────────────────────────────────
// Cancellation during recovery
// ─────────────────────────────────────────────────────────────────────────

// If the registered cancel func itself blocks (e.g. it triggers cleanup that
// hangs), the watchdog goroutine must still terminate when its parent ctx is
// cancelled — handleStuck releases the watchdog mutex before invoking the
// cancel, so Stop is not deadlocked by a slow registered cancel.
func TestCancellationDuringRecovery_DoesNotDeadlock(t *testing.T) {
	t.Parallel()
	t0 := time.Now()
	started := t0.Add(-1 * time.Hour)
	plan := &pm.Plan{Tasks: []*pm.Task{taskAt(1, "x", started)}}

	// The registered cancel blocks "indefinitely" (release on test cleanup).
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	w := &Watchdog{
		WorkDir:        t.TempDir(),
		GetPlan:        func() *pm.Plan { return plan },
		Interval:       10 * time.Millisecond,
		StuckThreshold: 1 * time.Minute,
		ArtifactQuiet:  1 * time.Minute,
		AutoKillAfter:  1 * time.Nanosecond,
	}

	cancelInvoked := make(chan struct{})
	w.Register(1, func() {
		close(cancelInvoked)
		<-release // simulate a slow recovery
	})

	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)

	select {
	case <-cancelInvoked:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel never invoked")
	}

	// Now cancel the watchdog context. Because the cancel func is still
	// blocked, the goroutine that called it (the watchdog goroutine) is
	// stuck inside cancel() too. That's expected behaviour — but the
	// watchdog's *next* tick should never start, and Wait is allowed to
	// remain blocked until the registered cancel returns.
	cancel()

	// The proof of "no deadlock with the watchdog mutex": Register on a
	// *different* task ID must succeed promptly even while cancel() is
	// blocked — i.e. handleStuck must have released w.mu before invoking
	// cancel. If it hadn't, this Register would block on w.mu forever.
	done := make(chan struct{})
	go func() {
		w.Register(2, func() {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Register blocked while cancel() is in flight — handleStuck still holds w.mu")
	}
}
