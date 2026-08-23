package container

// Tests for surviving a control-plane restart (Task 20191) and for the
// running half of the orphan sweep that catches what could not be survived.
//
// The split mirrors container_test.go's. The pure half proves the decisions —
// which container is old enough to kill, which timestamp formats the runtimes
// speak, whether a rebuilt driver knows its handles — and runs on a machine
// with no container runtime. The integration half proves the mechanism, and is
// skipped through the same requireRuntime/requireImage guards the rest of the
// package uses, because only a real container proves that `logs --follow`
// really does attach to a workload this process did not start.
//
// The pure half needs one thing neither existing harness offers: a runtime the
// log pump can actually execute. fakeExecutor hands out a /usr/bin/docker path
// that no pure test ever runs, and pointing rehydration at the host's real
// docker would put a daemon round-trip — and a flake — into a test that has no
// container to talk to. stubRuntime is that one thing and nothing more: a
// shell script answering the four subcommands the pump uses.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// --- pure tests -------------------------------------------------------

// stubRuntime writes a shell script that impersonates the runtime CLI and
// returns a Runtime pointing at it. body is the script's case body, keyed on
// $1 (the subcommand); $2 onwards are that subcommand's arguments, so a
// container name is $2 for `wait`/`rm` and $3 for `logs --follow`.
func stubRuntime(t *testing.T, body string) Runtime {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stub-runtime")
	script := "#!/bin/sh\ncase \"$1\" in\n" + body + "\n*) exit 0 ;;\nesac\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write stub runtime: %v", err)
	}
	return Runtime{Name: RuntimeDocker, Path: path}
}

// vanishedContainerStub answers the way both runtimes answer for a container
// that no longer exists: `logs` produces nothing and `wait` refuses. It is the
// worst case rehydration has to survive — a row describing a container that
// was removed while the control plane was down.
const vanishedContainerStub = `logs) exit 0 ;;
wait) echo "Error response from daemon: No such container: $2" >&2; exit 1 ;;`

// liveContainerStub keeps `wait` outstanding so an adopted record stays
// Running for the duration of a test. The sleep is bounded rather than
// unbounded because nothing in the test can cancel the pump — only finish
// does that — so an unbounded wait would leave a child process alive for as
// long as the whole package's test binary runs.
const liveContainerStub = `logs) sleep 3; exit 0 ;;
wait) sleep 3; echo 0 ;;`

// storeExecutor builds an Executor with a stubbed runtime and a durable store,
// without going through New — so the test controls exactly when rehydration
// happens.
func storeExecutor(t *testing.T, id string, rt Runtime, store executor.HandleStore) *Executor {
	t.Helper()
	opts, err := Options{ID: id, HandleStore: store}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	return &Executor{
		id:      opts.ID,
		opts:    opts,
		rt:      rt,
		handles: make(map[string]*record),
		store:   store,
	}
}

// savedHandle is a persisted row for a container the runtime knows by name.
func savedHandle(id, executorID, name string, startedAt time.Time) executor.HandleRecord {
	return executor.HandleRecord{
		HandleID:    id,
		ExecutorID:  executorID,
		Driver:      executor.KindContainer,
		ExternalID:  name,
		ProjectPath: "/srv/project",
		TaskID:      42,
		Image:       "docker.io/library/alpine@sha256:deadbeef",
		StartedAt:   startedAt,
		Meta:        map[string]string{metaRuntime: RuntimeDocker},
	}
}

// TestRehydrateRestoresHandlesAcrossRestart is the restart simulation: a
// driver records a handle, the driver is discarded, and a new one built from
// the same store answers for that handle instead of ErrHandleNotFound.
func TestRehydrateRestoresHandlesAcrossRestart(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	rt := stubRuntime(t, liveContainerStub)
	started := time.Now().Add(-90 * time.Second).Truncate(time.Millisecond)
	rec := savedHandle("c-restart01", "test-restart", "cloop-project-restart01", started)

	// The pre-restart process: it dispatched a workload and wrote the row.
	// Nothing else of it survives — which is the point, so it is never even
	// constructed here.
	if err := store.PutHandle(rec); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	// The negative control. Without the store, the rebuilt driver has exactly
	// the pre-Task-20191 behaviour, and asserting it here is what keeps the
	// positive assertions below from being vacuous: they would pass on any
	// driver that answered every handle ID.
	blind := storeExecutor(t, "test-restart", rt, nil)
	blind.rehydrate()
	if _, err := blind.Status(context.Background(), rec.HandleID); !errors.Is(err, executor.ErrHandleNotFound) {
		t.Fatalf("a driver with no handle store must not know %s; Status err = %v", rec.HandleID, err)
	}

	// The post-restart process.
	ex := storeExecutor(t, "test-restart", rt, store)
	ex.rehydrate()
	ctx := context.Background()

	status, err := ex.Status(ctx, rec.HandleID)
	if err != nil {
		t.Fatalf("Status on a rehydrated handle: %v", err)
	}
	if !status.StartedAt.Equal(started) {
		t.Errorf("StartedAt = %v, want the persisted %v — the record was invented, not restored",
			status.StartedAt, started)
	}
	if status.ExecutorID != "test-restart" {
		t.Errorf("ExecutorID = %q, want test-restart", status.ExecutorID)
	}

	lines, err := ex.Stream(ctx, rec.HandleID)
	if err != nil {
		t.Fatalf("Stream on a rehydrated handle: %v", err)
	}
	if lines == nil {
		t.Fatal("Stream returned a nil channel for a rehydrated handle")
	}

	if err := ex.Signal(ctx, rec.HandleID, executor.SignalTerminate); err != nil {
		t.Fatalf("Signal on a rehydrated handle: %v", err)
	}

	if got := ex.Handles(); len(got) != 1 || got[0] != rec.HandleID {
		t.Errorf("Handles() = %v, want exactly [%s]", got, rec.HandleID)
	}
}

// TestRehydrateIsIdempotent covers both ways a row can be offered twice:
// AttachHandleStore called again, and a store whose rows this driver has
// already adopted. Either producing a second record would mean two log pumps
// on one container.
func TestRehydrateIsIdempotent(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	rt := stubRuntime(t, liveContainerStub)
	rec := savedHandle("c-idem0001", "test-idem", "cloop-project-idem0001", time.Now())
	if err := store.PutHandle(rec); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := storeExecutor(t, "test-idem", rt, nil)
	ex.AttachHandleStore(store)

	ex.mu.Lock()
	first := ex.handles[rec.HandleID]
	ex.mu.Unlock()
	if first == nil {
		t.Fatal("AttachHandleStore did not adopt the persisted row")
	}

	// Attaching the same store again, and then rehydrating directly, must both
	// be no-ops for a row that is already tracked.
	ex.AttachHandleStore(store)
	ex.rehydrate()

	ex.mu.Lock()
	second := ex.handles[rec.HandleID]
	count := len(ex.handles)
	ex.mu.Unlock()

	if count != 1 {
		t.Fatalf("handle map holds %d records after three adoptions of one row, want 1", count)
	}
	if second != first {
		t.Fatal("the record was replaced on re-adoption — the original's log pump is now writing to an orphaned bus")
	}
}

// TestRehydrateDropsRowForVanishedContainer covers the row that must not
// survive: one describing a container the runtime no longer has. Without this,
// a single removed container leaves a row that every subsequent boot adopts,
// fails, and re-adopts forever.
func TestRehydrateDropsRowForVanishedContainer(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	rt := stubRuntime(t, vanishedContainerStub)
	rec := savedHandle("c-vanish01", "test-vanish", "cloop-project-vanish01", time.Now().Add(-time.Hour))
	if err := store.PutHandle(rec); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := storeExecutor(t, "test-vanish", rt, store)
	ex.rehydrate()

	// The pump does the work, so wait for it rather than assuming a duration.
	deadline := time.Now().Add(30 * time.Second)
	for store.Len() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if store.Len() != 0 {
		t.Fatalf("the row for a vanished container was not dropped; store holds %d", store.Len())
	}

	status, err := ex.Status(context.Background(), rec.HandleID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.State.Terminal() {
		t.Fatalf("state = %q, want a terminal state — a container that cannot be waited on is not running",
			status.State)
	}
}

// TestRehydrateIgnoresForeignRows checks the two rows a container driver must
// refuse: one from another driver, and one with no external ID. Both would
// otherwise be adopted, fail, and be deleted — and for the foreign row that
// deletion destroys another driver's only record of a live workload.
func TestRehydrateIgnoresForeignRows(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	rt := stubRuntime(t, vanishedContainerStub)

	foreign := savedHandle("c-foreign1", "test-foreign", "default/some-pod", time.Now())
	foreign.Driver = executor.KindKubernetes
	if err := store.PutHandle(foreign); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := storeExecutor(t, "test-foreign", rt, store)
	ex.rehydrate()

	if got := ex.Handles(); len(got) != 0 {
		t.Fatalf("adopted %v, want nothing — a %s row is not this driver's to touch", got, executor.KindKubernetes)
	}
	// Give any (incorrectly) spawned pump time to finish the handle and delete
	// the row; the row surviving is the assertion that nothing was spawned.
	time.Sleep(200 * time.Millisecond)
	if store.Len() != 1 {
		t.Fatal("the foreign driver's row was deleted — its live workload is now unreachable")
	}

	// A row with no external ID names nothing the runtime can be asked about.
	ex.adopt(executor.HandleRecord{HandleID: "c-noname01", ExecutorID: "test-foreign", Driver: executor.KindContainer})
	if got := ex.Handles(); len(got) != 0 {
		t.Fatalf("adopted %v, want nothing — a row with no external ID is unusable", got)
	}
}

// TestShouldReapRunningOrphan is the grace-period decision on its own. It is a
// pure function precisely so this can be exhaustive without a runtime: every
// one of these cases is either impossible or catastrophically slow to stage
// against a real docker.
func TestShouldReapRunningOrphan(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	const grace = 10 * time.Minute

	cases := []struct {
		name           string
		containerStart time.Time
		grace          time.Duration
		tracked        bool
		want           bool
		why            string
	}{
		{
			name:           "old and untracked is the whole point",
			containerStart: now.Add(-time.Hour),
			grace:          grace,
			want:           true,
			why:            "an hour-old container nobody tracks is a hub that died mid-run",
		},
		{
			name:           "exactly at the grace period is old enough",
			containerStart: now.Add(-grace),
			grace:          grace,
			want:           true,
			why:            "the boundary must be inclusive or a container can sit one nanosecond short forever",
		},
		{
			name:           "one nanosecond short is spared",
			containerStart: now.Add(-grace + time.Nanosecond),
			grace:          grace,
			want:           false,
			why:            "younger than the grace period means the owner may still be starting it",
		},
		{
			name:           "started microseconds ago is spared",
			containerStart: now.Add(-3 * time.Microsecond),
			grace:          grace,
			want:           false,
			why:            "this is our own start() between `run -d` and the handle-map insert",
		},
		{
			name:           "tracked is never reaped however old",
			containerStart: now.Add(-30 * 24 * time.Hour),
			grace:          grace,
			tracked:        true,
			want:           false,
			why:            "a tracked container belongs to a live run; age is irrelevant",
		},
		{
			name:           "an undateable container is spared",
			containerStart: time.Time{},
			grace:          grace,
			want:           false,
			why:            "a timestamp we could not parse is not evidence of age",
		},
		{
			name:           "a container from the future is spared",
			containerStart: now.Add(time.Minute),
			grace:          grace,
			want:           false,
			why:            "the runtime's clock disagrees with ours, so any age we compute is fiction",
		},
		{
			name:           "a zero grace period reaps nothing",
			containerStart: now.Add(-time.Hour),
			grace:          0,
			want:           false,
			why:            "zero is what an un-normalised Options carries; it must not mean 'reap on sight'",
		},
		{
			name:           "a negative grace period reaps nothing",
			containerStart: now.Add(-time.Hour),
			grace:          -time.Minute,
			want:           false,
			why:            "same reason as zero, and a negative window has no coherent meaning",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldReapRunningOrphan(now, tc.containerStart, tc.grace, tc.tracked)
			if got != tc.want {
				t.Fatalf("shouldReapRunningOrphan = %v, want %v: %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestOrphanGracePeriodDefaults checks the two places the default is applied.
// Both matter: Normalize covers executors built by New, and orphanGracePeriod
// covers the struct-literal ones the tests and the audit seam construct, where
// a zero window would make the least-configured executor the most destructive.
func TestOrphanGracePeriodDefaults(t *testing.T) {
	for name, in := range map[string]time.Duration{
		"unset":    0,
		"negative": -time.Second,
	} {
		t.Run("Normalize/"+name, func(t *testing.T) {
			got, err := Options{OrphanGracePeriod: in}.Normalize()
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if got.OrphanGracePeriod != DefaultOrphanGracePeriod {
				t.Fatalf("OrphanGracePeriod = %v, want the default %v", got.OrphanGracePeriod, DefaultOrphanGracePeriod)
			}
		})
	}

	t.Run("Normalize keeps an explicit value", func(t *testing.T) {
		got, err := Options{OrphanGracePeriod: 90 * time.Second}.Normalize()
		if err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		if got.OrphanGracePeriod != 90*time.Second {
			t.Fatalf("OrphanGracePeriod = %v, want the configured 90s", got.OrphanGracePeriod)
		}
	})

	t.Run("a struct-literal executor still gets the default", func(t *testing.T) {
		ex := &Executor{id: "raw", handles: make(map[string]*record)}
		if got := ex.orphanGracePeriod(); got != DefaultOrphanGracePeriod {
			t.Fatalf("orphanGracePeriod = %v, want the default %v", got, DefaultOrphanGracePeriod)
		}
	})
}

// TestParseRuntimeTime pins the formats the running sweep has to read. Getting
// this wrong is silent: an unparsable timestamp means nothing is ever reaped,
// which looks exactly like having no orphans.
func TestParseRuntimeTime(t *testing.T) {
	want := time.Date(2026, 8, 23, 4, 7, 51, 0, time.UTC)

	accepted := map[string]time.Time{
		// docker `ps --format {{.CreatedAt}}` — truncated to the second.
		"2026-08-23 04:07:51 +0000 UTC": want,
		// podman `ps --format {{.CreatedAt}}` — nanoseconds retained.
		"2026-08-23 04:07:51.920394978 +0000 UTC": want.Add(920394978 * time.Nanosecond),
		// A hub in a zone with a numeric offset: the offset wins over the
		// abbreviation, so the instant is right rather than shifted.
		"2026-08-23 06:07:51 +0200 CEST": want,
		// docker `inspect --format {{.State.StartedAt}}`.
		"2026-08-23T04:07:51.920394978Z": want.Add(920394978 * time.Nanosecond),
	}
	for in, expect := range accepted {
		got, err := parseRuntimeTime(in)
		if err != nil {
			t.Errorf("parseRuntimeTime(%q): %v", in, err)
			continue
		}
		if !got.Equal(expect) {
			t.Errorf("parseRuntimeTime(%q) = %v, want %v", in, got.UTC(), expect)
		}
	}

	for _, in := range []string{"", "   ", "2 hours ago", "not a timestamp", "1787458071"} {
		if _, err := parseRuntimeTime(in); err == nil {
			t.Errorf("parseRuntimeTime(%q) must fail so the sweep skips rather than guesses", in)
		}
	}
}

// TestTaskIDFromLabels covers the parse that puts a task ID on a handle
// record. executor.Spec has no typed task field, so this is the only place the
// association is made.
func TestTaskIDFromLabels(t *testing.T) {
	cases := map[string]struct {
		labels map[string]string
		want   int
	}{
		"canonical key":  {labels: map[string]string{"task_id": "42"}, want: 42},
		"alternate key":  {labels: map[string]string{"task": "7"}, want: 7},
		"no labels":      {labels: nil, want: 0},
		"unrelated only": {labels: map[string]string{"project": "cloop"}, want: 0},
		// `cloop executor test` labels its smoke run "task_id: smoke". A record
		// that identifies the container is worth keeping even when the
		// bookkeeping on it is not a number.
		"non-numeric": {labels: map[string]string{"task_id": "smoke"}, want: 0},
		"zero":        {labels: map[string]string{"task_id": "0"}, want: 0},
		"whitespace":  {labels: map[string]string{"task_id": "  13 "}, want: 13},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := taskIDFromLabels(tc.labels); got != tc.want {
				t.Fatalf("taskIDFromLabels(%v) = %d, want %d", tc.labels, got, tc.want)
			}
		})
	}
}

// --- integration tests ------------------------------------------------

// TestIntegration_RehydrateReattachesToLiveContainer is the claim the whole
// feature rests on: a driver that never started a container can still stream
// it, read its status and stop it, purely from a persisted name.
//
// The original executor is not (and cannot be) shut down — Go offers no way to
// unload it — so its log pump keeps following the same container throughout.
// That makes this test harder than the real restart it models, not easier: two
// followers and two `wait` calls race on one container, and the assertions
// still have to hold.
func TestIntegration_RehydrateReattachesToLiveContainer(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	ex := newTestExecutor(t, defaultTestImage, func(o *Options) {
		o.ID = "test-rehydrate"
		o.HandleStore = store
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// One directory, held in a variable: t.TempDir() mints a fresh one per
	// call, so re-deriving the container name from a second call would compare
	// against a name that was never used.
	workDir := t.TempDir()
	handle, err := ex.Start(ctx, executor.Spec{
		WorkDir: workDir,
		Argv:    []string{"/bin/sh", "-c", "echo before-restart; sleep 120"},
		Labels:  map[string]string{"task_id": "20191"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = ex.Signal(context.Background(), handle.ID, executor.SignalKill) }()

	rows, err := store.ListHandles("test-rehydrate")
	if err != nil {
		t.Fatalf("ListHandles: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("store holds %d rows after one Start, want 1", len(rows))
	}
	row := rows[0]
	// ExternalID must be the container *name*, not the handle ID: it is the
	// only identifier `logs`, `wait` and `kill` accept.
	if want := ContainerName(mustAbs(workDir), handle.ID); row.ExternalID != want {
		t.Errorf("ExternalID = %q, want the container name %q", row.ExternalID, want)
	}
	if row.ProjectPath != mustAbs(workDir) {
		t.Errorf("ProjectPath = %q, want the resolved work dir %q", row.ProjectPath, mustAbs(workDir))
	}
	if row.Driver != executor.KindContainer {
		t.Errorf("Driver = %q, want %q", row.Driver, executor.KindContainer)
	}
	if row.TaskID != 20191 {
		t.Errorf("TaskID = %d, want 20191 from the spec label", row.TaskID)
	}
	if row.Meta[metaRuntime] != ex.rt.Name {
		t.Errorf("Meta[%q] = %q, want %q", metaRuntime, row.Meta[metaRuntime], ex.rt.Name)
	}
	if row.Image == "" {
		t.Error("Image is empty; an operator reading the table cannot tell what is executing")
	}

	// The restart. Reusing ex.opts guarantees the rebuilt driver is configured
	// identically, which is what a real restart from the same config produces.
	restarted, err := New(ex.opts)
	if err != nil {
		t.Fatalf("rebuilding the driver from the same options: %v", err)
	}

	status, err := restarted.Status(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Status on the rebuilt driver: %v", err)
	}
	if status.State != executor.StateRunning {
		t.Fatalf("state = %q, want running — the container is still up", status.State)
	}

	lines, err := restarted.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream on the rebuilt driver: %v", err)
	}
	// The reattached follower starts from the container's beginning, so output
	// produced before the restart is still there: `logs --follow` replays the
	// log the runtime kept, which is the whole reason this works.
	var seen strings.Builder
	deadline := time.After(60 * time.Second)
	for !strings.Contains(seen.String(), "before-restart") {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("the reattached stream closed without the pre-restart output; got %q", seen.String())
			}
			seen.WriteString(line.Text)
		case <-deadline:
			t.Fatalf("no pre-restart output on the reattached stream within 60s; got %q", seen.String())
		}
	}

	if err := restarted.Signal(ctx, handle.ID, executor.SignalKill); err != nil {
		t.Fatalf("Signal on the rebuilt driver: %v", err)
	}
	// A stop that does not stop is the failure that matters: it is the state
	// the pre-Task-20191 driver was permanently in.
	stopped := false
	for i := 0; i < 300 && !stopped; i++ {
		st, serr := restarted.Status(ctx, handle.ID)
		if serr != nil {
			t.Fatalf("Status while waiting for the kill: %v", serr)
		}
		stopped = st.State.Terminal()
		if !stopped {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !stopped {
		t.Fatal("the workload survived a Signal from the rebuilt driver")
	}
}

// TestIntegration_ReapOrphansCollectsRunningOrphans is consequence (c) of Task
// 20191: before it, a hub killed mid-run left a sandbox running forever.
//
// All three sub-tests share one container, in this order, because the grace
// period is a property of the sweep and not of the container: the same
// container must survive a long-grace sweep and a foreign-executor sweep and
// then be collected by a short-grace one.
func TestIntegration_ReapOrphansCollectsRunningOrphans(t *testing.T) {
	owner := newTestExecutor(t, defaultTestImage, func(o *Options) { o.ID = "test-running-orphan" })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	handle, err := owner.Start(ctx, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", "sleep 240"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = owner.Signal(context.Background(), handle.ID, executor.SignalKill) }()

	owner.mu.Lock()
	name := owner.handles[handle.ID].name
	owner.mu.Unlock()

	// A container this young is indistinguishable from one a concurrent
	// control plane is in the middle of starting, so it must be left alone.
	// This is the assertion that stops the sweep from being a race.
	t.Run("younger than the grace period is spared", func(t *testing.T) {
		sweeper := rebuiltSweeper(t, owner, 10*time.Minute)
		removed, err := sweeper.ReapOrphans(ctx)
		if err != nil {
			t.Fatalf("ReapOrphans: %v", err)
		}
		for _, got := range removed {
			if strings.HasPrefix(got, name) {
				t.Fatalf("reaped %q, but it is younger than the grace period", got)
			}
		}
		assertContainerRunning(t, owner, name, true)
	})

	// Two container executors on one host must not reap each other's work,
	// which the LabelExecutor filter is what enforces.
	t.Run("another executor's container is not ours to reap", func(t *testing.T) {
		sweeper := rebuiltSweeper(t, owner, time.Millisecond)
		sweeper.id = "test-some-other-executor"
		removed, err := sweeper.ReapOrphans(ctx)
		if err != nil {
			t.Fatalf("ReapOrphans: %v", err)
		}
		for _, got := range removed {
			if strings.HasPrefix(got, name) {
				t.Fatalf("executor %q reaped %q, which belongs to %q", sweeper.id, got, owner.id)
			}
		}
		assertContainerRunning(t, owner, name, true)
	})

	t.Run("older than the grace period is collected", func(t *testing.T) {
		// Outrun the timestamp granularity: docker truncates {{.CreatedAt}} to
		// the second, so a container listed in the same second it was created
		// can legitimately read as zero seconds old.
		time.Sleep(1500 * time.Millisecond)

		sweeper := rebuiltSweeper(t, owner, time.Millisecond)
		removed, err := sweeper.ReapOrphans(ctx)
		if err != nil {
			t.Fatalf("ReapOrphans: %v", err)
		}
		want := name + ReapedRunningSuffix
		found := false
		for _, got := range removed {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("ReapOrphans returned %v, want it to contain %q", removed, want)
		}
		assertContainerRunning(t, owner, name, false)
	})
}

// rebuiltSweeper is a second executor over the same runtime and executor ID
// that tracks nothing — which is exactly what a hub looks like after being
// killed and restarted without a handle store.
func rebuiltSweeper(t *testing.T, from *Executor, grace time.Duration) *Executor {
	t.Helper()
	opts := from.opts
	opts.HandleStore = nil
	opts.OrphanGracePeriod = grace
	ex, err := New(opts)
	if err != nil {
		t.Fatalf("building the post-restart executor: %v", err)
	}
	return ex
}

// assertContainerRunning checks the runtime's own view, not the driver's: the
// question these tests ask is whether a container is still burning CPU, and the
// driver's bookkeeping is precisely what cannot be trusted to answer it.
func assertContainerRunning(t *testing.T, ex *Executor, name string, want bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), shortCmdTimeout)
	defer cancel()
	res, err := runCLI(ctx, ex.rt, nil, "inspect", "--format", "{{.State.Running}}", name)
	if err != nil {
		t.Fatalf("inspect %s: %v", name, err)
	}
	running := res.ExitCode == 0 && strings.TrimSpace(res.Stdout) == "true"
	if running != want {
		t.Fatalf("container %s running = %v, want %v (inspect exit %d: %s%s)",
			name, running, want, res.ExitCode, res.Stdout, res.Stderr)
	}
}

// TestRehydrateReArmsAnExpiredDeadline: an adopted container is *tracked*, so
// the orphan sweep will never collect it. Without re-arming the timeout, a
// task with a one-hour cap that outlived a restart would run until the host
// was rebooted — trading the bug this task fixes for a quieter version of it.
//
// The kill goes through the runtime, so the stub records it: asserting on the
// `kill` invocation rather than on the record's state is what makes this a
// test of the signal actually being delivered and not of bookkeeping.
func TestRehydrateReArmsAnExpiredDeadline(t *testing.T) {
	killLog := filepath.Join(t.TempDir(), "kills")
	rt := stubRuntime(t, `kill) echo "$4" >> `+killLog+` ;;
`+liveContainerStub)

	store := executor.NewMemoryHandleStore()
	started := time.Now().Add(-2 * time.Hour).Truncate(time.Millisecond)
	rec := savedHandle("c-expired1", "test-deadline", "cloop-project-expired1", started)
	// The hub was down when this expired.
	rec.Deadline = time.Now().Add(-time.Minute)
	if err := store.PutHandle(rec); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := storeExecutor(t, "test-deadline", rt, store)
	ex.rehydrate()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(killLog); err == nil &&
			strings.Contains(string(data), "cloop-project-expired1") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("an adopted container past its deadline was never killed — the timeout did not survive the restart")
}

// TestRehydrateDoesNotKillWithinTheDeadline is the complement, and the test
// that would catch a re-arm that read the persisted instant as a duration and
// so computed a negative delay for every adopted workload.
func TestRehydrateDoesNotKillWithinTheDeadline(t *testing.T) {
	killLog := filepath.Join(t.TempDir(), "kills")
	rt := stubRuntime(t, `kill) echo "$4" >> `+killLog+` ;;
`+liveContainerStub)

	store := executor.NewMemoryHandleStore()
	rec := savedHandle("c-live0001", "test-deadline-live", "cloop-project-live0001",
		time.Now().Add(-time.Minute).Truncate(time.Millisecond))
	rec.Deadline = time.Now().Add(time.Hour)
	if err := store.PutHandle(rec); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := storeExecutor(t, "test-deadline-live", rt, store)
	ex.rehydrate()

	time.Sleep(300 * time.Millisecond)
	if data, err := os.ReadFile(killLog); err == nil && len(data) > 0 {
		t.Fatalf("a container with an hour left was killed on adoption: %q — "+
			"the deadline was probably read as a duration rather than an instant", data)
	}
}

// TestRehydrateWithoutADeadlineArmsNoTimer: a row written before Task 20191,
// or by a workload that was deliberately uncapped, must not acquire a timeout
// by being adopted.
func TestRehydrateWithoutADeadlineArmsNoTimer(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	rec := savedHandle("c-notimer1", "test-no-deadline", "cloop-project-notimer1", time.Now())
	if err := store.PutHandle(rec); err != nil {
		t.Fatalf("PutHandle: %v", err)
	}

	ex := storeExecutor(t, "test-no-deadline", stubRuntime(t, liveContainerStub), store)
	ex.rehydrate()

	live, err := ex.lookup("c-notimer1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	live.mu.Lock()
	timer := live.killTimer
	live.mu.Unlock()
	if timer != nil {
		t.Fatal("a zero deadline must arm no kill timer")
	}
}
