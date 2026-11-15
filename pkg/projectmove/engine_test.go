package projectmove

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// errCrash stands for the hub process dying at a write.
var errCrash = errors.New("test: the hub stopped here")

// memStore is a Store in memory with the same compare-and-swap rule as the
// journal, and a world beside it: the project's binding, which a switch writes
// in the same "transaction" as the move.
type memStore struct {
	mu      sync.Mutex
	moves   map[string]Move
	binding map[string]string

	// writes counts every write attempted; crashAt, when positive, makes
	// that write crash — before it is applied, or after when crashAfter.
	writes     int
	crashAt    int
	crashAfter bool
	// dead is set by the crash: the process that crashed writes nothing
	// more, until restart brings a new one.
	dead bool
}

func newMemStore() *memStore {
	return &memStore{moves: map[string]Move{}, binding: map[string]string{}}
}

// crash decides whether this write crashes, and whether before or after. A
// write by a process that already crashed fails as if before.
func (s *memStore) crash() (before, after bool) {
	if s.dead {
		return true, false
	}
	s.writes++
	if s.crashAt > 0 && s.writes == s.crashAt {
		s.dead = true
		return !s.crashAfter, s.crashAfter
	}
	return false, false
}

func (s *memStore) Create(_ context.Context, m Move) (Move, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range s.moves {
		if o.Project.Path == m.Project.Path && o.Open() {
			return o, fmt.Errorf("%w: %s", ErrMoveOpen, o.ID)
		}
	}
	before, after := s.crash()
	if before {
		return Move{}, errCrash
	}
	m.Version = 1
	s.moves[m.ID] = m.clone()
	if after {
		return Move{}, errCrash
	}
	return m.clone(), nil
}

func (s *memStore) Get(_ context.Context, id string) (Move, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.moves[id]
	if !ok {
		return Move{}, ErrNotFound
	}
	return m.clone(), nil
}

func (s *memStore) Advance(_ context.Context, m Move, to Phase) (Move, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.advanceLocked(m, to, nil)
}

// advanceLocked applies one compare-and-swap, and with it whatever also
// changes in the same transaction.
func (s *memStore) advanceLocked(m Move, to Phase, also func()) (Move, error) {
	cur, ok := s.moves[m.ID]
	if !ok {
		return Move{}, ErrNotFound
	}
	if s.dead {
		return Move{}, errCrash
	}
	if cur.Phase != m.Phase || cur.Version != m.Version {
		return Move{}, fmt.Errorf("%w: at %s v%d, write expected %s v%d", ErrChanged, cur.Phase, cur.Version, m.Phase, m.Version)
	}
	before, after := s.crash()
	if before {
		return Move{}, errCrash
	}
	next := m.clone()
	next.Phase = to
	next.Version = cur.Version + 1
	if to.Open() || to == PhaseDone {
		next.FailedPhase, next.Error = "", ""
	}
	if !to.Open() {
		next.FinishedAt = time.Now()
	}
	s.moves[m.ID] = next
	if also != nil {
		also()
	}
	if after {
		return Move{}, errCrash
	}
	return next.clone(), nil
}

func (s *memStore) bindingOf(path string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binding[path]
}

// fakeDriver records each phase it runs and fails the ones a test names.
type fakeDriver struct {
	store *memStore

	mu    sync.Mutex
	calls []Phase
	fail  map[Phase]error
	// mismatch makes Verify report the target differs.
	mismatch bool
	// block, when set for a phase, holds it until the channel closes.
	block map[Phase]chan struct{}
}

func newDriver(s *memStore) *fakeDriver {
	return &fakeDriver{store: s, fail: map[Phase]error{}, block: map[Phase]chan struct{}{}}
}

func (d *fakeDriver) record(ctx context.Context, p Phase) error {
	d.mu.Lock()
	d.calls = append(d.calls, p)
	ch := d.block[p]
	err := d.fail[p]
	d.mu.Unlock()
	if ch != nil {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (d *fakeDriver) called() []Phase {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Phase(nil), d.calls...)
}

func (d *fakeDriver) Quiesce(ctx context.Context, m Move) (*QuiesceRecord, error) {
	if err := d.record(ctx, PhaseQuiesce); err != nil {
		return nil, err
	}
	return &QuiesceRecord{Stopped: []string{"the project"}}, nil
}

func (d *fakeDriver) Capture(ctx context.Context, m Move) (*CaptureRecord, error) {
	if err := d.record(ctx, PhaseCapture); err != nil {
		return nil, err
	}
	return &CaptureRecord{Store: "/store/" + m.ID, Delivery: DeliverDevice, Bundle: "repo.bundle", Bytes: 1234}, nil
}

func (d *fakeDriver) Switch(ctx context.Context, m Move) (Move, error) {
	if err := d.record(ctx, PhaseSwitch); err != nil {
		return Move{}, err
	}
	d.store.mu.Lock()
	defer d.store.mu.Unlock()
	m.Detail.Switch = &SwitchRecord{PreviousBinding: d.store.binding[m.Project.Path], At: time.Now()}
	return d.store.advanceLocked(m, PhaseSeed, func() { d.store.binding[m.Project.Path] = m.Target })
}

func (d *fakeDriver) Seed(ctx context.Context, m Move) (*SeedRecord, error) {
	if err := d.record(ctx, PhaseSeed); err != nil {
		return nil, err
	}
	return &SeedRecord{Delivery: DeliverDevice, Executor: m.Target}, nil
}

func (d *fakeDriver) Verify(ctx context.Context, m Move) (*VerifyRecord, error) {
	if err := d.record(ctx, PhaseVerify); err != nil {
		return nil, err
	}
	rec := &VerifyRecord{Delivery: DeliverDevice, Checked: 7}
	if d.mismatch {
		rec.Mismatches = []string{"branch refs/heads/main: want a, got b"}
	}
	return rec, nil
}

func (d *fakeDriver) RollBack(ctx context.Context, m Move) (Move, error) {
	if err := d.record(ctx, PhaseRolledBack); err != nil {
		return Move{}, err
	}
	d.store.mu.Lock()
	defer d.store.mu.Unlock()
	prev := ""
	if m.Detail.Switch != nil {
		prev = m.Detail.Switch.PreviousBinding
	}
	m.FailedPhase, m.Error = m.Detail.Rollback.FailedPhase, m.Detail.Rollback.Reason
	m.Detail.Rollback.Pending = false
	return d.store.advanceLocked(m, PhaseRolledBack, func() { d.store.binding[m.Project.Path] = prev })
}

func (d *fakeDriver) Retain(_ context.Context, m Move) *Retained {
	return &Retained{Source: "the hub's directory", Store: "/store/" + m.ID, Command: "cloop executor move cleanup " + m.ID}
}

// recordingHooks keeps every transition.
type recordingHooks struct {
	mu    sync.Mutex
	steps []string
}

func (h *recordingHooks) Transitioned(_ context.Context, from, to Move) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.steps = append(h.steps, string(from.Phase)+"->"+string(to.Phase))
}

// moveWorld is one hub's view of a move: its store, its driver, its engine.
type moveWorld struct {
	env    *fakeEnv
	store  *memStore
	driver *fakeDriver
	hooks  *recordingHooks
	engine *Engine
}

func newWorld() *moveWorld {
	w := &moveWorld{env: newEnv(), store: newMemStore(), hooks: &recordingHooks{}}
	w.store.binding[testProject.Path] = "local"
	w.driver = newDriver(w.store)
	w.engine = &Engine{Store: w.store, Driver: w.driver, Hooks: w.hooks, Member: "m1"}
	return w
}

// restart is the hub coming back: the same journal and world, a new process.
func (w *moveWorld) restart() {
	w.store.mu.Lock()
	w.store.dead, w.store.crashAt = false, 0
	w.store.mu.Unlock()
	w.driver = &fakeDriver{store: w.store, fail: w.driver.fail, mismatch: w.driver.mismatch, block: map[Phase]chan struct{}{}}
	w.engine = &Engine{Store: w.store, Driver: w.driver, Hooks: w.hooks, Member: "m2"}
}

func (w *moveWorld) start(t *testing.T, target string) Move {
	t.Helper()
	m, rep, err := w.engine.Start(context.Background(), w.env, StartRequest{Project: testProject, Target: target, StartedBy: "alice"})
	if err != nil {
		t.Fatalf("start: %v (report %+v)", err, rep)
	}
	return m
}

func TestAMoveRunsEveryPhaseOnceAndEndsVerified(t *testing.T) {
	w := newWorld()
	m := w.start(t, "dev1")
	if m.Phase != PhaseQuiesce || m.Source != "local" || m.Target != "dev1" || m.Detail.Preflight == nil {
		t.Fatalf("started = %+v", m)
	}
	out, err := w.engine.Drive(context.Background(), m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if out.Phase != PhaseDone || out.Error != "" || out.FinishedAt.IsZero() {
		t.Fatalf("ended = %s %q", out.Phase, out.Error)
	}
	want := []Phase{PhaseQuiesce, PhaseCapture, PhaseSwitch, PhaseSeed, PhaseVerify}
	if got := w.driver.called(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("phases = %v, want %v", got, want)
	}
	if got := w.store.bindingOf(testProject.Path); got != "dev1" {
		t.Errorf("binding = %q", got)
	}
	if out.Detail.Retained == nil || !strings.Contains(out.Detail.Retained.Command, m.ID) {
		t.Errorf("retained = %+v", out.Detail.Retained)
	}
	if out.Detail.Switch == nil || out.Detail.Switch.PreviousBinding != "local" {
		t.Errorf("switch = %+v", out.Detail.Switch)
	}
	if len(out.Detail.Timeline) != 6 {
		t.Errorf("timeline = %+v", out.Detail.Timeline)
	}
	steps := strings.Join(w.hooks.steps, " ")
	if steps != "->preflight preflight->quiesce quiesce->capture capture->switch switch->seed seed->verify verify->done" {
		t.Errorf("transitions = %s", steps)
	}
	// Driving a finished move does nothing.
	again, err := w.engine.Drive(context.Background(), m.ID)
	if err != nil || again.Version != out.Version || len(w.driver.called()) != len(want) {
		t.Errorf("a finished move was driven again: %v %v", again.Phase, err)
	}
}

func TestEachPhaseFailing(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		phase    Phase
		mismatch bool
		want     Phase
		binding  string
	}{
		{phase: PhaseQuiesce, want: PhaseFailed, binding: "local"},
		{phase: PhaseCapture, want: PhaseFailed, binding: "local"},
		{phase: PhaseSwitch, want: PhaseFailed, binding: "local"},
		{phase: PhaseSeed, want: PhaseRolledBack, binding: "local"},
		{phase: PhaseVerify, want: PhaseRolledBack, binding: "local"},
		{phase: PhaseVerify, mismatch: true, want: PhaseRolledBack, binding: "local"},
	} {
		name := string(tc.phase)
		if tc.mismatch {
			name += "-mismatch"
		}
		t.Run(name, func(t *testing.T) {
			w := newWorld()
			if tc.mismatch {
				w.driver.mismatch = true
			} else {
				w.driver.fail[tc.phase] = boom
			}
			m := w.start(t, "dev1")
			out, err := w.engine.Drive(context.Background(), m.ID)
			if err != nil {
				t.Fatal(err)
			}
			if out.Phase != tc.want || out.FailedPhase != tc.phase {
				t.Fatalf("ended %s (failed at %s), want %s at %s", out.Phase, out.FailedPhase, tc.want, tc.phase)
			}
			if !strings.Contains(out.Error, "boom") && !strings.Contains(out.Error, "does not hold what was captured") {
				t.Errorf("error = %q", out.Error)
			}
			if got := w.store.bindingOf(testProject.Path); got != tc.binding {
				t.Errorf("binding = %q, want %q", got, tc.binding)
			}
			called := w.driver.called()
			for _, p := range called {
				if p == PhaseRolledBack && !tc.phase.Switched() {
					t.Errorf("a failure before the switch rolled back: %v", called)
				}
			}
			if tc.phase.Switched() {
				if called[len(called)-1] != PhaseRolledBack {
					t.Errorf("no rollback: %v", called)
				}
				if out.Detail.Rollback == nil || out.Detail.Rollback.Pending {
					t.Errorf("rollback record = %+v", out.Detail.Rollback)
				}
				// The bundle is kept: the capture's record stands.
				if out.Detail.Capture == nil || out.Detail.Capture.Store == "" {
					t.Errorf("the capture record was dropped: %+v", out.Detail.Capture)
				}
			}
			if out.Detail.Retained != nil {
				t.Errorf("a failed move recorded a retained source as if done: %+v", out.Detail.Retained)
			}
			// A failed move frees the project for another.
			w.driver.fail = map[Phase]error{}
			w.driver.mismatch = false
			if _, _, err := w.engine.Start(context.Background(), w.env, StartRequest{Project: testProject, Target: "dev2"}); err != nil {
				t.Errorf("a new move after a failed one: %v", err)
			}
		})
	}
}

func TestAPreflightThatBlocksEndsTheMoveFailedAtPreflight(t *testing.T) {
	w := newWorld()
	m, rep, err := w.engine.Start(context.Background(), w.env, StartRequest{Project: testProject, Target: "nowhere"})
	var blocked *BlockedError
	if !errors.As(err, &blocked) || rep == nil || !rep.Blocked {
		t.Fatalf("err = %v, report %+v", err, rep)
	}
	if m.Phase != PhaseFailed || m.FailedPhase != PhasePreflight || !strings.Contains(m.Error, "No such executor") {
		t.Errorf("move = %s at %s: %q", m.Phase, m.FailedPhase, m.Error)
	}
	if len(w.driver.called()) != 0 || w.store.bindingOf(testProject.Path) != "local" {
		t.Errorf("a blocked move did work: %v", w.driver.called())
	}
}

// TestAMoveFromADeviceNeedsAnAgentThatCanCapture (Task 20495): a device whose
// agent captures over the protocol is moved like the hub's tree; one whose
// agent is too old is refused at the preflight, naming the upgrade, before
// anything is stopped or captured — never moved with a partial capture —
// unless the move abandons the source.
func TestAMoveFromADeviceNeedsAnAgentThatCanCapture(t *testing.T) {
	w := newWorld()
	w.env.binding = "dev1"
	w.store.binding[testProject.Path] = "dev1"
	w.env.deviceTree = &Tree{Git: GitState{Dir: "/var/lib/cloop-executor/work/app", Repository: true}}
	m, _, err := w.engine.Start(context.Background(), w.env, StartRequest{Project: testProject, Target: "local"})
	if err != nil || m.Phase != PhaseQuiesce {
		t.Fatalf("a capable device: err = %v, move %s", err, m.Phase)
	}
	if _, err := w.engine.Drive(context.Background(), m.ID); err != nil {
		t.Fatal(err)
	}

	w = newWorld()
	w.env.binding = "dev1"
	w.store.binding[testProject.Path] = "dev1"
	w.env.upgrade = &AgentUpgradeError{Device: "dev1", Have: 28, Need: 29,
		Message: "Device dev1's agent speaks protocol v28, and the hub needs v29 to capture a project's working copy for a move.",
		Remedy:  "Upgrade the agent from the Executors panel."}
	m, rep, err := w.engine.Start(context.Background(), w.env, StartRequest{Project: testProject, Target: "local"})
	var blocked *BlockedError
	if !errors.As(err, &blocked) || m.Phase != PhaseFailed || m.FailedPhase != PhasePreflight {
		t.Fatalf("an old agent: err = %v, move %s at %s", err, m.Phase, m.FailedPhase)
	}
	if !holds(rep, want{KindSourceAgent, SeverityBlocker, "Upgrade the agent"}) {
		t.Errorf("no upgrade finding:\n%s", dump(rep))
	}
	if calls := w.driver.called(); len(calls) != 0 {
		t.Errorf("a move refused at its preflight did work: %v", calls)
	}
	m, _, err = w.engine.Start(context.Background(), w.env, StartRequest{Project: testProject, Target: "local", AbandonSource: true})
	if err != nil || m.Phase != PhaseQuiesce || !m.AbandonSource {
		t.Fatalf("abandoning: %v %+v", err, m)
	}
}

func TestASecondMoveOfTheProjectIsRefusedWhileOneIsOpen(t *testing.T) {
	w := newWorld()
	first := w.start(t, "dev1")
	_, _, err := w.engine.Start(context.Background(), w.env, StartRequest{Project: testProject, Target: "dev2"})
	if !errors.Is(err, ErrMoveOpen) {
		t.Fatalf("err = %v, want ErrMoveOpen", err)
	}
	if _, err := w.engine.Drive(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.engine.Start(context.Background(), w.env, StartRequest{Project: testProject, Target: "dev2"}); err != nil {
		t.Errorf("after the first ended: %v", err)
	}
}

func TestAMoveRefusesAFeature(t *testing.T) {
	w := newWorld()
	_, _, err := w.engine.Start(context.Background(), w.env, StartRequest{
		Project: Project{Path: testProject.Path + "/.cloop/features/x"}, Target: "dev1"})
	if !errors.Is(err, ErrFeature) {
		t.Errorf("err = %v", err)
	}
}

// TestCrashAndResumeAtEveryPhaseBoundary stops the hub at every write the
// journal takes — before it commits and after — and has a new process resume
// the move: it must end where an uninterrupted move ends, with the binding
// where that move leaves it.
func TestCrashAndResumeAtEveryPhaseBoundary(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		fail    Phase
		end     Phase
		binding string
	}{
		{name: "verified", end: PhaseDone, binding: "dev1"},
		{name: "seed fails", fail: PhaseSeed, end: PhaseRolledBack, binding: "local"},
		{name: "capture fails", fail: PhaseCapture, end: PhaseFailed, binding: "local"},
	} {
		// Count the writes of an uninterrupted run.
		ref := newWorld()
		if scenario.fail != "" {
			ref.driver.fail[scenario.fail] = errors.New("boom")
		}
		m := ref.start(t, "dev1")
		if _, err := ref.engine.Drive(context.Background(), m.ID); err != nil {
			t.Fatal(err)
		}
		total := ref.store.writes
		for at := 1; at <= total; at++ {
			for _, after := range []bool{false, true} {
				name := fmt.Sprintf("%s/write%d/%s", scenario.name, at, map[bool]string{false: "before", true: "after"}[after])
				t.Run(name, func(t *testing.T) {
					w := newWorld()
					if scenario.fail != "" {
						w.driver.fail[scenario.fail] = errors.New("boom")
					}
					w.store.crashAt, w.store.crashAfter = at, after
					m, _, err := w.engine.Start(context.Background(), w.env, StartRequest{Project: testProject, Target: "dev1"})
					id := m.ID
					if err == nil {
						_, err = w.engine.Drive(context.Background(), id)
					}
					if !errors.Is(err, errCrash) {
						t.Fatalf("the crash at write %d did not happen: %v", at, err)
					}
					w.restart()
					if id == "" {
						// The crash took the move's very creation: find it, or
						// see that none was recorded and start again.
						for mid := range w.store.moves {
							id = mid
						}
						if id == "" {
							m = w.start(t, "dev1")
							id = m.ID
						}
					}
					out, err := w.engine.Drive(context.Background(), id)
					if err != nil {
						t.Fatalf("resume: %v", err)
					}
					want := scenario.end
					if out.Phase == PhaseFailed && out.FailedPhase == PhasePreflight {
						// The hub stopped during the preflight, which a
						// resume cannot run again: nothing changed.
						if got := w.store.bindingOf(testProject.Path); got != "local" {
							t.Errorf("binding = %q after a move that never left preflight", got)
						}
						return
					}
					if out.Phase != want {
						t.Fatalf("resumed move ended %s (%s at %s), want %s", out.Phase, out.Error, out.FailedPhase, want)
					}
					if got := w.store.bindingOf(testProject.Path); got != scenario.binding {
						t.Errorf("binding = %q, want %q", got, scenario.binding)
					}
					if out.Phase == PhaseRolledBack && (out.Detail.Rollback == nil || out.Detail.Rollback.Pending) {
						t.Errorf("rollback record = %+v", out.Detail.Rollback)
					}
					// Phases never ran out of order: a later phase never ran
					// before an earlier one after it.
					order := map[Phase]int{PhaseQuiesce: 1, PhaseCapture: 2, PhaseSwitch: 3, PhaseSeed: 4, PhaseVerify: 5, PhaseRolledBack: 6}
					last := 0
					for _, p := range w.driver.called() {
						if order[p] < last {
							t.Errorf("the resumed process ran %s after a later phase: %v", p, w.driver.called())
						}
						last = order[p]
					}
				})
			}
		}
	}
}

func TestAStoppedProcessLeavesThePhaseForTheNextOne(t *testing.T) {
	w := newWorld()
	hold := make(chan struct{})
	w.driver.block[PhaseSeed] = hold
	m := w.start(t, "dev1")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := w.engine.Drive(ctx, m.ID)
		done <- err
	}()
	// Wait for the seed to be under way, then take the lease away.
	deadline := time.After(10 * time.Second)
	for {
		called := w.driver.called()
		if len(called) > 0 && called[len(called)-1] == PhaseSeed {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the seed never started")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("drive = %v", err)
	}
	cur, _ := w.store.Get(context.Background(), m.ID)
	if cur.Phase != PhaseSeed || cur.Error != "" {
		t.Fatalf("a stopped process recorded %s %q", cur.Phase, cur.Error)
	}
	w.restart()
	out, err := w.engine.Drive(context.Background(), m.ID)
	if err != nil || out.Phase != PhaseDone {
		t.Fatalf("resumed: %s %v", out.Phase, err)
	}
}

func TestAProcessWhoseMoveWasTakenOverStops(t *testing.T) {
	w := newWorld()
	hold := make(chan struct{})
	w.driver.block[PhaseCapture] = hold
	m := w.start(t, "dev1")
	done := make(chan error, 1)
	go func() {
		_, err := w.engine.Drive(context.Background(), m.ID)
		done <- err
	}()
	for {
		called := w.driver.called()
		if len(called) > 0 && called[len(called)-1] == PhaseCapture {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Another process wrote the move meanwhile.
	cur, _ := w.store.Get(context.Background(), m.ID)
	if _, err := w.store.Advance(context.Background(), cur, cur.Phase); err != nil {
		t.Fatal(err)
	}
	close(hold)
	if err := <-done; !errors.Is(err, ErrChanged) {
		t.Fatalf("drive = %v, want ErrChanged", err)
	}
}

func TestPhaseHelpers(t *testing.T) {
	if PhaseSeed.next() != PhaseVerify || PhaseVerify.next() != PhaseDone || PhasePreflight.next() != PhaseQuiesce {
		t.Error("phase order")
	}
	for _, p := range []Phase{PhaseDone, PhaseFailed, PhaseRolledBack} {
		if p.Open() {
			t.Errorf("%s is open", p)
		}
	}
	if !PhaseSeed.Switched() || !PhaseVerify.Switched() || PhaseSwitch.Switched() || PhaseCapture.Switched() {
		t.Error("switched phases")
	}
	if Phase("bogus").valid() {
		t.Error("an unknown phase is valid")
	}
	id, err := NewMoveID()
	if err != nil || len(id) != 16 {
		t.Errorf("id = %q %v", id, err)
	}
	if DescribeTarget("pool:p1") != "executor pool p1" || DescribeTarget("") != "the hub's default executor" {
		t.Error("DescribeTarget")
	}
}
