package projectmove

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// Store journals moves. The hub's is DBStore, over the control plane's
// project_moves table; tests use an in-memory one.
type Store interface {
	// Create records a new move. A project with an open move refuses with
	// an error matching ErrMoveOpen.
	Create(ctx context.Context, m Move) (Move, error)
	// Get reads one move; ErrNotFound when there is none.
	Get(ctx context.Context, id string) (Move, error)
	// Advance writes m's detail (and FailedPhase and Error) and moves it to
	// phase to, if it is still at the phase and version m was read at —
	// otherwise an error matching ErrChanged. to may be m's own phase: the
	// write then only records the detail.
	Advance(ctx context.Context, m Move, to Phase) (Move, error)
}

// Driver does the work of each phase on a real hub; the engine sequences it
// and journals what it did. Every method may be called again for the same
// move after the hub stopped part-way through it, and must then finish the
// job rather than fail on what its earlier run left.
type Driver interface {
	// Quiesce stops the project's runs and keeps new ones from starting.
	Quiesce(ctx context.Context, m Move) (*QuiesceRecord, error)
	// Capture writes the source's bundle and files into the move store.
	Capture(ctx context.Context, m Move) (*CaptureRecord, error)
	// Switch binds the project to m.Target and moves m from switch to seed
	// in one transaction, writing m.Detail with the SwitchRecord added; it
	// returns the move as written.
	Switch(ctx context.Context, m Move) (Move, error)
	// Seed gives the target what was captured.
	Seed(ctx context.Context, m Move) (*SeedRecord, error)
	// Verify reads the target back and compares it with the capture.
	Verify(ctx context.Context, m Move) (*VerifyRecord, error)
	// RollBack restores the binding the switch replaced and moves m to
	// rolled_back in one transaction; it returns the move as written.
	RollBack(ctx context.Context, m Move) (Move, error)
	// Retain says what a verified move keeps, and how to clean it up.
	Retain(ctx context.Context, m Move) *Retained
}

// Hooks hears about every write the engine makes. The hub audits and
// broadcasts from it.
type Hooks interface {
	Transitioned(ctx context.Context, from, to Move)
}

// Engine drives moves. Its zero value is not usable: Store and Driver are
// required.
type Engine struct {
	Store  Store
	Driver Driver
	Hooks  Hooks
	// Member names the hub process driving, for the timeline.
	Member string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

// StartRequest asks for a move.
type StartRequest struct {
	Project Project
	// Target is the binding the project moves to; see ParseTarget.
	Target string
	// AbandonSource moves without capturing the source: the way off a
	// device that is gone for good.
	AbandonSource bool
	// StartedBy is who asked.
	StartedBy string
	// ProbeTimeout bounds the preflight's reachability probes.
	ProbeTimeout time.Duration
}

// ErrHandOff is a phase saying another hub process must run it — in a hub
// cluster, the member holding the connection the phase needs. The engine
// records nothing and stops driving; the member that can run the phase takes
// the move's lease next.
var ErrHandOff = errors.New("projectmove: another hub process must run this phase")

// ErrSourceUnsupported refuses a move whose source this hub cannot capture.
var ErrSourceUnsupported = errors.New("projectmove: this hub cannot capture the project's source")

// Start records a move and runs its preflight, with the caller's env (the
// target must be one they may use). A move that passes is left at quiesce for
// Drive to take on; one that does not is recorded as failed at preflight, and
// the error says why — a *BlockedError carries the report. A project that
// already has a move in progress refuses with ErrMoveOpen.
func (e *Engine) Start(ctx context.Context, env Env, req StartRequest) (Move, *Report, error) {
	if e == nil || e.Store == nil || e.Driver == nil || env == nil {
		return Move{}, nil, errors.New("projectmove: no engine")
	}
	project := req.Project
	project.Path = strings.TrimSpace(project.Path)
	if project.Path == "" || !filepath.IsAbs(project.Path) {
		return Move{}, nil, fmt.Errorf("%w: %q is not an absolute path", ErrInvalidProject, project.Path)
	}
	project.Path = filepath.Clean(project.Path)
	if parent, _, ok := feature.ParentOf(project.Path); ok {
		return Move{}, nil, fmt.Errorf("%w: move %s", ErrFeature, parent)
	}
	if project.Name == "" {
		project.Name = filepath.Base(project.Path)
	}
	tgt, err := ParseTarget(req.Target)
	if err != nil {
		return Move{}, nil, err
	}
	source, err := env.Binding(ctx, project)
	if err != nil {
		return Move{}, nil, fmt.Errorf("projectmove: where %s is bound now: %w", project.Path, err)
	}
	id, err := NewMoveID()
	if err != nil {
		return Move{}, nil, err
	}
	at := e.now()
	m := Move{
		ID: id, Project: project, Source: strings.TrimSpace(source), Target: tgt.Binding,
		Phase: PhasePreflight, AbandonSource: req.AbandonSource, StartedBy: req.StartedBy,
		CreatedAt: at, UpdatedAt: at,
		Detail: Detail{Timeline: []Step{{Phase: PhasePreflight, Started: at, Member: e.Member}}},
	}
	created, err := e.Store.Create(ctx, m)
	if err != nil {
		return created, nil, err
	}
	e.hook(ctx, Move{}, created)

	rep, perr := Preflight(ctx, env, project, tgt.Binding, Options{
		AbandonSource: req.AbandonSource, Quiesce: true, ProbeTimeout: req.ProbeTimeout,
	})
	work := created.clone()
	work.Detail.Timeline[len(work.Detail.Timeline)-1].Ended = e.now()
	if perr == nil {
		work.Detail.Preflight = summarize(rep)
		switch {
		case rep.Blocked:
			perr = &BlockedError{Report: rep}
		default:
			perr = sourceSupported(rep, req.AbandonSource)
		}
	}
	if perr != nil {
		out, err := e.fail(ctx, work, PhasePreflight, perr)
		if err != nil {
			return out, rep, err
		}
		return out, rep, perr
	}
	out, err := e.advance(ctx, created, work, PhaseQuiesce)
	return out, rep, err
}

// sourceSupported refuses a source this hub cannot capture: a device's working
// copy or a pool runner's volume is out of its reach, and a move that cannot
// capture must say so before it stops a run, unless it was asked to abandon
// the source.
func sourceSupported(rep *Report, abandon bool) error {
	if abandon {
		return nil
	}
	switch rep.Source.Workspace {
	case WorkspaceHubTree, WorkspaceEphemeral, "":
		return nil
	case WorkspaceDevice:
		return fmt.Errorf("%w: the project's working copy is on device %s, and this hub can capture a project only from its own filesystem; move it with abandon_source to leave the device's copy behind", ErrSourceUnsupported, nonEmpty(rep.Source.Parent, rep.Source.ExecutorID))
	case WorkspacePool:
		return fmt.Errorf("%w: the project's working copy is on executor pool %s's volumes, which this hub cannot read; push its work, then move it with abandon_source", ErrSourceUnsupported, rep.Source.PoolID)
	}
	return nil
}

// Drive runs the move from the phase it is at until it ends, ctx is
// cancelled, or another process takes it over (ErrChanged). It is what a hub
// runs for a move it holds the lease of, after Start and after a restart
// alike.
//
// An error means the move is not finished: the store could not be written,
// ctx ended, or the move is someone else's now. A move that failed is not an
// error: it is returned failed or rolled back.
func (e *Engine) Drive(ctx context.Context, id string) (Move, error) {
	if e == nil || e.Store == nil || e.Driver == nil {
		return Move{}, errors.New("projectmove: no engine")
	}
	for {
		if err := contextErr(ctx); err != nil {
			return Move{}, err
		}
		m, err := e.Store.Get(ctx, id)
		if err != nil {
			return m, err
		}
		if !m.Open() {
			return m, nil
		}
		if !m.Phase.valid() {
			return m, fmt.Errorf("projectmove: move %s is at %q, which this build does not know", m.ID, m.Phase)
		}
		var out Move
		switch {
		case m.Detail.Rollback != nil && m.Detail.Rollback.Pending:
			out, err = e.rollBack(ctx, m)
		case m.Phase == PhasePreflight:
			// Start runs the preflight with the caller's view of the target;
			// with the caller gone it cannot be run again.
			work := m.clone()
			out, err = e.fail(ctx, work, PhasePreflight,
				errors.New("the hub stopped before the move's preflight finished; nothing was changed, so start the move again"))
		default:
			out, err = e.runPhase(ctx, m)
		}
		if err != nil {
			return out, err
		}
	}
}

// runPhase runs m's phase and journals the outcome.
func (e *Engine) runPhase(ctx context.Context, m Move) (Move, error) {
	phase := m.Phase
	started := e.now()
	work := m.clone()
	step := Step{Phase: phase, Started: started, Member: e.Member}

	var perr error
	switch phase {
	case PhaseQuiesce:
		rec, err := e.Driver.Quiesce(ctx, work)
		work.Detail.Quiesce, perr = rec, err
	case PhaseCapture:
		rec, err := e.Driver.Capture(ctx, work)
		work.Detail.Capture, perr = rec, err
		if err == nil && rec != nil {
			hubmetrics.ProjectMoveCapturedBytes.Add(float64(rec.Bytes))
		}
	case PhaseSwitch:
		step.Ended = e.now()
		work.Detail.Timeline = append(work.Detail.Timeline, step)
		out, err := e.Driver.Switch(ctx, work)
		if err == nil {
			e.observe(phase, started, nil)
			e.hook(ctx, m, out)
			return out, nil
		}
		if errors.Is(err, ErrChanged) || errors.Is(err, ErrHandOff) || contextErr(ctx) != nil {
			return m, err
		}
		perr = err
		work.Detail.Timeline = work.Detail.Timeline[:len(work.Detail.Timeline)-1]
	case PhaseSeed:
		rec, err := e.Driver.Seed(ctx, work)
		work.Detail.Seed, perr = rec, err
	case PhaseVerify:
		rec, err := e.Driver.Verify(ctx, work)
		work.Detail.Verify, perr = rec, err
		if err == nil && rec != nil && len(rec.Mismatches) > 0 {
			perr = fmt.Errorf("the target does not hold what was captured: %s", summarizeMismatches(rec.Mismatches))
		}
		if perr == nil {
			work.Detail.Retained = e.Driver.Retain(ctx, work)
		}
	default:
		return m, fmt.Errorf("projectmove: move %s is at %q, which has no work", m.ID, phase)
	}
	if err := contextErr(ctx); err != nil {
		// Told to stop — the hub is shutting down, or this process lost
		// the move's lease. Whatever the phase got to is run again by
		// whoever drives the move next; nothing is recorded as failed.
		return m, err
	}
	if errors.Is(perr, ErrHandOff) {
		return m, perr
	}
	e.observe(phase, started, perr)
	step.Ended = e.now()
	if perr != nil {
		step.Error = perr.Error()
	}
	work.Detail.Timeline = append(work.Detail.Timeline, step)
	if perr != nil {
		return e.fail(ctx, work, phase, perr)
	}
	return e.advance(ctx, m, work, phase.next())
}

// summarizeMismatches bounds a list of mismatches for a sentence.
func summarizeMismatches(mm []string) string {
	const show = 5
	if len(mm) <= show {
		return strings.Join(mm, "; ")
	}
	return strings.Join(mm[:show], "; ") + fmt.Sprintf("; and %d more", len(mm)-show)
}

// fail records a failed phase. Before the switch that ends the move failed;
// after it, the move is marked as rolling back — journalled first, so a hub
// that stops before the rollback commits rolls back when it resumes — and
// rolled back.
func (e *Engine) fail(ctx context.Context, work Move, phase Phase, cause error) (Move, error) {
	msg := strings.TrimPrefix(cause.Error(), "projectmove: ")
	if !phase.Switched() {
		from := work
		work.FailedPhase, work.Error = phase, msg
		out, err := e.write(ctx, from, work, PhaseFailed)
		if err == nil {
			hubmetrics.ProjectMoves.Inc(string(PhaseFailed))
		}
		return out, err
	}
	work.Detail.Rollback = &RollbackRecord{Pending: true, FailedPhase: phase, Reason: msg, At: e.now()}
	marked, err := e.write(ctx, work, work, phase)
	if err != nil {
		return marked, err
	}
	return e.rollBack(ctx, marked)
}

// rollBack runs the driver's rollback of a move marked for one.
func (e *Engine) rollBack(ctx context.Context, m Move) (Move, error) {
	started := e.now()
	work := m.clone()
	work.Detail.Timeline = append(work.Detail.Timeline, Step{Phase: PhaseRolledBack, Started: started, Ended: started, Member: e.Member})
	out, err := e.Driver.RollBack(ctx, work)
	if err != nil {
		return m, err
	}
	hubmetrics.ProjectMoves.Inc(string(PhaseRolledBack))
	e.hook(ctx, m, out)
	return out, nil
}

// advance moves work, read as from, on to phase to.
func (e *Engine) advance(ctx context.Context, from, work Move, to Phase) (Move, error) {
	out, err := e.write(ctx, from, work, to)
	if err == nil && to == PhaseDone {
		hubmetrics.ProjectMoves.Inc(string(PhaseDone))
	}
	return out, err
}

// write journals work at phase to, compared against from.
func (e *Engine) write(ctx context.Context, from, work Move, to Phase) (Move, error) {
	work.Phase, work.Version = from.Phase, from.Version
	out, err := e.Store.Advance(ctx, work, to)
	if err != nil {
		return from, err
	}
	e.hook(ctx, from, out)
	return out, nil
}

func (e *Engine) hook(ctx context.Context, from, to Move) {
	if e.Hooks != nil {
		e.Hooks.Transitioned(ctx, from, to)
	}
}

// observe records how long a phase ran.
func (e *Engine) observe(phase Phase, started time.Time, err error) {
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	hubmetrics.ProjectMovePhaseDuration.Observe(e.now().Sub(started).Seconds(), string(phase), outcome)
}
