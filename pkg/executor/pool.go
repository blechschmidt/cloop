package executor

// pool.go: projects bound to an executor pool (Task 20482).
//
// An executor pool is a set of ephemeral runners a controller outside the hub
// starts on demand — Kubernetes Pods, in the first controller — each of which
// enrolls with a single-use token, takes one run and is retired. The pool, not
// any one runner, is what a project is bound to: a runner does not exist until
// the project's run asks for one, so there is no executor ID to bind ahead of
// time.
//
// So a binding may name a pool instead of an executor. Its value is
// PoolBindingPrefix and the pool's ID, stored where every other binding is,
// and Resolve answers it with a *PoolCapacityError rather than an executor:
// nothing can be dispatched to a pool directly. The hub's run paths read that
// error as "queue this run for the pool" (pkg/ui), and every other dispatch —
// a model call, a requirement check — reports it, because a runner is taken
// by exactly one run and a helper call that took it would leave the queued
// run that asked for it waiting for another.
//
// A process that knows nothing of pools — the CLI, an older hub sharing the
// database — fails closed on such a binding: this file's Resolve refuses it
// with the error above, and a build before this one looks the value up as an
// executor ID, finds none, and refuses the run.

import (
	"errors"
	"fmt"
	"strings"
)

// PoolBindingPrefix marks a project binding that names an executor pool.
// No executor ID carries it: agent IDs are base64url, which has no ':'.
const PoolBindingPrefix = "pool:"

// PoolBinding is the binding value for a project bound to poolID.
func PoolBinding(poolID string) string { return PoolBindingPrefix + strings.TrimSpace(poolID) }

// PoolOf reports the pool a binding value names, if it names one.
func PoolOf(binding string) (poolID string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(binding), PoolBindingPrefix)
	if !found || strings.TrimSpace(rest) == "" {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

// ErrWaitingForPoolCapacity is what a dispatch to a pool-bound project gets
// when it is not a run the pool's queue can hold, and what a *PoolCapacityError
// unwraps to.
var ErrWaitingForPoolCapacity = errors.New("executor: waiting for pool capacity")

// PoolCapacityError is Resolve's answer for a project bound to an executor
// pool: there is no executor to hand back, only a queue to wait in.
type PoolCapacityError struct {
	// PoolID is the pool the project is bound to.
	PoolID string
	// PoolName is the pool's name, when the caller knows it.
	PoolName string
	// ProjectPath is the project that was resolved.
	ProjectPath string
	// Reason says why nothing runs yet, when the caller knows: the pool has
	// no idle runner, all of its runners are busy, it was revoked.
	Reason string
}

// Error implements error.
func (e *PoolCapacityError) Error() string {
	pool := e.PoolID
	if e.PoolName != "" {
		pool = fmt.Sprintf("%s (%s)", e.PoolName, e.PoolID)
	}
	msg := fmt.Sprintf("executor: project %q runs on executor pool %s: waiting for pool capacity", e.ProjectPath, pool)
	if r := strings.TrimSpace(e.Reason); r != "" {
		msg += ": " + r
	} else {
		msg += ": its runs wait in the pool's queue for a runner, and nothing else is dispatched to a pool"
	}
	return msg
}

// Unwrap lets callers match with errors.Is(err, ErrWaitingForPoolCapacity).
func (e *PoolCapacityError) Unwrap() error { return ErrWaitingForPoolCapacity }

// Ephemeral is implemented by a driver whose executor takes one workload and
// is then retired — an executor pool's runner. Such an executor is never a
// placement or failover target: it was started for the run its pool's queue
// assigns it, and a second workload would find it gone.
type Ephemeral interface {
	Ephemeral() bool
}

// ErrEphemeralRunner refuses a binding, a default or a dispatch that names an
// executor pool's runner directly: a runner takes only the run its pool's queue
// hands it, through the pool, never by name.
var ErrEphemeralRunner = errors.New("executor: an executor pool's runner takes only the run its pool hands it; " +
	"bind the project to the pool (pool:<id>) instead")

// IsEphemeral reports whether ex is an ephemeral pool runner.
func IsEphemeral(ex Executor) bool {
	e, ok := ex.(Ephemeral)
	return ok && e.Ephemeral()
}

// MatchCandidate evaluates one candidate against req with the scheduler's own
// rules, returning the first constraint it fails. It exists for a caller that
// judges something no registry holds — an executor pool's runner template,
// before any runner of it exists — and must not answer differently from
// Select: it is reject(), not a copy of it.
func MatchCandidate(c Candidate, req Requirements) (Rejection, bool) {
	if c.Executor == nil {
		return Rejection{Constraint: ConstraintNoCandidates, Detail: "no executor"}, true
	}
	return reject(c, req)
}

// resolvePool answers a binding that names a pool. Nothing is dispatched to a
// pool directly, so the answer is always the capacity error; see the file
// header.
func (r *Registry) resolvePool(poolID, projectPath string) (Executor, error) {
	return nil, &PoolCapacityError{PoolID: poolID, ProjectPath: projectPath}
}
