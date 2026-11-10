package executorpool

// demand.go: what a pool may learn about the queue, and what it is told
// (Task 20482).
//
// A controller holding a pool's credential is told how many queued runs its
// pool could take. That number is information about other people's work, and
// the runs behind it are what the controller's runners will be handed — code,
// a seeded plan, brokered credentials. So a run counts towards a pool, and is
// handed to one of its runners, only when every one of these still holds:
//
//   - it was queued for this pool, and the project is still bound to it — an
//     administrator rebinding a project takes its queued run out of the pool's
//     sight;
//   - the pool's access list is the one the run was admitted under, when the
//     person who started it was there to be checked against it; a changed list
//     cannot be re-checked without their sign-in, so the run waits for them to
//     start it again;
//   - the pool's owner, when it has one, may read the project: an owner's
//     controller runs owner-controlled machines, and a project its owner may
//     not see must never reach them;
//   - the pool's runners can satisfy what the run needs, judged by the
//     scheduler's own rules (executor.MatchCandidate) against the pool's
//     declared labels and capabilities.
//
// Anything else is invisible, and is never counted, described or handed over.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Access answers the questions about a queued run that a pool cannot answer
// from its own rows. The hub supplies it; tests fake it.
type Access interface {
	// Binding returns the executor binding projectPath has now, "" for none.
	// An error means the binding could not be read, which decides nothing.
	Binding(projectPath string) (string, error)
	// OwnerMayRead reports whether the identity owner may read projectPath
	// under the hub's project access policy. An error is read as "no".
	OwnerMayRead(owner, projectPath string) (bool, error)
}

// Verdict is whether a queued run is visible to a pool.
type Verdict struct {
	Visible bool
	// Reason says why not, for the project's readers.
	Reason string
	// Final says waiting will not change the answer — the binding moved, the
	// access list changed, the owner may not read it, the runners cannot run
	// it — so the run is taken out of the queue rather than left to wait.
	Final bool
}

// Visible decides whether entry is visible to pool under the current access
// list fingerprint audienceFP. See the file header for the rules.
func Visible(pool Pool, entry statedb.PoolQueueRow, audienceFP string, access Access) Verdict {
	switch {
	case entry.PoolID != pool.ID:
		return Verdict{Reason: "it is queued for another pool", Final: true}
	case pool.Revoked():
		return Verdict{Reason: "its executor pool was revoked", Final: true}
	case !entry.Open():
		return Verdict{Reason: "it is no longer queued", Final: true}
	}
	if access == nil {
		return Verdict{Reason: "the hub cannot check who may see it"}
	}
	got, err := access.Binding(entry.ProjectPath)
	if err != nil {
		return Verdict{Reason: "the hub cannot read the project's binding: " + err.Error()}
	}
	if got != pool.Binding() {
		return Verdict{Reason: "the project is no longer bound to executor pool " + pool.Name, Final: true}
	}
	if entry.AudienceFP != audienceFP {
		return Verdict{Reason: "executor pool " + pool.Name + "'s access list changed after the run was queued; " +
			"start it again so it is checked against the list as it is now", Final: true}
	}
	if pool.Owner != "" {
		ok, err := access.OwnerMayRead(pool.Owner, entry.ProjectPath)
		if err != nil {
			return Verdict{Reason: "the hub cannot check whether the pool's owner may read the project: " + err.Error()}
		}
		if !ok {
			return Verdict{Reason: "executor pool " + pool.Name + " belongs to someone who may not read this project, " +
				"so its runners may not run it", Final: true}
		}
	}
	req, err := DecodeRequirements(entry.Requirements)
	if err != nil {
		return Verdict{Reason: "its requirements could not be read: " + err.Error(), Final: true}
	}
	if rej, rejected := pool.Admits(req); rejected {
		return Verdict{Reason: "executor pool " + pool.Name + "'s runners cannot run it: they " + rej.Detail +
			" (" + string(rej.Constraint) + ")", Final: true}
	}
	return Verdict{Visible: true}
}

// EncodeRequirements stores what a queued run needs of an executor.
func EncodeRequirements(req executor.Requirements) (string, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("executorpool: encode requirements: %w", err)
	}
	return string(b), nil
}

// DecodeRequirements reads what EncodeRequirements stored.
func DecodeRequirements(s string) (executor.Requirements, error) {
	var req executor.Requirements
	if strings.TrimSpace(s) == "" {
		return req, nil
	}
	if err := json.Unmarshal([]byte(s), &req); err != nil {
		return executor.Requirements{}, fmt.Errorf("executorpool: decode requirements: %w", err)
	}
	return req, nil
}

// Admits judges req against the pool's runner template with the scheduler's
// own rules, returning the first constraint it fails.
//
// The template is what a runner of this pool will be before it says anything
// for itself: an ephemeral remote agent, isolated from the hub, carrying the
// pool's labels and declared capabilities, with what every current agent can
// do — fetch a workspace, return its work, receive a branch and a project. A
// queued run's requirements are checked against the real runner again when it
// is handed over; this check is what decides whether the run counts at all.
func (p Pool) Admits(req executor.Requirements) (executor.Rejection, bool) {
	// Capacity is the queue's business, and a runner is pinned by the hand-over,
	// never by a requirement a run was queued with.
	req.IgnoreCapacity = true
	req.ExecutorID = ""
	return executor.MatchCandidate(p.Template(), req)
}

// Template is the placement candidate a runner of this pool is judged as
// before one exists. See Admits.
func (p Pool) Template() executor.Candidate {
	caps := p.agentCapabilities()
	return executor.Candidate{
		Executor:          &template{pool: p, caps: caps},
		Health:            executor.Health{State: executor.NodeReady},
		Labels:            p.Labels,
		Harnesses:         p.Capabilities.Harnesses,
		ContainerRuntimes: p.Capabilities.ContainerRuntimes,
		MemoryMB:          p.Capabilities.MemoryMB,
	}
}

// agentCapabilities is what a runner of this pool would advertise at hello.
func (p Pool) agentCapabilities() remote.AgentCapabilities {
	return remote.AgentCapabilities{
		OS:                    p.Capabilities.Platform,
		Arch:                  p.Capabilities.Arch,
		CPUs:                  p.Capabilities.CPUs,
		MemoryMB:              p.Capabilities.MemoryMB,
		ContainerRuntimes:     p.Capabilities.ContainerRuntimes,
		Harnesses:             p.Capabilities.Harnesses,
		WorkDirRoot:           p.WorkDirRoot,
		Labels:                p.Labels,
		WorkspaceProvisioning: true,
		WriteBack:             true,
		BranchBundles:         true,
		MaxConcurrent:         1,
	}
}

// template is a pool's runner as placement sees it before one exists. It runs
// nothing: every workload method refuses.
type template struct {
	pool Pool
	caps remote.AgentCapabilities
}

var errTemplate = errors.New("executorpool: a pool's runner template runs nothing")

func (t *template) ID() string   { return t.pool.Binding() }
func (t *template) Kind() string { return executor.KindRemoteAgent }
func (t *template) Capabilities() executor.Capabilities {
	c := t.caps.Executor()
	c.MaxConcurrent = 1
	return c
}
func (t *template) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errTemplate
}
func (t *template) Signal(context.Context, string, executor.Signal) error { return errTemplate }
func (t *template) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, errTemplate
}
func (t *template) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errTemplate
}
func (t *template) HealthCheck(context.Context) error { return nil }

// Ephemeral implements executor.Ephemeral: a pool's runner takes one run.
func (t *template) Ephemeral() bool { return true }

// The revocation half of executor.Revoker: a current agent honours revocation,
// and the run's requirements are judged as one would.
func (t *template) SupportsRevocation() bool { return true }
func (t *template) HoldsLease(string) bool   { return false }
func (t *template) Leases() []string         { return nil }
func (t *template) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	return executor.RevokeOutcome{LeaseID: req.LeaseID, ExecutorID: t.ID(), State: executor.RevokeStateRevoked}
}
func (t *template) Revocations() []executor.RevokeOutcome { return nil }

// AudienceFingerprint condenses a pool's access list, so a queued run can tell
// whether the list it was admitted under is still the list. Order-free; the
// empty list has its own fingerprint, "".
func AudienceFingerprint(entries []statedb.ExecutorAudienceEntry) string {
	if len(entries) == 0 {
		return ""
	}
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		lines = append(lines, strings.ToLower(strings.TrimSpace(e.Kind))+"\x00"+strings.TrimSpace(e.Value))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:8])
}

// Snapshot is what a pool's controller is told: the demand it should meet and
// the runners it has.
type Snapshot struct {
	PoolID     string `json:"pool_id"`
	Name       string `json:"name"`
	Revoked    bool   `json:"revoked"`
	MaxRunners int    `json:"max_runners"`
	// Demand is how many queued runs this pool could take.
	Demand int `json:"demand"`
	// Busy runners hold a run; Idle ones enrolled and wait for one; Pending
	// ones were minted and have not enrolled.
	Busy    int `json:"busy"`
	Idle    int `json:"idle"`
	Pending int `json:"pending"`
	// Runners is Busy + Idle + Pending: what counts against MaxRunners.
	Runners int `json:"runners"`
	// Spare is how many more runners MaxRunners allows.
	Spare int `json:"spare"`
	// Wanted is how many runners the controller should start now: the demand
	// the idle and pending runners will not meet, within Spare.
	Wanted int `json:"wanted"`
	// Revision changes whenever anything above does, so a long-poll can ask
	// for "anything newer than this" on whichever hub member it reaches.
	Revision string `json:"revision"`
	// At is when the snapshot was taken.
	At time.Time `json:"at"`
}

// ComputeSnapshot counts a pool's demand and runners. Only visible queued runs
// count; see Visible. The verdicts for every open entry come back too, keyed
// by queue ID, for the caller that acts on them.
func ComputeSnapshot(pool Pool, runners []statedb.ExecutorPoolRunnerRow, queue []statedb.PoolQueueRow,
	audienceFP string, access Access, now time.Time) (Snapshot, map[string]Verdict) {
	snap := Snapshot{PoolID: pool.ID, Name: pool.Name, Revoked: pool.Revoked(), MaxRunners: pool.MaxRunners, At: now.UTC()}
	verdicts := map[string]Verdict{}
	for _, q := range queue {
		if q.PoolID != pool.ID || q.State != statedb.PoolQueueWaiting {
			continue
		}
		v := Visible(pool, q, audienceFP, access)
		verdicts[q.ID] = v
		if v.Visible {
			snap.Demand++
		}
	}
	for _, r := range runners {
		if r.PoolID != pool.ID || !r.Live(now) {
			continue
		}
		switch r.State {
		case statedb.PoolRunnerBusy:
			snap.Busy++
		case statedb.PoolRunnerIdle:
			snap.Idle++
		case statedb.PoolRunnerPending:
			snap.Pending++
		}
	}
	snap.Runners = snap.Busy + snap.Idle + snap.Pending
	if !snap.Revoked {
		snap.Spare = max(0, pool.MaxRunners-snap.Runners)
		snap.Wanted = min(snap.Spare, max(0, snap.Demand-snap.Idle-snap.Pending))
	} else {
		snap.Demand = 0
	}
	snap.Revision = snap.revision(pool)
	return snap, verdicts
}

// revision fingerprints everything a controller acts on — the counts and the
// pool's definition, which says what to start its runners as — and not the
// time.
func (s Snapshot) revision(pool Pool) string {
	spec, _ := json.Marshal(pool.Spec())
	key := fmt.Sprintf("%s|%t|%d|%d|%d|%d|%d|%d|%s", s.PoolID, s.Revoked, s.MaxRunners, s.Demand, s.Busy, s.Idle,
		s.Pending, s.Wanted, spec)
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}
