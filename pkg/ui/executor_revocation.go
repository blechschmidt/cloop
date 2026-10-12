package ui

// executor_revocation.go: a cordon, a drain or an agent's revocation made from
// the CLI takes back what the device holds, as the dashboard's does (Task
// 20424).
//
// The dashboard's cordon and drain take an edge device's leases back
// (revokeLeasesForExecutor), and its delete drops the agent's session. The CLI
// wrote the scheduler row, or the credential's revocation, and stopped: a
// cordoned device kept every credential the cordon was meant to take back, and
// a revoked agent kept its session until it next reconnected — while the
// runbook's incident response told the operator to use the CLI.
//
// The CLI is no hub member: it holds no session and reaches no device. So it
// does what `cloop secret revoke` does (Task 20403) — records what it can,
// announces the change on the hub bus, and waits for the members to answer:
//
//   - The record is the durable half. Every lease recorded as issued to the
//     device, or to a virtual executor running through it, is recorded revoked
//     before anything is announced. The member holding the device's session
//     enforces it now; the member that adopts a run of it later takes the
//     material back instead of the lease over; and with no hub serving at all,
//     the next hub to start enforces it with its lease janitor
//     (reconcileRecordedRevocations) once the device reconnects.
//   - The announcement is the fast half. The member holding the device's
//     session takes its leases back there and then, so the device wipes its
//     lease files while the link is up; for a revoked agent every member then
//     drops it, the one holding its session with a "do not reconnect"
//     goodbye. Each member answers with what it did.
//
// A member acts only on a change the store confirms: a cordon or drain the
// scheduler row records, an agent credential the enrollment store records
// revoked. The bus is a table any process holding the database can write, and
// a forged event must not be able to strip a healthy device of its leases or
// disconnect a valid agent.
//
// Only an edge device's leases are taken back. A cordon of an executor on the
// hub itself — its container runtime, a Kubernetes cluster, the host — leaves
// its workloads their credentials, as the dashboard's does: taking a
// container's environment back means killing it, and a cordon is the operation
// that promises in-flight work continues.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The changes to an executor the CLI announces.
const (
	ExecutorOpCordon = "cordon"
	ExecutorOpDrain  = "drain"
	ExecutorOpRevoke = "revoke"
)

// Bus keys for an executor change announced by a process that is no member.
const (
	invalidateExecutorRevocation    = "executor_revocation"
	invalidateExecutorRevocationAck = "executor_revocation_ack"
)

// executorRevocationRequest is the announcement on the bus.
type executorRevocationRequest struct {
	RequestID  string `json:"request_id"`
	ExecutorID string `json:"executor_id"`
	Op         string `json:"op"`
	Reason     string `json:"reason,omitempty"`
	Actor      string `json:"actor,omitempty"`
}

// executorRevocationAck is a member's answer to one.
type executorRevocationAck struct {
	RequestID string `json:"request_id"`
	ExecutorRevocationMemberReport
}

// ExecutorRevocationAnnouncement is what the CLI tells running hubs about a
// change it wrote to the store.
type ExecutorRevocationAnnouncement struct {
	ExecutorID string
	// Op is ExecutorOpCordon, ExecutorOpDrain or ExecutorOpRevoke.
	Op     string
	Reason string
	Actor  string
}

// LeaseTakeBack is what one lease came to on the member that took it back.
type LeaseTakeBack struct {
	LeaseID string             `json:"lease_id"`
	State   remote.RevokeState `json:"state"`
	Detail  string             `json:"detail,omitempty"`
}

// ExecutorRevocationMemberReport is one member's answer.
type ExecutorRevocationMemberReport struct {
	Member   string `json:"member"`
	Hostname string `json:"hostname,omitempty"`
	// Refused says why the member did nothing: the store does not record the
	// change the announcement claims.
	Refused string `json:"refused,omitempty"`
	// HoldsSession reports that the device's session is on this member.
	HoldsSession bool `json:"holds_session,omitempty"`
	// Acted reports that this member took the device's leases back: it holds
	// the session, or no live member does and it leads adoption.
	Acted bool `json:"acted,omitempty"`
	// Disconnected reports, for a revoked agent, that this member dropped the
	// session it held.
	Disconnected bool `json:"disconnected,omitempty"`
	// Leases is what each lease came to on this member.
	Leases []LeaseTakeBack `json:"leases,omitempty"`
}

// LeaseRevocationState is what the store records of one revoked lease once
// the members have answered.
type LeaseRevocationState struct {
	LeaseID string
	// Pending: not yet taken back from every holder; Detail says what it
	// waits for.
	Pending    bool
	Detail     string
	EnforcedBy string
}

// ExecutorRevocationReport is what an announced executor change came to.
type ExecutorRevocationReport struct {
	// Device is the edge agent whose session serves the executor: the
	// executor itself, or the device a virtual executor runs through. Empty
	// for an executor on the hub itself, whose change takes nothing back and
	// is not announced.
	Device string
	// Recorded are the leases recorded as issued to it, recorded revoked
	// before the announcement.
	Recorded []string
	// Answered are the members' answers; Silent the members alive when it was
	// announced that did not answer within the wait.
	Answered []ExecutorRevocationMemberReport
	Silent   []string
	// Exclusive names a hub holding the control plane alone, which reads no
	// bus; ExclusiveDetail says what it does instead.
	Exclusive       string
	ExclusiveDetail string
	// NoHub: no hub serves this control plane, and the recorded revocations
	// wait for the next to start.
	NoHub bool
	// Leases is what the store records of each recorded lease afterwards.
	Leases []LeaseRevocationState
}

// executorRevocationReason is the reason a change's lease revocations carry,
// in the dashboard's words for the same change.
func executorRevocationReason(op, reason string) string {
	switch op {
	case ExecutorOpCordon:
		return "executor cordoned: " + reason
	case ExecutorOpDrain:
		return "executor draining: " + reason
	default:
		if strings.TrimSpace(reason) == "" {
			return "agent credential revoked"
		}
		return "agent credential revoked: " + reason
	}
}

// AnnounceExecutorRevocation tells every running hub member about a cordon, a
// drain or an agent revocation the caller has already written to the store,
// records revoked the leases the device holds, waits up to wait for the
// members alive at the time to answer, and reports what they did and what the
// store then records of each lease — for `cloop executor cordon|drain|revoke`,
// which change the store from a process that reaches no device.
//
// An executor that serves no edge device is not announced: there is nothing on
// a device to take back.
func AnnounceExecutorRevocation(db *statedb.DB, origin string, ann ExecutorRevocationAnnouncement,
	wait time.Duration) (ExecutorRevocationReport, error) {
	var rep ExecutorRevocationReport
	if db == nil {
		return rep, errors.New("no database")
	}
	ann.ExecutorID = strings.TrimSpace(ann.ExecutorID)
	if ann.ExecutorID == "" {
		return rep, errors.New("an executor id is required")
	}
	switch ann.Op {
	case ExecutorOpCordon, ExecutorOpDrain, ExecutorOpRevoke:
	default:
		return rep, fmt.Errorf("unknown executor change %q", ann.Op)
	}
	device, covered, err := deviceExecutors(db, ann.ExecutorID, ann.Op == ExecutorOpRevoke)
	if err != nil {
		return rep, err
	}
	rep.Device = device
	if device == "" {
		return rep, nil
	}
	rep.Recorded, err = recordDeviceLeaseRevocations(db, covered,
		executorRevocationReason(ann.Op, ann.Reason), ann.Actor)
	if err != nil {
		return rep, err
	}

	rows, err := db.ListHubMembers()
	if err != nil {
		return rep, fmt.Errorf("read the hub members: %w", err)
	}
	now := time.Now()
	expect := map[string]bool{}
	for _, r := range rows {
		if hubcluster.RowAlive(r, now) {
			expect[r.InstanceID] = true
		}
	}
	if st, ierr := hublease.Inspect(hublease.Options{Store: db}); ierr == nil && st.Live && !expect[st.Row.InstanceID] {
		rep.Exclusive = st.Row.InstanceID
		then := "takes the recorded leases back from the device at its next pass, within " + leaseJanitorBound.String()
		if ann.Op == ExecutorOpRevoke {
			then += ", and drops the agent's session at that pass too"
		}
		rep.ExclusiveDetail = fmt.Sprintf("holds this control plane exclusively (pid %d on %s) and reads no "+
			"announcements; its lease janitor %s", st.Row.PID, st.Row.Hostname, then)
	}
	if len(expect) == 0 {
		rep.NoHub = rep.Exclusive == ""
		rep.Leases = leaseRevocationStates(db, rep.Recorded)
		return rep, nil
	}

	_, _, cursor, err := db.HubEventBounds()
	if err != nil {
		return rep, fmt.Errorf("read the bus: %w", err)
	}
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return rep, err
	}
	requestID := hex.EncodeToString(idBytes)
	payload, err := json.Marshal(executorRevocationRequest{
		RequestID: requestID, ExecutorID: ann.ExecutorID, Op: ann.Op, Reason: ann.Reason, Actor: ann.Actor,
	})
	if err != nil {
		return rep, err
	}
	if _, err := db.AppendHubEvents([]statedb.HubEventRow{{
		Origin: origin, Topic: busTopicInvalidate, Key: invalidateExecutorRevocation,
		Payload: string(payload), CreatedAt: time.Now(),
	}}); err != nil {
		return rep, fmt.Errorf("write the announcement to the bus: %w", err)
	}

	got := map[string]ExecutorRevocationMemberReport{}
	complete := func() bool {
		for id := range expect {
			if _, ok := got[id]; !ok {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(wait)
	for !complete() && time.Now().Before(deadline) {
		if evs, err := db.HubEventsAfter(cursor, 512); err == nil {
			for _, ev := range evs {
				cursor = ev.Seq
				if ev.Topic != busTopicInvalidate || ev.Key != invalidateExecutorRevocationAck || ev.Target != origin {
					continue
				}
				var ack executorRevocationAck
				if json.Unmarshal([]byte(ev.Payload), &ack) != nil || ack.RequestID != requestID {
					continue
				}
				// Filed under the member the bus says sent it, whatever the
				// payload claims.
				ack.Member = ev.Origin
				got[ev.Origin] = ack.ExecutorRevocationMemberReport
			}
		}
		if !complete() {
			time.Sleep(150 * time.Millisecond)
		}
	}
	for id := range expect {
		if r, ok := got[id]; ok {
			rep.Answered = append(rep.Answered, r)
		} else {
			rep.Silent = append(rep.Silent, id)
		}
	}
	sort.Strings(rep.Silent)
	sort.Slice(rep.Answered, func(i, j int) bool { return rep.Answered[i].Member < rep.Answered[j].Member })
	rep.Leases = leaseRevocationStates(db, rep.Recorded)
	return rep, nil
}

// deviceExecutors names the edge agent whose session serves id — id itself
// for an agent, its parent for a virtual executor — and the executors whose
// leases a change of id covers: id, and for an agent each virtual executor
// running through it. An executor that is neither serves no device, and both
// are empty. isAgent says id is known to be an agent, which a revocation
// knows from the credential store even for one that never connected.
func deviceExecutors(db *statedb.DB, id string, isAgent bool) (device string, covered []string, err error) {
	if v, ok, err := db.VirtualExecutor(id); err != nil {
		return "", nil, fmt.Errorf("read virtual executor %s: %w", id, err)
	} else if ok {
		return v.ParentID, []string{id}, nil
	}
	if !isAgent {
		row, err := db.GetExecutor(id)
		switch {
		case errors.Is(err, statedb.ErrExecutorNotFound):
			return "", nil, nil
		case err != nil:
			return "", nil, fmt.Errorf("read executor %s: %w", id, err)
		}
		if row.Kind != executor.KindRemoteAgent {
			return "", nil, nil
		}
	}
	covered = []string{id}
	children, err := db.ListVirtualExecutors()
	if err != nil {
		return "", nil, fmt.Errorf("read virtual executors: %w", err)
	}
	for _, v := range children {
		if v.ParentID == id {
			covered = append(covered, v.ID)
		}
	}
	return id, covered, nil
}

// recordDeviceLeaseRevocations records revoked every lease recorded as issued
// to one of executors, with a scrub, and returns their ids.
//
// The same record secretbroker.RecordLeaseRevocation writes, written directly:
// the CLI has no reason to unseal anything to say a lease is revoked.
func recordDeviceLeaseRevocations(db *statedb.DB, executors []string, reason, actor string) ([]string, error) {
	rows, err := db.ListSecretLeases()
	if err != nil {
		return nil, fmt.Errorf("read the recorded leases: %w", err)
	}
	var out []string
	for _, r := range rows {
		if !slices.Contains(executors, r.ExecutorID) {
			continue
		}
		if err := db.PutLeaseRevocation(statedb.LeaseRevocationRow{
			LeaseID: r.LeaseID, Action: string(remote.RevokeScrub), Reason: reason, Actor: actor,
			ExecutorID: r.ExecutorID, ProjectID: r.ProjectID, Holder: r.Holder,
		}); err != nil {
			return out, fmt.Errorf("record the revocation of lease %s: %w", r.LeaseID, err)
		}
		out = append(out, r.LeaseID)
	}
	return out, nil
}

// leaseRevocationStates reads what the store records of each lease's
// whole-lease revocation.
func leaseRevocationStates(db *statedb.DB, leases []string) []LeaseRevocationState {
	out := make([]LeaseRevocationState, 0, len(leases))
	for _, id := range leases {
		st := LeaseRevocationState{LeaseID: id, Pending: true}
		if revs, err := db.LeaseRevocations(id); err == nil {
			for _, r := range revs {
				if r.GrantID != "" {
					continue
				}
				st.Pending, st.Detail, st.EnforcedBy = r.Pending(), r.Detail, r.EnforcedBy
			}
		}
		out = append(out, st)
	}
	return out
}

// ── a member's half ─────────────────────────────────────────────────────────

// onBusExecutorRevocation answers an executor change another process
// announced. On its own goroutine: the bus delivers in order, and a device can
// take most of a minute to answer.
func (s *Server) onBusExecutorRevocation(ev hubcluster.Event) {
	var req executorRevocationRequest
	if err := ev.Decode(&req); err != nil || strings.TrimSpace(req.ExecutorID) == "" {
		return
	}
	go func() {
		defer recoverGoroutine("take back what an announced executor change left a device holding")
		ctx, cancel := context.WithTimeout(context.Background(), revokeFanoutTimeout)
		defer cancel()
		rep := s.executorRevocationHere(ctx, req)
		if n := s.clusterNode(); n != nil && req.RequestID != "" {
			rep.Member = n.ID()
			rep.Hostname, _ = os.Hostname()
			n.PublishTo(ev.Origin, busTopicInvalidate, invalidateExecutorRevocationAck,
				executorRevocationAck{RequestID: req.RequestID, ExecutorRevocationMemberReport: rep})
		}
	}()
}

// executorRevocationHere does this member's part of an announced change: take
// the device's leases back if this member holds its session — or no live
// member does and this one leads — and, for a revoked agent, drop it.
func (s *Server) executorRevocationHere(ctx context.Context, req executorRevocationRequest) ExecutorRevocationMemberReport {
	var rep ExecutorRevocationMemberReport
	id := strings.TrimSpace(req.ExecutorID)
	if why := s.unconfirmedExecutorChange(id, req.Op); why != "" {
		rep.Refused = why
		return rep
	}
	agent := s.agentForExecutorID(id)
	if agent == "" && req.Op == ExecutorOpRevoke {
		// A revoked agent this member never registered is still the agent.
		agent = id
	}
	if agent == "" {
		rep.Refused = id + " is not an edge device or a virtual executor of one on this hub member"
		return rep
	}
	acts, holds := s.actsForAgent(agent)
	rep.HoldsSession, rep.Acted = holds, acts
	if acts {
		rep.Leases = s.takeBackDeviceLeases(ctx, id, agent, executorRevocationReason(req.Op, req.Reason), req.Actor)
	}
	if req.Op == ExecutorOpRevoke {
		rep.Disconnected = s.retireRevokedAgent(agent)
	}
	return rep
}

// unconfirmedExecutorChange checks an announced change against the store and
// says why it cannot be acted on, or "" when the store records it.
func (s *Server) unconfirmedExecutorChange(id, op string) string {
	dir := controlPlaneDir()
	if dir == "" {
		return "this hub member has no control plane"
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return "the control plane's database could not be read: " + err.Error()
	}
	defer db.Close()
	switch op {
	case ExecutorOpCordon, ExecutorOpDrain:
		row, err := db.GetExecutorHealth(id)
		if err != nil {
			return "the store records no scheduling state for " + id
		}
		if st := executor.NodeState(row.State); !st.AdminHeld() {
			return fmt.Sprintf("the store records %s as %s, not cordoned or draining", id, st)
		}
		return ""
	case ExecutorOpRevoke:
		store, err := executorstore.New(db)
		if err != nil {
			return "the credential store could not be read: " + err.Error()
		}
		rec, err := store.GetAgent(id)
		if err != nil || !rec.Revoked() {
			return "the store does not record agent " + id + "'s credential as revoked"
		}
		return ""
	default:
		return fmt.Sprintf("unknown executor change %q", op)
	}
}

// actsForAgent reports whether this member takes back what agent's device
// holds, and whether it holds the agent's session: it does when it holds the
// session, and when no live member does and it leads adoption — the leases
// are then recorded and taken back wherever this member can reach them.
func (s *Server) actsForAgent(agent string) (acts, holds bool) {
	n := s.clusterNode()
	if n == nil {
		return true, true
	}
	o, found, err := n.Lookup(ownerAgent, agent)
	switch {
	case err != nil:
		// Not evidence of anything: the member that would answer for it is
		// unknown, and acting twice is safe where acting nowhere is not.
		return true, false
	case found && o.Self:
		return true, true
	case found && o.Alive:
		return false, false
	default:
		return n.LeadsAdoption(), false
	}
}

// takeBackDeviceLeases revokes, with a scrub, every lease the device holds
// for executorID: those agent's session lists when executorID is the agent
// itself, and every lease recorded as issued to executorID or to a virtual
// executor running through it. It reports what each came to.
func (s *Server) takeBackDeviceLeases(ctx context.Context, executorID, agent, reason, actor string) []LeaseTakeBack {
	var leases []string
	if executorID == agent {
		if hub, err := s.remoteHub(); err == nil && hub != nil {
			if ex, ok := hub.Executor(agent); ok {
				leases = ex.Leases()
			}
		}
	}
	return s.revokeRecordedLeasesOf(ctx, executorID, reason, actor, leases)
}

// retireRevokedAgent ends an agent whose credential is revoked on this member:
// the session, if this member holds it, is dropped with a "do not reconnect"
// goodbye and its handles failed; its executor, and the virtual executors
// running through it, leave this member's registry. It reports whether a
// session was dropped here.
func (s *Server) retireRevokedAgent(agent string) bool {
	hub, err := s.remoteHub()
	if err != nil || hub == nil {
		return false
	}
	connected := false
	if ex, ok := hub.Executor(agent); ok {
		connected = ex.Connected()
	}
	tearDownRevokedAgent(hub, agent)
	executor.DefaultRegistry.Unregister(agent)
	for _, ex := range executor.List() {
		if v, ok := ex.(interface{ ParentID() string }); ok && v.ParentID() == agent {
			executor.DefaultRegistry.Unregister(ex.ID())
		}
	}
	s.broadcastExecutorUpdateLocal("revoked", agent)
	return connected
}

// retireRevokedAgents drops every agent connected here whose credential the
// store records as revoked, after taking its leases back — the bound on a
// revocation no member was told of: one made by an older CLI, or on a hub that
// reads no bus. Run by the lease janitor.
func (s *Server) retireRevokedAgents(ctx context.Context) {
	hub, err := s.remoteHub()
	if err != nil || hub == nil {
		return
	}
	var connected []string
	for _, ex := range hub.Executors() {
		if ex.Connected() {
			connected = append(connected, ex.ID())
		}
	}
	if len(connected) == 0 {
		return
	}
	dir := controlPlaneDir()
	if dir == "" {
		return
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return
	}
	var revoked []string
	if store, err := executorstore.New(db); err == nil {
		for _, id := range connected {
			if rec, err := store.GetAgent(id); err == nil && rec.Revoked() {
				revoked = append(revoked, id)
			}
		}
	}
	_ = db.Close()
	for _, id := range revoked {
		reason := executorRevocationReason(ExecutorOpRevoke, "found by the lease janitor")
		s.takeBackDeviceLeases(ctx, id, id, reason, "janitor")
		s.retireRevokedAgent(id)
		fmt.Fprintf(os.Stderr, "ui: dropped agent %s, whose credential is revoked, and took its leases back\n", id)
	}
}
