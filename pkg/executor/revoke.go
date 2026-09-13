package executor

// revoke.go is the driver-independent half of taking a secret lease back from
// a workload that is already running.
//
// # Why this is here and not in a driver
//
// It used to live entirely in pkg/executor/remote. That package had the whole
// vocabulary — actions, states, acks, a replay log — and the remote driver
// refused to place a workload carrying revocable credentials on an agent too
// old to give them back. The reasoning it recorded for that refusal is the
// reason this file exists:
//
//	Refusing here — rather than running it and hoping nobody revokes — is what
//	keeps "revoking a lease takes the credential away" a property of the system
//	instead of a property of which devices happen to be up to date.
//
// The same sentence, read one level up, indicts the arrangement itself. If the
// guarantee is a property of the *system*, it cannot be implemented in one
// driver. A GitHub PAT leased to a local container sandbox or to an in-cluster
// pod was not revocable at all: the TTL from the lease design and the push
// revocation built on top of it were, on those backends, comments. Worse, the
// Executors panel reported every non-remote driver as revocable on the theory
// that the hub owns their filesystem — true of the directory, irrelevant to
// whether anything ever wipes it.
//
// So the types moved up here and the capability became an interface. A driver
// implements Revoker or it does not, RequireRevocable turns "does not" into a
// refusal at placement time, and a new backend has to opt in deliberately
// rather than inherit a guarantee nobody wrote code for.
//
// # What a revocation actually guarantees
//
// Three different strengths, and RevokeReport says which one you got rather
// than flattening them into "revoked":
//
//   - Files are genuinely gone. Wiped and unlinked, so the next read fails.
//     This is the strong case and it covers the credentials that matter most
//     in practice — kubeconfigs and the git credential helper's token file.
//   - Egress allowlist entries are genuinely gone: the next connection is
//     refused.
//   - Environment variables are dropped from whatever copy the control plane
//     still holds, but a *running process* already has its own copy and no
//     API can reach into another process's heap. This is why RevokeKill
//     exists, and why a driver that cannot scrub env-borne material reports
//     what it killed instead of claiming a scrub it did not perform.
//
// Callers must not describe an env scrub as though the running task had lost
// the credential; see docs/security/model.md.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

// RevokeAction is what a driver should do about a workload still using the
// material being taken away.
type RevokeAction string

const (
	// RevokeScrub invalidates the material and lets the task keep running.
	// It will fail naturally the next time it reaches for the credential.
	//
	// This is the default because a long autonomous run is usually doing
	// many things, only one of which needed the revoked credential. Killing
	// it to revoke a kubeconfig it used an hour ago throws away hours of
	// work to close a window that scrubbing already closes.
	//
	// A driver that cannot scrub a particular material without terminating
	// the workload escalates and reports the kill. Silently doing nothing
	// would be the only worse answer than killing.
	RevokeScrub RevokeAction = "scrub"
	// RevokeKill scrubs and then terminates every task holding the lease.
	//
	// It exists because scrubbing has one hard limit: a credential handed to
	// a process as an environment variable is in that process's own memory,
	// and no control plane can reach into another process's heap. When the
	// credential itself is compromised rather than merely over-granted,
	// killing the task is the only thing that actually stops its use.
	RevokeKill RevokeAction = "kill"
)

// Valid reports whether the action is one a driver knows.
func (a RevokeAction) Valid() bool { return a == RevokeScrub || a == RevokeKill }

// RevokeRequest takes one lease's material back from a running executor.
type RevokeRequest struct {
	// LeaseID is the lease being revoked. Required.
	LeaseID string `json:"lease_id"`
	// GrantID narrows the revocation to one grant within the lease. Empty
	// revokes everything the lease delivered.
	GrantID string `json:"grant_id,omitempty"`
	// Reason is operator-facing text carried into the driver's log and the
	// audit trail, so "why did my run lose its token" has an answer on both
	// sides of the link.
	Reason string `json:"reason,omitempty"`
	// Action is scrub or kill. An empty or unknown action is treated as
	// scrub: the conservative reading of a request from a possibly-newer
	// control plane is the one that does not destroy work.
	Action RevokeAction `json:"action,omitempty"`
}

// Effective returns the action to apply, defaulting an absent or unknown
// value to RevokeScrub.
func (r RevokeRequest) Effective() RevokeAction {
	if r.Action.Valid() {
		return r.Action
	}
	return RevokeScrub
}

// Matches reports whether a binding is in scope for this request.
//
// A request naming only a lease covers every grant under it; one naming a
// grant covers just that grant. Getting this backwards in either direction is
// a real failure — too narrow leaves material behind, too wide takes away
// credentials the operator did not revoke — so it is written once here rather
// than re-derived per driver.
func (r RevokeRequest) Matches(b SecretBinding) bool {
	if strings.TrimSpace(b.LeaseID) != strings.TrimSpace(r.LeaseID) {
		return false
	}
	want := strings.TrimSpace(r.GrantID)
	return want == "" || want == strings.TrimSpace(b.GrantID)
}

// RevokeReport is what a driver actually did.
//
// It is deliberately specific rather than a bare "ok". An operator revoking a
// kubeconfig needs to know whether the file is gone or whether the driver
// merely forgot about it, and a report that cannot distinguish the two would
// let a UI claim a guarantee the system did not deliver.
type RevokeReport struct {
	LeaseID string       `json:"lease_id"`
	GrantID string       `json:"grant_id,omitempty"`
	Action  RevokeAction `json:"action,omitempty"`
	// Known reports whether the driver was holding this lease at all. False
	// is a success, not a failure: the material is not here, which is the
	// end state the revocation asked for.
	Known bool `json:"known"`
	// EnvScrubbed names the variables whose values were dropped. Names only
	// — echoing a revoked credential back to the control plane would be a
	// fine way to write it into a log.
	//
	// A name here means the *control plane's* copy is gone. It does not mean
	// a process that already forked with that variable has lost it; see
	// Killed for the material that needed stronger treatment.
	EnvScrubbed []string `json:"env_scrubbed,omitempty"`
	// FilesRemoved counts credential files wiped.
	FilesRemoved int `json:"files_removed,omitempty"`
	// EgressDropped reports that the lease's network allowlist entry is gone
	// *on this executor*.
	//
	// Only the remote driver sets it, and that is correct rather than an
	// omission. A remote agent keeps an allowlist of its own on the device, so
	// it has something local to drop. The hub's own drivers do not: the
	// allowlist lives in the egress broker's proxy session, which the hub tears
	// down with the lease itself before any driver is asked — reported as
	// WipedLocally, not here. A container or Kubernetes driver claiming to have
	// dropped it would be taking credit for another component's work, and would
	// read as a second, independent guarantee where there is one.
	EgressDropped bool `json:"egress_dropped,omitempty"`
	// Killed lists the handles terminated — for RevokeKill, and for a
	// RevokeScrub the driver could not honour without terminating.
	Killed []string `json:"killed,omitempty"`
	// Error is non-empty when part of the revocation failed. The report is
	// still returned: "I tried and this is what went wrong" is far more
	// actionable than silence, which a hub can only read as unreachable.
	Error string `json:"error,omitempty"`
}

// RevokeState is how far one lease's revocation has got.
type RevokeState string

const (
	// RevokeStatePending: the revocation is on its way, or is queued for a
	// driver that is not currently reachable but is expected back.
	RevokeStatePending RevokeState = "revoke_pending"
	// RevokeStateRevoked: the driver reported what it took back.
	RevokeStateRevoked RevokeState = "revoked"
	// RevokeStateUnreachable: the executor is offline, so the material is
	// still out there. The revocation is queued and will be replayed, but
	// until then this is the honest state and the UI must show it as such.
	RevokeStateUnreachable RevokeState = "unreachable"
	// RevokeStateFailed: the driver answered, and the answer was an error.
	RevokeStateFailed RevokeState = "failed"
)

// Terminal reports whether the state can still change on its own. Only
// RevokeStateRevoked is final; a failure is retried on the next sweep and an
// unreachable executor is retried when it reconnects.
func (s RevokeState) Terminal() bool { return s == RevokeStateRevoked }

// RevokeOutcome is one executor's result for one lease revocation.
type RevokeOutcome struct {
	LeaseID    string      `json:"lease_id"`
	GrantID    string      `json:"grant_id,omitempty"`
	ExecutorID string      `json:"executor_id"`
	State      RevokeState `json:"state"`
	// Action is what was asked for, echoed so a caller reading only the
	// outcome knows whether a kill was requested.
	Action RevokeAction `json:"action,omitempty"`
	Reason string       `json:"reason,omitempty"`
	// SentAt / AckedAt bound how long the material was still live after the
	// operator pressed the button. Operators ask this after an incident.
	SentAt  time.Time `json:"sent_at"`
	AckedAt time.Time `json:"acked_at,omitempty"`
	// Ack is the driver's report, present once State is RevokeStateRevoked.
	Ack *RevokeReport `json:"ack,omitempty"`
	// Error explains a failed or unreachable outcome.
	Error string `json:"error,omitempty"`
}

// Pending reports whether this outcome still needs to be delivered.
func (r RevokeOutcome) Pending() bool { return !r.State.Terminal() }

// ---------------------------------------------------------------------------
// The interface
// ---------------------------------------------------------------------------

// Revoker is an executor that can take a secret lease's material back from a
// workload it has already started.
//
// It is optional in the Go sense and mandatory in the policy sense: a driver
// that does not implement it is refused any spec carrying revocable bindings
// (see RequireRevocable), so the omission surfaces as a named refusal at
// placement time rather than as a credential nobody can withdraw.
//
// Implementations must be safe for concurrent use.
type Revoker interface {
	Executor

	// SupportsRevocation reports whether a revocation issued *right now*
	// would be honoured.
	//
	// It is separate from implementing the interface because the two answer
	// different questions. Implementing Revoker is a property of the driver
	// and is known at compile time; this is a property of the moment — a
	// remote agent that is offline, or one speaking a protocol too old for
	// the frame, cannot honour anything even though its driver can.
	SupportsRevocation() bool

	// HoldsLease reports whether any workload this executor tracks was
	// started with material from leaseID.
	HoldsLease(leaseID string) bool

	// Leases lists the lease IDs this executor is currently holding material
	// for, sorted.
	Leases() []string

	// RevokeLease takes one lease's material back.
	//
	// It returns an outcome rather than an error because the caller's next
	// move depends on *which* failure: an error alone cannot say whether the
	// material is gone, in doubt, or definitely still out there. A driver
	// that was not holding the lease returns RevokeStateRevoked with
	// Ack.Known false — "not here" is the end state a revocation wants.
	RevokeLease(ctx context.Context, req RevokeRequest) RevokeOutcome

	// Revocations reports this executor's revocation log, newest first, so
	// the Secrets panel can show what landed and what is still owed.
	Revocations() []RevokeOutcome
}

// AsRevoker returns ex as a Revoker, reporting whether it is one.
func AsRevoker(ex Executor) (Revoker, bool) {
	rv, ok := ex.(Revoker)
	return rv, ok
}

// SupportsRevocation reports whether ex could honour a revocation issued now.
//
// This is the one function the UI and placement should both call. The
// Executors panel previously answered it with "is this driver remote?", and
// treated every other driver as revocable on the theory that the hub owns
// their filesystem — which says nothing about whether any code wipes it. A
// driver that has not implemented Revoker now reports false, which is what it
// always was.
func SupportsRevocation(ex Executor) bool {
	rv, ok := AsRevoker(ex)
	return ok && rv.SupportsRevocation()
}

// ---------------------------------------------------------------------------
// Placement
// ---------------------------------------------------------------------------

// ErrRevocationUnsupported is returned when a workload carrying revocable
// credentials is aimed at an executor that cannot give them back.
var ErrRevocationUnsupported = errors.New("executor cannot revoke secret leases")

// RevocationDeniedError explains a refused placement in the terms the operator
// needs: which executor, which credentials, and what to do about it.
type RevocationDeniedError struct {
	// ExecutorID and Kind name the driver that was refused.
	ExecutorID string
	Kind       string
	// Bindings are the revocable bindings that made the spec ineligible.
	Bindings []SecretBinding
	// Detail is the driver's own reason, when it implements Revoker but
	// cannot honour a revocation at this moment (an offline agent, a
	// protocol too old). Empty when the driver does not implement Revoker
	// at all.
	Detail string
}

func (e *RevocationDeniedError) Error() string {
	what := DescribeBindings(e.Bindings)
	if e.Detail != "" {
		return fmt.Sprintf("%v: executor %s (%s) carries %s, which the control plane must be able to "+
			"revoke mid-run: %s", ErrRevocationUnsupported, e.ExecutorID, e.Kind, what, e.Detail)
	}
	return fmt.Sprintf("%v: executor %s uses the %s driver, which does not implement revocation, but this "+
		"workload carries %s; a lease placed there could not be withdrawn while the task runs. "+
		"Run this project on an executor that supports revocation, or remove the grant from the project",
		ErrRevocationUnsupported, e.ExecutorID, e.Kind, what)
}

func (e *RevocationDeniedError) Unwrap() error { return ErrRevocationUnsupported }

// RequireRevocable refuses to place spec on ex when the spec carries material
// that ex cannot take back.
//
// This is the rule the remote driver enforced for its own agents, applied to
// every driver. A spec with no revocable bindings passes on any executor —
// the refusal is about credentials, not about drivers — so a deployment that
// has never configured the secret broker is unaffected.
//
// Drivers that implement Revoker still enforce their own, more specific
// refusals inside Start (a remote agent checks the negotiated protocol
// version against the live session). This is the outer gate, and the two are
// deliberately redundant: a security control with one enforcement point is a
// security control with a bypass.
func RequireRevocable(ex Executor, spec Spec) error {
	if ex == nil {
		return nil
	}
	revocable := spec.RevocableSecrets()
	if len(revocable) == 0 {
		return nil
	}
	rv, ok := AsRevoker(ex)
	if !ok {
		return &RevocationDeniedError{ExecutorID: ex.ID(), Kind: ex.Kind(), Bindings: revocable}
	}
	if !rv.SupportsRevocation() {
		return &RevocationDeniedError{
			ExecutorID: ex.ID(), Kind: ex.Kind(), Bindings: revocable,
			Detail: "the executor is not currently able to honour a revocation",
		}
	}
	return nil
}

// DescribeBindings names the credentials in a refusal, so the operator reads
// "the GitHub PAT github-ci" rather than "a secret". A lease ID is the last
// resort: "lease_7f3a" means nothing to the person who granted
// "prod-kubeconfig".
func DescribeBindings(bindings []SecretBinding) string {
	names := make([]string, 0, len(bindings))
	for _, b := range bindings {
		switch {
		case b.SecretName != "" && b.Kind != "":
			names = append(names, fmt.Sprintf("%s (%s)", b.SecretName, b.Kind))
		case b.SecretName != "":
			names = append(names, b.SecretName)
		case b.Kind != "":
			names = append(names, b.Kind)
		default:
			names = append(names, b.LeaseID)
		}
	}
	sort.Strings(names)
	switch len(names) {
	case 0:
		return "brokered credentials"
	case 1:
		return "the brokered credential " + names[0]
	default:
		return "brokered credentials " + strings.Join(names, ", ")
	}
}

// ---------------------------------------------------------------------------
// Revocation log
// ---------------------------------------------------------------------------

// MaxRetainedRevocations bounds a driver's revocation log. A control plane
// runs for months and an operator can revoke as often as they like, so without
// a ceiling this would grow forever. Completed entries are evicted
// oldest-first; pending ones never are, because forgetting a pending
// revocation would silently drop the replay that is the whole point of
// retaining it.
//
// The log is live state, not the record of what happened. Durability belongs
// to the audit trail, which the hub writes per outcome — a process restart
// must not be able to erase the evidence that a credential was withdrawn.
const MaxRetainedRevocations = 512

// RevocationLog is a driver's record of the leases it has been told to take
// back, so they can be replayed and reported.
//
// It is shared by every Revoker rather than reimplemented per driver: the
// eviction rule above is subtle enough that three copies would eventually
// become three different rules, and the one that quietly dropped a pending
// entry would lose a revocation rather than a log line.
//
// The zero value is not usable; call NewRevocationLog.
type RevocationLog struct {
	mu sync.Mutex
	// byLease is keyed by "leaseID\x00grantID" so a whole-lease revocation
	// and a single-grant one do not overwrite each other.
	byLease map[string]*RevokeOutcome
	order   []string
}

// NewRevocationLog returns an empty log.
func NewRevocationLog() *RevocationLog {
	return &RevocationLog{byLease: make(map[string]*RevokeOutcome)}
}

func revocationKey(leaseID, grantID string) string {
	return strings.TrimSpace(leaseID) + "\x00" + strings.TrimSpace(grantID)
}

// Record inserts or refreshes an entry, returning a copy of the live state.
func (rl *RevocationLog) Record(res RevokeOutcome) RevokeOutcome {
	key := revocationKey(res.LeaseID, res.GrantID)
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if prev, ok := rl.byLease[key]; ok {
		// A repeat revocation of an already-settled lease is not an error and
		// must not reopen it: the material is gone, and flipping a settled
		// "revoked" back to "pending" would make the panel oscillate for an
		// operator who clicked twice.
		if prev.State.Terminal() {
			return *prev
		}
		prev.State = res.State
		prev.Action = res.Action
		prev.SentAt = res.SentAt
		prev.Error = res.Error
		if res.Reason != "" {
			prev.Reason = res.Reason
		}
		return *prev
	}

	entry := res
	rl.byLease[key] = &entry
	rl.order = append(rl.order, key)
	rl.pruneLocked()
	return entry
}

// pruneLocked evicts the oldest settled entries. Callers hold rl.mu.
func (rl *RevocationLog) pruneLocked() {
	if len(rl.order) <= MaxRetainedRevocations {
		return
	}
	kept := rl.order[:0]
	for _, key := range rl.order {
		entry, ok := rl.byLease[key]
		if !ok {
			continue
		}
		if len(rl.byLease) > MaxRetainedRevocations && entry.State.Terminal() {
			delete(rl.byLease, key)
			continue
		}
		kept = append(kept, key)
	}
	rl.order = kept
}

// Settle applies a driver's report to an entry.
func (rl *RevocationLog) Settle(leaseID, grantID string, ack RevokeReport, at time.Time) {
	key := revocationKey(leaseID, grantID)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	entry, ok := rl.byLease[key]
	if !ok {
		return
	}
	// A settled entry stays settled, for the same reason Record refuses to
	// reopen one. The material was already taken back; a second revocation
	// that fails is reporting on a credential that is no longer there, and
	// letting it flip "revoked" to "failed" would tell an operator their
	// credential is live when it is gone. It would also leave SentAt from the
	// first attempt beside AckedAt from the second, so the "how long was this
	// live after I pressed the button" figure would span both.
	if entry.State.Terminal() {
		return
	}
	entry.AckedAt = at
	copied := ack
	entry.Ack = &copied
	if ack.Error != "" {
		entry.State = RevokeStateFailed
		entry.Error = ack.Error
		return
	}
	entry.State = RevokeStateRevoked
	entry.Error = ""
}

// Fail marks an entry undelivered, without discarding it: it stays in the log
// so a later replay can retry it.
func (rl *RevocationLog) Fail(leaseID, grantID string, state RevokeState, err error) {
	key := revocationKey(leaseID, grantID)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	entry, ok := rl.byLease[key]
	if !ok {
		return
	}
	entry.State = state
	if err != nil {
		entry.Error = err.Error()
	}
}

// Pending returns the revocations still owed, oldest first.
func (rl *RevocationLog) Pending() []RevokeOutcome {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	out := make([]RevokeOutcome, 0, len(rl.byLease))
	for _, entry := range rl.byLease {
		if entry.Pending() {
			out = append(out, *entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SentAt.Before(out[j].SentAt) })
	return out
}

// Snapshot returns every entry, newest first.
func (rl *RevocationLog) Snapshot() []RevokeOutcome {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	out := make([]RevokeOutcome, 0, len(rl.byLease))
	for _, entry := range rl.byLease {
		out = append(out, *entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SentAt.After(out[j].SentAt) })
	return out
}

// ---------------------------------------------------------------------------
// Lease → handle index
// ---------------------------------------------------------------------------

// LeaseIndex maps a lease to the handles started with its material, so a
// revocation knows which workloads to reach into.
//
// Every driver needs exactly this and nothing more, so it is written once.
// The zero value is not usable; call NewLeaseIndex.
type LeaseIndex struct {
	mu sync.RWMutex
	// byLease is leaseID → set of handle IDs. Keyed by lease alone rather
	// than by lease+grant: a revocation narrowed to one grant still has to
	// find the handle, and the grant filter applies to the bindings once it
	// gets there.
	byLease map[string]map[string]struct{}
	// bindings is handleID → the attribution that travelled with its spec,
	// so a driver can answer "what did this lease actually deliver here"
	// without retaining the spec (and with it the credential values).
	bindings map[string][]SecretBinding
	// unresolved is handleID → why its bindings are unknown.
	//
	// It is the difference between "this workload holds nothing" and "nobody
	// can say what this workload holds", which the maps above cannot express:
	// both are an absent key. Conflating them is precisely the restart bug —
	// a rehydrated holder read as a non-holder, and a revocation that reached
	// nothing reported as one that had nothing to reach.
	unresolved map[string]string
}

// NewLeaseIndex returns an empty index.
func NewLeaseIndex() *LeaseIndex {
	return &LeaseIndex{
		byLease:    make(map[string]map[string]struct{}),
		bindings:   make(map[string][]SecretBinding),
		unresolved: make(map[string]string),
	}
}

// Bind records that handleID was started with material from spec's bindings.
//
// Only the bindings are retained, never the Spec: SecretBinding carries names
// and paths and no values, which is exactly what makes it safe to keep for the
// lifetime of a handle.
func (li *LeaseIndex) Bind(handleID string, bindings []SecretBinding) {
	if li == nil {
		return
	}
	handleID = strings.TrimSpace(handleID)
	if handleID == "" {
		return
	}
	kept := make([]SecretBinding, 0, len(bindings))
	for _, b := range bindings {
		if !b.Revocable() {
			continue
		}
		kept = append(kept, b)
	}

	li.mu.Lock()
	defer li.mu.Unlock()
	// A caller telling us what a handle holds answers the question an
	// unresolved mark asks — including when the answer is "nothing revocable".
	// Clearing it *before* the empty check is the part that matters: a Bind
	// that recorded nothing still resolved the doubt, and leaving the mark
	// standing would make every later revocation on this executor report a
	// failure about a workload whose bindings are in fact known.
	delete(li.unresolved, handleID)
	if len(kept) == 0 {
		return
	}
	li.bindings[handleID] = kept
	for _, b := range kept {
		id := strings.TrimSpace(b.LeaseID)
		if li.byLease[id] == nil {
			li.byLease[id] = make(map[string]struct{})
		}
		li.byLease[id][handleID] = struct{}{}
	}
}

// Adopt restores a rehydrated handle's lease bindings from its persisted
// record, or marks the handle unresolved when the record cannot say.
//
// Every driver's adopt path calls exactly this, which is the point: the
// decision of what an unrecorded binding *means* is a security decision, and
// four copies of it would eventually become four different answers — with the
// permissive one silently losing a revocation.
//
// A record with SecretsRecorded true is authoritative, including when it names
// no bindings: the workload genuinely held nothing, and binding nothing is
// correct. A record with it false predates binding persistence (its row was
// written by an older binary), so the honest answer is that this driver cannot
// account for the handle — recorded as unresolved, and reported as a failure
// by any revocation that follows. That state clears on its own when the
// workload finishes and Release runs.
func (li *LeaseIndex) Adopt(rec HandleRecord) {
	if li == nil {
		return
	}
	handleID := strings.TrimSpace(rec.HandleID)
	if handleID == "" {
		return
	}
	if rec.SecretsRecorded {
		li.Bind(handleID, rec.Secrets)
		return
	}
	li.MarkUnresolved(handleID,
		"the handle row predates lease-binding persistence, so the leases this workload holds are unknown")
}

// MarkUnresolved records that handleID may hold leased material this index
// cannot enumerate.
//
// Callers use it for a row whose bindings could not be decoded as well as for
// one that never carried any. Both mean the same thing to a revocation, and
// the reason string is what tells the operator which it was.
func (li *LeaseIndex) MarkUnresolved(handleID, reason string) {
	if li == nil {
		return
	}
	handleID = strings.TrimSpace(handleID)
	if handleID == "" {
		return
	}
	if strings.TrimSpace(reason) == "" {
		reason = "the leases this workload holds are unknown"
	}
	li.mu.Lock()
	defer li.mu.Unlock()
	li.unresolved[handleID] = reason
}

// Release forgets a handle's lease bindings once it is gone.
func (li *LeaseIndex) Release(handleID string) {
	if li == nil {
		return
	}
	li.mu.Lock()
	defer li.mu.Unlock()
	delete(li.bindings, handleID)
	// Also clears the unresolved mark: a workload that has finished holds
	// nothing, so the doubt it created ends with it. Leaving the mark would
	// make one pre-upgrade workload poison every later revocation on this
	// executor for as long as the process lived.
	delete(li.unresolved, handleID)
	for id, handles := range li.byLease {
		delete(handles, handleID)
		if len(handles) == 0 {
			delete(li.byLease, id)
		}
	}
}

// Unresolved returns handleID → reason for every handle whose bindings this
// index cannot enumerate, sorted by handle.
func (li *LeaseIndex) Unresolved() map[string]string {
	if li == nil {
		return nil
	}
	li.mu.RLock()
	defer li.mu.RUnlock()
	if len(li.unresolved) == 0 {
		return nil
	}
	out := make(map[string]string, len(li.unresolved))
	for id, reason := range li.unresolved {
		out[id] = reason
	}
	return out
}

// UnresolvedError describes the handles this index cannot account for, or nil
// when there are none.
//
// A driver puts this on the revocation's report rather than swallowing it. The
// alternative — reporting the leases it *could* resolve and staying quiet
// about the rest — is the exact shape of the bug this exists to prevent: an
// answer that looks like a successful revocation and is not one.
func (li *LeaseIndex) UnresolvedError() error {
	pending := li.Unresolved()
	if len(pending) == 0 {
		return nil
	}
	ids := make([]string, 0, len(pending))
	for id := range pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// One reason is quoted in full; several are summarised, because they are
	// near-always the same reason repeated per handle.
	detail := pending[ids[0]]
	if len(ids) > 1 {
		detail = "their lease bindings could not be rebuilt"
	}
	return fmt.Errorf(
		"%w: %d workload(s) still running here (%s) cannot be checked against this lease — %s; "+
			"treat the credential as still live and rotate it at the source",
		ErrBindingsUnresolved, len(ids), strings.Join(ids, ", "), detail)
}

// ErrBindingsUnresolved reports that an executor is running a workload whose
// leased material it cannot enumerate, so a revocation aimed at that executor
// cannot be confirmed.
//
// It is a failure and not a warning. "I do not know whether this credential is
// still in use" has to reach the operator as something other than the word
// revoked, or the panel is telling them an incident is closed when it is not.
var ErrBindingsUnresolved = errors.New("executor cannot account for a running workload's secret leases")

// Holds reports whether any tracked handle carries material from leaseID.
//
// It answers true when any handle is unresolved, whatever the lease. That is
// deliberately blunt and deliberately conservative: an unresolved handle might
// hold this lease and nothing here can tell, so the two available answers are
// "possibly" and a lie. True routes the revocation to RevokeLease, which is
// where the doubt is reported as a failure — a false here would skip this
// executor entirely and leave the fleet aggregate reading revoked.
func (li *LeaseIndex) Holds(leaseID string) bool {
	if li == nil {
		return false
	}
	li.mu.RLock()
	defer li.mu.RUnlock()
	if len(li.unresolved) > 0 {
		return true
	}
	_, ok := li.byLease[strings.TrimSpace(leaseID)]
	return ok
}

// Leases lists the lease IDs currently held, sorted.
//
// Unlike Holds this reports only what is *known*, because there is no honest
// way to name a lease an unresolved handle might be holding. Callers that
// enumerate leases to revoke them — draining an executor, say — must therefore
// also consult UnresolvedError, or they will drain an executor and report it
// clean while a workload on it holds a credential nobody listed.
func (li *LeaseIndex) Leases() []string {
	if li == nil {
		return nil
	}
	li.mu.RLock()
	out := make([]string, 0, len(li.byLease))
	for id := range li.byLease {
		out = append(out, id)
	}
	li.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Handles lists the handle IDs holding material matching req, each with the
// bindings that request covers. Handles are returned sorted so a revocation
// processes them deterministically.
func (li *LeaseIndex) Handles(req RevokeRequest) map[string][]SecretBinding {
	if li == nil {
		return nil
	}
	li.mu.RLock()
	defer li.mu.RUnlock()
	ids := li.byLease[strings.TrimSpace(req.LeaseID)]
	if len(ids) == 0 {
		return nil
	}
	out := make(map[string][]SecretBinding, len(ids))
	for handleID := range ids {
		var matched []SecretBinding
		for _, b := range li.bindings[handleID] {
			if req.Matches(b) {
				matched = append(matched, b)
			}
		}
		if len(matched) > 0 {
			out[handleID] = matched
		}
	}
	return out
}

// SortedHandles returns the keys of Handles in a stable order.
func SortedHandles(m map[string][]SecretBinding) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// EnvKeys returns every environment variable name the bindings contributed,
// deduplicated and sorted.
func EnvKeys(bindings []SecretBinding) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, b := range bindings {
		for _, k := range b.EnvKeys {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
