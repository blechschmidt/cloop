package secretbroker

// The request side of the broker (Task 20271).
//
// Everything else in this package answers "may this executor hold this
// credential". Nothing answered "may I have one" — Mint and Grant are gated on
// authz.PermSecretGrant and there was no other door, so a developer who needed a
// repository or a cluster had to ask in a chat window and wait for somebody to
// hand-mint it. That is not merely inconvenient; it is the mechanism by which
// over-broad standing grants get created. The person minting is reconstructing a
// scope from a sentence, under interruption, and a wider grant is always the
// cheaper guess than a wrong narrow one.
//
// An AccessRequest makes the ask a first-class record: who, for what, scoped how,
// for how long, and why. An approval then replays it through Broker.Grant — the
// same function `cloop secret grant` and POST /api/grants call — so there is
// exactly one place in the process where a grant comes into existence, and
// therefore exactly one place where its constraints are validated.
//
// # The three rules that make this safe
//
// An approval cannot widen the ask. The minted grant carries the request's own
// subject and constraints verbatim; ApproveInput has no field that could
// substitute a different repository list or a different project. An approver who
// wants something narrower denies and says so, or mints directly through the
// grant path that is already theirs. This is a property of the type, not a check
// that could be forgotten.
//
// An approval cannot exceed the approver's own reach. Delegation carries the
// ceiling the caller is entitled to hand out, and the minted TTL is the minimum
// of what was asked, what the approver typed, and that ceiling. A request aimed
// at every project or every executor is refused outright unless the approver is
// entitled to delegate fleet-wide.
//
// Nobody approves their own request. Refused explicitly, by comparing the
// decider against the requester, rather than left to whatever the surrounding
// role check happens to be — because on a small team the requester very often
// *does* hold PermSecretGrant, and a two-person rule that evaporates exactly
// then is not a rule.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RequestState is where an access request sits in its lifecycle.
type RequestState string

const (
	// RequestPending: filed, not yet decided. The only state from which any
	// transition is possible.
	RequestPending RequestState = "pending"
	// RequestApproved: a grant was minted. GrantID names it.
	RequestApproved RequestState = "approved"
	// RequestDenied: an approver refused, with a note.
	RequestDenied RequestState = "denied"
	// RequestWithdrawn: the requester took it back.
	RequestWithdrawn RequestState = "withdrawn"
	// RequestExpired: nobody decided it in time.
	//
	// A terminal state of its own rather than a flavour of denied, because the
	// two mean opposite things to the person who asked: denied is an answer,
	// expired is the absence of one. An operator whose requests keep expiring
	// has a queue problem, and collapsing the states would hide it.
	RequestExpired RequestState = "expired"
)

// Valid reports whether s is a known state.
func (s RequestState) Valid() bool {
	switch s {
	case RequestPending, RequestApproved, RequestDenied, RequestWithdrawn, RequestExpired:
		return true
	}
	return false
}

// Terminal reports whether no further transition is possible from s.
func (s RequestState) Terminal() bool { return s.Valid() && s != RequestPending }

const (
	// DefaultRequestTTL is how long a request waits for a decision before it
	// lapses.
	//
	// Bounded at all because the failure mode of an unbounded queue is not that
	// it grows — it is that a stale request gets approved. Three days is long
	// enough to survive a weekend and short enough that an approval is still
	// being made against a reason the approver can evaluate.
	DefaultRequestTTL = 72 * time.Hour

	// MaxRequestTTL caps how long a request may wait, whatever the caller asks
	// for. Same argument, applied to the caller who would rather it never
	// lapsed.
	MaxRequestTTL = 30 * 24 * time.Hour

	// DefaultDelegationMaxTTL is the ceiling on a minted grant's lifetime when
	// an approver's Delegation does not state one.
	//
	// Deliberately shorter than a request may ask for: the default answer to
	// "how long should this credential live" should be days, and an approver who
	// genuinely needs longer states it rather than gets it by omission.
	DefaultDelegationMaxTTL = 7 * 24 * time.Hour

	// MaxDelegationTTL is the longest lifetime any approver may hand out,
	// whatever their Delegation says.
	//
	// Not a security boundary — an approver can always approve again, and one
	// with a shell on the hub can write the row by hand. What it is, is a floor
	// under the product's own honesty: the broker exists to replace the
	// forever-credential, and an approval path that could mint a ten-year grant
	// in one click would put the thing back exactly where it was found. Ninety
	// days matches the ceiling the Secrets panel already enforces on
	// hand-minted grants, so the two doors cannot disagree.
	MaxDelegationTTL = 90 * 24 * time.Hour

	// MaxJustificationBytes bounds the free text a request carries. Long enough
	// for a paragraph and a ticket link; short enough that the field cannot be
	// used to stuff the control-plane database.
	MaxJustificationBytes = 4096
)

// AccessRequest is one developer's ask, and its decision.
//
// There is no payload field and nowhere one could go: a request names a secret
// that already exists. The credential itself never touches this type, which is
// what makes an AccessRequest safe to render into a review panel, a CLI table
// and an audit payload without any of them having to redact it.
type AccessRequest struct {
	ID string `json:"id"`
	// RequestedBy is the identity that asked — an OIDC subject, a service
	// account, or "cli:<user>". It is the value ApproveRequest compares against
	// the decider, so it must identify a person and not a role.
	RequestedBy string `json:"requested_by"`

	SecretID   string `json:"secret_id"`
	SecretName string `json:"secret_name,omitempty"`
	Kind       Kind   `json:"kind,omitempty"`

	// Subject and Constraints are the grant this request is asking to have
	// created. They are replayed verbatim on approval.
	Subject     Subject     `json:"subject"`
	Constraints Constraints `json:"constraints"`
	Scope       string      `json:"scope,omitempty"`

	// TTL is the grant lifetime asked for. What was actually issued is
	// GrantExpiresAt minus DecidedAt, which will be shorter whenever the
	// approver or their delegation clamped it — and a reviewer comparing the
	// two is exactly how "did anyone actually narrow this" gets answered.
	TTL time.Duration `json:"ttl"`

	// Justification is why. Required, because a request with no stated reason
	// cannot be evaluated, only rubber-stamped.
	Justification string `json:"justification"`

	State     RequestState `json:"state"`
	CreatedAt time.Time    `json:"created_at"`
	// ExpiresAt is when this *request* lapses undecided. Never the credential's
	// expiry — that is GrantExpiresAt.
	ExpiresAt time.Time `json:"expires_at"`

	DecidedBy    string    `json:"decided_by,omitempty"`
	DecidedAt    time.Time `json:"decided_at,omitempty"`
	DecisionNote string    `json:"decision_note,omitempty"`

	// GrantID is the grant an approval minted, and empty in every other state.
	GrantID        string    `json:"grant_id,omitempty"`
	GrantExpiresAt time.Time `json:"grant_expires_at,omitempty"`
}

// Pending reports whether the request is still awaiting a decision at now,
// treating a lapsed deadline as not pending even before a sweep has moved it.
//
// The clock is consulted rather than the state alone so that a decision path
// cannot act on a request the next sweep is about to expire. Without it, whether
// a stale request could still be approved would depend on how recently the
// janitor happened to run.
func (r AccessRequest) Pending(now time.Time) bool {
	if r.State != RequestPending {
		return false
	}
	return r.ExpiresAt.IsZero() || now.Before(r.ExpiresAt)
}

// RequestUse is one lease that redeemed the grant an approval produced.
//
// It answers the question an approver actually has a week later — not "does this
// grant exist", which they know, but "did anything use it, and for what". A
// grant nothing ever redeemed and a grant feeding a workload around the clock
// are indistinguishable from broker_grants alone.
type RequestUse struct {
	RequestID  string `json:"request_id"`
	LeaseID    string `json:"lease_id"`
	GrantID    string `json:"grant_id,omitempty"`
	ExecutorID string `json:"executor_id,omitempty"`
	ProjectID  string `json:"project_id,omitempty"`
	// TaskID is the unit of work that held the lease, or 0 when the lease was
	// issued for a whole project run rather than one task.
	//
	// Zero at the moment the lease is issued and filled in afterwards: the hub
	// leases credentials *before* it dispatches the workload that will hold
	// them, so at lease time there is genuinely no task to name. See
	// statedb.AttributeRequestUseTasks.
	TaskID    int       `json:"task_id,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// RequestStore is the persistence a broker needs to serve requests.
//
// Optional, and detected by type assertion in the same shape as KeyStore: the
// core Store contract is implemented by test doubles and by anything embedding
// the broker, and widening it would break every one of them to add a feature
// most do not need. A broker over a store that does not implement it refuses
// request operations with ErrRequestsUnsupported rather than silently
// pretending to record them.
type RequestStore interface {
	// PutAccessRequest inserts or replaces a request by ID.
	PutAccessRequest(r AccessRequest) error
	// GetAccessRequest returns one request, or a wrapped ErrRequestNotFound.
	GetAccessRequest(id string) (AccessRequest, error)
	// ListAccessRequests returns every request, including decided ones — the
	// broker filters, so a review UI can still see history.
	ListAccessRequests() ([]AccessRequest, error)
	// ExpireAccessRequests moves pending requests past their deadline to
	// expired and returns the ones it changed.
	ExpireAccessRequests(now time.Time) ([]AccessRequest, error)
	// RecordRequestUse notes that a lease redeemed an approved request's
	// grant, upserting on (request, lease).
	RecordRequestUse(u RequestUse) error
	// ListRequestUses returns the uses recorded against one request, or every
	// use when requestID is empty.
	ListRequestUses(requestID string) ([]RequestUse, error)
}

// requests returns the store as a RequestStore, or the reason it is not one.
func (b *Broker) requests() (RequestStore, error) {
	rs, ok := b.store.(RequestStore)
	if !ok {
		return nil, fmt.Errorf("%w: this broker's store does not keep requests", ErrRequestsUnsupported)
	}
	return rs, nil
}

// Delegation bounds what one approver may hand out.
//
// It is a parameter rather than something this package derives, because the
// answer lives in pkg/authz and in the caller's session: the broker knows what a
// grant *is*, not who the person clicking approve is allowed to be. Passing it
// in keeps the authorisation model in one place and still lets the clamp be
// applied at the point the grant is minted, where it cannot be bypassed by a
// caller that forgot to check.
//
// The zero value is the safe one: no wildcard subjects, and the default TTL
// ceiling. A caller that forgets to populate it gets the narrow answer.
type Delegation struct {
	// MaxTTL caps the minted grant's lifetime. Zero means
	// DefaultDelegationMaxTTL.
	MaxTTL time.Duration
	// AllowWildcardSubject permits approving a request aimed at every project,
	// every executor, or every requester.
	//
	// Its own flag rather than a TTL question because the two failure modes are
	// not comparable: a grant that lives too long is bounded by its expiry,
	// while a grant aimed at project:* reaches every tenant on the hub for as
	// long as it lasts. An approver entitled to the first is not automatically
	// entitled to the second.
	AllowWildcardSubject bool
}

// maxTTL resolves the ceiling: the default when unset, and never above
// MaxDelegationTTL however generous the caller's Delegation claims to be.
//
// Clamping a caller-supplied ceiling here rather than trusting it means the
// product-wide maximum holds even for a call site that computed its Delegation
// wrongly — which is the failure this function is cheap insurance against.
func (d Delegation) maxTTL() time.Duration {
	if d.MaxTTL <= 0 {
		return DefaultDelegationMaxTTL
	}
	if d.MaxTTL > MaxDelegationTTL {
		return MaxDelegationTTL
	}
	return d.MaxTTL
}

// AccessRequestInput is what a requester supplies.
type AccessRequestInput struct {
	// SecretRef is a secret ID or name. The secret must already exist: a
	// request asks for access to a credential an operator stored, never for one
	// to be created, because creating one means supplying material and a
	// requester by definition does not have it.
	SecretRef     string
	Subject       Subject
	Constraints   Constraints
	Scope         string
	TTL           time.Duration
	Justification string
	// RequestTTL is how long to wait for a decision. Zero means
	// DefaultRequestTTL.
	RequestTTL time.Duration
	// Actor is the requesting identity. Required: an anonymous request cannot
	// be approved, because the self-approval check has nothing to compare.
	Actor string
}

// RequestAccess files a request for a grant that does not exist yet.
//
// The request is validated against the secret's kind at filing time, using the
// same Constraints.ValidateFor that Grant uses. That is deliberate: an ask that
// could never be approved — a github request with no repository allowlist —
// should fail in front of the person who can fix it, not days later in front of
// the approver, who would then have to guess what was meant.
func (b *Broker) RequestAccess(ctx context.Context, in AccessRequestInput) (AccessRequest, error) {
	if err := ctx.Err(); err != nil {
		return AccessRequest{}, err
	}
	ev := Event{
		Action:      ActionRequestOpen,
		Actor:       in.Actor,
		Subject:     in.Subject.String(),
		Constraints: in.Constraints.Summary(),
	}

	store, err := b.requests()
	if err != nil {
		return AccessRequest{}, b.denyErr(ev, err)
	}
	if strings.TrimSpace(in.Actor) == "" {
		return AccessRequest{}, b.denyf(ev, ErrInvalidRequest,
			"a request must name who is asking: an anonymous request cannot be approved, "+
				"because there is nobody to refuse self-approval against")
	}
	justification := strings.TrimSpace(in.Justification)
	if justification == "" {
		return AccessRequest{}, b.denyf(ev, ErrInvalidRequest,
			"a justification is required: a request with no stated reason cannot be "+
				"evaluated, only rubber-stamped")
	}
	if len(justification) > MaxJustificationBytes {
		return AccessRequest{}, b.denyf(ev, ErrInvalidRequest,
			"justification is %d bytes; the maximum is %d", len(justification), MaxJustificationBytes)
	}
	if err := in.Subject.Validate(); err != nil {
		return AccessRequest{}, b.denyErr(ev, err)
	}

	s, err := resolveSecret(b.store, in.SecretRef)
	if err != nil {
		return AccessRequest{}, b.denyf(ev, ErrSecretNotFound,
			"resolve %q: %v", SafeRef(in.SecretRef), err)
	}
	ev.SecretID, ev.SecretName, ev.Kind = s.ID, s.Name, s.Kind

	// The same validation the grant path applies, applied now. See the doc
	// comment: an unapprovable ask should fail in front of its author.
	if err := in.Constraints.ValidateFor(s.Kind); err != nil {
		return AccessRequest{}, b.denyErr(ev, err)
	}

	ttl := in.TTL
	if ttl <= 0 {
		ttl = DefaultGrantTTL
	}
	requestTTL := in.RequestTTL
	if requestTTL <= 0 {
		requestTTL = DefaultRequestTTL
	}
	if requestTTL > MaxRequestTTL {
		requestTTL = MaxRequestTTL
	}

	id, err := newID("req")
	if err != nil {
		return AccessRequest{}, err
	}
	now := b.now()
	req := AccessRequest{
		ID:            id,
		RequestedBy:   strings.TrimSpace(in.Actor),
		SecretID:      s.ID,
		SecretName:    s.Name,
		Kind:          s.Kind,
		Subject:       in.Subject,
		Constraints:   in.Constraints,
		Scope:         strings.TrimSpace(in.Scope),
		TTL:           ttl,
		Justification: justification,
		State:         RequestPending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(requestTTL),
	}
	if err := store.PutAccessRequest(req); err != nil {
		return AccessRequest{}, b.denyf(ev, ErrInvalidRequest, "store request: %v", err)
	}

	ev.RequestID = req.ID
	ev.ExpiresAt = req.ExpiresAt
	ev.Decision = DecisionAllow
	ev.Reason = "requested " + ttl.String() + ": " + justification
	b.emit(ev)
	return req, nil
}

// RequestFilter narrows ListRequests.
type RequestFilter struct {
	// State, when set, keeps only requests in that state.
	State RequestState
	// RequestedBy, when set, keeps only that identity's requests. This is what
	// scopes the list for a caller who may file requests but not decide them.
	RequestedBy string
	// SecretRef, when set, keeps only requests for that secret.
	SecretRef string
	// PendingOnly keeps only requests still awaiting a decision, including
	// dropping ones whose deadline has passed but which no sweep has moved yet.
	PendingOnly bool
}

// ListRequests returns requests matching the filter, newest first.
func (b *Broker) ListRequests(f RequestFilter) ([]AccessRequest, error) {
	store, err := b.requests()
	if err != nil {
		return nil, err
	}
	all, err := store.ListAccessRequests()
	if err != nil {
		return nil, err
	}
	var secretID string
	if strings.TrimSpace(f.SecretRef) != "" {
		s, serr := resolveSecret(b.store, f.SecretRef)
		if serr != nil {
			return nil, serr
		}
		secretID = s.ID
	}

	now := b.now()
	out := all[:0:0]
	for _, r := range all {
		if f.State != "" && r.State != f.State {
			continue
		}
		if f.RequestedBy != "" && !sameIdentity(r.RequestedBy, f.RequestedBy) {
			continue
		}
		if secretID != "" && r.SecretID != secretID {
			continue
		}
		if f.PendingOnly && !r.Pending(now) {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// GetRequest returns one request by ID.
func (b *Broker) GetRequest(id string) (AccessRequest, error) {
	store, err := b.requests()
	if err != nil {
		return AccessRequest{}, err
	}
	return store.GetAccessRequest(strings.TrimSpace(id))
}

// WithdrawRequest lets the requester take back a pending ask.
//
// Only the requester may withdraw, and the check is here rather than at the
// route: "withdraw" and "deny" are different words for different acts, and an
// approver who wants a request gone says no to it, on the record, with a note.
// Letting an approver withdraw would give them a way to make a request they did
// not want to answer disappear without ever appearing as a refusal.
func (b *Broker) WithdrawRequest(ctx context.Context, id, actor string) (AccessRequest, error) {
	if err := ctx.Err(); err != nil {
		return AccessRequest{}, err
	}
	ev := Event{Action: ActionRequestWithdraw, Actor: actor, RequestID: id}

	store, err := b.requests()
	if err != nil {
		return AccessRequest{}, b.denyErr(ev, err)
	}
	req, err := store.GetAccessRequest(strings.TrimSpace(id))
	if err != nil {
		return AccessRequest{}, b.denyf(ev, ErrRequestNotFound, "request %q: %v", id, err)
	}
	ev.SecretID, ev.SecretName, ev.Kind = req.SecretID, req.SecretName, req.Kind
	ev.Subject = req.Subject.String()

	if !sameIdentity(req.RequestedBy, actor) {
		return AccessRequest{}, b.denyf(ev, ErrNotRequester,
			"only %s may withdraw this request; an approver refuses it instead, which is "+
				"recorded as a denial", req.RequestedBy)
	}
	if req.State != RequestPending {
		return AccessRequest{}, b.denyf(ev, ErrRequestNotPending,
			"request is already %s", req.State)
	}

	req.State = RequestWithdrawn
	req.DecidedBy = strings.TrimSpace(actor)
	req.DecidedAt = b.now()
	if err := store.PutAccessRequest(req); err != nil {
		return AccessRequest{}, b.denyf(ev, ErrInvalidRequest, "store request: %v", err)
	}

	ev.Decision = DecisionAllow
	ev.Reason = "withdrawn by the requester"
	b.emit(ev)
	return req, nil
}

// DecideInput is what an approver supplies. Shared by ApproveRequest and
// DenyRequest so the two cannot drift apart on identity or note handling.
type DecideInput struct {
	RequestID string
	// Actor is the deciding identity, compared against the requester to refuse
	// self-approval.
	Actor string
	// Note is the approver's comment. Required on a denial — a refusal with no
	// reason is one the requester can only respond to by asking again — and
	// optional on an approval.
	Note string
	// TTL, when positive, shortens the minted grant. It can only ever narrow:
	// a value above what was requested, or above the delegation ceiling, is
	// clamped rather than honoured.
	TTL time.Duration
	// Delegation is the ceiling this approver may hand out.
	Delegation Delegation
}

// ApproveRequest mints the grant a request asked for.
//
// The grant is created by calling Broker.Grant — the same entry point the CLI
// and the REST panel use — rather than by writing a Grant struct here. That is
// the single most important line in this file: Grant is where a grant's
// constraints are validated against its secret's kind, where the audit row for a
// creation is emitted, and where any future check will be added. A second
// minting path would be a second place for that logic to be missing.
//
// What this function adds on top is the two-person rule, the delegation clamp,
// and the record linking the grant back to the ask.
func (b *Broker) ApproveRequest(ctx context.Context, in DecideInput) (AccessRequest, Grant, error) {
	if err := ctx.Err(); err != nil {
		return AccessRequest{}, Grant{}, err
	}
	ev := Event{Action: ActionRequestApprove, Actor: in.Actor, RequestID: in.RequestID}

	store, err := b.requests()
	if err != nil {
		return AccessRequest{}, Grant{}, b.denyErr(ev, err)
	}
	req, err := store.GetAccessRequest(strings.TrimSpace(in.RequestID))
	if err != nil {
		return AccessRequest{}, Grant{}, b.denyf(ev, ErrRequestNotFound,
			"request %q: %v", in.RequestID, err)
	}
	ev.SecretID, ev.SecretName, ev.Kind = req.SecretID, req.SecretName, req.Kind
	ev.Subject = req.Subject.String()
	ev.Constraints = req.Constraints.Summary()

	now := b.now()
	if err := b.checkDecidable(ev, req, in.Actor, now); err != nil {
		return AccessRequest{}, Grant{}, err
	}

	// Scope ceiling. A wildcard subject reaches every tenant on the hub for as
	// long as the grant lasts, so it is refused unless this approver is
	// entitled to delegate that far — checked before the TTL clamp, because a
	// shorter lifetime does not make a fleet-wide grant narrower.
	if isWildcardSubject(req.Subject) && !in.Delegation.AllowWildcardSubject {
		return AccessRequest{}, Grant{}, b.denyf(ev, ErrDelegationExceeded,
			"this request is aimed at %s, which reaches every project or executor on "+
				"this hub; you are not entitled to delegate that far. Deny it and ask "+
				"for a request scoped to one project", req.Subject.String())
	}

	ttl, clamped := clampGrantTTL(req.TTL, in.TTL, in.Delegation.maxTTL())

	grant, err := b.Grant(ctx, GrantRequest{
		SecretRef:   req.SecretID,
		Subject:     req.Subject,
		Constraints: req.Constraints,
		Scope:       req.Scope,
		TTL:         ttl,
		// The grant is attributed to the approver, not the requester. They are
		// the one who exercised the authority; the requester is recorded on the
		// request this grant points back to.
		Actor: strings.TrimSpace(in.Actor),
	})
	if err != nil {
		// Grant has already emitted its own denial with the underlying reason.
		// This second row says the *approval* failed, which is the one the
		// requester is waiting on.
		return AccessRequest{}, Grant{}, b.denyf(ev, ErrInvalidRequest,
			"mint the grant this request asked for: %v", err)
	}

	req.State = RequestApproved
	req.DecidedBy = strings.TrimSpace(in.Actor)
	req.DecidedAt = now
	req.DecisionNote = strings.TrimSpace(in.Note)
	req.GrantID = grant.ID
	req.GrantExpiresAt = grant.ExpiresAt
	if err := store.PutAccessRequest(req); err != nil {
		// The grant exists and the request does not say so. Revoking it is the
		// only outcome that leaves the two consistent: a live credential no
		// record points at is precisely what this feature exists to stop, and
		// an approver can always approve again.
		if rerr := b.Revoke(ctx, grant.ID, strings.TrimSpace(in.Actor)); rerr != nil {
			return AccessRequest{}, Grant{}, b.denyf(ev, ErrInvalidRequest,
				"recording the approval failed (%v) and the grant it minted could not be "+
					"revoked (%v): grant %s is live and unrecorded — revoke it by hand",
				err, rerr, grant.ID)
		}
		return AccessRequest{}, Grant{}, b.denyf(ev, ErrInvalidRequest,
			"record the approval: %v (the grant it minted was revoked, so nothing is live)", err)
	}

	ev.GrantID = grant.ID
	ev.ExpiresAt = grant.ExpiresAt
	ev.Decision = DecisionAllow
	ev.Reason = approvalReason(req, ttl, clamped)
	b.emit(ev)
	return req, grant, nil
}

// DenyRequest refuses a request, on the record.
func (b *Broker) DenyRequest(ctx context.Context, in DecideInput) (AccessRequest, error) {
	if err := ctx.Err(); err != nil {
		return AccessRequest{}, err
	}
	ev := Event{Action: ActionRequestDeny, Actor: in.Actor, RequestID: in.RequestID}

	store, err := b.requests()
	if err != nil {
		return AccessRequest{}, b.denyErr(ev, err)
	}
	req, err := store.GetAccessRequest(strings.TrimSpace(in.RequestID))
	if err != nil {
		return AccessRequest{}, b.denyf(ev, ErrRequestNotFound, "request %q: %v", in.RequestID, err)
	}
	ev.SecretID, ev.SecretName, ev.Kind = req.SecretID, req.SecretName, req.Kind
	ev.Subject = req.Subject.String()

	if err := b.checkDecidable(ev, req, in.Actor, b.now()); err != nil {
		return AccessRequest{}, err
	}
	note := strings.TrimSpace(in.Note)
	if note == "" {
		return AccessRequest{}, b.denyf(ev, ErrInvalidRequest,
			"a denial needs a reason: without one the requester can only respond by "+
				"asking again")
	}
	if len(note) > MaxJustificationBytes {
		return AccessRequest{}, b.denyf(ev, ErrInvalidRequest,
			"note is %d bytes; the maximum is %d", len(note), MaxJustificationBytes)
	}

	req.State = RequestDenied
	req.DecidedBy = strings.TrimSpace(in.Actor)
	req.DecidedAt = b.now()
	req.DecisionNote = note
	if err := store.PutAccessRequest(req); err != nil {
		return AccessRequest{}, b.denyf(ev, ErrInvalidRequest, "store request: %v", err)
	}

	// DecisionAllow: the *operation* succeeded. The audit trail's decision field
	// says whether the brokered action was carried out, not whether the answer
	// was yes — a denial recorded as DecisionDeny would be indistinguishable
	// from an approver who was refused the right to decide at all.
	ev.Decision = DecisionAllow
	ev.Reason = "denied: " + note
	b.emit(ev)
	return req, nil
}

// checkDecidable applies the rules common to approving and denying: the request
// must still be open, and the decider must not be the requester.
func (b *Broker) checkDecidable(ev Event, req AccessRequest, actor string, now time.Time) error {
	if strings.TrimSpace(actor) == "" {
		return b.denyf(ev, ErrInvalidRequest, "a decision must name who made it")
	}
	if sameIdentity(req.RequestedBy, actor) {
		return b.denyf(ev, ErrSelfApproval,
			"%s filed this request and cannot decide it: the point of the request path "+
				"is that a second person looks at the scope", req.RequestedBy)
	}
	if req.State != RequestPending {
		return b.denyf(ev, ErrRequestNotPending, "request is already %s", req.State)
	}
	if !req.ExpiresAt.IsZero() && !now.Before(req.ExpiresAt) {
		// Refused even though no sweep has moved the row yet, so that whether a
		// stale request can still be approved does not depend on how recently
		// the janitor ran.
		return b.denyf(ev, ErrRequestExpired,
			"request lapsed at %s undecided; ask the requester to file it again so the "+
				"justification is current", req.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// ExpireRequests moves pending requests past their deadline to expired and
// emits one audit event for each.
//
// An event per expiry rather than a summary count, because a lapsed request is
// an outcome the requester is owed: from their side, an expiry and an approval
// nobody told them about look identical until they try to use the credential.
func (b *Broker) ExpireRequests(ctx context.Context) ([]AccessRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, err := b.requests()
	if err != nil {
		return nil, err
	}
	lapsed, err := store.ExpireAccessRequests(b.now())
	if err != nil {
		return nil, err
	}
	for _, req := range lapsed {
		b.emit(Event{
			Action:      ActionRequestExpire,
			Actor:       "secretbroker",
			RequestID:   req.ID,
			SecretID:    req.SecretID,
			SecretName:  req.SecretName,
			Kind:        req.Kind,
			Subject:     req.Subject.String(),
			Constraints: req.Constraints.Summary(),
			ExpiresAt:   req.ExpiresAt,
			Decision:    DecisionAllow,
			Reason: "request from " + req.RequestedBy + " lapsed undecided after " +
				req.ExpiresAt.Sub(req.CreatedAt).String(),
		})
	}
	return lapsed, nil
}

// RequestUses returns what an approval actually produced: every lease that
// redeemed the grant, and the task that held it where one is known.
func (b *Broker) RequestUses(requestID string) ([]RequestUse, error) {
	store, err := b.requests()
	if err != nil {
		return nil, err
	}
	return store.ListRequestUses(strings.TrimSpace(requestID))
}

// recordGrantUse notes that a lease materialised a grant, when that grant came
// from an approved request.
//
// Called from LeaseFor for every material it delivers. Best-effort and silent:
// this is bookkeeping for a review panel, and a write failure here must not deny
// an executor credentials it is entitled to. The audit trail records the lease
// either way, so the information is not lost, only less convenient.
func (b *Broker) recordGrantUse(grantID, leaseID string, r Requester, now time.Time) {
	store, ok := b.store.(RequestStore)
	if !ok || grantID == "" || leaseID == "" {
		return
	}
	all, err := store.ListAccessRequests()
	if err != nil {
		return
	}
	for _, req := range all {
		if req.State != RequestApproved || req.GrantID != grantID {
			continue
		}
		_ = store.RecordRequestUse(RequestUse{
			RequestID:  req.ID,
			LeaseID:    leaseID,
			GrantID:    grantID,
			ExecutorID: r.ExecutorID,
			ProjectID:  r.ProjectID,
			FirstSeen:  now,
			LastSeen:   now,
		})
		return
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// clampGrantTTL resolves the minted lifetime from what was asked, what the
// approver typed, and what they are entitled to delegate, and reports whether
// the result is shorter than the ask.
//
// Every input can only narrow. An approver typing a longer TTL than the request
// asked for does not get it — they would be granting something nobody asked for
// and the requester never justified.
func clampGrantTTL(requested, approver, ceiling time.Duration) (time.Duration, bool) {
	ttl := requested
	if ttl <= 0 {
		ttl = DefaultGrantTTL
	}
	if approver > 0 && approver < ttl {
		ttl = approver
	}
	if ceiling > 0 && ceiling < ttl {
		ttl = ceiling
	}
	return ttl, ttl < requested
}

// approvalReason renders the audit annotation for an approval, saying plainly
// whether the ask was narrowed.
func approvalReason(req AccessRequest, ttl time.Duration, clamped bool) string {
	if clamped {
		return fmt.Sprintf("approved for %s (requested %s, clamped): %s",
			ttl, req.TTL, req.Justification)
	}
	return fmt.Sprintf("approved for %s: %s", ttl, req.Justification)
}

// isWildcardSubject reports whether a subject reaches beyond one named project
// or executor.
func isWildcardSubject(s Subject) bool {
	switch s.Type {
	case SubjectAny:
		return true
	case SubjectProject, SubjectExecutor:
		return s.Value == "*"
	case SubjectLabel:
		// A label selector names a fleet by property rather than by id, which is
		// how a whole class of edge devices is addressed. Treated as wildcard
		// for the ceiling: the set it selects is open-ended and can grow after
		// the approval, when a device is enrolled carrying the label.
		return true
	}
	return false
}

// sameIdentity compares two actor strings for the self-approval and
// withdrawal checks.
//
// Case-insensitive after trimming, because the same person arrives as an OIDC
// subject in one path and an email in another and the casing of an email is not
// significant. It is deliberately *not* fuzzy beyond that: a prefix or substring
// match would let "alice" and "alice-ci" be confused, and the direction of that
// error is a two-person rule silently becoming a one-person rule.
func sameIdentity(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(a, b)
}
