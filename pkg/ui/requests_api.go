package ui

// The Access Requests panel's backend (Task 20271).
//
// pkg/secretbroker brokered credentials in one direction only: Mint and Grant
// were gated on authz.PermSecretGrant and there was no other door. A developer
// who needed a repository or a Kubernetes cluster had to ask in a chat window
// and wait for somebody to hand-mint a grant — which is not merely slow, it is
// the mechanism by which over-broad standing grants get made. The person minting
// is reconstructing a scope from a sentence, under interruption, and a wider
// guess is always cheaper than a wrong narrow one.
//
// These six endpoints give the ask a home:
//
//	GET  /api/grant-requests                  the queue
//	POST /api/grant-requests                  file one
//	POST /api/grant-requests/{id}/withdraw    take one back
//	POST /api/grant-requests/{id}/approve     mint the grant it asked for
//	POST /api/grant-requests/{id}/deny        refuse, with a reason
//	GET  /api/grant-requests/{id}/uses        what the approval actually did
//
// # Permissions, and why they are not all the same
//
// Filing, listing and withdrawing take authz.PermSecretRequest, which sits at
// operator. Approving and denying take authz.PermSecretGrant, at maintainer.
// That split is the feature: asking confers nothing — a request is a row with a
// justification on it — while approving mints a real credential.
//
// Two consequences the route table cannot express, handled here:
//
// A caller who may ask but not approve sees only their own requests. The list is
// otherwise reconnaissance: which credentials exist, who has been asking for
// what, and which projects are worth aiming at. Scoping is applied to the
// response rather than trusted from a query parameter, so a caller cannot widen
// it by editing the URL.
//
// A caller who may approve still cannot approve their own request. That is
// enforced in the broker rather than here, because it must hold for the CLI path
// too — and because on a small team the requester very often holds
// PermSecretGrant, which is exactly when a two-person rule that lives in one
// handler stops existing.
//
// # The non-disclosure invariant
//
// Like secrets_api.go, no response built here may contain secret material. It is
// structural rather than reviewed: secretbroker.AccessRequest has no payload
// field and no place one could go — a request names a secret that already
// exists — so there is nothing to redact on the way out.

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// requestTTLMaxMinutes bounds how long a request may wait for a decision,
// mirroring secretbroker.MaxRequestTTL so the panel refuses in front of the user
// rather than having the broker silently clamp.
const requestTTLMaxMinutes = 30 * 24 * 60

// ---------------------------------------------------------------------------
// wire types
// ---------------------------------------------------------------------------

// requestView is one row of GET /api/grant-requests.
type requestView struct {
	ID          string `json:"id"`
	RequestedBy string `json:"requested_by"`
	SecretID    string `json:"secret_id"`
	SecretName  string `json:"secret_name,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Subject     string `json:"subject"`
	Constraints string `json:"constraints,omitempty"`
	Scope       string `json:"scope,omitempty"`
	// TTLMinutes is the grant lifetime asked for; GrantExpiresAt is what was
	// actually issued. A panel showing both is how a reviewer sees that an
	// approver narrowed an ask rather than waved it through.
	TTLMinutes    int    `json:"ttl_minutes"`
	Justification string `json:"justification"`

	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// ExpiresInSeconds counts down to the decision deadline; negative once it
	// has passed but before a sweep has moved the row.
	ExpiresInSeconds int64 `json:"expires_in_seconds,omitempty"`

	DecidedBy      string    `json:"decided_by,omitempty"`
	DecidedAt      time.Time `json:"decided_at,omitempty"`
	DecisionNote   string    `json:"decision_note,omitempty"`
	GrantID        string    `json:"grant_id,omitempty"`
	GrantExpiresAt time.Time `json:"grant_expires_at,omitempty"`

	// Mine and Decidable let the panel render the right buttons without
	// re-deriving the rules. Decidable is false for one's own request even when
	// the caller holds PermSecretGrant, which is the whole two-person point and
	// would otherwise show an approve button that always fails.
	Mine      bool `json:"mine"`
	Decidable bool `json:"decidable"`
}

// requestUseView is one row of GET /api/grant-requests/{id}/uses.
type requestUseView struct {
	LeaseID    string `json:"lease_id"`
	GrantID    string `json:"grant_id,omitempty"`
	ExecutorID string `json:"executor_id,omitempty"`
	ProjectID  string `json:"project_id,omitempty"`
	// TaskID is the unit of work that held the lease, or 0 when the lease was
	// issued for a whole project run. Attributed is the honest discriminator:
	// zero means "not attributed", never "no task ran".
	TaskID     int       `json:"task_id,omitempty"`
	Attributed bool      `json:"attributed"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// createRequestBody is POST /api/grant-requests.
type createRequestBody struct {
	SecretRef     string `json:"secret_ref"`
	Subject       string `json:"subject"`
	Scope         string `json:"scope,omitempty"`
	TTLMinutes    int    `json:"ttl_minutes"`
	WaitMinutes   int    `json:"wait_minutes,omitempty"`
	Justification string `json:"justification"`

	Repos       []string `json:"repos,omitempty"`
	Devices     []string `json:"devices,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Namespaces  []string `json:"namespaces,omitempty"`
	Contexts    []string `json:"contexts,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	Registries  []string `json:"registries,omitempty"`
	EnvKeys     []string `json:"env_keys,omitempty"`
	Writable    bool     `json:"writable,omitempty"`
}

// decideRequestBody is POST /api/grant-requests/{id}/{approve,deny}.
type decideRequestBody struct {
	Note string `json:"note,omitempty"`
	// TTLMinutes, when positive, shortens the minted grant. It can only narrow:
	// the broker clamps anything above the request's own ask or above the
	// approver's ceiling, so a larger number here is not an escalation, it is
	// simply ignored.
	TTLMinutes int `json:"ttl_minutes,omitempty"`
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// handleGrantRequestsList serves GET /api/grant-requests.
//
// Query parameters: ?state=pending|approved|denied|withdrawn|expired and
// ?mine=1. Neither can widen the response — a caller without PermSecretGrant is
// narrowed to their own requests regardless of what they ask for.
func (s *Server) handleGrantRequestsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierror.WriteError(w, apierror.New(apierror.CodeMethodNotAllowed, "GET required"))
		return
	}
	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()
	if !bs.requireSecretBroker(w) {
		return
	}

	actor := s.auditActor(r)
	canDecide := s.permissionsFor(r, authz.GlobalScope).Allows(authz.PermSecretGrant)

	filter := secretbroker.RequestFilter{}
	if state := strings.TrimSpace(r.URL.Query().Get("state")); state != "" {
		st := secretbroker.RequestState(strings.ToLower(state))
		if !st.Valid() {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
				"unknown state "+state))
			return
		}
		filter.State = st
	}
	// The narrowing, applied after the caller's own filter so that asking for
	// somebody else's requests without the permission to see them yields your
	// own rather than an error — the panel has no reason to learn that other
	// requesters exist.
	if !canDecide || isTruthyParam(r.URL.Query().Get("mine")) {
		filter.RequestedBy = actor
	}

	requests, err := bs.secret.ListRequests(filter)
	if err != nil {
		writeBrokerError(w, err, "list access requests")
		return
	}

	now := time.Now()
	views := make([]requestView, 0, len(requests))
	pending := 0
	for _, req := range requests {
		views = append(views, requestViewOf(req, actor, canDecide, now))
		if req.Pending(now) {
			pending++
		}
	}
	jsonOK(w, map[string]any{
		"requests": views,
		// pending_count is the queue depth the header badge shows. Counted over
		// the same filtered set the caller received, so it can never hint at
		// requests they were not shown.
		"pending_count": pending,
		"can_decide":    canDecide,
		"actor":         actor,
	})
}

// handleGrantRequestCreate serves POST /api/grant-requests: file an ask.
func (s *Server) handleGrantRequestCreate(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var body createRequestBody
	if !decodeSecretsBody(w, r, &body) {
		return
	}
	subject, err := secretbroker.ParseSubject(body.Subject)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	ttl, err := grantTTL(body.TTLMinutes)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	if body.WaitMinutes < 0 || body.WaitMinutes > requestTTLMaxMinutes {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"wait_minutes must be between 0 and "+strconv.Itoa(requestTTLMaxMinutes)))
		return
	}

	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()
	if !bs.requireSecretBroker(w) {
		return
	}

	actor := s.auditActor(r)
	// Constraints go to the broker unchecked for the same reason the grant path
	// hands them over unchecked: RequestAccess calls Constraints.ValidateFor,
	// which is the single definition of "does this allowlist actually gate this
	// kind of credential". A second copy here could only drift.
	req, err := bs.secret.RequestAccess(r.Context(), secretbroker.AccessRequestInput{
		SecretRef:     strings.TrimSpace(body.SecretRef),
		Subject:       subject,
		Scope:         strings.TrimSpace(body.Scope),
		TTL:           ttl,
		RequestTTL:    time.Duration(body.WaitMinutes) * time.Minute,
		Justification: body.Justification,
		Actor:         actor,
		Constraints: secretbroker.Constraints{
			Repos:       cleanList(body.Repos),
			Devices:     cleanList(body.Devices),
			Permissions: cleanList(body.Permissions),
			Namespaces:  cleanList(body.Namespaces),
			Contexts:    cleanList(body.Contexts),
			Hosts:       cleanList(body.Hosts),
			Registries:  cleanList(body.Registries),
			EnvKeys:     cleanList(body.EnvKeys),
			Writable:    body.Writable,
		},
	})
	if err != nil {
		writeBrokerError(w, err, "file access request")
		return
	}

	s.broadcastAuditAppend(string(secretbroker.ActionRequestOpen))
	s.broadcastSecretsUpdate("request_created", req.ID)
	jsonOK(w, requestViewOf(req, actor, false, time.Now()))
}

// handleGrantRequestWithdraw serves POST /api/grant-requests/{id}/withdraw.
//
// Gated on PermSecretRequest, not PermSecretGrant: withdrawing is the
// requester's own act. That only one person may do it is the broker's rule —
// see WithdrawRequest — and it is there rather than here so the CLI cannot
// diverge from it.
func (s *Server) handleGrantRequestWithdraw(w http.ResponseWriter, r *http.Request) {
	s.decideGrantRequest(w, r, requestActionWithdraw)
}

// handleGrantRequestApprove serves POST /api/grant-requests/{id}/approve.
func (s *Server) handleGrantRequestApprove(w http.ResponseWriter, r *http.Request) {
	s.decideGrantRequest(w, r, requestActionApprove)
}

// handleGrantRequestDeny serves POST /api/grant-requests/{id}/deny.
func (s *Server) handleGrantRequestDeny(w http.ResponseWriter, r *http.Request) {
	s.decideGrantRequest(w, r, requestActionDeny)
}

// requestAction names which transition decideGrantRequest is performing.
type requestAction string

const (
	requestActionWithdraw requestAction = "withdraw"
	requestActionApprove  requestAction = "approve"
	requestActionDeny     requestAction = "deny"
)

// decideGrantRequest is the shared body of the three transition handlers.
//
// One function rather than three because the differences are two lines and the
// similarities — id parsing, broker opening, actor resolution, broadcast, error
// mapping — are twenty. Three copies is how one of them ends up without the
// broadcast, or reporting the wrong action into the audit stream.
func (s *Server) decideGrantRequest(w http.ResponseWriter, r *http.Request, action requestAction) {
	if !requirePOST(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "request id is required"))
		return
	}
	var body decideRequestBody
	// An empty body is legitimate for withdraw and approve, so a decode failure
	// is only fatal when there was something to decode.
	if r.ContentLength > 0 && !decodeSecretsBody(w, r, &body) {
		return
	}

	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()
	if !bs.requireSecretBroker(w) {
		return
	}

	actor := s.auditActor(r)
	in := secretbroker.DecideInput{
		RequestID:  id,
		Actor:      actor,
		Note:       body.Note,
		TTL:        time.Duration(body.TTLMinutes) * time.Minute,
		Delegation: s.delegationFor(r),
	}

	var (
		req      secretbroker.AccessRequest
		err      error
		auditAct secretbroker.Action
		// event is the verb the WebSocket envelope carries. Spelled out per
		// branch rather than derived from `action`, because "withdraw"+"d" is
		// not a word and a wire string outlives the convenience that produced it.
		event   string
		payload = map[string]any{"ok": true, "id": id}
	)
	switch action {
	case requestActionWithdraw:
		req, err = bs.secret.WithdrawRequest(r.Context(), id, actor)
		auditAct, event = secretbroker.ActionRequestWithdraw, "request_withdrawn"
	case requestActionDeny:
		req, err = bs.secret.DenyRequest(r.Context(), in)
		auditAct, event = secretbroker.ActionRequestDeny, "request_denied"
	case requestActionApprove:
		var grant secretbroker.Grant
		req, grant, err = bs.secret.ApproveRequest(r.Context(), in)
		auditAct, event = secretbroker.ActionRequestApprove, "request_approved"
		if err == nil {
			payload["grant_id"] = grant.ID
			// The same honest caveat the grant panel carries: an approval mints
			// authority, and authority takes effect at the next lease.
			payload["note"] = "The grant is live. An executor picks it up at its next " +
				"lease, within one lease period."
		}
	}
	if err != nil {
		writeBrokerError(w, err, string(action)+" access request")
		return
	}

	s.broadcastAuditAppend(string(auditAct))
	s.broadcastSecretsUpdate(event, req.ID)
	payload["request"] = requestViewOf(req, actor, true, time.Now())
	jsonOK(w, payload)
}

// handleGrantRequestUses serves GET /api/grant-requests/{id}/uses: the leases
// that actually redeemed an approved request's grant.
//
// This is the endpoint that makes an approval reviewable. broker_grants can say
// a grant exists; only this can say whether anything used it, from where, and
// for how long — which is the number that decides whether the next request from
// the same person should be narrower.
func (s *Server) handleGrantRequestUses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierror.WriteError(w, apierror.New(apierror.CodeMethodNotAllowed, "GET required"))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "request id is required"))
		return
	}
	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()
	if !bs.requireSecretBroker(w) {
		return
	}

	uses, err := bs.secret.RequestUses(id)
	if err != nil {
		writeBrokerError(w, err, "list request uses")
		return
	}
	views := make([]requestUseView, 0, len(uses))
	for _, u := range uses {
		views = append(views, requestUseView{
			LeaseID:    u.LeaseID,
			GrantID:    u.GrantID,
			ExecutorID: u.ExecutorID,
			ProjectID:  u.ProjectID,
			TaskID:     u.TaskID,
			Attributed: u.TaskID != 0,
			FirstSeen:  u.FirstSeen,
			LastSeen:   u.LastSeen,
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].FirstSeen.Before(views[j].FirstSeen) })
	jsonOK(w, map[string]any{"id": id, "uses": views})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// delegationFor computes the ceiling this caller may hand out.
//
// The broker deliberately does not derive this — it knows what a grant is, not
// who the person clicking approve is — so the mapping from role to ceiling lives
// here, once, and is passed down to be enforced at the point of minting.
//
// Two tiers, and the distinction is not lifetime but reach:
//
//	admin       may delegate fleet-wide (project:*, executor:*, a label
//	            selector) and up to the panel's own 90-day grant ceiling.
//	maintainer  may approve requests aimed at one named project or executor,
//	            for up to a week.
//
// A maintainer is the role that brokers credentials day to day, and capping them
// at a named subject is what stops "approve" becoming a one-click route to a
// credential that reaches every tenant on the hub. They can still mint such a
// grant deliberately through POST /api/grants, which is a different act with a
// different audit row — the point is that it cannot happen by approving
// somebody else's ask without reading it.
func (s *Server) delegationFor(r *http.Request) secretbroker.Delegation {
	d := s.permissionsFor(r, authz.GlobalScope)
	if d.Role == authz.RoleAdmin {
		return secretbroker.Delegation{
			MaxTTL:               time.Duration(secretGrantTTLMaxMinutes) * time.Minute,
			AllowWildcardSubject: true,
		}
	}
	return secretbroker.Delegation{MaxTTL: secretbroker.DefaultDelegationMaxTTL}
}

// requestViewOf renders one request for the wire.
func requestViewOf(req secretbroker.AccessRequest, actor string, canDecide bool, now time.Time) requestView {
	v := requestView{
		ID:             req.ID,
		RequestedBy:    req.RequestedBy,
		SecretID:       req.SecretID,
		SecretName:     req.SecretName,
		Kind:           string(req.Kind),
		Subject:        req.Subject.String(),
		Constraints:    req.Constraints.Summary(),
		Scope:          req.Scope,
		TTLMinutes:     int(req.TTL / time.Minute),
		Justification:  req.Justification,
		State:          string(req.State),
		CreatedAt:      req.CreatedAt,
		ExpiresAt:      req.ExpiresAt,
		DecidedBy:      req.DecidedBy,
		DecidedAt:      req.DecidedAt,
		DecisionNote:   req.DecisionNote,
		GrantID:        req.GrantID,
		GrantExpiresAt: req.GrantExpiresAt,
	}
	v.Mine = strings.EqualFold(strings.TrimSpace(req.RequestedBy), strings.TrimSpace(actor)) &&
		strings.TrimSpace(actor) != ""
	// Not decidable by the person who filed it, whatever they hold. Mirrors the
	// broker's refusal so the panel does not offer a button that always fails.
	v.Decidable = canDecide && !v.Mine && req.Pending(now)
	if !req.ExpiresAt.IsZero() {
		v.ExpiresInSeconds = int64(req.ExpiresAt.Sub(now) / time.Second)
	}
	return v
}

// requestBrokerErrorCode maps the request sentinels onto API error codes.
//
// Kept beside writeBrokerError's own table rather than folded into it because
// these are the codes a *client* acts on: 409 tells the panel to re-read because
// somebody else decided first, and 403 on self-approval tells it to stop
// offering the button.
func requestBrokerErrorCode(err error) (apierror.Code, bool) {
	switch {
	case errors.Is(err, secretbroker.ErrRequestNotFound):
		return apierror.CodeNotFound, true
	case errors.Is(err, secretbroker.ErrRequestNotPending),
		errors.Is(err, secretbroker.ErrRequestExpired):
		return apierror.CodeConflict, true
	case errors.Is(err, secretbroker.ErrSelfApproval),
		errors.Is(err, secretbroker.ErrNotRequester),
		errors.Is(err, secretbroker.ErrDelegationExceeded):
		return apierror.CodeForbidden, true
	case errors.Is(err, secretbroker.ErrInvalidRequest):
		return apierror.CodeInvalidInput, true
	case errors.Is(err, secretbroker.ErrRequestsUnsupported):
		return apierror.CodeUnavailable, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// catalogue
// ---------------------------------------------------------------------------

// catalogEntry is one row of GET /api/secrets/catalog: the least a requester
// needs to name a credential.
type catalogEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// handleSecretCatalog serves GET /api/secrets/catalog.
//
// It exists because of a tension the request path creates and cannot avoid. A
// request names a secret, so a requester has to know one exists — and
// GET /api/secrets is deliberately maintainer-only, on the stated grounds that
// the inventory of which credentials exist, who holds them, and which executor
// they are bound to is reconnaissance. Both of those are right, and together
// they would leave an operator able to file a request only for a name somebody
// told them in a chat window, which is the exact problem this feature exists to
// remove.
//
// The resolution is to publish strictly less. This returns an id, a name and a
// kind, and nothing else. Every field secretView carries that could inform an
// attack is absent by construction rather than by filtering:
//
//	no fingerprint  — it identifies the stored record, and comparing two of
//	                  them is a question a requester has no reason to ask
//	no grant counts — "which credentials are in heavy use" is a target list
//	no metadata     — operator-supplied free text, which is where a rotation
//	                  date, an owner, or an internal hostname ends up
//	no created_at / created_by — who provisioned what, and when
//
// What remains is what a requester must type to ask, and it is bounded by the
// same reasoning that makes `secret.request` an operator permission at all: the
// role that can start runs already spends the credentials this lists.
func (s *Server) handleSecretCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierror.WriteError(w, apierror.New(apierror.CodeMethodNotAllowed, "GET required"))
		return
	}
	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()
	if !bs.requireSecretBroker(w) {
		return
	}

	secrets, err := bs.secret.ListSecrets()
	if err != nil {
		writeBrokerError(w, err, "list secret catalogue")
		return
	}
	out := make([]catalogEntry, 0, len(secrets))
	for _, sec := range secrets {
		out = append(out, catalogEntry{ID: sec.ID, Name: sec.Name, Kind: string(sec.Kind)})
	}
	jsonOK(w, map[string]any{"secrets": out, "kinds": kindNames()})
}
