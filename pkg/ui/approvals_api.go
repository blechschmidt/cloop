package ui

// The approvals inbox (Task 20427): what is waiting on the person asking.
//
//	GET /api/approvals         the items, each with its deadline, and the
//	                           caller's own requests and how they ended
//	GET /api/approvals/count   the number, for the navigation badge
//
// Two decisions wait on an administrator: a self-service grant request (Task
// 20271) and an API token a role policy suspends until it is approved (Task
// 20422). Both were listed only inside panels an approver had to think of
// opening, so a request lapsed after three days unless somebody happened to
// look. The badge asks this route on every change, and the change itself
// arrives as the opaque secrets_update or approvals_update broadcast — an event
// verb and an id, never a row, because the WebSocket fans out to every
// connected client whatever its role.
//
// # What "may decide" means
//
// Exactly what the decision routes enforce, evaluated per item, so the inbox
// never offers what the hub would refuse:
//
//   - A grant request: pending; not filed by the caller (the broker's
//     two-person rule — a requester never sees their own request as theirs to
//     decide); secret.grant hub-wide (the approve route's gate, and the reach
//     requestApprovers names); secret.grant on the request's own subject — a
//     project's scope or an executor's — so a runtime deny on one project
//     withholds that project's requests; and, for a subject that reaches every
//     project or executor or names a label selector, the administrator's
//     delegation (secretbroker.Delegation.AllowWildcardSubject).
//   - An API token: the hub enforces a role policy (without one no token is
//     suspended), the caller holds token.admin, and holds every role the token
//     carries — handleTokenApprove's anti-escalation rule.
//
// A role on one project confers none of it: approving has always taken
// secret.grant across the hub, and a maintainer of project A sees neither A's
// requests nor B's, nor how many there are. A viewer gets zero.
//
// The routes are ungated (authz.PermPublic) for the reason /api/me is: the
// answer is computed from the caller's own authority, and a caller with none
// gets an empty inbox — not a 403 and an audit row on every broadcast, which
// is what gating the badge's own request would produce for every member whose
// only role is on one project. authMiddleware still requires a signed-in caller.

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
)

// approvalsMineWindow is how far back the caller's own decided requests are
// shown: long enough to see the answer to last week's ask.
const approvalsMineWindow = 7 * 24 * time.Hour

// approvalsMineMax bounds the caller's own requests in a response.
const approvalsMineMax = 50

// approvalItem is one thing waiting on the caller.
type approvalItem struct {
	// Kind is grant_request or api_token.
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// Deadline is when the item stops being decidable: a request lapses, a
	// token expires. Empty for a token that never expires.
	Deadline          string `json:"deadline,omitempty"`
	DeadlineInSeconds int64  `json:"deadline_in_seconds,omitempty"`

	// Request is the grant request, as GET /api/grant-requests renders it to
	// someone who may decide it.
	Request *requestView `json:"request,omitempty"`
	// Token is the token awaiting approval: never its hash, never a secret.
	Token *tokenBrief `json:"token,omitempty"`
}

// approvalsView is GET /api/approvals.
type approvalsView struct {
	Items         []approvalItem `json:"items"`
	Count         int            `json:"count"`
	GrantRequests int            `json:"grant_requests"`
	APITokens     int            `json:"api_tokens"`
	// NextDeadline is the earliest deadline among the items: when the badge
	// should next ask, because an item will have lapsed out of the count.
	NextDeadline string `json:"next_deadline,omitempty"`
	// Mine is the caller's own requests: the pending ones, and those decided,
	// withdrawn or lapsed in the last week — how a requester sees the answer.
	Mine []requestView `json:"mine"`
	// Actor is who the hub takes the caller to be, the identity a request of
	// theirs is filed under.
	Actor string `json:"actor,omitempty"`
}

// approvalsCountView is GET /api/approvals/count.
type approvalsCountView struct {
	Count         int    `json:"count"`
	GrantRequests int    `json:"grant_requests"`
	APITokens     int    `json:"api_tokens"`
	NextDeadline  string `json:"next_deadline,omitempty"`
	// MinePending names the caller's own pending requests, so the dashboard
	// can say so when the broadcast announces one of them decided.
	MinePending []string `json:"mine_pending"`
}

// handleApprovals serves GET /api/approvals.
func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.approvalsFor(r, time.Now()))
}

// handleApprovalsCount serves GET /api/approvals/count.
func (s *Server) handleApprovalsCount(w http.ResponseWriter, r *http.Request) {
	v := s.approvalsFor(r, time.Now())
	out := approvalsCountView{
		Count: v.Count, GrantRequests: v.GrantRequests, APITokens: v.APITokens,
		NextDeadline: v.NextDeadline, MinePending: []string{},
	}
	for _, m := range v.Mine {
		if m.State == string(secretbroker.RequestPending) {
			out.MinePending = append(out.MinePending, m.ID)
		}
	}
	jsonOK(w, out)
}

// approvalsFor computes the caller's inbox. Failures to read are an empty
// inbox, never an error: the badge must not turn a database hiccup into a
// toast on every broadcast, and the panels that decide surface their own.
func (s *Server) approvalsFor(r *http.Request, now time.Time) approvalsView {
	g := s.grantFor(r)
	global := g.decide(authz.GlobalScope)
	actor := s.auditActor(r)
	v := approvalsView{Items: []approvalItem{}, Mine: []requestView{}, Actor: actor}

	var deadlines []time.Time
	scopes := s.newSubjectScopes()
	for _, req := range s.approvalRequests() {
		if req.Pending(now) && s.mayDecideRequest(g, global, actor, req, now, scopes) {
			view := requestViewOf(req, actor, true, now)
			item := approvalItem{Kind: "grant_request", ID: req.ID, Request: &view}
			if !req.ExpiresAt.IsZero() {
				item.Deadline = req.ExpiresAt.UTC().Format(time.RFC3339)
				item.DeadlineInSeconds = int64(req.ExpiresAt.Sub(now) / time.Second)
				deadlines = append(deadlines, req.ExpiresAt)
			}
			v.Items = append(v.Items, item)
			v.GrantRequests++
			continue
		}
		if !sameRequester(req.RequestedBy, actor) || len(v.Mine) >= approvalsMineMax {
			continue
		}
		decided := req.DecidedAt
		if req.State == secretbroker.RequestExpired || (req.State == secretbroker.RequestPending && !req.Pending(now)) {
			decided = req.ExpiresAt
		}
		if req.Pending(now) || (!decided.IsZero() && now.Sub(decided) <= approvalsMineWindow) {
			mine := requestViewOf(req, actor, false, now)
			if req.State == secretbroker.RequestPending && !req.Pending(now) {
				// Lapsed before a sweep moved the row: say what it is.
				mine.State = string(secretbroker.RequestExpired)
			}
			v.Mine = append(v.Mine, mine)
		}
	}

	// Device forwarder binding requests (Task 20430), rendered as the grant
	// requests they are filed beside and decided by executor.manage.
	for _, req := range s.forwarderRequestsAsAccess() {
		if mayDecideForwarderRequest(global, actor, req, now) {
			view := requestViewOf(req, actor, true, now)
			item := approvalItem{Kind: "grant_request", ID: req.ID, Request: &view}
			if !req.ExpiresAt.IsZero() {
				item.Deadline = req.ExpiresAt.UTC().Format(time.RFC3339)
				item.DeadlineInSeconds = int64(req.ExpiresAt.Sub(now) / time.Second)
				deadlines = append(deadlines, req.ExpiresAt)
			}
			v.Items = append(v.Items, item)
			v.GrantRequests++
			continue
		}
		if !sameRequester(req.RequestedBy, actor) || len(v.Mine) >= approvalsMineMax {
			continue
		}
		if req.Pending(now) || (!req.DecidedAt.IsZero() && now.Sub(req.DecidedAt) <= approvalsMineWindow) {
			v.Mine = append(v.Mine, requestViewOf(req, actor, false, now))
		}
	}

	for _, t := range s.tokensAwaitingFor(r, global, now) {
		brief := tokenBrief{ID: t.ID, Name: t.Name, Prefix: t.Prefix, Roles: t.Roles,
			CreatedBy: t.CreatedBy, CreatedAt: formatTokenTime(t.CreatedAt)}
		item := approvalItem{Kind: "api_token", ID: t.ID, Token: &brief}
		if !t.ExpiresAt.IsZero() {
			item.Deadline = t.ExpiresAt.UTC().Format(time.RFC3339)
			item.DeadlineInSeconds = int64(t.ExpiresAt.Sub(now) / time.Second)
			deadlines = append(deadlines, t.ExpiresAt)
		}
		v.Items = append(v.Items, item)
		v.APITokens++
	}

	// Soonest deadline first: what lapses next is what to look at first.
	sort.SliceStable(v.Items, func(i, j int) bool {
		a, b := v.Items[i].Deadline, v.Items[j].Deadline
		if (a == "") != (b == "") {
			return a != ""
		}
		return a < b
	})
	v.Count = len(v.Items)
	for _, d := range deadlines {
		if d.After(now) && (v.NextDeadline == "" || d.UTC().Format(time.RFC3339) < v.NextDeadline) {
			v.NextDeadline = d.UTC().Format(time.RFC3339)
		}
	}
	return v
}

// approvalRequests reads every access request from the control plane. None on
// a hub without the root key its secret broker needs: every route that decides
// or files a request answers such a hub 503, so its inbox offers nothing to
// decide. The rows themselves need no key, which is why this asks.
func (s *Server) approvalRequests() []secretbroker.AccessRequest {
	if key, err := rootkey.Current(); err != nil || key == "" {
		return nil
	}
	if _, err := os.Stat(state.DBPath(s.WorkDir)); err != nil {
		return nil
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		return nil
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		return nil
	}
	reqs, err := store.ListAccessRequests()
	if err != nil {
		return nil
	}
	// Newest first, as the broker lists them: the caller's own requests are
	// capped, and the cap should keep the recent ones.
	sort.SliceStable(reqs, func(i, j int) bool { return reqs[i].CreatedAt.After(reqs[j].CreatedAt) })
	return reqs
}

// mayDecideRequest reports whether the caller may decide req: the approve
// route's gate, the subject's own scope, the delegation ceiling and the
// broker's two-person rule, as the package comment sets out.
func (s *Server) mayDecideRequest(g *grant, global authz.Decision, actor string, req secretbroker.AccessRequest,
	now time.Time, scopes *subjectScopes) bool {
	if !req.Pending(now) || sameRequester(req.RequestedBy, actor) {
		return false
	}
	if !global.Allows(authz.PermSecretGrant) {
		return false
	}
	if requestReachesFleet(req.Subject) && global.Role != authz.RoleAdmin {
		return false
	}
	return scopes.grants(g, req.Subject)
}

// subjectScopes resolves request subjects to scopes for one inbox, reading
// the project registry once rather than once per request: resolving a
// project's name walks every registered project.
type subjectScopes struct {
	s     *Server
	names map[string]string
}

func (s *Server) newSubjectScopes() *subjectScopes { return &subjectScopes{s: s} }

// grants reports whether g holds secret.grant on the scope sub names. A
// subject that names none of its own — one reaching the fleet — is decided at
// the global scope alone, which the caller has already checked.
func (c *subjectScopes) grants(g *grant, sub secretbroker.Subject) bool {
	scope, ok := c.of(sub)
	return !ok || g.decide(scope).Allows(authz.PermSecretGrant)
}

func (c *subjectScopes) of(sub secretbroker.Subject) (authz.Scope, bool) {
	v := strings.TrimSpace(sub.Value)
	if v == "" || v == "*" {
		return authz.Scope{}, false
	}
	switch sub.Type {
	case secretbroker.SubjectProject:
		if c.names == nil {
			c.names = map[string]string{}
			for _, e := range c.s.allProjectEntries() {
				c.names[e.Path] = e.Name
			}
		}
		path := policyProjectPath(v)
		return authz.Scope{Project: c.names[path], ProjectPath: path}, true
	case secretbroker.SubjectExecutor:
		return authz.Scope{Executor: v}, true
	}
	return authz.Scope{}, false
}

// requestReachesFleet reports whether a request is aimed at an open-ended set
// of requesters — every project or executor, or a label selector — which only
// an administrator may delegate (delegationFor, secretbroker's
// isWildcardSubject).
func requestReachesFleet(sub secretbroker.Subject) bool {
	return sub.Wildcard() || sub.Type == secretbroker.SubjectLabel
}

// requestSubjectScope is the authorization scope a request's subject names: a
// project's, or an executor's. A subject reaching the fleet has none of its
// own and is decided at the global scope alone.
func (s *Server) requestSubjectScope(sub secretbroker.Subject) (authz.Scope, bool) {
	return s.newSubjectScopes().of(sub)
}

// sameRequester compares a request's filer with the caller the way the broker
// does (secretbroker.sameIdentity): case-insensitively, trimmed, never equal
// when either is empty.
func sameRequester(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	return a != "" && b != "" && strings.EqualFold(a, b)
}

// tokensAwaitingFor lists the tokens the caller may approve: under an enforced
// policy, holding token.admin and every role each token carries.
func (s *Server) tokensAwaitingFor(r *http.Request, global authz.Decision, now time.Time) []apitoken.Token {
	if !s.authzActive() || !global.Allows(authz.PermTokenAdmin) {
		return nil
	}
	mgr, err := s.tokenManager()
	if err != nil {
		return nil
	}
	tokens, err := mgr.List()
	if err != nil {
		return nil
	}
	delegator := s.delegatorFor(r)
	var out []apitoken.Token
	for i := range tokens {
		t := tokens[i]
		if !t.Active(now) || !t.AwaitsApproval() {
			continue
		}
		if apitoken.CheckDelegation(delegator, t.Roles, t.ProjectScope) != nil {
			continue
		}
		out = append(out, t)
	}
	return out
}

// broadcastApprovalsUpdate tells every dashboard that something an approver
// may decide changed outside the secret broker — a token waiting, approved or
// revoked — so each asks for its own count. An event verb and an id, nothing
// else, for the reason broadcastSecretsUpdate gives.
func (s *Server) broadcastApprovalsUpdate(event, id string) {
	s.broadcastApprovalsNotice(event, id)
	s.nudgeApprovalNotify()
}

// broadcastApprovalsNotice is the broadcast alone, for the notifier itself:
// nudging it from its own pass would only buy a second pass.
func (s *Server) broadcastApprovalsNotice(event, id string) {
	payload, err := json.Marshal(map[string]any{"event": event, "id": id})
	if err != nil {
		return
	}
	s.broadcastToAll(wsMessage{Type: "approvals_update", Data: json.RawMessage(payload)})
}
