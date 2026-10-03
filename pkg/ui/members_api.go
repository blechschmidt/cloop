package ui

// Project members over REST (Task 20366):
//
//	GET    /api/projects/{idx}/members                 the owner and the members
//	POST   /api/projects/{idx}/members                 add an identity at a role
//	PATCH  /api/projects/{idx}/members?identity=…      change a member's role
//	DELETE /api/projects/{idx}/members?identity=…      remove a member
//	DELETE /api/projects/{idx}/members/self            leave a project
//
// # Why {idx}
//
// The gate resolves {idx} against the caller's own visible project list and
// refuses an index that does not resolve, so a caller who cannot see a project
// has no URL that reads or rewrites its roster. A name or a path in the body
// would have had to re-derive that check here.
//
// # Who may do what
//
// Reading the roster takes project.read: everybody on a project may see who
// else is, and the panel is also where a member finds Leave. Changing it takes
// project.share on that project — maintainer and up — and three more rules the
// route table cannot express:
//
//   - the ceiling: nobody grants a role above their own on the project, and
//     nobody changes or removes a member whose role is above their own, or a
//     maintainer could mint an admin and act through them;
//   - nobody edits their own membership except to leave it, which has its own
//     route so that "may I remove this person" never depends on who the person
//     is;
//   - a feature is shared with its project, and its roster is edited there.
//
// The identity travels in the query string on PATCH and DELETE because several
// clients and proxies drop a DELETE body, and a revocation that silently
// became "remove nobody" is the wrong failure for this operation.

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// maxMemberBodyBytes bounds a membership request; the largest legal one is an
// identity, a role and a reason.
const maxMemberBodyBytes = 16 << 10

// memberView is one row of the Members card.
type memberView struct {
	Identity  string    `json:"identity"`
	Role      string    `json:"role"`
	Reason    string    `json:"reason,omitempty"`
	GrantedAt time.Time `json:"granted_at"`
	GrantedBy string    `json:"granted_by,omitempty"`

	// Self marks the caller's own row, so the card offers Leave there
	// without knowing the caller's identity key.
	Self bool `json:"self"`
	// Manageable reports whether the caller may change or remove this
	// member: they may share the project and hold at least this member's role.
	Manageable bool `json:"manageable"`
}

// membersResponse is what GET returns.
type membersResponse struct {
	Project string       `json:"project"`
	Path    string       `json:"path"`
	Owner   string       `json:"owner,omitempty"`
	Members []memberView `json:"members"`

	// InheritedFrom names the project a feature takes its members from; the
	// roster is edited there.
	InheritedFrom string `json:"inherited_from,omitempty"`

	// YourRole is the caller's effective role on the project, the ceiling on
	// what they may grant. GrantableRoles is that ceiling as a list, so the
	// card never offers a role the hub would refuse.
	YourRole       string   `json:"your_role"`
	CanShare       bool     `json:"can_share"`
	GrantableRoles []string `json:"grantable_roles"`

	// Available is false where memberships cannot apply: no single sign-on,
	// so no identity a membership could name.
	Available bool   `json:"available"`
	Note      string `json:"note,omitempty"`
}

// memberRequest is the POST and PATCH body. Reason is a pointer so a PATCH
// can leave it alone by omitting it.
type memberRequest struct {
	Identity string  `json:"identity"`
	Role     string  `json:"role"`
	Reason   *string `json:"reason"`
}

// ── handlers ────────────────────────────────────────────────────────────────

// handleProjectMembers serves GET /api/projects/{idx}/members.
func (s *Server) handleProjectMembers(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return
	}
	project, inherited := s.memberProject(entry)
	resp := membersResponse{
		Project:        project.Name,
		Path:           project.Path,
		Owner:          project.Owner,
		Members:        []memberView{},
		GrantableRoles: []string{},
	}
	if inherited {
		resp.InheritedFrom = project.Name
	}
	store := s.memberStore()
	resp.Available = store != nil && s.oidcEnabled()
	g := s.grantFor(r)
	scope := s.entryScope(project)
	yours := g.decide(scope)
	resp.YourRole = string(yours.Role)
	resp.CanShare = resp.Available && !inherited && yours.Allows(authz.PermProjectShare)
	resp.Note = s.membersNote(project, resp.Available)
	if resp.CanShare {
		for _, role := range authz.AllRoles {
			if role != authz.RoleNone && yours.Role.AtLeast(role) {
				resp.GrantableRoles = append(resp.GrantableRoles, string(role))
			}
		}
	}
	self := identityMemberKey(s.recipientIdentity(r))
	for _, m := range store.MembersOf(project.Path) {
		resp.Members = append(resp.Members, memberView{
			Identity:   m.IdentityKey,
			Role:       string(m.Role),
			Reason:     m.Reason,
			GrantedAt:  m.GrantedAt,
			GrantedBy:  m.GrantedBy,
			Self:       self != "" && m.IdentityKey == self,
			Manageable: resp.CanShare && m.IdentityKey != self && yours.Role.AtLeast(m.Role),
		})
	}
	jsonOK(w, resp)
}

// handleProjectMemberAdd serves POST /api/projects/{idx}/members.
func (s *Server) handleProjectMemberAdd(w http.ResponseWriter, r *http.Request) {
	entry, store, ok := s.memberMutationTarget(w, r)
	if !ok {
		return
	}
	req, ok := decodeMemberRequest(w, r)
	if !ok {
		return
	}
	key, err := projectmember.ParseKey(req.Identity)
	if err != nil {
		writeMemberError(w, apierror.CodeInvalidInput, err)
		return
	}
	role, err := projectmember.ParseGrantableRole(req.Role)
	if err != nil {
		writeMemberError(w, apierror.CodeInvalidInput, err)
		return
	}
	if key == s.callerMemberKey(r) {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"you cannot add yourself to a project: a membership is granted by another maintainer"))
		return
	}
	if msg := s.membershipWouldAddNothing(entry, key); msg != "" {
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, msg))
		return
	}
	if !s.requireMemberCeiling(w, r, entry, role, "") {
		return
	}
	if existing, found := store.Lookup(entry.Path, key); found {
		apierror.WriteError(w, apierror.New(apierror.CodeConflict,
			key+" is already a member of this project, as "+string(existing.Role)+" — change their role instead").
			WithDetails(map[string]any{"role": string(existing.Role)}))
		return
	}
	reason := ""
	if req.Reason != nil {
		reason = *req.Reason
	}
	// Checked again inside the write, against the table rather than the
	// cache: another maintainer, hub or the CLI may have added them since.
	mustBeNew := func(prev, _ *projectmember.Member) error {
		if prev != nil {
			return &memberRefusal{code: apierror.CodeConflict,
				msg:     key + " is already a member of this project, as " + string(prev.Role) + " — change their role instead",
				details: map[string]any{"role": string(prev.Role)}}
		}
		return nil
	}
	stored, _, err := store.Grant(projectmember.Member{
		ProjectPath: entry.Path,
		IdentityKey: key,
		Role:        role,
		Reason:      reason,
		GrantedBy:   s.auditActor(r),
	}, s.memberAudit(r, entry, "", mustBeNew))
	if err != nil {
		s.writeMemberStoreError(w, err)
		return
	}
	s.announceMembershipChange(entry.Path)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(memberView{
		Identity: stored.IdentityKey, Role: string(stored.Role), Reason: stored.Reason,
		GrantedAt: stored.GrantedAt, GrantedBy: stored.GrantedBy, Manageable: true,
	})
}

// handleProjectMemberChange serves PATCH /api/projects/{idx}/members?identity=….
func (s *Server) handleProjectMemberChange(w http.ResponseWriter, r *http.Request) {
	entry, store, ok := s.memberMutationTarget(w, r)
	if !ok {
		return
	}
	existing, ok := s.existingMember(w, r, store, entry)
	if !ok {
		return
	}
	req, ok := decodeMemberRequest(w, r)
	if !ok {
		return
	}
	// A PATCH may change the reason alone; an absent role keeps the current one.
	role := existing.Role
	if strings.TrimSpace(req.Role) != "" {
		parsed, err := projectmember.ParseGrantableRole(req.Role)
		if err != nil {
			writeMemberError(w, apierror.CodeInvalidInput, err)
			return
		}
		role = parsed
	}
	if !s.requireMemberCeiling(w, r, entry, role, existing.Role) {
		return
	}
	reason := existing.Reason
	if req.Reason != nil {
		reason = strings.TrimSpace(*req.Reason)
	}
	if role == existing.Role && reason == existing.Reason {
		jsonOK(w, map[string]any{"identity": existing.IdentityKey, "role": string(role), "changed": false})
		return
	}
	// A change never creates a membership, and the ceiling is held against
	// the role the table holds now, not the cached one: a member removed or
	// raised since the check must not be re-admitted or overridden.
	yours := s.callerRoleOn(r, entry)
	var previous authz.Role
	stillThere := func(prev, _ *projectmember.Member) error {
		if prev == nil {
			return &memberRefusal{code: apierror.CodeNotFound, msg: "that identity is not a member of this project"}
		}
		previous = prev.Role
		if refused := ceilingRefusal(yours, prev.Role, "that member's role is stronger than your own on this project"); refused != nil {
			return refused
		}
		return nil
	}
	stored, _, err := store.Grant(projectmember.Member{
		ProjectPath: entry.Path,
		IdentityKey: existing.IdentityKey,
		Role:        role,
		Reason:      reason,
		GrantedBy:   s.auditActor(r),
	}, s.memberAudit(r, entry, "", stillThere))
	if err != nil {
		s.writeMemberStoreError(w, err)
		return
	}
	s.announceMembershipChange(entry.Path)
	jsonOK(w, map[string]any{
		"identity":      stored.IdentityKey,
		"role":          string(stored.Role),
		"previous_role": string(previous),
		"changed":       true,
	})
}

// handleProjectMemberRemove serves DELETE /api/projects/{idx}/members?identity=….
func (s *Server) handleProjectMemberRemove(w http.ResponseWriter, r *http.Request) {
	entry, store, ok := s.memberMutationTarget(w, r)
	if !ok {
		return
	}
	existing, ok := s.existingMember(w, r, store, entry)
	if !ok {
		return
	}
	if !s.requireMemberCeiling(w, r, entry, "", existing.Role) {
		return
	}
	yours := s.callerRoleOn(r, entry)
	removed, err := store.Revoke(entry.Path, existing.IdentityKey,
		s.memberAudit(r, entry, auditaction.ActionProjectMemberRevoke, func(prev, _ *projectmember.Member) error {
			// The role the table holds now: one raised since the check is
			// above this caller's reach. (A nil *memberRefusal must not
			// become a non-nil error.)
			if refused := ceilingRefusal(yours, prev.Role, "that member's role is stronger than your own on this project"); refused != nil {
				return refused
			}
			return nil
		}))
	if err != nil {
		s.writeMemberStoreError(w, err)
		return
	}
	if removed == nil {
		// Removed concurrently, by another maintainer or the CLI.
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "that identity is not a member of this project"))
		return
	}
	s.announceMembershipChange(entry.Path)
	jsonOK(w, map[string]any{"ok": true, "identity": removed.IdentityKey, "role": string(removed.Role)})
}

// handleProjectMemberLeave serves DELETE /api/projects/{idx}/members/self.
//
// Leaving is self-service whatever role the member holds: the person most
// motivated to drop a grant they did not ask for is its holder, and requiring
// a maintainer would mean a viewer could not decline access somebody gave them.
func (s *Server) handleProjectMemberLeave(w http.ResponseWriter, r *http.Request) {
	entry, store, ok := s.memberMutationTarget(w, r)
	if !ok {
		return
	}
	self := s.callerMemberKey(r)
	if self == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"this caller has no signed-in identity, so it holds no membership to give up"))
		return
	}
	removed, err := store.Revoke(entry.Path, self, s.memberAudit(r, entry, auditaction.ActionProjectMemberLeave, nil))
	if err != nil {
		s.writeMemberStoreError(w, err)
		return
	}
	if removed == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"you are not a member of this project — you see it as its owner, an admin, or through the role policy"))
		return
	}
	s.announceMembershipChange(entry.Path)
	jsonOK(w, map[string]any{"ok": true, "identity": self, "left": true})
}

// ── shared steps ────────────────────────────────────────────────────────────

// memberProject is the project whose roster entry answers for: entry itself,
// or for a feature its project, with inherited set.
func (s *Server) memberProject(entry multiui.ProjectEntry) (multiui.ProjectEntry, bool) {
	if !entry.IsFeature() {
		return entry, false
	}
	if parent, ok := s.registeredEntry(entry.Parent); ok {
		return parent, true
	}
	// A parent the registry no longer lists: answer with the path alone,
	// which is all a membership is keyed by.
	return multiui.ProjectEntry{Name: entry.Parent, Path: entry.Parent, Owner: entry.Owner}, true
}

// memberMutationTarget resolves the project a roster change is about and the
// store that records it, refusing a feature and a hub without memberships.
func (s *Server) memberMutationTarget(w http.ResponseWriter, r *http.Request) (multiui.ProjectEntry, *projectmember.Store, bool) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return multiui.ProjectEntry{}, nil, false
	}
	if entry.IsFeature() {
		parent, _ := s.memberProject(entry)
		apierror.WriteError(w, apierror.New(apierror.CodeConflict,
			"a feature is shared with its project — change the members of "+parent.Name+" instead").
			WithDetails(map[string]any{"project": parent.Name}))
		return multiui.ProjectEntry{}, nil, false
	}
	store := s.memberStore()
	if store == nil || !s.oidcEnabled() {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"project sharing needs single sign-on: a membership names a signed-in identity, and this hub has none"))
		return multiui.ProjectEntry{}, nil, false
	}
	return entry, store, true
}

// existingMember reads ?identity= and returns that member, or answers 400/404.
func (s *Server) existingMember(w http.ResponseWriter, r *http.Request, store *projectmember.Store, entry multiui.ProjectEntry) (projectmember.Member, bool) {
	key := projectmember.NormalizeKey(r.URL.Query().Get("identity"))
	if key == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "an ?identity= is required"))
		return projectmember.Member{}, false
	}
	if key == s.callerMemberKey(r) {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"you cannot change your own membership — leave the project with DELETE /api/projects/{idx}/members/self, "+
				"or ask another maintainer"))
		return projectmember.Member{}, false
	}
	m, found := store.Lookup(entry.Path, key)
	if !found {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "that identity is not a member of this project"))
		return projectmember.Member{}, false
	}
	return m, true
}

// requireMemberCeiling refuses a change above the caller's own role on the
// project: granting a role stronger than theirs, or touching a member who
// holds one. Either is privilege escalation with an extra step. An empty role
// skips its half of the check.
func (s *Server) requireMemberCeiling(w http.ResponseWriter, r *http.Request, entry multiui.ProjectEntry, grant, current authz.Role) bool {
	yours := s.callerRoleOn(r, entry)
	if err := ceilingRefusal(yours, grant, "you cannot grant a role stronger than your own on this project"); err != nil {
		err.write(w)
		return false
	}
	if err := ceilingRefusal(yours, current, "that member's role is stronger than your own on this project"); err != nil {
		err.write(w)
		return false
	}
	return true
}

// callerRoleOn is the caller's effective role on entry's project — the
// ceiling on every roster change they make there. The grant is the gate's, so
// when the provider has just re-asserted the caller's claims this is the role
// they hold now, not the one their session arrived with.
func (s *Server) callerRoleOn(r *http.Request, entry multiui.ProjectEntry) authz.Role {
	return s.grantFor(r).decide(s.entryScope(entry)).Role
}

// memberRefusal is a roster change refused with a status of its own, from
// before the write or from inside its transaction.
type memberRefusal struct {
	code    apierror.Code
	msg     string
	details map[string]any
}

func (e *memberRefusal) Error() string { return e.msg }

func (e *memberRefusal) write(w http.ResponseWriter) {
	ae := apierror.New(e.code, e.msg)
	if e.details != nil {
		ae = ae.WithDetails(e.details)
	}
	apierror.WriteError(w, ae)
}

// ceilingRefusal refuses want when it is above yours; an empty want passes.
func ceilingRefusal(yours, want authz.Role, msg string) *memberRefusal {
	if want == "" || yours.AtLeast(want) {
		return nil
	}
	return &memberRefusal{code: apierror.CodeForbidden, msg: msg,
		details: map[string]any{"role": string(want), "your_role": string(yours)}}
}

// membershipWouldAddNothing explains why a grant would change nothing, or
// returns "". Only on a hub without role mappings: there, whoever can see a
// project already holds everything on it, so admitting them is a no-op that
// would still list them as a member at a role that does not describe them.
// Where role mappings are configured a membership adds to the policy for
// anyone, including the owner and the unowned case.
func (s *Server) membershipWouldAddNothing(entry multiui.ProjectEntry, key string) string {
	if s.authzActive() {
		return ""
	}
	switch {
	case entry.Owner == "":
		return "this project has no owner, so every signed-in user can already see it and act on it — " +
			"a membership would add nothing"
	case strings.EqualFold(entry.Owner, key):
		return "that identity owns this project"
	case !strings.HasPrefix(key, "sub:") && s.OIDC.IsAdmin(&oidcauth.Identity{Email: key}):
		return "that identity is a hub admin and already sees every project"
	}
	return ""
}

// callerMemberKey is the caller's own membership key: the signed-in user, or
// the owner of a token minted on someone's behalf; "" for neither.
func (s *Server) callerMemberKey(r *http.Request) string {
	if !s.oidcEnabled() {
		return ""
	}
	return identityMemberKey(s.recipientIdentity(r))
}

// membersNote says what a role means on this hub, where that is not what the
// ladder alone would suggest.
func (s *Server) membersNote(entry multiui.ProjectEntry, available bool) string {
	switch {
	case !available:
		return "Project sharing needs single sign-on: a membership names a signed-in identity, and this hub has none."
	case s.authzActive():
		return ""
	case entry.Owner == "":
		return "This project has no owner, so every signed-in user can already see it and act on it."
	}
	return "No role mappings are configured on this hub, so a member's role here is all they may do on this " +
		"project, while its owner and the hub's admins keep full access."
}

// memberAudit builds the audit rows committed with a roster change. force
// names the action for a removal (revoke or leave); a write records a grant
// when there was no membership before and a change when there was.
//
// guard, when set, runs first inside the same transaction and sees the row the
// table holds; an error from it aborts the change (see memberRefusal).
func (s *Server) memberAudit(r *http.Request, entry multiui.ProjectEntry, force auditaction.Action, guard func(prev, next *projectmember.Member) error) projectmember.Audit {
	actor := s.auditActor(r)
	return func(prev, next *projectmember.Member) ([]*statedb.AuditEvent, error) {
		if guard != nil {
			if err := guard(prev, next); err != nil {
				return nil, err
			}
		}
		action := force
		m := next
		payload := map[string]any{"project": entry.Name, "project_path": entry.Path, "via": "api"}
		switch {
		case next == nil && prev != nil:
			m = prev
			if action == "" {
				action = auditaction.ActionProjectMemberRevoke
			}
			if action == auditaction.ActionProjectMemberLeave {
				payload["left"] = true
			}
		case prev == nil:
			action = auditaction.ActionProjectMemberGrant
		default:
			action = auditaction.ActionProjectMemberChange
			payload["previous_role"] = string(prev.Role)
		}
		if m == nil {
			return nil, nil
		}
		payload["identity"] = m.IdentityKey
		payload["role"] = string(m.Role)
		if m.Reason != "" {
			payload["reason"] = m.Reason
		}
		return []*statedb.AuditEvent{memberAuditEvent(actor, action, m.ProjectPath, m.IdentityKey, payload)}, nil
	}
}

// memberAuditEvent is one project_member audit row.
func memberAuditEvent(actor string, action auditaction.Action, path, identity string, payload map[string]any) *statedb.AuditEvent {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{}`)
	}
	return &statedb.AuditEvent{
		Actor:      actor,
		EventType:  string(action),
		EntityType: "project_member",
		// The pair is what changed; an auditor filtering on either half
		// must find it.
		EntityID: path + "|" + identity,
		Payload:  string(body),
	}
}

// dropProjectMembers removes the roster of a project that is leaving the hub.
// Memberships are keyed by path, and one outliving its project would admit
// those people to whatever is registered at that path next. Called before the
// registry change, which does not happen if this fails.
func (s *Server) dropProjectMembers(r *http.Request, entry multiui.ProjectEntry) error {
	audit := s.memberAudit(r, entry, auditaction.ActionProjectMemberRevoke, nil)
	withReason := func(prev, next *projectmember.Member) ([]*statedb.AuditEvent, error) {
		evs, err := audit(prev, next)
		for _, ev := range evs {
			var p map[string]any
			if json.Unmarshal([]byte(ev.Payload), &p) == nil {
				p["reason"] = "the project was removed from the hub"
				if b, err := json.Marshal(p); err == nil {
					ev.Payload = string(b)
				}
			}
		}
		return evs, err
	}
	removed := 0
	if store := s.memberStore(); store != nil {
		rows, err := store.RevokeProject(entry.Path, withReason)
		if err != nil {
			return err
		}
		removed = len(rows)
	} else {
		// No store — single sign-on is off now — but rows written while it was
		// on must not outlive the project either. A hub with no control-plane
		// database yet has none to remove.
		if _, err := os.Stat(state.DBPath(s.WorkDir)); err != nil {
			return nil
		}
		db, closeDB, err := s.openControlPlaneDB()
		if err != nil {
			return err
		}
		defer closeDB()
		rows, err := db.AsControlPlane().DeleteProjectMembersOf(entry.Path, func(prev, next *statedb.ProjectMemberRow) ([]*statedb.AuditEvent, error) {
			if prev == nil {
				return nil, nil
			}
			role, _ := authz.ParseRole(prev.Role)
			return withReason(&projectmember.Member{ProjectPath: prev.ProjectPath, IdentityKey: prev.IdentityKey, Role: role}, nil)
		})
		if err != nil {
			return err
		}
		removed = len(rows)
	}
	if removed > 0 {
		s.announceMembershipChange(entry.Path)
	}
	return nil
}

func decodeMemberRequest(w http.ResponseWriter, r *http.Request) (memberRequest, bool) {
	var req memberRequest
	limitJSONBody(w, r, maxMemberBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return memberRequest{}, false
	}
	if req.Reason != nil && len(strings.TrimSpace(*req.Reason)) > projectmember.MaxReasonLen {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "the reason is too long"))
		return memberRequest{}, false
	}
	return req, true
}

func writeMemberError(w http.ResponseWriter, code apierror.Code, err error) {
	apierror.WriteError(w, apierror.New(code, strings.TrimPrefix(err.Error(), "projectmember: ")))
}

// writeMemberStoreError reports a store write that failed. The message names
// the failure for an operator; nothing about the table's contents leaks
// through it.
func (s *Server) writeMemberStoreError(w http.ResponseWriter, err error) {
	var refused *memberRefusal
	if errors.As(err, &refused) {
		refused.write(w)
		return
	}
	s.log().Warn(logger.EventAuthz, 0, "project membership write failed",
		map[string]interface{}{"error": err.Error()})
	apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not record the membership change: "+err.Error()))
}
