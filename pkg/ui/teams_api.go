package ui

// Teams over REST (Task 20478):
//
//	GET    /api/teams                              every team, its members and the projects it reaches
//	POST   /api/teams                              create a team
//	PATCH  /api/teams/{slug}                       rename it, or change the groups it follows
//	DELETE /api/teams/{slug}                       delete it, and every project share naming it
//	POST   /api/teams/{slug}/members               add a person by name
//	DELETE /api/teams/{slug}/members?identity=…    take a person off it
//
// All six take user.manage at the global scope: whoever decides who is on a
// team decides who reaches every project shared with it, which is a decision
// about access across the hub rather than about any one project. A project's
// administrator chooses which teams the project is shared with — the Members
// card, members_api.go — and nothing else about them. The writes but the
// removal of one person ask for a recent sign-in (Task 20448); taking somebody
// off a team withdraws access, and is undone by an action that does ask.
//
// Every change commits together with its audit rows. Deleting a team records
// one project.member.revoke per project it was shared with, so a project's own
// trail says who lost access to it and why.

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/hubteam"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// maxTeamBodyBytes bounds a team request: a slug, a name, a description and
// two group names.
const maxTeamBodyBytes = 16 << 10

// teamView is one team in GET /api/teams.
type teamView struct {
	hubteam.Team
	// Projects are the projects the team is shared with, and at which role.
	Projects []teamProjectView `json:"projects"`
	// Builtin marks Everyone.
	Builtin bool `json:"builtin,omitempty"`
}

type teamProjectView struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Role string `json:"role"`
}

// teamsResponse is what GET /api/teams returns.
type teamsResponse struct {
	Teams []teamView `json:"teams"`
	// Directory reports whether the hub is provisioned over SCIM, i.e.
	// whether a team can follow a provisioned group.
	Directory bool `json:"directory"`
}

// teamRequest is the POST and PATCH body. On a PATCH an absent field keeps its
// value; an empty one clears it (a group link) or resets it (the name, to the
// slug).
type teamRequest struct {
	Slug        string  `json:"slug"`
	Name        *string `json:"name"`
	Description *string `json:"description"`
	IdPGroup    *string `json:"idp_group"`
	SCIMGroup   *string `json:"scim_group"`
}

// teamMemberRequest is the body that adds a person to a team.
type teamMemberRequest struct {
	Identity string `json:"identity"`
}

// handleTeams serves GET /api/teams.
func (s *Server) handleTeams(w http.ResponseWriter, r *http.Request) {
	store, ok := s.teamsAvailable(w)
	if !ok {
		return
	}
	shares := map[string][]teamProjectView{}
	names := projectNamesByPath(s.allProjectEntries())
	for _, m := range s.memberStore().All() {
		slug, isTeam := teamShareSlug(m)
		if !isTeam {
			continue
		}
		name := names[m.ProjectPath]
		if name == "" {
			name = m.ProjectPath
		}
		shares[slug] = append(shares[slug], teamProjectView{Name: name, Path: m.ProjectPath, Role: string(m.Role)})
	}
	resp := teamsResponse{Teams: []teamView{}, Directory: s.Authz.HasDirectory()}
	everyone := hubteam.BuiltinTeam()
	resp.Teams = append(resp.Teams, teamView{Team: everyone, Builtin: true, Projects: nonNilProjects(shares[everyone.Slug])})
	for _, t := range store.All() {
		resp.Teams = append(resp.Teams, teamView{Team: t, Projects: nonNilProjects(shares[t.Slug])})
	}
	jsonOK(w, resp)
}

func nonNilProjects(p []teamProjectView) []teamProjectView {
	if p == nil {
		return []teamProjectView{}
	}
	sort.Slice(p, func(i, j int) bool { return p[i].Name < p[j].Name })
	return p
}

// handleTeamCreate serves POST /api/teams.
func (s *Server) handleTeamCreate(w http.ResponseWriter, r *http.Request) {
	store, ok := s.teamsAvailable(w)
	if !ok {
		return
	}
	var req teamRequest
	if !jsonbody.Decode(w, r, &req, jsonbody.Options{Limit: maxTeamBodyBytes}) {
		return
	}
	t := hubteam.Team{Slug: req.Slug, Name: optString(req.Name), Description: optString(req.Description),
		IdPGroup: optString(req.IdPGroup), SCIMGroup: optString(req.SCIMGroup), CreatedBy: s.auditActor(r)}
	created, err := store.Create(t, s.teamAudit(r, auditaction.ActionTeamCreate))
	if err != nil {
		s.writeTeamError(w, err)
		return
	}
	s.announceTeamsChange(created.Slug)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(teamView{Team: created, Projects: []teamProjectView{}})
}

// handleTeamUpdate serves PATCH /api/teams/{slug}.
func (s *Server) handleTeamUpdate(w http.ResponseWriter, r *http.Request) {
	store, ok := s.teamsAvailable(w)
	if !ok {
		return
	}
	current, ok := s.teamAt(w, r, store)
	if !ok {
		return
	}
	var req teamRequest
	if !jsonbody.Decode(w, r, &req, jsonbody.Options{Limit: maxTeamBodyBytes}) {
		return
	}
	if req.Slug != "" && hubteam.NormalizeSlug(req.Slug) != current.Slug {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"a team's slug cannot change: projects are shared with it by that name — create a new team instead"))
		return
	}
	next := current
	if req.Name != nil {
		next.Name = *req.Name
	}
	if req.Description != nil {
		next.Description = *req.Description
	}
	if req.IdPGroup != nil {
		next.IdPGroup = *req.IdPGroup
	}
	if req.SCIMGroup != nil {
		next.SCIMGroup = *req.SCIMGroup
	}
	next.UpdatedBy = s.auditActor(r)
	stored, _, err := store.Update(next, s.teamAudit(r, auditaction.ActionTeamUpdate))
	if err != nil {
		s.writeTeamError(w, err)
		return
	}
	s.announceTeamsChange(stored.Slug)
	jsonOK(w, teamView{Team: stored, Projects: []teamProjectView{}})
}

// handleTeamDelete serves DELETE /api/teams/{slug}.
func (s *Server) handleTeamDelete(w http.ResponseWriter, r *http.Request) {
	store, ok := s.teamsAvailable(w)
	if !ok {
		return
	}
	current, ok := s.teamAt(w, r, store)
	if !ok {
		return
	}
	removed, shares, err := store.Delete(current.Slug, s.teamAudit(r, auditaction.ActionTeamDelete))
	if err != nil {
		s.writeTeamError(w, err)
		return
	}
	// The membership store reads project_members, whose team rows went with
	// the team: reload it now, and tell the other hub members both changed.
	if ms := s.memberStore(); ms != nil {
		_ = ms.Refresh()
	}
	for _, sh := range shares {
		s.announceMembershipChange(sh.ProjectPath)
	}
	s.announceTeamsChange(removed.Slug)
	projects := make([]string, 0, len(shares))
	for _, sh := range shares {
		projects = append(projects, sh.ProjectPath)
	}
	jsonOK(w, map[string]any{"ok": true, "slug": removed.Slug, "unshared_projects": projects})
}

// handleTeamMemberAdd serves POST /api/teams/{slug}/members.
func (s *Server) handleTeamMemberAdd(w http.ResponseWriter, r *http.Request) {
	store, ok := s.teamsAvailable(w)
	if !ok {
		return
	}
	current, ok := s.teamAt(w, r, store)
	if !ok {
		return
	}
	var req teamMemberRequest
	if !jsonbody.Decode(w, r, &req, jsonbody.Options{Limit: maxTeamBodyBytes}) {
		return
	}
	key, err := hubteam.ParseMemberKey(req.Identity)
	if err != nil {
		s.writeTeamError(w, err)
		return
	}
	m, existed, err := store.AddMember(current.Slug, key, s.auditActor(r), s.teamAudit(r, auditaction.ActionTeamMemberAdd))
	if err != nil {
		s.writeTeamError(w, err)
		return
	}
	if existed {
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, key+" is already on the team "+current.Slug))
		return
	}
	s.announceTeamsChange(current.Slug)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(m)
}

// handleTeamMemberRemove serves DELETE /api/teams/{slug}/members?identity=….
// The identity travels in the query string for the reason the members API's
// does: a DELETE body is dropped by enough clients that "remove nobody" would
// be the failure.
func (s *Server) handleTeamMemberRemove(w http.ResponseWriter, r *http.Request) {
	store, ok := s.teamsAvailable(w)
	if !ok {
		return
	}
	current, ok := s.teamAt(w, r, store)
	if !ok {
		return
	}
	key := strings.TrimSpace(r.URL.Query().Get("identity"))
	if key == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "an ?identity= is required"))
		return
	}
	removed, err := store.RemoveMember(current.Slug, key, s.teamAudit(r, auditaction.ActionTeamMemberRemove))
	if err != nil {
		s.writeTeamError(w, err)
		return
	}
	if removed == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"that identity is not on the team "+current.Slug+" by name"))
		return
	}
	s.announceTeamsChange(current.Slug)
	jsonOK(w, map[string]any{"ok": true, "slug": current.Slug, "identity": removed.IdentityKey})
}

// ── shared steps ────────────────────────────────────────────────────────────

// teamsAvailable returns the team store, or answers 503 on a hub without one:
// a team is a set of signed-in identities, and a hub without sign-on has none.
func (s *Server) teamsAvailable(w http.ResponseWriter) (*hubteam.Store, bool) {
	store := s.teamStore()
	if store == nil || !s.oidcEnabled() {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"teams need single sign-on: a team is a set of signed-in identities, and this hub has none"))
		return nil, false
	}
	return store, true
}

// teamAt resolves the {slug} path segment, refusing Everyone, which has no
// definition to change and no members to edit.
func (s *Server) teamAt(w http.ResponseWriter, r *http.Request, store *hubteam.Store) (hubteam.Team, bool) {
	slug := hubteam.NormalizeSlug(r.PathValue("slug"))
	if slug == hubteam.Everyone {
		apierror.WriteError(w, apierror.New(apierror.CodeConflict,
			"Everyone is the built-in team of every signed-in identity: it cannot be changed, deleted or given members"))
		return hubteam.Team{}, false
	}
	t, ok := store.Get(slug)
	if !ok {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "there is no team "+slug+" on this hub"))
		return hubteam.Team{}, false
	}
	return t, true
}

// writeTeamError reports a refused or failed team write.
func (s *Server) writeTeamError(w http.ResponseWriter, err error) {
	msg := err.Error()
	for _, prefix := range []string{"team: ", "statedb: "} {
		msg = strings.ReplaceAll(msg, prefix, "")
	}
	switch {
	case errors.Is(err, statedb.ErrTeamExists):
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, "a team with that slug already exists"))
	case errors.Is(err, statedb.ErrTeamNotFound):
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "that team no longer exists on this hub"))
	case strings.HasPrefix(err.Error(), "team: ") && !strings.Contains(err.Error(), "statedb"):
		// A refusal of the request itself: a bad slug, an unparseable
		// identity, a field too long.
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, msg))
	default:
		s.log().Warn(logger.EventAuthz, 0, "team write failed", map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not record the team change: "+msg))
	}
}

// teamAudit builds the audit rows committed with a team change: one row for
// the team, and — for a deletion — one project.member.revoke per project the
// team was shared with.
func (s *Server) teamAudit(r *http.Request, action auditaction.Action) hubteam.Audit {
	return TeamAuditRows(s.auditActor(r), "api", action, nil)
}

// TeamAuditRows is teamAudit for any actor and channel, with extra fields for
// every row it writes; `cloop hub team` uses it with via "cli" and the
// operator's reason, so the API and the CLI record a team change alike.
func TeamAuditRows(actor, via string, action auditaction.Action, extra map[string]any) hubteam.Audit {
	return func(c statedb.TeamChange) ([]*statedb.AuditEvent, error) {
		payload := map[string]any{"via": via}
		for k, v := range extra {
			payload[k] = v
		}
		entity := ""
		switch {
		case c.MemberNext != nil || c.MemberPrev != nil:
			m := c.MemberNext
			if m == nil {
				m = c.MemberPrev
			}
			entity = m.TeamSlug + "|" + m.IdentityKey
			payload["team"] = m.TeamSlug
			payload["identity"] = m.IdentityKey
		default:
			t := c.Next
			if t == nil {
				t = c.Prev
			}
			if t == nil {
				return nil, nil
			}
			entity = t.Slug
			payload["team"] = t.Slug
			payload["name"] = t.Name
			if t.IdPGroup != "" {
				payload["idp_group"] = t.IdPGroup
			}
			if t.SCIMGroup != "" {
				payload["scim_group"] = t.SCIMGroup
			}
			if c.Prev != nil && c.Next != nil {
				payload["previous"] = map[string]any{"name": c.Prev.Name,
					"idp_group": c.Prev.IdPGroup, "scim_group": c.Prev.SCIMGroup}
			}
			if action == auditaction.ActionTeamDelete {
				members := make([]string, 0, len(c.RemovedMembers))
				for _, m := range c.RemovedMembers {
					members = append(members, m.IdentityKey)
				}
				payload["members"] = members
				payload["shares"] = len(c.RemovedShares)
			}
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		evs := []*statedb.AuditEvent{{
			Actor: actor, EventType: string(action), EntityType: "team",
			EntityID: entity, Payload: string(body),
		}}
		for _, sh := range c.RemovedShares {
			evs = append(evs, memberAuditEvent(actor, auditaction.ActionProjectMemberRevoke, sh.ProjectPath, sh.IdentityKey,
				map[string]any{"project_path": sh.ProjectPath, "identity": sh.IdentityKey,
					"team": strings.TrimPrefix(sh.IdentityKey, hubteam.KeyPrefix),
					"role": sh.Role, "via": via, "reason": "the team was deleted"}))
		}
		return evs, nil
	}
}

func optString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
