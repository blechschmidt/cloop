package ui

// Project access: private by default (Task 20478).
//
// On a hub with single sign-on a project somebody creates is private to them.
// The people who can see an owned project are:
//
//   - its owner, the identity that created it, who is its administrator;
//   - the hub's administrators (oidc.admin_emails, or the admin role hub-wide
//     under the role policy), who administer every project;
//   - the people it is shared with (project_members rows naming a person);
//   - the members of the teams it is shared with (project_members rows naming
//     "team:<slug>"; the built-in team "everyone" is every signed-in identity);
//   - whoever a role mapping or runtime binding that names the project admits
//     at viewer or above.
//
// What each of them may do: the owner holds admin. A hub administrator holds
// what the policy gives them (admin, unless a mapping pinned to the project
// holds them lower). Everybody else holds the strongest role among their shares
// and any binding pinned to the project, and nothing from a role they hold
// hub-wide: a hub-wide role says what somebody may do across the hub — create a
// project, read the executor fleet, keep personal secrets — and does not reach
// into a project somebody else created. That is what makes "share it with Bob
// as viewer" mean view even when Bob is a maintainer hub-wide.
//
// # Projects nobody owns
//
// A project with no owner — the hub's own directory, a path an operator named
// on the command line, anything registered before sign-on — is the operator's,
// and follows the operator's role policy exactly as before: on a hub whose
// default role is "none" only the identities a mapping names can read it, on a
// hub without a policy every signed-in user can. Sharing one adds to what the
// policy gives (Task 20366's union). Recording an owner is what makes such a
// project private.
//
// A runtime deny still wins over all of it (grant.decide checks it first).
//
// # Where the decisions are made
//
//   - projectViewer / viewerSees decide visibility: the ?project_idx index
//     space, the project list, every per-recipient broadcast, and the stream
//     re-checks. A list of N projects costs one viewer and N cheap lookups.
//   - shareDecision is what owning or being shared a project grants.
//   - subjectAuthority (RBAC on) and membershipBinds (RBAC off) turn those into
//     the decision grant.decide memoizes.

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/hubteam"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// invalidateTeams is the bus invalidation a team change publishes.
const invalidateTeams = "teams"

type teamStoreState struct {
	mu    sync.Mutex
	store *hubteam.Store
	db    *statedb.DB
	opts  []hubteam.Option
}

// OpenTeamStore returns the team store backed by the hub's control-plane
// database, opening it on first call. Fatal to `cloop ui` on error, like the
// membership store: a hub that cannot read the teams table would come up having
// silently withdrawn every project shared with a team.
func (s *Server) OpenTeamStore() (*hubteam.Store, error) {
	s.teams.mu.Lock()
	defer s.teams.mu.Unlock()
	if s.teams.store != nil {
		return s.teams.store, nil
	}
	db, err := statedb.Open(state.DBPath(s.WorkDir))
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}
	db = db.AsControlPlane()
	opts := append([]hubteam.Option{
		hubteam.WithErrorHandler(func(err error) {
			s.log().Warn(logger.EventAuthz, 0, "teams: still enforcing the last known set",
				map[string]interface{}{"error": err.Error()})
		}),
		hubteam.WithOnChange(s.onTeamsChange),
	}, s.teams.opts...)
	store, err := hubteam.New(db, opts...)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	s.teams.db, s.teams.store = db, store
	return store, nil
}

// teamStore returns the open store, or nil on a hub without one.
func (s *Server) teamStore() *hubteam.Store {
	if s == nil {
		return nil
	}
	s.teams.mu.Lock()
	defer s.teams.mu.Unlock()
	return s.teams.store
}

func (s *Server) closeTeamStore() {
	s.teams.mu.Lock()
	db := s.teams.db
	s.teams.db, s.teams.store = nil, nil
	s.teams.mu.Unlock()
	if db != nil {
		_ = db.Close()
	}
}

// onTeamsChange runs whenever a reload finds the teams different — a team
// created, deleted, relinked, or a person added or removed — wherever the
// change came from. Somebody may have lost every project a team gave them, so
// the live streams are re-checked; every project list may have changed; and
// the Members cards of the projects shared with a changed team re-read.
func (s *Server) onTeamsChange(c hubteam.Change) {
	defer recoverGoroutine("team change")
	s.evictWithdrawnStreams()
	s.broadcastProjectsUpdate()
	store := s.memberStore()
	if store == nil {
		return
	}
	changed := make(map[string]bool, len(c.Teams))
	for _, slug := range c.Teams {
		changed[hubteam.ShareKey(slug)] = true
	}
	seen := map[string]bool{}
	for _, m := range store.All() {
		if !changed[m.IdentityKey] || seen[m.ProjectPath] {
			continue
		}
		seen[m.ProjectPath] = true
		if raw, err := json.Marshal(map[string]string{"project": m.ProjectPath}); err == nil {
			s.deliverToProject(m.ProjectPath, wsMessage{Type: "members_update", Data: raw})
		}
	}
}

// announceTeamsChange tells the other hub members the teams changed.
func (s *Server) announceTeamsChange(slug string) {
	s.publishInvalidate(invalidateTeams, map[string]string{"team": slug})
}

// onBusTeamsInvalidate handles another member's (or the CLI's) announcement.
func (s *Server) onBusTeamsInvalidate() {
	store := s.teamStore()
	if store == nil {
		return
	}
	store.Invalidate()
	go func() {
		defer recoverGoroutine("team reload")
		_ = store.Refresh()
	}()
}

// AnnounceTeamsChange posts the bus event a hub member would publish after
// changing the teams, for a writer that is not a member — `cloop hub team`.
func AnnounceTeamsChange(db *statedb.DB, origin, slug string) error {
	if db == nil {
		return fmt.Errorf("no database")
	}
	payload, err := json.Marshal(map[string]string{"team": slug})
	if err != nil {
		return err
	}
	_, err = db.AppendHubEvents([]statedb.HubEventRow{{
		Origin: origin, Topic: busTopicInvalidate, Key: invalidateTeams,
		Payload: string(payload), CreatedAt: time.Now(),
	}})
	return err
}

// refreshTeams re-reads the teams table, for the membership watcher's tick.
func (s *Server) refreshTeams() {
	if store := s.teamStore(); store != nil {
		_ = store.Refresh()
	}
}

// ── who is on which team ────────────────────────────────────────────────────

// teamsOf returns the teams sub is on, Everyone included, or nil when no
// project on the hub is shared with a team (then nobody's teams matter).
func (s *Server) teamsOf(sub *authz.Subject) map[string]bool {
	if sub == nil || !s.memberStore().SharesWithTeams() {
		return nil
	}
	key := subjectMemberKey(sub)
	if key == "" {
		return nil
	}
	store := s.teamStore()
	f := hubteam.Facts{Key: key, Groups: sub.Groups}
	if store.NeedsDirectory() {
		f.SCIMGroups = s.Authz.DirectoryGroups(sub)
	}
	return store.TeamsOf(f)
}

// ── ownership ───────────────────────────────────────────────────────────────

// projectOwner returns the owner recorded for the project at path, as
// allProjectEntries lists it: only a registry row carries one, and the hub's
// own directory and the paths named on its command line are listed from those
// flags first, unowned, even when a registry row names them too.
func (s *Server) projectOwner(path string) string {
	if path == "" {
		return ""
	}
	if path == s.primaryProjectPath() {
		return ""
	}
	for _, p := range s.projectsSnapshot() {
		if abs, err := filepath.Abs(p); err == nil && abs == path {
			return ""
		}
	}
	registered, _ := multiui.Load()
	for _, e := range registered {
		if abs, err := filepath.Abs(e.Path); err == nil && abs == path {
			return e.Owner
		}
	}
	return ""
}

// ownedBy reports whether owner names the identity whose member key is key.
func ownedBy(owner, key string) bool {
	return owner != "" && key != "" && strings.EqualFold(owner, key)
}

// ── hub administrators ──────────────────────────────────────────────────────

// subjectIsHubAdmin reports whether sub administers the whole hub: named in
// oidc.admin_emails, or — where a role policy is in force — holding the admin
// role at the global scope. Either way, unless a runtime deny withdraws their
// authority hub-wide. A hub administrator sees every project.
func (s *Server) subjectIsHubAdmin(sub *authz.Subject) bool {
	if sub == nil || !s.oidcEnabled() {
		return false
	}
	if s.Authz.DeniedBy(sub, authz.GlobalScope) != nil {
		return false
	}
	if s.OIDC.IsAdmin(identityFromSubject(sub)) {
		return true
	}
	if !s.authzActive() {
		return false
	}
	return s.Authz.Resolve(sub, authz.GlobalScope).Role == authz.RoleAdmin
}

// identityIsHubAdmin is subjectIsHubAdmin for an identity.
func (s *Server) identityIsHubAdmin(user *oidcauth.Identity) bool {
	return s.subjectIsHubAdmin(subjectFromIdentity(user))
}

// ── visibility ──────────────────────────────────────────────────────────────

// projectViewer is one identity's standing for visibility, worked out once so
// that a list of projects costs one Resolve and a lookup per project.
type projectViewer struct {
	// all: sees every project — no single sign-on, or no identity at all (the
	// static bearer token, an unowned service token).
	all bool
	// admin: a hub administrator.
	admin   bool
	key     string
	subject *authz.Subject
	// teams the identity is on; nil when no project is shared with a team.
	teams map[string]bool
	// pinned: the policy names projects, so a binding may admit this viewer
	// to one they were not shared.
	pinned bool
}

// viewerFor builds user's projectViewer.
func (s *Server) viewerFor(user *oidcauth.Identity) projectViewer {
	if !s.oidcEnabled() || user == nil {
		return projectViewer{all: true}
	}
	sub := subjectFromIdentity(user)
	v := projectViewer{subject: sub, key: subjectMemberKey(sub)}
	if s.subjectIsHubAdmin(sub) {
		v.admin = true
		return v
	}
	v.teams = s.teamsOf(sub)
	v.pinned = s.authzActive() && s.Authz.PinsProjects()
	return v
}

// viewerSees reports whether v may see entry. names maps a project's path to
// its registry name, for a binding that names the project; nil looks it up.
func (s *Server) viewerSees(v projectViewer, entry multiui.ProjectEntry, names map[string]string) bool {
	if v.all || v.admin || entry.Owner == "" {
		// An unowned project is the operator's: visible to everyone, and the
		// role policy decides what each may do there (narrowToReadable then
		// drops the ones a caller cannot read).
		return true
	}
	path, name := entry.Path, entry.Name
	if entry.IsFeature() {
		// A feature is its project's: same owner, same shares.
		path = entry.Parent
		if names != nil {
			name = names[path]
		} else {
			name = s.projectNameForPath(path)
		}
	}
	if ownedBy(entry.Owner, v.key) {
		return true
	}
	store := s.memberStore()
	if v.key != "" {
		if _, ok := store.Lookup(path, v.key); ok {
			return true
		}
	}
	if len(v.teams) > 0 {
		for _, m := range store.TeamSharesOf(path) {
			if slug, ok := hubteam.SlugOfShareKey(m.IdentityKey); ok && v.teams[slug] {
				return true
			}
		}
	}
	if v.pinned {
		d := s.Authz.Resolve(v.subject, authz.Scope{Project: name, ProjectPath: path})
		if d.ProjectPinned() && d.Allows(authz.PermProjectRead) {
			return true
		}
	}
	return false
}

// entryNames maps every project's path to its registry name.
func projectNamesByPath(entries []multiui.ProjectEntry) map[string]string {
	names := make(map[string]string, len(entries))
	for _, e := range entries {
		if !e.IsFeature() {
			names[e.Path] = e.Name
		}
	}
	return names
}

// ── what owning or being shared a project grants ───────────────────────────

// shareDecision is what sub holds on scope's project by owning it or having
// it shared with them — as a person, or through a team — and whether there is
// any such grant. The owner holds admin; every share its role; the strongest
// wins, reported under the source of the grant that decided it.
func (s *Server) shareDecision(sub *authz.Subject, scope authz.Scope) (authz.Decision, bool) {
	if sub == nil || scope.ProjectPath == "" || !s.oidcEnabled() {
		return authz.Decision{}, false
	}
	path := policyProjectPath(scope.ProjectPath)
	key := subjectMemberKey(sub)
	var d authz.Decision
	found := false
	add := func(role authz.Role, src authz.Source) {
		m := authz.FromRoles([]authz.Role{role}, src, sub.Label(), scope)
		if !found {
			d, found = m, true
			return
		}
		d = authz.Union(d, m)
	}
	store := s.memberStore()
	if key != "" {
		if ownedBy(s.projectOwner(path), key) {
			add(authz.RoleAdmin, authz.SourceProjectOwner)
		}
		if role, ok := store.RoleFor(path, key); ok {
			add(role, authz.SourceProjectMember)
		}
	}
	if shares := store.TeamSharesOf(path); len(shares) > 0 {
		teams := s.teamsOf(sub)
		for _, m := range shares {
			if slug, ok := hubteam.SlugOfShareKey(m.IdentityKey); ok && teams[slug] {
				add(m.Role, authz.SourceProjectTeam)
			}
		}
	}
	return d, found
}

// watchTeams re-reads the teams table every memberWatchInterval, for the same
// reason watchMemberships re-reads the memberships: a change made where no bus
// reaches still closes a removed member's streams within seconds.
func (s *Server) watchTeams(ctx context.Context) {
	defer recoverGoroutine("team watcher")
	t := time.NewTicker(memberWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshTeams()
		}
	}
}

// teamShareSlug returns the team a membership names, if it names one.
func teamShareSlug(m projectmember.Member) (string, bool) {
	return hubteam.SlugOfShareKey(m.IdentityKey)
}
