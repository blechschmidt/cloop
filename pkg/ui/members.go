package ui

// Per-project memberships on the hub side (Task 20366).
//
// pkg/authz says what a membership means (Union: it only adds), and
// pkg/projectmember stores it behind a TTL cache. This file connects the two to
// a running hub: opening the store, the questions the request path asks it, and
// what happens to live streams when the answer changes.
//
// # The two questions
//
//   - "may this identity see this project?" — identityCanSeeEntry (oidc.go),
//     which decides the ?project_idx namespace, the project list and every
//     per-recipient broadcast. A member has to appear there, because every
//     index the dashboard can name is resolved through it.
//   - "what may this identity do on it?" — grant.decide (authz.go), which
//     unions the membership's role into whatever the identity already holds.
//
// Both look the membership up on the project's *policy* path, so a feature is
// shared exactly when its project is (features.go).
//
// # What a membership adds on a hub without role mappings
//
// Where RBAC is not configured, every signed-in user holds everything on every
// project they can see, and an owned project is visible to its owner and the
// hub's admins only. A member of such a project held nothing on it before the
// membership — they could not even address it — so the membership's role is
// their whole authority there: a viewer share means view. Anyone who can see
// the project without one (its owner, an admin, everyone for an unowned
// project) keeps the allow-all they had, so a membership still never demotes.
//
// # When the answer changes
//
// Authorization for a stream is decided at connect. A membership revoked while
// the member watches would otherwise leave them streaming the project's task
// updates and live output for as long as the tab stays open — reopening the
// leak Task 20189 closed. So every change the store reports, whether it came
// from this hub's REST handlers, from another hub member over the bus, from the
// CLI, or from the periodic refresh, re-checks every live stream and closes the
// ones whose identity lost the project.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"

	"nhooyr.io/websocket"
)

// memberWatchInterval is how often a hub re-reads the membership table on its
// own, so a change made where no bus reaches — a hub process outside the
// cluster, a hand edit — still closes a removed member's streams within
// seconds rather than at their next request.
const memberWatchInterval = 5 * time.Second

// invalidateMembers is the bus invalidation a membership change publishes.
const invalidateMembers = "members"

type memberStoreState struct {
	mu    sync.Mutex
	store *projectmember.Store
	db    *statedb.DB

	// opts are extra store options, for tests: a cluster test lengthens the
	// TTL so that only the bus can explain a peer seeing a change.
	opts []projectmember.Option
}

// OpenMemberStore returns the membership store backed by the hub's own
// control-plane database, opening it on first call.
//
// The error is a real failure and `cloop ui` aborts startup on it, as it does
// for the role store: a hub that cannot read this table would come up having
// silently un-shared every project, and the only symptom would be projects
// vanishing from colleagues' dashboards.
func (s *Server) OpenMemberStore() (*projectmember.Store, error) {
	s.members.mu.Lock()
	defer s.members.mu.Unlock()
	if s.members.store != nil {
		return s.members.store, nil
	}
	db, err := statedb.Open(state.DBPath(s.WorkDir))
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}
	// Marked, so the audit rows committed with each change are checked
	// against their declared home (statedb/audit_home.go).
	db = db.AsControlPlane()
	opts := append([]projectmember.Option{
		projectmember.WithErrorHandler(func(err error) {
			s.log().Warn(logger.EventAuthz, 0,
				"project memberships: still enforcing the last known set",
				map[string]interface{}{"error": err.Error()})
		}),
		projectmember.WithOnChange(s.onProjectMembersChange),
	}, s.members.opts...)
	store, err := projectmember.New(db, opts...)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	s.members.db, s.members.store = db, store
	return store, nil
}

// memberStore returns the open store, or nil on a hub without one.
func (s *Server) memberStore() *projectmember.Store {
	if s == nil {
		return nil
	}
	s.members.mu.Lock()
	defer s.members.mu.Unlock()
	return s.members.store
}

// closeMemberStore releases the store's database handle.
func (s *Server) closeMemberStore() {
	s.members.mu.Lock()
	db := s.members.db
	s.members.db, s.members.store = nil, nil
	s.members.mu.Unlock()
	if db != nil {
		_ = db.Close()
	}
}

// membersExist reports whether any project on this hub is shared: a slice
// length behind the store's cache, so a hub that never shared anything pays
// nothing for the feature.
func (s *Server) membersExist() bool {
	return s.memberStore().Any()
}

// subjectMemberKey is the membership key of a resolved subject — the same
// namespace as oidcauth.Identity.OwnerKey, which project owners are recorded in.
func subjectMemberKey(sub *authz.Subject) string {
	if sub == nil {
		return ""
	}
	return projectmember.KeyFor(sub.Email, sub.Sub)
}

// identityMemberKey is subjectMemberKey for an identity.
func identityMemberKey(id *oidcauth.Identity) string {
	if id == nil {
		return ""
	}
	return projectmember.KeyFor(id.Email, id.Sub)
}

// membershipDecision is what a membership alone grants sub on scope, and
// whether there is one. Looked up on the scope's policy path, so a feature's
// scope finds its project's membership even if a caller did not map it.
func (s *Server) membershipDecision(sub *authz.Subject, scope authz.Scope) (authz.Decision, bool) {
	if sub == nil || scope.ProjectPath == "" || !s.oidcEnabled() {
		return authz.Decision{}, false
	}
	role, ok := s.memberStore().RoleFor(policyProjectPath(scope.ProjectPath), subjectMemberKey(sub))
	if !ok {
		return authz.Decision{}, false
	}
	return authz.FromRoles([]authz.Role{role}, authz.SourceProjectMember, sub.Label(), scope), true
}

// subjectAuthority is what sub holds on scope where role mappings are in
// force: the policy's answer, unioned with any membership.
func (s *Server) subjectAuthority(sub *authz.Subject, scope authz.Scope) authz.Decision {
	d := s.Authz.Resolve(sub, scope)
	if m, ok := s.membershipDecision(sub, scope); ok {
		d = authz.Union(d, m)
	}
	return d
}

// membershipBinds answers, for a hub without role mappings, whether a
// membership is sub's whole authority on scope — true when sub holds one and
// could not see the project without it. See the package comment above for
// why that is a grant and never a demotion.
func (s *Server) membershipBinds(sub *authz.Subject, scope authz.Scope) (authz.Decision, bool) {
	d, ok := s.membershipDecision(sub, scope)
	if !ok {
		return authz.Decision{}, false
	}
	entry, found := s.registeredEntry(policyProjectPath(scope.ProjectPath))
	if found && s.identityCanSeeWithoutMembership(identityFromSubject(sub), entry) {
		return authz.Decision{}, false
	}
	return d, true
}

// identityFromSubject is the reverse of subjectFromIdentity, for the checks
// that are phrased in identities.
func identityFromSubject(sub *authz.Subject) *oidcauth.Identity {
	if sub == nil {
		return nil
	}
	return &oidcauth.Identity{Sub: sub.Sub, Email: sub.Email, Groups: sub.Groups, Roles: sub.Roles}
}

// registeredEntry finds the project registered at path. Features are not
// returned: a feature's policy is its parent's, so callers ask for that.
func (s *Server) registeredEntry(path string) (multiui.ProjectEntry, bool) {
	for _, e := range s.allProjectEntries() {
		if e.Path == path && !e.IsFeature() {
			return e, true
		}
	}
	return multiui.ProjectEntry{}, false
}

// primaryProjectPath is the hub's own project — what an index-less request
// resolves to — as allProjectEntries lists it.
func (s *Server) primaryProjectPath() string {
	if s.WorkDir == "" {
		return ""
	}
	abs, err := filepath.Abs(s.WorkDir)
	if err != nil {
		return s.WorkDir
	}
	return abs
}

// statusesInclude reports whether path is among statuses.
func statusesInclude(statuses []multiui.ProjectStatus, path string) bool {
	for _, st := range statuses {
		if st.Path == path {
			return true
		}
	}
	return false
}

// identityHoldsMembership reports whether user is a member of entry's project.
func (s *Server) identityHoldsMembership(user *oidcauth.Identity, entry multiui.ProjectEntry) bool {
	key := identityMemberKey(user)
	if key == "" {
		return false
	}
	path := entry.Path
	if entry.IsFeature() {
		path = entry.Parent
	}
	_, ok := s.memberStore().Lookup(path, key)
	return ok
}

// recipientGrant builds the authorization context newGrant would build for a
// request carrying this identity and token, for the paths that have no
// request: the broadcast fan-out and the stream re-checks.
func (s *Server) recipientGrant(user *oidcauth.Identity, tok *apitoken.Token) *grant {
	if tok != nil {
		return &grant{server: s, token: tok}
	}
	if !s.authzActive() {
		g := &grant{server: s, bypass: authz.SourceAuthzDisabled}
		if user != nil && (s.Authz.HasRuntimeBindings() || s.membersExist()) {
			g.subject = subjectFromIdentity(user)
		}
		return g
	}
	if user == nil {
		return &grant{server: s, bypass: authz.SourceStaticToken}
	}
	return &grant{server: s, subject: subjectFromIdentity(user)}
}

// narrowToReadable drops the projects g may not read, for a caller who holds
// no project.read hub-wide.
//
// Visibility alone was the whole filter while the project list required
// project.read at the global scope: anyone who reached it could read every
// project they could see. A member whose only authority is the project shared
// with them — the common case on a hub whose default role is "none" — now
// reaches the list too (scopeProjectList), and for them "visible" includes
// unowned projects they have no role on. Showing those would hand out names,
// goals and progress the role policy withholds, so their list is the projects
// they can read. Everyone with project.read hub-wide is unaffected.
func (s *Server) narrowToReadable(g *grant, entries []multiui.ProjectEntry) []multiui.ProjectEntry {
	if g == nil || g.bypass != "" || len(entries) == 0 {
		return entries
	}
	if g.decide(authz.GlobalScope).Allows(authz.PermProjectRead) {
		return entries
	}
	names := make(map[string]string, len(entries))
	for _, e := range entries {
		if !e.IsFeature() {
			names[e.Path] = e.Name
		}
	}
	out := entries[:0:0]
	for _, e := range entries {
		scope := authz.Scope{Project: e.Name, ProjectPath: e.Path}
		if e.IsFeature() {
			scope = authz.Scope{Project: names[e.Parent], ProjectPath: e.Parent}
		}
		if g.decide(scope).Allows(authz.PermProjectRead) {
			out = append(out, e)
		}
	}
	return out
}

// narrowStatusesToReadable is narrowToReadable for a status list, reporting
// whether it removed anything.
func (s *Server) narrowStatusesToReadable(g *grant, entries []multiui.ProjectEntry, statuses []multiui.ProjectStatus) ([]multiui.ProjectStatus, bool) {
	if g == nil || g.bypass != "" || len(statuses) == 0 {
		return statuses, false
	}
	readable := make(map[string]bool, len(entries))
	for _, e := range s.narrowToReadable(g, entries) {
		readable[e.Path] = true
	}
	if len(readable) == len(entries) {
		return statuses, false
	}
	out := make([]multiui.ProjectStatus, 0, len(statuses))
	for _, st := range statuses {
		if readable[st.Path] {
			out = append(out, st)
		}
	}
	return out, len(out) != len(statuses)
}

// ── when memberships change ─────────────────────────────────────────────────

// onProjectMembersChange is the store's OnChange: it runs, on its own goroutine,
// whenever a reload finds the table different, wherever the change came from.
// It must not publish on the bus — every member reaches here through its own
// reload, and a publish from here would echo forever.
func (s *Server) onProjectMembersChange(c projectmember.Change) {
	defer recoverGoroutine("membership change")
	s.evictWithdrawnStreams()
	// Every recipient's project list may have gained or lost a project.
	s.broadcastProjectsUpdate()
	// And open Members cards re-read their roster.
	for _, path := range c.Projects {
		raw, err := json.Marshal(map[string]string{"project": path})
		if err != nil {
			continue
		}
		s.deliverToProject(path, wsMessage{Type: "members_update", Data: raw})
	}
}

// announceMembershipChange tells the other hub members that the table changed,
// so each reloads now rather than at its next TTL. This hub's own store has
// already been brought up to date by the write.
func (s *Server) announceMembershipChange(projectPath string) {
	s.publishInvalidate(invalidateMembers, map[string]string{"project": projectPath})
}

// onBusMembersInvalidate handles another member's (or the CLI's) announcement.
// The reload runs off the bus goroutine: it reads the database and may close
// streams, and a bus subscriber must not block.
func (s *Server) onBusMembersInvalidate() {
	store := s.memberStore()
	if store == nil {
		return
	}
	store.Invalidate()
	go func() {
		defer recoverGoroutine("membership reload")
		_ = store.Refresh()
	}()
}

// watchMemberships re-reads the membership table every memberWatchInterval
// for as long as ctx lives. Every member runs it, not only the leader: each
// one has its own streams to close.
func (s *Server) watchMemberships(ctx context.Context) {
	defer recoverGoroutine("membership watcher")
	t := time.NewTicker(memberWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if store := s.memberStore(); store != nil {
				_ = store.Refresh()
			}
		}
	}
}

// AnnounceMembershipChange posts the bus event a hub member would publish
// after changing project_members, for a writer that is not a member — `cloop
// project members`. Every live member polls the bus and reloads within its
// poll interval; a member that is down reads the table fresh when it starts.
// A failure is returned for the caller to report, never fatal to the write:
// without the event the change still lands within the hubs' refresh interval.
func AnnounceMembershipChange(db *statedb.DB, origin, projectPath string) error {
	if db == nil {
		return errors.New("no database")
	}
	payload, err := json.Marshal(map[string]string{"project": projectPath})
	if err != nil {
		return err
	}
	_, err = db.AppendHubEvents([]statedb.HubEventRow{{
		Origin:    origin,
		Topic:     busTopicInvalidate,
		Key:       invalidateMembers,
		Payload:   string(payload),
		CreatedAt: time.Now(),
	}})
	return err
}

// evictWithdrawnStreams closes every live stream whose identity can no longer
// read the project it is attached to.
//
// The client is taken out of its room before it is told to close, so nothing
// broadcast after this point is queued for it; its writer checks the kick ahead
// of anything already queued. Who may still read what is worked out with no
// broadcast lock held: it can read the database, and a broadcast must not
// wait on that.
func (s *Server) evictWithdrawnStreams() {
	entries := s.allProjectEntries()
	byPath := make(map[string]multiui.ProjectEntry, len(entries))
	for _, e := range entries {
		byPath[e.Path] = e
	}
	withdrawn := func(user *oidcauth.Identity, tok *apitoken.Token, workDir string) bool {
		return s.withdrawnFrom(user, tok, workDir, byPath)
	}

	type wsStream struct {
		hc      *hubClient
		workDir string
	}
	var sockets []wsStream
	s.hubMu.Lock()
	for workDir, clients := range s.hubClients {
		if workDir == hubRoomGlobal {
			continue
		}
		for hc := range clients {
			sockets = append(sockets, wsStream{hc, workDir})
		}
	}
	s.hubMu.Unlock()
	var streams []*sseClient
	s.mu.Lock()
	for c := range s.clients {
		if c.workDir != "" {
			streams = append(streams, c)
		}
	}
	s.mu.Unlock()

	var closed []wsStream
	for _, k := range sockets {
		if withdrawn(k.hc.user, k.hc.token, k.workDir) {
			closed = append(closed, k)
		}
	}
	var closedSSE []*sseClient
	for _, c := range streams {
		if withdrawn(c.user, c.token, c.workDir) {
			closedSSE = append(closedSSE, c)
		}
	}

	if len(closed) > 0 {
		s.hubMu.Lock()
		for _, k := range closed {
			room := s.hubClients[k.workDir]
			if _, still := room[k.hc]; !still {
				continue // gone on its own meanwhile
			}
			delete(room, k.hc)
			if len(room) == 0 {
				delete(s.hubClients, k.workDir)
			}
			select {
			case k.hc.kick <- streamEnd{message: "access to this project was withdrawn"}:
			default:
			}
		}
		s.hubMu.Unlock()
	}
	if len(closedSSE) > 0 {
		s.mu.Lock()
		for _, c := range closedSSE {
			if _, still := s.clients[c]; !still {
				continue
			}
			delete(s.clients, c)
			select {
			case c.kick <- streamEnd{}:
			default:
			}
		}
		s.mu.Unlock()
	}

	for _, k := range closed {
		s.log().Warn(logger.EventAuthz, 0,
			"closing a WebSocket stream whose identity can no longer read its project",
			map[string]interface{}{"project": k.workDir, "client": k.hc.id})
		s.broadcastPresence(k.workDir)
	}
	if len(closedSSE) > 0 {
		s.log().Warn(logger.EventAuthz, 0,
			"closing SSE streams whose identity can no longer read their project",
			map[string]interface{}{"streams": len(closedSSE)})
	}
}

// closeWithdrawn ends a socket whose identity lost its project: an
// access_withdrawn message saying so, then a 1008 close.
//
// The message is what the dashboard acts on, not the close code. nhooyr v1.8
// answers the browser's reply to our close frame with a second close frame
// when another goroutine is reading — handleWS's drain always is — and a
// browser fails the connection on that, reporting 1006 with our reason lost.
// A data frame sent first arrives intact either way.
func closeWithdrawn(ctx context.Context, conn *websocket.Conn, reason string) {
	if raw, err := json.Marshal(map[string]string{"reason": reason}); err == nil {
		if msg, err := json.Marshal(wsMessage{Type: "access_withdrawn", Data: raw}); err == nil {
			_ = wsWrite(ctx, conn, msg)
		}
	}
	_ = conn.Close(websocket.StatusPolicyViolation, reason)
}

// streamWithdrawn reports whether a stream attached to workDir has lost it.
// For a single stream; evictWithdrawnStreams asks the same question of all of
// them against one listing.
func (s *Server) streamWithdrawn(user *oidcauth.Identity, tok *apitoken.Token, workDir string) bool {
	if s.memberStore() == nil {
		// No memberships on this hub: nothing changes a stream's standing
		// between its gate and its room.
		return false
	}
	entries := s.allProjectEntries()
	byPath := make(map[string]multiui.ProjectEntry, len(entries))
	for _, e := range entries {
		byPath[e.Path] = e
	}
	return s.withdrawnFrom(user, tok, workDir, byPath)
}

// withdrawnFrom reports whether a stream's identity can no longer read the
// project of the room it is in. The hub's own project is always listed, so a
// room whose project is not is one that was removed — withdrawn from
// everybody.
func (s *Server) withdrawnFrom(user *oidcauth.Identity, tok *apitoken.Token, workDir string, byPath map[string]multiui.ProjectEntry) bool {
	if workDir == hubRoomGlobal {
		return false
	}
	entry, ok := byPath[workDir]
	if !ok {
		if abs, err := filepath.Abs(workDir); err == nil {
			entry, ok = byPath[abs]
		}
	}
	if !ok {
		return true
	}
	return !s.streamCanRead(user, tok, entry, byPath)
}

// closeProjectStreams closes every stream attached to a project, or to one of
// its features, telling each why — the project is going away.
func (s *Server) closeProjectStreams(path, reason string) {
	under := func(workDir string) bool {
		return workDir == path || strings.HasPrefix(workDir, path+string(filepath.Separator)+".cloop"+string(filepath.Separator)+"features"+string(filepath.Separator))
	}
	var closed []string
	s.hubMu.Lock()
	for workDir, clients := range s.hubClients {
		if workDir == hubRoomGlobal || !under(workDir) {
			continue
		}
		for hc := range clients {
			select {
			case hc.kick <- streamEnd{message: reason}:
			default:
			}
		}
		delete(s.hubClients, workDir)
		closed = append(closed, workDir)
	}
	s.hubMu.Unlock()
	s.mu.Lock()
	for c := range s.clients {
		if c.workDir != "" && under(c.workDir) {
			delete(s.clients, c)
			select {
			case c.kick <- streamEnd{message: reason}:
			default:
			}
		}
	}
	s.mu.Unlock()
	for _, workDir := range closed {
		s.log().Info(logger.EventAuthz, 0, "closed the streams of a removed project",
			map[string]interface{}{"project": workDir})
	}
}

// streamCanRead reports whether a stream's identity may still read entry: it
// can still see it, and its authority there still includes project.read.
func (s *Server) streamCanRead(user *oidcauth.Identity, tok *apitoken.Token, entry multiui.ProjectEntry, byPath map[string]multiui.ProjectEntry) bool {
	if user != nil && !s.identityCanSeeEntry(user, entry) {
		return false
	}
	scope := authz.Scope{Project: entry.Name, ProjectPath: entry.Path}
	if entry.IsFeature() {
		scope = authz.Scope{Project: byPath[entry.Parent].Name, ProjectPath: entry.Parent}
	}
	return s.recipientGrant(user, tok).decide(scope).Allows(authz.PermProjectRead)
}
