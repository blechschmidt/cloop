package ui

// Readers lists pushed to the dashboards that show them (Task 20503).
//
// A project's Overview shows its readers list — the projects whose runs may
// read it — and the projects it may read itself. An entry ties two projects,
// so a change to one list moves two Overviews: the listing project's readers,
// and the reader's list of what it may read. Neither is polled. When an entry
// is added or removed here, each project the entry names is owed a push, and
// every dashboard showing one of them is sent that project's lists as its own
// GET /api/projects/{idx}/readers would answer — rendered per recipient,
// because what a list says depends on who is looking: only projects the
// recipient can see are named, the rest are counted, and only an administrator
// is sent the hidden entries' ids and the projects they could add. A dashboard
// whose credential has ended, or that may no longer read the project, is sent
// nothing; the stream checks close it.
//
// Who may see which project changes too — a share, a team, a project added to
// the hub or removed from it — and with it what every open Readers section may
// name and the candidates it offers its administrators, so then every
// project's dashboards are owed a push. Those changes reach each hub member
// through its own member store and project watcher; an entry added or removed
// on another member reaches this one's dashboards through the cluster bus, as
// a notice naming the projects, which every member renders for its own.
//
// One drain delivers what is owed, a round at a time, reading the lists and
// each recipient's access afresh every round. A change that lands while a
// round renders is owed again and drawn by the next round, so the last thing
// a dashboard is sent is how its lists stood after the last change: two
// pushes rendered side by side could otherwise arrive in the wrong order and
// leave a dashboard showing a list as it was before.

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/projectreaders"
)

// invalidateReaders: an entry was added to or removed from a readers list on
// a member, and every member tells its dashboards of the projects it names.
const invalidateReaders = "readers"

// readersNotice names the projects whose lists changed.
type readersNotice struct {
	Projects []string `json:"projects"`
}

// readersPushState is what this member owes its dashboards.
type readersPushState struct {
	mu sync.Mutex
	// owed are the normalised paths of the projects whose dashboards are
	// owed their lists; all owes every project's.
	owed     map[string]bool
	all      bool
	draining bool
	// rounds counts finished rounds, so a test can wait for one.
	rounds atomic.Uint64
}

// readersChanged owes the dashboards of the projects at paths their lists, on
// this member and — through the bus — on every other: an entry naming them
// was added or removed here. Called once the change has committed.
func (s *Server) readersChanged(paths ...string) {
	paths = distinctReaderPaths(paths)
	if len(paths) == 0 {
		return
	}
	s.publishInvalidate(invalidateReaders, readersNotice{Projects: paths})
	s.oweReaders(paths, false)
}

// onBusReaders is another member's notice: its change, for this member's
// dashboards.
func (s *Server) onBusReaders(ev hubcluster.Event) {
	var n readersNotice
	if err := ev.Decode(&n); err != nil {
		return
	}
	s.oweReaders(distinctReaderPaths(n.Projects), false)
}

// readersRefreshAll owes every project's dashboards their lists: who may see
// which project changed — a share given or taken, a team's members, a project
// added to the hub or removed from it — so what each Readers section may name
// to whom, and the candidates it offers, may have changed with it. Each member
// learns of those changes itself, so this is never announced on the bus.
func (s *Server) readersRefreshAll() {
	s.oweReaders(nil, true)
}

// oweReaders records what is owed and starts the drain unless it runs.
func (s *Server) oweReaders(paths []string, all bool) {
	if len(paths) == 0 && !all {
		return
	}
	st := &s.readersPush
	st.mu.Lock()
	if st.owed == nil {
		st.owed = map[string]bool{}
	}
	for _, p := range paths {
		st.owed[p] = true
	}
	st.all = st.all || all
	start := !st.draining
	st.draining = true
	st.mu.Unlock()
	if start {
		go s.drainReadersPushes()
	}
}

// drainReadersPushes delivers what is owed, a round at a time, until nothing
// is: what was owed while a round ran is the next round's.
func (s *Server) drainReadersPushes() {
	st := &s.readersPush
	defer func() {
		// Whatever this round owed is lost with it, never the drain: the
		// next change starts another.
		if v := recover(); v != nil {
			s.log().Error(logger.EventAuthz, 0, "project readers: push to dashboards panicked",
				map[string]interface{}{"panic": fmt.Sprint(v)})
			st.mu.Lock()
			st.draining = false
			st.mu.Unlock()
		}
	}()
	for {
		st.mu.Lock()
		owed, all := st.owed, st.all
		st.owed, st.all = nil, false
		if len(owed) == 0 && !all {
			st.draining = false
			st.mu.Unlock()
			return
		}
		st.mu.Unlock()
		s.pushReaders(owed, all)
		st.rounds.Add(1)
	}
}

// distinctReaderPaths normalises paths and drops blanks and repeats, keeping
// the first occurrence's order.
func distinctReaderPaths(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = projectreaders.NormalizePath(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// readersRecipient is one stream credential's authority and project list, as
// a request carrying it would have them now.
type readersRecipient struct {
	g       *grant
	visible []multiui.ProjectEntry
}

// pushReaders sends this member's dashboards of each project owed — every
// project, with all — that project's lists, rendered for each dashboard's
// credential.
func (s *Server) pushReaders(owed map[string]bool, all bool) {
	// The registry's entries, by normalised path: a list names a project by
	// its path, and a room is keyed by the entry's own.
	var rooms []multiui.ProjectEntry
	for _, e := range s.allProjectEntries() {
		if e.IsFeature() || !(all || owed[projectreaders.NormalizePath(e.Path)]) || !s.hasStreamClients(e.Path) {
			continue
		}
		rooms = append(rooms, e)
	}
	if len(rooms) == 0 {
		return
	}
	res, err := s.loadReaders()
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "project readers: read the lists to push",
			map[string]interface{}{"error": err.Error()})
		return
	}
	// One verdict per credential, shared by every project pushed in this
	// round and every stream the credential opened.
	recipients := map[streamCredential]*readersRecipient{}
	recipientFor := func(c streamCredential) *readersRecipient {
		if rc, seen := recipients[c]; seen {
			return rc
		}
		var rc *readersRecipient
		if user, tok, _, ok := s.credentialAuthority(c); ok {
			if g := s.credentialGrant(c, user, tok); g != nil {
				rc = &readersRecipient{g: g, visible: s.recipientProjectEntries(user, tok, g)}
			}
		}
		recipients[c] = rc
		return rc
	}
	for _, entry := range rooms {
		rendered := map[streamCredential]json.RawMessage{}
		s.deliverReaders(entry.Path, func(c streamCredential) json.RawMessage {
			if data, seen := rendered[c]; seen {
				return data
			}
			var data json.RawMessage
			if rc := recipientFor(c); rc != nil && entryListed(rc.visible, entry.Path) &&
				rc.g.decide(s.entryScope(entry)).Allows(authz.PermProjectRead) {
				if raw, err := json.Marshal(s.readersViewFor(entry, rc.g, rc.visible, res)); err == nil {
					data = raw
				}
			}
			rendered[c] = data
			return data
		})
	}
}

// entryListed reports whether entries holds the project at path.
func entryListed(entries []multiui.ProjectEntry, path string) bool {
	for _, e := range entries {
		if e.Path == path {
			return true
		}
	}
	return false
}

// recipientProjectEntries is visibleProjectEntries for a stream: the project
// list — and so the index space — a request carrying the stream's credential
// would get. g is that credential's grant (credentialGrant).
func (s *Server) recipientProjectEntries(user *oidcauth.Identity, tok *apitoken.Token, g *grant) []multiui.ProjectEntry {
	entries := filterEntriesForToken(tok, s.allProjectEntries())
	if !s.oidcEnabled() {
		return entries
	}
	return s.narrowToReadable(g, s.filterEntriesForIdentity(user, entries))
}

// deliverReaders sends this member's sockets and event streams of workDir what
// render makes for each one's credential, when that is anything. Rendering
// runs with no client lock held: it reads the role and membership tables, and
// a broadcast must not hold every socket hostage to a database wait.
func (s *Server) deliverReaders(workDir string, render func(streamCredential) json.RawMessage) {
	s.hubMu.Lock()
	sockets := make([]*hubClient, 0, len(s.hubClients[workDir]))
	for hc := range s.hubClients[workDir] {
		sockets = append(sockets, hc)
	}
	s.hubMu.Unlock()
	s.mu.Lock()
	var streams []*sseClient
	for c := range s.clients {
		if c.workDir == workDir {
			streams = append(streams, c)
		}
	}
	s.mu.Unlock()

	socketData := make([]json.RawMessage, len(sockets))
	for i, hc := range sockets {
		socketData[i] = render(hc.cred)
	}
	streamData := make([]json.RawMessage, len(streams))
	for i, c := range streams {
		streamData[i] = render(c.cred)
	}

	s.hubMu.Lock()
	for i, hc := range sockets {
		if _, still := s.hubClients[workDir][hc]; still && socketData[i] != nil {
			s.sendOrLag(hc, wsMessage{Type: "project_readers", Data: socketData[i]})
		}
	}
	s.hubMu.Unlock()
	s.mu.Lock()
	for i, c := range streams {
		if _, still := s.clients[c]; still && streamData[i] != nil {
			s.sendSSEOrLag(c, sseEvent{Event: "project_readers", Data: string(streamData[i])})
		}
	}
	s.mu.Unlock()
}

// readerCandidatePath reports whether the PUT takes path back as it is, which
// is how the dashboard names a candidate: projectreaders.ParsePath trims,
// cleans and refuses a control character, so a registered path it would
// change could be offered and then not found.
func readerCandidatePath(path string) bool {
	p, err := projectreaders.ParsePath(path)
	return err == nil && p == path
}
