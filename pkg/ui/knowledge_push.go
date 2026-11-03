package ui

// Knowledge sources pushed to the dashboards that show them (Task 20473).
//
// Settings → Knowledge sources and a project's Knowledge tab show each source's
// sync — running or not, how the last one went, what the source holds — and
// none of it is polled. Whenever a source's sync moves on this member (it took
// the source's lease, indexed a page, ended) or a person changes the source
// here, the source is owed a push; a drain reads it once, as it is then, and
// sends each dashboard the source as that dashboard's own GET would show it —
// or nothing, to a dashboard that may not see it. A change made on another
// member reaches this member's dashboards through the cluster bus, as a notice
// naming the source, which every member renders for its own.
//
// What a dashboard may see is the knowledge routes' rule (knowledge.Access),
// asked of the credential its stream was opened with as that credential stands
// now: an operator learns of the organisation's sources and their own, never of
// someone else's personal one — not even that it changed. The drain reads the
// source fresh each round and sends what it read, so a push that loses a race
// with a later one is followed by that one: the last thing a dashboard is told
// is how the source stood after its last change.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// invalidateKnowledge: a knowledge source changed on a member — its sync
// moved, or a person changed it — and every member tells its dashboards.
const invalidateKnowledge = "knowledge"

// knowledgePushGap is the least time between two rounds of pushes, in
// nanoseconds: a sync indexing page after page moves its source many times a
// second, and a dashboard needs to see its counts move, not every page.
// Atomic, because a test shortens it while other hubs in the process drain.
var knowledgePushGap atomic.Int64

func init() { knowledgePushGap.Store(int64(750 * time.Millisecond)) }

// knowledgeNotice names a source that changed. A deleted source is named with
// the scope and owner it had, which decide who could see it, since nothing is
// left to read them from.
type knowledgeNotice struct {
	ID      int64  `json:"id"`
	Deleted bool   `json:"deleted,omitempty"`
	Scope   string `json:"scope,omitempty"`
	Owner   string `json:"owner,omitempty"`
	// local marks a change made on this member, which the drain also tells
	// the other members of.
	local bool
}

// knowledgePushState is what this member owes its dashboards.
type knowledgePushState struct {
	mu       sync.Mutex
	owed     map[int64]knowledgeNotice
	draining bool
}

// knowledgeChanged owes source id's dashboards a push: its sync moved, or a
// person changed it, on this member.
func (s *Server) knowledgeChanged(id int64) {
	if id > 0 {
		s.oweKnowledge(knowledgeNotice{ID: id, local: true})
	}
}

// knowledgeGone tells the dashboards that could see src that it was deleted.
func (s *Server) knowledgeGone(src knowledge.Source) {
	s.oweKnowledge(knowledgeNotice{ID: src.ID, Deleted: true, Scope: src.Scope, Owner: src.Owner, local: true})
}

// onBusKnowledge is a notice from another member: its change, for this
// member's dashboards.
func (s *Server) onBusKnowledge(ev hubcluster.Event) {
	var n knowledgeNotice
	if err := ev.Decode(&n); err == nil && n.ID > 0 {
		n.local = false
		s.oweKnowledge(n)
	}
}

// oweKnowledge records n and starts a drain unless one runs. A deletion
// stays owed over a later change of the same id, which can only be a stale
// one.
func (s *Server) oweKnowledge(n knowledgeNotice) {
	st := &s.knowledgePush
	st.mu.Lock()
	if st.owed == nil {
		st.owed = map[int64]knowledgeNotice{}
	}
	if prev, ok := st.owed[n.ID]; ok {
		if prev.Deleted {
			n = prev
		}
		n.local = n.local || prev.local
	}
	st.owed[n.ID] = n
	start := !st.draining
	st.draining = true
	st.mu.Unlock()
	if start {
		go s.drainKnowledgePushes()
	}
}

// drainKnowledgePushes delivers what is owed, a round at a time, until nothing
// is: what was owed while a round ran is the next round's.
func (s *Server) drainKnowledgePushes() {
	st := &s.knowledgePush
	defer func() {
		if v := recover(); v != nil {
			s.log().Error(logger.EventKnowledge, 0, "knowledge: push to dashboards panicked",
				map[string]interface{}{"panic": fmt.Sprint(v)})
			st.mu.Lock()
			st.draining = false
			st.mu.Unlock()
		}
	}()
	for {
		st.mu.Lock()
		owed := st.owed
		st.owed = nil
		if len(owed) == 0 {
			st.draining = false
			st.mu.Unlock()
			return
		}
		st.mu.Unlock()
		for _, n := range owed {
			if n.local {
				s.publishInvalidate(invalidateKnowledge, n)
			}
		}
		s.deliverKnowledge(owed)
		time.Sleep(time.Duration(knowledgePushGap.Load()))
	}
}

// knowledgeStreamPrincipal is the person behind a stream opened with c, as
// the knowledge routes see a request of theirs — the credential read as it
// stands now, like hubHealthMayRead's. false: it has ended, or it is no
// credential where sign-on requires one, and the stream is told nothing.
func (s *Server) knowledgeStreamPrincipal(c streamCredential) (knowledge.Principal, bool) {
	var user *oidcauth.Identity
	var tok *apitoken.Token
	switch {
	case c.tokenID != "":
		t, err := s.recheckToken(c.tokenID)
		if err != nil {
			return knowledge.Principal{}, false
		}
		tok = t
	case c.sessionHash != "":
		rec, st := s.OIDC.CheckSession(c.sessionHash)
		if st != oidcauth.SessionLive {
			return knowledge.Principal{}, false
		}
		id := rec.Identity
		user = &id
	case c.static:
		if _, retired := s.ownStaticTokenRetirement(); retired {
			return knowledge.Principal{}, false
		}
	default:
		if s.oidcEnabled() {
			return knowledge.Principal{}, false
		}
	}
	who := user
	if tok != nil {
		who = identityFromOwner(tok.OwnerBinding())
	}
	identity := ""
	if who != nil {
		identity = secretbroker.NormalizeOwner(who.OwnerKey())
	}
	return knowledge.Principal{Identity: identity, Decide: s.recipientGrant(user, tok).decide}, true
}

// knowledgePush is a knowledge_source message: the source as its recipient
// sees it, or word that one they could see was deleted.
type knowledgePush struct {
	Source  *knowledgeSourceView `json:"source,omitempty"`
	ID      int64                `json:"id"`
	Deleted bool                 `json:"deleted,omitempty"`
}

// deliverKnowledge sends each owed source to every dashboard of this member
// that may see it, rendered for that dashboard.
func (s *Server) deliverKnowledge(owed map[int64]knowledgeNotice) {
	s.hubMu.Lock()
	var sockets []*hubClient
	for _, clients := range s.hubClients {
		for hc := range clients {
			sockets = append(sockets, hc)
		}
	}
	s.hubMu.Unlock()
	s.mu.Lock()
	streams := make([]*sseClient, 0, len(s.clients))
	for c := range s.clients {
		streams = append(streams, c)
	}
	s.mu.Unlock()
	if len(sockets) == 0 && len(streams) == 0 {
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		return
	}
	defer db.Close()
	svc := knowledge.New(db, knowledge.WithEmbeddings(s.knowledgeEmbeddings()))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// One verdict per credential: every stream it opened sees the same.
	access := map[streamCredential]*knowledge.Access{}
	accessFor := func(c streamCredential) *knowledge.Access {
		acc, seen := access[c]
		if !seen {
			if p, ok := s.knowledgeStreamPrincipal(c); ok {
				acc = svc.For(p)
			}
			access[c] = acc
		}
		return acc
	}
	for id, n := range owed {
		src := knowledge.Source{ID: id, Scope: n.Scope, Owner: n.Owner}
		if !n.Deleted {
			src, err = svc.Peek(ctx, id)
			if errors.Is(err, knowledge.ErrNotFound) {
				// Deleted since: the deletion's own notice tells whoever
				// could see it.
				continue
			}
			if err != nil {
				s.log().Warn(logger.EventKnowledge, 0, "knowledge: read a source to push",
					map[string]interface{}{"source": id, "error": err.Error()})
				continue
			}
		}
		rendered := map[streamCredential]json.RawMessage{}
		render := func(c streamCredential) json.RawMessage {
			if data, seen := rendered[c]; seen {
				return data
			}
			var data json.RawMessage
			if acc := accessFor(c); acc != nil && acc.CanSee(src) {
				msg := knowledgePush{ID: id, Deleted: n.Deleted}
				if !n.Deleted {
					view := knowledgeSourceViewOf(acc, src)
					msg.Source = &view
				}
				if raw, err := json.Marshal(msg); err == nil {
					data = raw
				}
			}
			rendered[c] = data
			return data
		}
		s.sendKnowledgePush(sockets, streams, render)
	}
}

// sendKnowledgePush sends each socket and stream still connected what render
// makes for its credential, when that is anything.
func (s *Server) sendKnowledgePush(sockets []*hubClient, streams []*sseClient,
	render func(streamCredential) json.RawMessage) {
	type send struct {
		hc   *hubClient
		data json.RawMessage
	}
	var sends []send
	for _, hc := range sockets {
		if data := render(hc.cred); data != nil {
			sends = append(sends, send{hc, data})
		}
	}
	if len(sends) > 0 {
		s.hubMu.Lock()
		present := map[*hubClient]bool{}
		for _, clients := range s.hubClients {
			for hc := range clients {
				present[hc] = true
			}
		}
		for _, w := range sends {
			if present[w.hc] {
				s.sendOrLag(w.hc, wsMessage{Type: "knowledge_source", Data: w.data})
			}
		}
		s.hubMu.Unlock()
	}
	type sseSend struct {
		c    *sseClient
		data json.RawMessage
	}
	var sseSends []sseSend
	for _, c := range streams {
		if data := render(c.cred); data != nil {
			sseSends = append(sseSends, sseSend{c, data})
		}
	}
	if len(sseSends) > 0 {
		s.mu.Lock()
		for _, e := range sseSends {
			if _, still := s.clients[e.c]; still {
				s.sendSSEOrLag(e.c, sseEvent{Event: "knowledge_source", Data: string(e.data)})
			}
		}
		s.mu.Unlock()
	}
}
