package ui

// A long-lived connection ends when the credential that opened it does
// (Task 20398).
//
// A request is authenticated once and is over. A dashboard WebSocket, an SSE
// stream and a sandbox terminal are authenticated once and then stay open for
// hours, and nothing asked again whether the credential behind them still
// stood. They re-checked runtime denies and memberships on their keepalive
// tick, not the credential — so a session revoked by an administrator, ended
// by its user everywhere, signed out, expired, idle, refused by the identity
// provider or revoked from a shell left every stream it had opened running,
// and so did a revoked or expired API token. A sandbox terminal was worse: its
// re-check re-ran the authorization of its original request, which once the
// session row was gone carried no session, and so resolved to the static
// token's allow-all.
//
// # What is recorded
//
// Each stream records at open which credential admitted it: the session, by
// the hash the session store and the bus name it by; the API token, by id; or
// the static bearer token, which only the auth middleware can know and which
// it marks at the moment the token matched. A re-check asks about that
// credential and no other. Nothing infers "static token" from a session that
// is missing: a session stream whose session is gone is closed, never
// re-authorized as the deployment. And since Task 20406 the static token ends
// too, when it is retired (static_token.go).
//
// # When it is asked
//
//   - On the stream's own keepalive tick, beside the runtime-deny check. The
//     fallback, since it needs nothing to have been announced.
//   - At once when this hub hears that a session changed — oidcauth's
//     OnCacheInvalidate — or that a token was revoked, and when the cluster
//     bus carries either from another member or from the CLI. A session
//     "changed" also when its claims were refreshed, which is why the notice
//     triggers a re-check and never a close.
//
// The re-check is the request path's verdict (oidcauth.CheckSession,
// apitoken.Manager.Recheck): a stream ends exactly when a request carrying its
// credential would be refused. Asking does not count as the user being
// active, so an unattended tab's stream cannot keep its session alive.
//
// # How it ends
//
// The client is taken out of its room before it is told, as one evicted from
// a project is (members.go). A WebSocket is sent a credential_ended message
// naming the reason — session_ended, token_revoked or static_token_retired —
// and closed with 1008 and the same reason; an SSE stream gets a terminal credential_ended event; a
// terminal gets a closed frame and a 1008.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// streamCredential is the credential a long-lived connection was opened with.
// It is comparable, so one verdict serves every stream a credential opened.
type streamCredential struct {
	// sessionHash is oidcauth.HashSessionID of the session cookie.
	sessionHash string
	// tokenID is the API token's public id.
	tokenID string
	// static marks the hub's static bearer token, set from the auth
	// middleware's own record of having matched it (admittedByStaticToken).
	static bool
}

// none reports a stream opened with no credential at all — a hub with neither
// sign-on nor a static token, where there is nothing to revoke.
func (c streamCredential) none() bool {
	return c.sessionHash == "" && c.tokenID == "" && !c.static
}

// revocable reports whether anything can end the credential: a session, an
// API token, and since Task 20406 the static token, by retiring it. No
// credential cannot be revoked at all.
func (c streamCredential) revocable() bool {
	return c.sessionHash != "" || c.tokenID != "" || c.static
}

// kind names the credential for a log line.
func (c streamCredential) kind() string {
	switch {
	case c.sessionHash != "":
		return "session"
	case c.tokenID != "":
		return "api_token"
	case c.static:
		return "static_token"
	}
	return "none"
}

type staticTokenCtxKey struct{}

// admitStaticToken marks r as admitted on the hub's static bearer token.
// Called by the auth middleware at the moment the token matched, which is the
// only place that knows: everywhere else, a request without a session is just
// a request without a session.
func admitStaticToken(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), staticTokenCtxKey{}, true))
}

// admittedByStaticToken reports whether the auth middleware admitted r on the
// static bearer token.
func admittedByStaticToken(r *http.Request) bool {
	if r == nil {
		return false
	}
	v, _ := r.Context().Value(staticTokenCtxKey{}).(bool)
	return v
}

// streamCredentialFor records the credential r was admitted with. The session
// lookup counts as use, which is right: opening a stream is the user acting.
func (s *Server) streamCredentialFor(r *http.Request) streamCredential {
	var c streamCredential
	if tok := tokenFromRequest(r); tok != nil {
		c.tokenID = tok.ID
	}
	if s.oidcEnabled() {
		if rec, ok := s.OIDC.SessionFromRequest(r); ok {
			c.sessionHash = rec.ID
		}
	}
	c.static = admittedByStaticToken(r)
	return c
}

// streamUnauthenticated reports a stream that must not open: sign-on is on, so
// every request the gate admitted carried a session, a token or the static
// token, and one that now carries none had its session end between the gate
// and here. Opened anyway it would have no identity to filter by and nothing
// to re-check — every project, for as long as the tab stayed open.
func (s *Server) streamUnauthenticated(c streamCredential) bool {
	return s.oidcEnabled() && c.none()
}

// refuseUnauthenticatedStream answers a stream streamUnauthenticated refused,
// the way the gate answers a request with no credential.
func refuseUnauthenticatedStream(w http.ResponseWriter) {
	setSignInHint(w)
	jsonErr(w, "authentication required", http.StatusUnauthorized)
}

// streamEnd is why the hub ends a stream it holds open.
type streamEnd struct {
	// code is what a client acts on: empty when the stream's identity lost
	// the project (access_withdrawn, Task 20366), streamEndSession or
	// streamEndToken when the credential that opened it stopped being valid.
	code string
	// cause narrows code: for a session gone, expired or idle; for a token
	// revoked, expired, deleted or unverifiable.
	cause string
	// message is for a person.
	message string
}

// The close reasons of a stream whose credential ended. Distinct from the
// withdrawal's, so a client can tell "sign in again" from "this project is no
// longer yours".
const (
	streamEndSession = "session_ended"
	streamEndToken   = "token_revoked"
	// streamEndStaticToken: the static token that opened the stream was
	// retired (Task 20406).
	streamEndStaticToken = "static_token_retired"
)

// credentialEnded reports whether the credential a stream was opened with has
// stopped being valid, and why. The static token ends when it is retired; no
// credential never ends.
func (s *Server) credentialEnded(c streamCredential) (streamEnd, bool) {
	if c.sessionHash != "" {
		if _, st := s.OIDC.CheckSession(c.sessionHash); st != oidcauth.SessionLive {
			return sessionStreamEnd(st), true
		}
	}
	if c.tokenID != "" {
		if _, err := s.recheckToken(c.tokenID); err != nil {
			return tokenStreamEnd(err), true
		}
	}
	if c.static {
		if rec, retired := s.ownStaticTokenRetirement(); retired {
			return staticTokenStreamEnd(rec), true
		}
	}
	return streamEnd{}, false
}

// staticTokenStreamEnd is why a stream the static token opened ends: the
// token was retired.
func staticTokenStreamEnd(rec statedb.RetiredStaticTokenRow) streamEnd {
	return streamEnd{
		code:  streamEndStaticToken,
		cause: "retired",
		message: fmt.Sprintf("The static token this connection was opened with was retired on %s by %s.",
			rec.RetiredAt.UTC().Format(time.RFC3339), rec.RetiredBy),
	}
}

// recheckToken re-reads the token a stream was opened with.
func (s *Server) recheckToken(id string) (*apitoken.Token, error) {
	mgr, err := s.tokenManager()
	if err != nil {
		return nil, err
	}
	return mgr.Recheck(id)
}

func sessionStreamEnd(st oidcauth.SessionState) streamEnd {
	e := streamEnd{code: streamEndSession, cause: string(st)}
	switch st {
	case oidcauth.SessionExpired:
		e.message = "Your session reached its maximum lifetime. Sign in again to continue."
	case oidcauth.SessionIdle:
		e.message = "Your session ended after a period of inactivity. Sign in again to continue."
	default:
		e.cause = string(oidcauth.SessionGone)
		e.message = "Your session was ended. Sign in again to continue."
	}
	return e
}

func tokenStreamEnd(err error) streamEnd {
	e := streamEnd{code: streamEndToken}
	switch {
	case errors.Is(err, apitoken.ErrRevoked):
		e.cause, e.message = "revoked", "The API token this connection was opened with was revoked."
	case errors.Is(err, apitoken.ErrExpired):
		e.cause, e.message = "expired", "The API token this connection was opened with has expired."
	case errors.Is(err, apitoken.ErrNotFound):
		e.cause, e.message = "deleted", "The API token this connection was opened with no longer exists."
	default:
		e.cause, e.message = "unverifiable", "The API token this connection was opened with could not be verified."
	}
	return e
}

// credentialEndedPayload is the data of a credential_ended message or event.
func credentialEndedPayload(end streamEnd) map[string]string {
	return map[string]string{"reason": end.code, "cause": end.cause, "message": end.message}
}

// closeStream ends a socket for the reason its kick carries.
func closeStream(ctx context.Context, conn *websocket.Conn, end streamEnd) {
	if end.code == "" {
		closeWithdrawn(ctx, conn, end.message)
		return
	}
	closeCredentialEnded(ctx, conn, end)
}

// closeCredentialEnded ends a socket whose credential ended: a
// credential_ended message saying why, then a 1008 close carrying the reason.
// The message comes first for the reason closeWithdrawn gives: a browser often
// reports the close as 1006 and loses the reason.
func closeCredentialEnded(ctx context.Context, conn *websocket.Conn, end streamEnd) {
	if raw, err := json.Marshal(credentialEndedPayload(end)); err == nil {
		if msg, err := json.Marshal(wsMessage{Type: "credential_ended", Data: raw}); err == nil {
			_ = wsWrite(ctx, conn, msg)
		}
	}
	_ = conn.Close(websocket.StatusPolicyViolation, end.code)
}

// endSSE writes the event an SSE stream ends with. A stream whose credential
// ended is told so; one withdrawn from a project ends without a word, as it
// always has.
func endSSE(w http.ResponseWriter, flusher http.Flusher, end streamEnd) {
	if end.code == "" {
		return
	}
	if raw, err := json.Marshal(credentialEndedPayload(end)); err == nil {
		_ = writeSSE(w, flusher, "event: credential_ended\ndata: %s\n\n", raw)
	}
}

// logCredentialEnded records a stream closed because its credential ended.
// The session hash and token id are public identifiers, not credentials: they
// are what `cloop hub session list` and the tokens panel print.
func (s *Server) logCredentialEnded(transport string, c streamCredential, end streamEnd) {
	data := map[string]interface{}{"reason": end.code, "cause": end.cause, "credential": c.kind()}
	if c.sessionHash != "" {
		data["session"] = c.sessionHash
	}
	if c.tokenID != "" {
		data["token"] = c.tokenID
	}
	s.log().Warn(logger.EventAuthz, 0, "closing a "+transport+" whose credential has ended", data)
}

// ── authority from a recorded credential ────────────────────────────────────

// credentialAuthority re-resolves who a stream acts as from the credential it
// recorded: the session's identity as the session row holds it now — claims
// refreshed since the stream opened included — or the token as its row holds
// it now. ok is false when the credential has ended, with end saying why, and
// for no credential on a hub with sign-on, which cannot be resolved to anybody
// (end then carries no reason).
//
// One read of the credential serves both the verdict and the authority. Asked
// as two questions, a revocation landing between them closed a terminal for
// the wrong reason: the first read found the token live, the second found
// nothing to authorize.
func (s *Server) credentialAuthority(c streamCredential) (user *oidcauth.Identity, tok *apitoken.Token, end streamEnd, ok bool) {
	switch {
	case c.sessionHash != "":
		rec, st := s.OIDC.CheckSession(c.sessionHash)
		if st != oidcauth.SessionLive {
			return nil, nil, sessionStreamEnd(st), false
		}
		id := rec.Identity
		return &id, nil, streamEnd{}, true
	case c.tokenID != "":
		t, err := s.recheckToken(c.tokenID)
		if err != nil {
			return nil, nil, tokenStreamEnd(err), false
		}
		return identityFromOwner(t.OwnerBinding()), t, streamEnd{}, true
	case c.static:
		if rec, retired := s.ownStaticTokenRetirement(); retired {
			return nil, nil, staticTokenStreamEnd(rec), false
		}
		return nil, nil, streamEnd{}, true
	}
	// No credential: a hub without sign-on or a static token, where every
	// caller is the local operator. On a hub with sign-on nothing is admitted
	// this way, so a stream that recorded none cannot be answered for.
	return nil, nil, streamEnd{}, !s.oidcEnabled()
}

// credentialGrant is the authority a resolved credential holds. Explicit about
// the static token: the bypass is granted because the stream recorded that it
// was opened with it, never because no session was found.
func (s *Server) credentialGrant(c streamCredential, user *oidcauth.Identity, tok *apitoken.Token) *grant {
	switch {
	case tok != nil:
		return &grant{server: s, token: tok}
	case c.sessionHash != "":
		if user == nil {
			return nil // decide on a nil grant denies
		}
		return s.recipientGrant(user, nil)
	case c.static:
		return &grant{server: s, bypass: authz.SourceStaticToken}
	case !s.oidcEnabled():
		return &grant{server: s, bypass: authz.SourceAuthzDisabled}
	}
	return nil
}

// ── push: re-check when a credential is announced to have changed ───────────

// credentialRechecks coalesces the notices that ask for a re-check. A burst —
// a sweep ending a hundred sessions, a bus backlog — becomes one pass on one
// goroutine rather than a goroutine per notice.
type credentialRechecks struct {
	mu       sync.Mutex
	sessions map[string]struct{}
	tokens   map[string]struct{}
	static   bool
	all      bool
	running  bool

	// passes counts completed passes, so a test can wait for one instead of
	// sleeping.
	passes atomic.Uint64
}

// recheckSessionStreams re-checks, off the caller's goroutine, every stream
// opened with the session.
func (s *Server) recheckSessionStreams(sessionID string) {
	if sessionID = strings.TrimSpace(sessionID); sessionID == "" {
		return
	}
	s.queueCredentialRecheck(func(q *credentialRechecks) {
		if q.sessions == nil {
			q.sessions = make(map[string]struct{})
		}
		q.sessions[sessionID] = struct{}{}
	})
}

// recheckTokenStreams re-checks every stream opened with the token.
func (s *Server) recheckTokenStreams(tokenID string) {
	if tokenID = strings.TrimSpace(tokenID); tokenID == "" {
		return
	}
	s.queueCredentialRecheck(func(q *credentialRechecks) {
		if q.tokens == nil {
			q.tokens = make(map[string]struct{})
		}
		q.tokens[tokenID] = struct{}{}
	})
}

// recheckStaticTokenStreams re-checks every stream the static token opened,
// after a retirement (Task 20406).
func (s *Server) recheckStaticTokenStreams() {
	s.queueCredentialRecheck(func(q *credentialRechecks) { q.static = true })
}

// recheckAllCredentialStreams re-checks every stream whose credential can end.
func (s *Server) recheckAllCredentialStreams() {
	s.queueCredentialRecheck(func(q *credentialRechecks) { q.all = true })
}

func (s *Server) queueCredentialRecheck(add func(*credentialRechecks)) {
	q := &s.credRechecks
	q.mu.Lock()
	add(q)
	start := !q.running
	q.running = true
	q.mu.Unlock()
	if start {
		go s.runCredentialRechecks()
	}
}

// runCredentialRechecks drains the queue, one eviction pass per batch, and
// exits once a pass finds nothing new queued behind it.
func (s *Server) runCredentialRechecks() {
	q := &s.credRechecks
	for {
		q.mu.Lock()
		sessions, tokens, static, all := q.sessions, q.tokens, q.static, q.all
		q.sessions, q.tokens, q.static, q.all = nil, nil, false, false
		if len(sessions) == 0 && len(tokens) == 0 && !static && !all {
			q.running = false
			q.mu.Unlock()
			return
		}
		q.mu.Unlock()
		func() {
			defer recoverGoroutine("credential stream re-check")
			s.evictEndedCredentialStreams(func(c streamCredential) bool {
				if !c.revocable() {
					return false
				}
				if all || (static && c.static) {
					return true
				}
				if _, ok := sessions[c.sessionHash]; ok && c.sessionHash != "" {
					return true
				}
				_, ok := tokens[c.tokenID]
				return ok && c.tokenID != ""
			})
		}()
		q.passes.Add(1)
	}
}

// evictEndedCredentialStreams closes every live stream match selects whose
// credential has ended — dashboard WebSockets in every room, the landing
// page's included, SSE streams, and sandbox terminals.
//
// Modelled on evictWithdrawnStreams: each client is taken out of its room
// before it is told to close, so nothing broadcast after this point is queued
// for it, and its writer checks the kick ahead of anything already queued. The
// verdicts are reached with no broadcast lock held — they read the session
// and token stores — and once per credential, however many streams it opened.
func (s *Server) evictEndedCredentialStreams(match func(streamCredential) bool) {
	type wsStream struct {
		hc      *hubClient
		workDir string
	}
	var sockets []wsStream
	s.hubMu.Lock()
	for workDir, clients := range s.hubClients {
		for hc := range clients {
			if match(hc.cred) {
				sockets = append(sockets, wsStream{hc, workDir})
			}
		}
	}
	s.hubMu.Unlock()
	var streams []*sseClient
	s.mu.Lock()
	for c := range s.clients {
		if match(c.cred) {
			streams = append(streams, c)
		}
	}
	s.mu.Unlock()
	terminals := s.attachStreamsMatching(match)

	verdicts := map[streamCredential]*streamEnd{}
	ended := func(c streamCredential) (streamEnd, bool) {
		v, seen := verdicts[c]
		if !seen {
			if end, gone := s.credentialEnded(c); gone {
				v = &end
			}
			verdicts[c] = v
		}
		if v == nil {
			return streamEnd{}, false
		}
		return *v, true
	}

	type closingWS struct {
		wsStream
		end streamEnd
	}
	var closedWS []closingWS
	for _, k := range sockets {
		if end, gone := ended(k.hc.cred); gone {
			closedWS = append(closedWS, closingWS{k, end})
		}
	}
	type closingSSE struct {
		c   *sseClient
		end streamEnd
	}
	var closedSSE []closingSSE
	for _, c := range streams {
		if end, gone := ended(c.cred); gone {
			closedSSE = append(closedSSE, closingSSE{c, end})
		}
	}
	type closingTerminal struct {
		t   *attachStream
		end streamEnd
	}
	var closedTerminals []closingTerminal
	for _, t := range terminals {
		if end, gone := ended(t.cred); gone {
			closedTerminals = append(closedTerminals, closingTerminal{t, end})
		}
	}

	if len(closedWS) > 0 {
		s.hubMu.Lock()
		for _, k := range closedWS {
			room := s.hubClients[k.workDir]
			if _, still := room[k.hc]; !still {
				continue // gone on its own meanwhile
			}
			delete(room, k.hc)
			if len(room) == 0 {
				delete(s.hubClients, k.workDir)
			}
			select {
			case k.hc.kick <- k.end:
			default:
			}
		}
		s.hubMu.Unlock()
	}
	if len(closedSSE) > 0 {
		s.mu.Lock()
		for _, k := range closedSSE {
			if _, still := s.clients[k.c]; !still {
				continue
			}
			delete(s.clients, k.c)
			select {
			case k.c.kick <- k.end:
			default:
			}
		}
		s.mu.Unlock()
	}
	for _, k := range closedTerminals {
		select {
		case k.t.kick <- k.end:
		default:
		}
	}

	rooms := map[string]bool{}
	for _, k := range closedWS {
		s.logCredentialEnded("WebSocket stream", k.hc.cred, k.end)
		rooms[k.workDir] = true
	}
	for _, k := range closedSSE {
		s.logCredentialEnded("SSE stream", k.c.cred, k.end)
	}
	for _, k := range closedTerminals {
		s.logCredentialEnded("sandbox terminal", k.t.cred, k.end)
	}
	for workDir := range rooms {
		s.broadcastPresence(workDir)
	}
}

// ── sandbox terminals ───────────────────────────────────────────────────────

// attachStream is one open sandbox terminal, registered so a revocation can
// reach it as it reaches a dashboard stream.
type attachStream struct {
	cred streamCredential
	kick chan streamEnd
}

// attachStreamSet is the hub's open terminals.
type attachStreamSet struct {
	mu sync.Mutex
	m  map[*attachStream]struct{}
}

func (s *Server) registerAttachStream(cred streamCredential) *attachStream {
	t := &attachStream{cred: cred, kick: make(chan streamEnd, 1)}
	s.attachStreams.mu.Lock()
	if s.attachStreams.m == nil {
		s.attachStreams.m = make(map[*attachStream]struct{})
	}
	s.attachStreams.m[t] = struct{}{}
	s.attachStreams.mu.Unlock()
	return t
}

func (s *Server) unregisterAttachStream(t *attachStream) {
	s.attachStreams.mu.Lock()
	delete(s.attachStreams.m, t)
	s.attachStreams.mu.Unlock()
}

func (s *Server) attachStreamsMatching(match func(streamCredential) bool) []*attachStream {
	s.attachStreams.mu.Lock()
	defer s.attachStreams.mu.Unlock()
	var out []*attachStream
	for t := range s.attachStreams.m {
		if match(t.cred) {
			out = append(out, t)
		}
	}
	return out
}

// ── what this hub hears ─────────────────────────────────────────────────────

// onSessionChanged is the authenticator's OnCacheInvalidate on every hub
// (InstallOIDCHooks): the other members are told, and this hub's own streams
// opened with the session are re-checked.
func (s *Server) onSessionChanged(sessionID string) {
	s.publishInvalidate(invalidateSession, map[string]string{"session_hash": sessionID})
	s.recheckSessionStreams(sessionID)
}

// onTokenRevoked is the token manager's revoke hook (tokenManager).
func (s *Server) onTokenRevoked(tokenID string) {
	s.publishInvalidate(invalidateToken, map[string]string{"token_id": tokenID})
	s.recheckTokenStreams(tokenID)
}

// announceTokensRevoked is onTokenRevoked for tokens revoked behind the
// manager's back — offboarding writes them in its credential transaction.
func (s *Server) announceTokensRevoked(tokenIDs []string) {
	for _, id := range tokenIDs {
		s.onTokenRevoked(id)
	}
}

// ── announcements from outside the cluster ──────────────────────────────────

// AnnounceSessionsEnded posts the bus event a hub member publishes when a
// session ends, for a writer that is not a member: `cloop hub session revoke`
// and `cloop hub user offboard`, which delete session rows directly. Every
// member reading the bus drops the sessions from its cache and closes the
// streams and terminals they opened within its poll interval. all names every
// session at once, for a revocation of all of them.
//
// A failure is returned for the caller to report, never fatal to the
// revocation, which has already happened: a member that misses the event
// stops honouring the session once its cache ages out, and closes its streams
// at their next keepalive re-check after that.
func AnnounceSessionsEnded(db *statedb.DB, origin string, sessionIDs []string, all bool) error {
	if all {
		return appendInvalidations(db, origin, invalidateSession, []any{map[string]bool{"all": true}})
	}
	payloads := make([]any, 0, len(sessionIDs))
	for _, id := range sessionIDs {
		if id = strings.TrimSpace(id); id != "" {
			payloads = append(payloads, map[string]string{"session_hash": id})
		}
	}
	return appendInvalidations(db, origin, invalidateSession, payloads)
}

// AnnounceTokensRevoked is AnnounceSessionsEnded for API tokens and glasses
// links revoked by a writer that is not a hub member — `cloop hub token
// revoke` and `cloop hub user offboard`. Without it a member still closes the
// streams at their next keepalive re-check, which reads the token row.
func AnnounceTokensRevoked(db *statedb.DB, origin string, tokenIDs []string) error {
	payloads := make([]any, 0, len(tokenIDs))
	for _, id := range tokenIDs {
		if id = strings.TrimSpace(id); id != "" {
			payloads = append(payloads, map[string]string{"token_id": id})
		}
	}
	return appendInvalidations(db, origin, invalidateToken, payloads)
}

func appendInvalidations(db *statedb.DB, origin, key string, payloads []any) error {
	if db == nil {
		return errors.New("no database")
	}
	if len(payloads) == 0 {
		return nil
	}
	now := time.Now()
	rows := make([]statedb.HubEventRow, 0, len(payloads))
	for _, p := range payloads {
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		rows = append(rows, statedb.HubEventRow{
			Origin:    origin,
			Topic:     busTopicInvalidate,
			Key:       key,
			Payload:   string(raw),
			CreatedAt: now,
		})
	}
	_, err := db.AppendHubEvents(rows)
	return err
}
