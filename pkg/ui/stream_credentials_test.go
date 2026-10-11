package ui

// A stream ends when the credential that opened it does (Task 20398).
//
// TestMembers_RevocationClosesALiveSocket proves the shape for a membership:
// the client is taken out of its room, told why, and closed with 1008. These
// tests hold every long-lived channel to the same shape for every way a
// credential ends — and prove the two things that must not end one: a claim
// refresh, which announces itself exactly as a revocation does, and any
// session or token ending, for a stream opened with the static token. That
// one ends only when the static token is retired (Task 20406).
//
// None of them starts a run.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// credStaticToken is the fixture hub's static bearer token.
const credStaticToken = "static-deployment-token-20398"

// credFixture is one hub with single sign-on on a clock the test drives, a
// static token, the hooks `cloop ui` installs, and an administrator signed in.
type credFixture struct {
	srv  *Server
	ts   *httptest.Server
	idp  *uiFakeIdP
	clk  *clusterRenewClock
	mgr  *apitoken.Manager
	root *http.Client
}

func newCredFixture(t *testing.T) *credFixture {
	t.Helper()
	idp := newUIFakeIdP(t)
	idp.issueRefresh = "rt-stream"
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, credStaticToken)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	clk := &clusterRenewClock{}
	cfg := oidcauth.Config{
		Enabled:      true,
		Issuer:       idp.server.URL,
		ClientID:     "cloop-dashboard",
		ClientSecret: "test-secret",
		RedirectURL:  ts.URL + "/auth/callback",
		AdminEmails:  []string{rootEmail},
		SessionTTL:   3 * time.Hour,
		IdleTimeout:  time.Hour,
		// Revalidation is driven by hand (RevalidateDue), never by a janitor.
		RefreshInterval: time.Minute,
		// Off, so the root session's privileged calls never refresh claims
		// against a provider configured for somebody else.
		MaxClaimAge: -1,
		Clock:       clk.now,
	}
	srv.InstallOIDCHooks(&cfg)
	auth, err := oidcauth.New(cfg)
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth
	srv.RPS, srv.Burst = 10000, 10000

	mgr, err := srv.tokenManager()
	if err != nil {
		t.Fatalf("tokenManager: %v", err)
	}
	mgr.SetClock(clk.now) // before any token is used
	t.Cleanup(srv.closeTokenManager)

	f := &credFixture{srv: srv, ts: ts, idp: idp, clk: clk, mgr: mgr}
	f.root = f.signIn(t, rootEmail, "sub-root")
	return f
}

// signIn completes a sign-in as email and returns the browser that holds it.
func (f *credFixture) signIn(t *testing.T, email, sub string) *http.Client {
	t.Helper()
	f.idp.email, f.idp.sub, f.idp.name = email, sub, strings.Split(email, "@")[0]
	c := jarClient(t)
	login(t, c, f.ts)
	return c
}

// call sends a request with a JSON body, returning the status.
func (f *credFixture) call(t *testing.T, c *http.Client, method, path string, hdr http.Header) int {
	t.Helper()
	req, err := http.NewRequest(method, f.ts.URL+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// mintToken mints an API token that expires an hour from the fixture's now.
func (f *credFixture) mintToken(t *testing.T) apitoken.Minted {
	t.Helper()
	minted, err := f.mgr.Mint(apitoken.MintOptions{
		Name: "stream-ci", Roles: []string{"operator"}, CreatedBy: rootEmail,
		ExpiresAt: f.clk.now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return minted
}

func bearerHeader(token string) http.Header {
	return http.Header{"Authorization": []string{"Bearer " + token}}
}

// openStreamCredentials lists the credential of every WebSocket and SSE
// stream the hub holds open.
func (s *Server) openStreamCredentials() []streamCredential {
	var out []streamCredential
	s.hubMu.Lock()
	for _, clients := range s.hubClients {
		for hc := range clients {
			out = append(out, hc.cred)
		}
	}
	s.hubMu.Unlock()
	s.mu.Lock()
	for c := range s.clients {
		out = append(out, c.cred)
	}
	s.mu.Unlock()
	return out
}

// ── reading a stream from the client's side ─────────────────────────────────

// streamEnding is what a stream said as it ended.
type streamEnding struct {
	told        map[string]string // the credential_ended payload; nil if none came
	closeCode   websocket.StatusCode
	closeReason string
	err         error
}

// liveStream is an open stream read on a goroutine of its own.
type liveStream struct {
	kind string
	done chan streamEnding
	seen chan string // every message type or event name received
}

func (ls *liveStream) note(name string) {
	select {
	case ls.seen <- name:
	default:
	}
}

// awaitEnd waits for the stream to end.
func (ls *liveStream) awaitEnd(t *testing.T, within time.Duration) streamEnding {
	t.Helper()
	select {
	case e := <-ls.done:
		return e
	case <-time.After(within):
		t.Fatalf("the %s stream was still open %s later", ls.kind, within)
		return streamEnding{}
	}
}

// assertOpen fails if the stream ends within d.
func (ls *liveStream) assertOpen(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case e := <-ls.done:
		t.Fatalf("the %s stream ended: told %v, close %d %q, read error %v",
			ls.kind, e.told, e.closeCode, e.closeReason, e.err)
	case <-time.After(d):
	}
}

// awaitMessage waits for a message type or event name.
func (ls *liveStream) awaitMessage(t *testing.T, name string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-ls.seen:
			if got == name {
				return
			}
		case e := <-ls.done:
			t.Fatalf("the %s stream ended waiting for %q: told %v, err %v", ls.kind, name, e.told, e.err)
		case <-deadline:
			t.Fatalf("the %s stream received no %q", ls.kind, name)
		}
	}
}

// openWS dials a dashboard socket as c, presenting hdr.
func (f *credFixture) openWS(t *testing.T, path string, c *http.Client, hdr http.Header) *liveStream {
	t.Helper()
	return openWSAt(t, f.ts.URL, path, c, hdr)
}

// openSSE opens an event stream as c, presenting hdr.
func (f *credFixture) openSSE(t *testing.T, path string, c *http.Client, hdr http.Header) *liveStream {
	t.Helper()
	return openSSEAt(t, f.ts.URL, path, c, hdr)
}

// openWSAt dials the dashboard socket path of the hub at base.
func openWSAt(t *testing.T, base, path string, c *http.Client, hdr http.Header) *liveStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if c == nil {
		c = http.DefaultClient
	}
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(base, "http")+path,
		&websocket.DialOptions{HTTPClient: c, HTTPHeader: hdr})
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	ls := &liveStream{kind: "WebSocket " + path, done: make(chan streamEnding, 1), seen: make(chan string, 512)}
	go func() {
		var e streamEnding
		for {
			_, raw, err := conn.Read(ctx)
			if err != nil {
				var ce websocket.CloseError
				if errors.As(err, &ce) {
					e.closeCode, e.closeReason = ce.Code, ce.Reason
				}
				e.err = err
				ls.done <- e
				return
			}
			var m wsMessage
			if json.Unmarshal(raw, &m) != nil {
				continue
			}
			if m.Type == "credential_ended" {
				_ = json.Unmarshal(m.Data, &e.told)
			}
			ls.note(m.Type)
		}
	}()
	return ls
}

// openSSEAt opens the event stream path of the hub at base.
func openSSEAt(t *testing.T, base, path string, c *http.Client, hdr http.Header) *liveStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET %s = %d", path, resp.StatusCode)
	}
	ls := &liveStream{kind: "SSE " + path, done: make(chan streamEnding, 1), seen: make(chan string, 512)}
	go func() {
		defer resp.Body.Close()
		var e streamEnding
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
		event := ""
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				if event == "credential_ended" {
					_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e.told)
				}
				name := event
				if name == "" {
					name = "message"
				}
				ls.note(name)
			case line == "":
				event = ""
			}
		}
		e.err = sc.Err()
		ls.done <- e
	}()
	return ls
}

// streamChannel is one of the hub's long-lived channels.
type streamChannel struct {
	name string
	open func(t *testing.T, f *credFixture, c *http.Client, hdr http.Header) *liveStream
	// probe makes the hub send this channel something it forwards, and names
	// what the client then receives.
	probe func(f *credFixture) string
}

var credentialChannels = []streamChannel{
	{
		name: "websocket",
		open: func(t *testing.T, f *credFixture, c *http.Client, hdr http.Header) *liveStream {
			return f.openWS(t, "/api/ws", c, hdr)
		},
		probe: func(f *credFixture) string {
			f.srv.deliverToProject(f.srv.WorkDir, wsMessage{Type: "members_update", Data: json.RawMessage(`{}`)})
			return "members_update"
		},
	},
	{
		name: "websocket landing page",
		open: func(t *testing.T, f *credFixture, c *http.Client, hdr http.Header) *liveStream {
			return f.openWS(t, "/api/ws?scope=global", c, hdr)
		},
		probe: func(f *credFixture) string {
			f.srv.deliverToAll(wsMessage{Type: "members_update", Data: json.RawMessage(`{}`)})
			return "members_update"
		},
	},
	{
		name: "sse",
		open: func(t *testing.T, f *credFixture, c *http.Client, hdr http.Header) *liveStream {
			return f.openSSE(t, "/api/events", c, hdr)
		},
		probe: func(f *credFixture) string {
			f.srv.deliverSSE(f.srv.WorkDir, sseEvent{Event: "run_state", Data: `{"running":false}`})
			return "run_state"
		},
	},
	{
		name: "sse projects",
		open: func(t *testing.T, f *credFixture, c *http.Client, hdr http.Header) *liveStream {
			return f.openSSE(t, "/api/projects/events", c, hdr)
		},
		probe: func(f *credFixture) string {
			f.srv.broadcastProjectsUpdate()
			return "projects"
		},
	},
}

// streamSubject is who holds the stream an ending ends.
type streamSubject struct {
	client  *http.Client // the browser, or nil for a token
	header  http.Header
	session string // the session's hash, for a session stream
	token   apitoken.Minted
}

// credentialEnding is one way a credential stops being valid.
type credentialEnding struct {
	name string
	// token: the stream is opened with an API token rather than a session.
	token bool
	// pushed: the hub is told, so the stream must close long before any
	// keepalive — which is set to an hour to prove it. Otherwise only the
	// keepalive's re-check can notice, and it runs every 25ms.
	pushed bool
	end    func(t *testing.T, f *credFixture, s streamSubject)
	reason string
	cause  string
}

var credentialEndings = []credentialEnding{
	{
		name: "admin revoke", pushed: true, reason: streamEndSession, cause: "gone",
		end: func(t *testing.T, f *credFixture, s streamSubject) {
			if code := f.call(t, f.root, http.MethodDelete, "/api/sessions/"+s.session, nil); code != http.StatusOK {
				t.Fatalf("DELETE /api/sessions/{id} = %d", code)
			}
		},
	},
	{
		name: "logout-all", pushed: true, reason: streamEndSession, cause: "gone",
		end: func(t *testing.T, f *credFixture, s streamSubject) {
			// From another browser of the same person: the stolen-laptop case.
			other := f.signIn(t, aliceEmail, "sub-alice")
			if code := f.call(t, other, http.MethodPost, "/api/session/logout-all", nil); code != http.StatusOK {
				t.Fatalf("POST /api/session/logout-all = %d", code)
			}
		},
	},
	{
		name: "sign-out", pushed: true, reason: streamEndSession, cause: "gone",
		end: func(t *testing.T, f *credFixture, s streamSubject) {
			if code := f.call(t, s.client, http.MethodPost, oidcauth.LogoutPath, nil); code != http.StatusOK {
				t.Fatalf("POST %s = %d", oidcauth.LogoutPath, code)
			}
		},
	},
	{
		name: "idle expiry", reason: streamEndSession, cause: string(oidcauth.SessionIdle),
		end: func(t *testing.T, f *credFixture, s streamSubject) {
			// An hour with the stream open and nothing else, in steps the
			// stream's keepalive re-checks between. Those re-checks are not
			// use: one that counted as use would carry the idle clock along
			// with every step and keep the session alive for ever.
			for i := 0; i < 13; i++ {
				f.clk.advance(5 * time.Minute)
				time.Sleep(100 * time.Millisecond)
			}
		},
	},
	{
		name: "absolute expiry", reason: streamEndSession, cause: string(oidcauth.SessionExpired),
		end: func(t *testing.T, f *credFixture, s streamSubject) {
			// In use throughout, so only the ceiling can end it.
			for i := 0; i < 3; i++ {
				f.clk.advance(50 * time.Minute)
				if code := f.call(t, s.client, http.MethodGet, "/api/me", nil); code != http.StatusOK {
					t.Fatalf("GET /api/me while in use = %d", code)
				}
			}
			f.clk.advance(31 * time.Minute) // 3h01m in, 31 minutes idle
		},
	},
	{
		name: "token revoke", token: true, pushed: true, reason: streamEndToken, cause: "revoked",
		end: func(t *testing.T, f *credFixture, s streamSubject) {
			if code := f.call(t, f.root, http.MethodDelete, "/api/tokens/"+s.token.Token.ID, nil); code != http.StatusOK {
				t.Fatalf("DELETE /api/tokens/{id} = %d", code)
			}
		},
	},
	{
		name: "token expiry", token: true, reason: streamEndToken, cause: "expired",
		end: func(t *testing.T, f *credFixture, s streamSubject) {
			f.clk.advance(61 * time.Minute)
		},
	},
}

// streamTicks sets both keepalives for one test.
func streamTicks(t *testing.T, d time.Duration) {
	t.Helper()
	setWSPingTiming(t, d, 10*time.Second)
	setSSEKeepaliveInterval(t, d)
}

// TestStreamCredentials_EveryEndingClosesEveryChannel is the matrix: each way
// a session or token ends closes a stream it opened on each channel, with the
// reason saying which, and takes the client out of the hub's lists.
func TestStreamCredentials_EveryEndingClosesEveryChannel(t *testing.T) {
	for _, ch := range credentialChannels {
		for _, ending := range credentialEndings {
			ch, ending := ch, ending
			t.Run(ch.name+"/"+ending.name, func(t *testing.T) {
				if ending.pushed {
					streamTicks(t, time.Hour)
				} else {
					streamTicks(t, 25*time.Millisecond)
				}
				f := newCredFixture(t)

				var subj streamSubject
				if ending.token {
					subj.token = f.mintToken(t)
					subj.header = bearerHeader(subj.token.Plaintext)
				} else {
					subj.client = f.signIn(t, aliceEmail, "sub-alice")
					subj.session = sessionHashFromJar(t, subj.client, f.ts.URL)
				}
				ls := ch.open(t, f, subj.client, subj.header)
				waitMember(t, "the stream to register", func() bool { return len(f.srv.openStreamCredentials()) == 1 })
				cred := f.srv.openStreamCredentials()[0]
				if ending.token && cred.tokenID != subj.token.Token.ID {
					t.Fatalf("the stream recorded %+v, want the token", cred)
				}
				if !ending.token && cred.sessionHash != subj.session {
					t.Fatalf("the stream recorded %+v, want the session", cred)
				}
				// Open and served, before anything ends.
				ls.awaitMessage(t, ch.probe(f))

				ending.end(t, f, subj)

				got := ls.awaitEnd(t, 5*time.Second)
				if got.told == nil {
					t.Fatalf("the stream ended without a credential_ended message (close %d %q, err %v)",
						got.closeCode, got.closeReason, got.err)
				}
				if got.told["reason"] != ending.reason || got.told["cause"] != ending.cause {
					t.Errorf("told %v, want reason %q cause %q", got.told, ending.reason, ending.cause)
				}
				if got.told["message"] == "" {
					t.Error("the client was told no message to show")
				}
				if strings.HasPrefix(ls.kind, "WebSocket") &&
					(got.closeCode != websocket.StatusPolicyViolation || got.closeReason != ending.reason) {
					t.Errorf("close %d %q, want 1008 %q", got.closeCode, got.closeReason, ending.reason)
				}
				waitMember(t, "the hub to let the stream go", func() bool { return len(f.srv.openStreamCredentials()) == 0 })
			})
		}
	}
}

// TestStreamCredentials_AClaimRefreshDoesNotCloseAStream: a claim refresh is
// announced exactly as a revocation is — the session's cached copy is dropped
// and every listener told — so the announcement must lead to a re-check, and
// the re-check finds the session alive.
func TestStreamCredentials_AClaimRefreshDoesNotCloseAStream(t *testing.T) {
	for _, ch := range credentialChannels {
		ch := ch
		t.Run(ch.name, func(t *testing.T) {
			streamTicks(t, 25*time.Millisecond)
			f := newCredFixture(t)
			// Only alice's session is due: the provider below answers for her.
			alice := f.signIn(t, aliceEmail, "sub-alice")
			hash := sessionHashFromJar(t, alice, f.ts.URL)
			if ok, err := f.srv.OIDC.RevokeSession(sessionHashFromJar(t, f.root, f.ts.URL), "test", ""); err != nil || !ok {
				t.Fatalf("revoke root: %v %v", ok, err)
			}
			ls := ch.open(t, f, alice, nil)
			waitMember(t, "the stream to register", func() bool { return len(f.srv.openStreamCredentials()) == 1 })
			ls.awaitMessage(t, ch.probe(f))

			f.idp.email, f.idp.sub = aliceEmail, "sub-alice"
			f.idp.groups = []string{"moved-teams"}
			f.clk.advance(2 * time.Minute)
			before := f.srv.credRechecks.passes.Load()
			requests := f.idp.refreshRequests
			checked, terminated := f.srv.OIDC.RevalidateDue(context.Background())
			if checked != 1 || terminated != 0 || f.idp.refreshRequests == requests {
				t.Fatalf("RevalidateDue = (%d checked, %d terminated) after %d refreshes, want one refreshed and none ended",
					checked, terminated, f.idp.refreshRequests-requests)
			}
			if rec, st := f.srv.OIDC.CheckSession(hash); st != oidcauth.SessionLive ||
				len(rec.Identity.Groups) != 1 || rec.Identity.Groups[0] != "moved-teams" {
				t.Fatalf("the refresh did not reach the session: %q %v", st, rec.Identity.Groups)
			}
			waitMember(t, "the refresh's re-check to run", func() bool { return f.srv.credRechecks.passes.Load() > before })

			ls.assertOpen(t, 300*time.Millisecond)
			ls.awaitMessage(t, ch.probe(f))
		})
	}
}

// TestStreamCredentials_StaticTokenStreamsEndOnlyWhenItIsRetired: a stream
// opened with the static token recorded that it was, and nothing that ends a
// session or a token reaches it — not a revocation of every session, not a
// token revoked, not every session's clock running out, not a re-check of
// everything. Retiring the static token does: the stream is told why and
// closed with 1008, as any other credential's (Task 20406; it was
// TestStreamCredentials_StaticTokenStreamsAreUnaffected, when the static
// token could not end short of a restart).
func TestStreamCredentials_StaticTokenStreamsEndOnlyWhenItIsRetired(t *testing.T) {
	for _, ch := range credentialChannels {
		ch := ch
		t.Run(ch.name, func(t *testing.T) {
			streamTicks(t, 25*time.Millisecond)
			f := newCredFixture(t)
			alice := f.signIn(t, aliceEmail, "sub-alice")
			minted := f.mintToken(t)

			ls := ch.open(t, f, nil, bearerHeader(credStaticToken))
			waitMember(t, "the stream to register", func() bool { return len(f.srv.openStreamCredentials()) == 1 })
			if cred := f.srv.openStreamCredentials()[0]; !cred.static || cred.sessionHash != "" || cred.tokenID != "" {
				t.Fatalf("the stream recorded %+v, want the static token alone", cred)
			}
			ls.awaitMessage(t, ch.probe(f))

			if code := f.call(t, alice, http.MethodPost, "/api/session/logout-all", nil); code != http.StatusOK {
				t.Fatalf("logout-all = %d", code)
			}
			sessions, err := f.srv.OIDC.ListSessions()
			if err != nil {
				t.Fatal(err)
			}
			for _, rec := range sessions {
				if _, err := f.srv.OIDC.RevokeSession(rec.ID, "test", ""); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.mgr.Revoke(minted.Token.ID); err != nil {
				t.Fatal(err)
			}
			f.clk.advance(4 * time.Hour)
			before := f.srv.credRechecks.passes.Load()
			f.srv.recheckAllCredentialStreams()
			waitMember(t, "a re-check of everything", func() bool { return f.srv.credRechecks.passes.Load() > before })

			ls.assertOpen(t, 300*time.Millisecond)
			ls.awaitMessage(t, ch.probe(f))

			// Retired — by itself, which it may.
			retireViaRoute(t, f.ts.URL, bearerHeader(credStaticToken), false)
			expectStaticTokenEnded(t, ls)
			waitMember(t, "the hub to let the stream go", func() bool { return len(f.srv.openStreamCredentials()) == 0 })
		})
	}
}

// expectStaticTokenEnded asserts a stream ended because the static token that
// opened it was retired.
func expectStaticTokenEnded(t *testing.T, ls *liveStream) {
	t.Helper()
	got := ls.awaitEnd(t, 5*time.Second)
	if got.told["reason"] != streamEndStaticToken || got.told["cause"] != "retired" ||
		!strings.Contains(got.told["message"], "retired") {
		t.Fatalf("the %s ended telling %v (close %d %q, err %v), want static_token_retired",
			ls.kind, got.told, got.closeCode, got.closeReason, got.err)
	}
	if strings.HasPrefix(ls.kind, "WebSocket") &&
		(got.closeCode != websocket.StatusPolicyViolation || got.closeReason != streamEndStaticToken) {
		t.Errorf("close %d %q, want 1008 %q", got.closeCode, got.closeReason, streamEndStaticToken)
	}
}

// TestStreamCredentials_RetiringTheStaticTokenClosesItsStreamsAtOnce: the
// retirement itself ends what the token opened — the keepalives are an hour
// away, so nothing else can — and leaves a session's stream alone.
func TestStreamCredentials_RetiringTheStaticTokenClosesItsStreamsAtOnce(t *testing.T) {
	for _, ch := range credentialChannels {
		ch := ch
		t.Run(ch.name, func(t *testing.T) {
			streamTicks(t, time.Hour)
			f := newCredFixture(t)
			static := ch.open(t, f, nil, bearerHeader(credStaticToken))
			alice := f.signIn(t, aliceEmail, "sub-alice")
			session := ch.open(t, f, alice, nil)
			waitMember(t, "both streams to register", func() bool { return len(f.srv.openStreamCredentials()) == 2 })

			// Retired by an administrator's session this time.
			req, _ := http.NewRequest(http.MethodPost, f.ts.URL+"/api/static-token/retire",
				strings.NewReader(`{"reason":"single sign-on works now"}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := f.root.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("retire = %d", resp.StatusCode)
			}
			expectStaticTokenEnded(t, static)
			session.assertOpen(t, 300*time.Millisecond)
			session.awaitMessage(t, ch.probe(f))
		})
	}
}

// TestAttach_RetiringTheStaticTokenClosesItsTerminal: a sandbox terminal the
// static token opened — the static token's allow-all, the one shell no deny
// binding reaches — closes when the token is retired, at once, with 1008 and
// the reason in the closed frame and the audit trail.
func TestAttach_RetiringTheStaticTokenClosesItsTerminal(t *testing.T) {
	setAttachRecheckInterval(t, time.Hour)
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, credStaticToken, []string{rootEmail})
	t.Cleanup(srv.closeTokenManager)
	ls := openTerminal(t, srv, ts.URL, nil, bearerHeader(credStaticToken))
	ls.assertOpen(t, 200*time.Millisecond)

	retireViaRoute(t, ts.URL, bearerHeader(credStaticToken), false)
	got := ls.awaitEnd(t, 5*time.Second)
	if got.closeCode != websocket.StatusPolicyViolation || got.closeReason != streamEndStaticToken {
		t.Errorf("close %d %q, want 1008 %q", got.closeCode, got.closeReason, streamEndStaticToken)
	}
	if got.told == nil || !strings.Contains(got.told["message"], "retired") {
		t.Errorf("the terminal was told %v, want why", got.told)
	}
	waitMember(t, "the close to be audited", func() bool {
		return strings.Contains(attachCloseDetails(t, srv), streamEndStaticToken)
	})
}

// TestStreamCredentials_NoCredentialIsRefusedUnderSignOn: with sign-on on,
// every request the gate admits carries a session, a token or the static
// token. A stream reaching its handler with none — its session ended between
// the gate and the handler — would have no identity to filter by and nothing
// to re-check, so it is refused rather than opened as nobody in particular.
func TestStreamCredentials_NoCredentialIsRefusedUnderSignOn(t *testing.T) {
	f := newCredFixture(t)
	for _, tc := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/api/ws", f.srv.handleWS},
		{"/api/events", f.srv.handleEvents},
		{"/api/projects/events", f.srv.handleProjectsEvents},
		{"/api/tasks/1/attach", f.srv.handleAttachWS},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.SetPathValue("id", "1")
		rec := httptest.NewRecorder()
		tc.handler(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with no credential = %d, want 401", tc.path, rec.Code)
		}
	}
}

// ── sandbox terminals, end to end ───────────────────────────────────────────

// attachFakeExecutor isolates, and its sessions stay open until closed: enough
// to hold a real terminal open through handleAttachWS.
type attachFakeExecutor struct{ id string }

func (e *attachFakeExecutor) ID() string   { return e.id }
func (e *attachFakeExecutor) Kind() string { return "attach-fake" }
func (e *attachFakeExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer}
}
func (e *attachFakeExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("attach-fake runs nothing")
}
func (e *attachFakeExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *attachFakeExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (e *attachFakeExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("attach-fake runs nothing")
}
func (e *attachFakeExecutor) HealthCheck(context.Context) error { return nil }
func (e *attachFakeExecutor) Attach(context.Context, executor.AttachRequest) (executor.AttachConn, error) {
	return &idleAttachConn{closed: make(chan struct{})}, nil
}

type idleAttachConn struct {
	once   sync.Once
	closed chan struct{}
}

func (c *idleAttachConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}
func (c *idleAttachConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *idleAttachConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *idleAttachConn) Resize(uint16, uint16) error { return nil }

// openTerminal opens a sandbox terminal on task 1 of the hub's own project,
// running on a fake isolating executor, and waits for it to be ready.
func openTerminal(t *testing.T, srv *Server, base string, c *http.Client, hdr http.Header) *liveStream {
	t.Helper()
	execID := "attach-fake-" + strings.ReplaceAll(t.Name(), "/", "-")
	if err := executor.Register(&attachFakeExecutor{id: execID}); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(execID) })
	seedRunningSession(t, srv, srv.WorkDir, execID, "h-"+execID, 1)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if c == nil {
		c = http.DefaultClient
	}
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(base, "http")+"/api/tasks/1/attach",
		&websocket.DialOptions{HTTPClient: c, HTTPHeader: hdr})
	if err != nil {
		t.Fatalf("dial the terminal: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	ls := &liveStream{kind: "sandbox terminal", done: make(chan streamEnding, 1), seen: make(chan string, 64)}
	go func() {
		var e streamEnding
		for {
			_, raw, err := conn.Read(ctx)
			if err != nil {
				var ce websocket.CloseError
				if errors.As(err, &ce) {
					e.closeCode, e.closeReason = ce.Code, ce.Reason
				}
				e.err = err
				ls.done <- e
				return
			}
			var m attachServerMsg
			if json.Unmarshal(raw, &m) != nil {
				continue
			}
			if m.Type == "closed" {
				e.told = map[string]string{"message": m.Message}
			}
			ls.note(m.Type)
		}
	}()
	ls.awaitMessage(t, "ready")
	return ls
}

// attachCloseDetails returns the detail of every sandbox.attach.close event.
func attachCloseDetails(t *testing.T, srv *Server) string {
	t.Helper()
	db, err := statedb.Open(state.DBPath(srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "sandbox.attach.close", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.Payload)
	}
	return b.String()
}

// TestAttach_ARevokedSessionClosesItsTerminal: the terminal a session opened
// closes when the session is revoked — at once, on the revocation's notice,
// with the recheck interval an hour away — and says so, with 1008 and the
// reason in both the closed frame and the audit trail.
func TestAttach_ARevokedSessionClosesItsTerminal(t *testing.T) {
	setAttachRecheckInterval(t, time.Hour)
	srv, base, clients := newAttachFixture(t)
	ls := openTerminal(t, srv, base, clients["admin"], nil)

	hash := sessionHashFromJar(t, clients["admin"], base)
	if ok, err := srv.OIDC.RevokeSession(hash, "security@example.com", ""); err != nil || !ok {
		t.Fatalf("RevokeSession = %v, %v", ok, err)
	}
	got := ls.awaitEnd(t, 5*time.Second)
	if got.closeCode != websocket.StatusPolicyViolation || got.closeReason != streamEndSession {
		t.Errorf("close %d %q, want 1008 %q", got.closeCode, got.closeReason, streamEndSession)
	}
	if got.told == nil || !strings.Contains(got.told["message"], "session") {
		t.Errorf("the terminal was told %v, want why", got.told)
	}
	waitMember(t, "the close to be audited", func() bool {
		return strings.Contains(attachCloseDetails(t, srv), streamEndSession)
	})
}

// TestAttach_ARevokedTokenClosesItsTerminalOnTheRecheck: the fallback. A token
// revoked straight in the database — as a hub that heard nothing would see it
// — is caught by the terminal's own re-check.
func TestAttach_ARevokedTokenClosesItsTerminalOnTheRecheck(t *testing.T) {
	setAttachRecheckInterval(t, 25*time.Millisecond)
	srv, base, _ := newAttachFixture(t)
	mgr, err := srv.tokenManager()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.closeTokenManager)
	minted, err := mgr.Mint(apitoken.MintOptions{Name: "break-glass", Roles: []string{"admin"}, CreatedBy: "root"})
	if err != nil {
		t.Fatal(err)
	}
	ls := openTerminal(t, srv, base, nil, bearerHeader(minted.Plaintext))
	ls.assertOpen(t, 200*time.Millisecond)

	db, err := statedb.Open(state.DBPath(srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.RevokeAPIToken(minted.Token.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	got := ls.awaitEnd(t, 5*time.Second)
	if got.closeCode != websocket.StatusPolicyViolation || got.closeReason != streamEndToken {
		t.Errorf("close %d %q, want 1008 %q", got.closeCode, got.closeReason, streamEndToken)
	}
}
