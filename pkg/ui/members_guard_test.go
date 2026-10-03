package ui

// The ways around a membership rule that an adversarial review of Task 20366
// found, each pinned: a ceiling read from claims the provider had already
// withdrawn, roster writes checked against a cache another writer had moved
// past, sharing switching claim freshness on for a whole hub, a revocation
// landing between a stream's gate and its room, the streams of a removed
// project, who is on the projects page, and what an empty project list costs.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// newStaleClaimsMemberHub is a hub whose session claims are stale the instant
// they are written (MaxClaimAge of a nanosecond, as in
// newClaimFreshnessFixture), so every privileged request re-asserts them at
// the provider — or, when the provider hands out no refresh token, cannot.
// alice owns a project there and is signed in.
func newStaleClaimsMemberHub(t *testing.T, idp *uiFakeIdP, resolver *authz.Resolver) *memberFixture {
	t.Helper()
	t.Setenv(multiui.EnvRoot, t.TempDir())
	srv := New(setupProjectDir(t, cloopGoal, nil), 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:         true,
		Issuer:          idp.server.URL,
		ClientID:        "cloop-dashboard",
		ClientSecret:    "test-secret",
		RedirectURL:     ts.URL + "/auth/callback",
		AdminEmails:     []string{rootEmail},
		RefreshInterval: -1,
		MaxClaimAge:     time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.OIDC = auth
	if resolver != nil {
		srv.Authz = resolver
	}
	if _, err := srv.OpenMemberStore(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.closeMemberStore)
	srv.RPS, srv.Burst = 10000, 10000

	project := setupProjectDir(t, "alice's goal", nil)
	registerOwned(t, project, aliceEmail)
	idp.email, idp.sub, idp.name = aliceEmail, "sub-alice", "alice"
	alice := jarClient(t)
	login(t, alice, ts)
	return &memberFixture{srv: srv, ts: ts, project: project, alice: alice}
}

// TestMembers_TheCeilingIsTheRoleTheProviderAssertsNow: moved from an admin
// group to a maintainer group at the provider, alice's next share is capped at
// maintainer. The gate re-asserts her claims for project.share, and the
// ceiling has to be read from that answer — not from the claims her session
// arrived with, which would let her mint an admin in exactly the window the
// re-assertion exists to close.
func TestMembers_TheCeilingIsTheRoleTheProviderAssertsNow(t *testing.T) {
	idp := newUIFakeIdP(t)
	idp.issueRefresh = "rt-1"
	idp.groups = []string{"admins"}
	resolver, err := authz.New(authz.Config{
		DefaultRole: authz.RoleNone,
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "admins", Role: authz.RoleAdmin},
			{Claim: authz.ClaimGroup, Value: "maintainers", Role: authz.RoleMaintainer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := newStaleClaimsMemberHub(t, idp, resolver)
	members := f.membersURL(t, f.alice)

	idp.groups = []string{"maintainers"}
	if code, body := f.call(t, f.alice, http.MethodPost, members,
		map[string]any{"identity": carolEmail, "role": "admin"}); code != http.StatusForbidden {
		t.Fatalf("a maintainer at the provider granted admin on her session's old claims: %d %v", code, body)
	}
	if _, found := f.srv.memberStore().Lookup(f.project, carolEmail); found {
		t.Fatal("the refused grant was written")
	}
	// At the role she holds now, she still shares.
	if code, body := f.call(t, f.alice, http.MethodPost, members,
		map[string]any{"identity": carolEmail, "role": "maintainer"}); code != http.StatusCreated {
		t.Fatalf("a maintainer shares at maintainer: %d %v", code, body)
	}
}

// TestMembers_SharingLeavesClaimFreshnessAloneWithoutRoleMappings: on a hub
// with admin_emails alone, privileged actions are granted by the deployment,
// not by claims, so a provider that issues no refresh token was never a
// problem there. Sharing one project must not change that for everybody.
func TestMembers_SharingLeavesClaimFreshnessAloneWithoutRoleMappings(t *testing.T) {
	idp := newUIFakeIdP(t) // no refresh token: claims can never be re-asserted
	f := newStaleClaimsMemberHub(t, idp, nil)
	if f.srv.authzActive() {
		t.Fatal("test assumption broken: role mappings are configured")
	}
	if code, body := f.call(t, f.alice, http.MethodGet, "/api/sessions", nil); code != http.StatusOK {
		t.Fatalf("test assumption broken: a privileged read before sharing: %d %v", code, body)
	}
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members,
		map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}
	if code, body := f.call(t, f.alice, http.MethodGet, "/api/sessions", nil); code != http.StatusOK {
		t.Errorf("after one project was shared, a privileged read demands claims the provider cannot re-assert: %d %v", code, body)
	}
	if code, body := f.call(t, f.alice, http.MethodPost, members,
		map[string]any{"identity": carolEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Errorf("a second share: %d %v", code, body)
	}
}

// TestMembers_ARosterChangeIsCheckedAgainstTheTable: another hub or the CLI
// changes the roster, and this hub's cache has not caught up. A change made
// against the cache must not re-admit someone removed meanwhile, overwrite
// someone added meanwhile, or reach someone raised above the caller meanwhile.
func TestMembers_ARosterChangeIsCheckedAgainstTheTable(t *testing.T) {
	f := newMemberFixture(t, true)
	// A cache only an explicit reload moves, so it stays behind the table
	// for as long as the test needs — as it can for up to its TTL in use.
	f.srv.closeMemberStore()
	f.srv.members.opts = []projectmember.Option{projectmember.WithTTL(time.Hour)}
	store, err := f.srv.OpenMemberStore()
	if err != nil {
		t.Fatal(err)
	}
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members,
		map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}
	// The other writer, on its own handle to the same table.
	other, err := statedb.Open(state.DBPath(f.srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	// Removed elsewhere: a PATCH (a reason edit) is not a way back in.
	if _, err := other.DeleteProjectMember(f.project, bobEmail, nil); err != nil {
		t.Fatal(err)
	}
	if _, cached := store.Lookup(f.project, bobEmail); !cached {
		t.Fatal("test assumption broken: the cache already saw the removal")
	}
	bob := "?identity=" + url.QueryEscape(bobEmail)
	if code, body := f.call(t, f.alice, http.MethodPatch, members+bob,
		map[string]any{"reason": "still pairing"}); code != http.StatusNotFound {
		t.Errorf("a PATCH on a member removed elsewhere: %d %v, want 404", code, body)
	}
	if _, err := other.GetProjectMember(f.project, bobEmail); !errors.Is(err, statedb.ErrProjectMemberNotFound) {
		t.Fatalf("the PATCH re-admitted a removed member (%v)", err)
	}

	// Added elsewhere: an add is a conflict, not an overwrite.
	if _, _, err := other.PutProjectMember(statedb.ProjectMemberRow{
		ProjectPath: f.project, IdentityKey: carolEmail, Role: string(authz.RoleOperator)}, nil); err != nil {
		t.Fatal(err)
	}
	if code, body := f.call(t, f.alice, http.MethodPost, members,
		map[string]any{"identity": carolEmail, "role": "viewer"}); code != http.StatusConflict {
		t.Errorf("adding a member added elsewhere: %d %v, want 409", code, body)
	}
	if row, err := other.GetProjectMember(f.project, carolEmail); err != nil || row.Role != string(authz.RoleOperator) {
		t.Fatalf("the add overwrote a membership made elsewhere: %+v %v", row, err)
	}

	// Raised elsewhere above alice, a maintainer: out of her reach, whatever
	// her cache says.
	if err := store.Refresh(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.PutProjectMember(statedb.ProjectMemberRow{
		ProjectPath: f.project, IdentityKey: carolEmail, Role: string(authz.RoleAdmin)}, nil); err != nil {
		t.Fatal(err)
	}
	if m, _ := store.Lookup(f.project, carolEmail); m.Role != authz.RoleOperator {
		t.Fatalf("test assumption broken: the cache holds carol as %s", m.Role)
	}
	carol := "?identity=" + url.QueryEscape(carolEmail)
	if code, body := f.call(t, f.alice, http.MethodDelete, members+carol, nil); code != http.StatusForbidden {
		t.Errorf("a maintainer removed an admin her cache listed as an operator: %d %v", code, body)
	}
	if code, body := f.call(t, f.alice, http.MethodPatch, members+carol,
		map[string]any{"role": "viewer"}); code != http.StatusForbidden {
		t.Errorf("a maintainer demoted an admin her cache listed as an operator: %d %v", code, body)
	}
	if row, err := other.GetProjectMember(f.project, carolEmail); err != nil || row.Role != string(authz.RoleAdmin) {
		t.Fatalf("the admin's membership was changed: %+v %v", row, err)
	}
}

// TestMembers_ARevocationBetweenTheGateAndTheRoomStillCloses: a stream is
// authorized at its gate and joins its project's room a moment later. A
// revocation landing in between sets off an eviction pass that cannot find the
// stream yet, and nothing would ever look again — so the stream asks once
// more after it has joined.
func TestMembers_ARevocationBetweenTheGateAndTheRoomStillCloses(t *testing.T) {
	f := newMemberFixture(t, true)
	// Every eviction pass the store sets off is announced here once done.
	passes := make(chan struct{}, 8)
	f.srv.closeMemberStore()
	f.srv.members.opts = []projectmember.Option{projectmember.WithOnChange(func(c projectmember.Change) {
		f.srv.onProjectMembersChange(c)
		passes <- struct{}{}
	})}
	store, err := f.srv.OpenMemberStore()
	if err != nil {
		t.Fatal(err)
	}
	waitPass := func(what string) {
		t.Helper()
		select {
		case <-passes:
		case <-time.After(10 * time.Second):
			t.Fatalf("no eviction pass after %s", what)
		}
	}
	members := f.membersURL(t, f.alice)

	for _, transport := range []string{"websocket", "sse"} {
		t.Run(transport, func(t *testing.T) {
			if code, body := f.call(t, f.alice, http.MethodPost, members,
				map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
				t.Fatalf("share: %d %v", code, body)
			}
			waitPass("the share")
			// The revocation, and the whole of its eviction pass, land
			// after the gate and before the room: the order in which
			// that pass misses the stream.
			var once sync.Once
			f.srv.streamJoinHook = func(workDir string) {
				if workDir != f.project {
					return
				}
				once.Do(func() {
					if _, err := store.Revoke(f.project, bobEmail, nil); err != nil {
						t.Error(err)
					}
					waitPass("the revocation")
				})
			}
			defer func() { f.srv.streamJoinHook = nil }()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if transport == "websocket" {
				conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.ts.URL, "http")+"/api/ws?project_idx=0",
					&websocket.DialOptions{HTTPClient: f.bob})
				if err != nil {
					t.Fatalf("bob opens the project's socket: %v", err)
				}
				defer conn.CloseNow()
				told := false
				for {
					_, raw, err := conn.Read(ctx)
					if err != nil {
						var ce websocket.CloseError
						if !errors.As(err, &ce) || ce.Code != websocket.StatusPolicyViolation {
							t.Fatalf("the socket ended with %v, want a 1008 close", err)
						}
						break
					}
					var m wsMessage
					_ = json.Unmarshal(raw, &m)
					if m.Type != "access_withdrawn" {
						t.Fatalf("a socket revoked before it joined its room was sent %q", m.Type)
					}
					told = true
				}
				if !told {
					t.Error("the socket was closed without an access_withdrawn message")
				}
			} else {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.ts.URL+"/api/events?project_idx=0", nil)
				resp, err := f.bob.Do(req)
				if err != nil {
					t.Fatalf("bob opens the project's event stream: %v", err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatalf("the event stream stayed open after its membership was revoked: %v (read %q)", err, body)
				}
				if strings.Contains(string(body), "data:") {
					t.Fatalf("an event stream revoked before it joined its room was sent %q", body)
				}
			}
			waitMember(t, "the stream to leave the room", func() bool { return f.srv.roomSize(f.project) == 0 })
		})
	}
}

// TestMembers_RemovingTheProjectClosesItsStreams: rooms are keyed by path, so
// a stream left attached to a removed project would be sent whatever is
// registered at that path next. Its owner's streams go too, membership or
// not — this project has no members, so no membership change is there to
// close anything.
func TestMembers_RemovingTheProjectClosesItsStreams(t *testing.T) {
	f := newMemberFixture(t, true)
	i := f.idx(t, f.alice, f.project)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wsBase := "ws" + strings.TrimPrefix(f.ts.URL, "http")
	var socks []*websocket.Conn
	for _, c := range []*http.Client{f.alice, f.root} {
		idx := f.idx(t, c, f.project)
		conn, _, err := websocket.Dial(ctx, wsBase+"/api/ws?project_idx="+itoa(idx), &websocket.DialOptions{HTTPClient: c})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.CloseNow()
		if !readUntil(ctx, t, conn, func(m wsMessage) bool { return m.Type == "task_update" }) {
			t.Fatal("the socket received no state")
		}
		socks = append(socks, conn)
	}
	waitMember(t, "both sockets in the project's room", func() bool { return f.srv.roomSize(f.project) == 2 })

	sse, err := http.NewRequestWithContext(ctx, http.MethodGet, f.ts.URL+"/api/events?project_idx="+itoa(i), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.alice.Do(sse)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	waitMember(t, "the event stream to register", func() bool {
		f.srv.mu.Lock()
		defer f.srv.mu.Unlock()
		for c := range f.srv.clients {
			if c.workDir == f.project {
				return true
			}
		}
		return false
	})

	if code, body := f.call(t, f.alice, http.MethodDelete, "/api/projects/"+itoa(i), nil); code != http.StatusOK {
		t.Fatalf("alice removes the project: %d %v", code, body)
	}
	for n, conn := range socks {
		var ce websocket.CloseError
		for {
			_, _, err := conn.Read(ctx)
			if err == nil {
				continue
			}
			if !errors.As(err, &ce) {
				t.Fatalf("socket %d ended without a close frame: %v", n, err)
			}
			break
		}
		if ce.Code != websocket.StatusPolicyViolation {
			t.Errorf("socket %d closed with %d (%q), want 1008", n, ce.Code, ce.Reason)
		}
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Errorf("the removed project's event stream did not end: %v", err)
	}
	if n := f.srv.roomSize(f.project); n != 0 {
		t.Errorf("%d sockets are still in the removed project's room", n)
	}
}

// TestMembers_AMemberIsNotToldWhoElseIsOnTheProjectsPage: who has the projects
// page open is hub-wide knowledge. A member whose authority is one shared
// project gets their live project list there, and nobody's name.
func TestMembers_AMemberIsNotToldWhoElseIsOnTheProjectsPage(t *testing.T) {
	f := newMemberFixture(t, true)
	if code, body := f.call(t, f.alice, http.MethodPost, f.membersURL(t, f.alice),
		map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wsBase := "ws" + strings.TrimPrefix(f.ts.URL, "http")
	root, _, err := websocket.Dial(ctx, wsBase+"/api/ws?scope=global", &websocket.DialOptions{HTTPClient: f.root})
	if err != nil {
		t.Fatal(err)
	}
	defer root.CloseNow()
	waitMember(t, "root on the projects page", func() bool { return f.srv.roomSize(hubRoomGlobal) == 1 })
	bob, _, err := websocket.Dial(ctx, wsBase+"/api/ws?scope=global", &websocket.DialOptions{HTTPClient: f.bob})
	if err != nil {
		t.Fatal(err)
	}
	defer bob.CloseNow()

	// Root, who reads the hub, is told bob arrived — so the announcement
	// went out after bob joined, and bob would have had it too.
	if !readUntil(ctx, t, root, func(m wsMessage) bool {
		return m.Type == "presence" && strings.Contains(string(m.Data), `"name":"bob"`)
	}) {
		t.Fatal("root was not told who is on the projects page")
	}
	// A projects push, queued behind anything bob was sent before it.
	f.srv.broadcastProjectsUpdate()
	for {
		_, raw, err := bob.Read(ctx)
		if err != nil {
			t.Fatalf("bob's socket ended before the projects push: %v", err)
		}
		var m wsMessage
		_ = json.Unmarshal(raw, &m)
		if m.Type == "presence" {
			t.Fatalf("a member was told who is on the projects page: %s", m.Data)
		}
		if m.Type == "projects" {
			break
		}
	}
}

// TestMembers_AnEmptyListIsCheapAndStillRecorded: a signed-in identity with no
// project to read is answered with an empty list, without the hub reloading
// every project's state to arrive at it, and the refusal behind it stays on
// the audit trail. Its live stream is refused outright.
func TestMembers_AnEmptyListIsCheapAndStillRecorded(t *testing.T) {
	f := newMemberFixture(t, true)
	reloaded := func() bool {
		f.srv.projMu.RLock()
		defer f.srv.projMu.RUnlock()
		return f.srv.projStatuses != nil
	}
	forget := func() {
		f.srv.projMu.Lock()
		f.srv.projStatuses, f.srv.projEntries = nil, nil
		f.srv.projMu.Unlock()
	}

	forget()
	if code, paths := f.projects(t, f.carol); code != http.StatusOK || len(paths) != 0 {
		t.Fatalf("carol, who can read nothing, lists %d %v; want an empty list", code, paths)
	}
	if reloaded() {
		t.Error("a caller with no project made the hub reload every project's state")
	}
	f.projects(t, f.alice)
	if !reloaded() {
		t.Fatal("test assumption broken: a project list does not reload the statuses")
	}
	// Bounded: an admitted stream would never end on its own.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.ts.URL+"/api/projects/events", nil)
	resp, err := f.carol.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a caller with no project opened the projects stream: %d, want 403", resp.StatusCode)
	}

	log, err := eventlog.Open(f.srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	events, _, err := log.List(eventlog.AuditFilter{EventType: string(auditaction.ActionAuthzDenied)})
	if err != nil {
		t.Fatal(err)
	}
	recorded := false
	for _, ev := range events {
		if ev.Actor == carolEmail && strings.Contains(ev.Payload, `"path":"/api/projects"`) {
			recorded = true
		}
	}
	if !recorded {
		t.Errorf("carol's empty list left no denial on the trail (%d denials recorded)", len(events))
	}
}
