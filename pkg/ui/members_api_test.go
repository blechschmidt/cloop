package ui

// Project members (Task 20366): the REST surface, what a membership grants on
// a hub with role mappings and on one without, visibility, live streams, the
// glasses view, features, and project removal.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	aliceEmail = "alice@example.com"
	bobEmail   = "bob@example.com"
	carolEmail = "carol@example.com"
	rootEmail  = "root@example.com"
)

// memberFixture is one hub with single sign-on, a project alice owns, and a
// signed-in client per person.
type memberFixture struct {
	srv     *Server
	ts      *httptest.Server
	project string // alice's project

	alice, bob, carol, root *http.Client
}

// newMemberFixture builds the hub. With rbac, role mappings are configured the
// way :8888's are — a default role of "none" — plus a global maintainer
// binding for alice; without, the hub runs on admin_emails alone.
func newMemberFixture(t *testing.T, rbac bool, extra ...authz.Binding) *memberFixture {
	t.Helper()
	// A registry of its own: these tests assert on indices.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", []string{rootEmail})
	project := setupProjectDir(t, "alice's goal", nil)
	registerOwned(t, project, aliceEmail)
	if rbac {
		resolver, err := authz.New(authz.Config{
			DefaultRole: authz.RoleNone,
			AdminEmails: []string{rootEmail},
			Bindings: append([]authz.Binding{
				{Claim: authz.ClaimEmail, Value: aliceEmail, Role: authz.RoleMaintainer},
			}, extra...),
		})
		if err != nil {
			t.Fatal(err)
		}
		srv.Authz = resolver
	}
	if _, err := srv.OpenMemberStore(); err != nil {
		t.Fatalf("OpenMemberStore: %v", err)
	}
	t.Cleanup(srv.closeMemberStore)
	// The test drives several sessions and many requests from one address.
	srv.RPS, srv.Burst = 10000, 10000

	f := &memberFixture{srv: srv, ts: ts, project: project}
	as := func(email, sub string, groups ...string) *http.Client {
		// Logins are sequential, so the IdP's claims can be flipped
		// between them (as newRBACFixture does).
		idp.email, idp.sub, idp.name, idp.groups = email, sub, strings.Split(email, "@")[0], groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	f.alice = as(aliceEmail, "sub-alice")
	f.bob = as(bobEmail, "sub-bob", "engineers")
	f.carol = as(carolEmail, "sub-carol")
	f.root = as(rootEmail, "sub-root")
	return f
}

// call sends a JSON request and decodes a JSON object answer.
func (f *memberFixture) call(t *testing.T, c *http.Client, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, f.ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	if len(out) == 0 && len(raw) > 0 {
		out["_raw"] = string(raw)
	}
	return resp.StatusCode, out
}

// projects returns the paths of c's project list, or nil when refused.
func (f *memberFixture) projects(t *testing.T, c *http.Client) (int, []string) {
	t.Helper()
	code, body := f.call(t, c, http.MethodGet, "/api/projects", nil)
	var paths []string
	if list, ok := body["projects"].([]any); ok {
		for _, p := range list {
			if m, ok := p.(map[string]any); ok {
				paths = append(paths, m["path"].(string))
			}
		}
	}
	return code, paths
}

// idx is c's index of path, or -1.
func (f *memberFixture) idx(t *testing.T, c *http.Client, path string) int {
	t.Helper()
	_, paths := f.projects(t, c)
	for i, p := range paths {
		if p == path {
			return i
		}
	}
	return -1
}

func (f *memberFixture) membersURL(t *testing.T, c *http.Client) string {
	t.Helper()
	i := f.idx(t, c, f.project)
	if i < 0 {
		t.Fatalf("the project is not in the caller's list")
	}
	return "/api/projects/" + itoa(i) + "/members"
}

// TestMembers_ShareOnAHubWhoseDefaultRoleIsNone is the flow on :8888's
// configuration: an identity with no role at all is admitted to one project at
// one role, works there, and is refused everything else — including adding
// members, which takes a maintainer.
func TestMembers_ShareOnAHubWhoseDefaultRoleIsNone(t *testing.T) {
	f := newMemberFixture(t, true)

	// Before sharing, bob has no role anywhere: an empty list — not even
	// the unowned hub project, which his role does not cover — and no
	// project to open.
	if code, paths := f.projects(t, f.bob); code != http.StatusOK || len(paths) != 0 {
		t.Fatalf("bob lists %d %v before anything is shared, want an empty list", code, paths)
	}
	if code, _ := f.call(t, f.bob, http.MethodGet, "/api/state", nil); code != http.StatusNotFound {
		t.Errorf("bob reads the hub's own project: %d, want 404", code)
	}

	members := f.membersURL(t, f.alice)
	code, body := f.call(t, f.alice, http.MethodPost, members,
		map[string]any{"identity": "Bob@Example.com", "role": "operator", "reason": "pairing on payments"})
	if code != http.StatusCreated || body["identity"] != bobEmail || body["role"] != "operator" {
		t.Fatalf("alice shares with bob: %d %v", code, body)
	}

	// Bob's list is exactly the project shared with him — not the unowned
	// hub project he has no role on — and it is a multi-project list, so his
	// dashboard addresses it by index rather than falling back to the hub's own.
	code, body = f.call(t, f.bob, http.MethodGet, "/api/projects", nil)
	if code != http.StatusOK || body["multi_project"] != true {
		t.Fatalf("bob's project list: %d %v", code, body)
	}
	if _, paths := f.projects(t, f.bob); len(paths) != 1 || paths[0] != f.project {
		t.Fatalf("bob sees %v, want only %s", paths, f.project)
	}
	if code, body := f.call(t, f.bob, http.MethodGet, "/api/state?project_idx=0", nil); code != http.StatusOK {
		t.Fatalf("bob reads the shared project: %d %v", code, body)
	}
	if code, body := f.call(t, f.bob, http.MethodGet, "/api/me?project_idx=0", nil); code != http.StatusOK || body["role"] != "operator" {
		t.Fatalf("bob's role on the shared project: %d %v", code, body)
	}
	if code, body := f.call(t, f.bob, http.MethodPost, "/api/tasks?project_idx=0", map[string]any{"title": "from bob"}); code >= 300 {
		t.Fatalf("an operator member adds a task: %d %v", code, body)
	}
	// An operator may not reshape the project or share it.
	if code, _ := f.call(t, f.bob, http.MethodPost, "/api/projects/0/members",
		map[string]any{"identity": carolEmail, "role": "viewer"}); code != http.StatusForbidden {
		t.Errorf("an operator member added a member: %d, want 403", code)
	}
	if code, _ := f.call(t, f.bob, http.MethodDelete, "/api/projects/0", nil); code != http.StatusForbidden {
		t.Errorf("an operator member deleted the project: %d, want 403", code)
	}
	// Nothing hub-wide came with the membership.
	if code, _ := f.call(t, f.bob, http.MethodGet, "/api/executors", nil); code != http.StatusForbidden {
		t.Errorf("a member read the fleet: %d, want 403", code)
	}

	// The roster, as bob sees it.
	code, body = f.call(t, f.bob, http.MethodGet, "/api/projects/0/members", nil)
	if code != http.StatusOK || body["can_share"] != false || body["owner"] != aliceEmail {
		t.Fatalf("bob reads the roster: %d %v", code, body)
	}
	if list := body["members"].([]any); len(list) != 1 || list[0].(map[string]any)["self"] != true {
		t.Fatalf("bob's roster rows: %v", body["members"])
	}

	// Carol is on nothing and sees nothing.
	if code, _ := f.call(t, f.carol, http.MethodGet, "/api/state?project_idx=0", nil); code != http.StatusNotFound {
		t.Errorf("carol reads index 0: %d, want 404", code)
	}

	// The ceiling and the input rules.
	for name, c := range map[string]struct {
		body map[string]any
		want int
	}{
		"above the granter's role": {map[string]any{"identity": carolEmail, "role": "admin"}, http.StatusForbidden},
		"oneself":                  {map[string]any{"identity": aliceEmail, "role": "viewer"}, http.StatusBadRequest},
		"not an identity":          {map[string]any{"identity": "carol", "role": "viewer"}, http.StatusBadRequest},
		"no such role":             {map[string]any{"identity": carolEmail, "role": "owner"}, http.StatusBadRequest},
		"already a member":         {map[string]any{"identity": bobEmail, "role": "viewer"}, http.StatusConflict},
	} {
		if code, body := f.call(t, f.alice, http.MethodPost, members, c.body); code != c.want {
			t.Errorf("%s: %d %v, want %d", name, code, body, c.want)
		}
	}

	// Narrowed to viewer, bob can no longer add tasks.
	bob := "?identity=" + url.QueryEscape(bobEmail)
	if code, body := f.call(t, f.alice, http.MethodPatch, members+bob, map[string]any{"role": "viewer"}); code != http.StatusOK || body["previous_role"] != "operator" {
		t.Fatalf("alice narrows bob: %d %v", code, body)
	}
	if code, _ := f.call(t, f.bob, http.MethodPost, "/api/tasks?project_idx=0", map[string]any{"title": "again"}); code != http.StatusForbidden {
		t.Errorf("a viewer member added a task: %d, want 403", code)
	}

	// Removed, the project is gone from bob's list and from his reach.
	if code, body := f.call(t, f.alice, http.MethodDelete, members+bob, nil); code != http.StatusOK {
		t.Fatalf("alice removes bob: %d %v", code, body)
	}
	if code, paths := f.projects(t, f.bob); code != http.StatusOK || len(paths) != 0 {
		t.Errorf("after removal bob lists %d %v, want an empty list", code, paths)
	}
	// And no live channel: the landing page's stream needs a project to read.
	if code, _ := f.call(t, f.bob, http.MethodGet, "/api/events?scope=global", nil); code != http.StatusForbidden {
		t.Errorf("a caller who can read nothing opened the global stream: %d, want 403", code)
	}
	if code, _ := f.call(t, f.bob, http.MethodGet, "/api/state?project_idx=0", nil); code != http.StatusNotFound {
		t.Errorf("after removal bob reads index 0: %d, want 404", code)
	}
	if code, _ := f.call(t, f.alice, http.MethodDelete, members+bob, nil); code != http.StatusNotFound {
		t.Errorf("removing a non-member: %d, want 404", code)
	}

	// Every change is on the control plane's trail, committed with it.
	db, err := statedb.Open(state.DBPath(f.srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "project_member"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ev := range evs {
		got = append(got, ev.EventType)
		if ev.Actor != aliceEmail || ev.EntityID != f.project+"|"+bobEmail {
			t.Errorf("audit row %s: actor %q entity %q", ev.EventType, ev.Actor, ev.EntityID)
		}
	}
	want := []string{string(auditaction.ActionProjectMemberGrant), string(auditaction.ActionProjectMemberChange),
		string(auditaction.ActionProjectMemberRevoke)}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("audit rows %v, want %v", got, want)
	}
}

// TestMembers_NeverDemote: a membership only adds. Bob holds operator
// everywhere through his group; a viewer membership on alice's project shows
// it to him and leaves him an operator there. An admin keeps admin.
func TestMembers_NeverDemote(t *testing.T) {
	f := newMemberFixture(t, true, authz.Binding{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator})
	if i := f.idx(t, f.bob, f.project); i >= 0 {
		t.Fatal("bob sees alice's project before it is shared with him")
	}
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}
	i := f.idx(t, f.bob, f.project)
	if i < 0 {
		t.Fatal("the membership did not make the project visible")
	}
	if code, body := f.call(t, f.bob, http.MethodGet, "/api/me?project_idx="+itoa(i), nil); body["role"] != "operator" {
		t.Errorf("a viewer membership demoted an operator to %v (%d)", body["role"], code)
	}
	if code, body := f.call(t, f.bob, http.MethodPost, "/api/tasks?project_idx="+itoa(i), map[string]any{"title": "x"}); code >= 300 {
		t.Errorf("an operator with a viewer membership was refused a task: %d %v", code, body)
	}
	// Root, an admin, granted viewer by name, keeps everything.
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": rootEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share with root: %d %v", code, body)
	}
	ri := f.idx(t, f.root, f.project)
	if code, body := f.call(t, f.root, http.MethodGet, "/api/me?project_idx="+itoa(ri), nil); body["role"] != "admin" {
		t.Errorf("an admin's role on the project = %v (%d)", body["role"], code)
	}
}

// TestMembers_HubWithoutRoleMappings: with admin_emails alone, everyone holds
// everything on what they can see, and a membership is a member's whole
// authority on a project they could not otherwise see — a viewer share means
// view. Grants that could add nothing are refused with the reason.
func TestMembers_HubWithoutRoleMappings(t *testing.T) {
	f := newMemberFixture(t, false)
	if f.srv.authzActive() {
		t.Fatal("test assumption broken: role mappings are configured")
	}
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}
	i := f.idx(t, f.bob, f.project)
	if i < 0 {
		t.Fatal("the membership did not make the project visible")
	}
	if code, _ := f.call(t, f.bob, http.MethodGet, "/api/state?project_idx="+itoa(i), nil); code != http.StatusOK {
		t.Errorf("a viewer member reads: %d", code)
	}
	if code, _ := f.call(t, f.bob, http.MethodPost, "/api/tasks?project_idx="+itoa(i), map[string]any{"title": "x"}); code != http.StatusForbidden {
		t.Errorf("a viewer member added a task on a hub without role mappings: %d, want 403", code)
	}
	if code, body := f.call(t, f.bob, http.MethodGet, "/api/me?project_idx="+itoa(i), nil); body["role"] != "viewer" {
		t.Errorf("bob's role there = %v (%d), want viewer", body["role"], code)
	}
	// Everywhere else bob still holds what the deployment gives everyone.
	hub := f.idx(t, f.bob, f.srv.primaryProjectPath())
	if code, body := f.call(t, f.bob, http.MethodPost, "/api/tasks?project_idx="+itoa(hub), map[string]any{"title": "y"}); code >= 300 {
		t.Errorf("the membership narrowed bob on the unowned hub project: %d %v", code, body)
	}
	// And the owner, also named, keeps full access — refused as pointless.
	if code, _ := f.call(t, f.root, http.MethodPost, members, map[string]any{"identity": aliceEmail, "role": "viewer"}); code != http.StatusConflict {
		t.Errorf("naming the owner: %d, want 409", code)
	}
	if code, _ := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": rootEmail, "role": "viewer"}); code != http.StatusConflict {
		t.Errorf("naming an admin: %d, want 409", code)
	}
	hubMembers := "/api/projects/" + itoa(f.idx(t, f.alice, f.srv.primaryProjectPath())) + "/members"
	if code, _ := f.call(t, f.alice, http.MethodPost, hubMembers, map[string]any{"identity": carolEmail, "role": "viewer"}); code != http.StatusConflict {
		t.Errorf("sharing an unowned project: %d, want 409", code)
	}
	_, body := f.call(t, f.alice, http.MethodGet, members, nil)
	if note, _ := body["note"].(string); !strings.Contains(note, "No role mappings") {
		t.Errorf("the roster does not say what a role means here: %q", note)
	}
	// Bob leaves; the project is gone from his list.
	if code, body := f.call(t, f.bob, http.MethodDelete, "/api/projects/"+itoa(i)+"/members/self", nil); code != http.StatusOK || body["left"] != true {
		t.Fatalf("bob leaves: %d %v", code, body)
	}
	if f.idx(t, f.bob, f.project) >= 0 {
		t.Error("bob still sees the project he left")
	}
}

// TestMembers_RevocationClosesALiveSocket: a removed member's open stream
// stops receiving the project at once — it is taken out of the room and
// closed with 1008 — and their landing page is pushed a list without it.
func TestMembers_RevocationClosesALiveSocket(t *testing.T) {
	f := newMemberFixture(t, true)
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wsBase := "ws" + strings.TrimPrefix(f.ts.URL, "http")
	project, _, err := websocket.Dial(ctx, wsBase+"/api/ws?project_idx=0", &websocket.DialOptions{HTTPClient: f.bob})
	if err != nil {
		t.Fatalf("bob opens the project's socket: %v", err)
	}
	defer project.CloseNow()
	landing, _, err := websocket.Dial(ctx, wsBase+"/api/ws?scope=global", &websocket.DialOptions{HTTPClient: f.bob})
	if err != nil {
		t.Fatalf("bob opens the landing page's socket: %v", err)
	}
	defer landing.CloseNow()

	// The connect burst proves the socket is in the project's room.
	if !readUntil(ctx, t, project, func(m wsMessage) bool { return m.Type == "task_update" }) {
		t.Fatal("bob's project socket received no state")
	}
	waitMember(t, "bob in the project's room", func() bool { return f.srv.roomSize(f.project) > 0 })

	if code, body := f.call(t, f.alice, http.MethodDelete, members+"?identity="+url.QueryEscape(bobEmail), nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, body)
	}

	// The project socket is told why, then closed with a policy violation,
	// bounded. The message is what a browser acts on: see closeWithdrawn.
	var closeErr websocket.CloseError
	told := false
	for {
		_, raw, err := project.Read(ctx)
		if err == nil {
			var m wsMessage
			if json.Unmarshal(raw, &m) == nil && m.Type == "access_withdrawn" {
				told = true
			}
			continue // and frames already queued before the revocation
		}
		if !errors.As(err, &closeErr) {
			t.Fatalf("the project socket ended without a close frame: %v", err)
		}
		break
	}
	if !told {
		t.Error("the socket was closed without an access_withdrawn message")
	}
	if closeErr.Code != websocket.StatusPolicyViolation {
		t.Errorf("close code %d (%q), want 1008", closeErr.Code, closeErr.Reason)
	}
	if f.srv.roomSize(f.project) != 0 {
		t.Error("the revoked client is still in the project's room")
	}

	// The landing page is pushed a project list without it.
	if !readUntil(ctx, t, landing, func(m wsMessage) bool {
		if m.Type != "projects" {
			return false
		}
		var p struct {
			Projects []struct {
				Path string `json:"path"`
			} `json:"projects"`
		}
		if json.Unmarshal(m.Data, &p) != nil {
			return false
		}
		for _, x := range p.Projects {
			if x.Path == f.project {
				return false
			}
		}
		return true
	}) {
		t.Fatal("bob's landing page was not pushed a list without the project")
	}
}

// readUntil reads messages until match holds, the socket ends, or ctx ends.
func readUntil(ctx context.Context, t *testing.T, c *websocket.Conn, match func(wsMessage) bool) bool {
	t.Helper()
	for {
		_, raw, err := c.Read(ctx)
		if err != nil {
			return false
		}
		var m wsMessage
		if json.Unmarshal(raw, &m) == nil && match(m) {
			return true
		}
	}
}

// waitMember polls cond for up to 10 s.
func waitMember(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// roomSize counts this hub's WebSocket clients attached to workDir.
func (s *Server) roomSize(workDir string) int {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	return len(s.hubClients[workDir])
}

// TestMembers_GlassesLinkFollowsTheMembership: a link minted by a member
// reaches the shared project, and stops the moment the membership goes.
func TestMembers_GlassesLinkFollowsTheMembership(t *testing.T) {
	f := newMemberFixture(t, true)
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": bobEmail, "role": "operator"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}
	code, body := f.call(t, f.bob, http.MethodPost, "/api/glasses/link", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("bob mints a glasses link: %d %v", code, body)
	}
	link, _ := body["url"].(string)
	u, err := url.Parse(link)
	if err != nil || u.Query().Get("token") == "" {
		t.Fatalf("glasses link %q carries no token", link)
	}
	tok := u.Query().Get("token")
	anon := &http.Client{}
	glasses := func(path string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, f.ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := anon.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, b := glasses("/api/glasses/projects"); code != http.StatusOK || !strings.Contains(b, "alice's goal") {
		t.Fatalf("bob's glasses list: %d %s", code, b)
	}
	if code, b := glasses("/api/glasses/tasks?project_idx=0"); code != http.StatusOK {
		t.Fatalf("bob's glasses read the shared project's tasks: %d %s", code, b)
	}
	if code, _ := f.call(t, f.alice, http.MethodDelete, members+"?identity="+url.QueryEscape(bobEmail), nil); code != http.StatusOK {
		t.Fatal("revoke failed")
	}
	if code, b := glasses("/api/glasses/projects"); code == http.StatusOK && strings.Contains(b, "alice's goal") {
		t.Errorf("the link still lists the project after the membership went: %s", b)
	}
	if code, _ := glasses("/api/glasses/tasks?project_idx=0"); code != http.StatusNotFound {
		t.Errorf("the link still reads the project's tasks: %d, want 404", code)
	}
}

// TestMembers_AFeatureIsSharedWithItsProject: a member of a project sees and
// works on its features, and the roster is edited on the project.
func TestMembers_AFeatureIsSharedWithItsProject(t *testing.T) {
	f := newMemberFixture(t, true)
	feat := addFeature(t, f.project, "login", time.Now(), nil)
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": bobEmail, "role": "operator"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}
	fi := f.idx(t, f.bob, feat)
	if fi < 0 {
		t.Fatal("a member of the project does not see its feature")
	}
	if code, _ := f.call(t, f.bob, http.MethodGet, "/api/state?project_idx="+itoa(fi), nil); code != http.StatusOK {
		t.Errorf("a member reads the feature: %d", code)
	}
	code, body := f.call(t, f.bob, http.MethodGet, "/api/projects/"+itoa(fi)+"/members", nil)
	if code != http.StatusOK || body["inherited_from"] == "" || body["path"] != f.project {
		t.Errorf("the feature's roster: %d %v", code, body)
	}
	ai := f.idx(t, f.alice, feat)
	if code, _ := f.call(t, f.alice, http.MethodPost, "/api/projects/"+itoa(ai)+"/members",
		map[string]any{"identity": carolEmail, "role": "viewer"}); code != http.StatusConflict {
		t.Errorf("adding a member on a feature: %d, want 409", code)
	}
	if f.idx(t, f.carol, feat) >= 0 {
		t.Error("a non-member sees the feature")
	}
}

// TestMembers_RemovingTheProjectRemovesItsRoster: a roster keyed by a path
// must not outlive the project, or it would admit those people to whatever is
// registered there next.
func TestMembers_RemovingTheProjectRemovesItsRoster(t *testing.T) {
	f := newMemberFixture(t, true)
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}
	i := f.idx(t, f.alice, f.project)
	if code, body := f.call(t, f.alice, http.MethodDelete, "/api/projects/"+itoa(i), nil); code != http.StatusOK {
		t.Fatalf("alice removes the project: %d %v", code, body)
	}
	if got := f.srv.memberStore().MembersOf(f.project); len(got) != 0 {
		t.Fatalf("the removed project still has members %+v", got)
	}
	// Registered again, it starts with nobody.
	registerOwned(t, f.project, carolEmail)
	if f.idx(t, f.bob, f.project) >= 0 {
		t.Error("a member of the removed project sees the one registered at its path")
	}
}

// TestMembers_RoutesAreGated: the roster's routes as the route table declares
// them, without a membership store, and with OIDC off.
func TestMembers_RoutesAreGated(t *testing.T) {
	want := map[string]authz.Permission{
		"GET /api/projects/{idx}/members":         authz.PermProjectRead,
		"POST /api/projects/{idx}/members":        authz.PermProjectShare,
		"PATCH /api/projects/{idx}/members":       authz.PermProjectShare,
		"DELETE /api/projects/{idx}/members":      authz.PermProjectShare,
		"DELETE /api/projects/{idx}/members/self": authz.PermViewPrefs,
	}
	seen := 0
	srv := &Server{WorkDir: t.TempDir()}
	for _, rs := range srv.routeTable() {
		if perm, ok := want[rs.Pattern]; ok {
			seen++
			if rs.Perm != perm {
				t.Errorf("%s requires %s, want %s", rs.Pattern, rs.Perm, perm)
			}
		}
		if strings.Contains(rs.Pattern, "/members") && rs.Scope != scopeProjectIdx {
			t.Errorf("%s is not scoped to its project index", rs.Pattern)
		}
	}
	if seen != len(want) {
		t.Errorf("found %d of the %d member routes in the table", seen, len(want))
	}

	// OIDC off: nothing to share with, said plainly.
	dir := setupProjectDir(t, "local", nil)
	plain := New(dir, 0, "")
	ts := httptest.NewServer(plain.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Post(ts.URL+"/api/projects/0/members", "application/json", strings.NewReader(`{"identity":"bob@example.com","role":"viewer"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("sharing on a hub without single sign-on: %d, want 503", resp.StatusCode)
	}
	resp, err = http.Get(ts.URL + "/api/projects/0/members")
	if err != nil {
		t.Fatal(err)
	}
	var body membersResponse
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body.Available || body.CanShare {
		t.Errorf("the roster without single sign-on: %d %+v", resp.StatusCode, body)
	}
}

// TestMembers_VisibilityAndAuthorityUnitRules pins the two questions on
// constructed values: who can see an entry (features answer for their
// project) and what decide() grants.
func TestMembers_VisibilityAndAuthorityUnitRules(t *testing.T) {
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "hub", nil)
	auth, err := oidcauth.New(oidcauth.Config{Enabled: true, Issuer: "https://idp.example.com",
		ClientID: "c", ClientSecret: "s", RedirectURL: "https://hub.example.com/auth/callback",
		AdminEmails: []string{rootEmail}})
	if err != nil {
		t.Fatal(err)
	}
	srv := New(dir, 0, "")
	srv.OIDC = auth
	store, err := srv.OpenMemberStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.closeMemberStore)
	if _, _, err := store.Grant(projectMember("/srv/payments", bobEmail, authz.RoleViewer), nil); err != nil {
		t.Fatal(err)
	}
	bob := &oidcauth.Identity{Sub: "sub-bob", Email: "Bob@Example.com"}
	carol := &oidcauth.Identity{Sub: "sub-carol", Email: carolEmail}
	project := multiui.ProjectEntry{Name: "payments", Path: "/srv/payments", Owner: aliceEmail}
	feature := multiui.ProjectEntry{Name: "payments/login", Path: "/srv/payments/.cloop/features/login",
		Owner: aliceEmail, Parent: "/srv/payments", Feature: "login"}
	for _, e := range []multiui.ProjectEntry{project, feature} {
		if !srv.identityCanSeeEntry(bob, e) {
			t.Errorf("a member cannot see %s", e.Name)
		}
		if srv.identityCanSeeEntry(carol, e) {
			t.Errorf("a non-member sees %s", e.Name)
		}
	}
	// On this hub (no role mappings) the membership is bob's authority on
	// the project, and on its feature's scope, which is the project's.
	g := srv.recipientGrant(bob, nil)
	if d := g.decide(srv.entryScope(feature)); d.Role != authz.RoleViewer || d.Source != authz.SourceProjectMember {
		t.Errorf("bob on the feature's scope: %s from %s", d.Role, d.Source)
	}
	if d := g.decide(authz.GlobalScope); d.Role != authz.RoleAdmin {
		t.Errorf("the membership changed bob's hub-wide allow-all: %s", d.Role)
	}
}

func projectMember(path, key string, role authz.Role) projectmember.Member {
	return projectmember.Member{ProjectPath: path, IdentityKey: key, Role: role}
}

// TestMembers_ProjectScopedTokenFollowsItsOwnersMembership: a token scoped to
// the shared project and bound to the member reaches it while the membership
// lasts, reaches nothing else, and stops the moment the membership goes.
func TestMembers_ProjectScopedTokenFollowsItsOwnersMembership(t *testing.T) {
	f := newMemberFixture(t, true)
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": bobEmail, "role": "operator"}); code != http.StatusCreated {
		t.Fatalf("share: %d %v", code, body)
	}
	mgr, err := f.srv.tokenManager()
	if err != nil {
		t.Fatal(err)
	}
	minted, err := mgr.Mint(apitoken.MintOptions{
		Name: "bob-ci", Roles: []string{"operator"}, ProjectScope: []string{f.project},
		CreatedBy: rootEmail, Owner: &apitoken.Owner{Sub: "sub-bob", Email: bobEmail},
	})
	if err != nil {
		t.Fatal(err)
	}
	pat := &http.Client{Transport: bearer{minted.Plaintext}}

	if code, paths := f.projects(t, pat); code != http.StatusOK || strings.Join(paths, ",") != f.project {
		t.Fatalf("the token lists %d %v, want the shared project alone", code, paths)
	}
	if code, body := f.call(t, pat, http.MethodPost, "/api/tasks?project_idx=0", map[string]any{"title": "from ci"}); code >= 300 {
		t.Fatalf("the member's token adds a task: %d %v", code, body)
	}
	if code, _ := f.call(t, f.alice, http.MethodDelete, members+"?identity="+url.QueryEscape(bobEmail), nil); code != http.StatusOK {
		t.Fatal("revoke failed")
	}
	if code, _ := f.call(t, pat, http.MethodGet, "/api/state?project_idx=0", nil); code != http.StatusNotFound {
		t.Errorf("the token still reads the project after the membership went: %d, want 404", code)
	}
	if code, paths := f.projects(t, pat); code != http.StatusOK || len(paths) != 0 {
		t.Errorf("the token still lists %d %v", code, paths)
	}
}

// bearer is a RoundTripper that presents an API token.
type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
