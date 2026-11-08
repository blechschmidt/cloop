package ui

// Teams and private-by-default projects over the hub's own API (Task 20478).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// teamsURL is the teams collection.
const teamsURL = "/api/teams"

func (f *memberFixture) createTeam(t *testing.T, body map[string]any) {
	t.Helper()
	if code, resp := f.call(t, f.root, http.MethodPost, teamsURL, body); code != http.StatusCreated {
		t.Fatalf("root creates team %v: %d %v", body["slug"], code, resp)
	}
}

func (f *memberFixture) addToTeam(t *testing.T, slug, who string) {
	t.Helper()
	if code, resp := f.call(t, f.root, http.MethodPost, teamsURL+"/"+slug+"/members", map[string]any{"identity": who}); code != http.StatusCreated {
		t.Fatalf("root adds %s to %s: %d %v", who, slug, code, resp)
	}
}

func (f *memberFixture) shareWithTeam(t *testing.T, slug, role string) {
	t.Helper()
	if code, resp := f.call(t, f.alice, http.MethodPost, f.membersURL(t, f.alice), map[string]any{"team": slug, "role": role}); code != http.StatusCreated {
		t.Fatalf("alice shares with team %s: %d %v", slug, code, resp)
	}
}

// TestTeams_OnlyTheHubsAdministratorsKeepThem: whoever decides who is on a
// team decides who reaches every project shared with it, so the six routes
// take user.manage — refused to alice, who maintains projects hub-wide and
// owns one.
func TestTeams_OnlyTheHubsAdministratorsKeepThem(t *testing.T) {
	f := newMemberFixture(t, true)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, teamsURL},
		{http.MethodPost, teamsURL},
		{http.MethodPatch, teamsURL + "/ops"},
		{http.MethodDelete, teamsURL + "/ops"},
		{http.MethodPost, teamsURL + "/ops/members"},
		{http.MethodDelete, teamsURL + "/ops/members?identity=bob@example.com"},
	} {
		if code, body := f.call(t, f.alice, c.method, c.path, map[string]any{"slug": "ops", "identity": bobEmail}); code != http.StatusForbidden {
			t.Errorf("a maintainer: %s %s = %d %v, want 403", c.method, c.path, code, body)
		}
	}

	f.createTeam(t, map[string]any{"slug": "Ops", "name": "Operations", "idp_group": "/sre"})
	for name, c := range map[string]struct {
		method, path string
		body         map[string]any
		want         int
	}{
		"a taken slug":            {http.MethodPost, teamsURL, map[string]any{"slug": "ops"}, http.StatusConflict},
		"a bad slug":              {http.MethodPost, teamsURL, map[string]any{"slug": "no spaces"}, http.StatusBadRequest},
		"the built-in team":       {http.MethodPost, teamsURL, map[string]any{"slug": "everyone"}, http.StatusBadRequest},
		"renaming the slug":       {http.MethodPatch, teamsURL + "/ops", map[string]any{"slug": "other"}, http.StatusBadRequest},
		"changing Everyone":       {http.MethodPatch, teamsURL + "/everyone", map[string]any{"name": "x"}, http.StatusConflict},
		"a missing team":          {http.MethodDelete, teamsURL + "/nope", nil, http.StatusNotFound},
		"a team as a team member": {http.MethodPost, teamsURL + "/ops/members", map[string]any{"identity": "team:ops"}, http.StatusBadRequest},
		"not an identity":         {http.MethodPost, teamsURL + "/ops/members", map[string]any{"identity": "bob"}, http.StatusBadRequest},
	} {
		if code, body := f.call(t, f.root, c.method, c.path, c.body); code != c.want {
			t.Errorf("%s: %d %v, want %d", name, code, body, c.want)
		}
	}
	f.addToTeam(t, "ops", "Bob@Example.com")
	if code, body := f.call(t, f.root, http.MethodPost, teamsURL+"/ops/members", map[string]any{"identity": bobEmail}); code != http.StatusConflict {
		t.Errorf("adding bob twice: %d %v", code, body)
	}
	if code, body := f.call(t, f.root, http.MethodPatch, teamsURL+"/ops", map[string]any{"description": "on call"}); code != http.StatusOK || body["description"] != "on call" || body["idp_group"] != "sre" {
		t.Errorf("a PATCH changes only what it names: %d %v", code, body)
	}

	code, body := f.call(t, f.root, http.MethodGet, teamsURL, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/teams: %d %v", code, body)
	}
	teams := body["teams"].([]any)
	if len(teams) != 2 || teams[0].(map[string]any)["slug"] != "everyone" || teams[1].(map[string]any)["slug"] != "ops" {
		t.Fatalf("teams = %v, want Everyone then ops", teams)
	}
	ops := teams[1].(map[string]any)
	if members := ops["members"].([]any); len(members) != 1 || members[0].(map[string]any)["identity"] != bobEmail {
		t.Errorf("ops members = %v", ops["members"])
	}

	// Every change is on the control plane's trail.
	db, err := statedb.Open(state.DBPath(f.srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "team"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ev := range evs {
		got = append(got, ev.EventType)
		if ev.Actor != rootEmail {
			t.Errorf("audit row %s by %q, want root", ev.EventType, ev.Actor)
		}
	}
	want := []string{string(auditaction.ActionTeamCreate), string(auditaction.ActionTeamMemberAdd), string(auditaction.ActionTeamUpdate)}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("audit rows %v, want %v", got, want)
	}
}

// TestTeams_AProjectSharedWithATeamReachesItsMembers: alice shares her project
// with a team bob is on; bob sees it and holds the team's role there, carol —
// on no team — does not, and once bob is taken off the team it is gone.
func TestTeams_AProjectSharedWithATeamReachesItsMembers(t *testing.T) {
	f := newMemberFixture(t, true)
	f.createTeam(t, map[string]any{"slug": "payments", "name": "Payments"})
	f.addToTeam(t, "payments", bobEmail)
	if f.idx(t, f.bob, f.project) >= 0 {
		t.Fatal("bob sees alice's project before it is shared")
	}
	f.shareWithTeam(t, "payments", "operator")

	i := f.idx(t, f.bob, f.project)
	if i < 0 {
		t.Fatal("a team member does not see a project shared with the team")
	}
	if code, body := f.call(t, f.bob, http.MethodGet, "/api/me?project_idx="+itoa(i), nil); code != http.StatusOK || body["role"] != "operator" {
		t.Errorf("bob's role through the team: %d %v", code, body)
	}
	if code, body := f.call(t, f.bob, http.MethodPost, "/api/tasks?project_idx="+itoa(i), map[string]any{"title": "from the team"}); code >= 300 {
		t.Errorf("an operator through a team was refused a task: %d %v", code, body)
	}
	if code, _ := f.call(t, f.bob, http.MethodPost, "/api/projects/"+itoa(i)+"/members", map[string]any{"identity": carolEmail, "role": "viewer"}); code != http.StatusForbidden {
		t.Errorf("an operator through a team shared the project: %d, want 403", code)
	}
	if f.idx(t, f.carol, f.project) >= 0 {
		t.Error("carol, on no team, sees the project")
	}
	// The roster names the team, and who reaches it through it.
	code, body := f.call(t, f.alice, http.MethodGet, f.membersURL(t, f.alice), nil)
	if code != http.StatusOK {
		t.Fatalf("roster: %d %v", code, body)
	}
	list := body["members"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["kind"] != "team" || list[0].(map[string]any)["identity"] != "team:payments" {
		t.Fatalf("roster rows %v, want the team", list)
	}
	if team := list[0].(map[string]any)["team"].(map[string]any); team["name"] != "Payments" || team["members"] != float64(1) {
		t.Errorf("the team's row: %v", team)
	}
	offered := body["teams"].([]any)
	if len(offered) != 2 || offered[0].(map[string]any)["slug"] != "everyone" {
		t.Errorf("teams on offer: %v, want Everyone and payments", offered)
	}

	// Off the team, off the project.
	if code, body := f.call(t, f.root, http.MethodDelete, teamsURL+"/payments/members?identity="+url.QueryEscape(bobEmail), nil); code != http.StatusOK {
		t.Fatalf("root takes bob off the team: %d %v", code, body)
	}
	if f.idx(t, f.bob, f.project) >= 0 {
		t.Error("taken off the team, bob still sees the project")
	}
	if code, _ := f.call(t, f.bob, http.MethodGet, "/api/state?project_idx="+itoa(i), nil); code != http.StatusNotFound {
		t.Errorf("taken off the team, bob still reads index %d: %d", i, code)
	}
}

// TestTeams_ATeamFollowsAnIdentityProviderGroup: a team linked to a group has
// as members everyone whose token carries it, with nobody added by name —
// matched exactly as a group role mapping is.
func TestTeams_ATeamFollowsAnIdentityProviderGroup(t *testing.T) {
	f := newMemberFixture(t, true) // bob signs in carrying the group "engineers"
	f.createTeam(t, map[string]any{"slug": "eng", "idp_group": "/Engineers"})
	f.shareWithTeam(t, "eng", "viewer")
	i := f.idx(t, f.bob, f.project)
	if i < 0 {
		t.Fatal("a member of the linked group does not see the project")
	}
	if _, body := f.call(t, f.bob, http.MethodGet, "/api/me?project_idx="+itoa(i), nil); body["role"] != "viewer" {
		t.Errorf("bob's role through the group: %v", body["role"])
	}
	if f.idx(t, f.carol, f.project) >= 0 {
		t.Error("carol, outside the group, sees the project")
	}
	// Relinked to another group, the team no longer has bob.
	if code, body := f.call(t, f.root, http.MethodPatch, teamsURL+"/eng", map[string]any{"idp_group": "sre"}); code != http.StatusOK {
		t.Fatalf("relink: %d %v", code, body)
	}
	if f.idx(t, f.bob, f.project) >= 0 {
		t.Error("relinked away from bob's group, the team still reaches him")
	}
}

// TestTeams_EveryoneOpensAProjectToTheWholeHub: the built-in team has every
// signed-in identity, carol included, who holds no role at all here.
func TestTeams_EveryoneOpensAProjectToTheWholeHub(t *testing.T) {
	f := newMemberFixture(t, true)
	f.shareWithTeam(t, "everyone", "viewer")
	i := f.idx(t, f.carol, f.project)
	if i < 0 {
		t.Fatal("a project shared with Everyone is not visible to a signed-in user")
	}
	if _, body := f.call(t, f.carol, http.MethodGet, "/api/me?project_idx="+itoa(i), nil); body["role"] != "viewer" {
		t.Errorf("carol through Everyone: %v", body["role"])
	}
	if code, _ := f.call(t, f.carol, http.MethodPost, "/api/tasks?project_idx="+itoa(i), map[string]any{"title": "x"}); code != http.StatusForbidden {
		t.Errorf("a viewer through Everyone added a task: %d", code)
	}
	if _, body := f.call(t, f.alice, http.MethodGet, f.membersURL(t, f.alice), nil); body["visibility"] != "everyone" {
		t.Errorf("visibility = %v, want everyone", body["visibility"])
	}
	// A team that does not exist cannot be named.
	if code, body := f.call(t, f.alice, http.MethodPost, f.membersURL(t, f.alice), map[string]any{"team": "ghosts", "role": "viewer"}); code != http.StatusNotFound {
		t.Errorf("sharing with a missing team: %d %v", code, body)
	}
}

// TestTeams_DeletingATeamUnsharesEveryProjectItReached: the shares go in the
// same commit as the team, and each project's own trail says who lost access
// and why.
func TestTeams_DeletingATeamUnsharesEveryProjectItReached(t *testing.T) {
	f := newMemberFixture(t, true)
	f.createTeam(t, map[string]any{"slug": "payments"})
	f.addToTeam(t, "payments", bobEmail)
	f.shareWithTeam(t, "payments", "operator")
	if f.idx(t, f.bob, f.project) < 0 {
		t.Fatal("the share did not reach bob")
	}
	code, body := f.call(t, f.root, http.MethodDelete, teamsURL+"/payments", nil)
	if code != http.StatusOK {
		t.Fatalf("delete: %d %v", code, body)
	}
	if projects := body["unshared_projects"].([]any); len(projects) != 1 || projects[0] != f.project {
		t.Errorf("unshared %v", body["unshared_projects"])
	}
	if f.idx(t, f.bob, f.project) >= 0 {
		t.Error("the deleted team still reaches bob")
	}
	if got := f.srv.memberStore().MembersOf(f.project); len(got) != 0 {
		t.Errorf("the team's share outlived it: %+v", got)
	}
	db, err := statedb.Open(state.DBPath(f.srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "project_member"})
	if err != nil {
		t.Fatal(err)
	}
	revoked := false
	for _, ev := range evs {
		if ev.EventType == string(auditaction.ActionProjectMemberRevoke) && strings.Contains(ev.Payload, "the team was deleted") {
			revoked = true
		}
	}
	if !revoked {
		t.Error("the project's trail does not record the share the deletion took")
	}
	// Re-created under the same slug, the team starts with no projects.
	f.createTeam(t, map[string]any{"slug": "payments"})
	f.addToTeam(t, "payments", bobEmail)
	if f.idx(t, f.bob, f.project) >= 0 {
		t.Error("a team re-created under a deleted team's slug inherited its projects")
	}
}

// TestTeams_LeavingATeamClosesTheLiveSocket: bob watches a project he reaches
// through a team; taken off the team, his socket is told and closed, as a
// revoked membership's is.
func TestTeams_LeavingATeamClosesTheLiveSocket(t *testing.T) {
	f := newMemberFixture(t, true)
	f.createTeam(t, map[string]any{"slug": "payments"})
	f.addToTeam(t, "payments", bobEmail)
	f.shareWithTeam(t, "payments", "viewer")
	i := f.idx(t, f.bob, f.project)
	if i < 0 {
		t.Fatal("the share did not reach bob")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wsBase := "ws" + strings.TrimPrefix(f.ts.URL, "http")
	conn, _, err := websocket.Dial(ctx, wsBase+"/api/ws?project_idx="+itoa(i), &websocket.DialOptions{HTTPClient: f.bob})
	if err != nil {
		t.Fatalf("bob opens the project's socket: %v", err)
	}
	defer conn.CloseNow()
	if !readUntil(ctx, t, conn, func(m wsMessage) bool { return m.Type == "task_update" }) {
		t.Fatal("bob's socket received no state")
	}
	waitMember(t, "bob in the project's room", func() bool { return f.srv.roomSize(f.project) > 0 })

	if code, body := f.call(t, f.root, http.MethodDelete, teamsURL+"/payments/members?identity="+url.QueryEscape(bobEmail), nil); code != http.StatusOK {
		t.Fatalf("take bob off the team: %d %v", code, body)
	}
	told := false
	var closeErr websocket.CloseError
	for {
		_, raw, err := conn.Read(ctx)
		if err == nil {
			var m wsMessage
			if json.Unmarshal(raw, &m) == nil && m.Type == "access_withdrawn" {
				told = true
			}
			continue
		}
		if !errors.As(err, &closeErr) {
			t.Fatalf("the socket ended without a close frame: %v", err)
		}
		break
	}
	if !told || closeErr.Code != websocket.StatusPolicyViolation {
		t.Errorf("told %v, closed %d — want access_withdrawn and 1008", told, closeErr.Code)
	}
}

// TestTeams_PrivateByDefault pins the visibility rules on one hub: a project a
// person creates is theirs and the hub administrators', a role mapping naming
// it admits whom it names, a hub-wide role does not, and the admin role
// granted through a group — not only admin_emails — sees every project.
func TestTeams_PrivateByDefault(t *testing.T) {
	t.Setenv(multiui.EnvRoot, t.TempDir())
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", []string{rootEmail})
	project := setupProjectDir(t, "alice's goal", nil)
	registerOwned(t, project, aliceEmail)
	resolver, err := authz.New(authz.Config{
		DefaultRole: authz.RoleNone,
		AdminEmails: []string{rootEmail},
		Bindings: []authz.Binding{
			{Claim: authz.ClaimEmail, Value: aliceEmail, Role: authz.RoleMaintainer},
			{Claim: authz.ClaimGroup, Value: "everyone-operates", Role: authz.RoleOperator},
			{Claim: authz.ClaimGroup, Value: "platform-admins", Role: authz.RoleAdmin},
			{Claim: authz.ClaimGroup, Value: "auditors", Role: authz.RoleViewer, Project: project},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	if _, err := srv.OpenMemberStore(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.closeMemberStore)
	if _, err := srv.OpenTeamStore(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.closeTeamStore)
	srv.RPS, srv.Burst = 10000, 10000
	f := &memberFixture{srv: srv, ts: ts, project: project, idp: idp}
	as := func(email string, groups ...string) *http.Client {
		idp.email, idp.sub, idp.name, idp.groups = email, "sub-"+email, email, groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	alice := as(aliceEmail)
	operator := as("op@example.com", "everyone-operates")
	platform := as("pat@example.com", "platform-admins")
	auditor := as("aud@example.com", "auditors")

	if i := f.idx(t, alice, project); i < 0 {
		t.Fatal("the owner does not see her project")
	} else if _, body := f.call(t, alice, http.MethodGet, "/api/me?project_idx="+itoa(i), nil); body["role"] != "admin" {
		t.Errorf("the owner's role = %v, want admin", body["role"])
	}
	if f.idx(t, operator, project) >= 0 {
		t.Error("an operator hub-wide sees a project somebody else created")
	}
	if i := f.idx(t, platform, project); i < 0 {
		t.Error("an administrator through a group does not see every project")
	} else if _, body := f.call(t, platform, http.MethodGet, "/api/me?project_idx="+itoa(i), nil); body["role"] != "admin" {
		t.Errorf("a group administrator's role there = %v", body["role"])
	}
	if i := f.idx(t, auditor, project); i < 0 {
		t.Error("a role mapping naming the project does not admit whom it names")
	} else if _, body := f.call(t, auditor, http.MethodGet, "/api/me?project_idx="+itoa(i), nil); body["role"] != "viewer" {
		t.Errorf("the auditor's role there = %v, want viewer", body["role"])
	}
	// Even addressing the project by an index another caller uses, the
	// operator gets nothing: the index space is per caller.
	if code, _ := f.call(t, operator, http.MethodGet, "/api/state?project_idx=1", nil); code == http.StatusOK {
		t.Error("an operator reached a private project by index")
	}
}
