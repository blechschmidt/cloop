package ui

// A project's readers list over REST (Task 20498): who may read and change it
// on a hub with single sign-on and on one without, what a caller is told about
// projects they cannot see, the input rules, the audit rows, and the entries
// outliving a rename and a move but not their project.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/projectreaders"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// newReadersFixture is the member fixture with role mappings (default role
// none) and a second project alice owns, the reader: the first is the
// project whose list the tests change.
func newReadersFixture(t *testing.T) (f *memberFixture, reader string) {
	t.Helper()
	f = newMemberFixture(t, true)
	reader = setupProjectDir(t, "the reader's goal", nil)
	registerOwned(t, reader, aliceEmail)
	return f, reader
}

// readersURL is c's readers route for the project at path.
func (f *memberFixture) readersURL(t *testing.T, c *http.Client, path string) string {
	t.Helper()
	i := f.idx(t, c, path)
	if i < 0 {
		t.Fatalf("%s is not in the caller's list", path)
	}
	return "/api/projects/" + itoa(i) + "/readers"
}

// readersOf reads the project's list from the control plane, as a run's
// dispatch will.
func readersOf(t *testing.T, srv *Server) *projectreaders.Resolver {
	t.Helper()
	db, err := statedb.Open(state.DBPath(srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r, err := projectreaders.Load(db)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// readerAuditRows lists the project_reader rows on the control plane's trail,
// oldest first.
func readerAuditRows(t *testing.T, srv *Server) []statedb.AuditEvent {
	t.Helper()
	db, err := statedb.Open(state.DBPath(srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "project_reader", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// detail is one detail of an error answer decoded into a map.
func detail(body map[string]any, key string) string {
	e, _ := body["error"].(map[string]any)
	d, _ := e["details"].(map[string]any)
	v, _ := d[key].(string)
	return v
}

// listed is the paths an answer's list names.
func listed(body map[string]any, key string) []string {
	var out []string
	list, _ := body[key].([]any)
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			p, _ := m["path"].(string)
			out = append(out, p)
		}
	}
	return out
}

func TestReaders_RoutesAreClassified(t *testing.T) {
	want := map[string]struct {
		perm authz.Permission
		sudo sudoRule
	}{
		"GET /api/projects/{idx}/readers":    {authz.PermProjectRead, sudoNone},
		"PUT /api/projects/{idx}/readers":    {authz.PermProjectReaders, sudoWrites},
		"DELETE /api/projects/{idx}/readers": {authz.PermProjectReaders, sudoWrites},
	}
	seen := 0
	for _, rs := range (&Server{WorkDir: t.TempDir()}).routeTable() {
		if !strings.Contains(rs.Pattern, "/readers") {
			continue
		}
		w, ok := want[rs.Pattern]
		if !ok {
			t.Errorf("%s is a readers route nobody classified", rs.Pattern)
			continue
		}
		seen++
		if rs.Perm != w.perm || rs.Sudo != w.sudo || rs.Scope != scopeProjectIdx || len(rs.MethodPerms) > 0 {
			t.Errorf("%s: perm %s sudo %v scope %v, want %s, %v, the project index", rs.Pattern, rs.Perm, rs.Sudo, rs.Scope, w.perm, w.sudo)
		}
	}
	if seen != len(want) {
		t.Errorf("found %d of the %d readers routes", seen, len(want))
	}
	// Only the administrator's rung holds the write.
	for _, role := range authz.AllRoles {
		holds := false
		for _, p := range role.Permissions() {
			if p == authz.PermProjectReaders {
				holds = true
			}
		}
		if holds != (role == authz.RoleAdmin) {
			t.Errorf("role %s holds project.readers = %v", role, holds)
		}
	}
	if !authz.RequiresRecentSignIn(authz.PermProjectReaders) || !authz.RequiresFreshClaims(authz.PermProjectReaders) {
		t.Error("project.readers is exercised on stale claims or without a recent sign-in")
	}
}

// TestReaders_AnAdministratorKeepsTheList: the project's owner adds a project
// she can see, adding it again changes nothing, both sides of the list say so,
// the run-side answer agrees, and taking it off again is recorded with it.
func TestReaders_AnAdministratorKeepsTheList(t *testing.T) {
	f, reader := newReadersFixture(t)
	target := f.project
	list := f.readersURL(t, f.alice, target)
	readerIdx := f.idx(t, f.alice, reader)

	code, body := f.call(t, f.alice, http.MethodPut, list, map[string]any{"reader": reader})
	if code != http.StatusOK || body["added"] != true {
		t.Fatalf("alice adds the reader: %d %v", code, body)
	}
	added, _ := body["reader"].(map[string]any)
	id, _ := added["id"].(string)
	if !strings.HasPrefix(id, "prd_") || added["path"] != reader || added["idx"] != float64(readerIdx) ||
		added["project"] != filepath.Base(reader) || added["added_by"] != aliceEmail {
		t.Fatalf("the entry as answered: %v", added)
	}
	for _, again := range []map[string]any{{"reader": reader + "/"}, {"reader_idx": readerIdx}} {
		code, body := f.call(t, f.alice, http.MethodPut, list, again)
		got, _ := body["reader"].(map[string]any)
		if code != http.StatusOK || body["added"] != false || got["id"] != id {
			t.Errorf("adding it again by %v: %d %v, want the same entry, unchanged", again, code, body)
		}
	}

	code, body = f.call(t, f.alice, http.MethodGet, list, nil)
	if code != http.StatusOK || body["can_manage"] != true || body["hidden_readers"] != float64(0) {
		t.Fatalf("alice reads the list: %d %v", code, body)
	}
	if got := listed(body, "readers"); len(got) != 1 || got[0] != reader {
		t.Errorf("readers = %v, want %s", got, reader)
	}
	if got := listed(body, "readable"); len(got) != 0 {
		t.Errorf("the project reads %v, want nothing", got)
	}
	code, body = f.call(t, f.alice, http.MethodGet, f.readersURL(t, f.alice, reader), nil)
	if got := listed(body, "readable"); code != http.StatusOK || len(got) != 1 || got[0] != target {
		t.Errorf("the reader's side: %d readable %v, want %s", code, got, target)
	}
	r := readersOf(t, f.srv)
	if !r.CanRead(reader, target) || r.CanRead(target, reader) || r.CanRead(target, target) {
		t.Errorf("CanRead after the change: reader→target %v, target→reader %v, itself %v",
			r.CanRead(reader, target), r.CanRead(target, reader), r.CanRead(target, target))
	}

	del := list + "?reader=" + url.QueryEscape(reader)
	if code, body := f.call(t, f.alice, http.MethodDelete, del, nil); code != http.StatusOK || body["id"] != id || body["reader"] != reader {
		t.Fatalf("alice takes it off: %d %v", code, body)
	}
	if code, _ := f.call(t, f.alice, http.MethodDelete, del, nil); code != http.StatusNotFound {
		t.Errorf("taking it off again: %d, want 404", code)
	}
	if readersOf(t, f.srv).CanRead(reader, target) {
		t.Error("the reader still reads the project after it was taken off")
	}

	// Each change on the control plane's trail, the additions that changed
	// nothing not at all.
	evs := readerAuditRows(t, f.srv)
	var got []string
	for _, ev := range evs {
		got = append(got, ev.EventType)
		var p map[string]any
		_ = json.Unmarshal([]byte(ev.Payload), &p)
		if ev.Actor != aliceEmail || ev.EntityID != target+"|"+reader || p["id"] != id ||
			p["project_path"] != target || p["reader_path"] != reader || p["via"] != "api" ||
			p["project"] != filepath.Base(target) || p["reader"] != filepath.Base(reader) {
			t.Errorf("audit row %s: actor %q entity %q payload %v", ev.EventType, ev.Actor, ev.EntityID, p)
		}
	}
	want := []string{string(auditaction.ActionProjectReaderAdd), string(auditaction.ActionProjectReaderRemove)}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("audit rows %v, want %v", got, want)
	}
}

// TestReaders_RefuseANonAdminMemberAForeignUserAndARevokedShare: a maintainer
// on the project reads the list and changes nothing; somebody the project is
// not shared with cannot reach it at all; an administrator by membership
// manages it — including an entry naming a project only its owner can see —
// until the share is revoked, after which the list is out of reach again.
func TestReaders_RefuseANonAdminMemberAForeignUserAndARevokedShare(t *testing.T) {
	f, reader := newReadersFixture(t)
	target := f.project
	alice := f.readersURL(t, f.alice, target)
	if code, body := f.call(t, f.alice, http.MethodPut, alice, map[string]any{"reader": reader}); code != http.StatusOK {
		t.Fatalf("alice adds the reader: %d %v", code, body)
	}
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": bobEmail, "role": "maintainer"}); code != http.StatusCreated {
		t.Fatalf("share with bob: %d %v", code, body)
	}

	// A maintainer member: reads, cannot see the reader, changes nothing.
	bob := f.readersURL(t, f.bob, target)
	code, body := f.call(t, f.bob, http.MethodGet, bob, nil)
	if code != http.StatusOK || body["can_manage"] != false || body["hidden_readers"] != float64(1) {
		t.Fatalf("bob reads the list: %d %v", code, body)
	}
	if got := listed(body, "readers"); len(got) != 0 {
		t.Errorf("bob is told about a project he cannot see: %v", got)
	}
	if hidden, ok := body["hidden"]; ok {
		t.Errorf("a member who may not change the list got its hidden entries: %v", hidden)
	}
	if strings.Contains(mustJSON(t, body), reader) {
		t.Errorf("the answer names the reader bob cannot see: %v", body)
	}
	code, body = f.call(t, f.bob, http.MethodPut, bob, map[string]any{"reader_idx": 0})
	if code != http.StatusForbidden || detail(body, "required_permission") != string(authz.PermProjectReaders) {
		t.Errorf("a maintainer adds a reader: %d %v, want 403 naming project.readers", code, body)
	}
	if code, body := f.call(t, f.bob, http.MethodDelete, bob+"?reader="+url.QueryEscape(reader), nil); code != http.StatusForbidden {
		t.Errorf("a maintainer takes a reader off: %d %v, want 403", code, body)
	}
	if !readersOf(t, f.srv).CanRead(reader, target) {
		t.Fatal("a refused member changed the list")
	}

	// A foreign user: no project to name, nothing to learn.
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		path := "/api/projects/0/readers"
		var body any
		if m == http.MethodPut {
			body = map[string]any{"reader": reader}
		}
		if m == http.MethodDelete {
			path += "?reader=" + url.QueryEscape(reader)
		}
		if code, got := f.call(t, f.carol, m, path, body); code != http.StatusNotFound {
			t.Errorf("carol %s: %d %v, want 404", m, code, got)
		}
	}

	// An administrator by membership manages the list, and takes back an
	// entry naming a project only its owner sees, by the entry's id.
	if code, body := f.call(t, f.alice, http.MethodPatch, members+"?identity="+url.QueryEscape(bobEmail), map[string]any{"role": "admin"}); code != http.StatusOK {
		t.Fatalf("bob to admin: %d %v", code, body)
	}
	code, body = f.call(t, f.bob, http.MethodGet, bob, nil)
	hidden, _ := body["hidden"].([]any)
	if code != http.StatusOK || body["can_manage"] != true || len(hidden) != 1 {
		t.Fatalf("bob as admin reads the list: %d %v", code, body)
	}
	entry, _ := hidden[0].(map[string]any)
	id, _ := entry["id"].(string)
	if entry["added_by"] != aliceEmail || strings.Contains(mustJSON(t, body), reader) {
		t.Errorf("the hidden entry: %v", entry)
	}
	code, body = f.call(t, f.bob, http.MethodDelete, bob+"?id="+id, nil)
	if code != http.StatusOK || body["id"] != id {
		t.Fatalf("bob takes the hidden entry off: %d %v", code, body)
	}
	if _, named := body["reader"]; named {
		t.Errorf("the removal named the reader bob cannot see: %v", body)
	}
	if readersOf(t, f.srv).CanRead(reader, target) {
		t.Fatal("the entry survived its removal")
	}

	// Revoked, bob reaches the list no more, and the entry alice adds again
	// stays where it is.
	if code, body := f.call(t, f.alice, http.MethodPut, alice, map[string]any{"reader": reader}); code != http.StatusOK {
		t.Fatalf("alice adds it again: %d %v", code, body)
	}
	if code, body := f.call(t, f.alice, http.MethodDelete, members+"?identity="+url.QueryEscape(bobEmail), nil); code != http.StatusOK {
		t.Fatalf("revoke bob: %d %v", code, body)
	}
	if i := f.idx(t, f.bob, target); i >= 0 {
		t.Fatalf("bob still lists the project at %d", i)
	}
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		path := bob
		var body any
		if m == http.MethodPut {
			body = map[string]any{"reader_idx": 0}
		}
		if m == http.MethodDelete {
			path += "?reader=" + url.QueryEscape(reader)
		}
		if code, got := f.call(t, f.bob, m, path, body); code != http.StatusNotFound {
			t.Errorf("bob %s after the revocation: %d %v, want 404", m, code, got)
		}
	}
	if !readersOf(t, f.srv).CanRead(reader, target) {
		t.Error("a revoked member's request changed the list")
	}
}

// TestReaders_OnlyProjectsTheCallerCanSee: an administrator by membership may
// list a project shared with her, and nothing she cannot see — answered the
// same as nothing at all — nor the project itself, a relative path, or a body
// naming the reader twice or not at all. A hub administrator sees, and may
// list, every project.
func TestReaders_OnlyProjectsTheCallerCanSee(t *testing.T) {
	f, reader := newReadersFixture(t)
	target := f.project
	members := f.membersURL(t, f.alice)
	if code, body := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": carolEmail, "role": "admin"}); code != http.StatusCreated {
		t.Fatalf("share the project with carol: %d %v", code, body)
	}
	list := f.readersURL(t, f.carol, target)
	primary, _ := filepath.Abs(f.srv.WorkDir)
	for name, c := range map[string]struct {
		body map[string]any
		want int
	}{
		"a project she cannot see": {map[string]any{"reader": reader}, http.StatusNotFound},
		"the hub's own project":    {map[string]any{"reader": primary}, http.StatusNotFound},
		"no project at all":        {map[string]any{"reader": "/srv/nowhere"}, http.StatusNotFound},
		"an index past her list":   {map[string]any{"reader_idx": 99}, http.StatusNotFound},
		"a negative index":         {map[string]any{"reader_idx": -1}, http.StatusNotFound},
		"the project itself":       {map[string]any{"reader": target}, http.StatusBadRequest},
		"a relative path":          {map[string]any{"reader": "projects/shop"}, http.StatusBadRequest},
		"both":                     {map[string]any{"reader": reader, "reader_idx": 0}, http.StatusBadRequest},
		"neither":                  {map[string]any{}, http.StatusBadRequest},
		"an unknown field":         {map[string]any{"readers": reader}, http.StatusBadRequest},
		"a control character":      {map[string]any{"reader": "/srv/a\nb"}, http.StatusBadRequest},
	} {
		if code, body := f.call(t, f.carol, http.MethodPut, list, c.body); code != c.want {
			t.Errorf("%s: %d %v, want %d", name, code, body, c.want)
		}
	}
	for name, q := range map[string]string{
		"no reader":       "",
		"a relative path": "?reader=projects/shop",
		"both":            "?reader=" + url.QueryEscape(reader) + "&id=prd_000000000000000000000000",
		"not an id":       "?id=x' OR 1=1",
	} {
		if code, body := f.call(t, f.carol, http.MethodDelete, list+strings.ReplaceAll(q, " ", "%20"), nil); code != http.StatusBadRequest {
			t.Errorf("DELETE with %s: %d %v, want 400", name, code, body)
		}
	}
	if len(readersOf(t, f.srv).All()) != 0 {
		t.Fatalf("a refused request was stored: %+v", readersOf(t, f.srv).All())
	}

	// Shared with her, the reader is hers to list.
	readerMembers := "/api/projects/" + itoa(f.idx(t, f.alice, reader)) + "/members"
	if code, body := f.call(t, f.alice, http.MethodPost, readerMembers, map[string]any{"identity": carolEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("share the reader with carol: %d %v", code, body)
	}
	list = f.readersURL(t, f.carol, target)
	if code, body := f.call(t, f.carol, http.MethodPut, list, map[string]any{"reader": reader}); code != http.StatusOK || body["added"] != true {
		t.Fatalf("carol lists a project shared with her: %d %v", code, body)
	}
	// The hub administrator lists the hub's own project too.
	if code, body := f.call(t, f.root, http.MethodPut, f.readersURL(t, f.root, target), map[string]any{"reader": primary}); code != http.StatusOK {
		t.Fatalf("root lists the hub's project: %d %v", code, body)
	}
	r := readersOf(t, f.srv)
	if !r.CanRead(reader, target) || !r.CanRead(primary, target) || len(r.All()) != 2 {
		t.Errorf("entries = %+v", r.All())
	}
}

// TestReaders_WritesAskForARecentSignIn: on a hub with single sign-on both
// writes ask for one, and the read does not.
func TestReaders_WritesAskForARecentSignIn(t *testing.T) {
	f, reader := newReadersFixture(t)
	f.idp.email, f.idp.sub = aliceEmail, "sub-alice"
	f.idp.setSignedInAt(time.Now().Add(-3 * time.Hour))
	stale := jarClient(t)
	login(t, stale, f.ts)
	f.idp.setSignedInAt(time.Time{})
	list := f.readersURL(t, stale, f.project)
	if code, body := f.call(t, stale, http.MethodGet, list, nil); code != http.StatusOK {
		t.Fatalf("a stale session reads the list: %d %v", code, body)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPut, list, map[string]any{"reader": reader}},
		{http.MethodDelete, list + "?reader=" + url.QueryEscape(reader), nil},
	} {
		code, body := f.call(t, stale, c.method, c.path, c.body)
		e, _ := body["error"].(map[string]any)
		if code != http.StatusUnauthorized || e["code"] != "REAUTH_REQUIRED" {
			t.Errorf("%s from a stale session: %d %v, want 401 REAUTH_REQUIRED", c.method, code, body)
		}
	}
	if len(readersOf(t, f.srv).All()) != 0 {
		t.Error("a stale session changed the list")
	}
}

// TestReaders_TheStaticAdminOnAHubWithoutSignIn: with no sign-in, whoever holds
// the hub's static token is its administrator — and nobody else gets in.
func TestReaders_TheStaticAdminOnAHubWithoutSignIn(t *testing.T) {
	t.Setenv(multiui.EnvRoot, t.TempDir())
	hub := setupProjectDir(t, "the hub's goal", nil)
	reader := setupProjectDir(t, "the reader's goal", nil)
	srv := New(hub, 0, "the-static-admin-token")
	srv.Projects = []string{reader}
	srv.RPS, srv.Burst = 10000, 10000
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	put := func(token string) int {
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/projects/0/readers", strings.NewReader(`{"reader_idx":1}`))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := put(""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", code)
	}
	if code := put("not-the-token"); code != http.StatusUnauthorized {
		t.Errorf("a wrong token: %d, want 401", code)
	}
	if code := put("the-static-admin-token"); code != http.StatusOK {
		t.Fatalf("the static admin: %d, want 200", code)
	}
	abs, _ := filepath.Abs(hub)
	if !readersOf(t, srv).CanRead(reader, abs) {
		t.Error("the static admin's entry is not in force")
	}
}

// TestReaders_FeaturesAreNeverListed: on a hub without sign-in, a feature has
// no list to change and is no reader; its project is both.
func TestReaders_FeaturesAreNeverListed(t *testing.T) {
	f := newFeatureFixture(t)
	featureDir := addFeature(t, f.parent, "checkout", time.Now(), nil)
	// The list: the hub (0), the parent (1), its feature (2).
	code, body := f.do(t, http.MethodGet, "/api/projects/2/readers", nil)
	if code != http.StatusOK || body["feature"] != true || len(listed(body, "readers")) != 0 {
		t.Fatalf("a feature's list: %d %v", code, body)
	}
	if code, body := f.do(t, http.MethodPut, "/api/projects/2/readers", map[string]any{"reader_idx": 0}); code != http.StatusConflict {
		t.Errorf("changing a feature's list: %d %v, want 409", code, body)
	}
	for _, req := range []map[string]any{{"reader_idx": 2}, {"reader": featureDir}} {
		if code, body := f.do(t, http.MethodPut, "/api/projects/0/readers", req); code != http.StatusBadRequest {
			t.Errorf("listing a feature as a reader by %v: %d %v, want 400", req, code, body)
		}
	}
	if code, body := f.do(t, http.MethodPut, "/api/projects/1/readers", map[string]any{"reader_idx": 0}); code != http.StatusOK || body["added"] != true {
		t.Fatalf("the static admin lists the hub on the parent: %d %v", code, body)
	}
	r := readersOf(t, f.srv)
	primary, _ := filepath.Abs(f.primary)
	if !r.CanRead(primary, f.parent) || r.CanRead(primary, featureDir) || r.CanRead(featureDir, f.parent) {
		t.Errorf("CanRead: hub→parent %v, hub→feature %v, feature→parent %v", r.CanRead(primary, f.parent),
			r.CanRead(primary, featureDir), r.CanRead(featureDir, f.parent))
	}
}

// TestReaders_RemovingAProjectTakesEveryEntryNamingIt: both sides of every
// list, each with its audit row saying why; entries not naming it stay.
func TestReaders_RemovingAProjectTakesEveryEntryNamingIt(t *testing.T) {
	f, reader := newReadersFixture(t)
	other := setupProjectDir(t, "a third project", nil)
	registerOwned(t, other, aliceEmail)
	put := func(project, reader string) {
		t.Helper()
		if code, body := f.call(t, f.alice, http.MethodPut, f.readersURL(t, f.alice, project), map[string]any{"reader": reader}); code != http.StatusOK {
			t.Fatalf("add %s to %s: %d %v", reader, project, code, body)
		}
	}
	put(f.project, reader) // the reader reads the project
	put(reader, other)     // the third reads the reader
	put(other, f.project)  // the project reads the third: untouched by what follows

	if code, body := f.call(t, f.alice, http.MethodDelete, "/api/projects/"+itoa(f.idx(t, f.alice, reader)), nil); code != http.StatusOK {
		t.Fatalf("remove the reader from the hub: %d %v", code, body)
	}
	r := readersOf(t, f.srv)
	if len(r.All()) != 1 || !r.CanRead(f.project, other) {
		t.Fatalf("after the removal: %+v, want only the third project's entry", r.All())
	}
	var reasons []string
	for _, ev := range readerAuditRows(t, f.srv) {
		if ev.EventType != string(auditaction.ActionProjectReaderRemove) {
			continue
		}
		var p map[string]any
		_ = json.Unmarshal([]byte(ev.Payload), &p)
		reasons = append(reasons, p["reason"].(string))
		if !strings.Contains(ev.EntityID, reader) {
			t.Errorf("a removal row for an entry that did not name the project: %s", ev.EntityID)
		}
	}
	if len(reasons) != 2 || reasons[0] != "the project was removed from the hub" || reasons[1] != reasons[0] {
		t.Errorf("removal rows' reasons: %v", reasons)
	}
}

// TestReaders_SurviveARename: the registry entry's name is a label; the
// entries name the project's path, and the list shows the new name.
func TestReaders_SurviveARename(t *testing.T) {
	f, reader := newReadersFixture(t)
	list := f.readersURL(t, f.alice, f.project)
	if code, body := f.call(t, f.alice, http.MethodPut, list, map[string]any{"reader": reader}); code != http.StatusOK {
		t.Fatalf("add: %d %v", code, body)
	}
	entries, err := multiui.Load()
	if err != nil {
		t.Fatal(err)
	}
	for i := range entries {
		if entries[i].Path == reader {
			entries[i].Name = "renamed-reader"
		}
		if entries[i].Path == f.project {
			entries[i].Name = "renamed-project"
		}
	}
	if err := multiui.Save(entries); err != nil {
		t.Fatal(err)
	}
	f.srv.refreshProjectStatuses()
	code, body := f.call(t, f.alice, http.MethodGet, f.readersURL(t, f.alice, f.project), nil)
	readers, _ := body["readers"].([]any)
	if code != http.StatusOK || body["project"] != "renamed-project" || len(readers) != 1 ||
		readers[0].(map[string]any)["project"] != "renamed-reader" {
		t.Fatalf("after the rename: %d %v", code, body)
	}
	if !readersOf(t, f.srv).CanRead(reader, f.project) {
		t.Error("the entry lapsed with the rename")
	}
}

// TestReaders_SurviveAMove: a move keeps the project's path, so it keeps both
// sides of its lists — and its preflight counts them among what it carries.
func TestReaders_SurviveAMove(t *testing.T) {
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir, db, srv, ts := movingProject(t)
	reader := setupProjectDir(t, "reads the moving project", nil)
	if err := multiui.AddPaths([]string{reader}); err != nil {
		t.Fatal(err)
	}
	put := func(idx int, readerIdx int) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/projects/"+itoa(idx)+"/readers",
			strings.NewReader(`{"reader_idx":`+itoa(readerIdx)+`}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Reader readerView `json:"reader"`
		}
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&out) != nil {
			t.Fatalf("add a reader to project %d: %d", idx, resp.StatusCode)
		}
		return out.Reader.ID
	}
	readsIt, itReads := put(0, 1), put(1, 0)

	env := &moveEnv{s: srv, r: httptest.NewRequest(http.MethodGet, "/", nil), now: time.Now()}
	bindings, err := env.PathBindings(t.Context(), projectmove.Project{Name: "moving", Path: dir})
	env.close()
	if err != nil {
		t.Fatal(err)
	}
	counted := -1
	for _, b := range bindings {
		if b.Store == "project_readers" {
			counted = b.Count
		}
	}
	if counted != 2 {
		t.Errorf("the preflight counts %d readers-list entries keyed by the path, want 2", counted)
	}

	box := newHarnessExec("rd-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordExecutor(t, db, "rd-box", executor.KindContainer)
	code, m, raw := startMoveOver(t, ts.URL, `{"target":"rd-box"}`)
	if code != http.StatusAccepted {
		t.Fatalf("start = HTTP %d: %s", code, raw)
	}
	if m = waitForMove(t, srv, m.ID); m.Phase != projectmove.PhaseDone {
		t.Fatalf("move ended %s at %s: %s", m.Phase, m.FailedPhase, m.Error)
	}
	r := readersOf(t, srv)
	a, okA := r.Entry(dir, reader)
	b, okB := r.Entry(reader, dir)
	if !okA || !okB || a.ID != readsIt || b.ID != itReads || len(r.All()) != 2 {
		t.Fatalf("after the move: %+v", r.All())
	}
	if !r.CanRead(reader, dir) || !r.CanRead(dir, reader) {
		t.Error("a moved project's lists stopped answering")
	}
}
