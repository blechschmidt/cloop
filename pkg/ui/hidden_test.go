package ui

// Tests for hiding projects from the dashboard (Task 20206).
//
// Three properties carry the feature, and each has burned this codebase
// before in some other guise:
//
//   - Hiding is presentation, not renumbering. Project indices address runs,
//     stops, deletes and every ?project_idx call; a hidden project therefore
//     stays in the payload, flagged, rather than being dropped out of it.
//   - Hiding is per viewer. The registry is one shared file.
//   - Hiding is not access control. It must not become the thing standing
//     between one tenant and another's project.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// projectsPayload is the decoded /api/projects response.
type projectsPayload struct {
	Projects []multiui.ProjectStatus  `json:"projects"`
	Stats    multiui.AggregateStats   `json:"stats"`
	Multi    bool                     `json:"multi_project"`
	Raw      []map[string]interface{} `json:"-"`
}

// getProjects fetches /api/projects through client (nil = default).
func getProjects(t *testing.T, c *http.Client, url string) projectsPayload {
	t.Helper()
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Get(url + "/api/projects")
	if err != nil {
		t.Fatalf("GET /api/projects: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/projects = %d", resp.StatusCode)
	}
	var out projectsPayload
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /api/projects: %v", err)
	}
	return out
}

// postHidden calls the hide/unhide endpoint for a project index.
func postHidden(t *testing.T, c *http.Client, url string, idx int, hidden bool) *http.Response {
	t.Helper()
	if c == nil {
		c = http.DefaultClient
	}
	body := `{"hidden":false}`
	if hidden {
		body = `{"hidden":true}`
	}
	req, err := http.NewRequest(http.MethodPost,
		url+"/api/projects/"+strconv.Itoa(idx)+"/hidden", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST hidden: %v", err)
	}
	return resp
}

// TestHideProjectRoundTrip is the feature end to end on a single-tenant hub:
// hide, observe, restore.
func TestHideProjectRoundTrip(t *testing.T) {
	t.Setenv(multiui.EnvRoot, t.TempDir())

	primary := setupProjectDir(t, "primary goal", nil)
	second := setupProjectDir(t, "second goal", nil)
	ts := newTestServer(t, primary, []string{second})

	before := getProjects(t, nil, ts.URL)
	if len(before.Projects) != 2 {
		t.Fatalf("expected 2 projects to start, got %d", len(before.Projects))
	}
	if before.Projects[0].Hidden || before.Projects[1].Hidden {
		t.Fatal("a project reported itself hidden before anything was hidden")
	}

	resp := postHidden(t, nil, ts.URL, 1, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST hidden = %d, want 200", resp.StatusCode)
	}

	after := getProjects(t, nil, ts.URL)
	// Still two entries: dropping one would renumber the list and send every
	// index-addressed call after it to the wrong project.
	if len(after.Projects) != 2 {
		t.Fatalf("hiding a project changed the list length to %d — indices must stay stable",
			len(after.Projects))
	}
	if after.Projects[0].Path != primary || after.Projects[1].Path != second {
		t.Errorf("hiding reordered the list: got %s, %s",
			after.Projects[0].Path, after.Projects[1].Path)
	}
	if after.Projects[0].Hidden {
		t.Error("the wrong project came back hidden")
	}
	if !after.Projects[1].Hidden {
		t.Error("the hidden project is not flagged hidden")
	}
	if after.Stats.TotalProjects != 1 {
		t.Errorf("stats.total_projects = %d, want 1 — hidden projects must not be counted",
			after.Stats.TotalProjects)
	}

	resp = postHidden(t, nil, ts.URL, 1, false)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST unhide = %d, want 200", resp.StatusCode)
	}
	restored := getProjects(t, nil, ts.URL)
	if restored.Projects[1].Hidden {
		t.Error("unhide did not restore the project")
	}
	if restored.Stats.TotalProjects != 2 {
		t.Errorf("stats.total_projects = %d after unhide, want 2", restored.Stats.TotalProjects)
	}
}

// TestHidePrimaryProjectPersists covers the project that is *not* in the
// registry: the directory the server was launched in. allProjectEntries
// synthesizes an entry for it before reading the registry, so a naive
// implementation drops the stored preference as a duplicate and the card
// silently reappears.
func TestHidePrimaryProjectPersists(t *testing.T) {
	t.Setenv(multiui.EnvRoot, t.TempDir())

	primary := setupProjectDir(t, "primary goal", nil)
	second := setupProjectDir(t, "second goal", nil)
	ts := newTestServer(t, primary, []string{second})

	resp := postHidden(t, nil, ts.URL, 0, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST hidden = %d, want 200", resp.StatusCode)
	}

	got := getProjects(t, nil, ts.URL)
	if len(got.Projects) != 2 || got.Projects[0].Path != primary {
		t.Fatalf("unexpected list: %+v", got.Projects)
	}
	if !got.Projects[0].Hidden {
		t.Error("hiding the server's own working directory did not stick — its " +
			"registry entry is being dropped as a duplicate of the synthesized one")
	}
}

// TestHideIsPerViewerOverHTTP is the tenancy property at the wire level:
// what alice hides, bob still sees.
func TestHideIsPerViewerOverHTTP(t *testing.T) {
	t.Setenv(multiui.EnvRoot, t.TempDir())

	idp := newUIFakeIdP(t)
	_, ts := newOIDCTestServer(t, idp, "", nil)

	shared := setupProjectDir(t, "shared project", nil)
	if err := multiui.AddPathsOwned([]string{shared}, ""); err != nil {
		t.Fatal(err)
	}

	idp.email, idp.sub, idp.name = "alice@example.com", "sub-alice", "Alice"
	alice := jarClient(t)
	login(t, alice, ts)

	idp.email, idp.sub, idp.name = "bob@example.com", "sub-bob", "Bob"
	bob := jarClient(t)
	login(t, bob, ts)

	// Locate the shared project in alice's list; her index namespace is the
	// one her POST will be resolved against.
	idxOf := func(p projectsPayload, path string) int {
		for i, st := range p.Projects {
			if st.Path == path {
				return i
			}
		}
		t.Fatalf("project %s not in list %+v", path, p.Projects)
		return -1
	}
	aliceBefore := getProjects(t, alice, ts.URL)
	resp := postHidden(t, alice, ts.URL, idxOf(aliceBefore, shared), true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice POST hidden = %d, want 200", resp.StatusCode)
	}

	aliceAfter := getProjects(t, alice, ts.URL)
	if !aliceAfter.Projects[idxOf(aliceAfter, shared)].Hidden {
		t.Error("alice hid the shared project but it is not flagged for her")
	}

	bobAfter := getProjects(t, bob, ts.URL)
	if bobAfter.Projects[idxOf(bobAfter, shared)].Hidden {
		t.Error("alice hiding a shared project also hid it from bob — the " +
			"registry is shared between tenants, the preference must not be")
	}
}

// TestHiddenIsNotAccessControl states the boundary out loud. Hiding must
// never be reachable as a way to affect a project the caller cannot see, and
// must never be mistaken for a way to keep one out of their reach.
func TestHiddenIsNotAccessControl(t *testing.T) {
	t.Setenv(multiui.EnvRoot, t.TempDir())

	idp := newUIFakeIdP(t)
	_, ts := newOIDCTestServer(t, idp, "", nil)

	bobDir := setupProjectDir(t, "bob project", nil)
	if err := multiui.AddPathsOwned([]string{bobDir}, "bob@example.com"); err != nil {
		t.Fatal(err)
	}

	idp.email, idp.sub, idp.name = "alice@example.com", "sub-alice", "Alice"
	alice := jarClient(t)
	login(t, alice, ts)

	// Bob's project is not in alice's index namespace at all. Every index she
	// can name must therefore resolve to something that is hers, and none of
	// them may reach his.
	list := getProjects(t, alice, ts.URL)
	for _, st := range list.Projects {
		if st.Path == bobDir {
			t.Fatal("alice can see bob's project — precondition for this test is broken")
		}
	}
	// One past the end of her list: the gate must refuse rather than fall
	// through to a broader scope.
	resp := postHidden(t, alice, ts.URL, len(list.Projects), true)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("hiding an out-of-range index returned 200; the index namespace " +
			"is per-caller and an unresolvable index must be refused")
	}

	// And the converse: a project alice *has* hidden is still delivered to
	// her and still addressable, because hiding conceals nothing.
	if len(list.Projects) > 0 {
		resp := postHidden(t, alice, ts.URL, 0, true)
		resp.Body.Close()
		after := getProjects(t, alice, ts.URL)
		if len(after.Projects) != len(list.Projects) {
			t.Errorf("hiding removed a project from the payload (%d → %d); it must "+
				"stay addressable so settings can restore it",
				len(list.Projects), len(after.Projects))
		}
	}
}

// TestViewPrefsIsGrantedFromViewerUp pins the permission to the bottom of the
// ladder. Tidying your own dashboard is not an administrative act, and gating
// it higher would leave the roles that live in the dashboard unable to do it.
func TestViewPrefsIsGrantedFromViewerUp(t *testing.T) {
	t.Parallel()

	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleMaintainer, authz.RoleAdmin} {
		if !contains(role.Permissions(), authz.PermViewPrefs) {
			t.Errorf("role %q does not hold %s", role, authz.PermViewPrefs)
		}
	}
	if contains(authz.RoleNone.Permissions(), authz.PermViewPrefs) {
		t.Errorf("role none holds %s — deny-by-default must still deny", authz.PermViewPrefs)
	}
}

// TestProjectsPayloadKeySeparatesViewers is the broadcast-cache trap.
//
// broadcastProjectsUpdate marshals one payload per distinct key and reuses it
// for every client sharing that key. visibilityKey deliberately collapses
// admins, unscoped-token clients and (OIDC off) every browser onto "", since
// authorization gives them the same list. Hiding does not: two admins who hid
// different projects need different payloads, and keying on authorization
// alone would hand whichever broadcast first to both.
func TestProjectsPayloadKeySeparatesViewers(t *testing.T) {
	t.Parallel()

	s := &Server{}
	alice := &oidcauth.Identity{Sub: "sub-alice", Email: "alice@example.com"}
	bob := &oidcauth.Identity{Sub: "sub-bob", Email: "bob@example.com"}

	// Nothing hidden anywhere: the cache should still collapse, or every
	// broadcast pays a marshal per connected client.
	if s.projectsPayloadKey(alice, nil, false) != s.projectsPayloadKey(bob, nil, false) {
		t.Error("with nothing hidden, two clients that see the same projects must share a payload")
	}

	// Someone has hidden something: the payload now depends on who is asking.
	if s.projectsPayloadKey(alice, nil, true) == s.projectsPayloadKey(bob, nil, true) {
		t.Error("two viewers share a cached projects payload once hiding is in play — " +
			"one user's hidden project would be broadcast as hidden to the other")
	}

	// A project-scoped token must keep contributing its own scope.
	tok := &apitoken.Token{ID: "tok1", ProjectScope: []string{"alpha"}}
	if s.projectsPayloadKey(alice, tok, true) == s.projectsPayloadKey(alice, nil, true) {
		t.Error("token scope stopped contributing to the payload key")
	}
}

// TestEntriesHaveHidden checks the flag that preserves the shared-payload
// fast path for the overwhelmingly common case of nobody hiding anything.
func TestEntriesHaveHidden(t *testing.T) {
	t.Parallel()

	if entriesHaveHidden(nil) {
		t.Error("an empty registry reported hidden projects")
	}
	plain := []multiui.ProjectEntry{{Path: "/a"}, {Path: "/b"}}
	if entriesHaveHidden(plain) {
		t.Error("a registry with no hidden_for reported hidden projects")
	}
	withHidden := append(plain, multiui.ProjectEntry{Path: "/c", HiddenFor: []string{"alice@example.com"}})
	if !entriesHaveHidden(withHidden) {
		t.Error("a registry with a hidden project reported none")
	}
}

// TestMarkHiddenForDoesNotMutateSharedCache guards the aliasing hazard: the
// status slice handed to the filter is the server's shared cache, read
// concurrently by every connected client. Stamping one recipient's
// preference into it would serve that preference to all of them.
func TestMarkHiddenForDoesNotMutateSharedCache(t *testing.T) {
	t.Parallel()

	shared := []multiui.ProjectStatus{{Path: "/a"}, {Path: "/b"}}
	entries := []multiui.ProjectEntry{
		{Path: "/a", HiddenFor: []string{"alice@example.com"}},
		{Path: "/b"},
	}

	marked, changed := markHiddenFor("alice@example.com", entries, shared)
	if !changed || !marked[0].Hidden {
		t.Fatal("alice's hidden project was not marked")
	}
	if shared[0].Hidden {
		t.Error("marking wrote through to the shared status cache — every other " +
			"connected client would receive alice's preference as their own")
	}

	// A viewer who hid nothing gets the original slice back untouched.
	same, changed := markHiddenFor("bob@example.com", entries, shared)
	if changed {
		t.Error("bob hid nothing but the filter reported a change")
	}
	if same[0].Hidden {
		t.Error("bob sees alice's project as hidden")
	}
}

// TestViewerKeyForFallsBackToLocal pins the single-tenant identity. Without a
// stable key there, SetHidden would refuse the write and hiding would appear
// to do nothing on every deployment that has not enabled OIDC.
func TestViewerKeyForFallsBackToLocal(t *testing.T) {
	t.Parallel()

	if got := viewerKeyFor(nil); got != localViewer {
		t.Errorf("viewerKeyFor(nil) = %q, want %q", got, localViewer)
	}
	if got := viewerKeyFor(&oidcauth.Identity{}); got != localViewer {
		t.Errorf("viewerKeyFor(empty identity) = %q, want %q", got, localViewer)
	}
	if got := viewerKeyFor(&oidcauth.Identity{Sub: "s1", Email: "Alice@Example.com"}); got != "alice@example.com" {
		t.Errorf("viewerKeyFor(alice) = %q, want her lowercased owner key", got)
	}
	// The sentinel must not be able to collide with a real key.
	if strings.Contains(localViewer, "@") || strings.HasPrefix(localViewer, "sub:") {
		t.Errorf("localViewer = %q could collide with a real OwnerKey", localViewer)
	}
}
