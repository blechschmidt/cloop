package ui

// End-to-end tests for the GitHub App surface (Task 20306).
//
// The hermetic half checks the input validation and the authorization edges,
// which is what most callers will hit. The live half drives the whole operator
// flow — connect, enumerate, assign, list, revoke — against api.github.com,
// because the point of the feature is that the hub can answer two questions
// the operator cannot, and only GitHub can say whether it really does.
//
// The live tests skip unless CLOOP_GITHUB_APP_ID and CLOOP_GITHUB_APP_KEY are
// set, so `go test ./...` stays hermetic and needs no credentials.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/state"
)

// ---------------------------------------------------------------------------
// Hermetic
// ---------------------------------------------------------------------------

// TestGitHubAppInstallationsRejectsIncompleteInput: both fields are required,
// and the message has to name which one is missing and where to find it. A
// discovery call that reached GitHub with an empty key would fail with GitHub's
// wording, which says nothing about cloop's dialog.
func TestGitHubAppInstallationsRejectsIncompleteInput(t *testing.T) {
	dir := t.TempDir()
	if _, err := state.Init(dir, "goal", 10); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	ts := newTestServer(t, dir, nil)

	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"no app id", map[string]any{"private_key": "x"}, "app_id is required"},
		{"zero app id", map[string]any{"app_id": 0, "private_key": "x"}, "app_id is required"},
		{"no key", map[string]any{"app_id": 1234}, "private_key is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			resp, err := http.Post(ts.URL+"/api/github-app/installations",
				"application/json", strings.NewReader(string(body)))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("incomplete input was accepted: %s", raw)
			}
			if !strings.Contains(string(raw), tc.want) {
				t.Errorf("response %s does not explain the problem (want %q)", raw, tc.want)
			}
		})
	}
}

// TestGitHubAppRepositoriesRequiresASecret: the inventory route names a stored
// credential, and without one there is nothing to enumerate.
func TestGitHubAppRepositoriesRequiresASecret(t *testing.T) {
	dir := t.TempDir()
	if _, err := state.Init(dir, "goal", 10); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	ts := newTestServer(t, dir, nil)

	resp, err := http.Get(ts.URL + "/api/github-app/repositories")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a request naming no secret was accepted: %s", raw)
	}
	if !strings.Contains(string(raw), "secret is required") {
		t.Errorf("response %s does not say what is missing", raw)
	}
}

// TestProjectRepositoriesRejectsAnEmptyAllowlist: a grant with no repositories
// authorises nothing, and the broker would refuse it anyway — but the refusal
// belongs in front of the person who forgot to tick a box.
func TestProjectRepositoriesRejectsAnEmptyAllowlist(t *testing.T) {
	dir := t.TempDir()
	if _, err := state.Init(dir, "goal", 10); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	ts := newTestServer(t, dir, nil)

	for _, body := range []string{`{"secret":"x","repos":[]}`, `{"secret":"x","repos":["  "]}`} {
		resp, err := http.Post(ts.URL+"/api/projects/0/repositories",
			"application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("empty allowlist accepted for %s: %s", body, raw)
		}
		if !strings.Contains(string(raw), "at least one repository") {
			t.Errorf("response %s does not explain the empty allowlist", raw)
		}
	}
}

// TestRepoAccessPermissions pins the two-word access level's expansion.
//
// It is the one place the panel's vocabulary becomes a GitHub permission set,
// so a change here silently widens or narrows every grant made through the UI.
func TestRepoAccessPermissions(t *testing.T) {
	read, err := repoAccessPermissions("read")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(read) != 1 || read[0] != "contents:read" {
		t.Errorf("read expands to %v, want [contents:read]", read)
	}
	write, err := repoAccessPermissions("write")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	// Nothing beyond contents and pull_requests: an agent that can push and
	// open a PR is the whole use, and administration or workflows would be a
	// materially different grant wearing the same word.
	for _, p := range write {
		if !strings.HasPrefix(p, "contents:") && !strings.HasPrefix(p, "pull_requests:") {
			t.Errorf("write access grants %q, which is beyond pushing and proposing", p)
		}
	}
	if !slices.Contains(write, "contents:write") {
		t.Errorf("write access does not grant contents:write: %v", write)
	}
	// An empty access level must mean the safe one.
	def, err := repoAccessPermissions("")
	if err != nil || len(def) != 1 || def[0] != "contents:read" {
		t.Errorf("unspecified access = %v (err %v), want read-only", def, err)
	}
	if _, err := repoAccessPermissions("admin"); err == nil {
		t.Error("an unrecognised access level was accepted")
	}
}

// ---------------------------------------------------------------------------
// Live
// ---------------------------------------------------------------------------

// TestLiveGitHubAppFlowThroughTheAPI walks the operator's whole path through
// the HTTP surface the dashboard uses: connect an App, store it, enumerate its
// repositories, assign one to a project, see it listed, revoke it.
func TestLiveGitHubAppFlowThroughTheAPI(t *testing.T) {
	appID := strings.TrimSpace(os.Getenv("CLOOP_GITHUB_APP_ID"))
	keyPath := strings.TrimSpace(os.Getenv("CLOOP_GITHUB_APP_KEY"))
	if appID == "" || keyPath == "" {
		t.Skip("set CLOOP_GITHUB_APP_ID and CLOOP_GITHUB_APP_KEY to run the live flow")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	t.Setenv("CLOOP_SECRET_KEY", "live-ui-flow-passphrase")

	dir := t.TempDir()
	if _, err := state.Init(dir, "github app flow", 10); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	ts := newTestServer(t, dir, nil)

	// 1. Discover. This is the step that used to be impossible: the operator
	//    has an App ID and a key, and no installation ID.
	var discovered struct {
		Installations []installationView `json:"installations"`
	}
	postJSON(t, ts, "/api/github-app/installations", map[string]any{
		"app_id":      appID,
		"private_key": string(keyPEM),
	}, &discovered)
	if len(discovered.Installations) == 0 {
		t.Fatal("discovery returned no installations")
	}
	inst := discovered.Installations[0]
	t.Logf("discovered installation %d on %s (%s)", inst.ID, inst.Account, inst.AccountType)
	if inst.Account == "" {
		t.Error("the dialog would render an installation with no account name")
	}

	// 2. Store it the way the panel does.
	payload, _ := json.Marshal(map[string]any{
		"app_id":          json.RawMessage(appID),
		"installation_id": inst.ID,
		"private_key":     string(keyPEM),
	})
	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	postJSON(t, ts, "/api/secrets", map[string]any{
		"name":     "live-app",
		"kind":     "github_app",
		"payload":  string(payload),
		"personal": false,
	}, &created)
	if created.ID == "" {
		t.Fatal("the App was not stored")
	}

	// 3. Enumerate. The names offered in the picker come from here.
	var inventory struct {
		Repositories []repositoryView `json:"repositories"`
	}
	getJSON(t, ts, "/api/github-app/repositories?secret="+created.ID, &inventory)
	t.Logf("installation covers %d repositories", len(inventory.Repositories))
	if len(inventory.Repositories) == 0 {
		t.Skip("the installation covers no repositories, so there is nothing to assign")
	}
	target := inventory.Repositories[0].FullName

	// 4. Assign one to the project.
	var assigned projectRepoAssignment
	postJSON(t, ts, "/api/projects/0/repositories", map[string]any{
		"secret": created.ID,
		"repos":  []string{target},
		"access": "write",
	}, &assigned)
	if assigned.GrantID == "" {
		t.Fatal("no grant was created")
	}
	if assigned.Access != "write" {
		t.Errorf("assignment access = %q, want write", assigned.Access)
	}

	// 5. It shows up as this project's access.
	var listed struct {
		Apps        []githubAppChoice       `json:"apps"`
		Assignments []projectRepoAssignment `json:"assignments"`
	}
	getJSON(t, ts, "/api/projects/0/repositories", &listed)
	if len(listed.Apps) == 0 {
		t.Error("the connected App is not offered to the project")
	}
	var found bool
	for _, a := range listed.Assignments {
		if a.GrantID == assigned.GrantID && slices.Contains(a.Repos, target) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the new grant is not listed as project access: %+v", listed.Assignments)
	}

	// 6. And can be withdrawn again.
	req, _ := http.NewRequest(http.MethodDelete,
		ts.URL+"/api/projects/0/repositories?grant="+assigned.GrantID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke returned HTTP %d: %s", resp.StatusCode, raw)
	}
	getJSON(t, ts, "/api/projects/0/repositories", &listed)
	for _, a := range listed.Assignments {
		if a.GrantID == assigned.GrantID {
			t.Errorf("grant %s still listed after revocation", a.GrantID)
		}
	}
}

// postJSON posts a body and decodes the response, failing on a non-200.
func postJSON(t *testing.T, ts *httptest.Server, path string, body any, out any) {
	t.Helper()
	enc, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s body: %v", path, err)
	}
	resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader(string(enc)))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s returned HTTP %d: %s", path, resp.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("decode %s response %s: %v", path, raw, err)
		}
	}
	// Nothing that came back may contain key material. The response shapes are
	// all public identifiers by construction; this catches a future field that
	// is not.
	if k := os.Getenv("CLOOP_GITHUB_APP_KEY"); k != "" {
		if pem, rerr := os.ReadFile(k); rerr == nil {
			assertNoKeyMaterial(t, path, string(raw), string(pem))
		}
	}
}

func getJSON(t *testing.T, ts *httptest.Server, path string, out any) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned HTTP %d: %s", path, resp.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode %s response %s: %v", path, raw, err)
	}
	if k := os.Getenv("CLOOP_GITHUB_APP_KEY"); k != "" {
		if pem, rerr := os.ReadFile(k); rerr == nil {
			assertNoKeyMaterial(t, path, string(raw), string(pem))
		}
	}
}

// assertNoKeyMaterial fails if a response echoed any line of the private key's
// body. The armour lines are skipped: they appear in every PEM and matching
// them would flag a response that merely mentioned the format.
func assertNoKeyMaterial(t *testing.T, path, body, pem string) {
	t.Helper()
	for _, line := range strings.Split(pem, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 40 || strings.HasPrefix(line, "-----") {
			continue
		}
		if strings.Contains(body, line) {
			t.Fatal(fmt.Sprintf("the response to %s echoed private key material", path))
		}
	}
}
