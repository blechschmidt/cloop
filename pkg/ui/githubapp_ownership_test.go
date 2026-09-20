package ui

// Ownership of a connected GitHub App (Task 20323).
//
// The bug these pin was reported as one sentence — "although I have a GitHub
// App installed, granting repository access to a project says
// secretbroker: secret not found: github-bb-se…" — and was three defects
// stacked so that each hid the next:
//
//  1. Mint stored the Owner it was handed regardless of MintRequest.Personal,
//     so connecting an App from the Settings dialog, which asks for a *shared*
//     one, produced a secret personally owned by whoever was signed in.
//  2. The assign handler called Broker.Grant without a Viewer. The zero Viewer
//     owns nothing, so a personal secret was refused — as a not-found, because
//     the broker deliberately will not confirm a name to someone who may not
//     see it. Not even the owner could spend their own credential.
//  3. The panel behind it listed secrets and grants unscoped, so the App still
//     appeared in the dropdown. The operator was offered a choice the next
//     request refused to honour, and told the thing they had just connected
//     did not exist.
//
// Written against the HTTP surface rather than the broker because every one of
// the three is a handler passing the wrong thing to a broker that was already
// correct — pkg/secretbroker's own tests were green throughout.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// testAppKeyPEM returns a PKCS#8 RSA key, generated once for the whole package.
//
// ParseGitHubApp really parses it — a github_app payload is refused at mint
// time if the key is not a key — so these tests cannot use a placeholder. One
// 2048-bit generation is affordable; one per test is not.
var testAppKeyPEM = sync.OnceValue(func() string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("generate test RSA key: " + err.Error())
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic("marshal test RSA key: " + err.Error())
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
})

// appPayload is the JSON body the Connect dialog seals as a github_app secret.
func appPayload(t *testing.T) string {
	t.Helper()
	blob, err := json.Marshal(map[string]any{
		"app_id":          1234,
		"installation_id": 5678,
		"private_key":     testAppKeyPEM(),
	})
	if err != nil {
		t.Fatalf("marshal github_app payload: %v", err)
	}
	return string(blob)
}

// connectApp stores a github_app secret the way the dashboard does, and returns
// the decoded response so a caller can assert on the ownership it came back
// with.
func connectApp(t *testing.T, f *personalFixture, who, name string, personal bool) struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Owner    string `json:"owner"`
	Personal bool   `json:"personal"`
} {
	t.Helper()
	code, body := f.postJSON(t, who, "/api/secrets", map[string]any{
		"name":     name,
		"kind":     "github_app",
		"payload":  appPayload(t),
		"personal": personal,
	})
	if code != http.StatusOK {
		t.Fatalf("%s connecting %s = %d, want 200\nbody: %s", who, name, code, body)
	}
	var out struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Owner    string `json:"owner"`
		Personal bool   `json:"personal"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode mint response: %v\nbody: %s", err, body)
	}
	return out
}

// projectRepos is the repositories panel as one person sees it.
type projectRepos struct {
	Apps []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"apps"`
	Assignments []struct {
		GrantID    string   `json:"grant_id"`
		SecretName string   `json:"secret_name"`
		Repos      []string `json:"repos"`
		Access     string   `json:"access"`
	} `json:"assignments"`
}

func loadProjectRepos(t *testing.T, f *personalFixture, who string) projectRepos {
	t.Helper()
	code, body := getFull(t, f.clients[who], f.base+"/api/projects/0/repositories")
	if code != http.StatusOK {
		t.Fatalf("%s GET repositories = %d, want 200\nbody: %s", who, code, body)
	}
	var out projectRepos
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode repositories: %v\nbody: %s", err, body)
	}
	return out
}

func (p projectRepos) appNames() []string {
	names := make([]string, 0, len(p.Apps))
	for _, a := range p.Apps {
		names = append(names, a.Name)
	}
	return names
}

// TestConnectingASharedGitHubAppStaysShared is defect 1.
//
// The Connect dialog sends personal:false and says why in a comment: an App an
// admin connects is infrastructure the whole hub grants from, and a personal
// one "would be invisible to every other maintainer and could not be assigned
// to a shared project". Mint honoured the Owner and ignored the flag, so the
// dialog's explicit choice was silently inverted on every OIDC hub.
func TestConnectingASharedGitHubAppStaysShared(t *testing.T) {
	f := newPersonalFixture(t)

	got := connectApp(t, f, "lead", "github-acme", false)
	if got.Personal || got.Owner != "" {
		t.Fatalf("an App connected as shared came back owned by %q (personal=%v); "+
			"the whole hub can no longer grant from it", got.Owner, got.Personal)
	}
}

// TestPersonalMintStillRecordsItsOwner guards the fix from overshooting: the
// cure for defect 1 is to stop storing an owner the caller did not ask for, not
// to stop storing owners.
func TestPersonalMintStillRecordsItsOwner(t *testing.T) {
	f := newPersonalFixture(t)

	got := connectApp(t, f, "lead", "github-lead-personal", true)
	if !got.Personal || got.Owner != "lead@corp.example" {
		t.Fatalf("a personal App came back owner=%q personal=%v, want lead@corp.example/true",
			got.Owner, got.Personal)
	}
}

// TestOwnerCanAssignTheirPersonalGitHubApp is defect 2, and is the reported
// symptom exactly: the person who connected the App, signed in as themselves,
// assigning it to their own project.
//
// The assertion is on the message as well as the status, because "secret not
// found" for a secret the same request had just listed is the part that made
// this impossible to diagnose from the dashboard.
func TestOwnerCanAssignTheirPersonalGitHubApp(t *testing.T) {
	f := newPersonalFixture(t)
	connectApp(t, f, "lead", "github-bb-selforg", true)

	code, body := f.postJSON(t, "lead", "/api/projects/0/repositories", map[string]any{
		"secret": "github-bb-selforg",
		"repos":  []string{"bb-selforg/cloop-hello-world"},
		"access": "write",
	})
	if code != http.StatusOK {
		t.Fatalf("the owner assigning their own App = %d, want 200\nbody: %s", code, body)
	}
	if strings.Contains(body, "not found") {
		t.Fatalf("the owner was told their own App does not exist: %s", body)
	}

	// And it shows up as a live assignment, so the panel agrees with the grant
	// that was just written.
	panel := loadProjectRepos(t, f, "lead")
	if len(panel.Assignments) != 1 {
		t.Fatalf("after assigning, the panel shows %d assignments, want 1",
			len(panel.Assignments))
	}
	if got := panel.Assignments[0].SecretName; got != "github-bb-selforg" {
		t.Errorf("assignment names secret %q, want github-bb-selforg", got)
	}
	if got := panel.Assignments[0].Access; got != "write" {
		t.Errorf("assignment access = %q, want write", got)
	}
}

// TestSharedGitHubAppRemainsAssignable is the other half of defect 2: passing a
// Viewer must not narrow the shared case, which is every hub that predates
// personal secrets and every hub with no IdP at all.
func TestSharedGitHubAppRemainsAssignable(t *testing.T) {
	f := newPersonalFixture(t)
	connectApp(t, f, "lead", "github-shared", false)

	code, body := f.postJSON(t, "lead", "/api/projects/0/repositories", map[string]any{
		"secret": "github-shared",
		"repos":  []string{"acme/tool"},
		"access": "read",
	})
	if code != http.StatusOK {
		t.Fatalf("assigning a shared App = %d, want 200\nbody: %s", code, body)
	}
}

// TestRepositoryPanelOffersSharedAppsToAProjectScopedMaintainer guards the
// narrowing from overshooting in the direction that is easy to miss.
//
// Both repository routes are evaluated against *this project's* scope, so a
// maintainer bound to one project may grant there and nowhere else. A dropdown
// that asked the global scope instead would answer "no" for exactly that person
// and hide the Apps their own POST accepts — the same dropdown-disagrees-with-
// the-handler shape as the original bug, one scope over.
func TestRepositoryPanelOffersSharedAppsToAProjectScopedMaintainer(t *testing.T) {
	f := newPersonalFixture(t)
	connectApp(t, f, "lead", "github-shared", false)

	// alice is a global operator: not a maintainer anywhere, so she must not be
	// offered the shared App...
	if names := loadProjectRepos(t, f, "alice").appNames(); hasName(names, "github-shared") {
		t.Errorf("an operator was offered a shared App they cannot grant: %v", names)
	}

	// ...while the maintainer is, and the POST agrees.
	names := loadProjectRepos(t, f, "lead").appNames()
	if !hasName(names, "github-shared") {
		t.Fatalf("the maintainer was not offered the shared App they can grant: %v", names)
	}
	code, body := f.postJSON(t, "lead", "/api/projects/0/repositories", map[string]any{
		"secret": "github-shared",
		"repos":  []string{"acme/tool"},
		"access": "read",
	})
	if code != http.StatusOK {
		t.Fatalf("the App the panel offered was refused by the POST: %d\nbody: %s", code, body)
	}
}

// TestRepositoryPanelHidesAnotherUsersApp is defect 3, in the direction that
// matters most: the panel is gated on project.read, so before this every person
// who could open a project's Overview tab was shown the name and ID of every
// GitHub App on the hub — including the personal ones their colleagues had
// connected.
func TestRepositoryPanelHidesAnotherUsersApp(t *testing.T) {
	f := newPersonalFixture(t)
	connectApp(t, f, "lead", "github-lead-private", true)

	if names := loadProjectRepos(t, f, "alice").appNames(); hasName(names, "github-lead-private") {
		t.Fatalf("alice, who merely reads the project, was shown lead's personal App: %v", names)
	}
}

// TestRepositoryPanelOffersOnlyWhatItWillGrant is defect 3 in the direction
// that produced the confusing error. An admin may *see* a colleague's personal
// secret — offboarding requires it — but may never spend one, so offering it in
// a dropdown whose only purpose is to spend it guarantees the refusal the bug
// report opened with.
func TestRepositoryPanelOffersOnlyWhatItWillGrant(t *testing.T) {
	f := newPersonalFixture(t)
	connectApp(t, f, "lead", "github-lead-private", true)

	names := loadProjectRepos(t, f, "root").appNames()
	if hasName(names, "github-lead-private") {
		t.Fatalf("the admin was offered an App they cannot spend: %v", names)
	}

	// Proven against the handler rather than assumed: the dropdown's omission
	// has to mean the same thing the POST does.
	code, body := f.postJSON(t, "root", "/api/projects/0/repositories", map[string]any{
		"secret": "github-lead-private",
		"repos":  []string{"acme/tool"},
		"access": "read",
	})
	if code == http.StatusOK {
		t.Fatalf("the admin spent another person's personal App: %s", body)
	}
}

// TestRepositoryInventoryRefusesAnotherUsersApp closes the last way in. The
// inventory route signs a JWT with the stored key and calls GitHub with it, so
// reaching it with somebody else's App is using their credential — which no
// permission in the ladder confers. It is scoped to a project index, so before
// this a maintainer of any one project could enumerate any App on the hub.
func TestRepositoryInventoryRefusesAnotherUsersApp(t *testing.T) {
	f := newPersonalFixture(t)
	connectApp(t, f, "lead", "github-lead-private", true)

	code, body := getFull(t, f.clients["root"],
		f.base+"/api/projects/0/repositories/available?secret=github-lead-private")
	if code == http.StatusOK {
		t.Fatalf("the admin enumerated another person's App: %s", body)
	}
	// Asserted on the reason, not merely on the failure. Before the fix this
	// route refused too — but only after signing an assertion with lead's key
	// and having api.github.com reject it, which is both a credential spent
	// without authority and a unit test reaching the network. The ownership
	// refusal fires before the envelope is even opened.
	//
	// ErrNotOwner rather than a not-found because root is an admin and may
	// legitimately see that lead keeps this App; seeing it and spending it are
	// what the model separates. A caller who could not see it at all gets the
	// not-found instead, which is what TestRepositoryPanelHidesAnotherUsersApp
	// covers from the other side.
	if !strings.Contains(body, "belongs to another user") {
		t.Errorf("the refusal did not come from the ownership check, so the key was "+
			"spent before anything objected: %s", body)
	}
	// And it arrives as a refusal rather than as a crash: an authorization
	// decision reported as a 500 tells the operator to file a bug instead of to
	// choose a credential they own.
	if code != http.StatusForbidden {
		t.Errorf("refusing another person's App answered %d, want 403: %s", code, body)
	}
}
