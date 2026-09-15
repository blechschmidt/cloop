package ui

// Tests for personal, user-scoped secrets over HTTP (Task 20275).
//
// pkg/secretbroker proves the ownership rule against the broker. These prove
// the two things only the hub can get wrong:
//
//  1. The route floor dropped to secret.own, so an operator now reaches six
//     endpoints that used to refuse them. Everything past that floor is
//     narrowed inside the handlers, and a handler that forgets would hand an
//     operator the inventory of the organisation's credentials.
//
//  2. Two different signed-in users get two different answers from the same
//     URL, which is the whole of what "scoped to themselves only" means to
//     somebody using the product.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// personalFixture is an OIDC-backed hub with a working secret broker and four
// distinct signed-in people, so that "alice cannot see bob's" is a statement
// about two identities rather than about two cookie jars.
type personalFixture struct {
	srv     *Server
	base    string
	clients map[string]*http.Client
}

func newPersonalFixture(t *testing.T) *personalFixture {
	t.Helper()

	t.Setenv(secretbroker.EnvPassphraseKey, "personal-secret-conformance-passphrase")

	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
			{Claim: authz.ClaimGroup, Value: "leads", Role: authz.RoleMaintainer},
			{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	// The hub's own project directory backs the broker the handlers open.
	seedMigratedDB(t, srv.WorkDir)
	if _, err := state.Init(srv.WorkDir, "personal secrets", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}

	loginAs := func(sub, email string, groups []string) *http.Client {
		idp.sub, idp.email, idp.groups = sub, email, groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}

	return &personalFixture{
		srv:  srv,
		base: ts.URL,
		clients: map[string]*http.Client{
			// Two operators: the pair the isolation claim is about.
			"alice": loginAs("sub-alice", "alice@corp.example", []string{"engineers"}),
			"bob":   loginAs("sub-bob", "bob@corp.example", []string{"engineers"}),
			// A maintainer, who owns the organisation's shared secrets.
			"lead": loginAs("sub-lead", "lead@corp.example", []string{"leads"}),
			// An admin, who may see everything and destroy anything but may
			// still not spend somebody else's credential.
			"root": loginAs("sub-root", "root@corp.example", []string{"owners"}),
		},
	}
}

// seedShared mints an organisation-owned secret directly through the broker,
// bypassing HTTP, so the listing assertions have something they must not show.
func (f *personalFixture) seedShared(t *testing.T, name, payload string) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(f.srv.WorkDir))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	broker, err := secretbroker.New(store)
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	if _, err := broker.Mint(t.Context(), secretbroker.MintRequest{
		Name: name, Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(payload), Actor: "ops",
	}); err != nil {
		t.Fatalf("seed shared secret: %v", err)
	}
}

func (f *personalFixture) postJSON(t *testing.T, who, path string, body any) (int, string) {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, f.base+path, strings.NewReader(string(blob)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.clients[who].Do(req)
	if err != nil {
		t.Fatalf("%s POST %s: %v", who, path, err)
	}
	defer resp.Body.Close()
	out := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		out.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, out.String()
}

// secretNames returns the names GET /api/secrets shows this person.
func (f *personalFixture) secretNames(t *testing.T, who string) []string {
	t.Helper()
	code, body := getFull(t, f.clients[who], f.base+"/api/secrets")
	if code != http.StatusOK {
		t.Fatalf("%s GET /api/secrets = %d\nbody: %s", who, code, body)
	}
	var env struct {
		Secrets []struct {
			Name     string `json:"name"`
			Owner    string `json:"owner"`
			Personal bool   `json:"personal"`
			Mine     bool   `json:"mine"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, body)
	}
	names := make([]string, 0, len(env.Secrets))
	for _, s := range env.Secrets {
		names = append(names, s.Name)
	}
	return names
}

// hasName reports whether a listing contains a secret by name.
func hasName(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// TestOperatorCanCreateASecretScopedToThemselves is the feature, end to end:
// an operator — who before this could not reach POST /api/secrets at all —
// stores a credential, and it belongs to them.
func TestOperatorCanCreateASecretScopedToThemselves(t *testing.T) {
	f := newPersonalFixture(t)

	code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name":     "alice-pat",
		"kind":     "github_pat",
		"payload":  "ghp_aliceOWNPAT0123456789abcdefghijkl",
		"personal": true,
	})
	if code != http.StatusOK {
		t.Fatalf("alice creating her own secret = %d, want 200\nbody: %s", code, body)
	}
	var created struct {
		Owner    string `json:"owner"`
		Personal bool   `json:"personal"`
		Mine     bool   `json:"mine"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, body)
	}
	if !created.Personal || !created.Mine {
		t.Errorf("created secret: personal=%v mine=%v, want both true", created.Personal, created.Mine)
	}
	if created.Owner != "alice@corp.example" {
		t.Errorf("owner = %q, want alice@corp.example", created.Owner)
	}
}

// TestPersonalSecretsAreInvisibleToOtherUsersOverHTTP is the isolation claim
// stated the way a user would: the same URL, two people, two answers.
func TestPersonalSecretsAreInvisibleToOtherUsersOverHTTP(t *testing.T) {
	f := newPersonalFixture(t)

	for _, who := range []string{"alice", "bob"} {
		code, body := f.postJSON(t, who, "/api/secrets", map[string]any{
			"name":     who + "-pat",
			"kind":     "github_pat",
			"payload":  fmt.Sprintf("ghp_%sSECRET0123456789abcdefghij", who),
			"personal": true,
		})
		if code != http.StatusOK {
			t.Fatalf("%s creating a secret = %d\nbody: %s", who, code, body)
		}
	}

	alices := f.secretNames(t, "alice")
	if !hasName(alices, "alice-pat") {
		t.Errorf("alice cannot see her own secret: %v", alices)
	}
	if hasName(alices, "bob-pat") {
		t.Errorf("alice can see bob's secret: %v", alices)
	}

	bobs := f.secretNames(t, "bob")
	if !hasName(bobs, "bob-pat") {
		t.Errorf("bob cannot see his own secret: %v", bobs)
	}
	if hasName(bobs, "alice-pat") {
		t.Errorf("bob can see alice's secret: %v", bobs)
	}

	// A maintainer holds secret.grant, which is authority over the
	// organisation's credentials. It must not have quietly become authority
	// over every developer's private ones.
	lead := f.secretNames(t, "lead")
	if hasName(lead, "alice-pat") || hasName(lead, "bob-pat") {
		t.Errorf("a maintainer can see personal secrets: %v", lead)
	}

	// An admin can, because offboarding requires it.
	root := f.secretNames(t, "root")
	if !hasName(root, "alice-pat") || !hasName(root, "bob-pat") {
		t.Errorf("an admin cannot see personal secrets, so offboarding would be impossible: %v", root)
	}
}

// TestOperatorAdmittedBySecretOwnStillCannotSeeSharedSecrets is the narrowing
// the lowered route floor makes necessary.
//
// This is the regression the floor invites: GET /api/secrets used to be
// maintainer-only precisely because the inventory of which credentials exist
// is reconnaissance, and admitting operators to the route must not admit them
// to that inventory.
func TestOperatorAdmittedBySecretOwnStillCannotSeeSharedSecrets(t *testing.T) {
	f := newPersonalFixture(t)
	f.seedShared(t, "fleet-deploy-key", "ghp_FLEETSHARED0123456789abcdefgh")

	if got := f.secretNames(t, "alice"); hasName(got, "fleet-deploy-key") {
		t.Errorf("an operator can enumerate the organisation's shared secrets: %v", got)
	}
	// The maintainer can, so the assertion above is about the narrowing rather
	// than about an empty store.
	if got := f.secretNames(t, "lead"); !hasName(got, "fleet-deploy-key") {
		t.Errorf("a maintainer cannot see the shared secret: %v", got)
	}
}

// TestOperatorCannotMintASharedSecret: creating an organisation-wide
// credential is still a maintainer's act.
//
// Without this, the lowered floor would let any operator write into the shared
// namespace every maintainer reads and grants from.
func TestOperatorCannotMintASharedSecret(t *testing.T) {
	f := newPersonalFixture(t)

	code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name":     "sneaky-shared",
		"kind":     "github_pat",
		"payload":  "ghp_SNEAKYSHARED0123456789abcdefg",
		"personal": false,
	})
	if code != http.StatusForbidden {
		t.Fatalf("operator minting a shared secret = %d, want 403\nbody: %s", code, body)
	}
	if !strings.Contains(body, string(authz.PermSecretGrant)) {
		t.Errorf("the refusal does not name the permission required\nbody: %s", body)
	}
	// And it really was not created.
	if got := f.secretNames(t, "root"); hasName(got, "sneaky-shared") {
		t.Errorf("the refused mint created the secret anyway: %v", got)
	}
}

// TestPersonalSecretCannotBeDeletedByAnotherUserOverHTTP closes the delete
// path, which reaches a different broker call than the listing does.
func TestPersonalSecretCannotBeDeletedByAnotherUserOverHTTP(t *testing.T) {
	f := newPersonalFixture(t)

	code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name": "alice-pat", "kind": "github_pat",
		"payload": "ghp_aliceDELETE0123456789abcdefghij", "personal": true,
	})
	if code != http.StatusOK {
		t.Fatalf("alice creating a secret = %d\nbody: %s", code, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Bob may not delete it, and must not learn from the status code that it
	// exists: 404, not 403.
	code, body = requestNoBody(t, f.clients["bob"], http.MethodDelete, f.base+"/api/secrets/"+created.ID)
	if code == http.StatusOK {
		t.Fatalf("bob deleted alice's secret\nbody: %s", body)
	}
	if code != http.StatusNotFound {
		t.Errorf("bob deleting alice's secret = %d, want 404 (not 403, which would confirm it exists)\nbody: %s", code, body)
	}
	if got := f.secretNames(t, "alice"); !hasName(got, "alice-pat") {
		t.Fatalf("alice's secret is gone after bob's attempt: %v", got)
	}

	// Alice can.
	if code, body = requestNoBody(t, f.clients["alice"], http.MethodDelete, f.base+"/api/secrets/"+created.ID); code != http.StatusOK {
		t.Fatalf("alice deleting her own secret = %d\nbody: %s", code, body)
	}
}

// TestSecretCatalogHidesOtherUsersPersonalSecrets covers the one secrets
// endpoint an ordinary operator could always read.
//
// The catalogue is how a requester learns which names exist to ask for. A
// colleague's personal credential is not something anyone can grant — there is
// no approver for it — so listing it there would leak the name for nothing.
func TestSecretCatalogHidesOtherUsersPersonalSecrets(t *testing.T) {
	f := newPersonalFixture(t)
	f.seedShared(t, "fleet-deploy-key", "ghp_FLEETSHARED0123456789abcdefgh")

	if code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name": "alice-pat", "kind": "github_pat",
		"payload": "ghp_aliceCATALOG0123456789abcdefgh", "personal": true,
	}); code != http.StatusOK {
		t.Fatalf("alice creating a secret = %d\nbody: %s", code, body)
	}

	catalog := func(who string) []string {
		code, body := getFull(t, f.clients[who], f.base+"/api/secrets/catalog")
		if code != http.StatusOK {
			t.Fatalf("%s GET catalog = %d\nbody: %s", who, code, body)
		}
		var env struct {
			Secrets []struct {
				Name string `json:"name"`
			} `json:"secrets"`
		}
		if err := json.Unmarshal([]byte(body), &env); err != nil {
			t.Fatalf("decode catalog: %v\nbody: %s", err, body)
		}
		out := make([]string, 0, len(env.Secrets))
		for _, s := range env.Secrets {
			out = append(out, s.Name)
		}
		return out
	}

	if got := catalog("bob"); hasName(got, "alice-pat") {
		t.Errorf("bob's request catalogue names alice's personal secret: %v", got)
	}
	// An admin sees every personal secret in the Secrets panel, but the
	// catalogue is "what may I ask for" — and nobody may ask for somebody
	// else's private credential.
	if got := catalog("root"); hasName(got, "alice-pat") {
		t.Errorf("an admin's request catalogue names alice's personal secret: %v", got)
	}
	// The shared secret is what the catalogue is for, and must still be there.
	if got := catalog("bob"); !hasName(got, "fleet-deploy-key") {
		t.Errorf("the catalogue lost the shared secret: %v", got)
	}
}

// TestSecretsRoutesNarrowOperatorsToTheirOwn is the structural companion to
// the behavioural tests above: it pins the route table itself.
//
// The route floor and the in-handler narrowing are two halves of one rule, and
// the dangerous edit is lowering a floor without adding the narrowing. This
// asserts which routes were deliberately lowered, so adding a seventh is a
// visible change here rather than a silent one in routes.go.
func TestSecretsRoutesNarrowOperatorsToTheirOwn(t *testing.T) {
	f := newPersonalFixture(t)

	lowered := map[string]bool{
		"GET /api/secrets":         true,
		"POST /api/secrets":        true,
		"DELETE /api/secrets/{id}": true,
		"GET /api/grants":          true,
		"POST /api/grants":         true,
		"DELETE /api/grants/{id}":  true,
	}
	// Leases stay above the floor. A lease is live fleet state — which
	// executor is holding which credential right now — and has no personal
	// dimension to scope it by.
	stillMaintainer := map[string]authz.Permission{
		"GET /api/leases":              authz.PermSecretGrant,
		"POST /api/leases/{id}/revoke": authz.PermSecretRevoke,
	}

	seen := map[string]bool{}
	for _, rs := range f.srv.routeTable() {
		if lowered[rs.Pattern] {
			seen[rs.Pattern] = true
			if rs.Perm != authz.PermSecretOwn {
				t.Errorf("%s declares %q, want %q", rs.Pattern, rs.Perm, authz.PermSecretOwn)
			}
		}
		if want, ok := stillMaintainer[rs.Pattern]; ok {
			seen[rs.Pattern] = true
			if rs.Perm != want {
				t.Errorf("%s declares %q, want %q — leases have no owner to scope by",
					rs.Pattern, rs.Perm, want)
			}
		}
	}
	for pattern := range lowered {
		if !seen[pattern] {
			t.Errorf("route %s is not registered", pattern)
		}
	}
	for pattern := range stillMaintainer {
		if !seen[pattern] {
			t.Errorf("route %s is not registered", pattern)
		}
	}

	// secret.own must sit at operator: the permission exists so that the role
	// which runs projects can bring its own credentials.
	if !roleHolds(authz.RoleOperator, authz.PermSecretOwn) {
		t.Error("operator does not hold secret.own, so the feature is unreachable by the role it is for")
	}
	if roleHolds(authz.RoleViewer, authz.PermSecretOwn) {
		t.Error("viewer holds secret.own; a role that cannot start a run has nothing to spend a credential on")
	}
}

func roleHolds(r authz.Role, p authz.Permission) bool {
	for _, have := range r.Permissions() {
		if have == p {
			return true
		}
	}
	return false
}
