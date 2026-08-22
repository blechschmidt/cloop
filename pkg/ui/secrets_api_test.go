package ui

// Tests for the RBAC-gated Secrets & Grants endpoints (Task 20171).
//
// Two properties, both narrow:
//
//  1. Every route is refused below maintainer. The panel exposes the whole
//     credential surface of the hub — which secrets exist, which executor may
//     use them, and what each may reach — so a viewer or operator reading it
//     is reconnaissance even though they can change nothing.
//
//  2. GET /api/leases never returns lease material. tests/security proves this
//     for the secret and grant routes against real seeded plaintext; leases
//     need a genuinely materialised one, which only the internal spawn path
//     can issue, so that half lives here.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// secretsReadRoutes are the routes gated on secret.grant, which maintainer
// and admin hold.
var secretsReadRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/secrets"},
	{http.MethodGet, "/api/grants"},
	{http.MethodGet, "/api/leases"},
	{http.MethodPost, "/api/secrets"},
	{http.MethodPost, "/api/grants"},
}

// secretsRevokeRoutes are the routes gated on secret.revoke.
var secretsRevokeRoutes = []struct{ method, path string }{
	{http.MethodDelete, "/api/secrets/sec_nonexistent"},
	{http.MethodDelete, "/api/grants/grant_nonexistent"},
	{http.MethodPost, "/api/leases/lease_nonexistent/revoke"},
}

// requestNoBody issues a bodyless request and returns status plus body.
func requestNoBody(t *testing.T, c *http.Client, method, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, url, err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	blob := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		blob = append(blob, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, string(blob)
}

// TestSecretsRoutesDenyBelowMaintainer is the deny-by-default assertion.
//
// The interesting row is `operator`: an operator starts runs, and a run is
// what consumes brokered credentials, so it is tempting to let them see which
// ones exist. They must not — being able to spend a credential is not the
// same as being able to enumerate the fleet's credentials.
func TestSecretsRoutesDenyBelowMaintainer(t *testing.T) {
	_, base, clients := newAuditFixture(t)

	all := append(append([]struct{ method, path string }{}, secretsReadRoutes...), secretsRevokeRoutes...)
	for _, rt := range all {
		for _, role := range []string{"viewer", "operator", "unmapped"} {
			t.Run(role+" denied "+rt.method+" "+rt.path, func(t *testing.T) {
				code, body := requestNoBody(t, clients[role], rt.method, base+rt.path)
				if code != http.StatusForbidden {
					t.Fatalf("%s %s %s = %d, want 403\nbody: %s", role, rt.method, rt.path, code, body)
				}
				var env struct {
					Error struct {
						Code    string         `json:"code"`
						Details map[string]any `json:"details"`
					} `json:"error"`
				}
				if err := json.Unmarshal([]byte(body), &env); err != nil {
					t.Fatalf("403 body is not the structured error shape: %v\nbody: %s", err, body)
				}
				if env.Error.Code != "FORBIDDEN" {
					t.Errorf("error.code = %q, want FORBIDDEN", env.Error.Code)
				}
			})
		}
	}
}

// TestSecretsRoutesAllowMaintainerAndAdmin is the other half: the gate must
// not be so tight that the roles meant to broker credentials cannot.
//
// Only the read routes are exercised. Driving the writes would assert the
// handlers rather than the gate, and a 403 is distinguishable from every
// status they return anyway.
func TestSecretsRoutesAllowMaintainerAndAdmin(t *testing.T) {
	_, base, clients := newAuditFixture(t)

	for _, path := range []string{"/api/secrets", "/api/grants", "/api/leases"} {
		for _, role := range []string{"maintainer", "admin"} {
			t.Run(role+" allowed "+path, func(t *testing.T) {
				code, body := getFull(t, clients[role], base+path)
				if code == http.StatusForbidden {
					t.Fatalf("%s GET %s = 403, want the gate to pass\nbody: %s", role, path, body)
				}
			})
		}
	}
}

// TestSecretsRoutesDeclareTheRightPermissions walks the same table the server
// registers, so a route cannot be tested here and gated differently in
// production.
func TestSecretsRoutesDeclareTheRightPermissions(t *testing.T) {
	srv, _, _ := newAuditFixture(t)

	want := map[string]authz.Permission{
		"GET /api/secrets":             authz.PermSecretGrant,
		"POST /api/secrets":            authz.PermSecretGrant,
		"DELETE /api/secrets/{id}":     authz.PermSecretRevoke,
		"GET /api/grants":              authz.PermSecretGrant,
		"POST /api/grants":             authz.PermSecretGrant,
		"DELETE /api/grants/{id}":      authz.PermSecretRevoke,
		"GET /api/leases":              authz.PermSecretGrant,
		"POST /api/leases/{id}/revoke": authz.PermSecretRevoke,
	}
	seen := map[string]bool{}

	for _, rs := range srv.routeTable() {
		perm, tracked := want[rs.Pattern]
		if !tracked {
			continue
		}
		seen[rs.Pattern] = true
		if rs.Perm != perm {
			t.Errorf("%s declares %q, want %q", rs.Pattern, rs.Perm, perm)
		}
		if rs.Scope != scopeGlobal {
			t.Errorf("%s is not global-scoped; secrets and grants span projects", rs.Pattern)
		}
		if len(rs.MethodPerms) != 0 {
			// A per-method override on these patterns would be a way to open a
			// read path below maintainer without it showing up in the table.
			t.Errorf("%s overrides its permission per method", rs.Pattern)
		}
	}
	for pattern := range want {
		if !seen[pattern] {
			t.Errorf("route %s is not registered", pattern)
		}
	}
}

// TestSecretsAPINeverDisclosesLeaseMaterial is the lease half of the
// non-disclosure guarantee.
//
// It issues a real lease through acquireSecretLease — the same call the spawn
// path makes — so the response is rendered from genuine Materials holding
// genuine plaintext, then asserts the plaintext is nowhere in the body while
// the metadata that makes the table useful is.
func TestSecretsAPINeverDisclosesLeaseMaterial(t *testing.T) {
	const canary = "ghp_LEASEVIEWCANARY0123456789abcdefghijkl"

	t.Setenv(secretbroker.EnvPassphraseKey, "lease-view-conformance-passphrase")
	dir := t.TempDir()
	if _, err := state.Init(dir, "lease view conformance", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	sec, err := broker.Mint(t.Context(), secretbroker.MintRequest{
		Name: "lease-view-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(canary), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := broker.Grant(t.Context(), secretbroker.GrantRequest{
		SecretRef:   sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "edge-lease"},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
		TTL:         time.Hour, Actor: "test",
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	_ = db.Close()

	// The real lease. Registering it in liveLeases is what acquireSecretLease
	// does on the spawn path, so this exercises the same registry the handler
	// reads.
	lease := acquireSecretLease(dir, "/srv/leaseproj", "edge-lease")
	if lease == nil {
		t.Fatal("acquireSecretLease returned nil — the fixture did not produce a lease, so this test would be vacuous")
	}
	defer lease.Close()
	if lease.lease == nil || len(lease.lease.Materials) == 0 {
		t.Fatal("lease carries no materials — this test would be vacuous")
	}
	// The credential really is on disk: without this the assertion below could
	// pass because nothing was ever materialised.
	if lease.mount == nil || lease.mount.Dir == "" {
		t.Fatal("lease was not materialised")
	}
	assertLeaseDirHoldsCanary(t, lease.mount.Dir, canary)

	srv := New(dir, 0, "")
	rec := httptestGet(t, srv, "/api/leases")

	if !strings.Contains(rec, lease.lease.ID) {
		t.Fatalf("GET /api/leases does not mention the outstanding lease %s — vacuous scan\nbody: %s",
			lease.lease.ID, rec)
	}
	// The metadata the table is for must be present...
	for _, want := range []string{"edge-lease", "lease-view-pat", "github_pat", "/srv/leaseproj"} {
		if !strings.Contains(rec, want) {
			t.Errorf("GET /api/leases omits %q, which the lease table needs\nbody: %s", want, rec)
		}
	}
	// ...and the credential must not be.
	if strings.Contains(rec, canary) {
		t.Fatalf("GET /api/leases discloses the leased credential\nbody: %s", rec)
	}
}

// httptestGet drives one GET through the server's real handler chain and
// returns the body. It builds the chain rather than calling the handler
// directly so the route gate is in the path, matching how the endpoint is
// reached in production.
func httptestGet(t *testing.T, srv *Server, path string) string {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	blob, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200\nbody: %s", path, resp.StatusCode, string(blob))
	}
	return string(blob)
}

// assertLeaseDirHoldsCanary proves the credential really was written, so a
// later assertion that it is absent from the API response is meaningful.
func assertLeaseDirHoldsCanary(t *testing.T, dir, canary string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read lease dir: %v", err)
	}
	for _, e := range entries {
		blob, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		if strings.Contains(string(blob), canary) {
			return
		}
	}
	t.Fatalf("the lease directory %s does not contain the credential — "+
		"the non-disclosure assertion that follows would be vacuous", dir)
}
