package security

// Guarantee 9: the Secrets & Grants API never returns credential material
// (Task 20171).
//
// Tasks 20159 and 20163 built the brokers; Task 20171 put a REST API and a
// dashboard panel in front of them. That is the moment the non-disclosure
// property stops being an internal invariant and becomes an externally
// reachable one: before, a leak needed someone to log a Material; now it
// needs one JSON field on one view struct.
//
// So this drives the real routes — through ui.Server.Handler(), the same
// middleware chain and route table production serves — against a store
// seeded with known plaintext of every grantable kind, and scans every
// response body for the canary in every encoding it could have taken. It
// covers the read paths, the write paths, and the error paths, because an
// error message that echoes what it was given is the classic way a value
// escapes a system that never intended to return it.
//
// The companion test is TestSecretsAPINeverDisclosesLeaseMaterial in
// pkg/ui/secrets_api_test.go, which does the same for GET /api/leases with a
// genuinely materialised lease. It lives inside the package because issuing
// one requires the internal spawn path.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// uiRouteCanaries are the plaintext payloads seeded into the store, one per
// grantable kind. Each is shaped like the real credential so that a filter
// keyed on shape cannot pass this test by accident, and each carries a
// distinct marker so a failure names which kind leaked.
var uiRouteCanaries = []struct {
	name        string
	kind        secretbroker.Kind
	payload     string
	canary      string
	constraints secretbroker.Constraints
}{
	{
		name:        "ui-pat",
		kind:        secretbroker.KindGitHubPAT,
		payload:     "ghp_UIROUTECANARYpat0123456789abcdefghij",
		canary:      "ghp_UIROUTECANARYpat0123456789abcdefghij",
		constraints: secretbroker.Constraints{Repos: []string{"acme/*"}, Permissions: []string{"contents:read"}},
	},
	{
		name: "ui-kubeconfig",
		kind: secretbroker.KindKubeconfig,
		payload: "apiVersion: v1\nkind: Config\n" +
			"clusters:\n- name: prod\n  cluster:\n    server: https://k8s.example.com\n" +
			"users:\n- name: ci\n  user:\n    token: UIROUTECANARYkubetoken0123456789\n" +
			"contexts:\n- name: prod\n  context:\n    cluster: prod\n    user: ci\n    namespace: team-a\n" +
			"current-context: prod\n",
		canary:      "UIROUTECANARYkubetoken0123456789",
		constraints: secretbroker.Constraints{Contexts: []string{"prod"}, Namespaces: []string{"team-a"}},
	},
	{
		name:        "ui-registry",
		kind:        secretbroker.KindRegistry,
		payload:     `{"auths":{"ghcr.io":{"auth":"UIROUTECANARYregistryauth0123456789"}}}`,
		canary:      "UIROUTECANARYregistryauth0123456789",
		constraints: secretbroker.Constraints{Registries: []string{"ghcr.io"}},
	},
	{
		name:        "ui-env",
		kind:        secretbroker.KindEnv,
		payload:     `{"NPM_TOKEN":"UIROUTECANARYnpmtoken0123456789abcdef"}`,
		canary:      "UIROUTECANARYnpmtoken0123456789abcdef",
		constraints: secretbroker.Constraints{EnvKeys: []string{"NPM_TOKEN"}},
	},
	{
		name:        "ui-egress-proxy",
		kind:        secretbroker.KindEgressProxy,
		payload:     "http://proxyuser:UIROUTECANARYproxypass0123456789@proxy.internal:3128",
		canary:      "UIROUTECANARYproxypass0123456789",
		constraints: secretbroker.Constraints{Hosts: []string{"api.github.com"}},
	},
}

// newSecretsAPIFixture builds a hub with a seeded broker store and returns a
// server exercising the real handler chain.
//
// Token auth is left off and no authz resolver is installed, so every request
// reaches the handler. That is the point: this test is about what the
// handlers *return*, and gating them would test the gate instead. RBAC
// enforcement on the same routes is asserted separately, in
// pkg/ui/secrets_api_test.go.
func newSecretsAPIFixture(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "ui-route-conformance-passphrase")

	dir := t.TempDir()
	if _, err := state.Init(dir, "secrets api conformance", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	seedSecretsStore(t, dir)

	srv := ui.New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, dir
}

// seedSecretsStore mints one secret per kind, grants each to an executor, and
// adds an egress grant — so every branch of the list handlers has real data
// to render and the scan below cannot pass by finding nothing.
func seedSecretsStore(t *testing.T, dir string) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	defer db.Close()

	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}

	ctx := context.Background()
	for _, c := range uiRouteCanaries {
		// Mint takes ownership of the slice and zeroes it, so the canary is
		// read from the table rather than from the payload afterwards.
		sec, err := broker.Mint(ctx, secretbroker.MintRequest{
			Name:    c.name,
			Kind:    c.kind,
			Payload: []byte(c.payload),
			Actor:   "conformance-suite",
		})
		if err != nil {
			t.Fatalf("Mint %s: %v", c.name, err)
		}
		if _, err := broker.Grant(ctx, secretbroker.GrantRequest{
			SecretRef:   sec.ID,
			Subject:     secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "edge-01"},
			Constraints: c.constraints,
			Scope:       "ci",
			TTL:         time.Hour,
			Actor:       "conformance-suite",
		}); err != nil {
			t.Fatalf("Grant %s: %v", c.name, err)
		}
	}

	estore, err := secretstore.NewEgressStore(db)
	if err != nil {
		t.Fatalf("NewEgressStore: %v", err)
	}
	ebroker, err := egressbroker.New(estore, egressbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("egressbroker.New: %v", err)
	}
	if _, err := ebroker.Grant(ctx, egressbroker.GrantRequest{
		Subject:      secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "edge-01"},
		Scope:        "deps",
		Hosts:        []string{"api.github.com", "*.npmjs.org"},
		Ports:        []int{443},
		MaxBytesUp:   1 << 20,
		MaxBytesDown: 1 << 26,
		TTL:          time.Hour,
		Actor:        "conformance-suite",
	}); err != nil {
		t.Fatalf("egress Grant: %v", err)
	}
}

// doJSON issues a request and returns the status and the raw body.
func doJSON(t *testing.T, ts *httptest.Server, method, path string, body any) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(blob)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	blob, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body of %s %s: %v", method, path, err)
	}
	return resp.StatusCode, string(blob)
}

// TestSecretsAPIRoutesNeverDiscloseMaterial is the guarantee proper.
func TestSecretsAPIRoutesNeverDiscloseMaterial(t *testing.T) {
	ts, _ := newSecretsAPIFixture(t)

	// Read the seeded inventory first: the ids it returns drive the
	// single-resource routes below, so the scan covers real rows rather than
	// 404s that would never have had a payload to leak in the first place.
	code, secretsBody := doJSON(t, ts, http.MethodGet, "/api/secrets", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/secrets = %d, want 200\nbody: %s", code, secretsBody)
	}
	var secretsResp struct {
		Secrets []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Kind        string `json:"kind"`
			Fingerprint string `json:"fingerprint"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(secretsBody), &secretsResp); err != nil {
		t.Fatalf("decode /api/secrets: %v\nbody: %s", err, secretsBody)
	}
	// A vacuous pass is the failure mode this whole file exists to avoid: if
	// the seed silently did nothing, every scan below would trivially find no
	// canary and report success.
	if len(secretsResp.Secrets) != len(uiRouteCanaries) {
		t.Fatalf("seeded %d secrets but GET /api/secrets returned %d — the scan below would be vacuous",
			len(uiRouteCanaries), len(secretsResp.Secrets))
	}

	code, grantsBody := doJSON(t, ts, http.MethodGet, "/api/grants", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/grants = %d, want 200\nbody: %s", code, grantsBody)
	}
	var grantsResp struct {
		Grants []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
			Kind   string `json:"kind"`
		} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(grantsBody), &grantsResp); err != nil {
		t.Fatalf("decode /api/grants: %v\nbody: %s", err, grantsBody)
	}
	// One grant per secret plus the egress grant.
	if want := len(uiRouteCanaries) + 1; len(grantsResp.Grants) != want {
		t.Fatalf("seeded %d grants but GET /api/grants returned %d — the scan below would be vacuous",
			want, len(grantsResp.Grants))
	}

	// Every response body every new route can produce, including the error
	// and mutation paths.
	bodies := map[string]string{
		"GET /api/secrets":         secretsBody,
		"GET /api/grants":          grantsBody,
		"GET /api/grants?active=1": mustBody(t, ts, http.MethodGet, "/api/grants?active=1", nil),
		"GET /api/leases":          mustBody(t, ts, http.MethodGet, "/api/leases", nil),
	}

	// Creation echoes its input back as a view; a handler that returned the
	// payload it had just sealed would be caught here and nowhere else.
	_, createBody := doJSON(t, ts, http.MethodPost, "/api/secrets", map[string]any{
		"name":    "ui-echo-probe",
		"kind":    string(secretbroker.KindGitHubPAT),
		"payload": echoProbeCanary,
	})
	bodies["POST /api/secrets"] = createBody

	// The same payload again: a duplicate-name rejection is an error built
	// from the request, which is where an echo would surface.
	_, dupBody := doJSON(t, ts, http.MethodPost, "/api/secrets", map[string]any{
		"name":    "ui-echo-probe",
		"kind":    string(secretbroker.KindGitHubPAT),
		"payload": echoProbeCanary,
	})
	bodies["POST /api/secrets (duplicate)"] = dupBody

	// An invalid kind and an invalid name both reject *after* the payload has
	// been read, so both error paths are holding a credential when they build
	// their message.
	_, badKind := doJSON(t, ts, http.MethodPost, "/api/secrets", map[string]any{
		"name": "ui-bad-kind", "kind": "not-a-kind", "payload": echoProbeCanary,
	})
	bodies["POST /api/secrets (bad kind)"] = badKind
	_, badName := doJSON(t, ts, http.MethodPost, "/api/secrets", map[string]any{
		"name": "not a valid name!", "kind": string(secretbroker.KindGitHubPAT), "payload": echoProbeCanary,
	})
	bodies["POST /api/secrets (bad name)"] = badName

	// Grant creation and its rejection path: a github grant with no repo
	// allowlist is refused by Constraints.ValidateFor, and the refusal
	// mentions the grant it was building.
	for _, g := range grantsResp.Grants {
		if g.Source != "secret" {
			continue
		}
		_, revoked := doJSON(t, ts, http.MethodDelete, "/api/grants/"+g.ID, nil)
		bodies["DELETE /api/grants/"+g.ID] = revoked
		break
	}
	for _, g := range grantsResp.Grants {
		if g.Source != "egress" {
			continue
		}
		_, revoked := doJSON(t, ts, http.MethodDelete, "/api/grants/"+g.ID, nil)
		bodies["DELETE /api/grants/"+g.ID+" (egress)"] = revoked
		break
	}

	for _, s := range secretsResp.Secrets {
		_, created := doJSON(t, ts, http.MethodPost, "/api/grants", map[string]any{
			"source": "secret", "secret_ref": s.ID, "subject": "executor:edge-02",
			"repos": []string{"acme/widgets"}, "contexts": []string{"prod"},
			"namespaces": []string{"team-a"}, "hosts": []string{"api.github.com"},
			"registries": []string{"ghcr.io"}, "env_keys": []string{"NPM_TOKEN"},
			"ttl_minutes": 60,
		})
		bodies["POST /api/grants ("+s.Kind+")"] = created
		// The under-constrained variant, which the broker rejects.
		_, rejected := doJSON(t, ts, http.MethodPost, "/api/grants", map[string]any{
			"source": "secret", "secret_ref": s.ID, "subject": "executor:edge-02", "ttl_minutes": 60,
		})
		bodies["POST /api/grants (unconstrained, "+s.Kind+")"] = rejected
	}

	// Deleting a secret revokes its grants; the response names the secret.
	if len(secretsResp.Secrets) > 0 {
		id := secretsResp.Secrets[0].ID
		_, deleted := doJSON(t, ts, http.MethodDelete, "/api/secrets/"+id, nil)
		bodies["DELETE /api/secrets/"+id] = deleted
	}
	// A lease revoke for an id that is not open: the 404 is built from the id.
	_, noLease := doJSON(t, ts, http.MethodPost, "/api/leases/lease_does_not_exist/revoke", nil)
	bodies["POST /api/leases/{id}/revoke (absent)"] = noLease

	// Re-read after the mutations: revoked rows stay in the listings, and a
	// revoked row is still a row that must not carry material.
	bodies["GET /api/secrets (after mutations)"] = mustBody(t, ts, http.MethodGet, "/api/secrets", nil)
	bodies["GET /api/grants (after mutations)"] = mustBody(t, ts, http.MethodGet, "/api/grants", nil)

	// Every seeded canary against every body.
	canaries := map[string]string{"echo-probe": echoProbeCanary}
	for _, c := range uiRouteCanaries {
		canaries[c.name] = c.canary
	}
	for sink, body := range bodies {
		for name, canary := range canaries {
			assertNoSecretLeak(t, body, canary, fmt.Sprintf("%s (canary %s)", sink, name))
		}
	}

	// The fingerprint is the one derived value these responses do carry, so
	// assert it is derived from the sealed record rather than from the
	// plaintext: a digest of the value would be an offline guessing oracle
	// for the low-entropy payloads the store also holds.
	for _, s := range secretsResp.Secrets {
		if !strings.HasPrefix(s.Fingerprint, "sha256:") {
			t.Errorf("secret %s fingerprint %q is not algorithm-prefixed", s.Name, s.Fingerprint)
		}
		for _, c := range uiRouteCanaries {
			if c.name != s.Name {
				continue
			}
			assertNoSecretLeak(t, s.Fingerprint, c.canary, "the fingerprint for "+s.Name)
			if strings.Contains(s.Fingerprint, plaintextDigest(c.payload)) {
				t.Errorf("secret %s fingerprint is a digest of the plaintext — "+
					"that is an offline guessing oracle for anyone who can read this endpoint", s.Name)
			}
		}
	}
}

// echoProbeCanary is the payload used for the write and error paths.
const echoProbeCanary = "ghp_UIROUTEECHOPROBE0123456789abcdefghijkl"

// mustBody issues a request and fails the test if it does not return 200.
func mustBody(t *testing.T, ts *httptest.Server, method, path string, body any) string {
	t.Helper()
	code, blob := doJSON(t, ts, method, path, body)
	if code != http.StatusOK {
		t.Fatalf("%s %s = %d, want 200\nbody: %s", method, path, code, blob)
	}
	return blob
}

// plaintextDigest is what the fingerprint would be if it hashed the value.
// The assertion above is that the real fingerprint is *not* this.
func plaintextDigest(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])[:16]
}

// TestSecretsAPIViewStructsCarryNoMaterialField is the structural half of the
// guarantee.
//
// The scan above proves that today's payloads do not appear in today's
// responses. This proves the stronger, future-proof property: the JSON keys
// these endpoints emit are a closed, reviewed set, so a field added to
// secretbroker.Secret or Material cannot start being serialised by accident.
// A new key here is not necessarily a leak — but it is necessarily a decision
// somebody should have to make deliberately.
func TestSecretsAPIViewStructsCarryNoMaterialField(t *testing.T) {
	ts, _ := newSecretsAPIFixture(t)

	allowed := map[string]map[string]bool{
		"/api/secrets": {
			"id": true, "name": true, "kind": true, "fingerprint": true,
			"metadata": true, "created_at": true, "created_by": true,
			"grants": true, "active_grants": true,
		},
		"/api/grants": {
			"id": true, "source": true, "kind": true, "secret_id": true,
			"secret_name": true, "scope": true, "subject": true, "summary": true,
			"constraints": true, "expires_at": true, "created_at": true,
			"created_by": true, "revoked_at": true, "status": true,
			"active": true, "remaining_seconds": true,
		},
	}
	lists := map[string]string{"/api/secrets": "secrets", "/api/grants": "grants"}

	for path, key := range lists {
		code, body := doJSON(t, ts, http.MethodGet, path, nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200\nbody: %s", path, code, body)
		}
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &envelope); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		var rows []map[string]json.RawMessage
		if err := json.Unmarshal(envelope[key], &rows); err != nil {
			t.Fatalf("decode %s.%s: %v", path, key, err)
		}
		if len(rows) == 0 {
			t.Fatalf("%s returned no rows — the key check would be vacuous", path)
		}
		for _, row := range rows {
			for field := range row {
				if !allowed[path][field] {
					t.Errorf("%s row carries unreviewed field %q.\n"+
						"Every key these endpoints emit is enumerated in this test on purpose: "+
						"if the new field is metadata, add it to the allowlist; if it could hold "+
						"credential material, it must not be serialised at all.", path, field)
				}
			}
		}
	}
}
