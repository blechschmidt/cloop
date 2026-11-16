package kubeguard

// Two runs of different projects hold sessions on one monitor at once (Task
// 20502), each against its own cluster credential. A request is served as the
// run whose whole credential it presents and as no other: the id of one run's
// session with the secret of the other's is refused, both ways, and so is no
// credential at all — and none of those reaches either cluster. A session's
// token reaches its own cluster and never the other run's.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestASessionCredentialServesItsOwnRunAndNoOther(t *testing.T) {
	alphaAPI, bravoAPI := newFakeAPIServer(t), newFakeAPIServer(t)
	reg, err := NewRegistry("https://monitor.example:8444")
	if err != nil {
		t.Fatal(err)
	}
	px, err := New(reg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(px)
	t.Cleanup(func() {
		srv.Close()
		_ = px.Close()
	})
	mint := func(api *fakeAPIServer, project, run string) *Minted {
		t.Helper()
		m, err := reg.Mint(MintRequest{Kubeconfig: testInsecureKubeconfig(api.srv.URL), Policy: ReadOnlyPolicy(),
			ProjectID: project, ExecutorID: "exec-1", RunID: run, GrantID: "grant-" + run, LeaseID: "lease-" + run})
		if err != nil {
			t.Fatalf("Mint %s: %v", run, err)
		}
		return m
	}
	alpha := mint(alphaAPI, "/srv/alpha", "run-alpha")
	bravo := mint(bravoAPI, "/srv/bravo", "run-bravo")

	get := func(authorization string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/namespaces/app/pods", nil)
		if err != nil {
			t.Fatal(err)
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	halves := func(m *Minted) (id, secret string) {
		id, secret, ok := strings.Cut(m.Token, ".")
		if !ok || id != m.Session.ID {
			t.Fatalf("token %q is not <session id>.<secret>", m.Token)
		}
		return id, secret
	}
	alphaID, alphaSecret := halves(alpha)
	bravoID, bravoSecret := halves(bravo)

	for name, header := range map[string]string{
		"alpha's id with bravo's secret": "Bearer " + alphaID + "." + bravoSecret,
		"bravo's id with alpha's secret": "Bearer " + bravoID + "." + alphaSecret,
		"no credential":                  "",
		"alpha's id alone":               "Bearer " + alphaID,
		"alpha's secret alone":           "Bearer " + alphaSecret,
	} {
		if got := get(header); got != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, got)
		}
	}
	if alphaAPI.count() != 0 || bravoAPI.count() != 0 {
		t.Fatalf("a refused credential reached a cluster: alpha's saw %d requests, bravo's %d",
			alphaAPI.count(), bravoAPI.count())
	}

	// Each whole credential is its own run: it reaches its own cluster, with
	// the credential the hub holds for that run, and never the other's.
	if got := get("Bearer " + alpha.Token); got != http.StatusOK {
		t.Fatalf("alpha's own credential: status %d", got)
	}
	if alphaAPI.count() != 1 || bravoAPI.count() != 0 {
		t.Errorf("alpha's credential reached alpha's cluster %d times and bravo's %d", alphaAPI.count(), bravoAPI.count())
	}
	if got := alphaAPI.last().Header.Get("Authorization"); got != "Bearer "+testClusterToken {
		t.Errorf("alpha's cluster saw %q, want the cluster credential the hub holds", got)
	}
	if got := get("Bearer " + bravo.Token); got != http.StatusOK {
		t.Fatalf("bravo's own credential: status %d", got)
	}
	if alphaAPI.count() != 1 || bravoAPI.count() != 1 {
		t.Errorf("bravo's credential reached alpha's cluster (%d) or not bravo's (%d)", alphaAPI.count()-1, bravoAPI.count())
	}

	// Closing one run's session leaves the other's working, and the closed
	// one's credential refused.
	reg.Close(alpha.Session.ID, "run ended")
	if got := get("Bearer " + alpha.Token); got != http.StatusUnauthorized {
		t.Errorf("alpha's closed session: status %d, want 401", got)
	}
	if got := get("Bearer " + bravo.Token); got != http.StatusOK {
		t.Errorf("bravo's session after alpha's closed: status %d", got)
	}
}
