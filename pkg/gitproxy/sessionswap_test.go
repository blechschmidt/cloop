package gitproxy_test

// Two runs of different projects hold sessions on one git proxy at once (Task
// 20502), each pinned to its own project's repository with its own forge
// credential. A request is served as the run whose whole credential it
// presents and as no other: one session's id with the other's token is
// refused, both ways, and so is no credential at all — none of which reaches
// the forge. A whole credential reaches its own repository, with the
// credential the hub holds for its run, and is refused on the other run's.

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

type forgeHit struct{ path, user, pass string }

func TestASessionCredentialServesItsOwnRunAndNoOther(t *testing.T) {
	var mu sync.Mutex
	var hits []forgeHit
	forge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		mu.Lock()
		hits = append(hits, forgeHit{r.URL.Path, user, pass})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = w.Write([]byte("001e# service=git-upload-pack\n0000"))
	}))
	t.Cleanup(forge.Close)
	seen := func() []forgeHit {
		mu.Lock()
		defer mu.Unlock()
		return append([]forgeHit(nil), hits...)
	}

	reg, err := gitproxy.NewRegistry("https://git.hub.example")
	if err != nil {
		t.Fatal(err)
	}
	px, err := gitproxy.New(reg, gitproxy.Options{Transport: forge.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(px)
	t.Cleanup(proxy.Close)

	mint := func(project, repo, pat, run string) *gitproxy.Minted {
		t.Helper()
		m, err := reg.Mint(gitproxy.MintRequest{
			Upstream:   forge.URL + "/acme/" + repo + ".git",
			Credential: gitproxy.Credential{Username: "x-access-token", Password: pat},
			Policy:     gitproxy.Policy{AllowFetch: true},
			ProjectID:  project, RunID: run, ExecutorID: "exec-1", Actor: "test",
		})
		if err != nil {
			t.Fatalf("Mint %s: %v", run, err)
		}
		return m
	}
	alpha := mint("/srv/alpha", "alpha", "alpha-forge-pat", "run-alpha")
	bravo := mint("/srv/bravo", "bravo", "bravo-forge-pat", "run-bravo")

	advertise := func(repo string, user, pass string, set bool) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, proxy.URL+"/acme/"+repo+"/info/refs?service=git-upload-pack", nil)
		if err != nil {
			t.Fatal(err)
		}
		if set {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
		}
		resp, err := proxy.Client().Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			t.Logf("refused %s as %s: %s", repo, user, body)
		}
		return resp.StatusCode
	}
	a, b := alpha.Credential(), bravo.Credential()

	for name, c := range map[string]struct {
		repo, user, pass string
		set              bool
	}{
		"alpha's id with bravo's token":                    {"alpha", a.Username, b.Password, true},
		"bravo's id with alpha's token":                    {"bravo", b.Username, a.Password, true},
		"alpha's id, bravo's token, on bravo's repository": {"bravo", a.Username, b.Password, true},
		"no credential":                                    {"alpha", "", "", false},
		"alpha's id alone":                                 {"alpha", a.Username, "", true},
		"alpha's token as the id":                          {"alpha", a.Password, a.Password, true},
	} {
		if got := advertise(c.repo, c.user, c.pass, c.set); got != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, got)
		}
	}
	if got := seen(); len(got) != 0 {
		t.Fatalf("a refused credential reached the forge: %+v", got)
	}

	// Alpha's whole credential on bravo's repository: authenticated, and
	// refused, because its session is alpha's repository's alone.
	if got := advertise("bravo", a.Username, a.Password, true); got != http.StatusForbidden {
		t.Errorf("alpha's credential on bravo's repository: status %d, want 403", got)
	}
	if got := seen(); len(got) != 0 {
		t.Fatalf("alpha's credential reached bravo's repository at the forge: %+v", got)
	}

	// Each whole credential is its own run: its own repository, with the
	// forge credential the hub holds for that run.
	if got := advertise("alpha", a.Username, a.Password, true); got != http.StatusOK {
		t.Fatalf("alpha's own credential on alpha's repository: status %d", got)
	}
	if got := advertise("bravo", b.Username, b.Password, true); got != http.StatusOK {
		t.Fatalf("bravo's own credential on bravo's repository: status %d", got)
	}
	got := seen()
	if len(got) != 2 || got[0] != (forgeHit{"/acme/alpha.git/info/refs", "x-access-token", "alpha-forge-pat"}) ||
		got[1] != (forgeHit{"/acme/bravo.git/info/refs", "x-access-token", "bravo-forge-pat"}) {
		t.Errorf("the forge saw %+v, want alpha's repository with alpha's credential, then bravo's with bravo's", got)
	}

	// Closing one run's session leaves the other's working.
	reg.Close(alpha.Session.ID, "run ended")
	if got := advertise("alpha", a.Username, a.Password, true); got != http.StatusUnauthorized {
		t.Errorf("alpha's closed session: status %d, want 401", got)
	}
	if got := advertise("bravo", b.Username, b.Password, true); got != http.StatusOK {
		t.Errorf("bravo's session after alpha's closed: status %d", got)
	}
}
