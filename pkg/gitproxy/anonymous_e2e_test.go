package gitproxy_test

// A request that presents no credential is counted, not audited (Task 20346).
//
// A guarded GitHub lease hands git a credential *helper*, and git asks a
// helper only after the server has challenged: every clone, fetch and push
// starts with a bare request the proxy answers 401. Against a live hub that
// handshake was half of the proxy's audit rows, each a "rejected ...
// unauthenticated" that was nothing of the kind, and anything able to reach
// the port could append more of them.

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// helperEnv delivers the session the way a guarded lease does: through a
// credential helper, which git consults only once it has been challenged.
func helperEnv(m *gitproxy.Minted) []string {
	c := m.Credential()
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=credential.helper",
		fmt.Sprintf("GIT_CONFIG_VALUE_0=!f() { test \"$1\" = get && printf 'username=%%s\\npassword=%%s\\n' '%s' '%s'; }; f",
			c.Username, c.Password),
	}
}

// anonymousRequests reads the counter the proxy keeps instead of an event.
func anonymousRequests(t *testing.T) int {
	t.Helper()
	for _, line := range strings.Split(hubmetrics.Default.Gather(), "\n") {
		if v, ok := strings.CutPrefix(line, "cloop_gitproxy_anonymous_requests_total "); ok {
			n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				t.Fatalf("unparseable sample %q: %v", line, err)
			}
			return int(n)
		}
	}
	return 0
}

func TestGitsAuthenticationChallengeIsCountedNotAudited(t *testing.T) {
	h := newHarness(t)

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m := h.mintScoped(t, []string{forgeOwner + "/*"}, pol)
	before := anonymousRequests(t)

	dir := filepath.Join(t.TempDir(), "work")
	if out, err := h.git(t, "", helperEnv(m), "clone", h.repoURL(forgeOwner, forgeName), dir); err != nil {
		t.Fatalf("clone through a credential helper: %v\n%s", err, out)
	}
	h.commit(t, dir, "work.txt", "written inside the sandbox\n")
	if out, err := h.git(t, dir, helperEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-1"); err != nil {
		t.Fatalf("push through a credential helper: %v\n%s", err, out)
	}

	if rejected := h.eventsOf(gitproxy.EventRejected); len(rejected) != 0 {
		t.Errorf("a clone and a push that both succeeded recorded %d rejection(s)%s", len(rejected), h.eventLog())
	}
	if anonymousRequests(t) == before {
		t.Fatal("git made no credential-less request, so this test is not exercising the challenge")
	}
	if len(h.eventsOf(gitproxy.EventFetch)) == 0 || len(h.eventsOf(gitproxy.EventPushAllowed)) == 0 {
		t.Errorf("the real operations went unrecorded%s", h.eventLog())
	}

	// Nor is anything else that reaches the port without a credential.
	before = anonymousRequests(t)
	resp, err := h.proxySrv.Client().Get(h.proxySrv.URL + "/robots.txt")
	if err != nil {
		t.Fatalf("GET /robots.txt: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /robots.txt = %d, want 404", resp.StatusCode)
	}
	if anonymousRequests(t) != before+1 {
		t.Errorf("a credential-less request to a route the proxy does not serve was not counted")
	}
	if rejected := h.eventsOf(gitproxy.EventRejected); len(rejected) != 0 {
		t.Errorf("a credential-less request was audited%s", h.eventLog())
	}
}

// TestAFailedCredentialIsStillAudited is the other half: a token that does
// not authenticate is a session being misused or outliving its TTL, and that
// stays a row.
func TestAFailedCredentialIsStillAudited(t *testing.T) {
	h := newHarness(t)

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m := h.mintScoped(t, []string{forgeOwner + "/*"}, pol)
	before := anonymousRequests(t)

	req, err := http.NewRequest(http.MethodGet,
		h.repoURL(forgeOwner, forgeName)+"/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(m.Session.ID, "not-the-session-token")
	resp, err := h.proxySrv.Client().Do(req)
	if err != nil {
		t.Fatalf("request with a wrong token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong token got %d, want 401", resp.StatusCode)
	}

	rejected := h.eventsOf(gitproxy.EventRejected)
	if len(rejected) != 1 || !strings.Contains(rejected[0].Detail, "unauthenticated") {
		t.Fatalf("a wrong token must leave exactly one rejected row%s", h.eventLog())
	}
	if rejected[0].RepoPath != forgeOwner+"/"+forgeName {
		t.Errorf("the row names %q, want the repository requested", rejected[0].RepoPath)
	}
	if anonymousRequests(t) != before {
		t.Error("a request that presented a credential was counted as anonymous")
	}
}
