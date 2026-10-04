// End-to-end: a GitHub App token re-minted under a live git proxy session
// (Task 20375).
//
// The topology is the production one with GitHub faked at both of its faces:
//
//	git ──session token──▶ gitproxy ──installation token──▶ forge
//	                          │                               ▲
//	                          └── refresh ──▶ broker ──mint──▶ fake GitHub API
//
// The broker is the real one, minting through secretbrokertest.GitHub, whose
// tokens expire an hour after a clock the test drives; the forge honours only
// a token that fake would honour now. So a fetch after the clock passes the
// first token's hour succeeds only if the session renewed it through the
// broker — a session that kept presenting the first token is refused by the
// forge, which the control session below proves.
package gitproxy_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// refreshWorld is a harness plus a broker leasing a github_app grant through
// a guard that mints its session on the harness's registry.
type refreshWorld struct {
	h      *harness
	gh     *secretbrokertest.GitHub
	store  *secretbrokertest.Store
	audit  *secretbrokertest.Recorder
	broker *secretbroker.Broker
	guard  *e2eGuard
	grant  secretbroker.Grant
	lease  *secretbroker.Lease
}

func newRefreshWorld(t *testing.T) *refreshWorld {
	t.Helper()
	h := newHarness(t)
	w := &refreshWorld{h: h, store: secretbrokertest.NewStore(), audit: &secretbrokertest.Recorder{}}
	w.gh = secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: forgeOwner + "/" + forgeName})
	w.gh.Clock = h.now
	h.forgeAuth.Store(func(_, pass, repo string) bool { return w.gh.CoversRepo(pass, repo) })

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := secretbroker.NewCipherWithKey(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	w.broker, err = secretbroker.New(w.store,
		secretbroker.WithCipher(cipher),
		secretbroker.WithClock(h.now),
		secretbroker.WithGitHubApp(w.gh),
		secretbroker.WithAuditor(w.audit))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	w.guard = &e2eGuard{h: h}
	w.broker.GitGuard = w.guard

	ctx := context.Background()
	sec, err := w.broker.Mint(ctx, secretbroker.MintRequest{
		Name: "app", Kind: secretbroker.KindGitHubApp, Payload: secretbrokertest.AppPayload(101, 202), Actor: "e2e",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	w.grant, err = w.broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: sec.ID,
		Subject:   secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/proj"},
		Constraints: secretbroker.Constraints{
			Repos: []string{forgeOwner + "/" + forgeName}, Permissions: []string{"contents:write"},
		},
		TTL: 24 * time.Hour, Actor: "e2e",
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	w.lease, err = w.broker.LeaseFor(ctx, secretbroker.Requester{ExecutorID: "exec-1", ProjectID: "/srv/proj"}, "e2e")
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	if w.guard.minted == nil {
		t.Fatal("the lease did not go through the guard, so no session presents the App token")
	}
	return w
}

// e2eGuard is what pkg/ui's gitGuard does, against the harness's registry: a
// scoped session over the grant's allowlist whose upstream credential renews
// itself through the broker.
type e2eGuard struct {
	h      *harness
	minted *gitproxy.Minted
	token  string
}

func (g *e2eGuard) GuardGitHub(_ context.Context, req secretbroker.GitGuardRequest) (secretbroker.GitGuardResult, error) {
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	var refresh gitproxy.RefreshFunc
	if req.Refresh != nil {
		refresh = func(ctx context.Context, held string) (gitproxy.Refreshed, error) {
			got, err := req.Refresh(ctx, held)
			if err != nil {
				if errors.Is(err, secretbroker.ErrRefreshRefused) {
					return gitproxy.Refreshed{}, fmt.Errorf("%w: %w", gitproxy.ErrCredentialRefused, err)
				}
				return gitproxy.Refreshed{}, err
			}
			return gitproxy.Refreshed{
				Credential: gitproxy.Credential{Username: secretbroker.GitHubUsername, Password: got.Token},
				ExpiresAt:  got.ExpiresAt,
				Retire:     got.Retire,
			}, nil
		}
	}
	m, err := g.h.reg.Mint(gitproxy.MintRequest{
		Upstream:            g.h.forge.URL,
		RepoPatterns:        req.Repos,
		Credential:          gitproxy.Credential{Username: secretbroker.GitHubUsername, Password: req.Token},
		CredentialExpiresAt: req.TokenExpiresAt,
		Refresh:             refresh,
		Policy:              pol,
		// Well past the token's hour, so what this test crosses is the token's
		// expiry and not the session's.
		TTL:       4 * time.Hour,
		ProjectID: req.ProjectID,
		Actor:     "e2e",
	})
	if err != nil {
		return secretbroker.GitGuardResult{}, err
	}
	g.minted, g.token = m, req.Token
	cred := m.Credential()
	return secretbroker.GitGuardResult{
		BaseURL: g.h.proxySrv.URL, Username: cred.Username, Password: cred.Password,
		ExpiresAt: m.Session.ExpiresAt, SessionID: m.Session.ID, PushRefs: pol.AllowedRefs,
	}, nil
}

// sessionEnv authenticates git to the proxy as m, the way a guarded lease's
// helper does.
func (w *refreshWorld) sessionEnv(m *gitproxy.Minted) []string {
	c := m.Credential()
	base := w.h.proxySrv.URL + "/"
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
	return []string{
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=http." + base + ".extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: " + auth,
		"GIT_CONFIG_KEY_1=credential.helper",
		"GIT_CONFIG_VALUE_1=",
	}
}

func (w *refreshWorld) repoURL() string { return w.h.proxySrv.URL + "/" + forgeOwner + "/" + forgeName }

// forgeAccepts asks the forge directly whether it honours token now.
func (w *refreshWorld) forgeAccepts(t *testing.T, token string) bool {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, w.h.upstream+"/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(secretbroker.GitHubUsername, token)
	resp, err := w.h.forge.Client().Do(req)
	if err != nil {
		t.Fatalf("asking the forge: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TestProxyFetchAndPushOutliveTheAppTokensHour is the guarantee: a run still
// fetching and pushing an hour after dispatch does so through a token the
// session renewed through the broker, at the scope of the first.
func TestProxyFetchAndPushOutliveTheAppTokensHour(t *testing.T) {
	w := newRefreshWorld(t)
	h := w.h
	m := w.guard.minted
	first := w.guard.token

	// The control: a session presenting the same first token with no way to
	// renew it. It is what every session was before Task 20375.
	control, err := h.reg.Mint(gitproxy.MintRequest{
		Upstream:     h.forge.URL,
		RepoPatterns: []string{forgeOwner + "/" + forgeName},
		Credential:   gitproxy.Credential{Username: secretbroker.GitHubUsername, Password: first},
		Policy:       func() gitproxy.Policy { p := gitproxy.WriteBackPolicy(); p.AllowFetch = true; return p }(),
		TTL:          4 * time.Hour,
	})
	if err != nil {
		t.Fatalf("minting the control session: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "work")
	if out, err := h.git(t, "", w.sessionEnv(m), "clone", w.repoURL(), dir); err != nil {
		t.Fatalf("clone through the proxy at dispatch: %v\n%s", err, out)
	}
	firstMints := len(w.gh.Scoped())

	// An hour and a minute later. The first token is dead at GitHub.
	h.advance(61 * time.Minute)
	if w.forgeAccepts(t, first) {
		t.Fatal("the forge still honours the first token after its hour; this test would prove nothing")
	}
	if out, err := h.git(t, dir, w.sessionEnv(control), "fetch", w.repoURL()); err == nil {
		t.Fatalf("a session that cannot renew its token fetched after the hour; the forge is not refusing "+
			"expired tokens\n%s", out)
	}

	// The real session: fetch, commit, push.
	if out, err := h.git(t, dir, w.sessionEnv(m), "fetch", "origin"); err != nil {
		t.Fatalf("fetch through the proxy after the token's hour: %v\n%s%s", err, out, h.eventLog())
	}
	sha := h.commit(t, dir, "late.txt", "pushed an hour after dispatch\n")
	if out, err := h.git(t, dir, w.sessionEnv(m), "push", "origin", "HEAD:refs/heads/cloop/late"); err != nil {
		t.Fatalf("push through the proxy after the token's hour: %v\n%s%s", err, out, h.eventLog())
	}
	if got, ok := h.upstreamSHA(t, "refs/heads/cloop/late"); !ok || got != sha {
		t.Fatalf("upstream refs/heads/cloop/late = %q (exists %t), want the pushed %s", got, ok, sha)
	}

	scoped := w.gh.Scoped()
	if len(scoped) != firstMints+1 {
		t.Fatalf("%d token(s) minted for the session after the hour, want exactly one renewal", len(scoped)-firstMints)
	}
	renewed := scoped[len(scoped)-1]
	if fmt.Sprint(renewed.RepositoryIDs) != fmt.Sprint(scoped[0].RepositoryIDs) ||
		fmt.Sprint(renewed.Permissions) != fmt.Sprint(scoped[0].Permissions) {
		t.Errorf("renewed token scope %v %v differs from the first %v %v",
			renewed.RepositoryIDs, renewed.Permissions, scoped[0].RepositoryIDs, scoped[0].Permissions)
	}
	if got := m.Session.CredentialExpiresAt(); !got.Equal(renewed.ExpiresAt) {
		t.Errorf("session presents a credential expiring %s, the renewal expires %s", got, renewed.ExpiresAt)
	}
	waitFor(t, "the superseded token to be destroyed at GitHub", func() bool {
		tok, _ := w.gh.Token(first)
		return tok.Revoked
	})

	var allowed int
	for _, ev := range w.audit.Events(secretbroker.ActionRenew) {
		if ev.Decision == secretbroker.DecisionAllow && strings.Contains(ev.Reason, m.Session.ID) {
			allowed++
		}
		if strings.Contains(ev.Reason, first) || strings.Contains(ev.Reason, renewed.Token) {
			t.Fatal("a secret.renew row carries a token")
		}
	}
	if allowed != 1 {
		t.Errorf("%d allowed secret.renew rows name the session, want one", allowed)
	}

	// Releasing the lease ends the renewed token too.
	w.broker.Release(w.lease.ID)
	if w.gh.Valid(renewed.Token) {
		t.Error("the renewed token outlived the lease")
	}
}

// TestRevokedGrantStopsTheProxyRefresh: a grant revoked since dispatch is never
// renewed. The session is closed, the token destroyed, the late fetch refused.
func TestRevokedGrantStopsTheProxyRefresh(t *testing.T) {
	w := newRefreshWorld(t)
	h := w.h
	m := w.guard.minted
	first := w.guard.token
	dir := filepath.Join(t.TempDir(), "work")
	if out, err := h.git(t, "", w.sessionEnv(m), "clone", w.repoURL(), dir); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	mints := len(w.gh.Scoped())

	// Revoked through the store, as the Secrets panel's broker — another
	// instance over the same database — revokes it.
	if err := w.store.RevokeGrant(w.grant.ID, h.now()); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	h.advance(55 * time.Minute)

	out, err := h.git(t, dir, w.sessionEnv(m), "fetch", "origin")
	if err == nil {
		t.Fatalf("a fetch after the grant was revoked succeeded\n%s", out)
	}
	if !m.Session.Closed() || !strings.Contains(m.Session.CloseReason(), "will not be renewed") {
		t.Fatalf("session closed=%t reason=%q; a refused renewal must close it", m.Session.Closed(), m.Session.CloseReason())
	}
	if n := len(w.gh.Scoped()); n != mints {
		t.Errorf("%d token(s) minted for a revoked grant", n-mints)
	}
	if w.gh.Valid(first) {
		t.Error("the revoked grant's token is still live at GitHub")
	}
	var denied int
	for _, ev := range w.audit.Events(secretbroker.ActionRenew) {
		if ev.Decision == secretbroker.DecisionDeny && strings.Contains(ev.Reason, "revoked") {
			denied++
		}
	}
	if denied == 0 {
		t.Error("no denied secret.renew row records the refusal")
	}
	closed := h.eventsOf(gitproxy.EventSessionClosed)
	if len(closed) == 0 || !strings.Contains(closed[len(closed)-1].Detail, "will not be renewed") {
		t.Errorf("no session_closed row names the refusal%s", h.eventLog())
	}
}

// waitFor polls cond.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
