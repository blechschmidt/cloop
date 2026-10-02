package ui

// Silent renewal on a control plane two hub processes serve (Task 20359).
//
// Three things are cluster-specific, and each would break the feature without
// failing anything a single hub can show:
//
//   - The provider sends the frame back to the load balancer, which may pick
//     the member that did not begin the renewal. The pending record — nonce,
//     PKCE verifier, the session it is for — lives only in the beginner's
//     memory, so the callback has to be forwarded there.
//   - Writing the re-asserted claims takes the cluster-wide refresh lock, the
//     one every refresh-token redemption of the session takes, so two members
//     never race to write one session's authority.
//   - The other member has the session cached. It must drop that copy when the
//     claims change, or it keeps serving the stale ones for up to thirty
//     seconds — long enough for the dashboard to be refused what it just
//     renewed.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// clusterRenewClock is the members' shared clock: one control plane, one now.
type clusterRenewClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *clusterRenewClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *clusterRenewClock) advance(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

// withClusterOIDC gives a member single sign-on against idp, with the cluster
// hooks a real hub installs and the session store every member shares. The
// provider redirects to callbackBase, which plays the load balancer.
func withClusterOIDC(t *testing.T, m *clusterMember, idp *uiFakeIdP, callbackBase string, clk *clusterRenewClock) {
	t.Helper()
	store, err := m.srv.OpenSessionStore()
	if err != nil {
		t.Fatalf("OpenSessionStore: %v", err)
	}
	cfg := oidcauth.Config{
		Enabled:         true,
		Issuer:          idp.server.URL,
		ClientID:        "cloop-dashboard",
		RedirectURL:     callbackBase + "/auth/callback",
		RefreshInterval: -1,
		MaxClaimAge:     5 * time.Minute,
		Store:           store,
		Clock:           clk.now,
	}
	m.srv.ClusterOIDCConfig(&cfg)
	if cfg.StatePrefix != m.node.ID() || cfg.RefreshLock == nil || cfg.OnCacheInvalidate == nil {
		t.Fatalf("ClusterOIDCConfig did not install the cluster hooks: %+v", cfg)
	}
	auth, err := oidcauth.New(cfg)
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	m.srv.OIDC = auth
}

func TestClusterRenewalCompletesOnTheMemberThatBeganIt(t *testing.T) {
	_, a, b := clusterPair(t)
	idp := newUIFakeIdP(t)
	clk := &clusterRenewClock{}
	// The provider always answers through B: the load balancer's choice for
	// every callback in this test.
	withClusterOIDC(t, a, idp, b.ts.URL, clk)
	withClusterOIDC(t, b, idp, b.ts.URL, clk)

	// Sign in through A. The callback lands on B, which forwards it to A,
	// whose memory holds the login.
	c := jarClient(t)
	req, _ := http.NewRequest(http.MethodGet, a.ts.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in chain ended with %d at %s", resp.StatusCode, resp.Request.URL)
	}
	sessionHash := sessionHashFromJar(t, c, a.ts.URL)

	// Past the bound, and B has the session cached with its stale claims.
	clk.advance(10 * time.Minute)
	if age := claimAgeOn(t, c, b); age < 590 {
		t.Fatalf("precondition: B reports claim age %v, want ~600", age)
	}

	// Another member holds the session's refresh lock — a redemption of the
	// refresh token in flight there. The renewal must wait for it.
	if _, ok, err := b.node.Claim(ownerSessionRefresh, sessionHash, nil); err != nil || !ok {
		t.Fatalf("B claim refresh lock: ok=%v err=%v", ok, err)
	}
	type result struct {
		resp *http.Response
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := c.Get(a.ts.URL + "/auth/renew")
		if err != nil {
			done <- result{err: err}
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- result{resp: resp, body: string(body)}
	}()
	select {
	case r := <-done:
		t.Fatalf("the renewal completed while another member held the refresh lock: %v %s", r.err, r.body)
	case <-time.After(500 * time.Millisecond):
	}
	if age := claimAgeOn(t, c, a); age < 590 {
		t.Fatalf("claims were written while another member held the refresh lock (age %v)", age)
	}
	if _, err := b.node.Release(ownerSessionRefresh, sessionHash); err != nil {
		t.Fatalf("release: %v", err)
	}

	var r result
	select {
	case r = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the renewal never completed after the lock was released")
	}
	if r.err != nil {
		t.Fatalf("GET /auth/renew: %v", r.err)
	}
	if !strings.Contains(r.body, `outcome: "ok"`) {
		t.Fatalf("renewal across members failed:\n%s", r.body)
	}
	// The callback reached B and was answered by A.
	if got := r.resp.Request.URL.Host; got != strings.TrimPrefix(b.ts.URL, "http://") {
		t.Fatalf("the provider's answer landed on %s, want B — the test is not crossing members", got)
	}
	if got := r.resp.Header.Get(hubcluster.HeaderServedBy); got != a.node.ID() {
		t.Fatalf("the renewal callback was completed by %q, want A (%s), which holds its PKCE verifier",
			got, a.node.ID())
	}

	// B dropped its cached copy when A changed the session. Its cache holds an
	// entry for thirty seconds, and this waits five: only the invalidation A
	// published can move B's answer in time. Polled at a pace the hub's rate
	// limiter admits (20/s per address).
	deadline := time.Now().Add(5 * time.Second)
	for {
		age, ok := tryClaimAge(c, b)
		if ok && age < 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("B still reports claim age %v (ok=%v) after A renewed the session — "+
				"its cached copy was never invalidated", age, ok)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// tryClaimAge is claimAgeOn for a poll: a failed read is "not yet".
func tryClaimAge(c *http.Client, m *clusterMember) (float64, bool) {
	resp, err := c.Get(m.ts.URL + "/api/me")
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var me struct {
		Age *float64 `json:"claim_age_seconds"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&me) != nil || me.Age == nil {
		return 0, false
	}
	return *me.Age, true
}

// sessionHashFromJar reads the session cookie the jar holds for base and
// returns the id every hub process stores it under.
func sessionHashFromJar(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	u, _ := url.Parse(base)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == oidcauth.SessionCookieName {
			return oidcauth.HashSessionID(ck.Value)
		}
	}
	t.Fatal("the jar holds no session cookie")
	return ""
}

// claimAgeOn reads claim_age_seconds from member m's /api/me.
func claimAgeOn(t *testing.T, c *http.Client, m *clusterMember) float64 {
	t.Helper()
	f := &renewFixture{ts: m.ts, c: c}
	age, ok := f.me(t)["claim_age_seconds"].(float64)
	if !ok {
		t.Fatal("/api/me reports no claim age")
	}
	return age
}
