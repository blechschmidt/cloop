package gitproxy_test

// Every forge host has its own route through the proxy (Task 20423), driven by
// the real git client against the real forge.
//
// The forge here stands for a GitHub Enterprise Server at its own host:port.
// A session for it is served beneath /_forge/<host>/ and nowhere else; a
// session for github.com — which the same forge stands in for, as the hub's
// test override makes it — is served at the base and never beneath another
// host's route. So an enterprise token is never presented in answer to a
// github.com URL, nor a github.com token to an enterprise one, whatever the
// sandbox asks for.

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// forgeHostOf is the canonical host:port of the harness's forge.
func (h *harness) forgeHostOf(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(h.forge.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// mintScopedFor mints a scoped session whose credential is for host, presented
// to the forge.
func (h *harness) mintScopedFor(t *testing.T, host string) *gitproxy.Minted {
	t.Helper()
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m, err := h.reg.Mint(gitproxy.MintRequest{
		Upstream:     h.forge.URL,
		ForgeHost:    host,
		RepoPatterns: []string{forgeOwner + "/*"},
		Credential:   gitproxy.Credential{Username: forgeUser, Password: forgePAT},
		Policy:       pol,
		ProjectID:    "proj-forge",
		Actor:        "dev@example.com",
	})
	if err != nil {
		t.Fatalf("minting a scoped session for %s: %v", host, err)
	}
	return m
}

func TestAnEnterpriseSessionIsServedOnItsOwnRouteOnly(t *testing.T) {
	h := newHarness(t)
	host := h.forgeHostOf(t)
	m := h.mintScopedFor(t, host)

	route := h.proxySrv.URL + "/" + gitproxy.ForgeRouteSegment + "/" + host
	if m.RepoURL != route {
		t.Fatalf("the session's route = %q, want %q", m.RepoURL, route)
	}
	if got, err := gitproxy.ForgeRoute(h.proxySrv.URL, strings.ToUpper(host)); err != nil || got != route {
		t.Fatalf("ForgeRoute = %q, %v; want %q", got, err, route)
	}

	// Its own route: served.
	dir := filepath.Join(t.TempDir(), "work")
	if out, err := h.git(t, "", h.credEnv(m), "clone", route+"/"+forgeOwner+"/"+forgeName, dir); err != nil {
		t.Fatalf("cloning on the enterprise route failed: %v\n%s", err, out)
	}

	// github.com's route — where the sandbox's github.com URLs land: refused
	// before anything is forwarded.
	before := len(h.eventsOf(gitproxy.EventFetch))
	out, err := h.git(t, "", h.credEnv(m), "clone", h.proxySrv.URL+"/"+forgeOwner+"/"+forgeName,
		filepath.Join(t.TempDir(), "w2"))
	if err == nil {
		t.Fatalf("an enterprise session was served on github.com's route:\n%s", out)
	}
	if !strings.Contains(out, "403") && !strings.Contains(out, host) {
		t.Fatalf("the refusal does not explain itself:\n%s", out)
	}
	if after := len(h.eventsOf(gitproxy.EventFetch)); after != before {
		t.Fatalf("a refused request was forwarded (%d fetches, was %d)", after, before)
	}
	rejected := h.eventsOf(gitproxy.EventRejected)
	if len(rejected) == 0 || !strings.Contains(rejected[len(rejected)-1].Detail, host) {
		t.Fatalf("the rejection row does not name the session's host:%s", h.eventLog())
	}

	// Another host's route: refused too.
	out, err = h.git(t, "", h.credEnv(m), "ls-remote",
		h.proxySrv.URL+"/"+gitproxy.ForgeRouteSegment+"/attacker.example/"+forgeOwner+"/"+forgeName)
	if err == nil {
		t.Fatalf("an enterprise session was served on another host's route:\n%s", out)
	}
}

func TestAGitHubSessionIsNeverServedOnAnEnterpriseRoute(t *testing.T) {
	h := newHarness(t)
	host := h.forgeHostOf(t)
	// The forge stands in for github.com here, as the hub's override makes it
	// in tests: the session's credential is a github.com one.
	m := h.mintScopedFor(t, "")
	if m.Session.ForgeHost != "github.com" || m.RepoURL != h.proxySrv.URL {
		t.Fatalf("a scoped session with no host named is for %q at %q", m.Session.ForgeHost, m.RepoURL)
	}
	if out, err := h.git(t, "", h.credEnv(m), "ls-remote", h.proxySrv.URL+"/"+forgeOwner+"/"+forgeName); err != nil {
		t.Fatalf("github.com's route refused its own session: %v\n%s", err, out)
	}
	out, err := h.git(t, "", h.credEnv(m), "ls-remote",
		h.proxySrv.URL+"/"+gitproxy.ForgeRouteSegment+"/"+host+"/"+forgeOwner+"/"+forgeName)
	if err == nil {
		t.Fatalf("a github.com session was served on %s's route:\n%s", host, out)
	}
}

// TestARouteMustNameItsHostCanonically: one session, one URL. A route that
// spells its host another way — or names github.com, whose route is the base —
// is not a route the proxy serves.
func TestARouteMustNameItsHostCanonically(t *testing.T) {
	h := newHarness(t)
	host := h.forgeHostOf(t)
	m := h.mintScopedFor(t, host)
	for _, spelled := range []string{strings.ToUpper(host), host + ".", "0" + host, "github.com", ""} {
		if spelled == host {
			continue // an address has no case to vary
		}
		u := h.proxySrv.URL + "/" + gitproxy.ForgeRouteSegment + "/" + spelled + "/" + forgeOwner + "/" + forgeName
		if out, err := h.git(t, "", h.credEnv(m), "ls-remote", u); err == nil {
			t.Errorf("%s was served:\n%s", u, out)
		}
	}
}

// TestAPinnedSessionKeepsItsOwnURL: a workspace's pinned session is served at
// the base and its repository, whatever host its credential is for — that URL
// pins host and repository both — and on no route of another host.
func TestAPinnedSessionKeepsItsOwnURL(t *testing.T) {
	h := newHarness(t)
	host := h.forgeHostOf(t)
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m, err := h.reg.Mint(gitproxy.MintRequest{
		Upstream: h.upstream, ForgeHost: host, Policy: pol,
		Credential: gitproxy.Credential{Username: forgeUser, Password: forgePAT},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, out, err := h.clone(t, m); err != nil {
		t.Fatalf("the pinned session's own URL was refused: %v\n%s", err, out)
	}
	if out, err := h.git(t, "", h.credEnv(m), "ls-remote",
		h.proxySrv.URL+"/"+gitproxy.ForgeRouteSegment+"/attacker.example/"+forgeOwner+"/"+forgeName); err == nil {
		t.Fatalf("a pinned session was served on another host's route:\n%s", out)
	}
}

// TestNoSessionIsMintedOrRestoredOffItsHost: the credential is presented to
// the session's forge host and to no other, so a pinned upstream — or an
// enterprise session's — elsewhere is refused at mint and at restore.
func TestNoSessionIsMintedOrRestoredOffItsHost(t *testing.T) {
	h := newHarness(t)
	host := h.forgeHostOf(t)
	cred := gitproxy.Credential{Username: forgeUser, Password: forgePAT}
	for _, req := range []gitproxy.MintRequest{
		{Upstream: h.upstream, ForgeHost: "github.com", Credential: cred},
		{Upstream: h.upstream, ForgeHost: "attacker.example", Credential: cred},
		{Upstream: "https://attacker.example", ForgeHost: host, RepoPatterns: []string{"acme/*"}, Credential: cred},
		{Upstream: h.upstream, ForgeHost: "not a host", Credential: cred},
	} {
		if _, err := h.reg.Mint(req); err == nil {
			t.Errorf("minted %s for %s", req.Upstream, req.ForgeHost)
		}
	}

	// A record from before hosts were recorded reads as what it was minted
	// for: a scoped one is github.com's, a pinned one its upstream's host.
	m := h.mintScopedFor(t, "")
	rec := gitproxy.SessionRecord{
		ID: "legacy-1", TokenSHA256: strings.Repeat("ab", 32), RepoPatterns: []string{"acme/*"},
		Upstream: h.forge.URL, Policy: m.Session.Policy, IssuedAt: h.now(), ExpiresAt: h.now().Add(10 * 60e9),
	}
	if err := h.reg.CheckRestore(rec); err != nil {
		t.Fatalf("a legacy scoped record was refused: %v", err)
	}
	rec.ForgeHost = "attacker.example"
	if err := h.reg.CheckRestore(rec); err == nil {
		t.Fatal("a scoped record for another host than its upstream's was restorable")
	}
	pinned := gitproxy.SessionRecord{
		ID: "legacy-2", TokenSHA256: strings.Repeat("cd", 32), Upstream: h.upstream,
		Policy: m.Session.Policy, IssuedAt: h.now(), ExpiresAt: h.now().Add(10 * 60e9),
	}
	if err := h.reg.CheckRestore(pinned); err != nil {
		t.Fatalf("a legacy pinned record was refused: %v", err)
	}
	pinned.ForgeHost = "github.com"
	if err := h.reg.CheckRestore(pinned); err == nil {
		t.Fatal("a pinned record whose credential is for github.com was restorable against another host")
	}
}
