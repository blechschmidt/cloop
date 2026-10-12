package secretbroker

// A GitHub grant is bound to its forge host (Task 20423): github.com for a
// PAT unless its secret recorded a GitHub Enterprise Server host, and the web
// host of an App's base_url. These tests hold the broker's half: the host is
// read from the sealed payload, recorded at mint and never taken from the
// caller, carried on every material and every guard request, and the only host
// the sandbox's helpers and rewrites will present a credential to.

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const ghesHost = "ghes.example.com"

func TestParseGitHubPATReadsTheHostFromThePayload(t *testing.T) {
	for _, tc := range []struct {
		payload, token, host string
	}{
		{"ghp_bare0123456789", "ghp_bare0123456789", "github.com"},
		{"  ghp_bare0123456789\n", "ghp_bare0123456789", "github.com"},
		{`{"token":"ghp_x","host":"GHES.Example.com."}`, "ghp_x", ghesHost},
		{`{"token":"ghp_x","host":"ghes.example.com:443"}`, "ghp_x", ghesHost},
		{`{"token":"ghp_x","host":"ghes.example.com:8443"}`, "ghp_x", "ghes.example.com:8443"},
		{`{"token":"ghp_x"}`, "ghp_x", "github.com"},
		{`{"token":"ghp_x","host":"github.com"}`, "ghp_x", "github.com"},
	} {
		token, host, err := parseGitHubPAT([]byte(tc.payload))
		if err != nil {
			t.Errorf("parseGitHubPAT(%q): %v", tc.payload, err)
			continue
		}
		if token != tc.token || host != tc.host {
			t.Errorf("parseGitHubPAT(%q) = %q, %q; want %q, %q", tc.payload, token, host, tc.token, tc.host)
		}
	}
}

// TestParseGitHubPATRefusesWhatItCannotBind: a document that does not parse
// would otherwise be delivered as a token that is not one — or, misspelt, bound
// to github.com when its author meant an enterprise server.
func TestParseGitHubPATRefusesWhatItCannotBind(t *testing.T) {
	const secretToken = "ghp_mustNotAppearInTheError"
	for _, payload := range []string{
		"",
		"   ",
		`{"token":"` + secretToken + `","hostname":"ghes.example.com"}`,
		`{"token":"` + secretToken + `","host":"gh es"}`,
		`{"token":"","host":"ghes.example.com"}`,
		`{"token":"` + secretToken + `"} {"token":"x"}`,
		`{"token":"` + secretToken + `",`,
		`{"token":"` + secretToken + `","host":"https://user@ghes/x?"}`,
	} {
		_, _, err := parseGitHubPAT([]byte(payload))
		if err == nil {
			t.Errorf("parseGitHubPAT(%q) was accepted", payload)
			continue
		}
		if !errors.Is(err, ErrMalformedPayload) {
			t.Errorf("parseGitHubPAT(%q) = %v, want ErrMalformedPayload", payload, err)
		}
		if strings.Contains(err.Error(), secretToken) {
			t.Errorf("the refusal quotes the token: %v", err)
		}
	}
}

func TestGitHubPATPayloadRoundTrips(t *testing.T) {
	doc, err := GitHubPATPayload(" ghp_x ", "GHES.example.com")
	if err != nil {
		t.Fatal(err)
	}
	token, host, err := parseGitHubPAT(doc)
	if err != nil || token != "ghp_x" || host != ghesHost {
		t.Fatalf("round trip = %q, %q, %v", token, host, err)
	}
	// github.com, or no host, is the bare token every PAT was before.
	for _, h := range []string{"", "github.com", "GitHub.com."} {
		doc, err := GitHubPATPayload("ghp_x", h)
		if err != nil || string(doc) != "ghp_x" {
			t.Errorf("GitHubPATPayload(%q) = %q, %v; want the bare token", h, doc, err)
		}
	}
	if _, err := GitHubPATPayload("", ghesHost); err == nil {
		t.Error("an empty token was rendered")
	}
	if _, err := GitHubPATPayload("ghp_x", "not a host"); err == nil {
		t.Error("an unusable host was rendered")
	}
}

// TestMintRecordsTheHostFromThePayloadNotTheCaller: the metadata is derived,
// and what a caller typed into it is replaced — on every kind.
func TestMintRecordsTheHostFromThePayloadNotTheCaller(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()
	lie := map[string]string{MetaForgeHost: "attacker.example", "ticket": "OPS-1"}

	doc, _ := GitHubPATPayload("ghp_enterprise", ghesHost)
	ghes, err := b.Mint(ctx, MintRequest{Name: "ghes-pat", Kind: KindGitHubPAT, Payload: doc, Metadata: lie, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got := ghes.Metadata[MetaForgeHost]; got != ghesHost {
		t.Errorf("GHES PAT recorded %q, want %q", got, ghesHost)
	}
	if ghes.Metadata["ticket"] != "OPS-1" {
		t.Error("the caller's other metadata was lost")
	}
	if lie[MetaForgeHost] != "attacker.example" {
		t.Error("Mint wrote into the caller's map")
	}

	bare, err := b.Mint(ctx, MintRequest{Name: "gh-pat", Kind: KindGitHubPAT, Payload: []byte("ghp_x"), Metadata: lie, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got := bare.Metadata[MetaForgeHost]; got != "github.com" {
		t.Errorf("bare PAT recorded %q, want github.com", got)
	}

	app, err := b.Mint(ctx, MintRequest{Name: "ghes-app", Kind: KindGitHubApp, Payload: ghesAppPayload(t), Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got := app.Metadata[MetaForgeHost]; got != ghesHost {
		t.Errorf("GHES App recorded %q, want %q", got, ghesHost)
	}

	env, err := b.Mint(ctx, MintRequest{Name: "env", Kind: KindEnv, Payload: []byte(`{"A":"b"}`), Metadata: lie, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := env.Metadata[MetaForgeHost]; ok {
		t.Errorf("an env secret kept a forge host: %v", env.Metadata)
	}

	// A PAT document that cannot be bound mints nothing.
	if _, err := b.Mint(ctx, MintRequest{Name: "broken", Kind: KindGitHubPAT,
		Payload: []byte(`{"token":"ghp_x","hostname":"ghes"}`), Actor: "t"}); err == nil {
		t.Error("a PAT document with a misspelt host was minted")
	}

	// Bookkeeping cannot move it either.
	updated, err := b.UpdateSecretMetadata(ghes.ID, func(m map[string]string) { m[MetaForgeHost] = "attacker.example" })
	if err != nil {
		t.Fatal(err)
	}
	if got := updated.Metadata[MetaForgeHost]; got != ghesHost {
		t.Errorf("UpdateSecretMetadata moved the forge host to %q", got)
	}
}

// TestSecretForgeHostReadsSecretsMintedBeforeHosts: nothing written earlier is
// widened. A legacy PAT is a bare github.com token; a legacy App's host is in
// its sealed base_url, so it is unknown here — never a match.
func TestSecretForgeHostReadsSecretsMintedBeforeHosts(t *testing.T) {
	if h, known := SecretForgeHost(Secret{Kind: KindGitHubPAT}); !known || h != "github.com" {
		t.Errorf("legacy PAT = %q, %v; want github.com", h, known)
	}
	if h, known := SecretForgeHost(Secret{Kind: KindGitHubApp}); known {
		t.Errorf("legacy App = %q, known; its host is in its sealed payload", h)
	}
	if h, known := SecretForgeHost(Secret{Kind: KindGitHubPAT, Metadata: map[string]string{MetaForgeHost: "GHES.example.com"}}); !known || h != ghesHost {
		t.Errorf("recorded PAT = %q, %v", h, known)
	}
	if _, known := SecretForgeHost(Secret{Kind: KindGitHubPAT, Metadata: map[string]string{MetaForgeHost: "not a host"}}); known {
		t.Error("an unusable recorded host was reported as known")
	}
	if _, known := SecretForgeHost(Secret{Kind: KindKubeconfig}); known {
		t.Error("a kubeconfig has a forge host")
	}
}

// ghesAppPayload is a github_app payload for an installation on a GitHub
// Enterprise Server.
func ghesAppPayload(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(appPayload{
		AppID: 12345, InstallationID: 67890, PrivateKey: appKeyPEM(t),
		BaseURL: "https://" + ghesHost + "/api/v3",
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestEveryGitHubMaterialCarriesItsHost: the lease reads the host from the
// sealed payload, and a guard is told it.
func TestEveryGitHubMaterialCarriesItsHost(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    Kind
		payload func(*testing.T) []byte
		host    string
	}{
		{"pat", KindGitHubPAT, func(*testing.T) []byte { return []byte("ghp_public") }, "github.com"},
		{"ghes pat", KindGitHubPAT, func(*testing.T) []byte { d, _ := GitHubPATPayload("ghp_e", ghesHost); return d }, ghesHost},
		{"app", KindGitHubApp, func(t *testing.T) []byte { return appPayloadJSON(t) }, "github.com"},
		{"ghes app", KindGitHubApp, ghesAppPayload, ghesHost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _, _, clk := newTestBroker(t)
			gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "acme/tool"})
			gh.clock = clk.Now
			b.appMinter = newGitHubAppMinter(gh, clk.Now)
			guard := workingGuard()
			if tc.host != "github.com" {
				guard.result.ForgeURL = guard.result.BaseURL + "/_forge/" + tc.host
			}
			b.GitGuard = guard
			s, err := b.Mint(context.Background(), MintRequest{Name: "s", Kind: tc.kind, Payload: tc.payload(t), Actor: "t"})
			if err != nil {
				t.Fatal(err)
			}
			grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"acme/*"}}, time.Hour)
			lease, err := b.Lease(context.Background(), "e1", "/srv/app")
			if err != nil {
				t.Fatal(err)
			}
			if len(lease.Materials) != 1 {
				t.Fatalf("materials = %d", len(lease.Materials))
			}
			m := lease.Materials[0]
			if m.GitHubHost() != tc.host {
				t.Errorf("material host = %q, want %q", m.GitHubHost(), tc.host)
			}
			if guard.seen.Host != tc.host {
				t.Errorf("the guard was asked for host %q, want %q", guard.seen.Host, tc.host)
			}
			if m.Env[GitHubHostEnvKey] != tc.host {
				t.Errorf("%s = %q, want %q", GitHubHostEnvKey, m.Env[GitHubHostEnvKey], tc.host)
			}
			if err := m.CheckForgeHost("https://attacker.example/acme/tool"); err == nil {
				t.Error("a material matched a host it is not for")
			}
			if err := m.CheckForgeHost("https://" + strings.ToUpper(tc.host) + "./acme/tool"); err != nil {
				t.Errorf("a material refused its own host spelled another way: %v", err)
			}
		})
	}
}

// unguardedLeaseFor materialises an unguarded lease of one github_pat payload.
func unguardedLeaseFor(t *testing.T, payload []byte, repos []string) *Mount {
	t.Helper()
	b, _, _, _ := newTestBroker(t)
	s, err := b.Mint(context.Background(), MintRequest{Name: "pat", Kind: KindGitHubPAT, Payload: payload, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: repos}, time.Hour)
	lease, err := b.Lease(t.Context(), "e1", "/srv/app")
	if err != nil {
		t.Fatal(err)
	}
	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mount.Close() })
	return mount
}

// TestAnUnguardedHelperAnswersOnlyForItsGrantsHost: the in-sandbox helper of a
// GitHub Enterprise Server token never releases it for github.com — nor a
// github.com token for the server — with the same owner/name on both.
func TestAnUnguardedHelperAnswersOnlyForItsGrantsHost(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	const ghesToken = "ghp_enterpriseTokenOnly0123456789"
	doc, _ := GitHubPATPayload(ghesToken, ghesHost)
	mount := unguardedLeaseFor(t, doc, []string{"acme/*"})

	if out := gitCredentialFill(t, mount, "https://"+ghesHost+"/acme/tool"); !strings.Contains(out, ghesToken) {
		t.Errorf("the server's own helper did not answer for it:\n%s", out)
	}
	for _, other := range []string{
		"https://github.com/acme/tool",
		"https://GHES.example.com.attacker.example/acme/tool",
		"https://ghes.example.com:8443/acme/tool",
		"https://attacker.example/acme/tool",
	} {
		if out := gitCredentialFill(t, mount, other); strings.Contains(out, ghesToken) {
			t.Errorf("the GitHub Enterprise Server token was released for %s:\n%s", other, out)
		}
	}
	// Case and a trailing dot are the same server, and git may spell it so.
	if out := gitCredentialFill(t, mount, "https://GHES.Example.com./acme/tool"); !strings.Contains(out, ghesToken) {
		t.Errorf("the helper did not fold its own host's case and trailing dot:\n%s", out)
	}

	const ghToken = "ghp_publicTokenOnly0123456789abcd"
	gh := unguardedLeaseFor(t, []byte(ghToken), []string{"acme/*"})
	if out := gitCredentialFill(t, gh, "https://"+ghesHost+"/acme/tool"); strings.Contains(out, ghToken) {
		t.Errorf("a github.com token was released for %s:\n%s", ghesHost, out)
	}
}

// TestAWildcardGHESGrantIsNotExportedAsAGitHubToken: GITHUB_TOKEN and GH_TOKEN
// go to github.com in every tool that reads them, and an enterprise token is
// never presented there.
func TestAWildcardGHESGrantIsNotExportedAsAGitHubToken(t *testing.T) {
	const ghesToken = "ghp_enterpriseWildcard0123456789ab"
	doc, _ := GitHubPATPayload(ghesToken, ghesHost)
	mount := unguardedLeaseFor(t, doc, []string{"*"})
	env := strings.Join(mount.Env(), "\n")
	if strings.Contains(env, "GITHUB_TOKEN=") || strings.Contains(env, "GH_TOKEN=") {
		t.Errorf("an enterprise token was exported for github.com tools:\n%s", env)
	}
	if !strings.Contains(env, "GH_ENTERPRISE_TOKEN="+ghesToken) {
		t.Errorf("the enterprise token was not exported for the enterprise host:\n%s", env)
	}
}

// routedGuard stands in for the hub's guard: a session per grant, served on
// the proxy route of the grant's own host.
type routedGuard struct {
	base     string
	requests []GitGuardRequest
}

func (g *routedGuard) GuardGitHub(_ context.Context, req GitGuardRequest) (GitGuardResult, error) {
	g.requests = append(g.requests, req)
	host := req.Host
	if host == "" {
		host = "github.com"
	}
	route := g.base
	if host != "github.com" {
		route = g.base + "/_forge/" + host
	}
	id := "sess-" + strings.ReplaceAll(host, ".", "-")
	return GitGuardResult{
		BaseURL: g.base, ForgeURL: route, Username: id, Password: "token-of-" + id,
		SessionID: id, ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

// TestGuardedGrantsForTwoHostsGetOneRewriteEach is the collision the guarded
// path had: a github.com grant and a GitHub Enterprise Server grant for the
// same owner/name in one lease. Each host is rewritten to its own proxy route,
// and each helper answers beneath its own route only — so a github.com URL can
// never reach the enterprise session, nor the reverse.
func TestGuardedGrantsForTwoHostsGetOneRewriteEach(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	const proxy = "https://hub.internal:8443"
	b, _, _, _ := newTestBroker(t)
	guard := &routedGuard{base: proxy}
	b.GitGuard = guard
	ctx := context.Background()
	gh, err := b.Mint(ctx, MintRequest{Name: "gh", Kind: KindGitHubPAT, Payload: []byte("ghp_public0123"), Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := GitHubPATPayload("ghp_enterprise0123", ghesHost)
	ghes, err := b.Mint(ctx, MintRequest{Name: "ghes", Kind: KindGitHubPAT, Payload: doc, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	grantTo(t, b, gh.ID, "project:/srv/app", Constraints{Repos: []string{"acme/tool"}}, time.Hour)
	grantTo(t, b, ghes.ID, "project:/srv/app", Constraints{Repos: []string{"acme/tool"}}, time.Hour)
	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatal(err)
	}
	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mount.Close() })

	hosts := map[string]bool{}
	for _, r := range guard.requests {
		hosts[r.Host] = true
	}
	if !hosts["github.com"] || !hosts[ghesHost] || len(guard.requests) != 2 {
		t.Fatalf("guard requests = %+v, want one per host", guard.requests)
	}

	for _, tc := range []struct{ in, want string }{
		{"https://github.com/acme/tool", proxy + "/acme/tool"},
		{"git@github.com:acme/tool.git", proxy + "/acme/tool.git"},
		{"https://" + ghesHost + "/acme/tool", proxy + "/_forge/" + ghesHost + "/acme/tool"},
		{"git@" + ghesHost + ":acme/tool.git", proxy + "/_forge/" + ghesHost + "/acme/tool.git"},
		{"https://attacker.example/acme/tool", "https://attacker.example/acme/tool"},
	} {
		if got := gitRewrittenURL(t, mount, tc.in); got != tc.want {
			t.Errorf("git rewrote %s to %s, want %s", tc.in, got, tc.want)
		}
	}

	ghSession, ghesSession := "token-of-sess-github-com", "token-of-sess-"+strings.ReplaceAll(ghesHost, ".", "-")
	onBase := gitCredentialFill(t, mount, proxy+"/acme/tool")
	if !strings.Contains(onBase, ghSession) || strings.Contains(onBase, ghesSession) {
		t.Errorf("github.com's route was answered with the wrong session:\n%s", onBase)
	}
	onRoute := gitCredentialFill(t, mount, proxy+"/_forge/"+ghesHost+"/acme/tool")
	if !strings.Contains(onRoute, ghesSession) || strings.Contains(onRoute, ghSession) {
		t.Errorf("the enterprise route was answered with the wrong session:\n%s", onRoute)
	}
	if out := gitCredentialFill(t, mount, proxy+"/_forge/attacker.example/acme/tool"); strings.Contains(out, "token-of-") {
		t.Errorf("a route no grant is for was answered:\n%s", out)
	}
}

// TestAGuardWithNoRouteForAnEnterpriseHostFailsTheLease: a guard that would put
// an enterprise session at github.com's route — where the sandbox's github.com
// rewrite lands — is a guard that cannot keep the two apart. The lease fails
// rather than deliver it.
func TestAGuardWithNoRouteForAnEnterpriseHostFailsTheLease(t *testing.T) {
	doc, _ := GitHubPATPayload("ghp_enterprise0123", ghesHost)
	mat := Material{
		SecretName: "ghes-pat", GrantID: "g1", Kind: KindGitHubPAT,
		Constraints: Constraints{Repos: []string{"acme/*"}}, Env: map[string]string{},
	}
	b := &Broker{GitGuard: workingGuard()} // BaseURL only: no route of its own
	if _, err := b.githubMaterial(context.Background(), mat, doc); !errors.Is(err, ErrGuardUnavailable) {
		t.Fatalf("githubMaterial = %v, want ErrGuardUnavailable", err)
	}

	guard := workingGuard()
	guard.result.ForgeURL = "https://elsewhere.example/_forge/" + ghesHost
	b = &Broker{GitGuard: guard}
	if _, err := b.githubMaterial(context.Background(), mat, doc); err == nil {
		t.Fatal("a route off the proxy's own host was accepted")
	}
}

// TestRedactionValuesRedactTheTokenOfAnEnterprisePAT: the value scrubbed from
// output is the token, not the document that records its host.
func TestRedactionValuesRedactTheTokenOfAnEnterprisePAT(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	doc, _ := GitHubPATPayload("ghp_redactThisTokenNotTheDoc01", ghesHost)
	s, err := b.Mint(context.Background(), MintRequest{Name: "ghes", Kind: KindGitHubPAT, Payload: doc, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"acme/*"}}, time.Hour)
	lease, err := b.Lease(context.Background(), "e1", "/srv/app")
	if err != nil {
		t.Fatal(err)
	}
	got := b.RedactionValues(lease.ID)
	if len(got) != 1 || got[0] != "ghp_redactThisTokenNotTheDoc01" {
		t.Fatalf("RedactionValues = %q, want the bare token", got)
	}
}

// TestTheRestorePathReadsTheGrantsHost: a process restoring a git proxy
// session learns where its credential may go from the grant — the PAT's
// payload, the App's token slot — before it mints anything.
func TestTheRestorePathReadsTheGrantsHost(t *testing.T) {
	t.Run("pat", func(t *testing.T) {
		b, _, _, _ := newTestBroker(t)
		doc, _ := GitHubPATPayload("ghp_restore0123", ghesHost)
		s, err := b.Mint(context.Background(), MintRequest{Name: "p", Kind: KindGitHubPAT, Payload: doc, Actor: "t"})
		if err != nil {
			t.Fatal(err)
		}
		g := grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"acme/*"}}, time.Hour)
		lease, err := b.Lease(context.Background(), "e1", "/srv/app")
		if err != nil {
			t.Fatal(err)
		}
		host, err := b.GitHubGrantHost(lease.ID, g.ID)
		if err != nil || host != ghesHost {
			t.Fatalf("GitHubGrantHost = %q, %v", host, err)
		}
		up, err := b.GitHubUpstream(context.Background(), lease.ID, g.ID, "sess-1")
		if err != nil || up.Host != ghesHost || up.Token != "ghp_restore0123" {
			t.Fatalf("GitHubUpstream host = %q, %v", up.Host, err)
		}
	})
	t.Run("app", func(t *testing.T) {
		b, _, _, clk := newTestBroker(t)
		gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "acme/tool"})
		gh.clock = clk.Now
		b.appMinter = newGitHubAppMinter(gh, clk.Now)
		b.GitGuard = &routedGuard{base: "https://hub.internal:8443"}
		s, err := b.Mint(context.Background(), MintRequest{Name: "a", Kind: KindGitHubApp, Payload: ghesAppPayload(t), Actor: "t"})
		if err != nil {
			t.Fatal(err)
		}
		g := grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"acme/*"}}, time.Hour)
		lease, err := b.Lease(context.Background(), "e1", "/srv/app")
		if err != nil {
			t.Fatal(err)
		}
		host, err := b.GitHubGrantHost(lease.ID, g.ID)
		if err != nil || host != ghesHost {
			t.Fatalf("GitHubGrantHost = %q, %v", host, err)
		}
		up, err := b.GitHubUpstream(context.Background(), lease.ID, g.ID, "sess-1")
		if err != nil || up.Host != ghesHost {
			t.Fatalf("GitHubUpstream host = %q, %v", up.Host, err)
		}
	})
}
