package gitcreds_test

// A workspace credential is chosen and bound by (host, path) (Task 20423).
//
// A grant's repository allowlist names owner/name; the host its credential is
// good against is its secret's. Before this, a grant for acme/* matched
// https://attacker.example/acme/tool exactly as it matched github.com, and the
// token was leased for — and so sent to — whatever host the project's origin
// named. These tests hold every driver's lease to the rule: another host with
// a matching owner/name gets no credential, and a refusal naming both hosts.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/forgehost"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// brokerWithHostedPAT mints one PAT issued by host ("" for github.com) and
// grants it to subject for patterns.
func brokerWithHostedPAT(t testing.TB, token, host, subject string, patterns []string) *secretbroker.Broker {
	t.Helper()
	b := newHostBroker(t)
	if err := mintHostedPAT(b, token, host, subject, patterns); err != nil {
		t.Fatalf("mint/grant: %v", err)
	}
	return b
}

func newHostBroker(t testing.TB) *secretbroker.Broker {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*13 + 1)
	}
	cipher, err := secretbroker.NewCipherWithKey(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	b, err := secretbroker.New(newMemStore(), secretbroker.WithCipher(cipher))
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	return b
}

func mintHostedPAT(b *secretbroker.Broker, token, host, subject string, patterns []string) error {
	payload, err := secretbroker.GitHubPATPayload(token, host)
	if err != nil {
		return err
	}
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: "acme-pat", Kind: secretbroker.KindGitHubPAT, Payload: payload, Actor: "test",
	})
	if err != nil {
		return err
	}
	sub, err := secretbroker.ParseSubject(subject)
	if err != nil {
		return err
	}
	_, err = b.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: sub,
		Constraints: secretbroker.Constraints{Repos: patterns},
		TTL:         time.Hour, Actor: "test",
	})
	return err
}

func workspaceAt(repo string) executor.Workspace {
	return executor.Workspace{Kind: executor.WorkspaceGit, Repo: repo, Ref: "main", CredentialGrant: "acme-pat"}
}

// lookAlikes are origins on hosts other than github.com, each with the
// owner/name the grant admits, spelled the ways a host that is not github.com
// can be made to look like one — or to look like nothing in particular.
var lookAlikes = []struct{ repo, host string }{
	{"https://attacker.example/acme/tool", "attacker.example"},
	{"https://ATTACKER.Example./acme/tool.git", "attacker.example"},
	{"https://github.com:8443/acme/tool", "github.com:8443"},
	{"https://github.com.attacker.example/acme/tool", "github.com.attacker.example"},
	{"https://attacker-github.com/acme/tool", "attacker-github.com"},
	{"https://gіthub.com/acme/tool", "xn--gthub-n2e.com"}, // Cyrillic і
	{"https://140.82.112.3/acme/tool", "140.82.112.3"},
	{"https://www.github.com/acme/tool", "www.github.com"},
}

// TestAnOriginOnAnotherHostGetsNoCredential is the defect.
func TestAnOriginOnAnotherHostGetsNoCredential(t *testing.T) {
	const token = "ghp_mustStayOffEveryOtherHost0123"
	b := brokerWithHostedPAT(t, token, "", "project:/srv/app", []string{"acme/*"})
	src, err := gitcreds.New(b, "device-1", "ui")
	if err != nil {
		t.Fatal(err)
	}
	for _, la := range lookAlikes {
		t.Run(la.repo, func(t *testing.T) {
			for _, lease := range []func(context.Context, string, executor.Workspace) (executor.WorkspaceAccess, func(), error){
				src.ForWorkspace, src.ForProxiedWorkspace,
			} {
				access, release, err := lease(context.Background(), "/srv/app", workspaceAt(la.repo))
				release()
				if !access.Credential.Empty() || strings.Contains(access.Credential.Password, token) {
					t.Fatalf("a credential was leased for %s", la.repo)
				}
				var gerr *executor.WorkspaceGrantError
				if !errors.As(err, &gerr) {
					t.Fatalf("err = %v, want a *WorkspaceGrantError", err)
				}
				if !gerr.HostMismatch() || gerr.Host != la.host || gerr.GrantHost != "github.com" {
					t.Fatalf("refusal = %+v, want hosts %s and github.com", gerr, la.host)
				}
				msg := err.Error()
				if !strings.Contains(msg, la.host) || !strings.Contains(msg, "github.com") {
					t.Fatalf("the refusal does not name both hosts: %s", msg)
				}
				if strings.Contains(msg, "--repos") {
					t.Fatalf("the refusal sends the operator to widen the allowlist, which cannot help: %s", msg)
				}
			}
		})
	}
}

// TestAnOriginWithUserinfoGetsNoCredential: userinfo is how one host is made to
// look like another ("https://github.com@attacker.example/..."). A workspace
// URL may not carry it at all, so it is refused before any host is compared —
// and nothing is leased.
func TestAnOriginWithUserinfoGetsNoCredential(t *testing.T) {
	b := brokerWithHostedPAT(t, "ghp_userinfoTrick0123", "", "project:/srv/app", []string{"acme/*"})
	src, _ := gitcreds.New(b, "device-1", "ui")
	for _, repo := range []string{
		"https://github.com@attacker.example/acme/tool",
		"https://x-access-token@github.com/acme/tool",
	} {
		access, release, err := src.ForWorkspace(context.Background(), "/srv/app", workspaceAt(repo))
		release()
		if err == nil || !access.Credential.Empty() {
			t.Errorf("%s: credential %v, err %v", repo, !access.Credential.Empty(), err)
		}
	}
}

// TestTheGrantsOwnHostSpelledAnotherWayKeepsItsCredential: the folding that
// makes a host equal is case, a trailing dot, the default port and IDN — and
// a github.com grant keeps working under every one of them.
func TestTheGrantsOwnHostSpelledAnotherWayKeepsItsCredential(t *testing.T) {
	const token = "ghp_sameHostDifferentSpelling01"
	b := brokerWithHostedPAT(t, token, "", "project:/srv/app", []string{"acme/*"})
	src, _ := gitcreds.New(b, "device-1", "ui")
	for _, repo := range []string{
		"https://github.com/acme/tool.git",
		"https://GitHub.COM/acme/tool",
		"https://github.com./acme/tool",
		"https://github.com:443/acme/tool",
		"https://ｇｉｔｈｕｂ.com/acme/tool",
	} {
		w := workspaceAt(repo)
		access, release, err := src.ForWorkspace(context.Background(), "/srv/app", w)
		if err != nil {
			release()
			t.Errorf("%s was refused: %v", repo, err)
			continue
		}
		if access.Credential.Password != token || access.Credential.Host != "github.com" {
			t.Errorf("%s: credential bound to %q", repo, access.Credential.Host)
		}
		// And the header the fetch carries is scoped to the origin, which is
		// the grant's host.
		if _, err := executor.GitCredentialConfig(w, access.Credential); err != nil {
			t.Errorf("%s: the credential cannot be scoped to its own host: %v", repo, err)
		}
		release()
	}
}

// TestAGitHubEnterpriseGrantIsBoundToItsServer: a PAT whose secret records a
// GitHub Enterprise Server host is leased for that server and for nothing
// else — github.com least of all.
func TestAGitHubEnterpriseGrantIsBoundToItsServer(t *testing.T) {
	const token = "ghp_enterpriseOnly0123456789"
	b := brokerWithHostedPAT(t, token, "ghes.example.com", "project:/srv/app", []string{"acme/*"})
	src, _ := gitcreds.New(b, "device-1", "ui")

	access, release, err := src.ForWorkspace(context.Background(), "/srv/app", workspaceAt("https://ghes.example.com/acme/tool"))
	if err != nil {
		t.Fatalf("the server's own repository was refused: %v", err)
	}
	if access.Credential.Password != token || access.Credential.Host != "ghes.example.com" {
		t.Fatalf("credential bound to %q", access.Credential.Host)
	}
	release()

	_, release, err = src.ForWorkspace(context.Background(), "/srv/app", workspaceAt("https://github.com/acme/tool"))
	release()
	var gerr *executor.WorkspaceGrantError
	if !errors.As(err, &gerr) || gerr.Host != "github.com" || gerr.GrantHost != "ghes.example.com" {
		t.Fatalf("a GitHub Enterprise Server token was offered for github.com: %v", err)
	}
}

// TestTheCredentialRefusesToBeScopedToAnotherHost is the last check before git
// sends anything: whatever chose it, a credential bound to one host produces
// no extraHeader for a workspace on another.
func TestTheCredentialRefusesToBeScopedToAnotherHost(t *testing.T) {
	cred := executor.GitCredential{Username: "x-access-token", Password: "ghp_x", Host: "github.com", GrantID: "g1"}
	for _, la := range lookAlikes {
		pairs, err := executor.GitCredentialConfig(workspaceAt(la.repo), cred)
		var gerr *executor.WorkspaceGrantError
		if !errors.As(err, &gerr) || len(pairs) != 0 {
			t.Errorf("%s: pairs %v, err %v", la.repo, pairs, err)
			continue
		}
		if gerr.Host != la.host || gerr.GrantHost != "github.com" {
			t.Errorf("%s: refusal names %q and %q", la.repo, gerr.Host, gerr.GrantHost)
		}
	}
}

// FuzzNoCredentialLeavesItsGrantsHost: whatever the origin, the grant's host
// and its allowlist, a credential is leased only for a workspace on the
// grant's own host, is bound to that host, and scopes its header there.
func FuzzNoCredentialLeavesItsGrantsHost(f *testing.F) {
	for _, s := range [][3]string{
		{"https://github.com/acme/tool", "", "acme/*"},
		{"https://attacker.example/acme/tool", "", "acme/*"},
		{"https://GitHub.com./acme/tool.git", "", "*"},
		{"https://ghes.example.com/acme/tool", "ghes.example.com", "acme/tool"},
		{"https://github.com/acme/tool", "ghes.example.com", "acme/*"},
		{"https://ghes.example.com:8443/acme/tool", "ghes.example.com", "*/*"},
		{"https://gіthub.com/acme/tool", "", "acme/*"},
		{"https://github.com@attacker.example/acme/tool", "", "acme/*"},
		{"https://127.0.0.1:41234/acme/tool", "127.0.0.1:41234", "acme/*"},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, origin, grantHost, pattern string) {
		b := newHostBroker(t)
		if err := mintHostedPAT(b, "ghp_fuzzToken0123456789", grantHost, "project:/srv/app", []string{pattern}); err != nil {
			return // a host or pattern no grant can be minted with
		}
		want := forgehost.GitHub
		if strings.TrimSpace(grantHost) != "" {
			c, err := forgehost.Canonical(grantHost)
			if err != nil {
				t.Fatalf("a grant was minted for unusable host %q", grantHost)
			}
			want = c
		}
		src, err := gitcreds.New(b, "device-1", "ui")
		if err != nil {
			t.Fatal(err)
		}
		w := workspaceAt(origin)
		access, release, err := src.ForWorkspace(context.Background(), "/srv/app", w)
		defer release()
		if err != nil || access.Credential.Empty() {
			return
		}
		if access.Credential.Host != want {
			t.Fatalf("credential for %q bound to %q, want its grant's %q", origin, access.Credential.Host, want)
		}
		originHost, herr := w.ForgeHost()
		if herr != nil || originHost != want {
			t.Fatalf("a %s credential was leased for %q (host %q, %v)", want, origin, originHost, herr)
		}
		pairs, err := executor.GitCredentialConfig(w, access.Credential)
		if err != nil {
			t.Fatalf("a leased credential cannot be scoped to its workspace: %v", err)
		}
		for _, p := range pairs {
			if strings.HasPrefix(p[0], "http.") {
				scope, _ := strings.CutPrefix(p[0], "http.")
				scope, _ = strings.CutSuffix(scope, ".extraHeader")
				if !forgehost.Equal(scope, want) {
					t.Fatalf("the header is scoped to %q, not %s", scope, want)
				}
			}
		}
	})
}
