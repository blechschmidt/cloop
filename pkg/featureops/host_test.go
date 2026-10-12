package featureops

// A token handed over explicitly — the hub's brokered grant, or --token — obeys
// the host rule an ambient one does (Task 20423). It used to skip it, so a
// project whose origin named another host had the hub's grant pushed there and
// its pull request opened against that host's API.

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/forgehost"
)

func TestAnExplicitTokenObeysTheHostRule(t *testing.T) {
	hermeticGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")
	hub := WithHubEnv(context.Background(), func(extra ...[2]string) []string { return executor.GitEnv(extra...) })
	const tok = "ghp_brokeredGrantToken0123"

	for _, tc := range []struct {
		name, host, api string
		want            bool
	}{
		{"github.com grant, github.com origin", "github.com", forgehost.GitHubAPI, true},
		{"github.com grant, no API named", "github.com", "", true},
		{"github.com grant, another host", "attacker.example", forgehost.GitHubAPI, false},
		{"github.com grant, look-alike", "xn--gthub-n2e.com", forgehost.GitHubAPI, false},
		{"github.com grant, github.com on another port", "github.com:8443", forgehost.GitHubAPI, false},
		{"github.com grant, suffix", "github.com.attacker.example", "", false},
		{"enterprise grant, its server", "ghes.example.com", "https://ghes.example.com/api/v3", true},
		{"enterprise grant, github.com origin", "github.com", "https://ghes.example.com/api/v3", false},
		{"enterprise grant, another port", "ghes.example.com:8443", "https://ghes.example.com/api/v3", false},
		{"enterprise grant on a port", "ghes.example.com:8443", "https://ghes.example.com:8443/api/v3", true},
	} {
		remote := Remote{Host: tc.host, Repo: "acme/app", HTTPS: true}
		for _, ctx := range []context.Context{context.Background(), hub} {
			got, src := ResolveToken(ctx, dir, remote, tok, tc.api)
			if (got == tok) != tc.want {
				t.Errorf("%s (hub mode %v): resolved %q from %q, want allowed=%v",
					tc.name, hubEnv(ctx) != nil, got, src, tc.want)
			}
			if !tc.want && got != "" {
				t.Errorf("%s: a refused explicit token fell through to %s", tc.name, src)
			}
		}
	}

	// A remote with no host — a local path, the repository named by hand —
	// has no origin to steer the token; it goes only to the endpoint named.
	if got, src := ResolveToken(context.Background(), dir, Remote{Repo: "acme/app"}, tok, ""); got != tok || src != "flag" {
		t.Errorf("explicit token with no remote host: %q from %q", got, src)
	}
}

func TestTokenMayReachFollowsTheAPIsHost(t *testing.T) {
	for _, c := range []struct {
		host, override string
		want           bool
	}{
		{"github.com", "https://api.github.com", true},
		{"github.com", "https://ghe.corp/api/v3", false},
		{"ghe.corp:8443", "https://ghe.corp:8443/api/v3", true},
		{"ghe.corp", "https://ghe.corp:8443/api/v3", false},
		{"GHE.corp.", "https://ghe.corp/api/v3", true},
		{"github.com", "http://127.0.0.1:41234", true}, // a stand-in for the public API
		{"attacker.example", "http://127.0.0.1:41234", false},
		{"xn--gthub-n2e.com", "", false},
		{"github.com:8443", "", false},
		{"github.com", "ftp://api.github.com", false},
	} {
		if got := tokenMayReach(c.host, c.override); got != c.want {
			t.Errorf("tokenMayReach(%q, %q) = %v, want %v", c.host, c.override, got, c.want)
		}
	}
}

func TestParseRemoteKeepsTheHostsPort(t *testing.T) {
	for _, c := range []struct{ in, host string }{
		{"https://ghes.corp:8443/acme/app.git", "ghes.corp:8443"},
		{"https://GitHub.com./acme/app", "github.com"},
		{"https://github.com:443/acme/app", "github.com"},
		{"ssh://git@github.com:22/acme/app.git", "github.com"},
		{"ssh://git@ghes.corp:2222/acme/app.git", "ghes.corp:2222"},
		{"git@GitHub.com:acme/app.git", "github.com"},
	} {
		r, err := ParseRemote(c.in)
		if err != nil || r.Host != c.host {
			t.Errorf("ParseRemote(%q) = %+v, %v; want host %q", c.in, r, err, c.host)
		}
	}
	if APIBaseURL("ghes.corp:8443") != "https://ghes.corp:8443/api/v3" {
		t.Errorf("APIBaseURL lost the port: %s", APIBaseURL("ghes.corp:8443"))
	}
	if _, err := ParseRemote("https://user:s3cret@gіthub.com/acme/app"); err != nil && strings.Contains(err.Error(), "s3cret") {
		t.Errorf("a host error quotes the remote's credential: %v", err)
	}
}

// TestHubModeSendsTheGrantNowhereElse: the hub's push authenticates with the
// brokered token as an extraheader for the origin's host. With the origin on
// another host than the grant's API names, there is no token to push with —
// the push is refused before git runs, and the API is never called.
func TestHubModeSendsTheGrantNowhereElse(t *testing.T) {
	project, _ := newProject(t)
	gitRun(t, project, "remote", "set-url", "origin", "https://attacker.example/acme/app.git")
	ctx := context.Background()
	info, err := Create(ctx, CreateOptions{ProjectDir: project, Name: "steer"})
	if err != nil {
		t.Fatal(err)
	}
	commitIn(t, info.Path, "s.txt", "s\n")
	gh, srv := newFakeGitHub(t, "ghp_brokeredGrantToken0123")

	hub := WithHubEnv(ctx, func(extra ...[2]string) []string { return executor.GitEnv(extra...) })
	res, err := OpenPR(hub, PROptions{FeatureDir: info.Path, Token: "ghp_brokeredGrantToken0123", APIURL: srv.URL})
	if err == nil {
		t.Fatalf("a pull request was opened with a github.com grant for an origin on attacker.example: %+v", res)
	}
	if !strings.Contains(err.Error(), "no credential") {
		t.Errorf("err = %v, want the push refused for want of a credential", err)
	}
	gh.mu.Lock()
	defer gh.mu.Unlock()
	if len(gh.creates) != 0 {
		t.Fatalf("the API was called %d times", len(gh.creates))
	}
}
