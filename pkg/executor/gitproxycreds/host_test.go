package gitproxycreds

// A workspace's pinned session presents its forge credential to the grant's
// host and nowhere else (Task 20423).
//
// The session's upstream used to be the workspace's origin, verbatim: a
// project whose origin named https://attacker.example/acme/tool had a session
// minted that presented the forge token there — the very credential the proxy
// exists to keep on the hub. Now the upstream is built from the credential's
// host and the repository path, and an origin on any other host is refused
// before a session exists.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestAPinnedSessionIsNeverMintedForAnotherHost(t *testing.T) {
	for _, tc := range []struct{ repo, host string }{
		{"https://attacker.example/acme/tool", "attacker.example"},
		{"https://ATTACKER.example./acme/tool.git", "attacker.example"},
		{"https://github.com:8443/acme/tool", "github.com:8443"},
		{"https://github.com.attacker.example/acme/tool", "github.com.attacker.example"},
		{"https://gіthub.com/acme/tool", "xn--gthub-n2e.com"},
	} {
		t.Run(tc.repo, func(t *testing.T) {
			// The inner source here does not check hosts — it stands for a
			// lease that chose a credential for some other reason — so this
			// is the decorator's own refusal.
			inner := &fakeInner{access: patAccess()}
			reg := newRegistry(t, time.Time{})
			src := newSource(t, inner, reg, 0)
			w := gitWorkspace()
			w.Repo = tc.repo

			access, release, err := src.ForWorkspace(context.Background(), "proj-1", w)
			release()
			if !access.Credential.Empty() || access.Repo != "" {
				t.Fatalf("a session was handed out for %s: %+v", tc.repo, access)
			}
			var gerr *executor.WorkspaceGrantError
			if !errors.As(err, &gerr) || gerr.Host != tc.host || gerr.GrantHost != "github.com" {
				t.Fatalf("err = %v, want a refusal naming %s and github.com", err, tc.host)
			}
			if !strings.Contains(err.Error(), tc.host) || !strings.Contains(err.Error(), "github.com") {
				t.Fatalf("the refusal does not name both hosts: %v", err)
			}
			if n := len(reg.Sessions()); n != 0 {
				t.Fatalf("%d session(s) were minted for another host", n)
			}
			if inner.releases != 1 {
				t.Fatalf("the inner lease was released %d times, want once", inner.releases)
			}
		})
	}
}

// TestAPinnedSessionsUpstreamIsTheGrantsHost: the URL the proxy forwards to is
// the credential's host and the repository's path — never the origin's
// spelling of either.
func TestAPinnedSessionsUpstreamIsTheGrantsHost(t *testing.T) {
	for _, tc := range []struct {
		repo, credHost, upstream, forge string
	}{
		{"https://GitHub.com./acme/tool.git", "github.com", "https://github.com/acme/tool", "github.com"},
		{"https://github.com:443/acme/tool", "github.com", "https://github.com/acme/tool", "github.com"},
		{"https://ghes.example.com/acme/tool", "ghes.example.com", "https://ghes.example.com/acme/tool", "ghes.example.com"},
		{"https://GHES.example.com:8443/acme/tool", "ghes.example.com:8443", "https://ghes.example.com:8443/acme/tool", "ghes.example.com:8443"},
	} {
		inner := &fakeInner{access: patAccess()}
		inner.access.Credential.Host = tc.credHost
		reg := newRegistry(t, time.Time{})
		src := newSource(t, inner, reg, 0)
		w := gitWorkspace()
		w.Repo = tc.repo
		access, release, err := src.ForWorkspace(context.Background(), "proj-1", w)
		if err != nil {
			t.Fatalf("%s: %v", tc.repo, err)
		}
		sessions := reg.Sessions()
		if len(sessions) != 1 {
			t.Fatalf("%s: %d sessions", tc.repo, len(sessions))
		}
		if s := sessions[0]; s.Upstream != tc.upstream || s.ForgeHost != tc.forge {
			t.Errorf("%s: session upstream %q on %q, want %q on %q", tc.repo, s.Upstream, s.ForgeHost, tc.upstream, tc.forge)
		}
		// The sandbox's credential is the proxy's, and scoped to it.
		if access.Credential.Host != "hub.internal:8443" {
			t.Errorf("%s: the session credential is bound to %q, not the proxy", tc.repo, access.Credential.Host)
		}
		if _, err := executor.GitCredentialConfig(access.Apply(w), access.Credential); err != nil {
			t.Errorf("%s: the session credential cannot be scoped to the routed workspace: %v", tc.repo, err)
		}
		release()
	}
}

// TestACredentialThatNamesNoHostIsNotHeld: a source that cannot say where its
// credential belongs is not guessed for. Guessing would mean the origin.
func TestACredentialThatNamesNoHostIsNotHeld(t *testing.T) {
	inner := &fakeInner{access: patAccess()}
	inner.access.Credential.Host = ""
	reg := newRegistry(t, time.Time{})
	src := newSource(t, inner, reg, 0)
	access, release, err := src.ForWorkspace(context.Background(), "proj-1", gitWorkspace())
	release()
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) || !access.Credential.Empty() {
		t.Fatalf("err = %v, credential %v; want a refusal", err, !access.Credential.Empty())
	}
	if n := len(reg.Sessions()); n != 0 {
		t.Fatalf("%d session(s) minted for a credential with no host", n)
	}
}
