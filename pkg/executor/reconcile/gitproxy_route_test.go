package reconcile

// routeWorkspaceSource (Task 20349): only `cloop ui` runs the git interception
// proxy, and every other process that registers the Kubernetes driver used to
// hand its Pods the forge credential even with the proxy configured.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
)

// countingSource is a workspace source that records whether it was consulted.
type countingSource struct{ calls int }

func (c *countingSource) ForWorkspace(context.Context, string, executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	c.calls++
	return executor.WorkspaceAccess{Credential: executor.GitCredential{
		Username: "x-access-token", Password: "ghp_forgecredential0123456789",
	}}, func() {}, nil
}

func proxyConfig(enabled bool) *config.Config {
	cfg := &config.Config{}
	cfg.Executors.GitProxy.Enabled = enabled
	return cfg
}

// TestWorkspaceSourceFailsClosedWithoutTheProxy is the gap: a process with the
// proxy configured and no way to route through it refuses, and never asks the
// broker for the forge credential it would have handed over.
func TestWorkspaceSourceFailsClosedWithoutTheProxy(t *testing.T) {
	inner := &countingSource{}
	src := routeWorkspaceSource(proxyConfig(true), Options{}, "k8s-prod", inner)

	access, release, err := src.ForWorkspace(context.Background(), "/srv/app", executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git", CredentialGrant: "acme",
	})
	if release == nil {
		t.Fatal("the refusing source returned a nil release; a driver defers it unconditionally")
	}
	release()
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Fatalf("err = %v, want ErrWorkspaceUnavailable", err)
	}
	if !access.Credential.Empty() {
		t.Fatal("the refusal still carried a credential")
	}
	if inner.calls != 0 {
		t.Fatalf("the broker was asked for the forge credential %d time(s) on the refusal path", inner.calls)
	}
	for _, want := range []string{"executors.git_proxy", "cloop ui", "k8s-prod"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should name %q so the operator can act on it: %v", want, err)
		}
	}
}

// TestWorkspaceSourceRoutesThroughTheCallersProxy: the hub that runs the proxy
// passes its wrapper, and that decides — never the fail-closed default.
func TestWorkspaceSourceRoutesThroughTheCallersProxy(t *testing.T) {
	inner := &countingSource{}
	wrapped := &countingSource{}
	var gotID string
	src := routeWorkspaceSource(proxyConfig(true), Options{
		WrapWorkspaceSource: func(id string, s executor.WorkspaceCredentialSource) executor.WorkspaceCredentialSource {
			gotID = id
			if s != inner {
				t.Error("the wrapper was not handed the broker source")
			}
			return wrapped
		},
	}, "k8s-prod", inner)
	if src != wrapped {
		t.Fatalf("got %T, want the caller's wrapper", src)
	}
	if gotID != "k8s-prod" {
		t.Errorf("the wrapper was told executor %q, want k8s-prod", gotID)
	}
}

// TestWorkspaceSourceIsUnchangedWithoutAProxySection: no proxy configured is the
// documented "credential goes to the one fetching git child" behaviour, and a
// hub without a broker still has no source at all.
func TestWorkspaceSourceIsUnchangedWithoutAProxySection(t *testing.T) {
	inner := &countingSource{}
	if src := routeWorkspaceSource(proxyConfig(false), Options{}, "k8s-prod", inner); src != inner {
		t.Fatalf("got %T, want the broker source unchanged", src)
	}
	if src := routeWorkspaceSource(nil, Options{}, "k8s-prod", inner); src != inner {
		t.Fatalf("a nil config changed the source to %T", src)
	}
	if src := routeWorkspaceSource(proxyConfig(true), Options{}, "k8s-prod", nil); src != nil {
		t.Fatalf("no broker became a %T; it must stay nil so a public fetch still works", src)
	}
}
