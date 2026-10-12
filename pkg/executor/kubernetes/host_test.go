package kubernetes

// The Kubernetes workspace path binds the credential to its grant's host
// (Task 20423), with the broker's real source: an origin on another host with
// a matching owner/name is refused before the cluster is touched — no
// cloop-ws Secret holding the token, no Pod — and the refusal names both
// hosts. A github.com origin's Secret carries the host the token is bound to,
// which the init container's provisioner checks again.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// hostBoundSource is the hub's real workspace source over one PAT, granted to
// this test's executor for acme/*.
func hostBoundSource(t *testing.T) executor.WorkspaceCredentialSource {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*3 + 17)
	}
	cipher, err := secretbroker.NewCipherWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(secretbrokertest.NewStore(), secretbroker.WithCipher(cipher))
	if err != nil {
		t.Fatal(err)
	}
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: "acme-pat", Kind: secretbroker.KindGitHubPAT, Payload: []byte(fakeWorkspaceToken), Actor: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "k8s-test"},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}}, TTL: time.Hour, Actor: "t",
	}); err != nil {
		t.Fatal(err)
	}
	src, err := gitcreds.New(b, "k8s-test", "test")
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestStart_AWorkspaceOnAnotherHostGetsNoSecret(t *testing.T) {
	for _, tc := range []struct{ repo, host string }{
		{"https://attacker.example/acme/widgets.git", "attacker.example"},
		{"https://Attacker.Example./acme/widgets", "attacker.example"},
		{"https://github.com:8443/acme/widgets", "github.com:8443"},
		{"https://gіthub.com/acme/widgets", "xn--gthub-n2e.com"},
	} {
		t.Run(tc.repo, func(t *testing.T) {
			ex, api, leases := newTestExecutor(t, func(o *Options) { o.Workspace = hostBoundSource(t) })
			spec := workspaceSpec()
			spec.Workspace.Repo = tc.repo

			_, err := ex.Start(context.Background(), spec)
			var gerr *executor.WorkspaceGrantError
			if !errors.As(err, &gerr) || gerr.Host != tc.host || gerr.GrantHost != "github.com" {
				t.Fatalf("Start = %v; want a refusal naming %s and github.com", err, tc.host)
			}
			if !strings.Contains(err.Error(), tc.host) || !strings.Contains(err.Error(), "github.com") {
				t.Fatalf("the refusal does not name both hosts: %v", err)
			}
			if names := api.secretNames(); len(names) != 0 {
				t.Fatalf("a Secret was created for a workspace on %s: %v", tc.host, names)
			}
			if names := api.podNames(); len(names) != 0 {
				t.Fatalf("a Pod was created for a workspace on %s: %v", tc.host, names)
			}
			if got := api.requestsMatching("POST"); len(got) != 0 {
				t.Fatalf("the driver wrote to the cluster: %v", got)
			}
			leases.waitOutstandingEmpty(t, 2*time.Second)
		})
	}
}

func TestStart_AWorkspaceSecretNamesTheHostItsTokenIsBoundTo(t *testing.T) {
	ex, api, _ := newTestExecutor(t, func(o *Options) { o.Workspace = hostBoundSource(t) })
	handle, err := ex.Start(context.Background(), workspaceSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	api.mu.Lock()
	sec := api.secrets[workspaceSecretName(handle.ID)]
	api.mu.Unlock()
	if sec == nil {
		t.Fatalf("no workspace Secret; got %v", api.secretNames())
	}
	if sec.StringData[EnvWorkspaceToken] != fakeWorkspaceToken {
		t.Fatal("the Secret does not carry the leased token")
	}
	if got := sec.StringData[EnvWorkspaceHost]; got != "github.com" {
		t.Fatalf("the Secret binds the token to %q, want github.com", got)
	}
}
