package remote_test

// The device workspace path binds the credential to its grant's host
// (Task 20423), with the broker's real source rather than a fake: an origin on
// another host with a matching owner/name is refused at the hub, naming both
// hosts, and the device is sent no start frame — so no token — at all. A
// github.com origin's credential reaches the device carrying the host it is
// bound to, which the device's own provisioner checks again.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// brokerSource is the hub's real workspace credential source over one PAT,
// granted to the demo project for acme/*.
func brokerSource(t *testing.T) executor.WorkspaceCredentialSource {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*5 + 9)
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
		Name: "github-ci", Kind: secretbroker.KindGitHubPAT, Payload: []byte(workspaceTestToken), Actor: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/projects/demo"},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}}, TTL: time.Hour, Actor: "t",
	}); err != nil {
		t.Fatal(err)
	}
	src, err := gitcreds.New(b, "agent-1", "test")
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestADeviceIsSentNoCredentialForAnotherHost(t *testing.T) {
	for _, tc := range []struct{ repo, host string }{
		{"https://attacker.example/acme/widget.git", "attacker.example"},
		{"https://GitHub.com.attacker.example./acme/widget", "github.com.attacker.example"},
		{"https://github.com:8443/acme/widget", "github.com:8443"},
		{"https://gіthub.com/acme/widget", "xn--gthub-n2e.com"},
	} {
		t.Run(tc.repo, func(t *testing.T) {
			ex := newWorkspaceExecutor(t, brokerSource(t))
			p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
			defer sess.Close()

			spec := gitSpec("github-ci")
			spec.Workspace.Repo = tc.repo
			_, err := ex.Start(context.Background(), spec)
			var gerr *executor.WorkspaceGrantError
			if !errors.As(err, &gerr) || gerr.Host != tc.host || gerr.GrantHost != "github.com" {
				t.Fatalf("Start = %v; want a refusal naming %s and github.com", err, tc.host)
			}
			if !strings.Contains(err.Error(), tc.host) || !strings.Contains(err.Error(), "github.com") {
				t.Fatalf("the refusal does not name both hosts: %v", err)
			}
			// Nothing was sent: no start frame, so no credential.
			for {
				f, rerr := p.read()
				if rerr != nil {
					break
				}
				if f.Type == remote.TypeStart {
					t.Fatalf("a start frame was sent for a workspace on %s", tc.host)
				}
			}
		})
	}
}

func TestADeviceCredentialCarriesTheHostItIsBoundTo(t *testing.T) {
	ex := newWorkspaceExecutor(t, brokerSource(t))
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloAt(remote.ProtocolVersion), nil)
	defer sess.Close()
	got := captureStart(t, p)
	if _, err := ex.Start(context.Background(), gitSpec("github-ci")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	payload := <-got
	if payload.WorkspaceCredential == nil || payload.WorkspaceCredential.Password != workspaceTestToken {
		t.Fatal("the device was not sent the leased credential")
	}
	if payload.WorkspaceCredential.Host != "github.com" {
		t.Fatalf("the credential reached the device bound to %q", payload.WorkspaceCredential.Host)
	}
	// And the device's provisioner will refuse to scope it anywhere else.
	cred := payload.GitCredential()
	other := payload.Spec.Workspace
	other.Repo = "https://attacker.example/acme/widget.git"
	if _, err := executor.GitCredentialConfig(other, cred); err == nil {
		t.Fatal("the device would scope a github.com credential to another host")
	}
	if _, err := executor.GitCredentialConfig(payload.Spec.Workspace, cred); err != nil {
		t.Fatalf("the device cannot scope the credential to its own workspace: %v", err)
	}
}
