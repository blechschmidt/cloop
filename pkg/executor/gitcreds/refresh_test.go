package gitcreds

// RefreshWorkspaceCredential (Task 20375): the workspace path's pinned git
// proxy session renews a GitHub App token through the lease that minted it.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

func TestRefreshWorkspaceCredentialRenewsAnAppToken(t *testing.T) {
	clock := secretbrokertest.NewClock(time.Now())
	gh := secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 1, FullName: "acme/tool"})
	gh.Clock = clock.Now
	store := secretbrokertest.NewStore()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	cipher, err := secretbroker.NewCipherWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(store, secretbroker.WithCipher(cipher), secretbroker.WithClock(clock.Now),
		secretbroker.WithGitHubApp(gh))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sec, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "ws-app", Kind: secretbroker.KindGitHubApp, Payload: secretbrokertest.AppPayload(1, 2), Actor: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	g, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "edge-1"},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/tool"}}, TTL: 24 * time.Hour, Actor: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	src, err := New(b, "edge-1", "t")
	if err != nil {
		t.Fatal(err)
	}
	access, release, err := src.ForProxiedWorkspace(ctx, "/srv/p", executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git", CredentialGrant: "ws-app",
	})
	if err != nil {
		t.Fatalf("ForProxiedWorkspace: %v", err)
	}
	defer release()
	cred := access.Credential
	if cred.TokenExpiresAt.IsZero() {
		t.Fatal("an App token's credential does not carry its expiry, so nothing would renew it")
	}

	clock.Advance(52 * time.Minute)
	renewed, retire, err := src.RefreshWorkspaceCredential(ctx, cred, cred.Password)
	if err != nil {
		t.Fatalf("RefreshWorkspaceCredential: %v", err)
	}
	if renewed.Password == cred.Password || !gh.Valid(renewed.Password) || !renewed.TokenExpiresAt.After(cred.TokenExpiresAt) {
		t.Fatal("the renewed credential is not a new, live, later-expiring token")
	}
	retire()
	if gh.Valid(cred.Password) {
		t.Error("retiring the superseded token left it alive")
	}

	if err := store.RevokeGrant(g.ID, clock.Now()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(55 * time.Minute)
	if _, _, err := src.RefreshWorkspaceCredential(ctx, renewed, renewed.Password); !errors.Is(err, executor.ErrCredentialRefused) {
		t.Fatalf("renewing a revoked grant = %v; want executor.ErrCredentialRefused", err)
	}
}
