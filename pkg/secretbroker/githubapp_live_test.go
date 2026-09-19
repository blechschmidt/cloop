package secretbroker

// Live integration test against a real GitHub App.
//
// Everything else in this package tests against fakeGitHub, which is the right
// default: a hermetic suite, no credentials in CI, no dependency on a third
// party's availability. But a fake also agrees with whatever this package
// believes about GitHub's wire format, so it cannot catch the class of bug
// where that belief is wrong — a field GitHub nests one level deeper than
// expected, an endpoint that wants a different authentication, a response whose
// end-of-list signal is not the one assumed.
//
// Installation discovery (Task 20306) is exactly that class. It is the one call
// authenticated by an app JWT rather than an installation token, its response
// nests the account, and unlike the repository listing it carries no
// total_count to page on. All three were checked against the real API here
// before being trusted.
//
// Opt in by pointing the environment at an App:
//
//	CLOOP_GITHUB_APP_ID=<numeric app id> \
//	CLOOP_GITHUB_APP_KEY=/path/to/private-key.pem \
//	go test ./pkg/secretbroker/ -run TestLiveGitHubApp -v
//
// Skipped otherwise, so `go test ./...` stays hermetic.

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// liveApp loads the App under test, or skips.
func liveApp(t *testing.T) (appID int64, keyPEM string) {
	t.Helper()
	rawID := strings.TrimSpace(os.Getenv("CLOOP_GITHUB_APP_ID"))
	keyPath := strings.TrimSpace(os.Getenv("CLOOP_GITHUB_APP_KEY"))
	if rawID == "" || keyPath == "" {
		t.Skip("set CLOOP_GITHUB_APP_ID and CLOOP_GITHUB_APP_KEY to run the live GitHub App test")
	}
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil {
		t.Fatalf("CLOOP_GITHUB_APP_ID=%q is not an integer: %v", rawID, err)
	}
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read CLOOP_GITHUB_APP_KEY: %v", err)
	}
	return id, string(pem)
}

// connectionPayload is what the Connect dialog posts: an App and a key, and no
// installation, because that is the field discovery exists to find.
func connectionPayload(t *testing.T, appID int64, keyPEM string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"app_id": appID, "private_key": keyPEM})
	if err != nil {
		t.Fatalf("marshal connection payload: %v", err)
	}
	return b
}

// TestLiveGitHubAppDiscovery drives discovery against api.github.com.
func TestLiveGitHubAppDiscovery(t *testing.T) {
	appID, keyPEM := liveApp(t)
	t.Setenv(EnvPassphraseKey, "live-github-app-test-passphrase")

	b, err := New(newMemStore())
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	installs, err := b.DiscoverGitHubAppInstallations(ctx, connectionPayload(t, appID, keyPEM))
	if err != nil {
		t.Fatalf("DiscoverGitHubAppInstallations: %v", err)
	}
	if len(installs) == 0 {
		t.Fatal("no installations returned, but discovery reports an empty list as an error")
	}
	for _, in := range installs {
		t.Logf("installation %d on %s (%s), repository_selection=%s",
			in.ID, in.Account, in.AccountType, in.RepositorySelection)
		if in.ID <= 0 {
			t.Errorf("installation has no ID: %+v", in)
		}
		// The account is what the dialog shows the operator to confirm they are
		// looking at the right org. An empty one means the nested decode is
		// wrong, which is the specific thing a fake cannot catch.
		if strings.TrimSpace(in.Account) == "" {
			t.Errorf("installation %d has no account name — the nested decode is wrong", in.ID)
		}
		if in.AccountType != "Organization" && in.AccountType != "User" {
			t.Errorf("installation %d has account type %q, want Organization or User", in.ID, in.AccountType)
		}
		if in.AppID != appID {
			t.Errorf("installation %d reports app_id %d, want %d", in.ID, in.AppID, appID)
		}
	}
}

// TestLiveGitHubAppRepositories stores the App the way the UI does — with the
// discovered installation ID — and enumerates what it covers.
func TestLiveGitHubAppRepositories(t *testing.T) {
	appID, keyPEM := liveApp(t)
	t.Setenv(EnvPassphraseKey, "live-github-app-test-passphrase")

	b, err := New(newMemStore())
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	installs, err := b.DiscoverGitHubAppInstallations(ctx, connectionPayload(t, appID, keyPEM))
	if err != nil {
		t.Fatalf("DiscoverGitHubAppInstallations: %v", err)
	}

	stored, err := json.Marshal(map[string]any{
		"app_id":          appID,
		"installation_id": installs[0].ID,
		"private_key":     keyPEM,
	})
	if err != nil {
		t.Fatalf("marshal stored payload: %v", err)
	}
	sec, err := b.Mint(ctx, MintRequest{
		Name:    "live-app",
		Kind:    KindGitHubApp,
		Payload: stored,
		Actor:   "live-test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	repos, err := b.GitHubAppRepositories(ctx, sec.ID)
	if err != nil {
		t.Fatalf("GitHubAppRepositories: %v", err)
	}
	if len(repos) == 0 {
		t.Skip("the installation covers no repositories, so there is nothing to scope a token to")
	}
	for _, r := range repos {
		t.Logf("repository %d %s (private=%t)", r.ID, r.FullName, r.Private)
		if r.ID <= 0 || !strings.Contains(r.FullName, "/") {
			t.Errorf("repository decoded wrong: %+v", r)
		}
	}

	// The payload that matters: a token GitHub itself narrowed to one
	// repository. Minting it here is what proves the scoping request is
	// accepted — a wrong field name would be a 422 rather than a wider token.
	target := repos[0].FullName
	res, err := b.appMinter.mint(ctx, mustParseStored(t, b, sec.ID), Constraints{
		Repos:       []string{target},
		Permissions: []string{"contents:read"},
	})
	if err != nil {
		t.Fatalf("mint scoped installation token for %s: %v", target, err)
	}
	defer b.appMinter.revoke(ctx, defaultGitHubBaseURL, res.token.Token)

	if res.summary != target {
		t.Errorf("token summary = %q, want the single repository %q", res.summary, target)
	}
	if got := res.token.RepositorySelection; got != "" && got != "selected" {
		t.Errorf("repository_selection = %q, want \"selected\" — the token was not narrowed", got)
	}
	if lvl := res.token.Permissions["contents"]; lvl != "read" {
		t.Errorf("contents permission = %q, want read; full set %v", lvl, res.token.Permissions)
	}
	// A read-only grant must not have been handed write anywhere.
	for scope, level := range res.token.Permissions {
		if level == "write" || level == "admin" {
			t.Errorf("contents:read grant yielded %s:%s — the permission narrowing did not apply",
				scope, level)
		}
	}
	t.Logf("minted token expires %s, permissions %v, selection %q",
		res.token.ExpiresAt.UTC().Format(time.RFC3339), res.token.Permissions,
		res.token.RepositorySelection)
}

// mustParseStored re-opens a stored App secret. The live tests need the parsed
// credential to drive the minter directly, which is otherwise only reachable
// through a lease.
func mustParseStored(t *testing.T, b *Broker, secretID string) *AppCredential {
	t.Helper()
	sec, err := b.DescribeSecret(secretID)
	if err != nil {
		t.Fatalf("DescribeSecret: %v", err)
	}
	plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, sec.ID), sec.Envelope())
	if err != nil {
		t.Fatalf("open payload: %v", err)
	}
	defer zero(plaintext)
	cred, err := ParseGitHubApp(plaintext)
	if err != nil {
		t.Fatalf("ParseGitHubApp: %v", err)
	}
	return cred
}
