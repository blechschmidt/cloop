package featureops

import (
	"context"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// TestHubModeGitCarriesItsConfigPairs is the regression test for the first
// live feature pull request on a remote device (Task 20371). In hub mode the
// push authenticates with an Authorization header delivered as a configuration
// pair; runGitConfig rendered the hub environment with it, then handed that to
// runGitWith, which replaced it with the bare hub environment — so the header
// never reached git, every push went out unauthenticated, and GitHub answered
// 403 "Write access to repository not granted".
//
// The renderer is the production one (pkg/executor/featurehub.HubEnv folds the
// pairs in through executor.GitEnv).
func TestHubModeGitCarriesItsConfigPairs(t *testing.T) {
	hermeticGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")
	ctx := WithHubEnv(context.Background(), func(extra ...[2]string) []string {
		return executor.GitEnv(extra...)
	})

	const key = "http.https://github.com/.extraheader"
	const value = "AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46dGVzdA=="
	out, err := runGitConfig(ctx, dir, [][2]string{{key, value}}, "config", "--get-all", key)
	if err != nil {
		t.Fatalf("hub-mode git did not see the configured header: %v", err)
	}
	if out != value {
		t.Fatalf("hub-mode git saw %s = %q, want %q", key, out, value)
	}

	// And it is the pair that carried it: a hub-mode run without one has no
	// header, so a credential never outlives the push it was given for.
	if out, err := runGit(ctx, dir, "config", "--get-all", key); err == nil || out != "" {
		t.Fatalf("a hub-mode run without the pair saw %s = %q (err %v)", key, out, err)
	}
}
