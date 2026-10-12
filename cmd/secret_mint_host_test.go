package cmd

// `cloop secret mint --github-host` records a GitHub Enterprise Server PAT's
// host with the token, sealed, so the broker presents it there and nowhere
// else (Task 20423).

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

func TestSecretMintRecordsAGitHubEnterpriseHost(t *testing.T) {
	dir := statedbtest.Dir(t)
	t.Chdir(dir)
	t.Setenv(secretbroker.EnvPassphraseKey, "mint-host-test-passphrase-0123456789")
	origKind, origValue, origHost := mintKindFlag, mintValueFlag, mintGitHubHostFlag
	t.Cleanup(func() {
		mintKindFlag, mintValueFlag, mintGitHubHostFlag = origKind, origValue, origHost
		secretMintCmd.SetContext(nil) //nolint:staticcheck // nil is cobra's "inherit from the parent"
	})
	secretMintCmd.SetContext(context.Background())

	mint := func(name, kind, value, host string) error {
		mintKindFlag, mintValueFlag, mintGitHubHostFlag = kind, value, host
		return secretMintCmd.RunE(secretMintCmd, []string{name})
	}
	if err := mint("ghes-pat", "github_pat", "ghp_enterpriseMintHost0123", "GHES.Example.com"); err != nil {
		t.Fatalf("mint --github-host: %v", err)
	}
	if err := mint("gh-pat", "github_pat", "ghp_publicMintHost0123", ""); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := mint("bad", "env", "x", "ghes.example.com"); err == nil || !strings.Contains(err.Error(), "github_pat") {
		t.Fatalf("--github-host on an env secret = %v, want a refusal", err)
	}
	if err := mint("bad2", "github_pat", "ghp_x0123456789", "https://ghes.example.com/api/v3"); err == nil {
		t.Fatal("--github-host accepted a URL rather than a host")
	}

	broker, closeFn, err := openBroker()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	for name, want := range map[string]string{"ghes-pat": "ghes.example.com", "gh-pat": "github.com"} {
		s, err := broker.DescribeSecret(name)
		if err != nil {
			t.Fatal(err)
		}
		if got, known := secretbroker.SecretForgeHost(s); !known || got != want {
			t.Errorf("%s is bound to %q (known %v), want %q", name, got, known, want)
		}
	}
}
