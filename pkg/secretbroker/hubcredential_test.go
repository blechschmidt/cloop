package secretbroker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The hub presents a shared env secret as itself — a bare value, or one key
// of several — and refuses to present a personal secret or a secret of
// another kind (Task 20426: an audit sink's token or client key).
func TestHubCredential(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()
	mint := func(req MintRequest) {
		t.Helper()
		if _, err := b.Mint(ctx, req); err != nil {
			t.Fatalf("mint %s: %v", req.Name, err)
		}
	}
	mint(MintRequest{Name: "hec-token", Kind: KindEnv, Payload: []byte("0d4e-token\n"), Actor: "admin"})
	mint(MintRequest{Name: "es", Kind: KindEnv, Payload: []byte(`{"API_KEY":"k1","USER":"u"}`), Actor: "admin"})
	mint(MintRequest{Name: "mine", Kind: KindEnv, Payload: []byte("personal"), Actor: "alice@corp",
		Owner: "alice@corp", Personal: true})
	mint(MintRequest{Name: "pat", Kind: KindGitHubPAT, Payload: []byte("ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"), Actor: "admin"})

	if got, err := b.HubCredential("hec-token"); err != nil || string(got) != "0d4e-token" {
		t.Errorf("bare value = %q, %v", got, err)
	}
	if got, err := b.HubCredential("es#API_KEY"); err != nil || string(got) != "k1" {
		t.Errorf("keyed value = %q, %v", got, err)
	}
	for ref, want := range map[string]error{
		"es":           ErrInvalidSecret,  // two values and none named
		"es#MISSING":   ErrSecretNotFound, // a key it does not hold
		"mine":         ErrNotOwner,       // a person's, not the organisation's
		"pat":          ErrInvalidKind,    // not an env secret
		"no-such-name": ErrSecretNotFound,
	} {
		if _, err := b.HubCredential(ref); !errors.Is(err, want) {
			t.Errorf("HubCredential(%q) = %v, want %v", ref, err, want)
		}
	}
}

// TestHubRegistryConfig: the registry login a Kubernetes executor resolves
// image tags with (Task 20457) is opened only from a shared registry secret in
// the Docker configuration form — the form that names the registry each login
// is for — by name or ID, and the bare user:password form is refused without
// echoing it.
func TestHubRegistryConfig(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()
	config := `{"auths":{"ghcr.io":{"username":"robot","password":"ghcr-robot-pw"}}}`
	sec, err := b.Mint(ctx, MintRequest{Name: "ghcr-robot", Kind: KindRegistry, Payload: []byte(config), Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []MintRequest{
		{Name: "bare", Kind: KindRegistry, Payload: []byte("robot:bare-registry-pw"), Actor: "admin"},
		{Name: "mine", Kind: KindRegistry, Payload: []byte(config), Actor: "alice@corp", Owner: "alice@corp", Personal: true},
		{Name: "env", Kind: KindEnv, Payload: []byte(config), Actor: "admin"},
	} {
		if _, err := b.Mint(ctx, req); err != nil {
			t.Fatalf("mint %s: %v", req.Name, err)
		}
	}

	for _, ref := range []string{"ghcr-robot", sec.ID, " ghcr-robot "} {
		if got, err := b.HubRegistryConfig(ref); err != nil || string(got) != config {
			t.Errorf("HubRegistryConfig(%q) = %q, %v", ref, got, err)
		}
	}
	for ref, want := range map[string]error{
		"bare":         ErrInvalidSecret, // names no registry
		"mine":         ErrNotOwner,      // a person's, not the organisation's
		"env":          ErrInvalidKind,   // not a registry secret
		"no-such-name": ErrSecretNotFound,
	} {
		_, err := b.HubRegistryConfig(ref)
		if !errors.Is(err, want) {
			t.Errorf("HubRegistryConfig(%q) = %v, want %v", ref, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), "bare-registry-pw") || strings.Contains(err.Error(), "ghcr-robot-pw")) {
			t.Errorf("HubRegistryConfig(%q) quotes the secret: %v", ref, err)
		}
	}
}

// TestSourceCredential: a knowledge source signs in with what its scope allows
// (Task 20467) — an organisation source with a shared env secret, a personal
// source only with its own owner's env secret — and the check answers the same
// without opening anything.
func TestSourceCredential(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()
	mint := func(req MintRequest) {
		t.Helper()
		if _, err := b.Mint(ctx, req); err != nil {
			t.Fatalf("mint %s: %v", req.Name, err)
		}
	}
	mint(MintRequest{Name: "wiki-bot", Kind: KindEnv, Payload: []byte("org-token\n"), Actor: "admin"})
	mint(MintRequest{Name: "atlassian", Kind: KindEnv, Payload: []byte(`{"TOKEN":"t1","OTHER":"o"}`), Actor: "admin"})
	mint(MintRequest{Name: "alice-wiki", Kind: KindEnv, Payload: []byte("alice-token"), Actor: "alice@corp",
		Owner: "alice@corp", Personal: true})
	mint(MintRequest{Name: "bob-wiki", Kind: KindEnv, Payload: []byte("bob-token"), Actor: "bob@corp",
		Owner: "bob@corp", Personal: true})
	mint(MintRequest{Name: "pat", Kind: KindGitHubPAT, Payload: []byte("ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"), Actor: "admin"})

	for _, tc := range []struct {
		ref, owner, want string
	}{
		{"wiki-bot", "", "org-token"},
		{"atlassian#TOKEN", "", "t1"},
		{"alice-wiki", "alice@corp", "alice-token"},
		{"alice-wiki", "Alice@Corp", "alice-token"}, // owner keys fold their email
	} {
		got, err := b.SourceCredential(tc.ref, tc.owner)
		if err != nil || string(got) != tc.want {
			t.Errorf("SourceCredential(%q, %q) = %q, %v; want %q", tc.ref, tc.owner, got, err, tc.want)
		}
		if err := b.CheckSourceCredential(tc.ref, tc.owner); err != nil {
			t.Errorf("CheckSourceCredential(%q, %q) = %v", tc.ref, tc.owner, err)
		}
	}
	for _, tc := range []struct {
		ref, owner string
		want       error
	}{
		{"alice-wiki", "", ErrNotOwner},               // an org source never reads with a person's secret
		{"wiki-bot", "alice@corp", ErrNotOwner},       // a personal source never reads with the organisation's
		{"bob-wiki", "alice@corp", ErrSecretNotFound}, // nor with another person's — whose existence it is not told
		{"pat", "", ErrInvalidKind},
		{"atlassian", "", ErrInvalidSecret}, // two values and none named
		{"atlassian#", "", ErrInvalidSecret},
		{"", "", ErrInvalidSecret},
		{"missing", "", ErrSecretNotFound},
	} {
		if _, err := b.SourceCredential(tc.ref, tc.owner); !errors.Is(err, tc.want) {
			t.Errorf("SourceCredential(%q, %q) = %v, want %v", tc.ref, tc.owner, err, tc.want)
		}
		// The check opens nothing, so the ambiguous "atlassian" is a matter
		// for the open: everything else is refused alike.
		if tc.ref == "atlassian" {
			continue
		}
		if err := b.CheckSourceCredential(tc.ref, tc.owner); !errors.Is(err, tc.want) {
			t.Errorf("CheckSourceCredential(%q, %q) = %v, want %v", tc.ref, tc.owner, err, tc.want)
		}
	}
	if err := b.CheckSourceCredential("bob-wiki", "alice@corp"); err == nil || strings.Contains(err.Error(), "bob@corp") {
		t.Errorf("refusing another person's secret named its owner: %v", err)
	}
}
