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
