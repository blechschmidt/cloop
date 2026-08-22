package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestImagePolicyRoundTripsFromYAML pins the file format.
//
// The chart, the compose stack and every hand-written config reach the policy
// through these keys. A field renamed in Go without a matching rename here is a
// policy that silently stops applying — the YAML still parses, the section is
// still present, and the hub allows everything.
func TestImagePolicyRoundTripsFromYAML(t *testing.T) {
	const src = `
sandbox:
  image_policy:
    allowed_registries:
      - ghcr.io
      - "*.internal.example"
    allowed_repos:
      - ghcr.io/acme/*
    require_digest: true
    require_signature: true
    cosign_public_keys:
      - /etc/cloop/cosign/acme.pub
    cosign_identities:
      - issuer: https://token.actions.githubusercontent.com
        subject_regexp: ^https://github\.com/acme/.+
    default_registry: ghcr.io
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(src), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	p := cfg.Sandbox.ImagePolicy.Policy()
	if err := p.Validate(); err != nil {
		t.Fatalf("the documented config does not validate: %v", err)
	}
	if got := strings.Join(p.AllowedRegistries, ","); got != "ghcr.io,*.internal.example" {
		t.Errorf("allowed_registries = %q", got)
	}
	if got := strings.Join(p.AllowedRepos, ","); got != "ghcr.io/acme/*" {
		t.Errorf("allowed_repos = %q", got)
	}
	if !p.RequireDigest || !p.RequireSignature {
		t.Errorf("require_digest/%v require_signature/%v — both keys must reach the policy",
			p.RequireDigest, p.RequireSignature)
	}
	if len(p.CosignPublicKeys) != 1 || p.CosignPublicKeys[0] != "/etc/cloop/cosign/acme.pub" {
		t.Errorf("cosign_public_keys = %v", p.CosignPublicKeys)
	}
	if len(p.CosignIdentities) != 1 ||
		p.CosignIdentities[0].Issuer != "https://token.actions.githubusercontent.com" ||
		p.CosignIdentities[0].SubjectRegexp != `^https://github\.com/acme/.+` {
		t.Errorf("cosign_identities = %+v", p.CosignIdentities)
	}
	if p.DefaultRegistry != "ghcr.io" {
		t.Errorf("default_registry = %q", p.DefaultRegistry)
	}

	// And the policy actually bites, so a passing parse cannot be mistaken for
	// a working control.
	if _, err := p.Evaluate("docker.io/library/alpine@sha256:" + strings.Repeat("a", 64)); err == nil {
		t.Error("the parsed policy admits a registry that is not on its allowlist")
	}
}

// TestAbsentSandboxSectionConstrainsNothing: adding this feature must not
// change what an existing config does. Every deployment that upgrades without
// editing its config.yaml has no sandbox section at all.
func TestAbsentSandboxSectionConstrainsNothing(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("provider: anthropic\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	p := cfg.Sandbox.ImagePolicy.Policy()
	if p.Configured() {
		t.Fatal("an absent sandbox section produced a configured policy")
	}
	if _, err := p.Evaluate("anything/at/all:latest"); err != nil {
		t.Fatalf("an unconfigured policy refused an image: %v", err)
	}
	if err := ValidateSandbox(cfg.Sandbox); err != nil {
		t.Fatalf("an absent sandbox section failed validation: %v", err)
	}
}

// TestValidateSandboxNamesTheSection: an operator reading the error has to know
// which key to edit.
func TestValidateSandboxNamesTheSection(t *testing.T) {
	err := ValidateSandbox(SandboxConfig{
		ImagePolicy: ImagePolicyConfig{RequireSignature: true},
	})
	if err == nil {
		t.Fatal("require_signature with nothing to verify against was accepted")
	}
	if !strings.Contains(err.Error(), "sandbox.image_policy") {
		t.Errorf("error = %q, want it to name the config section", err)
	}
}

// TestValidateNumericCoversTheSandboxSection: `cloop config set` and the config
// validator both go through ValidateNumeric, so a section it does not reach is
// one an operator can write a broken version of without being told.
func TestValidateNumericCoversTheSandboxSection(t *testing.T) {
	cfg := &Config{}
	cfg.Sandbox.ImagePolicy.RequireSignature = true
	if err := cfg.ValidateNumeric(); err == nil {
		t.Fatal("ValidateNumeric does not reach the sandbox section")
	}
}

// TestEvalStackConfigParses reads the committed docker-compose config.
//
// It is checked in as documentation and mounted verbatim by the eval stack, so
// a key that drifts out of the Go schema produces a stack that comes up with a
// section the hub ignores — which looks exactly like one it honours.
func TestEvalStackConfigParses(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "eval", "cloop-config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("eval config not present: %v", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("deploy/eval/cloop-config.yaml does not parse: %v", err)
	}
	if err := ValidateSandbox(cfg.Sandbox); err != nil {
		t.Fatalf("deploy/eval/cloop-config.yaml has an invalid image policy: %v", err)
	}
	p := cfg.Sandbox.ImagePolicy.Policy()
	if !p.Configured() {
		t.Error("the eval stack ships no image policy; the hosted profile is meant to show one")
	}
	if !p.RequireDigest {
		t.Error("the eval stack's image policy does not require digests")
	}
}
