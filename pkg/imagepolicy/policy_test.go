package imagepolicy

import (
	"errors"
	"strings"
	"testing"
)

// hubPolicy is the shape an operator actually writes: one registry, one org,
// digests required. Most cases below vary the reference against it rather than
// varying the policy, because that is the direction an attacker controls.
func hubPolicy() Policy {
	return Policy{
		AllowedRegistries: []string{"ghcr.io"},
		AllowedRepos:      []string{"ghcr.io/acme/*"},
		RequireDigest:     true,
	}
}

// A digest with hex letters in it, so the case-folding cases below actually
// exercise something.
const goodDigest = "sha256:" +
	"1a2b3c4d5e6f78901a2b3c4d5e6f78901a2b3c4d5e6f78901a2b3c4d5e6f7890"

// TestEvaluate is the table. Each case names the property it defends, because a
// case whose failure message is "want false, got true" teaches nothing about
// which door just opened.
func TestEvaluate(t *testing.T) {
	cases := []struct {
		name    string
		policy  Policy
		ref     string
		allowed bool
		rule    string // expected Decision.Rule on a denial
	}{
		// ── registry confusion ────────────────────────────────────────────
		// Both of these contain the allowed registry as a substring and pull
		// from somewhere else. They are the reason matching is on the parsed
		// host and not on the string.
		{
			name:    "allowed registry appearing as a repository path is not a registry",
			policy:  Policy{AllowedRegistries: []string{"docker.io"}},
			ref:     "evil.com/docker.io/foo:1",
			allowed: false, rule: RuleRegistry,
		},
		{
			name:    "allowed registry appearing as a domain prefix is a different host",
			policy:  Policy{AllowedRegistries: []string{"docker.io"}},
			ref:     "docker.io.evil.com/foo:1",
			allowed: false, rule: RuleRegistry,
		},
		{
			name:    "allowed registry as a domain suffix is a different host",
			policy:  Policy{AllowedRegistries: []string{"docker.io"}},
			ref:     "evildocker.io/foo:1",
			allowed: false, rule: RuleRegistry,
		},
		{
			name:    "an allowed registry with a port is not the same host as one without",
			policy:  Policy{AllowedRegistries: []string{"registry.internal"}},
			ref:     "registry.internal:5000/foo:1",
			allowed: false, rule: RuleRegistry,
		},
		{
			name:    "userinfo-looking prefix does not smuggle a host",
			policy:  Policy{AllowedRegistries: []string{"ghcr.io"}},
			ref:     "ghcr.io.attacker.example/acme/tools:1",
			allowed: false, rule: RuleRegistry,
		},

		// ── homographs ────────────────────────────────────────────────────
		// A Cyrillic "о" renders identically to a Latin "o" in every review
		// tool. References are ASCII by grammar, so the whole class is a
		// syntax error rather than a comparison problem.
		{
			name:    "cyrillic lookalike registry",
			policy:  Policy{AllowedRegistries: []string{"docker.io"}},
			ref:     "dоcker.io/library/alpine:3",
			allowed: false, rule: RuleSyntax,
		},
		{
			name:    "fullwidth solidus does not act as a path separator",
			policy:  Policy{AllowedRegistries: []string{"ghcr.io"}},
			ref:     "ghcr.io／acme/tools:1",
			allowed: false, rule: RuleSyntax,
		},
		{
			name:    "zero-width joiner inside an allowed host",
			policy:  Policy{AllowedRegistries: []string{"ghcr.io"}},
			ref:     "ghcr​.io/acme/tools:1",
			allowed: false, rule: RuleSyntax,
		},
		{
			name:    "punycode of a lookalike is a distinct host, not the allowed one",
			policy:  Policy{AllowedRegistries: []string{"docker.io"}},
			ref:     "xn--dcker-jsa.io/library/alpine:3",
			allowed: false, rule: RuleRegistry,
		},

		// ── case folding ──────────────────────────────────────────────────
		{
			name:    "an uppercase host still matches: DNS is case-insensitive",
			policy:  Policy{AllowedRegistries: []string{"ghcr.io"}},
			ref:     "GHCR.IO/acme/tools@" + goodDigest,
			allowed: true,
		},
		{
			name:    "an uppercase allowlist entry matches a lowercase host",
			policy:  Policy{AllowedRegistries: []string{"GHCR.IO"}},
			ref:     "ghcr.io/acme/tools@" + goodDigest,
			allowed: true,
		},

		// ── unqualified references ────────────────────────────────────────
		{
			name:    "a bare name is denied: its registry is host configuration",
			policy:  Policy{AllowedRegistries: []string{"docker.io"}},
			ref:     "alpine:3.20",
			allowed: false, rule: RuleUnqualified,
		},
		{
			name:    "default_registry qualifies a bare name",
			policy:  Policy{AllowedRegistries: []string{"docker.io"}, DefaultRegistry: "docker.io"},
			ref:     "alpine:3.20",
			allowed: true,
		},
		{
			name:    "default_registry does not bypass the allowlist",
			policy:  Policy{AllowedRegistries: []string{"ghcr.io"}, DefaultRegistry: "docker.io"},
			ref:     "alpine:3.20",
			allowed: false, rule: RuleRegistry,
		},

		// ── docker hub aliases ────────────────────────────────────────────
		{
			name:    "index.docker.io is docker.io",
			policy:  Policy{AllowedRegistries: []string{"docker.io"}},
			ref:     "index.docker.io/library/alpine@" + goodDigest,
			allowed: true,
		},
		{
			name:    "an alias does not admit an unrelated host",
			policy:  Policy{AllowedRegistries: []string{"docker.io"}},
			ref:     "registry-1.docker.io.evil.com/library/alpine@" + goodDigest,
			allowed: false, rule: RuleRegistry,
		},

		// ── wildcards ─────────────────────────────────────────────────────
		{
			name:    "*.example.com matches a subdomain",
			policy:  Policy{AllowedRegistries: []string{"*.example.com"}},
			ref:     "registry.example.com/acme/tools@" + goodDigest,
			allowed: true,
		},
		{
			name:    "*.example.com does not match the apex",
			policy:  Policy{AllowedRegistries: []string{"*.example.com"}},
			ref:     "example.com/acme/tools@" + goodDigest,
			allowed: false, rule: RuleRegistry,
		},
		{
			name:    "*.example.com matches at a label boundary only",
			policy:  Policy{AllowedRegistries: []string{"*.example.com"}},
			ref:     "notexample.com/acme/tools@" + goodDigest,
			allowed: false, rule: RuleRegistry,
		},
		{
			name:    "*.example.com is not fooled by a suffix host",
			policy:  Policy{AllowedRegistries: []string{"*.example.com"}},
			ref:     "evil.com/registry.example.com/tools@" + goodDigest,
			allowed: false, rule: RuleRegistry,
		},

		// ── repository allowlist ──────────────────────────────────────────
		{
			name:    "repo prefix matches at a component boundary",
			policy:  hubPolicy(),
			ref:     "ghcr.io/acme/tools@" + goodDigest,
			allowed: true,
		},
		{
			name:    "repo prefix does not match a sibling org with the same prefix",
			policy:  hubPolicy(),
			ref:     "ghcr.io/acme-evil/tools@" + goodDigest,
			allowed: false, rule: RuleRepository,
		},
		{
			name:    "an allowed repo on a different registry is still denied",
			policy:  Policy{AllowedRegistries: []string{"ghcr.io", "quay.io"}, AllowedRepos: []string{"ghcr.io/acme/*"}},
			ref:     "quay.io/acme/tools@" + goodDigest,
			allowed: false, rule: RuleRepository,
		},
		{
			name:    "a registry-less repo entry applies within any allowed registry",
			policy:  Policy{AllowedRegistries: []string{"ghcr.io", "quay.io"}, AllowedRepos: []string{"acme/tools"}},
			ref:     "quay.io/acme/tools@" + goodDigest,
			allowed: true,
		},
		{
			name:    "an exact repo entry does not match a deeper path",
			policy:  Policy{AllowedRegistries: []string{"ghcr.io"}, AllowedRepos: []string{"acme/tools"}},
			ref:     "ghcr.io/acme/tools/inner@" + goodDigest,
			allowed: false, rule: RuleRepository,
		},

		// ── digest requirement ────────────────────────────────────────────
		{
			name:    "a tag is refused when digests are required",
			policy:  hubPolicy(),
			ref:     "ghcr.io/acme/tools:3.12",
			allowed: false, rule: RuleDigest,
		},
		{
			name:    "a digest is accepted",
			policy:  hubPolicy(),
			ref:     "ghcr.io/acme/tools@" + goodDigest,
			allowed: true,
		},
		{
			name: "a tag is accepted when digests are not required",
			policy: Policy{
				AllowedRegistries: []string{"ghcr.io"},
				AllowedRepos:      []string{"ghcr.io/acme/*"},
			},
			ref:     "ghcr.io/acme/tools:3.12",
			allowed: true,
		},
		{
			name:    "a truncated digest is not a digest",
			policy:  hubPolicy(),
			ref:     "ghcr.io/acme/tools@sha256:dead",
			allowed: false, rule: RuleSyntax,
		},
		{
			name:    "an unknown digest algorithm is refused",
			policy:  hubPolicy(),
			ref:     "ghcr.io/acme/tools@md5:d41d8cd98f00b204e9800998ecf8427e",
			allowed: false, rule: RuleSyntax,
		},
		{
			name:    "uppercase hex is refused so one artifact has one spelling",
			policy:  hubPolicy(),
			ref:     "ghcr.io/acme/tools@sha256:" + strings.ToUpper(strings.TrimPrefix(goodDigest, "sha256:")),
			allowed: false, rule: RuleSyntax,
		},

		// ── syntax ────────────────────────────────────────────────────────
		{
			name:    "a leading dash would be read as a flag",
			policy:  hubPolicy(),
			ref:     "-v/etc:/etc",
			allowed: false, rule: RuleSyntax,
		},
		{
			name:    "whitespace splits an argv",
			policy:  hubPolicy(),
			ref:     "ghcr.io/acme/tools:1 --privileged",
			allowed: false, rule: RuleSyntax,
		},
		{
			name:    "an empty tag is refused",
			policy:  hubPolicy(),
			ref:     "ghcr.io/acme/tools:",
			allowed: false, rule: RuleSyntax,
		},
		{
			name:    "an empty reference is refused even with no policy",
			policy:  Policy{},
			ref:     "",
			allowed: false, rule: RuleSyntax,
		},

		// ── unconfigured policy ───────────────────────────────────────────
		{
			name:    "no policy allows any valid reference",
			policy:  Policy{},
			ref:     "evil.com/anything:latest",
			allowed: true,
		},
		{
			name:    "no policy still refuses a bare name? no — it has nothing to decide",
			policy:  Policy{},
			ref:     "alpine:3.20",
			allowed: true,
		},
		{
			name:    "cosign keys alone do not activate the policy",
			policy:  Policy{CosignPublicKeys: []string{"/etc/cloop/cosign.pub"}},
			ref:     "evil.com/anything:latest",
			allowed: true,
		},

		// ── allow-all registries with digest pinning ──────────────────────
		{
			name:    "* allows any registry but require_digest still bites",
			policy:  Policy{AllowedRegistries: []string{"*"}, RequireDigest: true},
			ref:     "quay.io/acme/tools:1",
			allowed: false, rule: RuleDigest,
		},
		{
			name:    "* with a digest is allowed",
			policy:  Policy{AllowedRegistries: []string{"*"}, RequireDigest: true},
			ref:     "quay.io/acme/tools@" + goodDigest,
			allowed: true,
		},
		{
			// An empty allowed_registries is "not constrained", not "deny
			// all": a hub that only wants immutable images must be able to say
			// so without enumerating every registry it tolerates.
			name:    "require_digest alone constrains only mutability",
			policy:  Policy{RequireDigest: true},
			ref:     "quay.io/acme/tools@" + goodDigest,
			allowed: true,
		},
		{
			name:    "require_digest alone still bites a tag",
			policy:  Policy{RequireDigest: true},
			ref:     "quay.io/acme/tools:1",
			allowed: false, rule: RuleDigest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := tc.policy.Evaluate(tc.ref)

			if d.Allowed != tc.allowed {
				t.Fatalf("Evaluate(%q).Allowed = %v, want %v (rule %q, reason %q)",
					tc.ref, d.Allowed, tc.allowed, d.Rule, d.Reason)
			}
			if tc.allowed {
				if err != nil {
					t.Fatalf("Evaluate(%q) allowed but returned %v", tc.ref, err)
				}
				return
			}

			if err == nil {
				t.Fatalf("Evaluate(%q) denied but returned a nil error", tc.ref)
			}
			if !errors.Is(err, ErrDenied) {
				t.Errorf("errors.Is(err, ErrDenied) = false for %q: %v", tc.ref, err)
			}
			var denied *DenyError
			if !errors.As(err, &denied) {
				t.Fatalf("Evaluate(%q) error is %T, want *DenyError", tc.ref, err)
			}
			if d.Rule != tc.rule {
				t.Errorf("Evaluate(%q).Rule = %q, want %q (reason: %s)", tc.ref, d.Rule, tc.rule, d.Reason)
			}
			if denied.Rule != d.Rule {
				t.Errorf("DenyError.Rule = %q but Decision.Rule = %q — they must agree", denied.Rule, d.Rule)
			}
			// A denial the author cannot act on is a support ticket.
			if strings.TrimSpace(denied.Reason) == "" {
				t.Error("DenyError carries no reason")
			}
			if strings.TrimSpace(denied.Remediation) == "" {
				t.Error("DenyError carries no remediation")
			}
			if !strings.Contains(denied.Error(), tc.rule) {
				t.Errorf("DenyError.Error() = %q, want it to name the rule %q", denied.Error(), tc.rule)
			}
		})
	}
}

// TestEvaluateReportsWhatMustHappenNext: a decision is not just a verdict, it
// tells the executor whether to pin and whether to verify. Getting NeedsPin
// wrong on an allowed tag is how a TOCTOU window reopens silently.
func TestEvaluateReportsWhatMustHappenNext(t *testing.T) {
	p := Policy{AllowedRegistries: []string{"ghcr.io"}, RequireSignature: true,
		CosignPublicKeys: []string{"/etc/cloop/cosign.pub"}}

	tag, err := p.Evaluate("ghcr.io/acme/tools:1")
	if err != nil {
		t.Fatal(err)
	}
	if !tag.NeedsPin {
		t.Error("an allowed tag reference must be reported as needing a pin")
	}
	if !tag.NeedsSignature {
		t.Error("require_signature must be reported on the decision")
	}

	pinned, err := p.Evaluate("ghcr.io/acme/tools@" + goodDigest)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.NeedsPin {
		t.Error("a digest reference must not be reported as needing a pin")
	}
}

// TestEvaluateIsPure: the same input yields the same verdict, and nothing about
// the host changes it. This is what makes the UI able to render a decision
// before a run and the executor able to reach the identical one during it.
func TestEvaluateIsPure(t *testing.T) {
	p := hubPolicy()
	const ref = "ghcr.io/acme/tools@" + goodDigest
	first, err1 := p.Evaluate(ref)
	second, err2 := p.Evaluate(ref)
	if (err1 == nil) != (err2 == nil) || first != second {
		t.Fatalf("Evaluate is not deterministic: %+v/%v vs %+v/%v", first, err1, second, err2)
	}
}

// TestNormalizeDoesNotWiden: trimming and case folding must not turn a
// malformed entry into a matching one.
func TestNormalizeDoesNotWiden(t *testing.T) {
	p := Policy{AllowedRegistries: []string{"  GHCR.IO  ", "", "ghcr.io"}}
	n := p.Normalize()
	if len(n.AllowedRegistries) != 1 || n.AllowedRegistries[0] != "ghcr.io" {
		t.Fatalf("Normalize() = %v, want exactly [ghcr.io]", n.AllowedRegistries)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		policy  Policy
		wantErr string // substring; "" means the policy is valid
	}{
		{
			name:   "a realistic hub policy",
			policy: hubPolicy(),
		},
		{
			name:    "a registry entry that is really a repository",
			policy:  Policy{AllowedRegistries: []string{"ghcr.io/acme"}},
			wantErr: "allowed_repos",
		},
		{
			name:    "a mid-label wildcard would match across boundaries",
			policy:  Policy{AllowedRegistries: []string{"ghcr.*.io"}},
			wantErr: "wildcard",
		},
		{
			name:    "a bare-suffix wildcard is not a label boundary",
			policy:  Policy{AllowedRegistries: []string{"*ghcr.io"}},
			wantErr: "wildcard",
		},
		{
			name:    "require_signature with nothing to verify against",
			policy:  Policy{RequireSignature: true},
			wantErr: "nothing to verify against",
		},
		{
			name: "an identity with no subject would trust every workflow at the issuer",
			policy: Policy{
				RequireSignature: true,
				CosignIdentities: []Identity{{Issuer: "https://token.actions.githubusercontent.com"}},
			},
			wantErr: "subject_regexp is required",
		},
		{
			name: "an uncompilable subject pattern",
			policy: Policy{
				RequireSignature: true,
				CosignIdentities: []Identity{{Issuer: "https://x", SubjectRegexp: "([a-z"}},
			},
			wantErr: "does not compile",
		},
		{
			name:    "a mid-path wildcard in a repo entry",
			policy:  Policy{AllowedRepos: []string{"acme/*/tools"}},
			wantErr: "trailing",
		},
		{
			name:    "a default registry with a path",
			policy:  Policy{DefaultRegistry: "docker.io/library"},
			wantErr: "bare registry host",
		},
		{
			// The hole an unconstrained allowed_registries would otherwise
			// leave: this reads as "only acme/tools" and would mean "acme/tools
			// on any registry in the world".
			name:    "an unqualified repo entry with no registry constraint",
			policy:  Policy{AllowedRepos: []string{"acme/tools"}},
			wantErr: "any* registry",
		},
		{
			name:   "the same entry is fine once a registry is constrained",
			policy: Policy{AllowedRegistries: []string{"ghcr.io"}, AllowedRepos: []string{"acme/tools"}},
		},
		{
			name:   "or once the entry itself names the registry",
			policy: Policy{AllowedRepos: []string{"ghcr.io/acme/tools"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestFingerprintTracksEveryRule: the fingerprint keys the verification cache,
// so a field it ignores is a policy change a cached verdict would survive.
func TestFingerprintTracksEveryRule(t *testing.T) {
	base := hubPolicy()
	mutations := map[string]Policy{
		"registry added":  {AllowedRegistries: []string{"ghcr.io", "quay.io"}, AllowedRepos: base.AllowedRepos, RequireDigest: true},
		"repo added":      {AllowedRegistries: base.AllowedRegistries, AllowedRepos: []string{"ghcr.io/acme/*", "ghcr.io/other/*"}, RequireDigest: true},
		"digest dropped":  {AllowedRegistries: base.AllowedRegistries, AllowedRepos: base.AllowedRepos},
		"signature added": {AllowedRegistries: base.AllowedRegistries, AllowedRepos: base.AllowedRepos, RequireDigest: true, RequireSignature: true, CosignPublicKeys: []string{"/k.pub"}},
		"key rotated":     {AllowedRegistries: base.AllowedRegistries, AllowedRepos: base.AllowedRepos, RequireDigest: true, CosignPublicKeys: []string{"/new.pub"}},
		"default set":     {AllowedRegistries: base.AllowedRegistries, AllowedRepos: base.AllowedRepos, RequireDigest: true, DefaultRegistry: "docker.io"},
		"identity added":  {AllowedRegistries: base.AllowedRegistries, AllowedRepos: base.AllowedRepos, RequireDigest: true, CosignIdentities: []Identity{{Issuer: "https://x", SubjectRegexp: ".*"}}},
	}
	want := base.Fingerprint()
	for name, p := range mutations {
		if got := p.Fingerprint(); got == want {
			t.Errorf("%s did not change the fingerprint (%s) — a cached signature verdict "+
				"would survive the policy edit", name, got)
		}
	}
	// And the reverse: a cosmetic difference must not invalidate the cache.
	cosmetic := Policy{AllowedRegistries: []string{"GHCR.IO "}, AllowedRepos: []string{" ghcr.io/acme/* "}, RequireDigest: true}
	if cosmetic.Fingerprint() != want {
		t.Error("whitespace and case changed the fingerprint")
	}
}
