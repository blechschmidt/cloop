package secretbroker

import (
	"errors"
	"strings"
	"testing"
)

// TestAllowsRepo covers the repository allowlist, including the shapes an
// attacker would reach for to widen a glob.
func TestAllowsRepo(t *testing.T) {
	tests := []struct {
		name    string
		repos   []string
		subject string
		want    bool
	}{
		// Straightforward allows.
		{"exact match", []string{"org/tool"}, "org/tool", true},
		{"owner glob", []string{"org/*"}, "org/tool", true},
		{"prefix glob", []string{"org/svc-*"}, "org/svc-api", true},
		{"bare star allows all", []string{"*"}, "anyone/anything", true},
		{"star slash star allows all", []string{"*/*"}, "anyone/anything", true},
		{"second pattern matches", []string{"a/b", "org/*"}, "org/tool", true},
		{"question mark", []string{"org/svc?"}, "org/svc1", true},

		// Case-insensitivity: GitHub names are case-insensitive, so an
		// allowlist written lowercase must cover a mixed-case request and
		// vice versa.
		{"mixed case subject", []string{"org/tool"}, "Org/Tool", true},
		{"mixed case pattern", []string{"Org/Tool"}, "org/tool", true},

		// URL and suffix normalisation.
		{"https url", []string{"org/tool"}, "https://github.com/org/tool", true},
		{"https url with .git", []string{"org/tool"}, "https://github.com/org/tool.git", true},
		{"scp style", []string{"org/tool"}, "git@github.com:org/tool.git", true},
		{"trailing slash", []string{"org/tool"}, "org/tool/", true},

		// Denials — the cases that matter.
		{"different owner", []string{"org/*"}, "other/tool", false},
		{"different repo", []string{"org/tool"}, "org/other", false},
		{"empty allowlist denies", nil, "org/tool", false},
		{"owner glob does not cross slash", []string{"org/*"}, "org/sub/tool", false},
		{"prefix is not a match", []string{"org/tool"}, "org/toolkit", false},
		{"owner prefix is not a match", []string{"org/*"}, "org-evil/tool", false},
		{"suffix confusion", []string{"org/*"}, "evilorg/tool", false},

		// Subject-side wildcards: a caller must not be able to make the
		// matcher answer "yes" by asking about a pattern.
		{"wildcard in subject", []string{"org/tool"}, "org/*", false},
		{"star subject against star pattern", []string{"org/*"}, "*/*", false},

		// Traversal.
		{"dotdot in subject", []string{"org/*"}, "org/../other", false},
		{"dotdot owner", []string{"*"}, "../etc", false},

		// Malformed subjects.
		{"no slash", []string{"*"}, "justaname", false},
		{"empty", []string{"*"}, "", false},
		{"only slash", []string{"*"}, "/", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Constraints{Repos: tc.repos}
			if got := c.AllowsRepo(tc.subject); got != tc.want {
				t.Errorf("AllowsRepo(%q) with %v = %v, want %v",
					tc.subject, tc.repos, got, tc.want)
			}
		})
	}
}

// TestCheckRepoReturnsDenialSentinel proves a denial is distinguishable from
// a malformed request, which is what lets the audit log say why.
func TestCheckRepoReturnsDenialSentinel(t *testing.T) {
	c := Constraints{Repos: []string{"org/*"}}
	err := c.CheckRepo("other/tool")
	if !errors.Is(err, ErrRepoDenied) {
		t.Fatalf("want ErrRepoDenied, got %v", err)
	}
	if !strings.Contains(err.Error(), "org/*") {
		t.Errorf("denial should name the allowlist, got %q", err)
	}
}

// TestAllowsHost covers the egress allowlist, especially the subdomain rule.
func TestAllowsHost(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []string
		subject string
		want    bool
	}{
		{"exact", []string{"api.example.com"}, "api.example.com", true},
		{"with port", []string{"api.example.com"}, "api.example.com:8443", true},
		{"from url", []string{"api.example.com"}, "https://api.example.com/v1/x", true},
		{"trailing dot", []string{"api.example.com"}, "api.example.com.", true},
		{"uppercase", []string{"api.example.com"}, "API.EXAMPLE.COM", true},
		{"wildcard subdomain", []string{"*.example.com"}, "api.example.com", true},
		{"wildcard deep subdomain", []string{"*.example.com"}, "a.b.example.com", true},
		{"star allows all", []string{"*"}, "anything.test", true},

		// The apex is deliberately not covered by "*.example.com": it is
		// usually a different service on a different host.
		{"wildcard excludes apex", []string{"*.example.com"}, "example.com", false},

		// Suffix confusion: notexample.com must not match *.example.com.
		{"suffix confusion", []string{"*.example.com"}, "notexample.com", false},
		{"evil suffix", []string{"*.example.com"}, "evil-example.com", false},

		{"empty allowlist denies", nil, "api.example.com", false},
		{"different host", []string{"api.example.com"}, "evil.test", false},

		// Credential and path smuggling in the subject.
		{"userinfo does not confuse", []string{"api.example.com"}, "https://api.example.com@evil.test/", false},
		{"path does not confuse", []string{"api.example.com"}, "evil.test/api.example.com", false},

		{"empty subject", []string{"*"}, "", false},
		{"wildcard in subject", []string{"*.example.com"}, "*.example.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Constraints{Hosts: tc.hosts}
			if got := c.AllowsHost(tc.subject); got != tc.want {
				t.Errorf("AllowsHost(%q) with %v = %v, want %v",
					tc.subject, tc.hosts, got, tc.want)
			}
		})
	}
}

// TestNormalizeHostRejectsUserinfoHost proves the userinfo strip keeps the
// real host rather than the decorative one.
func TestNormalizeHostRejectsUserinfoHost(t *testing.T) {
	got, err := NormalizeHost("https://api.example.com@evil.test/path")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got != "evil.test" {
		t.Fatalf("userinfo must not become the host: got %q, want %q", got, "evil.test")
	}
}

// TestAllowsNamespace covers the Kubernetes namespace allowlist.
func TestAllowsNamespace(t *testing.T) {
	tests := []struct {
		name       string
		namespaces []string
		subject    string
		want       bool
	}{
		{"exact", []string{"team-a"}, "team-a", true},
		{"glob", []string{"team-*"}, "team-a", true},
		{"star", []string{"*"}, "kube-system", true},
		{"second entry", []string{"team-a", "team-b"}, "team-b", true},

		{"empty denies", nil, "team-a", false},
		{"different namespace", []string{"team-a"}, "kube-system", false},
		{"prefix is not a match", []string{"team-a"}, "team-attack", false},
		{"glob does not cover other prefix", []string{"team-*"}, "other-a", false},
		{"empty subject", []string{"*"}, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Constraints{Namespaces: tc.namespaces}
			if got := c.AllowsNamespace(tc.subject); got != tc.want {
				t.Errorf("AllowsNamespace(%q) with %v = %v, want %v",
					tc.subject, tc.namespaces, got, tc.want)
			}
		})
	}
}

// TestAllowsContextFallsBackToNamespaces documents the rule that a grant
// naming only namespaces permits any context — the namespace pin is then the
// constraint, and requiring both would make the common case unusable.
func TestAllowsContextFallsBackToNamespaces(t *testing.T) {
	nsOnly := Constraints{Namespaces: []string{"team-a"}}
	if !nsOnly.AllowsContext("anything") {
		t.Error("namespace-only grant should permit any context")
	}
	both := Constraints{Namespaces: []string{"team-a"}, Contexts: []string{"prod"}}
	if both.AllowsContext("staging") {
		t.Error("explicit context list must exclude unlisted contexts")
	}
	neither := Constraints{}
	if neither.AllowsContext("prod") {
		t.Error("a grant with no constraints at all must deny")
	}
}

// TestValidateForRequiresGatingConstraints is the fail-closed check: a grant
// that does not bound the dimension its kind is dangerous in cannot be
// created at all.
func TestValidateForRequiresGatingConstraints(t *testing.T) {
	tests := []struct {
		kind    Kind
		c       Constraints
		wantErr bool
	}{
		{KindGitHubPAT, Constraints{}, true},
		{KindGitHubPAT, Constraints{Repos: []string{"org/*"}}, false},
		{KindGitHubApp, Constraints{}, true},
		{KindKubeconfig, Constraints{}, true},
		{KindKubeconfig, Constraints{Namespaces: []string{"team-a"}}, false},
		{KindKubeconfig, Constraints{Contexts: []string{"prod"}}, false},
		{KindEgressProxy, Constraints{}, true},
		{KindEgressProxy, Constraints{Hosts: []string{"*.example.com"}}, false},
		{KindRegistry, Constraints{}, true},
		{KindRegistry, Constraints{Registries: []string{"ghcr.io"}}, false},
		// An env secret's keys are its own scope, so no gate is required.
		{KindEnv, Constraints{}, false},
	}

	for _, tc := range tests {
		t.Run(string(tc.kind), func(t *testing.T) {
			err := tc.c.ValidateFor(tc.kind)
			if tc.wantErr && err == nil {
				t.Errorf("%s with %v should be rejected", tc.kind, tc.c)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("%s with %v should be accepted, got %v", tc.kind, tc.c, err)
			}
		})
	}
}

// TestValidatePatternRejectsShellMetacharacters is the injection boundary:
// these patterns must never be storable, because repo patterns are embedded
// into a generated shell script.
func TestValidatePatternRejectsShellMetacharacters(t *testing.T) {
	hostile := []string{
		"org/'; rm -rf /; echo '",
		"org/$(whoami)",
		"org/`id`",
		"org/a\nb",
		`org/a\b`,
		"org/a;b",
		"org/a|b",
		"org/a&b",
		"org/a>b",
		"org/a\"b",
		"org/../../etc",
		"",
		"   ",
		strings.Repeat("a", 300),
	}
	for _, p := range hostile {
		t.Run(strings.ReplaceAll(p, "\n", "\\n"), func(t *testing.T) {
			c := Constraints{Repos: []string{p}}
			if err := c.ValidateFor(KindGitHubPAT); err == nil {
				t.Errorf("pattern %q must be rejected", p)
			}
		})
	}
}

// TestValidateEnvKeyRejectsEncodingBreakers: a key with '=' or a newline
// would corrupt the K=V environment block every executor parses.
func TestValidateEnvKeyRejectsEncodingBreakers(t *testing.T) {
	for _, k := range []string{"A=B", "A\nB", "A B", "1LEADING", "", "a-b"} {
		if err := validateEnvKey(k); err == nil {
			t.Errorf("env key %q must be rejected", k)
		}
	}
	for _, k := range []string{"GITHUB_TOKEN", "_X", "A1", "lower_ok"} {
		if err := validateEnvKey(k); err != nil {
			t.Errorf("env key %q should be accepted: %v", k, err)
		}
	}
}

// TestAllowsPermission checks the scope-covers-verb rule and that an empty
// set authorises nothing.
func TestAllowsPermission(t *testing.T) {
	c := Constraints{Permissions: []string{"contents", "pull_requests:write"}}
	cases := map[string]bool{
		"contents:read":       true,  // scope entry covers the verb
		"contents:write":      true,  // ... in both directions
		"pull_requests:write": true,  // exact
		"pull_requests:read":  false, // narrower entry does not widen
		"admin:write":         false,
		"":                    false,
	}
	for perm, want := range cases {
		if got := c.AllowsPermission(perm); got != want {
			t.Errorf("AllowsPermission(%q) = %v, want %v", perm, got, want)
		}
	}
	if (Constraints{}).AllowsPermission("contents:read") {
		t.Error("empty permission set must authorise nothing")
	}
}

// TestSummaryHasNoPayload guards the string that goes into audit rows.
func TestSummaryHasNoPayload(t *testing.T) {
	c := Constraints{Repos: []string{"org/*"}, Namespaces: []string{"team-a"}}
	got := c.Summary()
	for _, want := range []string{"repos=org/*", "ns=team-a"} {
		if !strings.Contains(got, want) {
			t.Errorf("Summary() = %q, missing %q", got, want)
		}
	}
	if (Constraints{}).Summary() != "none" {
		t.Errorf("empty constraints should summarise as 'none'")
	}
}
