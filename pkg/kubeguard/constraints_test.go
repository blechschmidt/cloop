package kubeguard

// constraints_test.go asserts the invariants that span this package and
// pkg/secretbroker.
//
// The two have to agree about what a verb is and what a namespace pattern
// means, but they cannot share the code: pkg/secretbroker is imported by
// pkg/executor/kubernetes, which this package imports to parse a kubeconfig,
// so the dependency runs one way only. The duplication is deliberate and
// documented at both ends; this file is what keeps it honest.
//
// It lives on this side because this is the side that is allowed to see both.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// TestVerbVocabularyMatchesTheBroker: a verb the broker accepts on a grant
// and this package rejects would be a grant that stores fine and fails at
// lease time, inside someone else's run.
func TestVerbVocabularyMatchesTheBroker(t *testing.T) {
	for _, v := range allVerbs() {
		c := secretbroker.Constraints{Namespaces: []string{"app"}, Verbs: []string{v}}
		if err := c.ValidateFor(secretbroker.KindKubeconfig); err != nil {
			t.Errorf("kubeguard knows verb %q but the broker refuses it: %v", v, err)
		}
	}
	// And the reverse: every verb the broker accepts must validate here.
	for _, v := range allVerbs() {
		p := Policy{Verbs: []string{v}}
		p.Normalize()
		if err := p.Validate(); err != nil {
			t.Errorf("the broker accepts verb %q but kubeguard refuses it: %v", v, err)
		}
	}
	// A verb neither side knows is refused by both.
	c := secretbroker.Constraints{Namespaces: []string{"app"}, Verbs: []string{"frobnicate"}}
	if err := c.ValidateFor(secretbroker.KindKubeconfig); err == nil {
		t.Error("the broker accepted an unknown verb")
	}
}

// TestReadOnlyDefaultMatchesTheBroker: both sides resolve "no verbs named" to
// the same set, so a grant that says nothing and a session minted from it
// agree about what read-only means.
func TestReadOnlyDefaultMatchesTheBroker(t *testing.T) {
	brokerDefault := secretbroker.Constraints{Namespaces: []string{"app"}}.KubeVerbs()
	if got, want := strings.Join(brokerDefault, ","), strings.Join(ReadVerbs, ","); got != want {
		t.Errorf("broker default verbs = %q, kubeguard ReadVerbs = %q", got, want)
	}
	if !(secretbroker.Constraints{Namespaces: []string{"app"}}).KubeReadOnly() {
		t.Error("the broker does not consider a grant with no verbs read-only")
	}
	p := Policy{Verbs: brokerDefault}
	p.Normalize()
	if !p.ReadOnly() {
		t.Error("kubeguard does not consider the broker's default read-only")
	}
}

// TestNamespaceMatchingMatchesTheBroker: the same allowlist string is written
// once on a grant and read in both places. MinimizeKubeconfig uses the
// broker's matcher to decide which context survives; this package's uses the
// same patterns to decide each request. The two disagreeing would produce a
// session whose delivered kubeconfig names a namespace its own policy denies.
func TestNamespaceMatchingMatchesTheBroker(t *testing.T) {
	patterns := [][]string{
		{"app"},
		{"app-*"},
		{"*"},
		{"team-a", "team-b"},
		{"team-?"},
	}
	values := []string{"app", "app-one", "apples", "team-a", "team-ab", "kube-system", ""}

	for _, pats := range patterns {
		c := secretbroker.Constraints{Namespaces: pats}
		p := Policy{Namespaces: pats}
		p.Normalize()
		for _, v := range values {
			want := c.AllowsNamespace(v)
			got := p.AllowsNamespace(v)
			if got != want {
				t.Errorf("patterns %v, value %q: kubeguard=%v broker=%v", pats, v, got, want)
			}
		}
	}
}

// TestBrokerRefusesVerbsOnOtherKinds keeps the constraint where it means
// something: a verb list on a github or env grant would be silently ignored,
// which reads as enforcement that is not happening.
func TestBrokerRefusesVerbsOnOtherKinds(t *testing.T) {
	for _, kind := range []secretbroker.Kind{
		secretbroker.KindGitHubPAT, secretbroker.KindEnv, secretbroker.KindRegistry,
	} {
		c := secretbroker.Constraints{
			Repos: []string{"*"}, Registries: []string{"*"}, Verbs: []string{"get"},
		}
		if err := c.ValidateFor(kind); err == nil {
			t.Errorf("a verb allowlist was accepted on a %s grant", kind)
		}
	}
}
