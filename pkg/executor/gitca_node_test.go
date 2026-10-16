package executor

import (
	"strings"
	"testing"
)

// TestGitCAForNodeHoldsTheHubCAAlone: Node trusts NODE_EXTRA_CA_CERTS for
// every host the harness reaches (Task 20435), so a bundle asking for Node
// holds exactly one CA certificate, and a driver names it only when asked.
func TestGitCAForNodeHoldsTheHubCAAlone(t *testing.T) {
	caPEM, _ := testCA(t, true)
	otherPEM, _ := testCA(t, true)
	urls := []string{"https://hub.internal:8443/"}
	one := &GitCA{URLs: urls, PEM: caPEM, Node: true}
	if err := one.Validate(); err != nil {
		t.Fatalf("one CA for Node: %v", err)
	}
	two := &GitCA{URLs: urls, PEM: append(append([]byte(nil), caPEM...), otherPEM...), Node: true}
	if err := two.Validate(); err == nil {
		t.Fatal("a Node bundle of two CAs was accepted")
	}
	if err := (&GitCA{URLs: urls, PEM: two.PEM}).Validate(); err != nil {
		t.Fatalf("git alone may still take two: %v", err)
	}
	if got := one.NodeEnv("/etc/cloop/hub-ca/ca.crt"); len(got) != 1 || got[0] != "NODE_EXTRA_CA_CERTS=/etc/cloop/hub-ca/ca.crt" {
		t.Fatalf("NodeEnv = %v", got)
	}
	if got := (&GitCA{URLs: urls, PEM: caPEM}).NodeEnv("/x"); got != nil {
		t.Fatalf("a bundle that did not ask for Node set %v", got)
	}
	if c := one.Clone(); !c.Node {
		t.Fatal("Clone dropped Node")
	}
	// A workload whose harness talks to the relay needs the bundle even when
	// nothing it does is git.
	spec := Spec{Argv: []string{"true"}, GitCA: one}
	if !spec.NeedsGitCA("") {
		t.Fatal("a Node bundle was judged unneeded")
	}
	spec.GitCA = &GitCA{URLs: urls, PEM: caPEM}
	if spec.NeedsGitCA("") {
		t.Fatal("a git-only bundle with no git to do was judged needed")
	}
	if strings.Contains(NodeCAEnvKey, "=") {
		t.Fatal("bad key")
	}
}
