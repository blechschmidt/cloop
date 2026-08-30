package cmd

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/provider/claudecode"
)

// TestClaudeCodeCredentialRefresherWired guards the one-line wiring in
// providers.go's init().
//
// pkg/provider/claudecode deliberately does not import pkg/ratelimit — that
// package transitively pulls in the executor, Kubernetes and secret-broker
// trees, which would stop a leaf provider from compiling or being tested on
// its own. The cost of that decoupling is a registration that can be dropped
// without anything failing to build, so assert it here instead.
//
// Losing it degrades the Task 20204 retry quietly: the second attempt would
// still run, but only ever recover a refresh race that some peer process
// happened to win, never a credential this process has to rotate itself.
func TestClaudeCodeCredentialRefresherWired(t *testing.T) {
	if !claudecode.CredentialRefresherWired() {
		t.Fatal("claudecode credential refresher is not wired; " +
			"restore the claudecode.SetCredentialRefresher call in cmd/providers.go init()")
	}
}
