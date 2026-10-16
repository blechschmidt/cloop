package gitproxy

import (
	"strings"
	"testing"
)

// TestASHA256ZeroIDIsZero: a SHA-256 repository's all-zero object id is the
// zero id, so its delete is a delete — which a policy that allows updates and
// no deletes refuses — and its create a create.
func TestASHA256ZeroIDIsZero(t *testing.T) {
	zero64, one64 := strings.Repeat("0", 64), strings.Repeat("1", 64)
	del := RefUpdate{Old: one64, New: zero64, Ref: "refs/heads/cloop/x"}
	cre := RefUpdate{Old: zero64, New: one64, Ref: "refs/heads/cloop/x"}
	if !del.IsDelete() || del.IsUpdate() || del.Action() != "delete" {
		t.Errorf("a SHA-256 delete reads as %s", del.Action())
	}
	if !cre.IsCreate() || cre.IsUpdate() || cre.Action() != "create" {
		t.Errorf("a SHA-256 create reads as %s", cre.Action())
	}
	if _, err := parseCommand(zero64 + " " + zero64 + " refs/heads/cloop/x"); err == nil {
		t.Error("a SHA-256 zero-to-zero command was accepted")
	}
	pol := WriteBackPolicy()
	if err := pol.Decide(del); err == nil {
		t.Error("a SHA-256 delete was allowed by a policy that allows no delete")
	}
}
