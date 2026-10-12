package ui

// Every hub member sweeps the Claude homes of identities the control plane
// denies out of its own tree (Task 20422).

import (
	"context"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestClaudeSweep_AMemberTheOffboardingMissedRemovesTheHomeAsItStarts is the
// gap: an offboarding served by one member reaches only the copies it can, and
// a member that did not answer — stopped, or a build that does not know the
// request — keeps the departed person's refresh token in its tree. That member
// removes it itself as it starts, logs it out first, and records it; a person
// the control plane still admits, and one under a legal hold, keep theirs.
func TestClaudeSweep_AMemberTheOffboardingMissedRemovesTheHomeAsItStarts(t *testing.T) {
	dir, a, b := clusterPair(t)
	a.srv.claudeHomesRoot, b.srv.claudeHomesRoot = t.TempDir(), t.TempDir()
	homeA := seedClaudeHome(t, a.srv.claudeHomesRoot, "alice@example.com")
	missed := seedClaudeHome(t, b.srv.claudeHomesRoot, "alice@example.com")
	bobs := seedClaudeHome(t, b.srv.claudeHomesRoot, "bob@example.com")
	held := seedClaudeHome(t, b.srv.claudeHomesRoot, "carol@example.com")
	logouts := fakeLogouts(t)

	// The offboarding: alice and carol denied, carol under a legal hold, and
	// only the serving member's copy of alice's home reached.
	denyIdentity(t, dir, map[string]string{"email": "alice@example.com"})
	denyIdentity(t, dir, map[string]string{"email": "carol@example.com"})
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PutLegalHold(statedb.LegalHoldRow{Identity: "carol@example.com", Reason: "LH-17",
		PlacedAt: time.Now(), PlacedBy: "admin@example.com"}, nil); err != nil {
		t.Fatal(err)
	}
	db.Close()
	local := a.srv.offboardLocalClaude()
	local.Root = a.srv.claudeHomesRoot
	if _, _, err := local.Sever([]string{"alice@example.com"}, false, "admin@example.com", "left"); err != nil {
		t.Fatal(err)
	}
	if !dirGone(t, homeA) || dirGone(t, missed) {
		t.Fatal("the fixture: the serving member's copy should be gone and the missed one left")
	}

	// The missed member starts.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.srv.watchDeniedClaudeHomes(ctx); close(done) }()
	waitCluster(t, "the starting member to sweep its tree", func() bool { return dirGone(t, missed) })
	cancel()
	<-done

	if dirGone(t, bobs) {
		t.Fatal("the sweep removed the home of an identity the control plane admits")
	}
	if dirGone(t, held) {
		t.Fatal("the sweep removed a home a legal hold keeps")
	}
	if got := logouts(); len(got) != 2 || got[1] != missed {
		t.Fatalf("logged out %v, want the missed copy logged out before it was removed", got)
	}

	db, err = statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows := scimAuditRows(t, db, "user.claude_home_swept")
	if len(rows) != 1 {
		t.Fatalf("%d user.claude_home_swept rows, want one: %v", len(rows), rows)
	}
	r := rows[0]
	if r["identity"] != "alice@example.com" || r["dir"] != missed || r["removed"] != true ||
		r["logged_out"] != true || r["had_login"] != true || r["trigger"] != "startup" ||
		r["member"] != b.node.ID() || r["_actor"] != "hub:"+b.node.ID() {
		t.Fatalf("the removal was recorded as %v", r)
	}

	// Nothing left to do: a second sweep removes and records nothing.
	if got := b.srv.sweepDeniedClaudeHomes("timer"); len(got) != 0 {
		t.Fatalf("a second sweep did %+v", got)
	}
}

// TestClaudeSweep_AMemberWithoutATreeCreatesNone: the sweep looks, it never
// makes the root it looks under.
func TestClaudeSweep_AMemberWithoutATreeCreatesNone(t *testing.T) {
	dir, _, b := clusterPair(t)
	b.srv.claudeHomesRoot = t.TempDir() + "/never-made"
	denyIdentity(t, dir, map[string]string{"email": "alice@example.com"})
	if got := b.srv.sweepDeniedClaudeHomes("startup"); len(got) != 0 {
		t.Fatalf("swept %+v from a tree that does not exist", got)
	}
	if !dirGone(t, b.srv.claudeHomesRoot) {
		t.Fatal("the sweep created the Claude home root")
	}
}
