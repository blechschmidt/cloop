package cmd

// Covers the incident-response commands (Task 20248), and above all the lease
// rule they differ on.
//
// The rule is a claim about how a running hub reads each table, and it is not
// checkable by reading the code of these commands alone — so it is asserted
// here as behaviour: a live lease stops a quota write and does not stop a
// demotion. Getting it backwards in either direction is a real failure. Refuse
// too much and the emergency lever does not work during an emergency, which is
// the only time it is used; refuse too little and a write vanishes into a
// running hub's memory while reporting success.

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/rolestore"
	"github.com/blechschmidt/cloop/pkg/sessionstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// hubDir returns a directory holding an initialized control plane.
func hubDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// runHubSub executes a subcommand through a fresh command carrying the same
// RunE, so flag values do not leak between invocations of the package-level
// command. Same reason as runBootstrap in hub_bootstrap_test.go.
func runHubSub(t *testing.T, src *cobra.Command, register func(*cobra.Command), args ...string) error {
	t.Helper()
	c := &cobra.Command{
		Use:           src.Use,
		Args:          src.Args,
		RunE:          src.RunE,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	register(c)
	c.SetOut(io.Discard)
	c.SetErr(io.Discard)
	c.SetArgs(args)
	return c.Execute()
}

func roleRevoke(t *testing.T, args ...string) error {
	t.Helper()
	return runHubSub(t, hubRoleRevokeCmd,
		func(c *cobra.Command) { registerHubRoleFlags(c, "revoke") }, args...)
}

func quotaSet(t *testing.T, args ...string) error {
	t.Helper()
	return runHubSub(t, hubQuotaSetCmd,
		func(c *cobra.Command) { registerHubQuotaFlags(c, "set") }, args...)
}

func sessionRevoke(t *testing.T, args ...string) error {
	t.Helper()
	return runHubSub(t, hubSessionRevokeCmd,
		func(c *cobra.Command) { registerHubSessionFlags(c, "revoke") }, args...)
}

// holdLease takes the control-plane lease the way a running hub does.
func holdLease(t *testing.T, dir string) {
	t.Helper()
	lease, err := hublease.Acquire(hublease.Options{
		DBPath:  state.DBPath(dir),
		Address: ":8080",
		Version: "test",
	})
	if err != nil {
		t.Fatalf("hublease.Acquire: %v", err)
	}
	t.Cleanup(func() { _ = lease.Release() })
}

// TestQuotaWriteRefusesWhileAHubHoldsTheLease. The enforcer loads overrides
// once at startup, so a write behind a live hub is invisible to it and is
// overwritten by the next edit from the panel. Refusing is the honest answer.
func TestQuotaWriteRefusesWhileAHubHoldsTheLease(t *testing.T) {
	dir := hubDir(t)
	holdLease(t, dir)

	err := quotaSet(t, "alice@example.com", "--workdir", dir,
		"--limit", "daily_cost_usd=5", "--reason", "runaway plan")
	if err == nil {
		t.Fatal("quota set succeeded while a hub held the lease — the write would " +
			"neither take effect nor survive the hub's next edit")
	}
	// The refusal has to be actionable, not merely correct: an operator whose
	// tenant is burning budget needs to be told what to use instead.
	for _, want := range []string{"lease", "/api/quotas"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}

	// And nothing was written.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListQuotaOverrides()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("%d quota overrides written despite the refusal", len(rows))
	}
}

// TestRoleRevokeWorksWhileAHubHoldsTheLease is the other half of the rule, and
// the more important one. Role bindings are re-read on a TTL, so a demotion
// converges on a running hub — which is the only state a hub is in when
// somebody needs to demote an account.
func TestRoleRevokeWorksWhileAHubHoldsTheLease(t *testing.T) {
	dir := hubDir(t)
	holdLease(t, dir)

	if err := roleRevoke(t, "email", "alice@example.com",
		"--workdir", dir, "--reason", "credential compromise INC-4412"); err != nil {
		t.Fatalf("role revoke refused while a hub was running: %v\n"+
			"an emergency demotion that only works on a stopped hub is not one", err)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListRoleBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d role bindings, want 1", len(rows))
	}
	if rows[0].Effect != statedb.RoleEffectDeny || rows[0].Value != "alice@example.com" {
		t.Errorf("stored %+v, want a deny naming alice@example.com", rows[0])
	}
	if rows[0].Reason == "" || rows[0].CreatedBy == "" {
		t.Errorf("stored binding has no reason or actor: %+v", rows[0])
	}
}

// TestSessionRevokeWorksWhileAHubHoldsTheLease: `session revoke` exists for
// the case where the listener is wedged, and a wedged listener is a hub that
// is still holding its lease.
func TestSessionRevokeWorksWhileAHubHoldsTheLease(t *testing.T) {
	dir := hubDir(t)
	holdLease(t, dir)

	// No sessions exist, so the command refuses — but it must refuse for that
	// reason and not because of the lease.
	err := sessionRevoke(t, "--workdir", dir, "--all", "--reason", "IdP secret rotation")
	if err == nil {
		t.Fatal("revoking with no sessions reported success")
	}
	if strings.Contains(err.Error(), "lease") {
		t.Errorf("session revoke refused on the lease: %v\n"+
			"it is the command for the case where the hub is up but not serving", err)
	}
	if !strings.Contains(err.Error(), "no sessions match") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestMutationsRequireAReason. These rows are read back during incident
// review, and one that says an administrator was demoted without saying why is
// a question somebody has to answer from memory weeks later.
func TestMutationsRequireAReason(t *testing.T) {
	dir := hubDir(t)
	for _, tc := range []struct {
		name string
		run  func(...string) error
		args []string
	}{
		{"role revoke", func(a ...string) error { return roleRevoke(t, a...) },
			[]string{"email", "alice@example.com", "--workdir", dir}},
		{"quota set", func(a ...string) error { return quotaSet(t, a...) },
			[]string{"alice@example.com", "--workdir", dir, "--limit", "max_projects=1"}},
		{"session revoke", func(a ...string) error { return sessionRevoke(t, a...) },
			[]string{"--workdir", dir, "--all"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(tc.args...); err == nil || !strings.Contains(err.Error(), "--reason") {
				t.Errorf("ran without --reason: %v", err)
			}
			// A reason that says nothing is not a reason.
			if err := tc.run(append(tc.args, "--reason", "x")...); err == nil ||
				!strings.Contains(err.Error(), "--reason") {
				t.Errorf("accepted a one-character reason: %v", err)
			}
		})
	}
}

// TestRoleRevokeAuditsBeforeMutating. An unrecorded change to who may act is
// an authority change with nothing to review; re-running the command is cheap,
// so the trail is written first and a failure aborts before anything changes.
func TestRoleRevokeAuditsBeforeMutating(t *testing.T) {
	dir := hubDir(t)
	if err := roleRevoke(t, "email", "alice@example.com",
		"--workdir", dir, "--reason", "credential compromise INC-4412"); err != nil {
		t.Fatalf("role revoke: %v", err)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "role_binding.denied"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d audit rows for the demotion, want 1", len(rows))
	}
	ev := rows[0]
	if !strings.HasPrefix(ev.Actor, "cli:") {
		t.Errorf("actor = %q, want a cli: prefix naming the OS user", ev.Actor)
	}
	for _, want := range []string{"INC-4412", "alice@example.com", "os_user", "\"via\":\"cli\""} {
		if !strings.Contains(ev.Payload, want) {
			t.Errorf("audit payload is missing %q: %s", want, ev.Payload)
		}
	}

	// The chain must still verify: these rows are appended through the same
	// hash-chained path as everything else, not around it.
	report, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !report.OK {
		t.Errorf("audit chain broken after a CLI mutation at id %d: %s",
			report.BreakAtID, report.Reason)
	}
}

// TestRoleDeleteRestoresAndIsAudited covers the way back. Reinstating an
// administrator is at least as reviewable an act as demoting one.
func TestRoleDeleteRestoresAndIsAudited(t *testing.T) {
	dir := hubDir(t)
	if err := roleRevoke(t, "email", "alice@example.com",
		"--workdir", dir, "--reason", "credential compromise INC-4412"); err != nil {
		t.Fatalf("role revoke: %v", err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListRoleBindings()
	if err != nil || len(rows) != 1 {
		t.Fatalf("ListRoleBindings: %v (%d rows)", err, len(rows))
	}
	id := rows[0].ID
	_ = db.Close()

	del := func(args ...string) error {
		return runHubSub(t, hubRoleDeleteCmd,
			func(c *cobra.Command) { registerHubRoleFlags(c, "delete") }, args...)
	}
	if err := del(id, "--workdir", dir, "--reason", "investigation closed, account clean"); err != nil {
		t.Fatalf("role delete: %v", err)
	}

	db, err = statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if rows, err := db.ListRoleBindings(); err != nil || len(rows) != 0 {
		t.Errorf("after delete: %d bindings (err %v), want 0", len(rows), err)
	}
	if evs, _, err := db.ListAuditEvents(statedb.AuditFilter{
		EventType: "role_binding.deleted"}); err != nil || len(evs) != 1 {
		t.Errorf("%d audit rows for the deletion (err %v), want 1", len(evs), err)
	}

	// A mistyped id must be an error naming the problem, not a silent success.
	err = del("rb_doesnotexist", "--workdir", dir, "--reason", "typo under pressure")
	if err == nil || !strings.Contains(err.Error(), "rb_doesnotexist") {
		t.Errorf("deleting a missing binding returned %v", err)
	}
}

// TestUnusableBindingIsRejected. A binding that matches nothing is at its worst
// as a deny: the command reports success and withdraws nothing, and the
// operator moves on believing the account is contained.
func TestUnusableBindingIsRejected(t *testing.T) {
	dir := hubDir(t)
	for _, args := range [][]string{
		{"department", "engineering", "--workdir", dir, "--reason", "unknown claim kind"},
		{"email", "  ", "--workdir", dir, "--reason", "empty value"},
	} {
		if err := roleRevoke(t, args...); err == nil {
			t.Errorf("accepted an unusable binding: %v", args)
		}
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if rows, _ := db.ListRoleBindings(); len(rows) != 0 {
		t.Errorf("%d bindings stored despite rejection", len(rows))
	}
}

// TestGrantAgainstALiveDenyIsReportedAsInert.
//
// A row's identity includes its effect, so a grant and a deny for the same
// claim and scope coexist. The deny still wins, which is correct — but `grant`
// is the natural inverse an on-call engineer reaches for to undo a demotion,
// and against a live deny it does nothing. A green "Granted admin" there would
// send somebody away believing an account was restored.
func TestGrantAgainstALiveDenyIsReportedAsInert(t *testing.T) {
	dir := hubDir(t)
	if err := roleRevoke(t, "email", "alice@example.com",
		"--workdir", dir, "--reason", "credential compromise INC-4412"); err != nil {
		t.Fatalf("role revoke: %v", err)
	}

	out, runErr := captureStdout(t, func() error {
		return runHubSub(t, hubRoleGrantCmd,
			func(c *cobra.Command) { registerHubRoleFlags(c, "grant") },
			"email", "alice@example.com", "--role", "admin",
			"--workdir", dir, "--reason", "trying to undo the demotion")
	})
	if runErr != nil {
		t.Fatalf("role grant: %v", runErr)
	}
	if !strings.Contains(out, "INERT") {
		t.Errorf("granting over a live deny did not say the grant is inert:\n%s", out)
	}
	if !strings.Contains(out, "role delete") {
		t.Errorf("the output does not name the command that actually restores access:\n%s", out)
	}

	// Both rows exist, and the deny is still the one that decides.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListRoleBindings()
	if err != nil || len(rows) != 2 {
		t.Fatalf("ListRoleBindings: %v (%d rows, want 2)", err, len(rows))
	}
	store, err := rolestore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := authz.New(authz.Config{Runtime: store})
	if err != nil {
		t.Fatal(err)
	}
	if b := resolver.DeniedBy(&authz.Subject{Email: "alice@example.com"}, authz.Scope{}); b == nil {
		t.Error("the grant overrode the deny — precedence is broken, not just the message")
	}
}

// TestSessionRevokeDoesNotAuditWhatItDidNotRevoke.
//
// The batch loop deletes first and audits second, so the trail can never
// assert a revocation that did not happen. A session that ended between the
// listing and the delete — swept by the janitor, or ended from the panel — is
// not this operator's action and must not be recorded as one.
func TestSessionRevokeDoesNotAuditWhatItDidNotRevoke(t *testing.T) {
	dir := hubDir(t)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	store, err := sessionstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, id := range []string{"sess-a", "sess-b"} {
		if err := store.Put(oidcauth.SessionRecord{
			ID:        id,
			Identity:  oidcauth.Identity{Sub: "sub-alice", Email: "alice@example.com"},
			IssuedAt:  now,
			LastSeen:  now,
			ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	// One ends behind the command's back, after it would have listed.
	if _, err := store.Delete("sess-b"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	if err := sessionRevoke(t, "--workdir", dir, "--identity", "alice@example.com",
		"--reason", "credential compromise INC-4412"); err != nil {
		t.Fatalf("session revoke: %v", err)
	}

	db, err = statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "session.revoked"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d session.revoked rows, want 1 — the trail records a revocation that "+
			"did not happen, and a reviewer who believes it stops looking", len(rows))
	}
	if !strings.Contains(rows[0].Payload, "sess-a") && rows[0].EntityID != "sess-a" {
		t.Errorf("the recorded revocation is not the session that was actually ended: %+v", rows[0])
	}
}

// TestExplicitZeroQuotaIsNotRenderedAsAbsent. Normalize keeps a zero and the
// enforcer treats any request above a zero ceiling as a breach, so
// `--limit daily_cost_usd=0` is the strictest cap available. Printing it the
// same as "no override" would show a hard freeze as the absence of one, in the
// table an operator reads mid-incident.
func TestExplicitZeroQuotaIsNotRenderedAsAbsent(t *testing.T) {
	if got := quotaCellLabel(map[quota.Resource]float64{quota.ResDailyCostUSD: 0},
		quota.ResDailyCostUSD); got == "-" {
		t.Errorf("an explicit zero ceiling renders as %q, the same as no override", got)
	}
	if got := quotaCellLabel(map[quota.Resource]float64{}, quota.ResDailyCostUSD); got != "-" {
		t.Errorf("an absent ceiling renders as %q, want %q", got, "-")
	}
}

// TestOpenHubDBRefusesToCreate: a mistyped --workdir that silently produced an
// empty database would answer "no sessions" and "no bindings" to somebody
// running an incident, and those are the two answers they would most like to
// believe.
func TestOpenHubDBRefusesToCreate(t *testing.T) {
	empty := t.TempDir()
	if _, _, err := openHubDB(empty); err == nil {
		t.Error("openHubDB created a database in a directory that had none")
	}
	if _, err := os.Stat(state.DBPath(empty)); err == nil {
		t.Error("openHubDB left a database behind after refusing")
	}
}

// TestOperatorActorPrefersThePasswdDatabase: $USER is the caller's to set, and
// an audit record naming whoever the shell felt like claiming to be is worse
// than one naming nobody, because it reads as evidence.
func TestOperatorActorPrefersThePasswdDatabase(t *testing.T) {
	t.Setenv("USER", "totally-not-me")
	t.Setenv("LOGNAME", "totally-not-me")
	if got := operatorActor(); strings.Contains(got, "totally-not-me") {
		t.Errorf("operatorActor() = %q — it trusted $USER", got)
	}

	// SUDO_USER is environment too, so it is reported alongside the real uid
	// rather than in place of it: a record is never ambiguous about which half
	// can be trusted.
	t.Setenv("SUDO_USER", "claimed-human")
	got := operatorActor()
	if !strings.Contains(got, "sudo:claimed-human") {
		t.Errorf("operatorActor() = %q, want the SUDO_USER hint recorded", got)
	}
	if !strings.HasPrefix(got, "cli:") {
		t.Errorf("operatorActor() = %q, want a cli: prefix", got)
	}
	if strings.HasPrefix(got, "cli:claimed-human") {
		t.Errorf("operatorActor() = %q — SUDO_USER replaced the real uid", got)
	}
}

// TestQuotaSetMergesAndValidates: the override is sparse, so capping one
// resource must not silently freeze every other ceiling at whatever the
// identity's group granted on the day of the edit.
func TestQuotaSetMergesAndValidates(t *testing.T) {
	dir := hubDir(t)
	if err := quotaSet(t, "alice@example.com", "--workdir", dir,
		"--limit", "daily_cost_usd=5", "--reason", "runaway plan INC-4413"); err != nil {
		t.Fatalf("quota set: %v", err)
	}
	if err := quotaSet(t, "alice@example.com", "--workdir", dir,
		"--limit", "max_projects=3", "--reason", "also cap projects"); err != nil {
		t.Fatalf("second quota set: %v", err)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListQuotaOverrides()
	if err != nil || len(rows) != 1 {
		t.Fatalf("ListQuotaOverrides: %v (%d rows)", err, len(rows))
	}
	for _, want := range []string{"daily_cost_usd", "max_projects"} {
		if !strings.Contains(rows[0].LimitsJSON, want) {
			t.Errorf("the second edit dropped %s: %s", want, rows[0].LimitsJSON)
		}
	}

	// Nonsense must not reach storage.
	for _, bad := range [][]string{
		{"alice@example.com", "--workdir", dir, "--limit", "nonsense=1", "--reason", "unknown resource"},
		{"alice@example.com", "--workdir", dir, "--limit", "max_projects=-1", "--reason", "negative ceiling"},
		{"alice@example.com", "--workdir", dir, "--limit", "max_projects=abc", "--reason", "not a number"},
	} {
		if err := quotaSet(t, bad...); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

// TestSessionRevokeNeedsExactlyOneSelector. An id, one identity and every
// session differ by two orders of magnitude in blast radius, and the safe one
// is not obviously the one an operator meant — so there is no default.
func TestSessionRevokeNeedsExactlyOneSelector(t *testing.T) {
	dir := hubDir(t)
	for _, args := range [][]string{
		{"--workdir", dir, "--reason", "no selector at all"},
		{"abc123", "--all", "--workdir", dir, "--reason", "an id and everything"},
		{"abc123", "--identity", "a@b.c", "--workdir", dir, "--reason", "an id and an identity"},
	} {
		err := sessionRevoke(t, args...)
		if err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Errorf("args %v gave %v, want a refusal naming the ambiguity", args, err)
		}
	}
}
