package cmd

// `cloop hub token static` (Task 20406): retire the static admin token from a
// shell, finding it by what the running hubs report rather than by its value,
// refusing to strand a hub with no other way in, and announcing it on the bus.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/statictoken"
)

// reportHeld records that a running hub holds the token with value.
func reportHeld(t *testing.T, dir, value string, sso bool, usedAt time.Time) string {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fp := statictoken.Fingerprint(value)
	if err := db.ReportStaticTokenUse([]statedb.StaticTokenUseReport{{
		Fingerprint: fp, At: time.Now(), Held: true, HeldBy: "member-1", SSO: sso,
		UsedAt: usedAt, UsedIP: "203.0.113.7",
	}}); err != nil {
		t.Fatal(err)
	}
	return fp
}

func mintCLIAdmin(t *testing.T, dir string) {
	t.Helper()
	mgr, closer, err := openHubTokenManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if _, err := mgr.Mint(apitoken.MintOptions{Name: "break-glass", Roles: []string{"admin"}, CreatedBy: "root"}); err != nil {
		t.Fatal(err)
	}
}

func staticRetire(t *testing.T, args ...string) error {
	t.Helper()
	return runHubSub(t, hubTokenStaticRetireCmd,
		func(c *cobra.Command) { registerHubTokenStaticFlags(c, "retire") }, args...)
}

// retiredRow returns the retirement of fp, if any.
func retiredRow(t *testing.T, dir, fp string) (statedb.RetiredStaticTokenRow, bool) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListRetiredStaticTokens()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Fingerprint == fp {
			return r, true
		}
	}
	return statedb.RetiredStaticTokenRow{}, false
}

// TestStaticTokenRetireFindsTheHeldTokenAndAnnouncesIt: with nothing but the
// database — no value in the shell — the command retires the token a running
// hub reports holding, records it in the audit trail, and posts the bus notice
// every member acts on.
func TestStaticTokenRetireFindsTheHeldTokenAndAnnouncesIt(t *testing.T) {
	t.Setenv("CLOOP_UI_TOKEN", "")
	dir := hubDir(t)
	fp := reportHeld(t, dir, "the-hubs-static-token", false, time.Now().Add(-time.Hour))
	mintCLIAdmin(t, dir)

	if err := staticRetire(t, "--workdir", dir, "--reason", "leaked in a CI log, INC-4471"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	row, ok := retiredRow(t, dir, fp)
	if !ok || !strings.HasPrefix(row.RetiredBy, "cli:") || row.Reason != "leaked in a CI log, INC-4471" {
		t.Fatalf("retirement = %+v (found %v)", row, ok)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	audit, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionStaticTokenRetired)})
	if err != nil || len(audit) != 1 || audit[0].EntityID != fp {
		t.Fatalf("audit = %+v, %v", audit, err)
	}
	if v := payloadField(t, audit[0].Payload, "via"); v != "cli" {
		t.Errorf("via = %v", v)
	}

	events := announced(t, dir)
	if len(events) != 1 || events[0][0] != "static_token" || payloadField(t, events[0][1], "fingerprint") != fp {
		t.Fatalf("announced %v, want the retired fingerprint", events)
	}

	// Again: nothing to retire, and no second record.
	if err := staticRetire(t, "--workdir", dir, "--reason", "again, to be sure"); err == nil {
		t.Fatal("retiring with only a retired token held succeeded")
	}
	if err := staticRetire(t, "--workdir", dir, "--fingerprint", fp[:12], "--reason", "again, to be sure"); err != nil {
		t.Fatalf("retiring an already-retired token by fingerprint: %v", err)
	}
	if audit, _, _ := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionStaticTokenRetired)}); len(audit) != 1 {
		t.Fatalf("re-retiring wrote %d audit rows, want the first alone", len(audit))
	}
}

// TestStaticTokenRetireRefusesToStrandAHub: a hub with no single sign-on and
// no admin API token would be left with nobody able to administer it.
func TestStaticTokenRetireRefusesToStrandAHub(t *testing.T) {
	t.Setenv("CLOOP_UI_TOKEN", "")
	dir := hubDir(t)
	fp := reportHeld(t, dir, "token-only-hub-token", false, time.Time{})

	err := staticRetire(t, "--workdir", dir, "--reason", "SSO is coming")
	if err == nil || !strings.Contains(err.Error(), "no way in") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("retire on a token-only hub = %v, want the lock-out refusal naming --force", err)
	}
	if _, ok := retiredRow(t, dir, fp); ok {
		t.Fatal("the refused retirement was written")
	}
	if err := staticRetire(t, "--workdir", dir, "--reason", "locking the door first", "--force"); err != nil {
		t.Fatalf("retire --force: %v", err)
	}
	if _, ok := retiredRow(t, dir, fp); !ok {
		t.Fatal("retire --force wrote nothing")
	}

	// A hub that reports single sign-on is not stranded.
	sso := hubDir(t)
	ssoFP := reportHeld(t, sso, "sso-hub-token", true, time.Time{})
	if err := staticRetire(t, "--workdir", sso, "--reason", "SSO works now"); err != nil {
		t.Fatalf("retire on an SSO hub: %v", err)
	}
	if _, ok := retiredRow(t, sso, ssoFP); !ok {
		t.Fatal("the SSO hub's token was not retired")
	}
}

// TestStaticTokenRetirePicksTheToken: the value in this shell names a token no
// hub reported; two held tokens need --fingerprint.
func TestStaticTokenRetirePicksTheToken(t *testing.T) {
	dir := hubDir(t)
	mintCLIAdmin(t, dir)
	t.Setenv("CLOOP_UI_TOKEN", "exported-in-this-shell")
	if err := staticRetire(t, "--workdir", dir, "--reason", "retire the exported one"); err != nil {
		t.Fatalf("retire from the environment: %v", err)
	}
	if _, ok := retiredRow(t, dir, statictoken.Fingerprint("exported-in-this-shell")); !ok {
		t.Fatal("the exported token was not retired")
	}

	t.Setenv("CLOOP_UI_TOKEN", "")
	a := reportHeld(t, dir, "rotation-old", false, time.Time{})
	b := reportHeld(t, dir, "rotation-new", false, time.Time{})
	err := staticRetire(t, "--workdir", dir, "--reason", "rotation")
	if err == nil || !strings.Contains(err.Error(), "--fingerprint") ||
		!strings.Contains(err.Error(), statictoken.Short(a)) || !strings.Contains(err.Error(), statictoken.Short(b)) {
		t.Fatalf("two held tokens = %v, want both named and --fingerprint asked for", err)
	}
	if err := staticRetire(t, "--workdir", dir, "--fingerprint", a[:4], "--reason", "rotation"); err == nil {
		t.Fatal("a 4-character fingerprint was accepted")
	}
	if err := staticRetire(t, "--workdir", dir, "--fingerprint", a[:10], "--reason", "rotation"); err != nil {
		t.Fatalf("retire --fingerprint: %v", err)
	}
	if _, ok := retiredRow(t, dir, a); !ok {
		t.Fatal("the chosen token was not retired")
	}
	if _, ok := retiredRow(t, dir, b); ok {
		t.Fatal("the other token was retired too")
	}
}

// TestStaticTokenStatusJSON: what a script reads — status, where it is held,
// and how long it has gone unused.
func TestStaticTokenStatusJSON(t *testing.T) {
	t.Setenv("CLOOP_UI_TOKEN", "")
	dir := hubDir(t)
	fp := reportHeld(t, dir, "status-token", true, time.Now().Add(-48*time.Hour))

	var buf bytes.Buffer
	c := &cobra.Command{Use: "status", RunE: hubTokenStaticStatusCmd.RunE, SilenceErrors: true, SilenceUsage: true}
	registerHubTokenStaticFlags(c, "status")
	c.SetOut(&buf)
	c.SetArgs([]string{"--workdir", dir, "--json"})
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("status --json printed %q: %v", buf.String(), err)
	}
	if len(got) != 1 || got[0]["fingerprint"] != fp || got[0]["status"] != "accepted" || got[0]["held"] != true ||
		got[0]["last_used_ip"] != "203.0.113.7" {
		t.Fatalf("status --json = %v", got)
	}
	if unused, _ := got[0]["unused_seconds"].(float64); unused < 47*3600 {
		t.Fatalf("unused_seconds = %v, want about two days", got[0]["unused_seconds"])
	}
	if strings.Contains(buf.String(), "status-token") {
		t.Fatal("status printed the token's value")
	}
}
