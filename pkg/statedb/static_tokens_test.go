package statedb

// Tests for the static token tables (Task 20406).

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// staticFP is a well-formed fingerprint for the fixtures.
func staticFP(c byte) string { return strings.Repeat(string(c), 64) }

// TestStaticTokenMigrationIsAdditive: 0064 is applied to the control plane by
// whichever hub is newer, and the older one sharing it must keep opening it.
func TestStaticTokenMigrationIsAdditive(t *testing.T) {
	embedded, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range embedded {
		if m.Version != 64 {
			continue
		}
		if got := classifyMigration(m.SQL); got != CompatAdditive {
			t.Fatalf("migration %s classifies as %q, want additive", m.Name, got)
		}
		return
	}
	t.Fatal("migration 0064 is missing")
}

func TestRetireStaticToken_RecordsOnceWithItsAuditRow(t *testing.T) {
	db := openTestDB(t)
	fp := staticFP('a')
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ev := &AuditEvent{
		Actor: "cli:root", EventType: string(auditaction.ActionStaticTokenRetired),
		EntityType: "static_token", EntityID: fp, Payload: `{"reason":"leaked"}`,
	}
	stored, written, err := db.RetireStaticToken(RetiredStaticTokenRow{
		Fingerprint: fp, RetiredAt: at, RetiredBy: "cli:root", Reason: "leaked",
	}, ev)
	if err != nil || !written {
		t.Fatalf("RetireStaticToken = %+v, %v, %v", stored, written, err)
	}
	if !stored.RetiredAt.Equal(at) || stored.RetiredBy != "cli:root" || stored.Reason != "leaked" {
		t.Fatalf("stored %+v", stored)
	}

	// A second retirement keeps the first: the date an auditor reads does not
	// move, and no second audit row claims a second containment.
	again, written, err := db.RetireStaticToken(RetiredStaticTokenRow{
		Fingerprint: fp, RetiredAt: at.Add(time.Hour), RetiredBy: "someone-else", Reason: "again",
	}, &AuditEvent{Actor: "x", EventType: string(auditaction.ActionStaticTokenRetired), EntityType: "static_token", EntityID: fp})
	if err != nil || written {
		t.Fatalf("second RetireStaticToken = %+v, %v, %v; want the first row back, unwritten", again, written, err)
	}
	if !again.RetiredAt.Equal(at) || again.RetiredBy != "cli:root" {
		t.Fatalf("the second retirement moved the first: %+v", again)
	}

	rows, _, err := db.ListAuditEvents(AuditFilter{EventType: string(auditaction.ActionStaticTokenRetired)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].EntityID != fp {
		t.Fatalf("audit rows = %+v, want exactly the first retirement", rows)
	}
	if v, err := db.VerifyAuditChain(); err != nil || v.Status() != AuditChainIntact {
		t.Fatalf("chain after the retirement: %+v, %v", v, err)
	}

	list, err := db.ListRetiredStaticTokens()
	if err != nil || len(list) != 1 || list[0].Fingerprint != fp {
		t.Fatalf("ListRetiredStaticTokens = %+v, %v", list, err)
	}
}

// TestRetireStaticToken_RefusesWhatIsNotAFingerprint: a caller that passed the
// token itself must fail rather than store a credential.
func TestRetireStaticToken_RefusesWhatIsNotAFingerprint(t *testing.T) {
	db := openTestDB(t)
	for _, fp := range []string{"", "s3cret-static-token", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if _, _, err := db.RetireStaticToken(RetiredStaticTokenRow{Fingerprint: fp, RetiredBy: "x"}, nil); !errors.Is(err, ErrStaticTokenFingerprint) {
			t.Errorf("RetireStaticToken(%q) = %v, want ErrStaticTokenFingerprint", fp, err)
		}
	}
	if _, _, err := db.RetireStaticToken(RetiredStaticTokenRow{Fingerprint: staticFP('b')}, nil); err == nil {
		t.Error("a retirement naming nobody was stored")
	}
	if list, _ := db.ListRetiredStaticTokens(); len(list) != 0 {
		t.Fatalf("refused retirements were stored: %+v", list)
	}
	if err := db.ReportStaticTokenUse([]StaticTokenUseReport{{Fingerprint: "s3cret"}}); !errors.Is(err, ErrStaticTokenFingerprint) {
		t.Errorf("ReportStaticTokenUse with a token = %v, want ErrStaticTokenFingerprint", err)
	}
}

// TestReportStaticTokenUse_MergesWhatEachHubSaw: two hub processes holding one
// token each flush what they saw; the latest use wins whoever saw it, refusals
// add up, and a report that saw nothing keeps what was recorded.
func TestReportStaticTokenUse_MergesWhatEachHubSaw(t *testing.T) {
	db := openTestDB(t)
	fp := staticFP('c')
	t0 := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)

	if err := db.ReportStaticTokenUse([]StaticTokenUseReport{{
		Fingerprint: fp, At: t0, Held: true, HeldBy: "member-a", SSO: true,
		UsedAt: t0.Add(-time.Minute), UsedIP: "198.51.100.1",
	}}); err != nil {
		t.Fatal(err)
	}
	// Member B saw a later use; then member A reports again having seen an
	// older one it had not flushed yet, and nothing else.
	if err := db.ReportStaticTokenUse([]StaticTokenUseReport{{
		Fingerprint: fp, At: t0.Add(time.Minute), Held: true, HeldBy: "member-b",
		UsedAt: t0.Add(30 * time.Second), UsedIP: "203.0.113.7",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := db.ReportStaticTokenUse([]StaticTokenUseReport{{
		Fingerprint: fp, At: t0.Add(2 * time.Minute), Held: true, HeldBy: "member-a", SSO: true,
		UsedAt: t0.Add(10 * time.Second), UsedIP: "198.51.100.1",
		Refused: 2, RefusedAt: t0.Add(90 * time.Second), RefusedIP: "192.0.2.9",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := db.ReportStaticTokenUse([]StaticTokenUseReport{{
		Fingerprint: fp, At: t0.Add(3 * time.Minute), Refused: 1, RefusedAt: t0.Add(80 * time.Second), RefusedIP: "192.0.2.1",
	}}); err != nil {
		t.Fatal(err)
	}

	rows, err := db.ListStaticTokenUse()
	if err != nil || len(rows) != 1 {
		t.Fatalf("ListStaticTokenUse = %+v, %v", rows, err)
	}
	r := rows[0]
	if !r.FirstSeenAt.Equal(t0) {
		t.Errorf("first seen %v, want the first report %v", r.FirstSeenAt, t0)
	}
	if !r.HeldAt.Equal(t0.Add(2*time.Minute)) || r.HeldBy != "member-a" || !r.SSO {
		t.Errorf("held %v by %q sso %v, want the last holding report (a refusal-only report holds nothing)", r.HeldAt, r.HeldBy, r.SSO)
	}
	if !r.LastUsedAt.Equal(t0.Add(30*time.Second)) || r.LastUsedIP != "203.0.113.7" {
		t.Errorf("last used %v from %q, want member B's later use", r.LastUsedAt, r.LastUsedIP)
	}
	if r.RefusedCount != 3 || !r.LastRefusedAt.Equal(t0.Add(90*time.Second)) || r.LastRefusedIP != "192.0.2.9" {
		t.Errorf("refused %d, last %v from %q", r.RefusedCount, r.LastRefusedAt, r.LastRefusedIP)
	}
}
