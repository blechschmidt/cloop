package statedb

// The API token's mint policy and approval columns (Task 20422).

import (
	"errors"
	"testing"
	"time"
)

// TestAPITokenMintPolicyMigrationIsAdditive: 0071 is applied to the control
// plane by whichever hub is newer, and the older one sharing it keeps opening
// it — and keeps minting, its rows recorded with an empty minted_under
// (unknown).
func TestAPITokenMintPolicyMigrationIsAdditive(t *testing.T) {
	embedded, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range embedded {
		if m.Version == 71 {
			if got := classifyMigration(m.SQL); got != CompatAdditive {
				t.Fatalf("migration %s classifies as %q, want additive", m.Name, got)
			}
			return
		}
	}
	t.Fatal("migration 0071 is missing")
}

// TestAPITokenRoundTripsItsMintPolicyAndApproval: what governed the mint and
// the approval come back as written; a token written without them — as an
// older hub writes one — reads back unknown and unapproved.
func TestAPITokenRoundTripsItsMintPolicyAndApproval(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	if err := db.PutAPIToken(APITokenRow{ID: "aaaa", Name: "ci", Hash: "h", Prefix: "cloop_pat_aaaa",
		Roles: []string{"admin"}, CreatedAt: at, MintedUnder: "no_policy"}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutAPIToken(APITokenRow{ID: "bbbb", Name: "old", Hash: "h", Prefix: "cloop_pat_bbbb",
		Roles: []string{"viewer"}, CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetAPIToken("aaaa")
	if err != nil {
		t.Fatal(err)
	}
	if got.MintedUnder != "no_policy" || !got.ApprovedAt.IsZero() || got.ApprovedBy != "" {
		t.Fatalf("read back %q approved %v by %q", got.MintedUnder, got.ApprovedAt, got.ApprovedBy)
	}
	old, err := db.GetAPIToken("bbbb")
	if err != nil {
		t.Fatal(err)
	}
	if old.MintedUnder != "" || !old.ApprovedAt.IsZero() {
		t.Fatalf("a token written without a mint policy read back %q, approved %v", old.MintedUnder, old.ApprovedAt)
	}

	// The first approval is recorded and stands; a second changes nothing.
	ok, err := db.ApproveAPIToken("aaaa", "admin@example.com", at.Add(time.Hour))
	if err != nil || !ok {
		t.Fatalf("approve = %v, %v", ok, err)
	}
	ok, err = db.ApproveAPIToken("aaaa", "mallory@example.com", at.Add(2*time.Hour))
	if err != nil || ok {
		t.Fatalf("a second approval = %v, %v; want false, nil", ok, err)
	}
	rows, err := db.ListAPITokens()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ID == "aaaa" && (r.ApprovedBy != "admin@example.com" || !r.ApprovedAt.Equal(at.Add(time.Hour))) {
			t.Fatalf("listed approval %v by %q", r.ApprovedAt, r.ApprovedBy)
		}
	}

	// A revoked token, or none at all, is not approved.
	if err := db.RevokeAPIToken("bbbb", at); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApproveAPIToken("bbbb", "admin@example.com", at); !errors.Is(err, ErrAPITokenNotFound) {
		t.Fatalf("approving a revoked token: %v, want ErrAPITokenNotFound", err)
	}
	if _, err := db.ApproveAPIToken("cccc", "admin@example.com", at); !errors.Is(err, ErrAPITokenNotFound) {
		t.Fatalf("approving an unknown token: %v, want ErrAPITokenNotFound", err)
	}
}
