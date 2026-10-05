package secretstore_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// appProcess is a hub process holding leases as holder over db, minting
// through gh, with clock as its sense of time.
func appProcess(t *testing.T, db *statedb.DB, holder string, gh *secretbrokertest.GitHub,
	clock *secretbrokertest.Clock) *secretbroker.Broker {
	t.Helper()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	cipher, err := secretbroker.NewCipherWithKey(testKey())
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	b, err := secretbroker.New(store,
		secretbroker.WithCipher(cipher),
		secretbroker.WithAuditor(secretstore.NewAuditor(db)),
		secretbroker.WithGitHubApp(gh),
		secretbroker.WithClock(clock.Now),
		secretbroker.WithLeaseRecords(holder))
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	return b
}

// TestRestoredAppTokenSlotRefreshesPastItsHour is Task 20383 through a real
// database and secretbrokertest's clock: a GitHub App token a run holds as a
// file, minted by a hub process that then stops, is kept alive past GitHub's
// hour by the process that takes the run's lease over — re-minted at the
// recorded scope, from a record that names the scope and never the token.
func TestRestoredAppTokenSlotRefreshesPastItsHour(t *testing.T) {
	db, path := openTestDB(t)
	clock := secretbrokertest.NewClock(time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC))
	gh := secretbrokertest.NewGitHub(
		secretbroker.InstallationRepo{ID: 11, FullName: "acme/api"},
		secretbroker.InstallationRepo{ID: 12, FullName: "acme/web"})
	gh.Clock = clock.Now
	ctx := context.Background()

	a := appProcess(t, db, "hub_a", gh, clock)
	sec, err := a.Mint(ctx, secretbroker.MintRequest{
		Name: "app", Kind: secretbroker.KindGitHubApp, Payload: secretbrokertest.AppPayload(101, 202), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	grant, err := a.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: mustSubject(t, "project:/srv/app"),
		Constraints: secretbroker.Constraints{Repos: []string{"acme/api"}, Permissions: []string{"contents:write"}},
		TTL:         24 * time.Hour, Actor: "test",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	lease, err := a.LeaseFor(ctx, secretbroker.Requester{ExecutorID: "edge-01", ProjectID: "/srv/app", RunID: "run_1"}, "ui")
	if err != nil || len(lease.Materials) != 1 {
		t.Fatalf("lease = %+v, %v", lease, err)
	}
	var first string
	for _, f := range lease.Materials[0].Files {
		if f.Name == "github-token" {
			first = strings.TrimSpace(string(f.Content))
		}
	}
	if first == "" || !gh.Valid(first) {
		t.Fatal("the lease delivered no live token file")
	}
	firstReq := gh.Creates()[len(gh.Creates())-1]

	// The row the slot travels in names the scope, never the token.
	rows, err := db.ListAppTokenSlots(lease.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("slot rows = %+v, %v", rows, err)
	}
	if strings.Contains(rows[0].Scope, first) || rows[0].FileName != "github-token" || rows[0].Holder != "hub_a" ||
		!strings.Contains(rows[0].Scope, `"installation_id":202`) || !strings.Contains(rows[0].Scope, `"repository_ids":[11]`) {
		t.Fatalf("slot row = %+v", rows[0])
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// The next process: a new handle over the same file, ten minutes on.
	clock.Advance(10 * time.Minute)
	db2, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	b := appProcess(t, db2, "hub_b", gh, clock)
	taken, err := b.Restore(ctx, lease.ID)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !b.HoldsFileAppTokens(lease.ID) || b.AppTokensDue(lease.ID) {
		t.Fatalf("taken-over slot: holds %v, due %v", b.HoldsFileAppTokens(lease.ID), b.AppTokensDue(lease.ID))
	}

	refresh := func(label string) string {
		t.Helper()
		if !b.AppTokensDue(lease.ID) {
			t.Fatalf("%s: not due", label)
		}
		fr, err := b.RefreshLeaseFiles(ctx, taken)
		if err != nil || fr == nil || len(fr.Files) != 1 || fr.Files[0].Name != "github-token" {
			t.Fatalf("%s: RefreshLeaseFiles = %+v, %v", label, fr, err)
		}
		tok := strings.TrimSpace(string(fr.Files[0].Content))
		fr.Delivered(false)
		fr.Close()
		return tok
	}

	// Past the first token's hour: GitHub no longer honours it, the refreshed
	// file does.
	clock.Advance(46 * time.Minute)
	second := refresh("past the first hour")
	clock.Advance(5 * time.Minute)
	if gh.Valid(first) {
		t.Fatal("the fake GitHub still honours the first token past its hour")
	}
	if !gh.Valid(second) || !gh.CoversRepo(second, "acme/api") || gh.CoversRepo(second, "acme/web") {
		t.Fatalf("the refreshed token is not live at the recorded scope")
	}
	got := gh.Creates()[len(gh.Creates())-1]
	if !reflect.DeepEqual(got.RepositoryIDs, firstReq.RepositoryIDs) || !reflect.DeepEqual(got.Permissions, firstReq.Permissions) ||
		got.InstallationID != firstReq.InstallationID {
		t.Fatalf("re-minted at %+v, first minted at %+v", got, firstReq)
	}
	rows, _ = db2.ListAppTokenSlots(lease.ID)
	if len(rows) != 1 || rows[0].Holder != "hub_b" || !rows[0].TokenExpiresAt.After(clock.Now().Add(50*time.Minute)) {
		t.Fatalf("slot row after the refresh = %+v", rows)
	}

	// And past the second hour as well.
	clock.Advance(time.Hour - 10*time.Minute)
	third := refresh("past the second hour")
	clock.Advance(10 * time.Minute)
	if gh.Valid(second) || !gh.Valid(third) {
		t.Fatalf("second valid %v, third valid %v", gh.Valid(second), gh.Valid(third))
	}

	b.Release(lease.ID)
	if gh.Valid(third) {
		t.Fatal("the release left the new holder's token live")
	}
	if rows, _ := db2.ListAppTokenSlots(""); len(rows) != 0 {
		t.Fatalf("slot rows left behind: %+v", rows)
	}
	_ = grant
}
