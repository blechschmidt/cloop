package statedb

import (
	"errors"
	"testing"
	"time"
)

// TestProxySessionsMoveOnlyFromTheHolder covers the rows a proxy session
// outlives its hub process with (Task 20383): every write after the insert
// names the holder it expects, so a process that lost a session to the one
// that adopted its run can neither extend, checkpoint nor close it, two
// processes racing to restore it cannot both win, and a closed session cannot
// be taken over at all.
func TestProxySessionsMoveOnlyFromTheHolder(t *testing.T) {
	db := openTestDB(t)
	issued := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	row := ProxySessionRow{
		Kind: ProxySessionGit, SessionID: "sess_a", TokenSHA256: "ab12", LeaseID: "lease_a",
		GrantID: "grant_1", Holder: "hub_old", RunID: "run_1", ProjectID: "/p", ExecutorID: "dev1",
		Actor: "alice", Scope: `{"repo_patterns":["acme/*"]}`,
		IssuedAt: issued, ExpiresAt: issued.Add(time.Hour),
	}
	if err := db.PutProxySession(row); err != nil {
		t.Fatalf("PutProxySession: %v", err)
	}
	got, err := db.GetProxySession(ProxySessionGit, "sess_a")
	if err != nil {
		t.Fatalf("GetProxySession: %v", err)
	}
	if got.TokenSHA256 != "ab12" || got.LeaseID != "lease_a" || got.Holder != "hub_old" || got.Scope != row.Scope ||
		got.Counters != "{}" || !got.IssuedAt.Equal(issued) || !got.ExpiresAt.Equal(row.ExpiresAt) || !got.Open() {
		t.Fatalf("round trip = %+v, want %+v", got, row)
	}
	if _, err := db.GetProxySession(ProxySessionKube, "sess_a"); !errors.Is(err, ErrProxySessionNotFound) {
		t.Fatalf("another kind's row = %v, want ErrProxySessionNotFound", err)
	}

	later := issued.Add(2 * time.Hour)
	if ok, err := db.ExtendProxySession(ProxySessionGit, "sess_a", "hub_other", later); err != nil || ok {
		t.Fatalf("a non-holder's extension = %v, %v; want refused", ok, err)
	}
	if ok, err := db.CheckpointProxySession(ProxySessionGit, "sess_a", "hub_old", `{"bytes_up":7}`); err != nil || !ok {
		t.Fatalf("the holder's checkpoint = %v, %v", ok, err)
	}

	// Two processes adopt the run; one restores the session.
	if ok, err := db.TakeProxySession(ProxySessionGit, "sess_a", "hub_old", "hub_new"); err != nil || !ok {
		t.Fatalf("first takeover = %v, %v", ok, err)
	}
	if ok, err := db.TakeProxySession(ProxySessionGit, "sess_a", "hub_old", "hub_late"); err != nil || ok {
		t.Fatalf("second takeover from the same holder = %v, %v; want refused", ok, err)
	}
	// The process that lost it can touch it no longer.
	if ok, _ := db.CloseProxySession(ProxySessionGit, "sess_a", "hub_old", later, "lost", ""); ok {
		t.Fatal("the previous holder closed a session it lost")
	}
	if ok, _ := db.CheckpointProxySession(ProxySessionGit, "sess_a", "hub_old", `{}`); ok {
		t.Fatal("the previous holder checkpointed a session it lost")
	}
	if ok, _ := db.DeleteProxySession(ProxySessionGit, "sess_a", "hub_old"); ok {
		t.Fatal("the previous holder deleted a session it lost")
	}
	if ok, err := db.ExtendProxySession(ProxySessionGit, "sess_a", "hub_new", later); err != nil || !ok {
		t.Fatalf("the new holder's extension = %v, %v", ok, err)
	}
	got, _ = db.GetProxySession(ProxySessionGit, "sess_a")
	if got.Holder != "hub_new" || !got.ExpiresAt.Equal(later) || got.Counters != `{"bytes_up":7}` {
		t.Fatalf("after the takeover = %+v", got)
	}

	// Closed stays closed: no second close, no takeover of a closed session.
	if ok, err := db.CloseProxySession(ProxySessionGit, "sess_a", "hub_new", later, "lease released", `{"bytes_up":9}`); err != nil || !ok {
		t.Fatalf("the holder's close = %v, %v", ok, err)
	}
	if ok, _ := db.CloseProxySession(ProxySessionGit, "sess_a", "hub_new", later, "again", ""); ok {
		t.Fatal("a closed session was closed twice")
	}
	if ok, _ := db.TakeProxySession(ProxySessionGit, "sess_a", "hub_new", "hub_late"); ok {
		t.Fatal("a closed session was taken over")
	}
	got, _ = db.GetProxySession(ProxySessionGit, "sess_a")
	if got.Open() || got.CloseReason != "lease released" || got.Counters != `{"bytes_up":9}` {
		t.Fatalf("closed row = %+v", got)
	}
	if ok, err := db.DeleteProxySession(ProxySessionGit, "sess_a", "hub_new"); err != nil || !ok {
		t.Fatalf("retire = %v, %v", ok, err)
	}
	if _, err := db.GetProxySession(ProxySessionGit, "sess_a"); !errors.Is(err, ErrProxySessionNotFound) {
		t.Fatalf("after retirement = %v", err)
	}
}

// TestListProxySessionsFilters checks each filter on its own and together.
func TestListProxySessionsFilters(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	put := func(kind, id, lease, run, holder string, offset time.Duration, closed bool) {
		t.Helper()
		row := ProxySessionRow{Kind: kind, SessionID: id, LeaseID: lease, RunID: run, Holder: holder,
			IssuedAt: at.Add(offset), ExpiresAt: at.Add(time.Hour)}
		if closed {
			row.ClosedAt, row.CloseReason = at, "closed"
		}
		if err := db.PutProxySession(row); err != nil {
			t.Fatal(err)
		}
	}
	put(ProxySessionGit, "g1", "lease_a", "", "h1", 0, false)
	put(ProxySessionKube, "k1", "lease_a", "", "h1", time.Second, false)
	put(ProxySessionGit, "g2", "lease_b", "", "h2", 2*time.Second, true)
	put(ProxySessionEgress, "e1", "", "run_9", "h1", 3*time.Second, false)

	ids := func(f ProxySessionFilter) []string {
		t.Helper()
		rows, err := db.ListProxySessions(f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.SessionID)
		}
		return out
	}
	same := func(got []string, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	}
	same(ids(ProxySessionFilter{}), "g1", "k1", "g2", "e1")
	same(ids(ProxySessionFilter{LeaseIDs: []string{"lease_a"}}), "g1", "k1")
	same(ids(ProxySessionFilter{LeaseIDs: []string{"lease_a", "lease_b"}, OpenOnly: true}), "g1", "k1")
	same(ids(ProxySessionFilter{Kind: ProxySessionGit}), "g1", "g2")
	same(ids(ProxySessionFilter{RunID: "run_9"}), "e1")
	same(ids(ProxySessionFilter{Holder: "h1", Kind: ProxySessionKube}), "k1")
	same(ids(ProxySessionFilter{SessionIDs: []string{"e1", "g2"}}), "g2", "e1")
	// An empty, non-nil id list matches nothing rather than everything.
	same(ids(ProxySessionFilter{LeaseIDs: []string{}}))
	same(ids(ProxySessionFilter{SessionIDs: []string{}}))
}

// TestAppTokenSlotsFollowTheirLease covers the slot rows: written with the
// lease, moved with it, updated only by their holder, and swept once the lease
// record is gone.
func TestAppTokenSlotsFollowTheirLease(t *testing.T) {
	db := openTestDB(t)
	exp := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	if err := db.PutSecretLease(SecretLeaseRow{LeaseID: "lease_a", Holder: "hub_old",
		IssuedAt: exp.Add(-time.Hour), ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"grant_1", "grant_2"} {
		if err := db.PutAppTokenSlot(AppTokenSlotRow{LeaseID: "lease_a", GrantID: g, Holder: "hub_old",
			SecretID: "sec_" + g, SecretName: "app", Scope: `{"installation_id":67890}`,
			FileName: "github-token", TokenExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	// A slot whose lease has no record: what a process killed between the two
	// deletes leaves.
	if err := db.PutAppTokenSlot(AppTokenSlotRow{LeaseID: "lease_gone", GrantID: "grant_9", Holder: "hub_old"}); err != nil {
		t.Fatal(err)
	}

	rows, err := db.ListAppTokenSlots("lease_a")
	if err != nil || len(rows) != 2 {
		t.Fatalf("slots of lease_a = %v, %v", rows, err)
	}
	if rows[0].GrantID != "grant_1" || rows[0].Scope != `{"installation_id":67890}` || !rows[0].TokenExpiresAt.Equal(exp) ||
		rows[0].Guarded || rows[0].SecretName != "app" || rows[0].FileName != "github-token" {
		t.Fatalf("round trip = %+v", rows[0])
	}

	upd := rows[0]
	upd.Guarded, upd.SessionID, upd.TokenExpiresAt = true, "sess_x", exp.Add(time.Hour)
	upd.Holder = "hub_other"
	if ok, _ := db.UpdateAppTokenSlot(upd); ok {
		t.Fatal("a non-holder updated a slot")
	}
	upd.Holder = "hub_old"
	if ok, err := db.UpdateAppTokenSlot(upd); err != nil || !ok {
		t.Fatalf("the holder's update = %v, %v", ok, err)
	}

	if n, err := db.TakeAppTokenSlots("lease_a", "hub_old", "hub_new"); err != nil || n != 2 {
		t.Fatalf("takeover moved %d, %v; want 2", n, err)
	}
	if n, _ := db.TakeAppTokenSlots("lease_a", "hub_old", "hub_late"); n != 0 {
		t.Fatalf("a second takeover moved %d slots", n)
	}
	rows, _ = db.ListAppTokenSlots("lease_a")
	if rows[0].Holder != "hub_new" || !rows[0].Guarded || rows[0].SessionID != "sess_x" ||
		!rows[0].TokenExpiresAt.Equal(exp.Add(time.Hour)) {
		t.Fatalf("after the takeover = %+v", rows[0])
	}

	if n, err := db.DeleteOrphanedAppTokenSlots(); err != nil || n != 1 {
		t.Fatalf("orphan sweep removed %d, %v; want the one without a lease", n, err)
	}
	if all, _ := db.ListAppTokenSlots(""); len(all) != 2 {
		t.Fatalf("after the orphan sweep = %v", all)
	}
	if ok, err := db.DeleteAppTokenSlot("lease_a", "grant_2", "hub_old"); err != nil || ok {
		t.Fatalf("the previous holder deleted a slot = %v, %v", ok, err)
	}
	if n, err := db.DeleteAppTokenSlots("lease_a", "hub_new"); err != nil || n != 2 {
		t.Fatalf("release removed %d, %v; want 2", n, err)
	}
}
