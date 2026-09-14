package rolestore

// Covers the two properties the resolver depends on and cannot see for itself:
// that a write converges within the TTL, and that a read failure leaves the
// previous answer in force rather than handing authority back.

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func newDB(t *testing.T) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func putDeny(t *testing.T, db *statedb.DB, email string) statedb.RoleBindingRow {
	t.Helper()
	b, err := authz.NormalizeBinding(authz.Binding{Claim: authz.ClaimEmail, Value: email, Deny: true})
	if err != nil {
		t.Fatalf("NormalizeBinding: %v", err)
	}
	row, err := RowFor(b, "test", "cli:test", time.Now().UTC())
	if err != nil {
		t.Fatalf("RowFor: %v", err)
	}
	stored, err := db.PutRoleBinding(row)
	if err != nil {
		t.Fatalf("PutRoleBinding: %v", err)
	}
	return stored
}

// TestWriteConvergesWithinTTL is the property that lets `cloop hub role revoke`
// skip the control-plane lease: a write behind a live hub reaches its
// authorization decisions on its own, so there is nothing to diverge.
func TestWriteConvergesWithinTTL(t *testing.T) {
	db := newDB(t)
	now := time.Now()
	clock := func() time.Time { return now }

	store, err := New(db, WithTTL(10*time.Second), WithClock(clock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := store.RuntimeBindings(); len(got) != 0 {
		t.Fatalf("precondition: %d bindings on a fresh database", len(got))
	}

	putDeny(t, db, "alice@example.com")

	// Inside the TTL the cache still answers, which is the trade: one SQLite
	// query per TTL instead of one per permission check.
	if got := store.RuntimeBindings(); len(got) != 0 {
		t.Errorf("the cache re-read storage inside its TTL (%d bindings)", len(got))
	}

	now = now.Add(11 * time.Second)
	got := store.RuntimeBindings()
	if len(got) != 1 {
		t.Fatalf("after the TTL elapsed: %d bindings, want 1 — a demotion written "+
			"behind a running hub never reaches it", len(got))
	}
	if !got[0].Deny || got[0].Value != "alice@example.com" {
		t.Errorf("loaded %+v, want a deny naming alice@example.com", got[0])
	}
}

// TestReadFailureKeepsTheLastGoodAnswer is the failure policy, and it is the
// one that matters: bindings here only ever remove authority config already
// granted, so an empty answer on a storage fault is a path back to admin.
func TestReadFailureKeepsTheLastGoodAnswer(t *testing.T) {
	db := newDB(t)
	putDeny(t, db, "alice@example.com")

	now := time.Now()
	var mu sync.Mutex
	var reported []error
	store, err := New(db,
		WithTTL(time.Second),
		WithClock(func() time.Time { return now }),
		WithErrorHandler(func(err error) {
			mu.Lock()
			defer mu.Unlock()
			reported = append(reported, err)
		}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(store.RuntimeBindings()) != 1 {
		t.Fatal("precondition: the deny was not loaded")
	}

	// Break the read the only way a test can reach: close the handle.
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	now = now.Add(2 * time.Second)

	got := store.RuntimeBindings()
	if len(got) != 1 || !got[0].Deny {
		t.Errorf("after a failed refresh: %+v, want the previous deny still in force — "+
			"an unreachable database must not hand authority back", got)
	}
	mu.Lock()
	n := len(reported)
	mu.Unlock()
	if n == 0 {
		t.Error("a failed refresh was not reported, so an operator mid-incident has no " +
			"way to know their demotion has not landed")
	}
}

// TestFailedRefreshDoesNotRetryEveryRequest: without stamping the attempt
// before it runs, a wedged database would put every permission check of every
// request behind the same failing query.
func TestFailedRefreshDoesNotRetryEveryRequest(t *testing.T) {
	db := newDB(t)
	now := time.Now()
	var calls int
	store, err := New(db,
		WithTTL(time.Second),
		WithClock(func() time.Time { return now }),
		WithErrorHandler(func(error) { calls++ }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = db.Close()
	now = now.Add(2 * time.Second)

	for i := 0; i < 5; i++ {
		store.RuntimeBindings()
	}
	if calls != 1 {
		t.Errorf("%d failed refreshes across 5 reads inside one TTL, want 1", calls)
	}
}

// TestNewFailsWhenStorageIsUnreadable: the first load is eager and fatal, which
// is what bounds the degraded case above to "serving a list that was good once".
func TestNewFailsWhenStorageIsUnreadable(t *testing.T) {
	db := newDB(t)
	_ = db.Close()
	if _, err := New(db); err == nil {
		t.Error("New succeeded against a closed database — a hub would come up having " +
			"silently dropped every demotion")
	}
	if _, err := New(nil); err == nil {
		t.Error("New(nil) succeeded")
	}
}

// TestRowRoundTrip: storage and resolution must agree on what a binding is.
// They are two packages apart, and a disagreement means a command that reports
// success against a row that matches nobody.
func TestRowRoundTrip(t *testing.T) {
	for _, b := range []authz.Binding{
		{Claim: authz.ClaimEmail, Value: "Alice@Example.com", Deny: true},
		{Claim: authz.ClaimGroup, Value: "/Contractors", Role: authz.RoleViewer},
		{Claim: authz.ClaimSub, Value: "AbC123", Role: authz.RoleMaintainer, Project: "payments"},
		{Claim: authz.ClaimRole, Value: "temp", Role: authz.RoleOperator, Executor: "edge-1"},
	} {
		want, err := authz.NormalizeBinding(b)
		if err != nil {
			t.Fatalf("NormalizeBinding(%+v): %v", b, err)
		}
		row, err := RowFor(b, "why", "cli:test", time.Now().UTC())
		if err != nil {
			t.Fatalf("RowFor(%+v): %v", b, err)
		}
		got, err := BindingFrom(row)
		if err != nil {
			t.Fatalf("BindingFrom(%+v): %v", row, err)
		}
		if got != want {
			t.Errorf("round trip of %+v gave %+v, want %+v", b, got, want)
		}
	}
}

// TestUnreadableRowDoesNotDisarmTheRest: a binding written by a newer build,
// carrying a role this one does not know, must not take the denies with it.
func TestUnreadableRowDoesNotDisarmTheRest(t *testing.T) {
	db := newDB(t)
	putDeny(t, db, "alice@example.com")
	if _, err := db.PutRoleBinding(statedb.RoleBindingRow{
		Effect: statedb.RoleEffectAllow,
		Claim:  "department", // not a claim kind this build knows
		Value:  "engineering",
		Role:   "viewer",
	}); err != nil {
		t.Fatalf("PutRoleBinding: %v", err)
	}

	var skipped []error
	store, err := New(db, WithErrorHandler(func(err error) { skipped = append(skipped, err) }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := store.RuntimeBindings()
	if len(got) != 1 || !got[0].Deny {
		t.Errorf("loaded %+v, want only the deny — an unreadable row took the rest of "+
			"the table with it", got)
	}
	if len(skipped) != 1 {
		t.Errorf("%d rows reported as skipped, want 1", len(skipped))
	}
}

// TestBindingIDIsDeterministic: repeating a command under pressure must
// replace the binding rather than leave two rows with no way to tell which is
// live, and case differences must not defeat that.
func TestBindingIDIsDeterministic(t *testing.T) {
	db := newDB(t)
	first := putDeny(t, db, "Alice@Example.com")
	second := putDeny(t, db, "alice@example.com")
	if first.ID != second.ID {
		t.Errorf("ids differ across a case change: %s vs %s", first.ID, second.ID)
	}
	rows, err := db.ListRoleBindings()
	if err != nil {
		t.Fatalf("ListRoleBindings: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("%d rows after writing the same deny twice, want 1", len(rows))
	}
}

// TestGetMissingBindingIsTyped so the CLI can tell "you mistyped an id" from
// "storage is broken" and say the actionable one.
func TestGetMissingBindingIsTyped(t *testing.T) {
	db := newDB(t)
	if _, err := db.GetRoleBinding("rb_nope"); !errors.Is(err, statedb.ErrRoleBindingNotFound) {
		t.Errorf("GetRoleBinding on a missing id returned %v, want ErrRoleBindingNotFound", err)
	}
	deleted, err := db.DeleteRoleBinding("rb_nope")
	if err != nil {
		t.Errorf("DeleteRoleBinding on a missing id: %v", err)
	}
	if deleted {
		t.Error("DeleteRoleBinding reported deleting a row that never existed")
	}
}

// TestDenySortsFirst: both a human reading `role list` and the resolver's own
// scan should meet the rows that take authority away before the ones that
// grant it.
func TestDenySortsFirst(t *testing.T) {
	db := newDB(t)
	allow, err := authz.NormalizeBinding(authz.Binding{
		Claim: authz.ClaimGroup, Value: "aaa-sorts-before-everything", Role: authz.RoleViewer})
	if err != nil {
		t.Fatalf("NormalizeBinding: %v", err)
	}
	row, err := RowFor(allow, "grant", "cli:test", time.Now().UTC())
	if err != nil {
		t.Fatalf("RowFor: %v", err)
	}
	if _, err := db.PutRoleBinding(row); err != nil {
		t.Fatalf("PutRoleBinding: %v", err)
	}
	putDeny(t, db, "zzz@example.com")

	rows, err := db.ListRoleBindings()
	if err != nil {
		t.Fatalf("ListRoleBindings: %v", err)
	}
	if len(rows) != 2 || rows[0].Effect != statedb.RoleEffectDeny {
		t.Errorf("first row is %+v, want the deny", rows[0])
	}
}
