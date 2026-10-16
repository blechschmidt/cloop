package statedb

import (
	"errors"
	"testing"
	"time"
)

// TestForwarderBindingsStore covers the binding rows (Task 20430): what counts
// as in force, and that a revocation and a request's decision each happen
// once — what lets every hub member race to stamp a lapsed binding while only
// one audits it.
func TestForwarderBindingsStore(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	put := func(id, project string, expires time.Time) {
		t.Helper()
		if err := db.PutForwarderBinding(ForwarderBindingRow{ID: id, ForwarderID: "fwd1", Project: project,
			CreatedAt: now, ExpiresAt: expires}); err != nil {
			t.Fatal(err)
		}
	}
	put("b-live", "/p/a", now.Add(time.Hour))
	put("b-lapsed", "/p/a", now.Add(-time.Minute))
	put("b-other", "/p/b", now.Add(time.Hour))

	active, err := db.ListForwarderBindings(ForwarderBindingFilter{Project: "/p/a", ActiveAt: now})
	if err != nil || len(active) != 1 || active[0].ID != "b-live" {
		t.Fatalf("bindings in force for /p/a = %+v, %v; want b-live alone", active, err)
	}
	all, _ := db.ListForwarderBindings(ForwarderBindingFilter{ForwarderID: "fwd1"})
	if len(all) != 3 {
		t.Fatalf("every binding of fwd1 = %d, want 3", len(all))
	}

	if ok, err := db.RevokeForwarderBinding("b-live", "admin", "done", now); err != nil || !ok {
		t.Fatalf("first revoke = %v, %v", ok, err)
	}
	if ok, err := db.RevokeForwarderBinding("b-live", "someone-else", "again", now); err != nil || ok {
		t.Fatalf("second revoke = %v, %v; want no change", ok, err)
	}
	if got, _ := db.GetForwarderBinding("b-live"); got.RevokedBy != "admin" || got.Active(now) {
		t.Fatalf("revoked binding = %+v", got)
	}
	if _, err := db.RevokeForwarderBinding("missing", "admin", "", now); !errors.Is(err, ErrForwarderBindingNotFound) {
		t.Fatalf("revoking a missing binding = %v", err)
	}
	ids, err := db.RevokeForwarderBindingsOf("fwd1", "admin", "the forwarder was revoked", now)
	if err != nil || len(ids) != 2 {
		t.Fatalf("revoking fwd1's bindings = %v, %v; want the two still unrevoked", ids, err)
	}

	req := ForwarderBindingRequestRow{ID: "fbr_1", ForwarderID: "fwd1", Project: "/p/a", TTL: time.Hour,
		RequestedBy: "maint", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := db.PutForwarderBindingRequest(req); err != nil {
		t.Fatal(err)
	}
	if err := db.PutForwarderBindingRequest(req); err == nil {
		t.Fatal("a request id was filed twice")
	}
	if ok, err := db.DecideForwarderBindingRequest("fbr_1", ForwarderRequestApproved, "admin", "", "b-x", now); err != nil || !ok {
		t.Fatalf("approve = %v, %v", ok, err)
	}
	if ok, _ := db.DecideForwarderBindingRequest("fbr_1", ForwarderRequestDenied, "admin2", "no", "", now); ok {
		t.Fatal("a decided request was decided again")
	}
	got, err := db.GetForwarderBindingRequest("fbr_1")
	if err != nil || got.State != ForwarderRequestApproved || got.BindingID != "b-x" || got.TTL != time.Hour {
		t.Fatalf("request after approval = %+v, %v", got, err)
	}

	lapsing := ForwarderBindingRequestRow{ID: "fbr_2", ForwarderID: "fwd1", Project: "/p/a", RequestedBy: "maint",
		CreatedAt: now.Add(-3 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if err := db.PutForwarderBindingRequest(lapsing); err != nil {
		t.Fatal(err)
	}
	expired, err := db.ExpireForwarderBindingRequests(now)
	if err != nil || len(expired) != 1 || expired[0].ID != "fbr_2" {
		t.Fatalf("expired = %+v, %v; want fbr_2", expired, err)
	}
	if again, _ := db.ExpireForwarderBindingRequests(now); len(again) != 0 {
		t.Fatal("a request lapsed twice")
	}
}
