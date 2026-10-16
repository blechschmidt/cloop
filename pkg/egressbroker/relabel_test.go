package egressbroker

// relabel_test.go: a proxy session follows its executor's labels (Task 20432).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// memSessionStore's SessionLabelStore half.
var _ SessionLabelStore = (*memSessionStore)(nil)

func (m *memSessionStore) RelabelSession(id string, labels map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.records[id]
	rec.Labels = copyLabels(labels)
	m.records[id] = rec
	return nil
}

// TestRelabeledSessionIsJudgedByItsNewLabels: a session redeemed under a grant
// to label:site=lab, whose executor is then recorded as site=home, no longer
// stands on the grant — RecheckSession says so, which is what the hub's
// keepalive closes it on — and its record carries the new labels, so a process
// restoring it refuses it the same way.
func TestRelabeledSessionIsJudgedByItsNewLabels(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	store := newMemSessionStore()
	first, second, _ := twoBrokers(t, &now, store)
	mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "label:site=lab"), TTL: time.Hour})
	red := redeemDurable(t, first)
	id := red.Session.ID
	if err := first.RecheckSession(id); err != nil {
		t.Fatalf("precondition: the session does not stand on its grant: %v", err)
	}

	if changed, err := first.RelabelSession(id, map[string]string{"site": "lab"}); changed || err != nil {
		t.Errorf("relabeling to the same labels = %v, %v; want no change", changed, err)
	}
	changed, err := first.RelabelSession(id, map[string]string{"site": "home"})
	if !changed || err != nil {
		t.Fatalf("RelabelSession = %v, %v", changed, err)
	}
	if r, live := first.SessionRequester(id); !live || r.Labels["site"] != "home" || r.ExecutorID != "edge-1" {
		t.Errorf("the session is judged as %+v (live %v)", r, live)
	}
	if err := first.RecheckSession(id); !errors.Is(err, ErrNoGrant) {
		t.Errorf("RecheckSession after the relabel = %v, want ErrNoGrant", err)
	}
	rec := store.record(t, id)
	if !secretbroker.SameLabels(rec.Labels, map[string]string{"site": "home"}) {
		t.Fatalf("the record says %v, want the new labels", rec.Labels)
	}
	if _, err := second.RestoreSession(context.Background(), RestoreRequest{Record: rec}); !errors.Is(err, ErrNoGrant) {
		t.Errorf("restoring the relabeled record = %v, want it refused as no longer granted", err)
	}

	first.CloseSession(id, "test over")
	if _, err := first.RelabelSession(id, nil); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("relabeling a closed session = %v", err)
	}
}

// TestRestoreJudgesARecordByTheLabelsItCarries: a record whose labels match
// the grant restores, the same session under its own requester.
func TestRestoreJudgesARecordByTheLabelsItCarries(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	store := newMemSessionStore()
	first, second, _ := twoBrokers(t, &now, store)
	mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "label:site=lab"), TTL: time.Hour})
	red := redeemDurable(t, first)
	rec := store.record(t, red.Session.ID)
	first.SuspendSession(red.Session.ID, "hub stopping")

	sess, err := second.RestoreSession(context.Background(), RestoreRequest{Record: rec})
	if err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	if r := sess.issuedTo(); r.Labels["site"] != "lab" || r.ProjectID != "/srv/app" {
		t.Errorf("the restored session is judged as %+v", r)
	}
}
