package secretbroker

// requester_test.go: a Requester is the executor as the hub records it (Task
// 20432) — its labels included, so a label grant reaches it — and a lease
// follows its executor's labels when the record changes.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// staticRecords is ExecutorRecords over a fixed table: the hub's records, as
// far as a test is concerned. An executor not in it has no record.
type staticRecords map[string]RecordedExecutor

func (s staticRecords) RecordedExecutor(id string) (RecordedExecutor, error) {
	if rec, ok := s[id]; ok {
		return rec, nil
	}
	return RecordedExecutor{ID: id}, nil
}

// failingRecords is a hub whose records cannot be read.
type failingRecords struct{ err error }

func (f failingRecords) RecordedExecutor(string) (RecordedExecutor, error) {
	return RecordedExecutor{}, f.err
}

// ── memStore's LeaseLabelStore half ──────────────────────────────────────────

var _ LeaseLabelStore = (*memStore)(nil)

func (m *memStore) SetLeaseLabels(id, holder string, labels map[string]string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.leases[id]
	if !ok || r.Holder != holder {
		return false, nil
	}
	r.Requester = r.Requester.Relabeled(labels)
	m.leases[id] = r
	return true, nil
}

func TestNewRequesterCarriesTheRecordedLabelsAndTheScope(t *testing.T) {
	labels := map[string]string{"region": "eu"}
	withhold := map[string]string{"grant_x": "not this run's"}
	r := NewRequester(RecordedExecutor{ID: " edge-1 ", Labels: labels, Source: "agent credential"},
		RequestScope{ProjectID: "/srv/app", RunID: "run_1", GitHubProxied: true, KubeInProcess: true, Withhold: withhold})
	if r.ExecutorID != "edge-1" || r.ProjectID != "/srv/app" || r.RunID != "run_1" ||
		!r.GitHubProxied || !r.KubeInProcess || r.Withhold["grant_x"] == "" {
		t.Fatalf("requester = %+v", r)
	}
	if !SameLabels(r.Labels, labels) {
		t.Fatalf("labels = %v, want %v", r.Labels, labels)
	}
	// A copy: the record changing afterwards does not relabel a requester
	// already built from it.
	labels["region"] = "us"
	if r.Labels["region"] != "eu" {
		t.Errorf("the requester shares the record's map: %v", r.Labels)
	}
	if got := NewRequester(RecordedExecutor{ID: "x", Labels: map[string]string{}}, RequestScope{}); got.Labels != nil {
		t.Errorf("no labels should be nil, got %v", got.Labels)
	}
	// Executor and Scope take it apart again, and Relabeled changes only the
	// labels.
	back := NewRequester(r.Executor(), r.Scope())
	if back.ExecutorID != r.ExecutorID || back.ProjectID != r.ProjectID || !SameLabels(back.Labels, r.Labels) {
		t.Errorf("rebuilt = %+v, want %+v", back, r)
	}
	moved := r.Relabeled(map[string]string{"region": "us"})
	if moved.Labels["region"] != "us" || moved.RunID != "run_1" || r.Labels["region"] != "eu" {
		t.Errorf("relabeled = %+v (original %+v)", moved, r)
	}
}

func TestLookupExecutorAndRequesterFor(t *testing.T) {
	rec, err := LookupExecutor(nil, "  edge-1 ")
	if err != nil || rec.ID != "edge-1" || rec.HasLabels() {
		t.Errorf("no records = %+v, %v; want the ID alone", rec, err)
	}
	rec, err = LookupExecutor(staticRecords{"edge-1": {Labels: map[string]string{"a": "b"}, Source: "agent credential"}}, "edge-1")
	if err != nil || rec.ID != "edge-1" || rec.Labels["a"] != "b" || rec.Source != "agent credential" {
		t.Errorf("recorded = %+v, %v", rec, err)
	}
	boom := errors.New("database is locked")
	if _, err := LookupExecutor(failingRecords{boom}, "edge-1"); !errors.Is(err, boom) {
		t.Errorf("an unreadable record = %v, want it reported", err)
	}
	r, err := RequesterFor(failingRecords{boom}, "edge-1", RequestScope{ProjectID: "/srv/app"})
	if !errors.Is(err, boom) || r.ExecutorID != "" || r.ProjectID != "" {
		t.Errorf("RequesterFor over an unreadable record = %+v, %v; want the zero requester and the error", r, err)
	}
	if got := FormatLabels(map[string]string{"b": "2", "a": "1"}); got != "a=1,b=2" {
		t.Errorf("FormatLabels = %q", got)
	}
	if got := FormatLabels(nil); got != "none" {
		t.Errorf("FormatLabels(nil) = %q", got)
	}
}

// TestALabelGrantLeasesToTheRecordedLabelsOnly: a grant to a label selector is
// delivered to an executor whose recorded labels carry every pair, not to one
// carrying some of them, and never to a requester built by ID alone.
func TestALabelGrantLeasesToTheRecordedLabelsOnly(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()
	s := mintGitHub(t, b, "eu-gpu", "ghp_labelgrant0123456789abcdefghijklmn")
	g := grantTo(t, b, s.ID, "label:region=eu,gpu=true", Constraints{Repos: []string{"org/*"}}, time.Hour)
	records := staticRecords{
		"edge-eu":   {Labels: map[string]string{"region": "eu", "gpu": "true", "site": "fra"}},
		"edge-half": {Labels: map[string]string{"region": "eu"}},
	}
	for _, tc := range []struct {
		executor string
		want     int
	}{{"edge-eu", 1}, {"edge-half", 0}, {"edge-unknown", 0}} {
		r, err := RequesterFor(records, tc.executor, RequestScope{ProjectID: "/srv/app"})
		if err != nil {
			t.Fatal(err)
		}
		lease, err := b.LeaseFor(ctx, r, "test")
		if err != nil {
			t.Fatal(err)
		}
		if len(lease.Materials) != tc.want || (tc.want == 1 && lease.Materials[0].GrantID != g.ID) {
			t.Errorf("%s leased %d material(s), want %d", tc.executor, len(lease.Materials), tc.want)
		}
		b.Release(lease.ID)
	}
	lease, err := b.Lease(ctx, "edge-eu", "/srv/app")
	if err != nil {
		t.Fatal(err)
	}
	if !lease.Empty() {
		t.Errorf("a lease by executor ID alone carried a label grant: %d material(s)", len(lease.Materials))
	}
}

// TestRelabelLeaseJudgesItByTheNewLabels: a lease relabeled after its
// executor's record changed is judged by the new labels — the label grant they
// no longer match is reported, with the change, for the hub to take back; its
// record carries them for a process adopting the run; and a renewal re-issues
// without the grant.
func TestRelabelLeaseJudgesItByTheNewLabels(t *testing.T) {
	_, store, _, clock := newTestBroker(t)
	b, _ := holderBroker(t, store, clock, "hub-a")
	ctx := context.Background()
	eu := mintGitHub(t, b, "eu-pat", "ghp_relabeleu0123456789abcdefghijklmnop")
	all := mintGitHub(t, b, "all-pat", "ghp_relabelall0123456789abcdefghijklmno")
	euGrant := grantTo(t, b, eu.ID, "label:region=eu", Constraints{Repos: []string{"org/*"}}, time.Hour)
	anyGrant := grantTo(t, b, all.ID, "any", Constraints{Repos: []string{"org/*"}}, time.Hour)

	r, err := RequesterFor(staticRecords{"edge": {Labels: map[string]string{"region": "eu"}}}, "edge",
		RequestScope{ProjectID: "/srv/app"})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := b.LeaseFor(ctx, r, "test")
	if err != nil || len(lease.Materials) != 2 {
		t.Fatalf("lease = %v, %v; want both grants", lease, err)
	}

	if changed, err := b.RelabelLease(lease.ID, map[string]string{"region": "eu"}); changed || err != nil {
		t.Errorf("relabeling to the same labels = %v, %v; want no change", changed, err)
	}
	changed, err := b.RelabelLease(lease.ID, map[string]string{"region": "us"})
	if !changed || err != nil {
		t.Fatalf("RelabelLease = %v, %v", changed, err)
	}
	if held, _ := b.HeldRequester(lease.ID); held.Labels["region"] != "us" {
		t.Errorf("the lease is judged as %v, want region=us", held.Labels)
	}
	if rec := store.leases[lease.ID]; rec.Requester.Labels["region"] != "us" {
		t.Errorf("the record still says %v", rec.Requester.Labels)
	}

	lw := b.LabelWithdrawals(lease.ID, map[string]string{"region": "eu"})
	if len(lw) != 1 || lw[0].GrantID != euGrant.ID || lw[0].Subject != "label:region=eu" ||
		!strings.Contains(lw[0].Reason, "from region=eu to region=us") {
		t.Fatalf("label withdrawals = %+v; want the eu grant, saying the labels changed", lw)
	}
	if !slices.ContainsFunc(b.WithdrawnGrants(lease.ID), func(w WithdrawnGrant) bool { return w.GrantID == euGrant.ID }) {
		t.Error("WithdrawnGrants does not name the grant the new labels no longer match")
	}
	// Extend refuses a lease that still carries it, and goes on once the hub
	// has taken it back.
	if _, err := b.Extend(ctx, lease.ID); err == nil {
		t.Error("the lease was extended while carrying a grant its labels no longer match")
	}
	if n, err := b.DropLeaseGrant(ctx, lease.ID, euGrant.ID, lw[0].Reason); err != nil || n != 1 {
		t.Fatalf("DropLeaseGrant = %d, %v", n, err)
	}
	if _, err := b.Extend(ctx, lease.ID); err != nil {
		t.Errorf("Extend on the grant still standing: %v", err)
	}
	renewed, err := b.Renew(ctx, lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(renewed.Materials) != 1 || renewed.Materials[0].GrantID != anyGrant.ID {
		t.Errorf("the renewal carries %d material(s), want only the grant to any", len(renewed.Materials))
	}

	if _, err := b.RelabelLease("lease_unknown", nil); !errors.Is(err, ErrLeaseNotFound) {
		t.Errorf("relabeling an unknown lease = %v", err)
	}
}

// TestRelabelOfALeaseAnotherProcessTookOver: the record belongs to the process
// holding the lease now, so a stale holder's relabel does not write it.
func TestRelabelOfALeaseAnotherProcessTookOver(t *testing.T) {
	_, store, _, clock := newTestBroker(t)
	a, _ := holderBroker(t, store, clock, "hub-a")
	s := mintGitHub(t, a, "pat", "ghp_relabelmoved0123456789abcdefghijklm")
	grantTo(t, a, s.ID, "label:region=eu", Constraints{Repos: []string{"org/*"}}, time.Hour)
	r, _ := RequesterFor(staticRecords{"edge": {Labels: map[string]string{"region": "eu"}}}, "edge", RequestScope{})
	lease, err := a.LeaseFor(context.Background(), r, "test")
	if err != nil || lease.Empty() {
		t.Fatalf("lease = %v, %v", lease, err)
	}
	if ok, err := store.TakeLease(lease.ID, "hub-a", "hub-b"); !ok || err != nil {
		t.Fatalf("TakeLease = %v, %v", ok, err)
	}
	changed, err := a.RelabelLease(lease.ID, map[string]string{"region": "us"})
	if !changed || !errors.Is(err, ErrLeaseMoved) {
		t.Errorf("RelabelLease = %v, %v; want the change refused as ErrLeaseMoved", changed, err)
	}
	if rec := store.leases[lease.ID]; rec.Requester.Labels["region"] != "eu" {
		t.Errorf("hub-b's record was rewritten by hub-a: %v", rec.Requester.Labels)
	}
}

// TestALabelSelectorNoExecutorCouldCarryIsRefused: a selector naming a label
// no executor's labels may hold would make a grant nothing ever matches, so it
// is refused where it is written.
func TestALabelSelectorNoExecutorCouldCarryIsRefused(t *testing.T) {
	for _, spec := range []string{"label:my key=v", "label:k=v\x01"} {
		if _, err := ParseSubject(spec); !errors.Is(err, ErrInvalidSubject) {
			t.Errorf("ParseSubject(%q) = %v, want ErrInvalidSubject", spec, err)
		}
	}
	for _, spec := range []string{"label:region=eu", "label:gpu=", "label:topology.kubernetes.io/zone=a=b"} {
		if _, err := ParseSubject(spec); err != nil {
			t.Errorf("ParseSubject(%q) = %v, want it accepted", spec, err)
		}
	}
}
