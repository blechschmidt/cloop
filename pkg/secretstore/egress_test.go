// Integration tests for the SQLite-backed egress broker.
//
// pkg/egressbroker's own tests use an in-memory store, which is right for
// exercising policy. These cover what only a real database can show: that a
// grant's whole policy survives a process boundary intact, that revocation is
// a stamp rather than a delete, and that a corrupt row loses access rather
// than keeping it.

package secretstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func openEgressBroker(t *testing.T, db *statedb.DB) *egressbroker.Broker {
	t.Helper()
	store, err := secretstore.NewEgressStore(db)
	if err != nil {
		t.Fatalf("new egress store: %v", err)
	}
	b, err := egressbroker.New(store,
		egressbroker.WithAuditor(secretstore.NewAuditor(db)),
		egressbroker.WithEndpoint("127.0.0.1:8899"))
	if err != nil {
		t.Fatalf("new egress broker: %v", err)
	}
	return b
}

// TestEgressGrantSurvivesAProcessBoundary is the whole point of the adapter:
// every dimension of the policy must come back exactly as it went in, because
// a field that silently drops on reload is a field that silently stops
// constraining.
func TestEgressGrantSurvivesAProcessBoundary(t *testing.T) {
	db, path := openTestDB(t)
	ctx := context.Background()

	sub, err := secretbroker.ParseSubject("label:region=eu,gpu=true")
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	created, err := openEgressBroker(t, db).Grant(ctx, egressbroker.GrantRequest{
		Subject:      sub,
		Scope:        "ci",
		Hosts:        []string{"api.github.com", "*.githubusercontent.com"},
		CIDRs:        []string{"10.20.0.0/16"},
		Ports:        []int{443, 8443},
		Methods:      []string{"GET", "POST"},
		MaxBytesUp:   1 << 20,
		MaxBytesDown: 100 << 20,
		SessionTTL:   7 * time.Minute,
		TTL:          8 * time.Hour,
		Actor:        "cli:tester",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if cerr := db.Close(); cerr != nil {
		t.Fatalf("close: %v", cerr)
	}

	reopened, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	got, err := openEgressBroker(t, reopened).ListGrants(egressbroker.GrantFilter{ActiveOnly: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d grants after reopen, want 1", len(got))
	}
	g := got[0]

	if g.ID != created.ID || g.Scope != "ci" || g.CreatedBy != "cli:tester" {
		t.Errorf("identity fields did not survive: %+v", g)
	}
	if g.Subject.String() != "label:gpu=true,region=eu" {
		t.Errorf("subject = %q, want the canonical label selector", g.Subject.String())
	}
	if strings.Join(g.Hosts, ",") != "*.githubusercontent.com,api.github.com" {
		t.Errorf("hosts = %v", g.Hosts)
	}
	if strings.Join(g.CIDRs, ",") != "10.20.0.0/16" {
		t.Errorf("cidrs = %v", g.CIDRs)
	}
	if len(g.Ports) != 2 || g.Ports[0] != 443 || g.Ports[1] != 8443 {
		t.Errorf("ports = %v", g.Ports)
	}
	if strings.Join(g.Methods, ",") != "GET,POST" {
		t.Errorf("methods = %v", g.Methods)
	}
	if g.MaxBytesUp != 1<<20 || g.MaxBytesDown != 100<<20 {
		t.Errorf("quotas = up %d down %d", g.MaxBytesUp, g.MaxBytesDown)
	}
	if g.SessionTTL != 7*time.Minute {
		t.Errorf("session ttl = %s, want 7m", g.SessionTTL)
	}
	if !g.ExpiresAt.Equal(created.ExpiresAt) {
		t.Errorf("expiry = %s, want %s", g.ExpiresAt, created.ExpiresAt)
	}

	// And the reloaded policy still decides the same way.
	if err := g.CheckPort(443); err != nil {
		t.Errorf("443 should still be allowed: %v", err)
	}
	if err := g.CheckPort(22); !errors.Is(err, egressbroker.ErrPortNotAllowed) {
		t.Errorf("22 should still be refused, got %v", err)
	}
	if !g.HostMatches("api.github.com") || g.HostMatches("evil.test") {
		t.Error("host matching changed across the boundary")
	}
}

func TestEgressRevocationIsAStampAndSurvives(t *testing.T) {
	db, path := openTestDB(t)
	ctx := context.Background()
	b := openEgressBroker(t, db)

	sub, _ := secretbroker.ParseSubject("project:/srv/app")
	g, err := b.Grant(ctx, egressbroker.GrantRequest{
		Subject: sub, Hosts: []string{"api.example.com"}, TTL: time.Hour, Actor: "op",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := b.Revoke(ctx, g.ID, "op"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_ = db.Close()

	reopened, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	b2 := openEgressBroker(t, reopened)

	active, err := b2.ListGrants(egressbroker.GrantFilter{ActiveOnly: true})
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("a revoked grant must not be active, got %d", len(active))
	}
	all, err := b2.ListGrants(egressbroker.GrantFilter{})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 1 || all[0].RevokedAt.IsZero() {
		t.Fatalf("the revoked row must survive with its stamp, got %+v", all)
	}
	// It cannot be redeemed after the restart either.
	if _, err := b2.Redeem(ctx, egressbroker.RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "e1", ProjectID: "/srv/app"},
	}); !errors.Is(err, egressbroker.ErrNoGrant) {
		t.Fatalf("want ErrNoGrant after restart, got %v", err)
	}
}

// TestCorruptPolicyRowLosesAccess: a row the adapter cannot decode is skipped
// in the deny direction. Honouring a half-parsed policy is the failure mode
// worth spending a test on.
func TestCorruptPolicyRowLosesAccess(t *testing.T) {
	db, _ := openTestDB(t)

	if err := db.PutEgressGrant(statedb.EgressGrantRow{
		ID:           "egress_corrupt",
		SubjectType:  "project",
		SubjectValue: "/srv/app",
		PolicyJSON:   "{not json",
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("put row: %v", err)
	}
	// A row whose subject is unparseable is the other half of the same rule.
	if err := db.PutEgressGrant(statedb.EgressGrantRow{
		ID:           "egress_badsubject",
		SubjectType:  "nonsense",
		SubjectValue: "x",
		PolicyJSON:   `{"hosts":["*"]}`,
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("put row: %v", err)
	}

	b := openEgressBroker(t, db)
	grants, err := b.ListGrants(egressbroker.GrantFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("undecodable rows must be skipped, got %+v", grants)
	}
	if _, err := b.Redeem(context.Background(), egressbroker.RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "e1", ProjectID: "/srv/app"},
	}); !errors.Is(err, egressbroker.ErrNoGrant) {
		t.Fatalf("a corrupt row must not grant anything, got %v", err)
	}
}

// TestEgressDecisionsReachTheSharedAuditLog proves the two brokers write to
// one hash chain, which is what makes "what did this executor reach, and with
// whose authority" answerable from a single ordered source.
func TestEgressDecisionsReachTheSharedAuditLog(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	b := openEgressBroker(t, db)

	sub, _ := secretbroker.ParseSubject("project:/srv/app")
	if _, err := b.Grant(ctx, egressbroker.GrantRequest{
		Subject: sub, Hosts: []string{"api.example.com"}, TTL: time.Hour, Actor: "cli:tester",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	red, err := b.Redeem(ctx, egressbroker.RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
		TaskID:    "20163",
		Actor:     "cli:tester",
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	events, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "secret", Limit: 100})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}

	var sawGrant, sawRedeem bool
	for _, ev := range events {
		switch ev.EventType {
		case string(secretbroker.ActionEgressGrant):
			sawGrant = true
		case string(secretbroker.ActionEgressRedeem):
			sawRedeem = true
			var payload map[string]any
			if uerr := json.Unmarshal([]byte(ev.Payload), &payload); uerr != nil {
				t.Fatalf("decode payload: %v", uerr)
			}
			if payload["task_id"] != "20163" {
				t.Errorf("redeem row should carry the task, got %v", payload["task_id"])
			}
			if payload["executor_id"] != "edge-1" {
				t.Errorf("redeem row should carry the executor, got %v", payload["executor_id"])
			}
		}
		// The credential must not be anywhere in the chain.
		if strings.Contains(ev.Payload, red.Token) {
			t.Fatalf("audit row leaked the proxy token: %s", ev.Payload)
		}
	}
	if !sawGrant || !sawRedeem {
		t.Fatalf("expected egress.grant and egress.redeem rows; got %d events", len(events))
	}

	report, verr := db.VerifyAuditChain()
	if verr != nil || !report.OK {
		t.Fatalf("audit chain broken after egress writes: %+v err=%v", report, verr)
	}
}
