package egressbroker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// newBroker builds a broker over an in-memory store with a controllable
// clock, which is how every TTL assertion below avoids sleeping.
func newBroker(t *testing.T, now *time.Time, opts ...Option) (*Broker, *recordingAuditor) {
	t.Helper()
	audit := &recordingAuditor{}
	all := append([]Option{
		WithAuditor(audit),
		WithEndpoint("127.0.0.1:8899"),
		WithClock(func() time.Time { return *now }),
	}, opts...)
	b, err := New(NewMemStore(), all...)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	return b, audit
}

func mustSubject(t *testing.T, spec string) secretbroker.Subject {
	t.Helper()
	sub, err := secretbroker.ParseSubject(spec)
	if err != nil {
		t.Fatalf("parse subject %q: %v", spec, err)
	}
	return sub
}

func mustGrant(t *testing.T, b *Broker, req GrantRequest) Grant {
	t.Helper()
	if req.Hosts == nil && req.CIDRs == nil {
		req.Hosts = []string{"api.example.com"}
	}
	g, err := b.Grant(context.Background(), req)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	return g
}

// TestRedeemMintsACredentialThatIsNeverStored is the central secrecy claim:
// the plaintext token leaves Redeem and exists nowhere else in the process.
func TestRedeemMintsACredentialThatIsNeverStored(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	b, audit := newBroker(t, &now)
	mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), Actor: "op"})

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
		TaskID:    "t-1",
		Actor:     "op",
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if len(red.Token) != TokenBytes*2 {
		t.Fatalf("token is %d hex chars, want %d (256 bits)", len(red.Token), TokenBytes*2)
	}

	// A marshalled session must not carry the credential — that is what lets
	// one be returned over an API or written to a log.
	blob, err := json.Marshal(red.Session)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if strings.Contains(string(blob), red.Token) {
		t.Fatalf("marshalled session leaked the token: %s", blob)
	}
	// Nor may any audit row.
	for _, ev := range audit.all() {
		blob, _ := json.Marshal(ev)
		if strings.Contains(string(blob), red.Token) {
			t.Fatalf("audit event leaked the token: %s", blob)
		}
	}
	// The URL is the one place it appears, because the sandbox needs it.
	if !strings.Contains(red.ProxyURL, red.Token) {
		t.Error("the proxy URL should carry the credential")
	}

	// Two redemptions never share a credential.
	red2, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
	})
	if err != nil {
		t.Fatalf("second redeem: %v", err)
	}
	if red2.Token == red.Token || red2.Session.ID == red.Session.ID {
		t.Fatal("each redemption must mint a fresh, single-use credential")
	}
}

func TestAuthenticateRejectsEveryWrongCredentialTheSameWay(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	b, _ := newBroker(t, &now)
	mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app")})

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	if _, err := b.Authenticate(red.Session.ID, red.Token); err != nil {
		t.Fatalf("the minted credential must authenticate: %v", err)
	}
	for _, tc := range []struct {
		name, id, token string
	}{
		{"unknown session", "sess_nope", red.Token},
		{"wrong token", red.Session.ID, strings.Repeat("0", TokenBytes*2)},
		{"empty token", red.Session.ID, ""},
		{"swapped", red.Token, red.Session.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := b.Authenticate(tc.id, tc.token); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("want ErrUnauthenticated, got %v", err)
			}
		})
	}
}

func TestRedeemRequiresAMatchingActiveGrant(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	t.Run("no grant at all", func(t *testing.T) {
		b, _ := newBroker(t, &now)
		_, err := b.Redeem(context.Background(), RedeemRequest{
			Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
		})
		if !errors.Is(err, ErrNoGrant) {
			t.Fatalf("want ErrNoGrant, got %v", err)
		}
	})

	t.Run("grant for a different project", func(t *testing.T) {
		b, _ := newBroker(t, &now)
		mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/other")})
		_, err := b.Redeem(context.Background(), RedeemRequest{
			Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
		})
		if !errors.Is(err, ErrNoGrant) {
			t.Fatalf("want ErrNoGrant, got %v", err)
		}
	})

	t.Run("expired grant is refused and audited", func(t *testing.T) {
		local := now
		b, audit := newBroker(t, &local)
		mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})

		local = local.Add(2 * time.Hour)
		_, err := b.Redeem(context.Background(), RedeemRequest{
			Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
		})
		if !errors.Is(err, ErrNoGrant) {
			t.Fatalf("want ErrNoGrant, got %v", err)
		}
		// A grant that was *aimed at* this requester and refused must leave a
		// row, or "the sandbox has no network" is undebuggable.
		var sawExpiry bool
		for _, ev := range audit.all() {
			if ev.Action == secretbroker.ActionEgressRedeem &&
				ev.Decision == secretbroker.DecisionDeny &&
				strings.Contains(ev.Reason, "expired") {
				sawExpiry = true
			}
		}
		if !sawExpiry {
			t.Errorf("expected an audited expiry denial, got:\n%s", renderEvents(audit.all()))
		}
	})

	t.Run("label subject matches on executor labels", func(t *testing.T) {
		b, _ := newBroker(t, &now)
		mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "label:region=eu")})

		if _, err := b.Redeem(context.Background(), RedeemRequest{
			Requester: secretbroker.Requester{ExecutorID: "edge-1", Labels: map[string]string{"region": "eu"}},
		}); err != nil {
			t.Fatalf("a matching label should redeem: %v", err)
		}
		if _, err := b.Redeem(context.Background(), RedeemRequest{
			Requester: secretbroker.Requester{ExecutorID: "edge-2", Labels: map[string]string{"region": "us"}},
		}); !errors.Is(err, ErrNoGrant) {
			t.Fatalf("a non-matching label must not redeem, got %v", err)
		}
	})
}

func TestRevokeClosesSessionsAndBlocksRedemption(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	b, audit := newBroker(t, &now)
	g := mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app")})

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	if err := b.Revoke(context.Background(), g.ID, "op"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !red.Session.Closed() {
		t.Fatal("revocation must close the live session; a brokered capability can be recalled")
	}
	if _, err := b.Authenticate(red.Session.ID, red.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a revoked session must not authenticate, got %v", err)
	}
	if _, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
	}); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("a revoked grant must not be redeemable, got %v", err)
	}

	// Idempotent.
	if err := b.Revoke(context.Background(), g.ID, "op"); err != nil {
		t.Fatalf("second revoke should succeed: %v", err)
	}
	if err := b.Revoke(context.Background(), "egress_missing", "op"); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("want ErrGrantNotFound, got %v", err)
	}

	var sawClose bool
	for _, ev := range audit.all() {
		if ev.Action == secretbroker.ActionEgressClose {
			sawClose = true
		}
	}
	if !sawClose {
		t.Errorf("closing a session must be audited, got:\n%s", renderEvents(audit.all()))
	}
}

func TestSessionTTLIsClampedByTheBrokerCeiling(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	b, _ := newBroker(t, &now, WithMaxSessionTTL(5*time.Minute))
	mustGrant(t, b, GrantRequest{
		Subject:    mustSubject(t, "project:/srv/app"),
		SessionTTL: 3 * time.Hour,
		TTL:        24 * time.Hour,
	})

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if want := now.Add(5 * time.Minute); !red.Session.ExpiresAt.Equal(want) {
		t.Fatalf("session expires %s, want the broker ceiling %s", red.Session.ExpiresAt, want)
	}
}

// TestMaxSessionTTLOptionIsItselfBounded: a config typo must not be able to
// mint an all-day credential.
func TestMaxSessionTTLOptionIsItselfBounded(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	b, _ := newBroker(t, &now, WithMaxSessionTTL(72*time.Hour))
	mustGrant(t, b, GrantRequest{
		Subject:    mustSubject(t, "project:/srv/app"),
		SessionTTL: 72 * time.Hour,
		TTL:        365 * 24 * time.Hour,
	})

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if got := red.Session.ExpiresAt.Sub(now); got > MaxSessionTTLCeiling {
		t.Fatalf("session TTL %s exceeds the hard ceiling %s", got, MaxSessionTTLCeiling)
	}
}

func TestReapExpiredRetiresIdleSessions(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	local := now
	b, _ := newBroker(t, &local, WithMaxSessionTTL(time.Minute))
	mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if n := b.ReapExpired(); n != 0 {
		t.Fatalf("nothing should be reaped yet, got %d", n)
	}

	local = local.Add(2 * time.Minute)
	if n := b.ReapExpired(); n != 1 {
		t.Fatalf("reaped %d sessions, want 1", n)
	}
	if !red.Session.Closed() {
		t.Error("a reaped session must be marked closed")
	}
	if len(b.Sessions()) != 0 {
		t.Error("a reaped session must leave the registry")
	}
}

func TestRedemptionEnvIsCompleteAndBothCases(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	b, _ := newBroker(t, &now)
	mustGrant(t, b, GrantRequest{
		Subject: mustSubject(t, "project:/srv/app"),
		Hosts:   []string{"api.example.com"},
		CIDRs:   []string{"10.0.0.0/8"},
	})

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	env := red.Env()

	// Both cases of each variable: the ecosystem never agreed which to read,
	// and setting only one produces a sandbox whose tools half-ignore the
	// proxy — which in a --network=none sandbox looks like a network fault.
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"} {
		if env[k] == "" {
			t.Errorf("%s is unset", k)
		}
	}
	if env["HTTP_PROXY"] != red.ProxyURL || env["https_proxy"] != red.ProxyURL {
		t.Error("proxy variables must all name the same endpoint")
	}
	if !strings.Contains(env["NO_PROXY"], "127.0.0.1") {
		t.Errorf("NO_PROXY should keep loopback local, got %q", env["NO_PROXY"])
	}
	if env["CLOOP_EGRESS_ALLOW"] != "api.example.com" {
		t.Errorf("allowlist should be advertised, got %q", env["CLOOP_EGRESS_ALLOW"])
	}
	if env["CLOOP_EGRESS_ALLOW_CIDRS"] != "10.0.0.0/8" {
		t.Errorf("CIDRs should be advertised, got %q", env["CLOOP_EGRESS_ALLOW_CIDRS"])
	}

	lines := red.EnvLines()
	if len(lines) != len(env) {
		t.Fatalf("EnvLines produced %d entries for %d variables", len(lines), len(env))
	}
	for i := 1; i < len(lines); i++ {
		if lines[i-1] >= lines[i] {
			t.Fatalf("EnvLines must be sorted for a stable executor spec: %q then %q", lines[i-1], lines[i])
		}
	}
}

func TestBuildProxyURLEscapesTheCredential(t *testing.T) {
	url, err := buildProxyURL("host.containers.internal:8899", "sess_abc", "0123abcd")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if url != "http://sess_abc:0123abcd@host.containers.internal:8899" {
		t.Fatalf("url = %q", url)
	}
	// An https endpoint is forced back to http: the proxy hop is cleartext
	// and the confidentiality comes from the tunnelled TLS. Leaving it would
	// produce a certificate error nobody can explain.
	if got, _ := buildProxyURL("https://proxy.internal:8899", "id", "tok"); !strings.HasPrefix(got, "http://") {
		t.Errorf("scheme should be forced to http, got %q", got)
	}
	if _, err := buildProxyURL("", "id", "tok"); err == nil {
		t.Error("an empty endpoint must be an error, not a URL nothing can reach")
	}
}

func TestGrantValidationFailureIsNotAuditedAsADenial(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	b, audit := newBroker(t, &now)

	// No hosts and no CIDRs: a typo, not a security decision.
	if _, err := b.Grant(context.Background(), GrantRequest{
		Subject: mustSubject(t, "project:/srv/app"),
	}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("want ErrInvalidGrant, got %v", err)
	}
	for _, ev := range audit.all() {
		if ev.Decision == secretbroker.DecisionDeny {
			t.Errorf("a malformed request must not become a denial row: %s", ev.Fields())
		}
	}
}

func TestListGrantsFilters(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	local := now
	b, _ := newBroker(t, &local)

	a := mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
	local = local.Add(time.Second)
	other := mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/other"), TTL: 10 * time.Hour})

	all, err := b.ListGrants(GrantFilter{})
	if err != nil || len(all) != 2 {
		t.Fatalf("ListGrants = %d grants (%v), want 2", len(all), err)
	}
	if all[0].ID != other.ID {
		t.Error("listings should be newest-first")
	}

	bySubject, err := b.ListGrants(GrantFilter{Subject: "project:/srv/app"})
	if err != nil || len(bySubject) != 1 || bySubject[0].ID != a.ID {
		t.Fatalf("subject filter returned %v (%v)", bySubject, err)
	}

	local = local.Add(2 * time.Hour)
	active, err := b.ListGrants(GrantFilter{ActiveOnly: true})
	if err != nil || len(active) != 1 || active[0].ID != other.ID {
		t.Fatalf("active filter returned %d grants (%v), want only the unexpired one", len(active), err)
	}
	// The expired one is still visible without the filter — an audit reader
	// needs the rows a policy filter drops.
	if listed, _ := b.ListGrants(GrantFilter{}); len(listed) != 2 {
		t.Error("an expired grant must remain listable")
	}
}

func TestCloseSessionIsIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	b, audit := newBroker(t, &now)
	mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app")})

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	b.CloseSession(red.Session.ID, "done")
	b.CloseSession(red.Session.ID, "done again")
	b.CloseSession("sess_never_existed", "nothing")

	var closes int
	for _, ev := range audit.all() {
		if ev.Action == secretbroker.ActionEgressClose {
			closes++
		}
	}
	if closes != 1 {
		t.Fatalf("recorded %d close rows, want exactly 1", closes)
	}
}

func TestMemStoreRevocationIsAStampNotADelete(t *testing.T) {
	s := NewMemStore()
	at := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	if err := s.PutGrant(Grant{ID: "g1", Hosts: []string{"*"}}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.RevokeGrant("g1", at); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	g, err := s.GetGrant("g1")
	if err != nil {
		t.Fatalf("a revoked grant must remain readable: %v", err)
	}
	if !g.RevokedAt.Equal(at) {
		t.Errorf("revoked_at = %s, want %s", g.RevokedAt, at)
	}
	// A second revoke must not move the stamp: the moment access was
	// withdrawn is a fact.
	if err := s.RevokeGrant("g1", at.Add(time.Hour)); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	g, _ = s.GetGrant("g1")
	if !g.RevokedAt.Equal(at) {
		t.Errorf("revocation timestamp moved to %s", g.RevokedAt)
	}
	if err := s.RevokeGrant("missing", at); !errors.Is(err, ErrGrantNotFound) {
		t.Errorf("want ErrGrantNotFound, got %v", err)
	}
}
