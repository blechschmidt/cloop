package oidcauth

// Benchmarks for the authentication hot path and the claim-freshness gate in
// front of it (Task 20273).
//
// Bounded authorization staleness works by putting a potential round trip to
// the identity provider in front of privileged operations. The whole design
// rests on that cost never reaching a read, so these measure the two sides of
// the claim:
//
//	SessionFromRequest       every authenticated request, on every hub
//	ClaimsStale              the predicate the gate evaluates first
//	EnsureFreshClaims/fresh  the gate when claims are inside the bound, which
//	                         is every privileged call but the first in each
//	                         max_claim_age window
//
// The number that matters is the relationship between them, not any absolute:
// the freshness predicate is two time comparisons and must not show up against
// a session lookup, and the fresh path of the gate must cost one store read
// rather than anything resembling a network call. If EnsureFreshClaims/fresh
// ever lands within an order of magnitude of EnsureFreshClaims/stale — which
// deliberately contacts a local httptest IdP — something has started calling
// out when it should not.
//
// No latency assertion, matching pkg/ui/bench_test.go and pkg/statedb: these
// are a tripwire for a change in shape, read by a human comparing two runs, not
// a gate that fails CI on a noisy machine.

import (
	"context"
	"testing"
	"time"
)

// benchAuth builds an authenticator over the in-memory store with a fixed
// clock, so nothing here depends on wall time advancing mid-run.
func benchAuth(b *testing.B, idp *fakeIdP, maxClaimAge time.Duration) (*Authenticator, *clock) {
	b.Helper()
	clk := newClock()
	a, err := New(Config{
		Enabled:      true,
		Issuer:       idp.server.URL,
		ClientID:     "cloop-dashboard",
		ClientSecret: "s3cret",
		RedirectURL:  "https://cloop.example.com/auth/callback",
		SessionTTL:   24 * time.Hour,
		IdleTimeout:  8 * time.Hour,
		// Background revalidation off: a ticking janitor would add noise that
		// has nothing to do with what is being measured.
		RefreshInterval: -1,
		MaxClaimAge:     maxClaimAge,
		Store:           NewMemorySessionStore(0),
		Clock:           clk.now,
	})
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	return a, clk
}

func benchSession(b *testing.B, a *Authenticator, refreshToken string) string {
	b.Helper()
	sid, err := a.createSession(
		Identity{Sub: "u1", Email: "alice@example.com", Groups: []string{"admins", "engineering"}},
		reqWithCookie("seed"), refreshToken, &tokenResponse{ExpiresIn: 3600})
	if err != nil {
		b.Fatalf("createSession: %v", err)
	}
	return sid
}

// BenchmarkAuthenticatedReadPath is the authenticated read path with a warm
// cache: cookie hash, cache hit, two clock comparisons, throttled idle touch.
//
// This is the measurement the claim-freshness work is accountable to. It runs
// on every request a signed-in user makes, and Task 20273 must not appear in it
// at all — nothing here consults a claim timestamp, and if a future change
// moves the gate onto this path, this is the line where it shows up.
func BenchmarkAuthenticatedReadPath(b *testing.B) {
	idp := newFakeIdP(b)
	a, _ := benchAuth(b, idp, 5*time.Minute)
	sid := benchSession(b, a, "rt-1")

	req := reqWithCookie(sid)
	a.SessionFromRequest(req) // warm the cache

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := a.SessionFromRequest(req); !ok {
			b.Fatal("session must authenticate")
		}
	}
}

// BenchmarkClaimsStale isolates the predicate the gate consults before
// anything else. It is two time comparisons on a value receiver; the number is
// here so a future version that starts allocating, or reaches for the store, is
// visible against this line rather than only in a profile.
func BenchmarkClaimsStale(b *testing.B) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rec := SessionRecord{
		IssuedAt:       now.Add(-time.Hour),
		ClaimsAsOf:     now.Add(-time.Minute),
		ClaimsExpireAt: now.Add(time.Hour),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if rec.ClaimsStale(now, 5*time.Minute) {
			b.Fatal("claims are inside both deadlines")
		}
	}
}

// BenchmarkEnsureFreshClaims measures the gate in both of its states.
//
//	fresh  claims inside the bound: one store read, no network. This is what a
//	       burst of admin calls pays, and it is the number that decides whether
//	       gating privileged operations is affordable.
//	stale  claims outside it: a real refresh grant against a local httptest
//	       provider, so the figure is a floor for the real thing rather than an
//	       estimate of it. A production IdP over a network is far worse, which
//	       is exactly why this cost is kept off read paths and single-flighted.
//
// The stale case resets the clock each iteration rather than letting claims go
// fresh, so every iteration genuinely performs the round trip.
func BenchmarkEnsureFreshClaims(b *testing.B) {
	b.Run("fresh", func(b *testing.B) {
		idp := newFakeIdP(b)
		a, _ := benchAuth(b, idp, 5*time.Minute)
		id := HashSessionID(benchSession(b, a, "rt-1"))

		ctx := context.Background()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := a.EnsureFreshClaims(ctx, id); err != nil {
				b.Fatalf("EnsureFreshClaims: %v", err)
			}
		}
		b.StopTimer()
		if idp.refreshRequests != 0 {
			b.Fatalf("the fresh path made %d IdP round trips, want 0", idp.refreshRequests)
		}
	})

	b.Run("stale", func(b *testing.B) {
		idp := newFakeIdP(b)
		idp.refreshIDToken = func(int) map[string]any {
			return idp.refreshClaims(map[string]any{"groups": []string{"admins"}})
		}
		a, clk := benchAuth(b, idp, 5*time.Minute)
		id := HashSessionID(benchSession(b, a, "rt-1"))

		ctx := context.Background()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			clk.advance(6 * time.Minute)
			b.StartTimer()
			if _, err := a.EnsureFreshClaims(ctx, id); err != nil {
				b.Fatalf("EnsureFreshClaims: %v", err)
			}
		}
	})
}

// BenchmarkEnsureFreshClaimsConcurrent measures the fresh path under the
// concurrency a real dashboard produces: several privileged requests landing at
// once from one administrator's open panels.
//
// It is the parallel counterpart to the fresh case above, and what it guards is
// the mutex discipline: the fresh path must not take flightMu at all, so adding
// goroutines should not bend the per-op cost. If it does, the gate has become a
// serialisation point in front of every privileged request on the hub.
func BenchmarkEnsureFreshClaimsConcurrent(b *testing.B) {
	idp := newFakeIdP(b)
	a, _ := benchAuth(b, idp, 5*time.Minute)
	id := HashSessionID(benchSession(b, a, "rt-1"))

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := a.EnsureFreshClaims(ctx, id); err != nil {
				b.Fatalf("EnsureFreshClaims: %v", err)
			}
		}
	})
}
