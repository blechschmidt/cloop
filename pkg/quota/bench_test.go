package quota

// Benchmarks for admission, which runs on every request that consumes a
// quotable resource and therefore sits in front of the whole hub.
//
// Two things make this worth measuring rather than assuming. Admit is a single
// critical section — check-and-increment under one mutex, as
// TestConcurrentAdmissionNeverOverAdmits requires — so every admitted request
// on a multi-tenant hub serialises here. And limit resolution walks the
// binding list per call, so the cost depends on how many bindings an operator
// configured, which is exactly the sort of thing that is cheap in a
// single-tenant test and not cheap in the deployment it was written for.
//
// No latency assertion: see the note in pkg/statedb/bench_test.go.

import (
	"fmt"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// benchSubject builds a distinct identity, with group membership, so that
// per-identity accounting maps grow the way they do under real tenancy rather
// than collapsing onto one key.
func benchSubject(i int) *authz.Subject {
	return &authz.Subject{
		Sub:    fmt.Sprintf("u-%d", i),
		Email:  fmt.Sprintf("user%d@example.com", i),
		Groups: []string{fmt.Sprintf("team-%d", i%16), "engineering"},
	}
}

// benchConfig builds a config with n group bindings on top of defaults —
// the shape of a real multi-tenant deployment, where each team gets its own
// ceiling and resolution has to find the right one.
func benchConfig(bindings int) Config {
	cfg := Config{
		Defaults: Limits{
			ResProjects:        50,
			ResConcurrentTasks: 8,
			ResSessions:        10,
			ResDailyTokens:     5_000_000,
		},
	}
	for i := 0; i < bindings; i++ {
		cfg.Bindings = append(cfg.Bindings, Binding{
			Claim: authz.ClaimGroup,
			Value: fmt.Sprintf("team-%d", i),
			Limits: Limits{
				ResConcurrentTasks: float64(4 + i%12),
				ResDailyTokens:     float64(1_000_000 + i*1000),
			},
		})
	}
	return cfg
}

func benchEnforcer(b *testing.B, bindings int) *Enforcer {
	b.Helper()
	r, err := New(benchConfig(bindings))
	if err != nil {
		b.Fatalf("quota.New: %v", err)
	}
	// nil store: the persistence path is statedb's, and benchmarking it here
	// would measure SQLite rather than admission. pkg/statedb/bench_test.go
	// covers the storage side.
	return NewEnforcer(r, nil)
}

// BenchmarkAdmit measures the admission decision itself, against a
// counter-style resource with headroom so every call takes the admit path.
//
// Varying the binding count is the measurement that matters: 0 is the
// single-tenant hub this feature had to not disturb, 64 is an enterprise
// deployment with a binding per team. If resolution is a linear walk the two
// diverge, and this says by how much.
func BenchmarkAdmit(b *testing.B) {
	for _, bindings := range []int{0, 8, 64} {
		b.Run(fmt.Sprintf("bindings=%d", bindings), func(b *testing.B) {
			e := benchEnforcer(b, bindings)
			subj := benchSubject(1)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// A daily-token budget rather than a concurrency slot: slots
				// would be exhausted after the first few iterations and the
				// rest of the run would measure the denial path, which is not
				// the one that gates throughput.
				if _, err := e.Admit(subj, ResDailyTokens, 1); err != nil {
					b.Fatalf("Admit: %v", err)
				}
			}
		})
	}
}

// BenchmarkAdmitDistinctIdentities admits on behalf of a rotating set of
// tenants, which is what a shared hub actually does.
//
// A single-identity benchmark keeps one map entry hot and says nothing about
// how accounting behaves once the identity count is in the thousands — the
// case where a per-identity map that is never pruned shows up as memory
// rather than as latency. ReportAllocs is the useful column here.
func BenchmarkAdmitDistinctIdentities(b *testing.B) {
	const identities = 1000
	e := benchEnforcer(b, 16)
	subjects := make([]*authz.Subject, identities)
	for i := range subjects {
		subjects[i] = benchSubject(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Admit(subjects[i%identities], ResDailyTokens, 1); err != nil {
			b.Fatalf("Admit: %v", err)
		}
	}
}

// BenchmarkAdmitParallel measures admission under contention, which is the
// number that matters for a hub serving concurrent tenants.
//
// Admit has to be a single critical section to be correct, so this is
// expected to be worse than the serial case; what it guards against is that
// gap widening — a lock held across something newly expensive (a query, an
// allocation, a log write) turns every concurrent request into a queue.
func BenchmarkAdmitParallel(b *testing.B) {
	const identities = 256
	e := benchEnforcer(b, 16)
	subjects := make([]*authz.Subject, identities)
	for i := range subjects {
		subjects[i] = benchSubject(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := e.Admit(subjects[i%identities], ResDailyTokens, 1); err != nil {
				b.Fatalf("Admit: %v", err)
			}
			i++
		}
	})
}

// BenchmarkAdmitDenied measures the rejection path.
//
// Worth its own benchmark because it is the path a tenant hitting their
// ceiling takes on *every* subsequent request — the one case where the
// expensive branch is also the most frequently taken one. Building a Denial
// with its remediation text on each call would show up here.
func BenchmarkAdmitDenied(b *testing.B) {
	r, err := New(Config{Defaults: Limits{ResConcurrentTasks: 1}})
	if err != nil {
		b.Fatalf("quota.New: %v", err)
	}
	e := NewEnforcer(r, nil)
	subj := benchSubject(1)
	if _, err := e.Admit(subj, ResConcurrentTasks, 1); err != nil {
		b.Fatalf("seed Admit: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Admit(subj, ResConcurrentTasks, 1); err == nil {
			b.Fatal("Admit succeeded past the limit — the cap was breached")
		}
	}
}
