package quota

// The properties that make a quota a quota rather than a suggestion.
//
// The headline one is concurrent admission: N goroutines racing for K slots
// must produce exactly K admissions, no matter how the scheduler interleaves
// them. Run under -race, this is what proves check-and-increment is a single
// critical section rather than a read followed by a hopeful write.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
)

func alice() *authz.Subject {
	return &authz.Subject{Sub: "u-1", Email: "alice@example.com", Groups: []string{"engineering"}}
}

func mustResolver(t *testing.T, cfg Config) *Resolver {
	t.Helper()
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("quota.New: %v", err)
	}
	return r
}

// ── admission ───────────────────────────────────────────────────────────────

// TestConcurrentAdmissionNeverOverAdmits is the load-bearing test. Every
// goroutine asks for a slot at once; exactly `limit` may win.
//
// A read-then-write implementation passes this by luck at low concurrency and
// fails under -race, which is why the counts are asserted rather than the
// absence of a panic: over-admission is silent, and the only way to see it is
// to count.
func TestConcurrentAdmissionNeverOverAdmits(t *testing.T) {
	t.Parallel()

	const (
		limit   = 4
		callers = 200
	)
	e := NewEnforcer(mustResolver(t, Config{
		Defaults: Limits{ResConcurrentTasks: limit},
	}), nil)

	var admitted, denied atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release everyone at once to maximise the interleaving
			if _, err := e.Admit(alice(), ResConcurrentTasks, 1); err != nil {
				denied.Add(1)
				return
			}
			admitted.Add(1)
		}()
	}
	close(start)
	wg.Wait()

	if got := admitted.Load(); got != limit {
		t.Fatalf("admitted %d of %d callers against a limit of %d — the cap was breached",
			got, callers, limit)
	}
	if got := denied.Load(); got != callers-limit {
		t.Errorf("denied %d, want %d", got, callers-limit)
	}
	if used := e.Usage("alice@example.com")[ResConcurrentTasks]; used != limit {
		t.Errorf("counter reads %v after the race, want %d", used, limit)
	}
}

// TestConcurrentAdmitAndReleaseIsBalanced runs the full lifecycle
// concurrently: the counter must land exactly on zero, never negative and
// never stuck high. A release that raced an admit and lost would leak a slot.
func TestConcurrentAdmitAndReleaseIsBalanced(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{
		Defaults: Limits{ResConcurrentTasks: 8},
	}), nil)

	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.Admit(alice(), ResConcurrentTasks, 1); err != nil {
				return // denied: nothing to release
			}
			e.Release("alice@example.com", ResConcurrentTasks, 1)
		}()
	}
	wg.Wait()

	if used := e.Usage("alice@example.com")[ResConcurrentTasks]; used != 0 {
		t.Fatalf("counter is %v after every admission was released, want 0", used)
	}
}

// TestReleaseClampsAtZero: a double release — a run that reports completion
// twice — must not mint headroom the tenant never had.
func TestReleaseClampsAtZero(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResProjects: 2}}), nil)
	if _, err := e.Admit(alice(), ResProjects, 1); err != nil {
		t.Fatalf("first admit: %v", err)
	}
	e.Release("alice@example.com", ResProjects, 1)
	e.Release("alice@example.com", ResProjects, 1) // the buggy caller
	e.Release("alice@example.com", ResProjects, 1)

	if used := e.Usage("alice@example.com")[ResProjects]; used != 0 {
		t.Fatalf("usage is %v after over-release, want 0 — a negative counter is free quota", used)
	}
	// And the cap must still hold at exactly 2, not 2 plus the over-releases.
	for i := 0; i < 2; i++ {
		if _, err := e.Admit(alice(), ResProjects, 1); err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
	}
	if _, err := e.Admit(alice(), ResProjects, 1); err == nil {
		t.Fatal("third admit succeeded against a limit of 2 — over-release created headroom")
	}
}

// TestDenialCarriesRetryAfterOnlyWhenWaitingHelps. A Retry-After that will
// never come true trains clients to poll a wall.
func TestDenialCarriesRetryAfterOnlyWhenWaitingHelps(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{
		ResConcurrentTasks: 0,
		ResProjects:        0,
		ResExecutors:       0,
		ResDailyTokens:     0,
	}}), nil)

	cases := []struct {
		res       Resource
		transient bool
	}{
		{ResConcurrentTasks, true}, // a run will finish
		{ResDailyTokens, true},     // the UTC day will roll over
		{ResProjects, false},       // somebody must delete one
		{ResExecutors, false},      // somebody must revoke one
	}
	for _, tc := range cases {
		_, err := e.Admit(alice(), tc.res, 1)
		d, ok := err.(*Denial)
		if !ok {
			t.Fatalf("%s: want *Denial, got %v", tc.res, err)
		}
		if d.Transient() != tc.transient {
			t.Errorf("%s: Transient() = %v (retry_after %v), want %v",
				tc.res, d.Transient(), d.RetryAfter, tc.transient)
		}
	}
}

// TestDailyBudgetRollsOverAtUTCMidnight: yesterday's spend is history, not
// headroom, and today's must start clean without any scheduled job running.
func TestDailyBudgetRollsOverAtUTCMidnight(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 22, 23, 59, 0, 0, time.UTC)
	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResDailyTokens: 1000}}), nil,
		WithClock(func() time.Time { return now }))

	e.Spend("alice@example.com", 1000, 0)
	if err := e.CheckSpend(alice()); err == nil {
		t.Fatal("CheckSpend allowed a run after the budget was spent")
	}

	now = now.Add(2 * time.Minute) // past midnight UTC
	if err := e.CheckSpend(alice()); err != nil {
		t.Fatalf("CheckSpend still refuses after the day rolled over: %v", err)
	}
	if used := e.Usage("alice@example.com")[ResDailyTokens]; used != 0 {
		t.Errorf("today's counter reads %v, want 0 — yesterday's spend leaked forward", used)
	}
}

// ── resolution ──────────────────────────────────────────────────────────────

// TestMostSpecificBindingWinsPerResource: precedence is per-resource, so a
// narrow binding that sets one ceiling must not blank out the others.
func TestMostSpecificBindingWinsPerResource(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, Config{
		Defaults: Limits{ResProjects: 1, ResConcurrentTasks: 1},
		Bindings: []Binding{
			{Claim: authz.ClaimGroup, Value: "engineering",
				Limits: Limits{ResProjects: 10, ResConcurrentTasks: 3}},
			{Claim: authz.ClaimEmail, Value: "alice@example.com",
				Limits: Limits{ResProjects: 25}}, // says nothing about concurrency
		},
	})
	eff := r.Resolve(alice(), nil)

	if got, _ := eff.Limit(ResProjects); got != 25 {
		t.Errorf("max_projects = %v, want 25 from the email binding", got)
	}
	if got, _ := eff.Limit(ResConcurrentTasks); got != 3 {
		t.Errorf("max_concurrent_tasks = %v, want 3 — the email binding is silent on it, "+
			"so the group binding should still apply", got)
	}
	if src := eff.Sources[ResProjects]; src != "email:alice@example.com" {
		t.Errorf("provenance for max_projects = %q, want the email binding", src)
	}
}

// TestTieGoesToTheTighterLimit is the escalation guard: within one
// specificity tier, joining another group must never raise your own cap.
func TestTieGoesToTheTighterLimit(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, Config{
		Bindings: []Binding{
			{Claim: authz.ClaimGroup, Value: "engineering", Limits: Limits{ResProjects: 50}},
			{Claim: authz.ClaimGroup, Value: "contractors", Limits: Limits{ResProjects: 2}},
		},
	})
	subj := &authz.Subject{Sub: "u-2", Email: "carol@example.com",
		Groups: []string{"engineering", "contractors"}}

	if got, _ := r.Resolve(subj, nil).Limit(ResProjects); got != 2 {
		t.Fatalf("max_projects = %v for a member of both groups, want 2 — "+
			"taking the larger would let a tenant raise their own cap by joining a group", got)
	}

	// And the answer must not depend on binding order.
	reversed := mustResolver(t, Config{
		Bindings: []Binding{
			{Claim: authz.ClaimGroup, Value: "contractors", Limits: Limits{ResProjects: 2}},
			{Claim: authz.ClaimGroup, Value: "engineering", Limits: Limits{ResProjects: 50}},
		},
	})
	if got, _ := reversed.Resolve(subj, nil).Limit(ResProjects); got != 2 {
		t.Fatalf("max_projects = %v with the bindings reversed, want 2 — "+
			"resolution must not depend on YAML line order", got)
	}
}

// TestOverrideBeatsEveryBinding and clears back to policy on removal.
func TestOverrideBeatsEveryBinding(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{
		Bindings: []Binding{
			{Claim: authz.ClaimSub, Value: "u-1", Limits: Limits{ResProjects: 3}},
		},
	}), nil)

	if got, _ := e.Effective(alice()).Limit(ResProjects); got != 3 {
		t.Fatalf("baseline max_projects = %v, want 3", got)
	}
	if err := e.SetOverride("alice@example.com", Limits{ResProjects: 9}, "admin@example.com"); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}
	eff := e.Effective(alice())
	if got, _ := eff.Limit(ResProjects); got != 9 {
		t.Errorf("max_projects = %v after override, want 9", got)
	}
	if eff.Sources[ResProjects] != "override" {
		t.Errorf("provenance = %q, want override", eff.Sources[ResProjects])
	}

	if existed, err := e.ClearOverride("alice@example.com"); err != nil || !existed {
		t.Fatalf("ClearOverride = (%v, %v), want (true, nil)", existed, err)
	}
	if got, _ := e.Effective(alice()).Limit(ResProjects); got != 3 {
		t.Errorf("max_projects = %v after clearing, want the policy's 3", got)
	}
}

// TestNoPolicyAdmitsEverything: the single-tenant hub must be untouched.
func TestNoPolicyAdmitsEverything(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{}), nil)
	if e.Enabled() {
		t.Error("Enabled() is true with no policy and no overrides")
	}
	for i := 0; i < 100; i++ {
		if _, err := e.Admit(alice(), ResConcurrentTasks, 1); err != nil {
			t.Fatalf("admission %d refused with no policy configured: %v", i, err)
		}
	}
}

// TestAnonymousIsNotAccounted: with RBAC off there is no tenant to charge,
// and charging a shared "" identity would let one local user's runs deny
// another's.
func TestAnonymousIsNotAccounted(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResConcurrentTasks: 1}}), nil)
	for i := 0; i < 5; i++ {
		if _, err := e.Admit(nil, ResConcurrentTasks, 1); err != nil {
			t.Fatalf("nil subject admission %d refused: %v", i, err)
		}
	}
	if used := e.Usage("anonymous")[ResConcurrentTasks]; used != 0 {
		t.Errorf("anonymous accrued %v — quotas must not account an unidentified caller", used)
	}
}

// TestSessionAdmissionEvictsRatherThanRefuses. The number returned is how
// many of the identity's existing sessions must go to make room for one more.
func TestSessionAdmissionEvictsRatherThanRefuses(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResSessions: 3}}), nil)
	for _, tc := range []struct{ existing, evict int }{
		{0, 0}, {1, 0}, {2, 0},
		{3, 1}, // at the cap: drop one to fit the new session
		{5, 3}, // over the cap (a lowered quota): drop back to 2 + the new one
	} {
		if got := e.SessionAdmission(alice(), tc.existing); got != tc.evict {
			t.Errorf("SessionAdmission(existing=%d) = %d, want %d", tc.existing, got, tc.evict)
		}
	}

	// Unlimited by policy means never evict.
	none := NewEnforcer(mustResolver(t, Config{}), nil)
	if got := none.SessionAdmission(alice(), 100); got != 0 {
		t.Errorf("SessionAdmission with no session quota = %d, want 0", got)
	}
}

// ── validation ──────────────────────────────────────────────────────────────

func TestNewRejectsMalformedPolicy(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
	}{
		{"unknown resource in defaults", Config{Defaults: Limits{"max_widgets": 1}}},
		{"unknown claim kind", Config{Bindings: []Binding{
			{Claim: "team", Value: "x", Limits: Limits{ResProjects: 1}}}}},
		{"empty value", Config{Bindings: []Binding{
			{Claim: authz.ClaimGroup, Value: "  ", Limits: Limits{ResProjects: 1}}}}},
		{"binding sets nothing", Config{Bindings: []Binding{
			{Claim: authz.ClaimGroup, Value: "eng"}}}},
		{"unknown resource in a binding", Config{Bindings: []Binding{
			{Claim: authz.ClaimGroup, Value: "eng", Limits: Limits{"max_widgets": 1}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Error("New accepted a malformed policy — a binding that matches nothing " +
					"presents as 'my quota is not being enforced'")
			}
		})
	}
}

// TestNegativeCeilingMeansUnlimited disarms the near-universal convention
// that -1 means "no limit": reading it as a ceiling of -1 would deny every
// request from that tenant with no obvious cause.
func TestNegativeCeilingMeansUnlimited(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResProjects: -1}}), nil)
	if _, ok := e.Effective(alice()).Limit(ResProjects); ok {
		t.Fatal("a negative ceiling resolved to a real limit — -1 must mean unlimited")
	}
	for i := 0; i < 20; i++ {
		if _, err := e.Admit(alice(), ResProjects, 1); err != nil {
			t.Fatalf("admission %d refused under an 'unlimited' ceiling: %v", i, err)
		}
	}
}

// ── reconciliation ──────────────────────────────────────────────────────────

// TestReconcileRebuildsGaugesFromLiveState is the restart property: a counter
// left behind by a crash is erased by what actually exists, not decremented
// by something that no longer runs.
func TestReconcileRebuildsGaugesFromLiveState(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResConcurrentTasks: 2}}), store)

	// Two runs were in flight when the hub died.
	for i := 0; i < 2; i++ {
		if _, err := e.Admit(alice(), ResConcurrentTasks, 1); err != nil {
			t.Fatalf("pre-crash admit %d: %v", i, err)
		}
	}
	if _, err := e.Admit(alice(), ResConcurrentTasks, 1); err == nil {
		t.Fatal("the cap was not holding before the simulated crash")
	}

	// Restart: same store, fresh enforcer. The counters come back...
	restarted := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResConcurrentTasks: 2}}), store)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if used := restarted.Usage("alice@example.com")[ResConcurrentTasks]; used != 2 {
		t.Fatalf("after restart the counter reads %v, want the persisted 2", used)
	}
	// ...and without reconciliation the tenant would be starved forever,
	// because nothing decrements a slot for a process that no longer exists.
	if _, err := restarted.Admit(alice(), ResConcurrentTasks, 1); err == nil {
		t.Fatal("expected the stale counter to still refuse before reconciliation")
	}

	// Reconcile against the truth: no runs are actually in flight.
	if err := restarted.Reconcile(LiveState{
		Projects: map[string]float64{"alice@example.com": 1},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if used := restarted.Usage("alice@example.com")[ResConcurrentTasks]; used != 0 {
		t.Fatalf("concurrent-task counter is %v after reconciliation, want 0 — "+
			"the crash left a slot held by a process that no longer exists", used)
	}
	if used := restarted.Usage("alice@example.com")[ResProjects]; used != 1 {
		t.Errorf("project counter is %v, want the 1 live state reported", used)
	}

	// The reconciliation must have reached storage too, or the next restart
	// resurrects the ghost. Asserted before the admission below, which
	// legitimately writes a fresh concurrent-task gauge of its own.
	gauges := store.gauges()
	if _, stale := gauges[ResConcurrentTasks]; stale {
		t.Error("a stale concurrent-task gauge survived in the store after ReplaceGauges")
	}
	if gauges[ResProjects] != 1 {
		t.Errorf("persisted project gauge = %v, want 1", gauges[ResProjects])
	}

	if _, err := restarted.Admit(alice(), ResConcurrentTasks, 1); err != nil {
		t.Fatalf("admission still refused after reconciliation: %v", err)
	}
}

// TestReconcileLeavesDailySpendAlone: re-deriving spend on every restart
// would hand a compromised account a fresh budget each time it crashed the
// hub.
func TestReconcileLeavesDailySpendAlone(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResDailyTokens: 500}}), store)
	e.Spend("alice@example.com", 500, 1.25)

	restarted := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResDailyTokens: 500}}), store)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := restarted.Reconcile(LiveState{}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	usage := restarted.Usage("alice@example.com")
	if usage[ResDailyTokens] != 500 {
		t.Fatalf("token spend is %v after restart+reconcile, want the recorded 500 — "+
			"a restart must not refund a budget", usage[ResDailyTokens])
	}
	if usage[ResDailyCostUSD] != 1.25 {
		t.Errorf("cost spend is %v, want 1.25", usage[ResDailyCostUSD])
	}
	if err := restarted.CheckSpend(alice()); err == nil {
		t.Error("CheckSpend allowed a run after a restart consumed the whole daily budget")
	}
}

// TestOverridesSurviveRestart — an admin edit is policy and must outlive the
// process that received it.
func TestOverridesSurviveRestart(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	e := NewEnforcer(mustResolver(t, Config{}), store)
	if err := e.SetOverride("alice@example.com", Limits{ResProjects: 7}, "admin@example.com"); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}

	restarted := NewEnforcer(mustResolver(t, Config{}), store)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, _ := restarted.Effective(alice()).Limit(ResProjects); got != 7 {
		t.Fatalf("max_projects = %v after restart, want the persisted override of 7", got)
	}
	if !restarted.Enabled() {
		t.Error("an override alone must enable enforcement — an admin who caps one user means it")
	}
}

// TestLoadDropsStaleDayBuckets: a hub restarted the next morning must not
// read yesterday's spend as today's.
func TestLoadDropsStaleDayBuckets(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	store.counters = append(store.counters, CounterRow{
		Identity: "alice@example.com", Resource: ResDailyTokens,
		Bucket: "2020-01-01", Value: 999999,
	})

	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResDailyTokens: 10}}), store)
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if used := e.Usage("alice@example.com")[ResDailyTokens]; used != 0 {
		t.Fatalf("today's token counter reads %v, want 0 — a 2020 bucket was read as today", used)
	}
	if !store.pruned {
		t.Error("Load did not prune stale day buckets — the table grows one row per identity per day")
	}
}

// TestSnapshotCoversEveryKnownIdentity — the admin panel and /metrics both
// read it, and an identity missing from it is a tenant nobody can see.
func TestSnapshotCoversEveryKnownIdentity(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResProjects: 5}}), nil)
	if _, err := e.Admit(alice(), ResProjects, 1); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := e.SetOverride("bob@example.com", Limits{ResProjects: 1}, "admin"); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}

	got := map[string]View{}
	for _, v := range e.Snapshot([]string{"carol@example.com"}) {
		got[v.Identity] = v
	}
	for _, want := range []string{"alice@example.com", "bob@example.com", "carol@example.com"} {
		if _, ok := got[want]; !ok {
			t.Errorf("Snapshot omits %q", want)
		}
	}
	if !got["bob@example.com"].Overridden {
		t.Error("bob's view does not report the override")
	}
	if got["alice@example.com"].Usage[ResProjects] != 1 {
		t.Errorf("alice's project usage = %v, want 1", got["alice@example.com"].Usage[ResProjects])
	}
	if got["carol@example.com"].Usage[ResProjects] != 0 {
		t.Errorf("carol has usage but has consumed nothing")
	}
}

func TestDenialsAreCounted(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{Defaults: Limits{ResProjects: 0}}), nil)
	for i := 0; i < 3; i++ {
		if _, err := e.Admit(alice(), ResProjects, 1); err == nil {
			t.Fatalf("admission %d succeeded against a zero limit", i)
		}
	}
	if got := e.Denials()[ResProjects]; got != 3 {
		t.Fatalf("denial counter = %d, want 3 — a quota silently saturating is invisible", got)
	}
}

// ── an in-memory Store ──────────────────────────────────────────────────────

// memStore is deliberately mutex-guarded: Enforcer calls it while holding its
// own lock, so a race here would surface as a race in the admission tests
// rather than as a clean failure.
type memStore struct {
	mu        sync.Mutex
	overrides map[string]Override
	counters  []CounterRow
	pruned    bool
}

func newMemStore() *memStore {
	return &memStore{overrides: map[string]Override{}}
}

// gauges returns the persisted bucket-"" rows, for asserting what
// reconciliation actually wrote.
func (m *memStore) gauges() map[Resource]float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[Resource]float64{}
	for _, row := range m.counters {
		if row.Bucket == "" {
			out[row.Resource] = row.Value
		}
	}
	return out
}

func (m *memStore) LoadOverrides() ([]Override, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Override, 0, len(m.overrides))
	for _, o := range m.overrides {
		out = append(out, o)
	}
	return out, nil
}

func (m *memStore) PutOverride(o Override) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.overrides[o.Identity] = o
	return nil
}

func (m *memStore) DeleteOverride(identity string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.overrides[identity]
	delete(m.overrides, identity)
	return ok, nil
}

func (m *memStore) LoadCounters() ([]CounterRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CounterRow, len(m.counters))
	copy(out, m.counters)
	return out, nil
}

func (m *memStore) PutCounter(c CounterRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, row := range m.counters {
		if row.Identity == c.Identity && row.Resource == c.Resource && row.Bucket == c.Bucket {
			if c.Value <= 0 {
				m.counters = append(m.counters[:i], m.counters[i+1:]...)
				return nil
			}
			m.counters[i] = c
			return nil
		}
	}
	if c.Value > 0 {
		m.counters = append(m.counters, c)
	}
	return nil
}

func (m *memStore) ReplaceGauges(rows []CounterRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.counters[:0:0]
	for _, row := range m.counters {
		if row.Bucket != "" {
			kept = append(kept, row)
		}
	}
	m.counters = append(kept, rows...)
	return nil
}

func (m *memStore) PruneCountersBefore(bucket string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruned = true
	kept := m.counters[:0:0]
	for _, row := range m.counters {
		if row.Bucket == "" || row.Bucket >= bucket {
			kept = append(kept, row)
		}
	}
	m.counters = kept
	return nil
}

var _ Store = (*memStore)(nil)

// TestSpendAccumulatesPerIdentityAndRollsOverAtUTCMidnight is the enforcer-side
// pair to the hub's booking tests (Task 20264).
//
// Two properties in one, because they interact: counters are keyed by
// (identity, day), so a bug in either half — pooling two tenants into one
// counter, or carrying yesterday's key forward — presents as the other tenant
// or the other day being refused when they should not be.
func TestSpendAccumulatesPerIdentityAndRollsOverAtUTCMidnight(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 14, 23, 59, 0, 0, time.UTC)
	e := NewEnforcer(mustResolver(t, Config{
		Defaults: Limits{ResDailyTokens: 1000, ResDailyCostUSD: 10},
	}), nil, WithClock(func() time.Time { return now }))

	bob := &authz.Subject{Sub: "u-2", Email: "bob@example.com"}

	// Alice spends her whole token budget; Bob spends a little.
	e.Spend("alice@example.com", 600, 4)
	e.Spend("alice@example.com", 400, 3)
	e.Spend("bob@example.com", 50, 0.5)

	if got := e.Usage("alice@example.com")[ResDailyTokens]; got != 1000 {
		t.Errorf("alice's tokens = %v, want the 600+400 she spent", got)
	}
	if got := e.Usage("bob@example.com")[ResDailyTokens]; got != 50 {
		t.Errorf("bob's tokens = %v, want 50 — alice's spend pooled into his counter", got)
	}
	if got := e.Usage("alice@example.com")[ResDailyCostUSD]; got != 7 {
		t.Errorf("alice's usd = %v, want 7", got)
	}

	// Alice is out; Bob is not. A shared counter would refuse them together.
	if err := e.CheckSpend(alice()); err == nil {
		t.Error("alice spent her entire daily token budget and was still admitted")
	}
	if err := e.CheckSpend(bob); err != nil {
		t.Errorf("bob was refused on alice's spending: %v", err)
	}

	// Past UTC midnight both start clean, with no scheduled job having run.
	now = now.Add(2 * time.Minute)
	if err := e.CheckSpend(alice()); err != nil {
		t.Errorf("alice is still refused after the day rolled over: %v", err)
	}
	if got := e.Usage("alice@example.com")[ResDailyTokens]; got != 0 {
		t.Errorf("alice's new-day counter = %v, want 0 — yesterday's spend leaked forward", got)
	}

	// And today's spend accrues to today's bucket, not to yesterday's.
	e.Spend("alice@example.com", 700, 1)
	if got := e.Usage("alice@example.com")[ResDailyTokens]; got != 700 {
		t.Errorf("after the rollover alice's counter = %v, want 700", got)
	}
}

// TestCheckSpendIdentityKeysTheSameCounterSpendWrites is a regression test for
// a bug that made daily budgets unenforceable for every non-email identity.
//
// Spend keys the counter by the identity string. The obvious way to check it
// afterwards — CheckSpend(SubjectForIdentity(id)) — keys by subject.Label(),
// and the two disagree for any identity that is neither an email nor already
// "sub:"-prefixed: SubjectForIdentity("local").Label() is "sub:local". So the
// spend went to one counter and the gate read another, empty one, and the
// budget never applied. That covers the "local" sentinel every unauthenticated
// run is billed to, and any registry owner that is a bare username.
func TestCheckSpendIdentityKeysTheSameCounterSpendWrites(t *testing.T) {
	t.Parallel()

	for _, identity := range []string{"local", "ops-team", "alice@example.com", "sub:u-1"} {
		t.Run(identity, func(t *testing.T) {
			e := NewEnforcer(mustResolver(t, Config{
				Defaults: Limits{ResDailyTokens: 100},
			}), nil)

			if err := e.CheckSpendIdentity(identity); err != nil {
				t.Fatalf("refused before spending anything: %v", err)
			}
			e.Spend(identity, 150, 0)

			if got := e.Usage(identity)[ResDailyTokens]; got != 150 {
				t.Fatalf("Usage(%q) = %v, want the 150 that was spent", identity, got)
			}
			if err := e.CheckSpendIdentity(identity); err == nil {
				t.Fatalf("%q spent 150 against a limit of 100 and was still admitted — "+
					"the spend and the check are keyed differently", identity)
			}
		})
	}
}

// TestCheckSpendIdentityHonoursGroupDerivedLimits: the drain must resolve the
// same ceiling the run was admitted against.
//
// A synthesized subject carries no groups, so resolving through one falls back
// to the defaults. A tenant admitted at run start against a generous group
// budget would then be refused mid-run against a tighter default and have their
// work killed for exceeding a limit that is not theirs.
func TestCheckSpendIdentityHonoursGroupDerivedLimits(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{
		Defaults: Limits{ResDailyTokens: 1000},
		Bindings: []Binding{{
			Claim: authz.ClaimGroup, Value: "engineering",
			Limits: Limits{ResDailyTokens: 1000000},
		}},
	}), nil)

	// alice() is in the "engineering" group. Admission remembers her claims.
	if err := e.CheckSpend(alice()); err != nil {
		t.Fatalf("admission refused alice: %v", err)
	}
	e.Spend("alice@example.com", 5000, 0)

	// 5000 is over the 1000 default and far under her group's 1000000.
	if err := e.CheckSpendIdentity("alice@example.com"); err != nil {
		t.Fatalf("the drain refused alice at %v — it resolved the default limit "+
			"rather than the group binding she was admitted under", err)
	}

	// The binding is genuinely what is carrying her, not an absent limit.
	e.Spend("alice@example.com", 1000000, 0)
	if err := e.CheckSpendIdentity("alice@example.com"); err == nil {
		t.Fatal("alice blew even her group budget and was still admitted")
	}
}

// TestCheckSpendIdentityFindsAnOverrideOnANonEmailIdentity: an admin capping
// "local" must have that cap enforced. Overrides are keyed by identity, and
// resolving them through a synthesized subject's Label() would miss for
// exactly the identities the test above covers.
func TestCheckSpendIdentityFindsAnOverrideOnANonEmailIdentity(t *testing.T) {
	t.Parallel()

	e := NewEnforcer(mustResolver(t, Config{}), nil)
	if err := e.SetOverride("local", Limits{ResDailyTokens: 10}, "admin"); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}

	e.Spend("local", 25, 0)
	if err := e.CheckSpendIdentity("local"); err == nil {
		t.Fatal("an admin's cap on \"local\" was not enforced — the override " +
			"was looked up under a different key than it was stored under")
	}
}
