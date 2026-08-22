package quota

// Admission control: the half of this package that says no.
//
// Every cap is enforced at admission — before the project row is written,
// before the enrolment token is minted, before the run is dispatched — and
// never only in the frontend. A denial is a typed Denial the HTTP layer turns
// into a stable QUOTA_EXCEEDED error, so a scripted client sees the same
// refusal a browser does.
//
// The load-bearing property is that check-and-increment is one critical
// section. Two concurrent run starts against a cap of one must produce one
// admission and one denial, not two admissions, and no amount of retry can
// widen the window because there is no window: the counter is incremented
// under the same lock that read the limit. TestConcurrentAdmissionNeverOver-
// AdmitsUnderRace holds this down.

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// CounterRow is one persisted usage counter.
type CounterRow struct {
	Identity string
	Resource Resource
	// Bucket is the UTC day ("2006-01-02") for daily resources and "" for
	// gauges. Keeping it in the key rather than resetting rows at midnight
	// means a day rollover needs no scheduled job and no clock the process
	// has to stay awake for: yesterday's row simply stops being read.
	Bucket    string
	Value     float64
	UpdatedAt time.Time
}

// Override is one admin's per-identity edit.
type Override struct {
	Identity  string
	Limits    Limits
	UpdatedAt time.Time
	UpdatedBy string
}

// Store persists overrides and counters. The SQLite implementation is
// pkg/quotastore; keeping it behind an interface is what lets this package
// stay free of a driver and lets tests run without a database.
type Store interface {
	// LoadOverrides returns every per-identity override.
	LoadOverrides() ([]Override, error)

	// PutOverride writes (or replaces) one identity's override. Empty
	// limits are stored as an explicit "no overrides" rather than deleting
	// the row, so the admin panel can distinguish "reset to policy" from
	// "never edited".
	PutOverride(o Override) error

	// DeleteOverride removes one identity's override, reporting whether a
	// row existed.
	DeleteOverride(identity string) (bool, error)

	// LoadCounters returns every persisted counter, including stale day
	// buckets; the caller decides which are still current.
	LoadCounters() ([]CounterRow, error)

	// PutCounter writes one counter's value.
	PutCounter(c CounterRow) error

	// ReplaceGauges atomically swaps the whole set of gauge counters
	// (bucket "") for the supplied rows. Used by Reconcile: a per-row
	// update could not delete the rows for identities that no longer hold
	// anything, which is exactly the drift reconciliation exists to remove.
	ReplaceGauges(rows []CounterRow) error

	// PruneCountersBefore deletes daily counters older than bucket.
	PruneCountersBefore(bucket string) error
}

// counterKey identifies one counter in the in-memory table.
type counterKey struct {
	identity string
	resource Resource
	bucket   string
}

// Denial is the typed refusal returned by Admit. It carries everything the
// HTTP layer needs to build the response and everything an operator needs to
// understand the refusal without reading the server log.
type Denial struct {
	Identity  string
	Resource  Resource
	Limit     float64
	Used      float64
	Requested float64

	// RetryAfter is non-zero when waiting alone will clear the denial: a
	// running task will finish, a UTC day will roll over. It is zero when
	// the tenant or an admin must actually do something — delete a project,
	// revoke an executor, raise the cap — because a Retry-After that will
	// never come true trains clients to hammer a wall.
	RetryAfter time.Duration

	// Source is where the breached limit came from, for the error detail.
	Source string
}

// Transient reports whether waiting will clear this denial.
func (d *Denial) Transient() bool { return d != nil && d.RetryAfter > 0 }

func (d *Denial) Error() string {
	return fmt.Sprintf("quota exceeded: %s limit %s reached for %s (in use %s, requested %s)",
		d.Resource, formatAmount(d.Resource, d.Limit), d.Identity,
		formatAmount(d.Resource, d.Used), formatAmount(d.Resource, d.Requested))
}

func formatAmount(r Resource, v float64) string {
	if r.Integral() {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.2f", v)
}

// Usage is one identity's live consumption.
type Usage map[Resource]float64

// View pairs an identity's ceilings with its consumption. It is what the
// admin panel renders and what /metrics exports.
type View struct {
	Identity string              `json:"identity"`
	Limits   Limits              `json:"limits,omitempty"`
	Usage    Usage               `json:"usage"`
	Sources  map[Resource]string `json:"sources,omitempty"`

	// Overridden reports whether an admin has edited this identity, so the
	// panel can offer "reset to policy" only where there is something to
	// reset.
	Overridden bool `json:"overridden"`
}

// Enforcer holds the live counters and decides admissions. Safe for
// concurrent use; the zero value is not usable, call NewEnforcer.
type Enforcer struct {
	resolver *Resolver

	mu        sync.Mutex
	counters  map[counterKey]float64
	overrides map[string]Limits
	// subjects remembers the claims last seen for an identity so the admin
	// panel can resolve group-derived limits for a tenant who is not
	// currently making a request. It is a cache, not a source of truth: a
	// fresh process falls back to synthesizing a subject from the identity
	// key (see subjectForIdentity), which resolves email/sub bindings but
	// not group ones until that tenant's next request repopulates it.
	subjects map[string]*authz.Subject

	// denials counts refusals per resource for the life of the process.
	// Exported on /metrics because a quota that is silently saturating is
	// indistinguishable, from the outside, from a hub nobody is using.
	denials map[Resource]uint64

	store Store
	now   func() time.Time

	// onStoreError receives persistence failures. Persistence is
	// best-effort by design: the in-memory counter is authoritative for
	// this process, and refusing to admit because SQLite was briefly
	// locked would convert a durability problem into an outage.
	onStoreError func(error)
}

// Option configures an Enforcer.
type Option func(*Enforcer)

// WithClock replaces the clock, for tests and for day-rollover assertions.
func WithClock(now func() time.Time) Option {
	return func(e *Enforcer) {
		if now != nil {
			e.now = now
		}
	}
}

// WithStoreErrorHandler installs a callback for persistence failures.
func WithStoreErrorHandler(fn func(error)) Option {
	return func(e *Enforcer) { e.onStoreError = fn }
}

// NewEnforcer builds an Enforcer over resolver and store. A nil store makes
// the enforcer purely in-memory, which is what `cloop ui` falls back to when
// the control-plane database cannot be opened: caps still hold for the life
// of the process rather than silently vanishing.
func NewEnforcer(resolver *Resolver, store Store, opts ...Option) *Enforcer {
	e := &Enforcer{
		resolver:  resolver,
		counters:  make(map[counterKey]float64),
		overrides: make(map[string]Limits),
		subjects:  make(map[string]*authz.Subject),
		denials:   make(map[Resource]uint64),
		store:     store,
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Enabled reports whether any policy is in force. When false every Admit
// succeeds, which is what keeps a single-tenant hub untouched.
func (e *Enforcer) Enabled() bool {
	if e == nil || !e.resolver.Configured() {
		// An override alone is enough to enable enforcement: an admin who
		// caps one user on a hub with no policy file means it.
		if e == nil {
			return false
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		return len(e.overrides) > 0
	}
	return true
}

// Load reads overrides and counters from the store. Stale day buckets are
// dropped on the way in and pruned from storage, so a long-lived hub does not
// accumulate a row per identity per day forever.
func (e *Enforcer) Load() error {
	if e == nil || e.store == nil {
		return nil
	}
	overrides, err := e.store.LoadOverrides()
	if err != nil {
		return fmt.Errorf("quota: load overrides: %w", err)
	}
	counters, err := e.store.LoadCounters()
	if err != nil {
		return fmt.Errorf("quota: load counters: %w", err)
	}

	today := e.dayBucket(e.now())

	e.mu.Lock()
	for _, o := range overrides {
		if o.Identity == "" {
			continue
		}
		e.overrides[o.Identity] = o.Limits.Clone()
	}
	for _, c := range counters {
		if c.Identity == "" || !c.Resource.Valid() {
			continue
		}
		if c.Resource.Kind() == KindDaily && c.Bucket != today {
			continue // yesterday's spend is history, not headroom
		}
		if c.Value <= 0 {
			continue
		}
		e.counters[counterKey{c.Identity, c.Resource, c.Bucket}] = c.Value
	}
	e.mu.Unlock()

	if err := e.store.PruneCountersBefore(today); err != nil {
		e.reportStoreError(fmt.Errorf("quota: prune counters: %w", err))
	}
	return nil
}

// LiveState is ground truth for the gauge resources, gathered from the things
// that actually exist rather than from a counter that may have drifted.
//
// Every map is identity → count. An identity absent from a map holds none of
// that resource; the whole gauge table is replaced, not merged, so a counter
// left behind by a crash mid-run is erased rather than decremented forever.
type LiveState struct {
	Projects  map[string]float64
	Tasks     map[string]float64
	Executors map[string]float64
	Sessions  map[string]float64
}

// Reconcile replaces every gauge counter from live state.
//
// This runs at startup because the alternative — trusting the persisted
// counter — fails in the direction that hurts: a hub killed while three runs
// were in flight comes back believing that tenant is still using three slots,
// and keeps believing it forever. Nothing decrements a counter for a task
// whose process no longer exists. Rebuilding from what is actually running,
// enrolled and signed in makes a crash cost a moment of accuracy instead of a
// permanently narrowed tenant.
//
// Daily counters are deliberately untouched: they are cumulative, they have
// no live equivalent to rebuild from, and re-deriving them would hand a
// compromised account a fresh token budget on every restart.
func (e *Enforcer) Reconcile(live LiveState) error {
	if e == nil {
		return nil
	}
	fresh := map[counterKey]float64{
		// placeholder capacity hint; filled below
	}
	add := func(res Resource, counts map[string]float64) {
		for identity, v := range counts {
			if identity == "" || v <= 0 {
				continue
			}
			fresh[counterKey{identity, res, ""}] = v
		}
	}
	add(ResProjects, live.Projects)
	add(ResConcurrentTasks, live.Tasks)
	add(ResExecutors, live.Executors)
	add(ResSessions, live.Sessions)

	rows := make([]CounterRow, 0, len(fresh))
	now := e.now()

	e.mu.Lock()
	for k := range e.counters {
		if k.bucket == "" {
			delete(e.counters, k)
		}
	}
	for k, v := range fresh {
		e.counters[k] = v
		rows = append(rows, CounterRow{
			Identity: k.identity, Resource: k.resource, Bucket: "",
			Value: v, UpdatedAt: now,
		})
	}
	e.mu.Unlock()

	if e.store == nil {
		return nil
	}
	if err := e.store.ReplaceGauges(rows); err != nil {
		return fmt.Errorf("quota: persist reconciled gauges: %w", err)
	}
	return nil
}

// Admit reserves n units of res for subject, or returns a *Denial.
//
// The reservation and the limit check happen in one critical section, which
// is the whole point: concurrent callers cannot both observe headroom that
// only one of them can have.
func (e *Enforcer) Admit(subject *authz.Subject, res Resource, n float64) (Effective, error) {
	if e == nil {
		return Effective{}, nil
	}
	identity := subject.Label()
	if identity == "" || identity == "anonymous" {
		// No identity to account against: RBAC is off, or the caller used
		// the deployment's own credential. Quotas are a multi-tenancy
		// control and have nothing to say here.
		return Effective{}, nil
	}
	if n <= 0 {
		return e.Effective(subject), nil
	}

	bucket := e.bucketFor(res)

	e.mu.Lock()
	defer e.mu.Unlock()

	e.rememberSubjectLocked(subject)
	eff := e.resolveLocked(subject)
	key := counterKey{identity, res, bucket}
	used := e.counters[key]

	if limit, ok := eff.Limits.Get(res); ok && used+n > limit {
		e.denials[res]++
		return eff, &Denial{
			Identity:   identity,
			Resource:   res,
			Limit:      limit,
			Used:       used,
			Requested:  n,
			RetryAfter: e.retryAfter(res),
			Source:     eff.Sources[res],
		}
	}

	e.counters[key] = used + n
	e.persistLocked(key, used+n)
	return eff, nil
}

// Release returns n units of a gauge resource. Releasing more than is held
// clamps at zero rather than going negative: a double release (a run that
// reports completion twice) must not mint headroom.
func (e *Enforcer) Release(identity string, res Resource, n float64) {
	if e == nil || identity == "" || n <= 0 || res.Kind() != KindGauge {
		return
	}
	key := counterKey{identity, res, ""}

	e.mu.Lock()
	defer e.mu.Unlock()

	remaining := e.counters[key] - n
	if remaining <= 0 {
		delete(e.counters, key)
		e.persistLocked(key, 0)
		return
	}
	e.counters[key] = remaining
	e.persistLocked(key, remaining)
}

// Spend records consumption of a daily resource after the fact. Unlike Admit
// it never refuses: the tokens are already gone, and refusing to record them
// would be the one bug that lets a tenant exceed a budget indefinitely.
func (e *Enforcer) Spend(identity string, tokens, usd float64) {
	if e == nil || identity == "" {
		return
	}
	bucket := e.dayBucket(e.now())

	e.mu.Lock()
	defer e.mu.Unlock()

	if tokens > 0 {
		k := counterKey{identity, ResDailyTokens, bucket}
		e.counters[k] += tokens
		e.persistLocked(k, e.counters[k])
	}
	if usd > 0 {
		k := counterKey{identity, ResDailyCostUSD, bucket}
		e.counters[k] += usd
		e.persistLocked(k, e.counters[k])
	}
}

// CheckSpend reports whether identity has headroom left in its daily budgets
// without reserving anything. Used before dispatching a run: the exact cost
// is unknown up front, so the gate is "has this tenant already blown its
// budget?" rather than a reservation.
func (e *Enforcer) CheckSpend(subject *authz.Subject) error {
	if e == nil {
		return nil
	}
	identity := subject.Label()
	if identity == "" || identity == "anonymous" {
		return nil
	}
	bucket := e.dayBucket(e.now())

	e.mu.Lock()
	defer e.mu.Unlock()

	eff := e.resolveLocked(subject)
	for _, res := range []Resource{ResDailyTokens, ResDailyCostUSD} {
		limit, ok := eff.Limits.Get(res)
		if !ok {
			continue
		}
		used := e.counters[counterKey{identity, res, bucket}]
		if used >= limit {
			e.denials[res]++
			return &Denial{
				Identity:   identity,
				Resource:   res,
				Limit:      limit,
				Used:       used,
				Requested:  0,
				RetryAfter: e.retryAfter(res),
				Source:     eff.Sources[res],
			}
		}
	}
	return nil
}

// Effective resolves subject's ceilings without touching any counter.
func (e *Enforcer) Effective(subject *authz.Subject) Effective {
	if e == nil {
		return Effective{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rememberSubjectLocked(subject)
	return e.resolveLocked(subject)
}

// Usage returns identity's live consumption across every resource.
func (e *Enforcer) Usage(identity string) Usage {
	if e == nil || identity == "" {
		return Usage{}
	}
	bucket := e.dayBucket(e.now())

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.usageLocked(identity, bucket)
}

func (e *Enforcer) usageLocked(identity, bucket string) Usage {
	u := make(Usage, len(AllResources))
	for _, res := range AllResources {
		b := ""
		if res.Kind() == KindDaily {
			b = bucket
		}
		u[res] = e.counters[counterKey{identity, res, b}]
	}
	return u
}

// SetOverride records an admin's per-identity edit.
func (e *Enforcer) SetOverride(identity string, limits Limits, actor string) error {
	if e == nil {
		return fmt.Errorf("quota: no enforcer")
	}
	if identity == "" {
		return fmt.Errorf("quota: identity is required")
	}
	normalized, err := limits.Normalize()
	if err != nil {
		return err
	}
	now := e.now()

	e.mu.Lock()
	e.overrides[identity] = normalized.Clone()
	e.mu.Unlock()

	if e.store == nil {
		return nil
	}
	return e.store.PutOverride(Override{
		Identity: identity, Limits: normalized, UpdatedAt: now, UpdatedBy: actor,
	})
}

// ClearOverride drops an identity's edit, returning it to policy.
func (e *Enforcer) ClearOverride(identity string) (bool, error) {
	if e == nil || identity == "" {
		return false, nil
	}
	e.mu.Lock()
	_, existed := e.overrides[identity]
	delete(e.overrides, identity)
	e.mu.Unlock()

	if e.store == nil {
		return existed, nil
	}
	deleted, err := e.store.DeleteOverride(identity)
	return existed || deleted, err
}

// Snapshot returns one View per identity the enforcer knows about: everyone
// with an override, everyone holding a counter, everyone seen this process,
// plus any extra identities the caller supplies (the project registry knows
// about owners who have not made a request yet).
func (e *Enforcer) Snapshot(extra []string) []View {
	if e == nil {
		return nil
	}
	bucket := e.dayBucket(e.now())

	e.mu.Lock()
	defer e.mu.Unlock()

	seen := make(map[string]struct{}, len(e.overrides)+len(e.subjects)+len(extra))
	for id := range e.overrides {
		seen[id] = struct{}{}
	}
	for id := range e.subjects {
		seen[id] = struct{}{}
	}
	for k := range e.counters {
		seen[k.identity] = struct{}{}
	}
	for _, id := range extra {
		if id != "" {
			seen[id] = struct{}{}
		}
	}

	out := make([]View, 0, len(seen))
	for id := range seen {
		eff := e.resolveLocked(e.subjectForIdentityLocked(id))
		_, overridden := e.overrides[id]
		out = append(out, View{
			Identity:   id,
			Limits:     eff.Limits,
			Usage:      e.usageLocked(id, bucket),
			Sources:    eff.Sources,
			Overridden: overridden,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

// ViewFor returns one identity's limits and usage.
func (e *Enforcer) ViewFor(subject *authz.Subject) View {
	if e == nil {
		return View{}
	}
	identity := subject.Label()
	bucket := e.dayBucket(e.now())

	e.mu.Lock()
	defer e.mu.Unlock()
	e.rememberSubjectLocked(subject)
	eff := e.resolveLocked(subject)
	_, overridden := e.overrides[identity]
	return View{
		Identity:   identity,
		Limits:     eff.Limits,
		Usage:      e.usageLocked(identity, bucket),
		Sources:    eff.Sources,
		Overridden: overridden,
	}
}

// ── internals ───────────────────────────────────────────────────────────────

func (e *Enforcer) resolveLocked(subject *authz.Subject) Effective {
	return e.resolver.Resolve(subject, e.overrides[subject.Label()])
}

func (e *Enforcer) rememberSubjectLocked(subject *authz.Subject) {
	if subject == nil {
		return
	}
	id := subject.Label()
	if id == "" || id == "anonymous" {
		return
	}
	e.subjects[id] = subject
}

// subjectForIdentityLocked returns the claims last seen for id, or a
// synthesized subject when this process has not seen it. The synthesized form
// carries only what the identity key itself encodes, so group-derived limits
// are missing until that tenant makes a request — an accuracy gap in a
// read-only panel, never in enforcement, which always runs against the real
// subject on the request.
func (e *Enforcer) subjectForIdentityLocked(id string) *authz.Subject {
	if s, ok := e.subjects[id]; ok && s != nil {
		return s
	}
	return subjectFromIdentityKey(id)
}

// Denials returns the per-resource refusal counts for this process.
func (e *Enforcer) Denials() map[Resource]uint64 {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[Resource]uint64, len(e.denials))
	for k, v := range e.denials {
		out[k] = v
	}
	return out
}

// SubjectForIdentity reconstructs the claims an identity key encodes. It is
// exported for callers that hold an identity string but no live subject — an
// API token's minter, a project registry owner — and resolves email and sub
// bindings but not group ones, which the key does not carry.
func SubjectForIdentity(id string) *authz.Subject { return subjectFromIdentityKey(id) }

func subjectFromIdentityKey(id string) *authz.Subject {
	if len(id) > 4 && id[:4] == "sub:" {
		return &authz.Subject{Sub: id[4:]}
	}
	for i := 0; i < len(id); i++ {
		if id[i] == '@' {
			return &authz.Subject{Email: id}
		}
	}
	return &authz.Subject{Sub: id}
}

func (e *Enforcer) bucketFor(res Resource) string {
	if res.Kind() == KindDaily {
		return e.dayBucket(e.now())
	}
	return ""
}

func (e *Enforcer) dayBucket(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// retryAfter says how long a denial of res is worth waiting out. Zero means
// waiting will not help.
func (e *Enforcer) retryAfter(res Resource) time.Duration {
	switch res {
	case ResConcurrentTasks:
		// A slot frees when a run finishes. Half a minute is short enough
		// to feel responsive and long enough not to invite a spin loop.
		return 30 * time.Second
	case ResDailyTokens, ResDailyCostUSD:
		now := e.now().UTC()
		midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)
		if d := midnight.Sub(now); d > 0 {
			return d
		}
		return time.Minute
	}
	// Projects, executors and sessions are allocations, not queues: they
	// stay held until somebody removes one or raises the cap.
	return 0
}

func (e *Enforcer) persistLocked(k counterKey, value float64) {
	if e.store == nil {
		return
	}
	err := e.store.PutCounter(CounterRow{
		Identity: k.identity, Resource: k.resource, Bucket: k.bucket,
		Value: value, UpdatedAt: e.now(),
	})
	if err != nil {
		e.reportStoreError(err)
	}
}

func (e *Enforcer) reportStoreError(err error) {
	if err == nil {
		return
	}
	if e.onStoreError != nil {
		e.onStoreError(err)
	}
}

// SessionAdmission computes how many of an identity's existing sessions must
// be evicted to make room for one more.
//
// Sessions are the one resource enforced by eviction rather than refusal, and
// the reason is a lockout: refusing the login of a user who is already at
// their session cap leaves them with no session, and the self-service remedy
// (POST /api/session/logout-all) requires one. Evicting the least recently
// used session preserves the invariant the cap exists for — no identity ever
// holds more than N — without ever locking anyone out of their own account.
func (e *Enforcer) SessionAdmission(subject *authz.Subject, existing int) int {
	if e == nil || existing < 0 {
		return 0
	}
	identity := subject.Label()
	if identity == "" || identity == "anonymous" {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rememberSubjectLocked(subject)
	limit, ok := e.resolveLocked(subject).Limits.Get(ResSessions)
	if !ok {
		return 0
	}
	// Room for the new session means dropping to limit-1 first.
	surplus := float64(existing) - (limit - 1)
	if surplus <= 0 {
		return 0
	}
	return int(surplus)
}
