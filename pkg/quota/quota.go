// Package quota answers the question pkg/authz does not.
//
// RBAC decides whether an identity *may* act. Nothing decided how *much* it
// may consume, so on a shared hub one tenant could open unlimited projects,
// enrol unlimited executors, hold unlimited sessions, and — the expensive one
// — start unlimited concurrent runs against a token budget the whole
// organisation shares. pkg/globalbudget exists but is keyed by project, which
// is the wrong axis for a multi-tenant deployment: a user who can create
// projects can create budget headroom.
//
// This package is the identity-keyed half. It is deliberately stdlib-only
// apart from pkg/authz (whose Subject and ClaimKind it reuses so that quota
// bindings read exactly like role bindings in the same config file). The
// SQLite adapter lives in pkg/quotastore, the same seam as
// oidcauth.SessionStore/sessionstore and secretbroker.Store/secretstore.
//
// # The two kinds of resource
//
// Gauges (projects, concurrent tasks, executors, sessions) go up on admission
// and back down on release. They are the ones that can drift: a hub that
// crashes mid-run leaves a counter claiming a task is still running forever,
// which would slowly starve the tenant it was meant to protect. Enforcer
// therefore treats the persisted gauge as a cache and rebuilds it from live
// state at startup — see Enforcer.Reconcile.
//
// Daily counters (tokens, cost) only ever go up, inside a UTC-day bucket.
// They are the opposite case: they must survive a restart exactly, because
// re-deriving "spend so far today" from anything other than the recorded
// increments would hand a compromised account a fresh budget on every crash.
//
// # Why the most restrictive binding wins a tie
//
// Resolution is per-resource and most-specific-wins: a limit set directly on
// a subject beats one set on their email, which beats one set on a role,
// which beats one set on a group, which beats the deployment default. Within
// one tier — the case that actually happens, a user in several groups — the
// *smallest* limit wins.
//
// That is the opposite of how role bindings resolve (strongest role wins) and
// the difference is deliberate. A role is a grant, so unioning grants is the
// safe reading of "member of both". A quota is a ceiling, so unioning
// ceilings would mean any tenant could lift their own cap by joining one more
// group — turning group membership into a privilege-escalation primitive. The
// minimum is also order-independent, which matters because the alternative
// (first match wins) makes a security property depend on YAML line order.
package quota

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// Resource names one thing an identity can consume. The string values are
// the wire and YAML form and are part of the API contract: never rename one.
type Resource string

const (
	// ResProjects caps how many projects an identity may own at once.
	ResProjects Resource = "max_projects"

	// ResConcurrentTasks caps how many runs an identity may have executing
	// at once. This is the cap that actually protects the fleet: every
	// concurrent run holds an executor slot and spends tokens.
	ResConcurrentTasks Resource = "max_concurrent_tasks"

	// ResExecutors caps how many executors an identity may enrol. Enrolling
	// a device grants it the right to run workloads, so an unbounded tenant
	// can grow the trusted compute base without an admin ever looking.
	ResExecutors Resource = "max_executors"

	// ResSessions caps concurrent signed-in sessions per identity. Enforced
	// by evicting the oldest rather than by refusing the newest — see
	// SessionAdmission.
	ResSessions Resource = "max_sessions"

	// ResDailyTokens caps input+output tokens spent per UTC day.
	ResDailyTokens Resource = "daily_token_budget"

	// ResDailyCostUSD caps estimated USD spend per UTC day.
	ResDailyCostUSD Resource = "daily_cost_usd"
)

// AllResources lists every resource in a stable order: config validation,
// the admin panel's column order, and the /metrics gauge order all read it.
var AllResources = []Resource{
	ResProjects,
	ResConcurrentTasks,
	ResExecutors,
	ResSessions,
	ResDailyTokens,
	ResDailyCostUSD,
}

// Kind distinguishes the two accounting models described in the package doc.
type Kind int

const (
	// KindGauge rises on admission and falls on release.
	KindGauge Kind = iota

	// KindDaily accumulates within a UTC-day bucket and never falls.
	KindDaily
)

// Kind reports how r is accounted.
func (r Resource) Kind() Kind {
	switch r {
	case ResDailyTokens, ResDailyCostUSD:
		return KindDaily
	}
	return KindGauge
}

// Valid reports whether r is a known resource.
func (r Resource) Valid() bool {
	for _, known := range AllResources {
		if r == known {
			return true
		}
	}
	return false
}

// Integral reports whether r counts whole things. Used only for rendering:
// "3 projects" should not print as "3.0".
func (r Resource) Integral() bool { return r != ResDailyCostUSD }

// Limits is a sparse set of ceilings. A resource absent from the map is
// unlimited; a resource present with 0 means zero is allowed, which is a
// real and useful setting (a tenant who may run but may not enrol hardware).
//
// Sparseness is what makes partial overrides work: an admin can raise one
// user's max_projects without restating — and accidentally freezing — every
// other ceiling that user inherits from their group.
type Limits map[Resource]float64

// Get returns the ceiling for r and whether one is set.
func (l Limits) Get(r Resource) (float64, bool) {
	if l == nil {
		return 0, false
	}
	v, ok := l[r]
	return v, ok
}

// Clone returns a copy safe to hand to a caller that may mutate it.
func (l Limits) Clone() Limits {
	if l == nil {
		return nil
	}
	out := make(Limits, len(l))
	for k, v := range l {
		out[k] = v
	}
	return out
}

// Resources returns the resources l constrains, in AllResources order.
func (l Limits) Resources() []Resource {
	out := make([]Resource, 0, len(l))
	for _, r := range AllResources {
		if _, ok := l[r]; ok {
			out = append(out, r)
		}
	}
	return out
}

// Normalize returns a copy with unknown resources rejected and negative
// ceilings treated as "unlimited" rather than "deny everything".
//
// The negative case is a footgun worth disarming explicitly: an operator who
// types -1 means "no limit" in almost every system that has ever had a quota,
// and reading it as a ceiling of -1 would deny every request from that tenant
// with no obvious cause.
func (l Limits) Normalize() (Limits, error) {
	if len(l) == 0 {
		return nil, nil
	}
	out := make(Limits, len(l))
	for r, v := range l {
		key := Resource(strings.ToLower(strings.TrimSpace(string(r))))
		if !key.Valid() {
			return nil, fmt.Errorf("unknown quota resource %q (valid: %s)", r, resourceNames())
		}
		if v < 0 {
			// Unlimited: drop the entry rather than store a negative.
			continue
		}
		out[key] = v
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func resourceNames() string {
	names := make([]string, len(AllResources))
	for i, r := range AllResources {
		names[i] = string(r)
	}
	return strings.Join(names, ", ")
}

// Binding assigns limits to everyone matching one claim. It mirrors
// authz.Binding minus the scope fields: a quota is a property of an identity
// across the whole hub, not of an identity within one project. Scoping it per
// project would defeat the point, since the tenant chooses how many projects
// they have.
type Binding struct {
	// Claim selects what Value is compared against: group, role, email, sub.
	Claim authz.ClaimKind

	// Value is the claim value to match, normalized like authz's.
	Value string

	// Limits are the ceilings this binding contributes.
	Limits Limits
}

// tier orders bindings by specificity. Higher wins outright; see the package
// doc for why ties go to the smallest limit rather than the largest.
func (b Binding) tier() int {
	switch b.Claim {
	case authz.ClaimSub:
		return 4
	case authz.ClaimEmail:
		return 3
	case authz.ClaimRole:
		return 2
	case authz.ClaimGroup:
		return 1
	}
	return 0
}

// matches reports whether b applies to s. Kept byte-for-byte consistent with
// authz.Binding.matches — a value that names a group for a role binding must
// name the same group for a quota binding, or config becomes a guessing game.
func (b Binding) matches(s *authz.Subject) bool {
	if s == nil {
		return false
	}
	switch b.Claim {
	case authz.ClaimEmail:
		return s.Email != "" && strings.EqualFold(b.Value, strings.TrimSpace(s.Email))
	case authz.ClaimSub:
		return s.Sub != "" && b.Value == strings.TrimSpace(s.Sub)
	case authz.ClaimGroup:
		return containsFold(s.Groups, b.Value)
	case authz.ClaimRole:
		return containsFold(s.Roles, b.Value)
	}
	return false
}

func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(normalizeClaimValue(v), want) {
			return true
		}
	}
	return false
}

// normalizeClaimValue trims whitespace and one leading "/" so Keycloak's
// group-path form and the bare form are interchangeable, as in pkg/authz.
func normalizeClaimValue(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "/")
}

// Config is the deployment's quota policy.
type Config struct {
	// Defaults apply to every identity that no binding covers. Leaving it
	// empty means "unlimited by default", which is the correct behaviour
	// for the single-tenant hub this feature must not disturb.
	Defaults Limits

	// Bindings assign narrower (or wider) limits per claim.
	Bindings []Binding
}

// Resolver turns a Config into per-identity limits. It is immutable after
// New and safe for concurrent use.
type Resolver struct {
	defaults   Limits
	bindings   []Binding
	configured bool
}

// New validates cfg and returns a Resolver.
//
// Validation is strict for the same reason authz.New's is: a typo in a
// resource name or a claim kind produces a binding that matches nothing,
// which presents as "the quota I configured is not being enforced" — the
// failure mode a quota system can least afford to have silently.
func New(cfg Config) (*Resolver, error) {
	defaults, err := cfg.Defaults.Normalize()
	if err != nil {
		return nil, fmt.Errorf("quota defaults: %w", err)
	}

	bindings := make([]Binding, 0, len(cfg.Bindings))
	for i, b := range cfg.Bindings {
		nb, err := normalizeBinding(b)
		if err != nil {
			return nil, fmt.Errorf("quota binding %d: %w", i, err)
		}
		bindings = append(bindings, nb)
	}

	return &Resolver{
		defaults:   defaults,
		bindings:   bindings,
		configured: len(bindings) > 0 || len(defaults) > 0,
	}, nil
}

func normalizeBinding(b Binding) (Binding, error) {
	b.Claim = authz.ClaimKind(strings.ToLower(strings.TrimSpace(string(b.Claim))))
	if b.Claim == "" {
		return b, fmt.Errorf("claim is required (valid: %s)", claimNames())
	}
	if !b.Claim.Valid() {
		return b, fmt.Errorf("claim %q is not a known claim kind (valid: %s)", b.Claim, claimNames())
	}
	b.Value = normalizeClaimValue(b.Value)
	if b.Value == "" {
		return b, fmt.Errorf("value is required — a binding with an empty value would match nothing")
	}
	limits, err := b.Limits.Normalize()
	if err != nil {
		return b, err
	}
	if len(limits) == 0 {
		return b, fmt.Errorf("binding sets no limits — it would have no effect")
	}
	b.Limits = limits
	return b, nil
}

func claimNames() string {
	names := make([]string, len(authz.AllClaimKinds))
	for i, c := range authz.AllClaimKinds {
		names[i] = string(c)
	}
	return strings.Join(names, ", ")
}

// Configured reports whether any policy was set. A hub with no quota config
// enforces nothing, which keeps single-tenant local use exactly as it was.
func (r *Resolver) Configured() bool { return r != nil && r.configured }

// Effective is the resolved ceiling set for one identity, with provenance.
type Effective struct {
	// Identity is the key limits are accounted against — authz.Subject's
	// Label(), the same string oidcauth.Identity.OwnerKey() produces, so a
	// project's Owner and a quota's identity are always the same value.
	Identity string

	// Limits are the ceilings in force.
	Limits Limits

	// Sources says where each ceiling came from ("override", "group:eng",
	// "default"). The admin panel shows it so "why is this user capped at
	// two projects?" is answerable without reading YAML.
	Sources map[Resource]string
}

// Limit returns the ceiling for r and whether one applies.
func (e Effective) Limit(r Resource) (float64, bool) { return e.Limits.Get(r) }

// Resolve computes the ceilings for subject, with override applied on top.
//
// override is the admin's per-identity edit from the store. It is applied
// last and per-resource, so an admin can raise one ceiling for one person
// without inheriting responsibility for the rest of their limits.
func (r *Resolver) Resolve(subject *authz.Subject, override Limits) Effective {
	eff := Effective{
		Identity: subject.Label(),
		Limits:   make(Limits, len(AllResources)),
		Sources:  make(map[Resource]string, len(AllResources)),
	}
	if r == nil {
		return eff
	}

	for res, v := range r.defaults {
		eff.Limits[res] = v
		eff.Sources[res] = "default"
	}

	// Per-resource tier tracking: a binding that sets only max_projects
	// must not displace a more specific binding's daily_token_budget.
	tiers := make(map[Resource]int, len(AllResources))
	for res := range r.defaults {
		tiers[res] = 0
	}

	for _, b := range r.bindings {
		if !b.matches(subject) {
			continue
		}
		t := b.tier()
		for res, v := range b.Limits {
			cur, have := eff.Limits[res]
			switch {
			case !have || t > tiers[res]:
				// More specific, or the first word on this resource.
				eff.Limits[res] = v
				eff.Sources[res] = string(b.Claim) + ":" + b.Value
				tiers[res] = t
			case t == tiers[res] && v < cur:
				// Equally specific: the tighter ceiling wins. See the
				// package doc — unioning ceilings would let a tenant
				// raise their own cap by joining another group.
				eff.Limits[res] = v
				eff.Sources[res] = string(b.Claim) + ":" + b.Value
			}
		}
	}

	for res, v := range override {
		eff.Limits[res] = v
		eff.Sources[res] = "override"
	}

	if len(eff.Limits) == 0 {
		eff.Limits = nil
	}
	return eff
}

// ResolveAllSubjects is a convenience for the admin panel: resolve a batch of
// identities in one pass, sorted by identity for stable rendering.
func (r *Resolver) ResolveAll(subjects []*authz.Subject, overrides map[string]Limits) []Effective {
	out := make([]Effective, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, r.Resolve(s, overrides[s.Label()]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}
