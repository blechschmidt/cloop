// Package auditaction is the registry of every action name the hub can write
// into the `event_type` column of `audit_events`.
//
// Before this package, every one of those names was an inline string literal
// at its emission site, spread across pkg/statedb, pkg/secretbroker,
// pkg/gitproxy, pkg/kubeguard, pkg/claudeproxy, pkg/oidcauth, pkg/offboard and
// pkg/ui. Two things followed from that, and both of them were real:
//
//   - A typo produced an action name that no consumer would ever match. There
//     was nothing to compare a literal against, so `gitproxy.push_deneid`
//     would have appended rows forever, passed chain verification, exported
//     cleanly to a SIEM, and matched no detection rule. The failure is silent
//     in the one direction that matters — a control that looks like it is
//     working.
//
//   - Nothing told a reader which names exist. An operator wiring the SIEM
//     export into a detection rule had to read emission code in eight packages
//     to learn what they could key on, and docs/security/model.md cited
//     `sandbox.image_denied` and `gitproxy.push_denied` as evidence that a
//     control works with nothing guaranteeing those strings were still in the
//     code it described.
//
// So the names live here, once, each with the trigger that fires it, the
// entity it is recorded against, the payload keys it carries, a stability
// marker, and the permission that gates reading it. docs/reference/audit-events.md
// is generated from this registry, and three gates keep the arrangement from
// rotting:
//
//   - tests/arch/auditaction_test.go fails when an emission site names an
//     action this registry does not know, and when a family's source enum
//     grows a member with no registry entry.
//   - tests/docs/audit_events_test.go fails when the generated page drifts
//     from the registry, and when a prose page cites an action name that no
//     longer exists.
//   - The registry's own tests below fail on a duplicate, a malformed name, or
//     an entry missing the fields the page renders.
//
// # What is not enforced
//
// The registry does not filter. An emitter that somehow produces an
// unregistered name still writes its row: dropping an audit record to punish a
// bookkeeping mistake would turn a documentation defect into an evidence one.
// Enforcement happens at CI time, where a missing entry is a failed build
// rather than a missing row.
//
// The reverse direction is deliberately not gated either. A registry entry
// whose emission site is unreachable on a given build — a family member that
// only fires on an offline-agent path, say — is not an error. Requiring every
// entry to be provably emitted would mean deleting the documentation for the
// rarest events, which are the ones most in need of it.
package auditaction

import (
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// Action is one value of the `event_type` column in `audit_events`.
//
// Values are stable wire strings. They appear in exported SIEM records, in
// customer detection rules, and in rows already sealed into a hash chain that
// cannot be rewritten. Never rename one: add a new constant, mark the old one
// StabilityDeprecated, and let both exist until no stored row carries the old
// name — which, for an append-only table with a retention policy, means until
// retention has passed over it.
type Action string

// String returns the action as it appears in the database column.
func (a Action) String() string { return string(a) }

// Family returns the dotted prefix an action belongs to: "task.upsert" is in
// the "task" family, "sandbox.attach.open" in "sandbox.attach".
//
// The two-segment case is not a special rule bolted on for one family; it is
// what the names already say. `sandbox.image_denied` and `sandbox.attach.open`
// are not siblings — the first is a placement decision, the second is a human
// opening a shell — and a reader scanning the generated page for "everything
// about interactive access" is served by them grouping separately.
func (a Action) Family() string {
	s := string(a)
	for _, multi := range multiSegmentFamilies {
		if strings.HasPrefix(s, multi+".") {
			return multi
		}
	}
	if i := strings.Index(s, "."); i >= 0 {
		return s[:i]
	}
	return s
}

// Verb returns the action with its family prefix removed: "executor.cordon"
// yields "cordon".
//
// This exists because several emitters put the bare verb in the payload as
// well as the qualified name in the column — `{"action":"cordon"}` alongside
// `event_type='executor.cordon'`. Those payloads are already in sealed rows,
// so converting an emission site to carry a fully-qualified Action must not
// change what lands in the payload. Verb is how a converted site keeps the
// stored bytes identical.
func (a Action) Verb() string {
	fam := a.Family()
	if fam == string(a) {
		return string(a)
	}
	return strings.TrimPrefix(string(a), fam+".")
}

// multiSegmentFamilies are the families whose name contains a dot. Listed
// rather than inferred because there is no rule that distinguishes
// "sandbox.attach.open" from "ci.rule.created" by shape alone — both are three
// segments, and both are grouped by their first two.
var multiSegmentFamilies = []string{
	"sandbox.attach",
	"ci.rule",
	"ci.session",
	"ci.exchange",
	"ci.relay",
	"ci.config",
	"stt.credential",
	"secret.lease",
	"project.member",
}

// Stability says how much a consumer may rely on an action's name and payload.
type Stability string

const (
	// StabilityStable: the name and the payload keys listed for it will not
	// change. Safe to key a detection rule on. New payload keys may still be
	// added — a consumer must tolerate that — but no listed key will be
	// removed or repurposed.
	StabilityStable Stability = "stable"

	// StabilityBeta: the action fires, and its rows are real, but its name or
	// payload may still change while the surface that emits it settles. Key a
	// dashboard on it; do not key a paging alert on it.
	StabilityBeta Stability = "beta"

	// StabilityDeprecated: still emitted for compatibility, replaced by
	// something else. The Note says by what. Kept in the registry rather than
	// deleted because stored rows still carry the name and a reader looking it
	// up deserves an answer better than silence.
	StabilityDeprecated Stability = "deprecated"
)

// Valid reports whether s is a known stability marker.
func (s Stability) Valid() bool {
	switch s {
	case StabilityStable, StabilityBeta, StabilityDeprecated:
		return true
	}
	return false
}

// Entry is one registered action: everything the generated reference page says
// about it, and everything the gates check.
type Entry struct {
	// Action is the exact string written to the event_type column.
	Action Action

	// Entity is the value of the entity_type column for rows of this action.
	// It is what the EntityID is an identifier *of*, and a reader filtering
	// the trail by subject needs it to know which id space they are in.
	Entity string

	// Home is which of the two `audit_events` chains this action is written
	// to: the hub's control plane, the project's own database, or — for
	// authorization decisions alone — whichever the decision was scoped to.
	//
	// Declared rather than inferred because there is nothing to infer it
	// from. The home is decided by which *statedb.DB handle an emission site
	// holds, which is a fact about a call stack and not about the row, so a
	// reader of the trail cannot recover it and a mis-routed row cannot be
	// distinguished from a correctly-routed one. See home.go.
	Home HomeDB

	// Trigger is one sentence, present tense, naming the moment the row is
	// written — not what the feature is for. "A push is refused by branch
	// policy", not "guards pushes".
	Trigger string

	// Payload lists the JSON keys the emitter can set, in the order the
	// emitter sets them. Keys are frequently conditional: an emitter omits
	// what it does not know. The list is what a consumer may *expect to see*,
	// not what every row carries.
	Payload []string

	// Stability marks how much a consumer may rely on this.
	Stability Stability

	// Read is the permission a caller must hold to read rows of this action
	// back through the hub's audit API.
	//
	// It is per-entry rather than a package constant because the trail is one
	// table serving several audiences, and the day a family needs narrower
	// reads than authz.PermAuditRead the registry must be able to say so
	// without a schema change. Today every entry names the same permission,
	// and the generated page says that plainly rather than implying a
	// distinction that does not exist.
	Read authz.Permission

	// Note is optional: a second sentence for an action whose name or payload
	// would otherwise mislead. Most entries do not need one, and an entry that
	// has one usually earned it by being confusable with a neighbour.
	Note string
}

// Lookup returns the entry for a, and whether it is registered.
func Lookup(a Action) (Entry, bool) {
	e, ok := byAction[a]
	return e, ok
}

// Registered reports whether a is a known action.
func Registered(a Action) bool {
	_, ok := byAction[a]
	return ok
}

// All returns every registered entry, sorted by action name. The slice is a
// fresh copy: callers may sort or filter it without disturbing the registry.
func All() []Entry {
	out := make([]Entry, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool { return out[i].Action < out[j].Action })
	return out
}

// Families returns every family name that has at least one registered action,
// in the order the generated page presents them — which is the order the
// registry declares, not alphabetical, so related families stay adjacent.
func Families() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range registry {
		f := e.Action.Family()
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// InFamily returns the registered actions of one family, sorted by name.
func InFamily(family string) []Entry {
	var out []Entry
	for _, e := range registry {
		if e.Action.Family() == family {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Action < out[j].Action })
	return out
}

// ── Family constructors ────────────────────────────────────────────────────
//
// Five emitters compose their action name at runtime from a verb that arrives
// from somewhere else: an executor-fleet operation, a workspace phase, a
// gitproxy or kubeguard event kind, an authorization outcome. Before this
// package each of those was a bare string concatenation at the emission site
// — `"gitproxy." + string(ev.Kind)` — which is exactly the shape no gate can
// check, because the interesting half of the name is not in the file.
//
// The constructors below give those sites something to call instead. They do
// not validate: a name composed from an unknown verb is still returned and
// still emitted, for the reason given in the package doc. What they buy is
// that the composition now happens in one place per family, which is what lets
// tests/arch/auditaction_test.go walk each family's *source enum* and prove
// every member of it lands on a registered action. A new EventKind constant in
// pkg/gitproxy now fails CI until it is documented here.

const (
	// FamilyExecutor is the fleet-lifecycle family: enrol, revoke, cordon,
	// and the rest of the operations an operator performs on an executor.
	FamilyExecutor = "executor"
	// FamilyWorkspace is the source-provisioning family.
	FamilyWorkspace = "workspace"
	// FamilyGitProxy is the git interception proxy's family.
	FamilyGitProxy = "gitproxy"
	// FamilyKubeGuard is the Kubernetes interception proxy's family.
	FamilyKubeGuard = "kubeguard"
	// FamilyAuthz is the authorization-decision family.
	FamilyAuthz = "authz"
)

// ExecutorLifecycle returns the action for an executor-fleet verb:
// ExecutorLifecycle("cordon") is ActionExecutorCordon.
func ExecutorLifecycle(verb string) Action { return compose(FamilyExecutor, verb) }

// WorkspacePhase returns the action for a workspace-provisioning phase.
func WorkspacePhase(phase string) Action { return compose(FamilyWorkspace, phase) }

// GitProxyEvent returns the action for a pkg/gitproxy EventKind.
func GitProxyEvent(kind string) Action { return compose(FamilyGitProxy, kind) }

// KubeGuardEvent returns the action for a pkg/kubeguard EventKind.
func KubeGuardEvent(kind string) Action { return compose(FamilyKubeGuard, kind) }

// AuthzOutcome returns the action for an authorization outcome.
func AuthzOutcome(outcome string) Action { return compose(FamilyAuthz, outcome) }

// compose joins a family and a verb. Trimming guards the one case that would
// silently produce a name ending in a dot — an empty verb from an unset field
// — by collapsing it to the family itself, which is visibly wrong in a query
// result rather than invisibly wrong.
func compose(family, verb string) Action {
	verb = strings.TrimSpace(verb)
	if verb == "" {
		return Action(family)
	}
	return Action(family + "." + verb)
}

// byAction indexes the registry for Lookup. Built once at init rather than
// searched linearly: Registered is called from the gates once per emission
// site and once per documented literal, and from nothing on a hot path.
var byAction = func() map[Action]Entry {
	m := make(map[Action]Entry, len(registry))
	for _, e := range registry {
		m[e.Action] = e
	}
	return m
}()
