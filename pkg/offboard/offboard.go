// Package offboard answers one question in one operation: "this person left,
// are they out?" (Task 20261).
//
// Before this, the answer was no. An enterprise hub let an identity hold five
// independent credential surfaces, and disabling the account at the IdP severed
// none of them on its own:
//
//   - dashboard sessions, which outlive an IdP disablement until the absolute
//     TTL because a refresh that returns no id_token cannot narrow claims;
//   - API tokens, which carry an owner binding that nothing consulted on
//     departure, so a departed user's PAT worked until its ExpiresAt;
//   - glasses links, the same rows with a different Kind, whose own source
//     conceded that an IdP dropping someone from a group "is not noticed until
//     the link expires";
//   - secret leases held by their running tasks, which keep real credentials
//     materialised inside a sandbox;
//   - the tasks themselves, still executing on the fleet in their name.
//
// The documented remedy was a hand-written deny binding, which stops the
// account *acting* but ends nothing it already holds.
//
// # Why one package
//
// The CLI and the dashboard both need this, and they need it to mean exactly
// the same thing. Two implementations of "who counts as this person" is the
// failure mode that matters: the one that under-matches reports success while
// leaving a credential live. So resolution, planning and execution live here,
// and cmd/ and pkg/ui are thin.
//
// # Ordering
//
// Severing runs before stopping. Revoking credentials first means a task that
// notices its lease vanishing and retries cannot re-authenticate; stopping the
// task first would leave a window where its still-valid session could start
// another one. The durable credentials go in a single transaction (see
// statedb.OffboardIdentity) so there is no partially-offboarded state; leases
// and tasks cannot join that transaction — they are process memory and other
// databases — and so are applied after it, each reporting its own failures
// rather than rolling back a severing that already succeeded.
//
// # What it will not do
//
// Projects are reported, never deleted. A departing user's projects usually
// hold the team's work, and an offboarding command that silently removed them
// would be a data-loss tool wearing a security label. The operator gets the
// list and reassigns.
package offboard

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/rolestore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ---------------------------------------------------------------------------
// The surfaces
// ---------------------------------------------------------------------------

// Target is the resolved identity: every identifier that turned out to address
// the same person.
//
// Resolution matters because the operator types one thing — usually an email —
// and the surfaces are keyed inconsistently. Sessions carry a subject and an
// email; a token's owner may carry only a subject. Matching literally on what
// was typed would leave the subject-keyed token behind, which is precisely the
// credential an operator would never think to look for.
type Target struct {
	// Input is what the operator typed, preserved for the audit trail.
	Input string `json:"input"`

	// Key is the canonical owner key: lowercased email, or "sub:"+Subject.
	// This is what project ownership rows are recorded under.
	Key string `json:"key"`

	// Subjects and Emails are every identifier found to belong to this person.
	// Emails are lowercased; subjects are opaque and compared exactly.
	//
	// Always serialised, even when empty: a front end rendering "resolved to"
	// needs to distinguish "no subject" from a field that was omitted, and
	// omitempty would make an identity this hub has never seen indistinguishable
	// from a decoding bug.
	Subjects []string `json:"subjects"`
	Emails   []string `json:"emails"`
}

// OwnerKeys returns every owner-key spelling this identity may be stored under.
func (t Target) OwnerKeys() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		if v == "" {
			return
		}
		if _, dup := seen[v]; dup {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, e := range t.Emails {
		add(e)
	}
	for _, s := range t.Subjects {
		add("sub:" + s)
	}
	add(t.Key)
	sort.Strings(out)
	return out
}

// Label is the friendliest name for this identity.
func (t Target) Label() string {
	if len(t.Emails) > 0 {
		return t.Emails[0]
	}
	if len(t.Subjects) > 0 {
		return "sub:" + t.Subjects[0]
	}
	return t.Input
}

// SessionRef is one dashboard session that will be, or was, ended.
type SessionRef struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject,omitempty"`
	Email     string    `json:"email,omitempty"`
	IP        string    `json:"ip,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// TokenRef is one API token or glasses link.
type TokenRef struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	Prefix    string    `json:"prefix,omitempty"`
	Kind      string    `json:"kind,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	Roles     []string  `json:"roles,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// DenyRef is a deny binding the run will write.
type DenyRef struct {
	ID    string `json:"id"`
	Claim string `json:"claim"`
	Value string `json:"value"`
}

// LeaseRef is one live secret lease held on the departing user's behalf.
type LeaseRef struct {
	ID         string    `json:"id"`
	ExecutorID string    `json:"executor_id,omitempty"`
	ProjectID  string    `json:"project_id,omitempty"`
	Kinds      []string  `json:"kinds,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

// TaskRef is one in-flight task running in a project this identity owns.
type TaskRef struct {
	ProjectPath string `json:"project_path"`
	ProjectName string `json:"project_name,omitempty"`
	ID          int    `json:"id"`
	Title       string `json:"title,omitempty"`
	Status      string `json:"status,omitempty"`

	// Attempt names the execution observed, so a kill filed here cannot land on
	// a later attempt of the same task (Task 20203). Not serialised: it is an
	// internal fencing token, not something an operator reads.
	Attempt string `json:"-"`
}

// ProjectRef is a project owned by the departing user. Reported, never deleted.
type ProjectRef struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Owner string `json:"owner,omitempty"`
}

// Failure records a surface that could not be severed, so a partial run is
// legible instead of being reported as a success.
type Failure struct {
	Surface string `json:"surface"`
	Detail  string `json:"detail"`
}

// ---------------------------------------------------------------------------
// Plan and report
// ---------------------------------------------------------------------------

// Plan is the blast radius: everything a run would touch, resolved before
// anything is written. It is what --dry-run prints.
type Plan struct {
	Target   Target       `json:"target"`
	Sessions []SessionRef `json:"sessions"`
	Tokens   []TokenRef   `json:"tokens"`
	Glasses  []TokenRef   `json:"glasses"`
	Denies   []DenyRef    `json:"denies"`
	Leases   []LeaseRef   `json:"leases"`
	Tasks    []TaskRef    `json:"tasks"`
	Projects []ProjectRef `json:"projects"`

	// Warnings name things the run cannot be sure about — most importantly
	// tokens whose owner binding did not decode, which cannot be proven *not*
	// to belong to this person.
	Warnings []string `json:"warnings,omitempty"`
}

// Empty reports whether there is nothing to sever. A plan with only a deny
// binding is not empty: denying an identity that currently holds nothing is a
// legitimate pre-emptive offboarding.
func (p Plan) Empty() bool {
	return len(p.Sessions) == 0 && len(p.Tokens) == 0 && len(p.Glasses) == 0 &&
		len(p.Denies) == 0 && len(p.Leases) == 0 && len(p.Tasks) == 0
}

// Report is the outcome of a run. A dry run returns the Plan with DryRun set
// and every "-ed" field empty.
type Report struct {
	Plan
	DryRun bool      `json:"dry_run"`
	Actor  string    `json:"actor,omitempty"`
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`

	SessionsRevoked []string  `json:"sessions_revoked,omitempty"`
	TokensRevoked   []string  `json:"tokens_revoked,omitempty"`
	GlassesRevoked  []string  `json:"glasses_revoked,omitempty"`
	DeniesWritten   []string  `json:"denies_written,omitempty"`
	LeasesReleased  []string  `json:"leases_released,omitempty"`
	TasksStopped    []TaskRef `json:"tasks_stopped,omitempty"`

	// Failures is non-empty when a surface could not be severed. The run does
	// not abort on one: a lease that will not release is not a reason to leave
	// the sessions live. The caller decides what a partial run means, and both
	// front ends report it as an error with the detail attached.
	Failures []Failure `json:"failures,omitempty"`
}

// OK reports whether every surface was severed.
func (r Report) OK() bool { return len(r.Failures) == 0 }

// ---------------------------------------------------------------------------
// Collaborators
// ---------------------------------------------------------------------------

// Leases is the secret-broker surface offboarding needs. A hub with no broker
// passes nil, and leases are simply not part of the run.
type Leases interface {
	// LiveLeases reports every lease the broker would still honour.
	LiveLeases() []LeaseRef
	// Release ends one lease and destroys any credentials minted under it.
	Release(id string)
}

// Tasks is the per-project execution surface. A hub that cannot reach project
// databases passes nil.
type Tasks interface {
	// Running reports in-flight tasks for one project path.
	Running(projectPath string) ([]TaskRef, error)
	// Stop requests that the named execution be killed. The ref carries the
	// attempt token, so the request cannot land on a later attempt.
	Stop(t TaskRef, actor, reason string) error
}

// Projects enumerates project ownership.
type Projects interface {
	// Owned reports projects whose owner is any of the given owner keys.
	Owned(ownerKeys []string) ([]ProjectRef, error)
}

// Sessions is the running hub's session authority — its authenticator.
//
// Supplying it matters more than it looks. A hub whose session store is not
// durable (no sealing key, or no control-plane database) keeps sessions in
// process memory, where the control-plane table this package otherwise reads is
// simply empty. An offboarding driven off that table would report "0 sessions"
// and leave the person signed in — the worst possible answer to "are they out?".
// Going through the authenticator is also what drops the session from its
// 30-second read cache, which deleting the row underneath it does not.
//
// A caller with no running hub (the CLI, on a host whose hub may be down)
// passes nil and the control-plane table is used instead, which is correct
// there: there is no process holding memory sessions to ask.
type Sessions interface {
	// List reports every live session.
	List() ([]SessionRef, error)
	// Revoke ends one session and drops it from any in-process cache.
	// It reports whether a session was actually ended.
	Revoke(id, actor, reason string) (bool, error)
}

// Options configures a run.
type Options struct {
	// DB is the hub's control-plane database. Required.
	DB *statedb.DB

	// Identity is the email or subject the operator typed. Required.
	Identity string

	// Reason is recorded on every audit event. Required: an offboarding with
	// no stated cause is not reviewable, and the reviewability is the point.
	Reason string

	// Actor is who is doing this — an operator's email, or an OS user for CLI
	// runs.
	Actor string

	// Via distinguishes "cli" from "ui" in the trail.
	Via string

	// DryRun resolves and reports without writing anything.
	DryRun bool

	// Leases, Tasks and Projects are optional. A nil collaborator means that
	// surface is skipped, and the report says so rather than implying it was
	// clean.
	Leases   Leases
	Tasks    Tasks
	Projects Projects

	// Sessions is the live session authority. Strongly preferred where one
	// exists — see the interface doc.
	Sessions Sessions

	// Now is the clock, swappable in tests.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

// Run performs the offboarding, or reports what one would do when DryRun is set.
func Run(o Options) (Report, error) {
	if o.DB == nil {
		return Report{}, fmt.Errorf("offboard: nil database")
	}
	if strings.TrimSpace(o.Identity) == "" {
		return Report{}, fmt.Errorf("offboard: identity is required")
	}
	// Only the write needs a reason. Demanding one for a dry run — which
	// changes nothing and records nothing — would train operators to type a
	// placeholder, and the placeholder is what they would then reuse for the
	// real run, defeating the point of asking.
	if !o.DryRun && strings.TrimSpace(o.Reason) == "" {
		return Report{}, fmt.Errorf("offboard: a reason is required")
	}

	now := o.now()
	plan, err := BuildPlan(o)
	if err != nil {
		return Report{}, err
	}

	rep := Report{
		Plan:   plan,
		DryRun: o.DryRun,
		Actor:  o.Actor,
		Reason: o.Reason,
		At:     now,
	}
	if o.DryRun {
		return rep, nil
	}

	// 1. Sessions, through the live authenticator when there is one.
	//
	//    Ahead of the transaction, and therefore outside it. The trade is
	//    deliberate: keeping sessions inside the commit would buy atomicity
	//    with a severing that does not actually sever — the authenticator
	//    serves from an in-process cache, and on a hub without a durable store
	//    from process memory the table never sees. The failure mode this
	//    creates (sessions ended, transaction then fails) leaves the person
	//    *more* contained than before and is fixed by re-running; the one it
	//    avoids leaves them signed in while the report says otherwise.
	var revokedSessions []string
	if o.Sessions != nil {
		for _, s := range plan.Sessions {
			ended, err := o.Sessions.Revoke(s.ID, o.Actor, "offboarded")
			if err != nil {
				rep.Failures = append(rep.Failures, Failure{
					"session", fmt.Sprintf("revoke %s: %v", s.ID, err)})
				continue
			}
			if ended {
				revokedSessions = append(revokedSessions, s.ID)
			}
		}
	}

	// 2. The durable credentials, atomically. If this fails nothing else runs:
	//    stopping a person's tasks while their tokens still work is not a
	//    partial offboarding, it is an outage with no security benefit.
	//
	//    SessionIDs is empty when the authenticator already handled them, so
	//    the same row is never counted twice.
	txSessions := sessionIDs(plan.Sessions)
	if o.Sessions != nil {
		txSessions = nil
	}
	applied, err := o.DB.OffboardIdentity(statedb.OffboardWrite{
		IdentityKey:  plan.Target.Key,
		SessionIDs:   txSessions,
		TokenIDs:     tokenIDs(plan.Tokens),
		GlassesIDs:   tokenIDs(plan.Glasses),
		DenyBindings: denyRows(plan, o, now),
		At:           now,
		Audit: func(a statedb.OffboardApplied) ([]*statedb.AuditEvent, error) {
			// a is a copy, so folding the already-revoked sessions in here
			// shapes the audit record without disturbing what the transaction
			// reports back.
			a.Sessions = append(append([]string(nil), revokedSessions...), a.Sessions...)
			return credentialAuditEvents(plan, o, a)
		},
	})
	if err != nil {
		return rep, fmt.Errorf("sever credentials: %w", err)
	}
	rep.SessionsRevoked = append(revokedSessions, applied.Sessions...)
	rep.TokensRevoked = applied.Tokens
	rep.GlassesRevoked = applied.Glasses
	rep.DeniesWritten = applied.DenyBindingIDs

	// 2. Leases. Released after the credentials so a task that reacts to losing
	//    its secrets cannot re-authenticate to get them back.
	if o.Leases != nil && len(plan.Leases) > 0 {
		for _, l := range plan.Leases {
			o.Leases.Release(l.ID)
			rep.LeasesReleased = append(rep.LeasesReleased, l.ID)
		}
		if err := auditSurface(o, plan, "user.offboard_lease", map[string]any{
			"count":  len(rep.LeasesReleased),
			"leases": rep.LeasesReleased,
		}); err != nil {
			rep.Failures = append(rep.Failures, Failure{"lease", err.Error()})
		}
	}

	// 3. Tasks.
	if o.Tasks != nil && len(plan.Tasks) > 0 {
		for _, t := range plan.Tasks {
			if err := o.Tasks.Stop(t, o.Actor, o.Reason); err != nil {
				rep.Failures = append(rep.Failures, Failure{
					"task", fmt.Sprintf("stop %s#%d: %v", t.ProjectPath, t.ID, err)})
				continue
			}
			rep.TasksStopped = append(rep.TasksStopped, t)
		}
		if len(rep.TasksStopped) > 0 {
			if err := auditSurface(o, plan, "user.offboard_task", map[string]any{
				"count": len(rep.TasksStopped),
				"tasks": rep.TasksStopped,
			}); err != nil {
				rep.Failures = append(rep.Failures, Failure{"task", err.Error()})
			}
		}
	}

	// 4. Projects: reported only. The event records that a human still owes a
	//    reassignment, which is the whole reason not to delete them.
	if len(plan.Projects) > 0 {
		if err := auditSurface(o, plan, "user.offboard_project", map[string]any{
			"count":    len(plan.Projects),
			"projects": plan.Projects,
			"action":   "reported_for_reassignment",
		}); err != nil {
			rep.Failures = append(rep.Failures, Failure{"project", err.Error()})
		}
	}

	return rep, nil
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// credentialAuditEvents builds the events chained into the credential
// transaction: a summary, then one per surface that actually changed.
//
// One event per surface, not one per row. A departing user can hold dozens of
// sessions, and an offboarding that emitted an event each would bury the
// operation it is meant to prove — the same amplification that made the trail
// expensive enough to need a retention policy (Task 20218). The ids live in the
// payload, so "what exactly was severed" is still answerable.
func credentialAuditEvents(plan Plan, o Options, a statedb.OffboardApplied) ([]*statedb.AuditEvent, error) {
	var evs []*statedb.AuditEvent
	add := func(eventType string, payload map[string]any) error {
		ev, err := newEvent(o, plan, eventType, payload, a.At)
		if err != nil {
			return err
		}
		evs = append(evs, ev)
		return nil
	}

	// The summary comes first so a reviewer reading the chain in order meets
	// the operation before its parts.
	if err := add("user.offboard", map[string]any{
		"sessions": len(a.Sessions),
		"tokens":   len(a.Tokens),
		"glasses":  len(a.Glasses),
		"denies":   len(a.DenyBindingIDs),
		"leases":   len(plan.Leases),
		"tasks":    len(plan.Tasks),
		"projects": len(plan.Projects),
		"warnings": plan.Warnings,
	}); err != nil {
		return nil, err
	}
	if len(a.Sessions) > 0 {
		if err := add("user.offboard_session", map[string]any{
			"count": len(a.Sessions), "sessions": a.Sessions}); err != nil {
			return nil, err
		}
	}
	if len(a.Tokens) > 0 {
		if err := add("user.offboard_token", map[string]any{
			"count": len(a.Tokens), "tokens": a.Tokens}); err != nil {
			return nil, err
		}
	}
	if len(a.Glasses) > 0 {
		if err := add("user.offboard_glasses", map[string]any{
			"count": len(a.Glasses), "links": a.Glasses}); err != nil {
			return nil, err
		}
	}
	if len(a.DenyBindingIDs) > 0 {
		if err := add("user.offboard_deny", map[string]any{
			"count": len(a.DenyBindingIDs), "bindings": a.DenyBindingIDs,
			"claims": plan.Denies}); err != nil {
			return nil, err
		}
	}
	return evs, nil
}

// auditSurface records one of the surfaces severed outside the transaction.
func auditSurface(o Options, plan Plan, eventType string, payload map[string]any) error {
	ev, err := newEvent(o, plan, eventType, payload, o.now())
	if err != nil {
		return err
	}
	return o.DB.AppendAuditEvent(ev)
}

func newEvent(o Options, plan Plan, eventType string, payload map[string]any, at time.Time) (*statedb.AuditEvent, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["identity"] = plan.Target.Key
	payload["identity_input"] = plan.Target.Input
	payload["subjects"] = plan.Target.Subjects
	payload["emails"] = plan.Target.Emails
	payload["reason"] = o.Reason
	payload["via"] = o.Via
	blob, err := marshalPayload(payload)
	if err != nil {
		return nil, err
	}
	actor := o.Actor
	if actor == "" {
		actor = "system"
	}
	return &statedb.AuditEvent{
		Timestamp:  at,
		Actor:      actor,
		EventType:  eventType,
		EntityType: "user",
		EntityID:   plan.Target.Key,
		Payload:    blob,
	}, nil
}

// ---------------------------------------------------------------------------
// Deny bindings
// ---------------------------------------------------------------------------

// denyRows builds one deny binding per resolved identifier.
func denyRows(plan Plan, o Options, now time.Time) []statedb.RoleBindingRow {
	out := make([]statedb.RoleBindingRow, 0, len(plan.Denies))
	for _, d := range plan.Denies {
		binding, err := authz.NormalizeBinding(authz.Binding{
			Claim: authz.ClaimKind(d.Claim),
			Value: d.Value,
			Role:  authz.RoleNone,
			Deny:  true,
		})
		if err != nil {
			// Unreachable: BuildPlan normalised these already. Skipping rather
			// than failing keeps a malformed claim from blocking the rest of
			// the offboarding, and the plan's warning already named it.
			continue
		}
		row, err := rolestore.RowFor(binding, o.Reason, o.Actor, now)
		if err != nil {
			continue
		}
		out = append(out, row)
	}
	return out
}

// plannedDenies lists the deny bindings a run would write for this target.
func plannedDenies(t Target) ([]DenyRef, []string) {
	var (
		out      []DenyRef
		warnings []string
	)
	add := func(kind authz.ClaimKind, value string) {
		binding, err := authz.NormalizeBinding(authz.Binding{
			Claim: kind, Value: value, Role: authz.RoleNone, Deny: true,
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"cannot deny %s %q: %v — this identifier will NOT be blocked", kind, value, err))
			return
		}
		out = append(out, DenyRef{
			ID: statedb.RoleBindingID(statedb.RoleEffectDeny, string(binding.Claim),
				binding.Value, binding.Project, binding.Executor),
			Claim: string(binding.Claim),
			Value: binding.Value,
		})
	}
	for _, e := range t.Emails {
		add(authz.ClaimEmail, e)
	}
	for _, s := range t.Subjects {
		add(authz.ClaimSub, s)
	}
	return out, warnings
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func sessionIDs(in []SessionRef) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, s.ID)
	}
	return out
}

func tokenIDs(in []TokenRef) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, t.ID)
	}
	return out
}
