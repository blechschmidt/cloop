package ui

// resume_account.go: the Claude account a run the hub carries on by itself
// acts on (Task 20443).
//
// handleRun, a project's Run and the new-project autorun pin a run on an
// executor that shares the hub's filesystem to the Claude home of the person
// who asked (claudeEnvResolver, Task 20241). Three dispatches have nobody
// asking: the automatic resume after a usage cap, the member a cluster's
// leader hands that resume to (clusterAPIAutoResume), and a failover's
// replacement. They passed no resolver at all, so on a hub with single
// sign-on such a run inherited the hub process's own environment — the shared
// login claude_identity.go says an unidentified caller must never fall back
// to. Measured on :8888 on 2026-10-26: the hub ran with HOME=/root and no
// CLAUDE_CONFIG_DIR, while the run it started carried its starter's
// CLAUDE_CONFIG_DIR; the run it resumed carried none. Since Task 20440 an
// extra-usage hold resumes too, so this happened after every exhausted
// five-hour window: the run carried on on another account, or failed as not
// logged in.
//
// resumeAccount answers for those dispatches, from what the control plane
// recorded: whom the run being carried on was started for
// (recordHarnessInitiator — the hub's database, never the project tree a
// sandbox can write), else, for a run older than that record, the project's
// owner. Its home is placed exactly as a request's is (claudeEnvFor): on an
// executor that shares the hub's filesystem, CLAUDE_CONFIG_DIR and a cleared
// ambient token; on one that isolates, nothing — the secret broker supplies
// the credential there, as before, with personal credentials counted for the
// same person (harnessWho).
//
// It never creates a home. HomeFor makes one when its owner signs in or starts
// something; a machine acting on their behalf later finds it or does not. A
// dispatch is refused (starterUnavailableError), and the run waits paused
// with a starter_unavailable reason for a person to start it as themselves,
// when:
//
//   - the person is denied on the hub — a global deny binding, or a
//     deactivation at the identity provider (ownerStanding): on every
//     executor, since an isolating one would still spend their personal
//     grants;
//   - their home is gone — offboarding removed it, or they never had one
//     here — on an executor that shares the hub's filesystem, where the home
//     is what the run would use;
//   - nobody can be named — no record and no owner — on such an executor
//     too, where the alternative is the hub's own login;
//   - the control plane cannot be read, on every executor.
//
// A run whose starter acted for no one — the static bearer token, a service
// token minted on nobody's behalf — ran on the hub's own login by design (see
// "Callers with no identity" in docs/security/claude-code-identity.md), and
// is carried on on it: the resume acts for the same nobody. A hub without
// single sign-on has one operator and one login, and nothing here applies.

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/ratelimit"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// How a resume's identity was decided, for the audit trail and for the record
// the resume leaves in turn.
const (
	// actedForStarter: the person the run being carried on was started for,
	// as the control plane recorded at its dispatch — "" for a caller that
	// acts for no one, the static bearer token or a service token.
	actedForStarter = "starter"
	// actedForOwner: no record names a starter — the run predates it — so
	// the project's owner, who is also who the resume bills.
	actedForOwner = "owner"
	// actedForUnknown: nobody can be named — no record and no owner, or a
	// record of a different run than the one paused (a `cloop run` started
	// from a shell). Refused where the run would use the hub's own login.
	actedForUnknown = "unknown"
)

// resumeAccount is whom an automatic dispatch of a project's run acts for, and
// on which Claude account.
type resumeAccount struct {
	workDir string
	// who is whom the dispatch acts for, as the harness preflight counts
	// personal credentials.
	who harnessWho
	// basis is how who was decided — actedForStarter, actedForOwner or
	// actedForUnknown — and "" on a hub without single sign-on.
	basis string
	// scope is who's Claude home. The zero scope is the hub's own login: on a
	// hub without single sign-on, and for a run started acting for no one.
	scope claudeScope
	// unavailable is why the dispatch may not act for who, or nil.
	unavailable *starterUnavailableError
}

// starterUnavailableError refuses an automatic dispatch that cannot act for
// the person the run it carries on was started for.
type starterUnavailableError struct {
	// Identity is whom the dispatch would have acted for; "" when nobody
	// could be named.
	Identity string
	// Basis is how Identity was decided: actedForStarter, actedForOwner or
	// actedForUnknown.
	Basis string
	// Reason says why: a clause following the person, or a whole sentence
	// when nobody could be named. It is what the project's readers see — the
	// pause reason, the journal — so it is the same plain clause whether the
	// person's home is gone or the hub denies them, and never carries what
	// only the hub's operators may: that someone is denied or suspended, a
	// deny binding's reason (an offboarding writes its reason there, often an
	// HR matter), a legal hold, a database error.
	Reason string
	// Cause is that detail, for the hub's own log: "" when Reason says it
	// all.
	Cause string
	// AnyExecutor says the refusal holds wherever the run would go — the
	// person is denied, or the control plane cannot be read — and not only on
	// an executor that shares the hub's filesystem, where a missing home is
	// what the run would have used, or the hub's own login the alternative.
	AnyExecutor bool
	// Transient says waiting may change it — the control plane could not be
	// read just now — so the run is refused but not held: the next sweep
	// asks again.
	Transient bool
	// Copilot says what is missing is a Copilot credential (Task 20449),
	// which the person grants rather than signs in for.
	Copilot bool
}

func (e *starterUnavailableError) Error() string {
	switch {
	case e.Identity != "" && e.Basis == actedForOwner:
		return e.Identity + ", the project's owner (no record names who started this run), " + e.Reason
	case e.Identity != "":
		return e.Identity + ", who started this run, " + e.Reason
	}
	return e.Reason
}

// logDetail is Error with the operator-only cause, for the hub's log.
func (e *starterUnavailableError) logDetail() string {
	if e.Cause == "" {
		return e.Error()
	}
	return e.Error() + " (" + e.Cause + ")"
}

// Remediation is what a person does about it.
func (e *starterUnavailableError) Remediation() string {
	if e.Copilot {
		return "Carrying it on would spend the hub's own Copilot sign-in or another person's. Grant your Copilot " +
			"credential to the project from its Overview if you have not, then press Run to start it as yourself."
	}
	return "Carrying it on would spend the hub's own Claude login or another person's. Press Run to start it " +
		"as yourself, which acts on your own account."
}

// pause is the reason the run waits paused with.
func (e *starterUnavailableError) pause() pausereason.Reason {
	return pausereason.New(pausereason.CodeStarterUnavailable, e.Error()+"; press Run to start it as yourself")
}

// errStarterUnavailable reports whether err is such a refusal, and returns it.
func errStarterUnavailable(err error) (*starterUnavailableError, bool) {
	var su *starterUnavailableError
	if errors.As(err, &su) && su != nil {
		return su, true
	}
	return nil, false
}

// Reasons. reasonUnusable follows the person; the others are sentences.
const (
	// reasonUnusable covers a home that is gone and a person the hub denies
	// alike, so a project's readers cannot tell the two apart: Cause does.
	reasonUnusable = "has no Claude Code login on this hub that the hub may use for them"
	reasonNobody   = "nobody is recorded as having started this run, and the project has no owner"
	// reasonUnnamed is for a record a resume left on the unknown basis.
	reasonUnnamed = "nobody could be named as having started this run, so the hub does not know whose Claude " +
		"account to carry it on"
	reasonElsewhere = "this run was not started from this hub — its own record names a run the hub did not " +
		"dispatch — so the hub does not know whose Claude account to carry it on"
	reasonNoPlane = "whom this run was started for cannot be read: this process holds no control plane"
	reasonUnread  = "whom this run was started for could not be read from the hub's control plane"
	// reasonNotOnExecutor is for an executor restricted to an access list
	// that does not name them (or, nobody named, cannot be checked).
	reasonNotOnExecutor = "may not use the executor this project runs on"
	// reasonNoUsage is for a pause an older build recorded, which clears by
	// the starter's own usage windows: there is none to read.
	reasonNoUsage = "has no Claude Code login on this hub whose usage could show the window reopened"
	// reasonNoCopilot covers, for a copilot run on the hub's own host (Task
	// 20449), a person with no Copilot credential granted to the project that
	// counts for them, and one whose Copilot home is gone: Cause says which.
	reasonNoCopilot = "has no Copilot credential on this hub that the hub may use for them"
	// reasonNoCopilotNobody is for a run started acting for no one.
	reasonNoCopilotNobody = "this run was started acting for no one, and no Copilot credential is shared with the " +
		"project — the hub never signs a Copilot run in with its own"
)

// unavailableHomePath is where a dispatch that must not run on any Claude
// login points CLAUDE_CONFIG_DIR, should the clearance that refuses it ever
// be bypassed: under a file, so nobody — root included — can create it, and
// the CLI finds itself logged out instead of falling back to the hub's own
// login.
const unavailableHomePath = "/dev/null/cloop-no-claude-account"

// resumeAccountFor resolves whom an automatic dispatch of workDir's run acts
// for, and its Claude account, without creating anything.
func (s *Server) resumeAccountFor(workDir string) *resumeAccount {
	acct := &resumeAccount{workDir: workDir, who: harnessWho{personal: s.oidcEnabled()}}
	if !acct.who.personal {
		return acct // one operator and one login: the host's own, as before
	}
	refuse := func(e *starterUnavailableError) *resumeAccount {
		e.Identity, e.Basis = acct.who.identity, acct.basis
		acct.unavailable = e
		return acct
	}

	dir := controlPlaneDir()
	if dir == "" {
		return refuse(&starterUnavailableError{Reason: reasonNoPlane, AnyExecutor: true})
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return refuse(&starterUnavailableError{Reason: reasonUnread, Cause: err.Error(), AnyExecutor: true, Transient: true})
	}
	defer db.Close() //nolint:errcheck

	rec, ok, err := readHarnessInitiator(db, workDir)
	var describes bool
	if err == nil && ok {
		describes, err = recordDescribesPausedRun(rec, workDir)
	}
	switch {
	case errors.Is(err, errInitiatorUnreadable):
		// Not a read that may work next time: held until a person starts it.
		return refuse(&starterUnavailableError{Reason: reasonUnread, Cause: err.Error(), AnyExecutor: true})
	case err != nil:
		return refuse(&starterUnavailableError{Reason: reasonUnread, Cause: err.Error(), AnyExecutor: true, Transient: true})
	case ok && rec.Stale:
		acct.basis = actedForUnknown
		return refuse(&starterUnavailableError{Reason: reasonUnnamed,
			Cause: "the hub's two records of who started the run disagree: an older hub build dispatched it since"})
	case ok && !describes:
		acct.basis = actedForUnknown
		return refuse(&starterUnavailableError{Reason: reasonElsewhere,
			Cause: "the recorded run " + rec.RunID + " was dispatched at " + rec.At.UTC().Format(time.RFC3339) +
				"; the project's own run record names a run started later"})
	case ok:
		acct.who.identity, acct.basis = secretbroker.NormalizeOwner(rec.Identity), rec.Basis
		if acct.basis == actedForUnknown {
			return refuse(&starterUnavailableError{Reason: reasonUnnamed})
		}
		if acct.who.identity == "" {
			// Started acting for no one, and so on the hub's own login by
			// design: the resume acts for the same nobody.
			return acct
		}
	default:
		acct.who.identity, acct.basis = s.projectOwnerKey(workDir), actedForOwner
		if acct.who.identity == "" {
			acct.basis = actedForUnknown
			return refuse(&starterUnavailableError{Reason: reasonNobody})
		}
	}

	standing, err := readOwnerStanding(db, acct.who.identity)
	if err != nil {
		return refuse(&starterUnavailableError{Reason: reasonUnread, Cause: err.Error(), AnyExecutor: true, Transient: true})
	}
	if standing.denied() {
		return refuse(&starterUnavailableError{
			Reason: reasonUnusable, Cause: deniedClause(db, acct.who.identity, standing), AnyExecutor: true})
	}
	bindings, err := db.ListRoleBindings()
	if err != nil {
		return refuse(&starterUnavailableError{Reason: reasonUnread, Cause: err.Error(), AnyExecutor: true, Transient: true})
	}
	if deny := s.projectDenial(bindings, acct.who.identity, workDir); deny != nil {
		return refuse(&starterUnavailableError{Reason: reasonUnusable, AnyExecutor: true,
			Cause: "denied on this project by a role binding (" + denyBindingReason(*deny) + ")"})
	}

	home, err := claudecodeauth.HomePath(acct.who.identity)
	if err != nil {
		return refuse(&starterUnavailableError{Reason: reasonUnusable, Cause: "no resolvable Claude home: " + err.Error()})
	}
	if fi, err := os.Stat(home); err != nil || !fi.IsDir() {
		return refuse(&starterUnavailableError{Reason: reasonUnusable,
			Cause: "no Claude home: they were offboarded, or never signed in on this hub"})
	}
	acct.scope = claudeScope{Owner: acct.who.identity, ConfigDir: home}
	return acct
}

// recordTolerance is how much later than the dispatch it records a run's own
// process may have started and still be that dispatch's: the hub takes the
// record's time once the workload is up, and the run takes its own as its
// binary initialises — the two are a moment apart, either way round.
const recordTolerance = time.Minute

// recordDescribesPausedRun reports whether rec, the record of whom workDir's
// last hub-dispatched run was started for, speaks for the run paused there
// now. A run records its own process (run_owner); the one the hub dispatched
// started when the record was written. A run that recorded itself well after
// that was started some other way — a `cloop run` from a shell, a hub that
// keeps no record — whatever run id it took up: a shell's run adopts the
// hub's from the placement record the hub left, for ten minutes. A record of
// a run that records nothing of itself here — a device's, whose run_owner
// stays on the device — is newer than whatever run_owner says, and is
// honoured; so is a record older than the run binding.
//
// run_owner is written in the project's tree, which the run itself can
// write: this keeps the hub from misattributing a run, and is no boundary
// against a workload on the hub's own host, which can read every home there.
func recordDescribesPausedRun(rec harnessInitiator, workDir string) (bool, error) {
	if rec.RunID == "" || rec.At.IsZero() {
		return true, nil
	}
	st, err := state.LoadLite(workDir)
	if err != nil {
		return false, err
	}
	if st == nil || st.RunOwner == nil || st.RunOwner.StartedAt.IsZero() {
		return true, nil
	}
	return !st.RunOwner.StartedAt.After(rec.At.Add(recordTolerance)), nil
}

// deniedClause says why the hub denies owner, for the hub's operators only.
func deniedClause(db *statedb.DB, owner string, standing ownerStanding) string {
	if d := standing.deactivated; standing.suspended() {
		on := ""
		if !d.DeactivatedAt.IsZero() {
			on = " on " + d.DeactivatedAt.UTC().Format("2006-01-02")
		}
		return "suspended: deactivated at the identity provider" + on
	}
	if d := standing.deactivated; d != nil {
		return "offboarded on " + d.OffboardedAt.UTC().Format("2006-01-02") +
			", after the identity provider deactivated them"
	}
	if _, held, err := db.LegalHoldFor([]string{owner}); err == nil && held {
		return "offboarded; what they kept here is held only as evidence, under a legal hold"
	}
	return "denied by a role binding (" + standing.denyReason() + ")"
}

// projectDenial finds a deny binding on owner scoped to workDir's project — by
// its path or its registry name, a feature as its parent, exactly the scope
// authz checks a request on the project against (workDirScope). One scoped to
// an executor is not looked at: authz applies those to managing the executor,
// never to a project's run, and who may run work on an executor is its access
// list, which check reads. A binding on a group or a role is not among them
// either: whether the person is in it is a claim of their sign-in, which a
// machine acting for them does not have.
func (s *Server) projectDenial(bindings []statedb.RoleBindingRow, owner, workDir string) *statedb.RoleBindingRow {
	scope := s.workDirScope(workDir)
	for i, b := range bindings {
		if b.Effect != statedb.RoleEffectDeny || b.Project == "" || b.Executor != "" {
			continue
		}
		key := ""
		switch b.Claim {
		case "email":
			key = strings.ToLower(strings.TrimSpace(b.Value))
		case "sub":
			key = "sub:" + strings.TrimSpace(b.Value)
		}
		if key == "" || key != owner {
			continue
		}
		project := strings.TrimSpace(b.Project)
		if strings.EqualFold(project, scope.ProjectPath) || (scope.Project != "" && strings.EqualFold(project, scope.Project)) {
			return &bindings[i]
		}
	}
	return nil
}

// denyBindingReason is a deny binding's recorded reason, or a placeholder.
func denyBindingReason(b statedb.RoleBindingRow) string {
	return ownerStanding{deny: &b}.denyReason()
}

// projectOwnerKey is workDir's registered owner, normalised as owner keys are.
func (s *Server) projectOwnerKey(workDir string) string {
	for _, e := range s.allProjectEntries() {
		if e.Path == workDir {
			return secretbroker.NormalizeOwner(e.Owner)
		}
	}
	return ""
}

// envFor is the environment that pins a dispatch to ex to the account —
// claudeEnvFor, the placement every request's run gets. An account the
// dispatch may not act for is refused by check, in the clearance; should a
// caller ever pair this with another clearance, it still pins no login at all
// rather than leaving the hub's own in place.
func (a *resumeAccount) envFor(ex executor.Executor) []string {
	if a == nil || ex == nil {
		return nil
	}
	if a.unavailable != nil {
		if executor.IsolatesFromHost(ex) {
			return nil
		}
		return claudecodeauth.ScopeHarnessEnv(nil, unavailableHomePath)
	}
	return claudeEnvFor(a.scope, ex)
}

// check refuses a dispatch to ex that cannot act for the account's person.
func (a *resumeAccount) check(ex executor.Executor) error {
	if a == nil || ex == nil {
		return nil
	}
	if a.unavailable != nil && (a.unavailable.AnyExecutor || !executor.IsolatesFromHost(ex)) {
		return a.unavailable
	}
	return a.checkAudience(ex)
}

// checkAudience refuses a dispatch to an executor whose access list shows the
// person is not on it — as /api/run would refuse them (Task 20310). It can
// show that only from entries of the kind the person is known by — their
// email, or their subject when the identity provider gave no email — since a
// resume knows them by that one key: a group or role entry admits by a claim
// of a sign-in, and a subject entry for a person known by email by the other
// half of it, neither of which a machine acting for them has. A list with such
// an entry may admit them and is left as it was. An unreadable list refuses,
// as it does for a person.
func (a *resumeAccount) checkAudience(ex executor.Executor) error {
	if !a.who.personal {
		return nil
	}
	entries, err := executorAudience(ex.ID())
	if err != nil {
		return &starterUnavailableError{Identity: a.who.identity, Basis: a.basis, Reason: reasonNotOnExecutor,
			Cause: err.Error(), AnyExecutor: true, Transient: true}
	}
	members := audienceMembers(entries)
	if len(members) == 0 {
		return nil
	}
	subject, known := &authz.Subject{}, authz.ClaimEmail
	if rest, ok := strings.CutPrefix(a.who.identity, "sub:"); ok {
		subject.Sub, known = rest, authz.ClaimSub
	} else {
		subject.Email = a.who.identity
	}
	if a.who.identity != "" && authz.Admits(members, subject) {
		return nil
	}
	// A run started acting for no one could never have passed a restricted
	// list either: nobody is admitted by anything.
	for _, m := range members {
		if a.who.identity != "" && m.Kind != known {
			return nil
		}
	}
	return &starterUnavailableError{Identity: a.who.identity, Basis: a.basis, Reason: reasonNotOnExecutor,
		Cause: "not on the access list of executor " + ex.ID(), AnyExecutor: true}
}

// actedFor is the owner key the dispatch acts for, "" for no one.
func (a *resumeAccount) actedFor() string {
	if a == nil {
		return ""
	}
	return a.who.identity
}

// auditFields are what an audit row or journal entry records about whom the
// dispatch acted for: nothing on a hub without single sign-on, where there is
// one operator and nobody to name.
func (a *resumeAccount) auditFields() map[string]any {
	if a == nil || !a.who.personal || a.basis == "" {
		return nil
	}
	out := map[string]any{"acted_for_basis": a.basis}
	if a.who.identity != "" {
		out["acted_for"] = a.who.identity
	}
	return out
}

// describe renders whom the dispatch acted for in a journal sentence, or "".
func (a *resumeAccount) describe() string {
	switch {
	case a == nil || !a.who.personal || a.basis == "":
		return ""
	case a.who.identity == "" && a.basis == actedForUnknown:
		return "acting for no one: nobody can be named for the run it continues"
	case a.who.identity == "":
		return "acting for no one, as the run it continues was started"
	case a.basis == actedForOwner:
		return "acting for " + a.who.identity + ", the project's owner"
	}
	return "acting for " + a.who.identity + ", who started it"
}

// usageDir is the Claude configuration directory whose usage windows judge a
// pause for this account — "" for the hub's own — and false when there is
// none to read: nobody can be named, the person's home is gone, or they may
// not be acted for.
func (a *resumeAccount) usageDir() (string, bool) {
	switch {
	case a == nil:
		return "", true
	case a.unavailable != nil:
		return "", false
	}
	return a.scope.ConfigDir, true
}

// noUsage is why an older build's pause cannot be judged for this account, or
// nil when it can. Transient when the account itself is: the next sweep asks
// again.
func (a *resumeAccount) noUsage() *starterUnavailableError {
	if a == nil || a.unavailable == nil {
		return nil
	}
	e := *a.unavailable
	if e.Identity != "" {
		e.Reason = reasonNoUsage
	}
	return &e
}

// noCopilot is the refusal of a copilot dispatch to the hub's own host acting
// for the account's person, who has no Copilot credential that counts for them
// there or no Copilot home (Task 20449): cause is the preflight's refusal or
// the home's error, for the hub's log, and rep says whether it may clear by
// itself — a broker that could not be read just now.
func (a *resumeAccount) noCopilot(rep harnessReport, cause error) *starterUnavailableError {
	e := &starterUnavailableError{Identity: a.who.identity, Basis: a.basis, Reason: reasonNoCopilot, Copilot: true,
		Transient: rep.BrokerProblem != "" && !rep.BrokerUnset && !rep.NoControlPlane}
	if a.who.identity == "" {
		e.Reason = reasonNoCopilotNobody
	}
	if cause != nil {
		e.Cause = cause.Error()
	}
	return e
}

// newResumeClearance is the harness preflight for an automatic dispatch acting
// for a: the checks every run gets, and a's own — settled, like them, against
// the executor the dispatch resolves.
func newResumeClearance(a *resumeAccount) *harnessClearance {
	return &harnessClearance{workDir: a.workDir, who: a.who, basis: a.basis, check: true, account: a}
}

// resumeAccountUsage reads the usage windows of an account's Claude login:
// the starter's own, read under their home, or the hub's for the hub's own
// login. Cached for ratelimit.MinUsageCacheTTL like every other reader of it.
func resumeAccountUsage(configDir string) (*ratelimit.ClaudeUsage, error) {
	if configDir == "" {
		return ratelimit.FetchOrCachedUsage("", ratelimit.MinUsageCacheTTL)
	}
	return ratelimit.FetchOrCachedUsageIn(configDir, "", ratelimit.MinUsageCacheTTL)
}
