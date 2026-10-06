package ui

// ci_sessions.go: a CI relay session outlives the hub process that minted it
// (Task 20390).
//
// A GitHub Actions job that federated with the hub uses it as
// ANTHROPIC_BASE_URL for the rest of the job, for up to six hours. Its session
// lived in the memory of the process that minted it, so a job relaying through
// the hub during a nightly deploy or a rolling update got a 401 on its next
// call, retried it for about three minutes and failed with "Not logged in" —
// and could not simply federate again, because the OIDC token it exchanged had
// been spent and the jti replay guard refuses it a second time.
//
// Each session is now recorded (ci_sessions, through pkg/claudeproxy's
// Store): the SHA-256 of its token, the rule and the verified claims it was
// minted for, its policy and its spend — never the token, and never the hub's
// Anthropic credential, which is configuration and not the session's.
// Counters are flushed every ciCheckpointInterval and when the hub stops, and a
// hub that stops gracefully suspends its sessions rather than closing them.
//
// A request presenting the token of a session no live hub process serves is
// restored by the member receiving it — on demand, which is safe here as it is
// not for the git proxy's sessions: no lease stands behind a CI session, so
// restoring it where the request arrives separates it from nothing. The
// restore:
//
//  1. proves possession: the presented token must hash to the record's;
//  2. takes the record over by a conditional write on its holder, so of two
//     members receiving the job's calls one restores it and the other forwards
//     to it;
//  3. holds it to its rule as the rule stands now: a rule deleted, disabled or
//     no longer compiling, a pipeline the rule no longer admits, or an
//     identity the hub no longer federates gets the 401 the job would have got
//     and the session is closed; a narrowed policy or TTL applies, a widened
//     one does not;
//  4. serves it under its id and token hash with the counters it had reached,
//     so its request budget is the one it had left.
//
// The jti replay guard is untouched: a restore exchanges nothing.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/ciauth"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/sessionrecord"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ciCheckpointInterval is how often a live session's counters are flushed to
// its record. A hub killed outright loses at most this much of a session's
// count, which is what a restored session may overspend its request budget by.
// It is also how soon a hub process notices its own configuration switched
// federation off. A variable so tests can shorten it.
var ciCheckpointInterval = 15 * time.Second

// ciRestoreClaimWait bounds how long a member that lost the race to restore a
// session looks for the winner's claim, to forward the request there.
var ciRestoreClaimWait = 3 * time.Second

// ── the record ───────────────────────────────────────────────────────────────

// The record itself — its provenance, the store that writes it, the reader —
// lives in pkg/sessionrecord beside the git, Kubernetes and egress stores.

func newCISessionStore(db *statedb.DB, instance string) claudeproxy.SessionStore {
	return sessionrecord.NewCIStore(db, sessionHolderID, instance, logSessionStoreErr)
}

// ciInstance names this hub instance in the records of the CI sessions it
// serves (ci_sessions.instance): its port, which names the per-instance
// overlay that may set ui.ci.enabled (config.UIInstanceConfigPath), and which
// a restarted instance binds again. Its configuration governs those records;
// another instance's governs that one's.
func (s *Server) ciInstance() string {
	return strconv.Itoa(s.Port)
}

// ciInstanceLabel names an instance for a person reading a close reason.
func ciInstanceLabel(instance string) string {
	if instance == "" || instance == "0" {
		return "no port of its own"
	}
	return "port " + instance
}

// ciRecordOf reads a row back into what claudeproxy.Registry.Restore takes.
func ciRecordOf(row statedb.CISessionRow) (claudeproxy.SessionRecord, sessionrecord.CIProvenance, error) {
	return sessionrecord.CIRecord(row)
}

// ── restoring on demand ──────────────────────────────────────────────────────

// ciPresentedToken is the credential a relay request carries, as the relay
// reads it: a bearer, else x-api-key.
func ciPresentedToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		if tok, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return strings.TrimSpace(tok)
		}
		return ""
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

// ciHolderAlive reports whether the hub process holding a CI session's record
// is a live cluster member. A variable so tests can stand in for a cluster.
var ciHolderAlive = func(holder string) bool {
	n := currentCluster()
	return n != nil && n.IsAlive(holder)
}

// ciRestoreFlights makes the restores of one session single-flight in this
// process: a job's parallel calls arriving together share one restore, and
// each then acts on its outcome — served here, forwarded to the member that
// restored it, or refused. A flight is taken only by a caller that proved it
// holds the session's token, so knowing a session's id — it is in audit rows —
// cannot hold up the job's own calls.
var ciRestoreFlights = struct {
	sync.Mutex
	m map[string]*ciRestoreFlight
}{m: map[string]*ciRestoreFlight{}}

// ciRestoreFlight is one restore in progress; outcome is set before done
// closes.
type ciRestoreFlight struct {
	done    chan struct{}
	outcome ciRestoreOutcome
}

// restoreCISessionOnDemand brings back the session a relay request names, if
// it is recorded, the request holds its token, and no live hub process serves
// it. It reports whether it answered the request (forwarded it to the member
// that restored the session first); otherwise the relay decides the request
// here, against whatever the registry holds now.
func (s *Server) restoreCISessionOnDemand(w http.ResponseWriter, r *http.Request, svc *ciService, id string) bool {
	if svc == nil || svc.auditDB == nil || svc.reg == nil {
		return false
	}
	token := ciPresentedToken(r)
	if got, ok := claudeproxy.SessionIDOf(token); !ok || got != id {
		return false
	}
	// Possession first: a caller without the token gets the 401 it always
	// got, having taken nothing another caller waits on.
	if !ciTokenMatchesRecord(svc.auditDB, id, token) {
		return false
	}
	ciRestoreFlights.Lock()
	if f, busy := ciRestoreFlights.m[id]; busy {
		ciRestoreFlights.Unlock()
		select {
		case <-f.done:
		case <-r.Context().Done():
			return false
		}
		return s.afterCIRestore(w, r, id, f.outcome)
	}
	// Failed unless the restore says otherwise: one that panics leaves the
	// waiters a verdict that decides nothing.
	f := &ciRestoreFlight{done: make(chan struct{}), outcome: ciRestoreFailed}
	ciRestoreFlights.m[id] = f
	ciRestoreFlights.Unlock()

	func() {
		// Released before anything is forwarded — a forwarded response
		// streams for as long as the model answers, and the calls waiting
		// here must not wait for that — and released however the restore
		// ends, or every later call for the session would wait on it.
		defer func() {
			ciRestoreFlights.Lock()
			delete(ciRestoreFlights.m, id)
			ciRestoreFlights.Unlock()
			close(f.done)
		}()
		f.outcome = s.restoreCISession(svc, id, token)
	}()

	if label := f.outcome.metric(); label != "" {
		hubmetrics.SessionRestores.Inc(hubmetrics.RestoreKindCI, label)
	}
	return s.afterCIRestore(w, r, id, f.outcome)
}

// afterCIRestore acts on a restore's outcome for one request: a session
// another member restored first is forwarded there once that member claims
// it; anything else is decided here.
func (s *Server) afterCIRestore(w http.ResponseWriter, r *http.Request, id string, outcome ciRestoreOutcome) bool {
	if outcome == ciRestoreLost {
		return s.forwardCIRequestOnceClaimed(w, r, id)
	}
	return false
}

// ciTokenMatchesRecord reports whether token hashes to the record of session
// id, comparing in constant time.
func ciTokenMatchesRecord(db *statedb.DB, id, token string) bool {
	row, err := db.GetCISession(id)
	if err != nil {
		return false
	}
	return ciTokenMatches(row, token)
}

// ciTokenMatches reports whether token hashes to row's token hash.
func ciTokenMatches(row statedb.CISessionRow, token string) bool {
	want, err := hex.DecodeString(row.TokenSHA256)
	sum := sha256.Sum256([]byte(token))
	return err == nil && len(want) == sha256.Size && subtle.ConstantTimeCompare(sum[:], want) == 1
}

// ciRestoreOutcome is what one attempt to restore a session came to.
type ciRestoreOutcome int

const (
	ciRestoreNone     ciRestoreOutcome = iota // nothing to restore: unknown, closed, or the wrong token
	ciRestoreRestored                         // served here now
	ciRestoreLost                             // another hub process took it over first
	ciRestoreRefused                          // held to its rule, refused, and closed
	ciRestoreExpired                          // it lapsed before anything presented it
	ciRestoreFailed                           // could not be decided: the store did not answer
)

// metric is the outcome's cloop_proxy_session_restores_total label, "" for a
// request that restored nothing because there was nothing of its to restore.
func (o ciRestoreOutcome) metric() string {
	switch o {
	case ciRestoreRestored:
		return hubmetrics.RestoreRestored
	case ciRestoreLost:
		return hubmetrics.RestoreLost
	case ciRestoreRefused:
		return hubmetrics.RestoreRefused
	case ciRestoreExpired:
		return hubmetrics.RestoreExpired
	case ciRestoreFailed:
		return hubmetrics.RestoreFailed
	}
	return ""
}

// restoreCISession restores session id for a request presenting token.
func (s *Server) restoreCISession(svc *ciService, id, token string) ciRestoreOutcome {
	db := svc.auditDB
	self := leaseHolderID()
	if self == "" || svc.reg.Known(id) {
		return ciRestoreNone
	}
	row, err := db.GetCISession(id)
	switch {
	case errors.Is(err, statedb.ErrCISessionNotFound):
		return ciRestoreNone
	case err != nil:
		fmt.Fprintf(os.Stderr, "ui: read CI session %s: %v\n", id, err)
		return ciRestoreFailed
	case !row.Open():
		return ciRestoreNone
	}
	// Possession, before anything is written — again, on the record as read
	// now: a caller who merely knows the id learns nothing and changes
	// nothing.
	if !ciTokenMatches(row, token) {
		return ciRestoreNone
	}
	if !sessionNow().Before(row.ExpiresAt) {
		return ciRestoreExpired // the janitor retires it
	}
	from := row.Holder
	if from != self {
		if from != "" && ciHolderAlive(from) {
			// A live process holds it and does not claim to serve it:
			// that process's business.
			return ciRestoreNone
		}
		took, err := db.TakeCISession(id, from, self, svc.instance)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: take over CI session %s: %v\n", id, err)
			return ciRestoreFailed
		}
		if !took {
			return ciRestoreLost
		}
		row.Holder = self
	}

	// Held to the configuration of the instance it was served under, too:
	// one whose federation was switched off while none of its processes
	// served the session — stopped, or come back on another port — must not
	// have it restored here, where federation is on.
	if row.Instance != svc.instance && s.ciInstanceSwitchedOff(row.Instance) {
		s.refuseCIRestore(svc, row, fmt.Sprintf("federation is switched off on the hub instance that served it (%s)",
			ciInstanceLabel(row.Instance)))
		return ciRestoreRefused
	}
	rec, _, err := ciRecordOf(row)
	if err != nil {
		s.refuseCIRestore(svc, row, "its record cannot be read: "+err.Error())
		return ciRestoreRefused
	}
	held, detail, why, transient := s.holdCISessionToItsRule(svc, rec)
	switch {
	case transient:
		// Nothing decided — the rule could not be read just now. Held here,
		// unrestored; the job's next call tries again.
		fmt.Fprintf(os.Stderr, "ui: restore CI session %s (will retry): %s\n", id, why)
		return ciRestoreFailed
	case why != "":
		s.refuseCIRestore(svc, row, why)
		return ciRestoreRefused
	}
	pol, err := json.Marshal(held.Policy)
	if err != nil {
		return ciRestoreFailed
	}
	if ok, err := db.NarrowCISession(id, self, svc.instance, string(pol), held.ExpiresAt); err != nil {
		fmt.Fprintf(os.Stderr, "ui: record the policy restored CI session %s is held to: %v\n", id, err)
		return ciRestoreFailed
	} else if !ok {
		// Closed or taken over since it was read: not this process's.
		return ciRestoreLost
	}
	if _, err := svc.reg.Restore(claudeproxy.RestoreRequest{Record: held, From: from, Detail: detail}); err != nil {
		switch {
		case errors.Is(err, claudeproxy.ErrSessionExists):
			return ciRestoreRestored
		case errors.Is(err, claudeproxy.ErrTooManySessions):
			// Says nothing about this session: held here, tried again.
			fmt.Fprintf(os.Stderr, "ui: restore CI session %s (will retry): %v\n", id, err)
			return ciRestoreFailed
		case errors.Is(err, claudeproxy.ErrSessionLapsed):
			s.refuseCIRestore(svc, row, "it lapsed before it could be restored")
			return ciRestoreExpired
		case errors.Is(err, claudeproxy.ErrClosedHere):
			s.refuseCIRestore(svc, row, "this hub process had closed it")
		default:
			s.refuseCIRestore(svc, row, err.Error())
		}
		return ciRestoreRefused
	}
	fmt.Fprintf(os.Stderr, "ui: restored CI session %s (%s), held until then by %s\n", id, held.Repository, from)
	return ciRestoreRestored
}

// holdCISessionToItsRule holds a recorded session to its rule as the rule
// stands now. It returns the record to restore — its policy narrowed, its
// deadline clamped — and a note of what was narrowed; or why the session may
// not be restored, and whether that may pass (the rule could not be read).
func (s *Server) holdCISessionToItsRule(svc *ciService, rec claudeproxy.SessionRecord) (claudeproxy.SessionRecord, string, string, bool) {
	held, detail, why := s.holdCISessionToRule(svc, rec)
	return held, detail, why, why == ciRuleUnreadable
}

// ciRuleUnreadable is holdCISessionToRule's answer when the rule could not be
// read: nothing was decided.
const ciRuleUnreadable = "its rule could not be read just now"

func (s *Server) holdCISessionToRule(svc *ciService, rec claudeproxy.SessionRecord) (claudeproxy.SessionRecord, string, string) {
	if strings.TrimSpace(rec.RuleID) == "" {
		return rec, "", "it names no rule"
	}
	row, err := s.getCIRule(rec.RuleID)
	switch {
	case errors.Is(err, statedb.ErrCIPipelineRuleNotFound):
		return rec, "", "its rule was deleted"
	case err != nil:
		return rec, "", ciRuleUnreadable
	}
	rule := ciRuleFromRow(row)
	if !rule.Enabled {
		return rec, "", "its rule is disabled"
	}
	if err := rule.Prepare(); err != nil {
		return rec, "", "its rule no longer compiles: " + err.Error()
	}
	var all map[string]any
	if len(rec.Claims) == 0 || json.Unmarshal(rec.Claims, &all) != nil || len(all) == 0 {
		return rec, "", "its record carries no verified claims to hold the rule to"
	}
	claims := ciauth.ClaimsFromPayload(all)
	if err := svc.verifier.Federates(claims); err != nil {
		return rec, "", "the hub no longer federates the identity it was minted for: " + err.Error()
	}
	ok, err := rule.Matches(claims)
	if err != nil {
		return rec, "", "its rule can no longer be decided for this pipeline: " + err.Error()
	}
	if !ok {
		return rec, "", "its rule no longer admits this pipeline"
	}
	models := rule.Policy.Models
	if len(models) == 0 {
		models = svc.models
	}
	now := claudeproxy.Policy{
		Models:          models,
		MaxOutputTokens: rule.Policy.MaxOutputTokens,
		MaxRequests:     rule.Policy.Requests(),
	}
	held, err := claudeproxy.Narrow(rec.Policy, now)
	if err != nil {
		return rec, "", err.Error()
	}
	var notes []string
	if strings.Join(held.Models, ",") != strings.Join(rec.Policy.Models, ",") {
		notes = append(notes, "models narrowed to "+strings.Join(held.Models, ","))
	}
	if held.MaxRequests != rec.Policy.MaxRequests {
		notes = append(notes, fmt.Sprintf("request budget narrowed to %d", held.MaxRequests))
	}
	if held.OutputCap() != rec.Policy.OutputCap() {
		notes = append(notes, fmt.Sprintf("max_tokens narrowed to %d", held.OutputCap()))
	}
	out := rec
	out.Policy = held
	if limit := rec.IssuedAt.Add(rule.Policy.TTL()); out.ExpiresAt.After(limit) {
		out.ExpiresAt = limit
		notes = append(notes, "deadline held to its rule's TTL")
	}
	if !sessionNow().Before(out.ExpiresAt) {
		return rec, "", fmt.Sprintf("its rule's TTL of %s has run out since it was issued", rule.Policy.TTL())
	}
	if out.RuleName == "" {
		out.RuleName = rule.Name
	}
	return out, strings.Join(notes, "; "), ""
}

// refuseCIRestore closes this process's record of a session it took over and
// may not restore, and writes the close row no registry will.
func (s *Server) refuseCIRestore(svc *ciService, row statedb.CISessionRow, why string) {
	reason := "not restored by the hub process that received its next request: " + why
	ok, err := svc.auditDB.CloseCISession(row.SessionID, leaseHolderID(), sessionNow().UTC(), reason, "")
	if err != nil || !ok {
		return
	}
	appendCIRecordEnd(svc.auditDB, row, reason)
	fmt.Fprintf(os.Stderr, "ui: CI session %s %s\n", row.SessionID, reason)
}

// forwardCIRequestOnceClaimed forwards a relay request to the member that
// restored its session, once that member claims it, and reports whether it
// did.
func (s *Server) forwardCIRequestOnceClaimed(w http.ResponseWriter, r *http.Request, id string) bool {
	n := s.clusterNode()
	if n == nil {
		return false
	}
	deadline := time.Now().Add(ciRestoreClaimWait)
	for {
		if o, found, err := n.Lookup(ownerCISession, id); err == nil && found && !o.Self && o.Alive {
			return s.forwardTo(w, r, o.Member)
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-r.Context().Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// ── ending records nobody serves ─────────────────────────────────────────────

// closeCISessionRecordsForRule ends the records of every open session a rule
// minted, whoever holds them, after the live ones here were closed: a session
// no process serves right now must not be restored later under a rule that no
// longer stands. It returns how many it closed.
func closeCISessionRecordsForRule(db *statedb.DB, ruleID, reason string) int {
	if db == nil {
		return 0
	}
	rows, err := db.CloseCISessionsForRule(ruleID, time.Now().UTC(), reason)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: close the CI session records of rule %s: %v\n", ruleID, err)
		return 0
	}
	for _, row := range rows {
		appendCIRecordEnd(db, row, reason)
	}
	return len(rows)
}

// closeDormantCISessionRecords ends the records of instance's open sessions that
// no live hub process serves — held by one that stopped, by none, or by this
// one without served reporting it served here (nil: none is) — because CI
// federation was switched off or reconfigured on that instance, and none of
// them may be restored under a configuration that no longer stands. Another
// instance's records are governed by its own configuration — its overlay may
// set ui.ci.enabled otherwise (hubconfig.go) — and a session a live process
// serves is that process's to end. It returns how many it closed.
func closeDormantCISessionRecords(db *statedb.DB, instance, reason string, served func(string) bool) int {
	var rows []statedb.CISessionRow
	for _, row := range dormantCISessionRecords(db, served) {
		if row.Instance == instance {
			rows = append(rows, row)
		}
	}
	return closeCISessionRecordRows(db, rows, reason, served)
}

// dormantCISessionRecords returns the open records, of every instance, that
// no live hub process serves: held by one that stopped, by none, or by this
// one without served reporting it served here (nil: none is).
func dormantCISessionRecords(db *statedb.DB, served func(string) bool) []statedb.CISessionRow {
	if db == nil {
		return nil
	}
	rows, err := db.ListCISessions(statedb.CISessionFilter{OpenOnly: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: read the CI session records: %v\n", err)
		return nil
	}
	self := leaseHolderID()
	var out []statedb.CISessionRow
	for _, row := range rows {
		if row.Holder != "" && row.Holder != self && ciHolderAlive(row.Holder) {
			continue
		}
		if row.Holder == self && self != "" && served != nil && served(row.SessionID) {
			continue // this process's registry ends it, and writes its row
		}
		out = append(out, row)
	}
	return out
}

// closeCISessionRecordRows closes the records rows read, each fenced on the
// holder it was read with and skipped if served now reports it served here,
// writes the close rows no registry will, and returns how many it closed.
func closeCISessionRecordRows(db *statedb.DB, rows []statedb.CISessionRow, reason string,
	served func(string) bool) int {
	n := 0
	for _, row := range rows {
		if served != nil && served(row.SessionID) {
			continue // restored here since it was read
		}
		// Fenced on the holder read: one another process restored
		// meanwhile is left alone.
		if ok, err := db.CloseCISession(row.SessionID, row.Holder, time.Now().UTC(), reason, ""); err != nil || !ok {
			continue
		}
		appendCIRecordEnd(db, row, reason)
		n++
	}
	return n
}

// appendCIRecordEnd writes the ci.session.closed row for a session whose
// registry will never write one: it ended while no process served it.
func appendCIRecordEnd(db *statedb.DB, row statedb.CISessionRow, reason string) {
	rec, prov, err := ciRecordOf(row)
	if err != nil {
		rec = claudeproxy.SessionRecord{ID: row.SessionID, RuleID: row.RuleID}
	}
	if err := appendCIAuditEvent(db, claudeproxy.Event{
		Kind: claudeproxy.EventSessionClosed, SessionID: row.SessionID, RuleID: row.RuleID,
		RuleName: prov.RuleName, Project: prov.Project, Subject: prov.Subject, Repository: prov.Repository,
		Ref: prov.Ref, Workflow: prov.Workflow, Actor: prov.Actor, RunID: prov.RunID,
		Detail: fmt.Sprintf("%s: %d requests, %d denied, %d tokens", reason, rec.Usage.Requests,
			rec.Usage.Denied, rec.Usage.TotalTokens()),
		At: time.Now().UTC(),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ui: audit the end of CI session %s: %v\n", row.SessionID, err)
	}
}

// ── the janitor ──────────────────────────────────────────────────────────────

// sweepCISessionRecords retires the records of CI sessions nobody will
// restore: closed ones; open ones well past their deadline, whoever holds
// them; and lapsed ones whose holder is not a live hub process — or is this
// one, and serves them no more. Only the leader sweeps. It returns how many it
// retired.
func sweepCISessionRecords(db *statedb.DB, now time.Time, self string, alive func(string) bool,
	served func(string) bool) int {
	rows, err := db.ListCISessions(statedb.CISessionFilter{})
	if err != nil {
		return 0
	}
	retired := 0
	for _, row := range rows {
		unheld := row.Holder == "" || (row.Holder == self && !served(row.SessionID)) ||
			(row.Holder != self && !alive(row.Holder))
		var reason string
		switch {
		case !row.Open():
		case !now.Before(row.ExpiresAt.Add(sessionRecordGrace)):
			reason = fmt.Sprintf("lapsed at %s", row.ExpiresAt.UTC().Format(time.RFC3339))
		case unheld && !now.Before(row.ExpiresAt):
			reason = fmt.Sprintf("lapsed at %s while no hub process held it", row.ExpiresAt.UTC().Format(time.RFC3339))
		default:
			continue
		}
		deleted, err := db.DeleteCISession(row.SessionID, row.Holder)
		if err != nil || !deleted {
			continue
		}
		if row.Open() {
			appendCIRecordEnd(db, row, reason)
		}
		retired++
	}
	return retired
}

// ciSessionServed reports whether this process's relay serves session id.
func (s *Server) ciSessionServed(id string) bool {
	svc := s.ci.svc.Load()
	return svc != nil && svc.reg != nil && svc.reg.Known(id)
}

// reconcileHeld stops serving every recorded session whose record this
// process no longer holds open — closed by another member (its rule withdrawn,
// revoked, federation switched off) or taken over by one — whether or not its
// counters moved since the last checkpoint. Called on the checkpoint tick.
func (svc *ciService) reconcileHeld() {
	if svc == nil || svc.auditDB == nil || svc.reg == nil {
		return
	}
	self := leaseHolderID()
	if self == "" {
		return
	}
	// The ids first, then the records: a session minted in between has its
	// record already, and is not mistaken for one whose record went away.
	ids := svc.reg.DurableIDs()
	if len(ids) == 0 {
		return
	}
	open, err := svc.auditDB.OpenCISessionIDsHeldBy(self)
	if err != nil {
		return
	}
	held := make(map[string]bool, len(open))
	for _, id := range open {
		held[id] = true
	}
	svc.reg.DropUnheld(ids, held)
}
