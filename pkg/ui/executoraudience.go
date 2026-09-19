package ui

// executoraudience.go decides whether the identity behind a request may run
// work on a given executor.
//
// # Why the check lives here and not in pkg/executor
//
// executor.Resolve is the chokepoint every dispatch funnels through, and it is
// the obvious home for this — except that it is handed a project path and
// nothing else. It has no identity, cannot acquire one without importing the
// hub's session layer, and is called from contexts that legitimately have no
// user at all: the CLI, the failover supervisor, a scheduled run continuing
// after the person who started it went home.
//
// Pushing an identity down into it would mean either inventing a "system"
// subject that passes every gate — which is a bypass with a friendly name — or
// failing every internal dispatch closed, which breaks autonomous operation.
// So the gate sits at the HTTP boundary instead, on the two requests where a
// human actually chooses an executor:
//
//	POST /api/projects/{idx}/executor   binding a project to one
//	POST /api/run                       starting work that will land on one
//
// Both have a session. Everything downstream of them is a continuation of a
// decision already authorized here, which is the same reasoning that puts quota
// admission (admitSpend) at exactly these points and not deeper.
//
// # Fail closed, unlike the ceiling next door
//
// lookupProjectResourceCeiling fails *open*: a control-plane blip degrades a
// project to the fleet cap rather than refusing the run, because a ceiling
// bounds a number that is already bounded and an outage is the worse outcome.
//
// This lookup does the opposite. An audience is an access control, and "the
// database did not answer so we let everyone through" is how a storage fault
// becomes a privilege escalation. A read error here refuses the request with a
// 503 the operator can act on — deliberately noisier than the silent
// degradation one file over, because the two failures have opposite blast
// radii.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// executorAudience reads the allowlist for one executor from the control plane.
//
// The returned slice being empty means the executor is unrestricted — every
// executor is, until an admin adds the first entry — which is what makes this
// whole file a no-op for existing deployments.
//
// A missing or unmigrated control-plane database is "unrestricted" rather than
// an error: it is the state of a hub that has never had an audience, not a
// failed read of one that has. A database that exists but cannot be read *is*
// an error, and the caller must refuse rather than admit.
func executorAudience(executorID string) ([]statedb.ExecutorAudienceEntry, error) {
	if executorID == "" {
		return nil, nil
	}
	dir := controlPlaneDir()
	if dir == "" {
		return nil, nil
	}
	dbPath := state.DBPath(dir)
	// Stat first: statedb.Open creates and migrates, and an authorization
	// check is not the place to bring a control-plane database into existence.
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("read executor audience: %w", err)
	}
	defer db.Close()
	return db.ExecutorAudience(executorID)
}

// audienceMembers converts stored rows to the claim predicates authz matches.
func audienceMembers(entries []statedb.ExecutorAudienceEntry) []authz.AudienceMember {
	if len(entries) == 0 {
		return nil
	}
	out := make([]authz.AudienceMember, 0, len(entries))
	for _, e := range entries {
		if m := e.Member(); m.Value != "" {
			out = append(out, m)
		}
	}
	return out
}

// callerMayUseExecutor reports whether the identity behind r may run work on
// executorID.
//
// The error return is a *lookup* failure, distinct from a denial: one is a 503
// and the other a 403, and collapsing them would either hide an outage or
// accuse a user of lacking access they have.
func (s *Server) callerMayUseExecutor(r *http.Request, executorID string) (bool, error) {
	entries, err := executorAudience(executorID)
	if err != nil {
		return false, err
	}
	members := audienceMembers(entries)
	if len(members) == 0 {
		// Unrestricted, which is every executor until an admin adds the first
		// entry. Answered without consulting the subject at all, so a hub with
		// no identity provider keeps working exactly as it did.
		return true, nil
	}
	return authz.Admits(members, s.callerSubject(r)), nil
}

// admitExecutorAudience is the gate. It writes the refusal and returns false
// when the caller may not use executorID.
//
// A refusal is 403 with a typed code so the dashboard can tell this apart from
// the several other reasons a run does not start, and the message names the
// executor rather than the policy: "you are not admitted to executor X" is
// actionable — the reader knows which admin to ask — where "access denied"
// sends them to a support channel to find out what was denied.
func (s *Server) admitExecutorAudience(w http.ResponseWriter, r *http.Request, executorID string) bool {
	allowed, err := s.callerMayUseExecutor(r, executorID)
	if err != nil {
		// 503, not 403. The caller may well be admitted; we could not find
		// out. Telling them they lack access would be a guess presented as a
		// decision, and would send them to ask an admin for something they
		// already have.
		//
		// Written here rather than through writeExecutorBlocked because that
		// helper hardcodes 409: the codes it carries all mean "this request
		// conflicts with the fleet's configuration", and this one means the
		// hub could not read its own.
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"error":       fmt.Sprintf("cannot determine who may use executor %q right now", executorID),
			"code":        "executor_audience_unavailable",
			"remediation": err.Error(),
			"executor_id": executorID,
		})
		return false
	}
	if allowed {
		return true
	}
	writeJSONStatus(w, http.StatusForbidden, map[string]any{
		"error": fmt.Sprintf(
			"executor %q is restricted and your account is not on its access list — "+
				"ask an administrator to admit you, or bind this project to another executor",
			executorID),
		"code":        "executor_audience_denied",
		"executor_id": executorID,
	})
	return false
}

// writeJSONStatus writes a JSON body under an explicit status code, keeping the
// `error`/`code` key shape every other refusal in this package uses so a client
// that does not recognise a new code still renders the sentence.
func writeJSONStatus(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// applyAudience annotates each card with whether it is access-controlled and
// whether the caller is on the list.
//
// One query for the whole fleet, which is why statedb has AllExecutorAudiences
// rather than only the per-executor read: a lookup per card would be N queries
// on the dashboard's most-refreshed panel.
//
// A nil database or a failed query leaves every card marked admitted, which is
// the opposite of this file's fail-closed stance elsewhere and is deliberate:
// this is a *display* hint, not the gate. Marking everything forbidden on a
// transient read error would empty the panel and send an admin looking for an
// access problem that does not exist, while the real gate — which does fail
// closed — still refuses anything they try.
func (s *Server) applyAudience(r *http.Request, views []executorView, db *statedb.DB) []executorView {
	for i := range views {
		views[i].Admitted = true
	}
	if db == nil || len(views) == 0 {
		return views
	}
	all, err := db.AllExecutorAudiences()
	if err != nil || len(all) == 0 {
		return views
	}
	subject := s.callerSubject(r)
	for i := range views {
		entries, ok := all[views[i].ID]
		if !ok || len(entries) == 0 {
			continue
		}
		views[i].Restricted = true
		views[i].Admitted = authz.Admits(audienceMembers(entries), subject)
	}
	return views
}

// admitExecutorAudienceForProject is admitExecutorAudience for a project that
// is about to run, resolving which executor that means first.
//
// A project whose executor cannot be resolved is *not* refused here. Resolution
// fails for reasons this gate has no opinion about — an unregistered binding, a
// host-execution policy — and each of them is reported with its own message
// further down the dispatch path. Answering "access denied" first would replace
// a precise diagnosis with a misleading one.
func (s *Server) admitExecutorAudienceForProject(w http.ResponseWriter, r *http.Request, workDir string) bool {
	registerBuiltinExecutors()
	// ResolveBinding rather than Resolve: this asks only *which* executor the
	// project points at. Resolve additionally applies the host-execution
	// policy, and a project refused by that policy would be reported here as
	// an access-list problem, which it is not.
	ex, err := executor.ResolveBinding(workDir)
	if err != nil || ex == nil {
		return true
	}
	return s.admitExecutorAudience(w, r, ex.ID())
}
