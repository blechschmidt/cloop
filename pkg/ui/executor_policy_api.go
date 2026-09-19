package ui

// executor_policy_api.go is the admin's surface for the two policies a hub
// holds *about* an executor rather than an executor holding about itself:
//
//	how much any one workload on it may be given  — /api/executors/{id}/limits
//	who may run work on it at all                 — /api/executors/{id}/audience
//
// Its sibling executor_sandbox_api.go answers the third — whether payloads run
// on the device's host or in a container on it — and the three together are
// what "configure an executor" means in the dashboard. They are separate routes
// because they have separate lifecycles: clearing a containment override must
// not drop a memory cap, and neither should disturb an access list.
//
// # Why limits are a ceiling and not a default
//
// cloop already had per-executor resource *defaults* in config.yaml, and the
// container driver states the rule it resolves them under: "spec limits
// override the executor's configured defaults". A project's spec is read from
// .cloop/sandbox.yaml, a file in the repository, so under that rule the
// operator's number was advice and the project had the last word.
//
// What this route writes is not a default. See pkg/executor/ceiling.go: a
// ceiling can only lower, it composes with the fleet's and the project's by
// getting tighter, and each reduction is attributed to whichever ceiling caused
// it so the developer reading "your task was given 2 GB" can find out who to
// ask for more.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// executorLimitsRequest is the PUT body for an executor's resource ceiling.
//
// The sizes are strings for the reason config.ExecutorLimitsConfig's are: an
// admin types "8g", not 8192, and a field that demands megabytes invites the
// off-by-1024 that makes a sandbox OOM on startup. CPU is a float because a
// core allowance of 1.5 is a thing an admin means.
//
// Like the sandbox body, this replaces the whole record rather than patching
// it: the form shows four fields and saving it should store what the admin was
// looking at, including the ones they cleared.
type executorLimitsRequest struct {
	MaxCPU    float64 `json:"max_cpu"`
	MaxMemory string  `json:"max_memory"`
	MaxDisk   string  `json:"max_disk"`
	MaxPIDs   int     `json:"max_pids"`
	// Clear removes the ceiling entirely, leaving the executor bounded only by
	// the fleet's. Distinct from saving an all-zero record, which is an admin
	// asserting "this device needs no cap of its own" — the panel shows that as
	// configured, and the audit trail records someone having decided it.
	Clear bool `json:"clear"`
}

// ceiling parses the request into the executor package's ceiling type.
func (req executorLimitsRequest) ceiling() (executor.ResourceCeiling, error) {
	// Routed through config.ExecutorLimitsConfig rather than parsed here, so
	// that a ceiling typed into the dashboard and one written into config.yaml
	// are validated by the same code — including the memory floor, below which
	// a container cannot start at all. Two parsers would eventually disagree
	// about "8gb" or "8 G", and the one an admin hit would be a coin toss.
	return config.ExecutorLimitsConfig{
		MaxCPU:    req.MaxCPU,
		MaxMemory: req.MaxMemory,
		MaxDisk:   req.MaxDisk,
		MaxPIDs:   req.MaxPIDs,
	}.Ceiling()
}

// executorLimitsView is the GET body and the answer to every write.
type executorLimitsView struct {
	ExecutorID string                   `json:"executor_id"`
	Configured bool                     `json:"configured"`
	Ceiling    executor.ResourceCeiling `json:"ceiling"`
	// Fleet is the hub-wide ceiling, shown alongside so an admin can see that
	// raising this executor's cap above it achieves nothing — the tighter of
	// the two wins, and a form that hid the other number would let someone set
	// 16 GB, read it back as 16 GB, and get 8.
	Fleet     executor.ResourceCeiling `json:"fleet"`
	Effective executor.ResourceCeiling `json:"effective"`
	SetAt     string                   `json:"set_at,omitempty"`
	SetBy     string                   `json:"set_by,omitempty"`
	// Enforced reports whether this executor will actually hold a workload to
	// the ceiling. Remote agents advertise SupportsResourceLimits false: they
	// report a device's capacity for placement and then run the payload without
	// confining it. Saying so in the panel is the difference between a cap an
	// admin has and one they believe they have.
	Enforced bool `json:"enforced"`
}

// handleExecutorLimits serves GET and PUT /api/executors/{id}/limits.
func (s *Server) handleExecutorLimits(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "executor id is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		db, err := s.controlPlaneDB()
		if err != nil {
			jsonErr(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer db.Close()
		s.renderExecutorLimits(w, db, id)
	case http.MethodPut, http.MethodPost:
		s.serveExecutorLimitsPut(w, r, id)
	default:
		w.Header().Set("Allow", "GET, PUT")
		jsonErr(w, "method not allowed: use GET to read or PUT to set an executor's resource ceiling",
			http.StatusMethodNotAllowed)
	}
}

// renderExecutorLimits writes the view over an already-open database, for the
// reason renderExecutorSandbox does: statedb.Open creates and migrates, and two
// of those per write is a needless pair of WAL readers on the hottest file the
// hub has.
func (s *Server) renderExecutorLimits(w http.ResponseWriter, db *statedb.DB, id string) {
	c, configured, err := db.ExecutorResourceCeiling(id)
	if err != nil {
		jsonErr(w, "read resource ceiling: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fleet := executor.FleetResourceCeiling()
	view := executorLimitsView{
		ExecutorID: id,
		Configured: configured,
		Ceiling:    c,
		Fleet:      fleet,
		Effective:  fleet.Tighten(c),
		Enforced:   executorEnforcesLimits(id),
	}
	// Provenance comes from the list rather than a second point read: the table
	// is one row per executor and an admin panel reads it whole anyway.
	if rows, err := db.ListExecutorResourceLimits(); err == nil {
		for _, l := range rows {
			if l.ExecutorID == id {
				if !l.SetAt.IsZero() {
					view.SetAt = l.SetAt.UTC().Format("2006-01-02T15:04:05Z07:00")
				}
				view.SetBy = l.SetBy
				break
			}
		}
	}
	jsonOK(w, view)
}

// executorEnforcesLimits reports whether the registered executor will hold a
// workload to a ceiling. An unregistered id answers false: a cap on a device
// the hub cannot see is not one it can promise.
func executorEnforcesLimits(id string) bool {
	registerBuiltinExecutors()
	ex, err := executor.Get(id)
	if err != nil || ex == nil {
		return false
	}
	return ex.Capabilities().SupportsResourceLimits
}

func (s *Server) serveExecutorLimitsPut(w http.ResponseWriter, r *http.Request, id string) {
	var req executorLimitsRequest
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !isEmptyBody(err) {
		jsonErr(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()

	// Read the outgoing ceiling before overwriting it. A raised cap is the
	// change worth reviewing and it is invisible in the new value alone.
	before, _, err := db.ExecutorResourceCeiling(id)
	if err != nil {
		jsonErr(w, "read current resource ceiling: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if req.Clear {
		if err := db.ClearExecutorResourceLimit(id); err != nil {
			jsonErr(w, "clear resource ceiling: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditExecutorAction(r, "limits", id, map[string]any{
			"cleared": true,
			"from":    describeCeiling(before),
			"to":      describeCeiling(executor.ResourceCeiling{}),
		})
		s.broadcastExecutorUpdate("limits", id)
		s.renderExecutorLimits(w, db, id)
		return
	}

	want, err := req.ceiling()
	if err != nil {
		// 400: the admin typed something this hub cannot parse. Reported before
		// anything is written, so a malformed size does not half-apply.
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := db.SetExecutorResourceLimit(id, want, s.auditActor(r)); err != nil {
		if errors.Is(err, statedb.ErrDBLocked) {
			jsonErr(w, "the control plane is busy; retry: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		jsonErr(w, "save resource ceiling: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.auditExecutorAction(r, "limits", id, map[string]any{
		"from": describeCeiling(before),
		"to":   describeCeiling(want),
	})
	s.broadcastExecutorUpdate("limits", id)
	s.renderExecutorLimits(w, db, id)
}

// describeCeiling renders a ceiling for the audit trail in the units an admin
// typed, so a reviewer comparing `from` and `to` is comparing sentences rather
// than four pairs of integers.
func describeCeiling(c executor.ResourceCeiling) string {
	if c.IsZero() {
		return "uncapped"
	}
	var parts []string
	if c.CPUMillis > 0 {
		parts = append(parts, fmt.Sprintf("cpu=%gm", float64(c.CPUMillis)))
	}
	if c.MemoryMB > 0 {
		parts = append(parts, fmt.Sprintf("memory=%dMB", c.MemoryMB))
	}
	if c.DiskMB > 0 {
		parts = append(parts, fmt.Sprintf("disk=%dMB", c.DiskMB))
	}
	if c.PIDs > 0 {
		parts = append(parts, fmt.Sprintf("pids=%d", c.PIDs))
	}
	return strings.Join(parts, " ")
}

// ─── audience ────────────────────────────────────────────────────────────────

// executorAudienceRequest is the POST/DELETE body: one principal.
type executorAudienceRequest struct {
	// Kind is "user" or "group". A "user" value containing "@" is matched
	// against the email claim and anything else against the subject — see
	// authz.AudienceMemberFor, which owns that rule so this gate and the role
	// model cannot disagree about what an admin typed.
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// executorAudienceView is the GET body and the answer to every write.
type executorAudienceView struct {
	ExecutorID string                          `json:"executor_id"`
	Members    []statedb.ExecutorAudienceEntry `json:"members"`
	// Restricted is len(Members) > 0, sent explicitly because it is the field
	// the panel keys its wording off and "unrestricted" is not an obvious
	// reading of an empty array.
	Restricted bool `json:"restricted"`
	// CallerAdmitted reports whether the requesting identity may itself use
	// this executor. An admin can restrict a device they cannot use — managing
	// and using are separate rights — and the panel says so rather than letting
	// them find out at the next run.
	CallerAdmitted bool `json:"caller_admitted"`
}

// handleExecutorAudience serves GET, POST and DELETE
// /api/executors/{id}/audience.
//
// POST admits a principal, DELETE withdraws one. Both are idempotent: admitting
// someone already admitted refreshes their provenance, and withdrawing someone
// absent is a no-op, so a double-clicked button cannot produce a duplicate or
// an error.
func (s *Server) handleExecutorAudience(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "executor id is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		db, err := s.controlPlaneDB()
		if err != nil {
			jsonErr(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer db.Close()
		s.renderExecutorAudience(w, r, db, id)
	case http.MethodPost, http.MethodDelete:
		s.serveExecutorAudienceWrite(w, r, id)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		jsonErr(w, "method not allowed: use GET to read, POST to admit or DELETE to withdraw",
			http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderExecutorAudience(w http.ResponseWriter, r *http.Request, db *statedb.DB, id string) {
	members, err := db.ExecutorAudience(id)
	if err != nil {
		jsonErr(w, "read access list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if members == nil {
		members = []statedb.ExecutorAudienceEntry{}
	}
	jsonOK(w, executorAudienceView{
		ExecutorID:     id,
		Members:        members,
		Restricted:     len(members) > 0,
		CallerAdmitted: authz.Admits(audienceMembers(members), s.callerSubject(r)),
	})
}

func (s *Server) serveExecutorAudienceWrite(w http.ResponseWriter, r *http.Request, id string) {
	var req executorAudienceRequest
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !isEmptyBody(err) {
		jsonErr(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	value := strings.TrimSpace(req.Value)
	if value == "" {
		jsonErr(w, "a principal value is required: the group name, email or subject to admit",
			http.StatusBadRequest)
		return
	}
	// The two validations below apply to an admit and deliberately not to a
	// withdrawal. A row naming a kind this binary does not recognise is
	// reachable — a newer binary sharing this control plane could have written
	// one — and it renders on the list with a Remove button beside it. Refusing
	// that removal would leave an admin looking at an entry they are told is
	// invalid and cannot delete. Removal only ever widens access, so there is
	// nothing to protect by being strict about it.
	if r.Method == http.MethodPost {
		// Rejected here rather than only in statedb, so the admin is told which
		// kinds exist instead of receiving a storage error.
		if kind != "user" && kind != "group" && kind != "role" {
			jsonErr(w, fmt.Sprintf("principal kind %q is not one of user, group, role", req.Kind),
				http.StatusBadRequest)
			return
		}
		// A value this binary cannot turn into a claim predicate would be
		// stored and then never match, which is a silent lockout: the admin
		// sees their group on the list and the people in it are refused.
		if authz.AudienceMemberFor(kind, value).Value == "" {
			jsonErr(w, fmt.Sprintf("%q is not a usable %s principal", req.Value, kind),
				http.StatusBadRequest)
			return
		}
	}

	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()

	action := "admit"
	if r.Method == http.MethodDelete {
		action = "withdraw"
		if err := db.RemoveExecutorAudience(id, kind, value); err != nil {
			jsonErr(w, "withdraw principal: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		// The lockout guard. Adding the first principal is the act that turns
		// the gate on, and an admin who restricts an executor to a group they
		// are not in has just removed their own access to it — silently, and
		// on a hub where the people who could undo it may be exactly the ones
		// now locked out.
		//
		// Checked only for the add, and only for the *first* one: a hub whose
		// executor is already restricted has already been through this, and
		// refusing every subsequent edit would make a restricted executor
		// un-editable by anyone outside its own access list.
		if locked, err := s.audienceAddWouldLockOutCaller(r, db, id, kind, value); err != nil {
			jsonErr(w, "check access list: "+err.Error(), http.StatusInternalServerError)
			return
		} else if locked {
			writeJSONStatus(w, http.StatusConflict, map[string]any{
				"error": fmt.Sprintf(
					"restricting executor %q to %s %q would remove your own access to it — "+
						"admit yourself first, then add the others",
					id, kind, value),
				"code":        "executor_audience_self_lockout",
				"executor_id": id,
				"remediation": "add your own account or a group you belong to before restricting this executor; " +
					"on a hub without single sign-on there is no identity to admit, so access lists cannot be used",
			})
			return
		}
		if err := db.AddExecutorAudience(id, kind, value, s.auditActor(r)); err != nil {
			if errors.Is(err, statedb.ErrDBLocked) {
				jsonErr(w, "the control plane is busy; retry: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
			jsonErr(w, "admit principal: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	after, err := db.ExecutorAudience(id)
	if err != nil {
		jsonErr(w, "read access list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditExecutorAction(r, "audience", id, map[string]any{
		"action":          action,
		"principal_kind":  kind,
		"principal_value": value,
		// Whether the executor is access-controlled *after* the change.
		// Withdrawing the last entry sets this false, which widens the executor
		// to the whole fleet — the one edit here that grants rather than
		// revokes, and the one a reviewer most needs to see.
		"restricted": len(after) > 0,
		"members":    len(after),
	})
	s.broadcastExecutorUpdate("audience", id)
	s.renderExecutorAudience(w, r, db, id)
}

// audienceAddWouldLockOutCaller reports whether admitting (kind, value) to an
// executor that is currently unrestricted would leave the caller unable to use
// it.
//
// Returns false once the executor is already restricted: that decision has been
// made, and re-checking it on every subsequent edit would mean an admin outside
// the list could never add anyone to it.
func (s *Server) audienceAddWouldLockOutCaller(
	r *http.Request, db *statedb.DB, id, kind, value string,
) (bool, error) {
	existing, err := db.ExecutorAudience(id)
	if err != nil {
		return false, err
	}
	if len(existing) > 0 {
		return false, nil
	}
	return !authz.Admits([]authz.AudienceMember{authz.AudienceMemberFor(kind, value)},
		s.callerSubject(r)), nil
}
