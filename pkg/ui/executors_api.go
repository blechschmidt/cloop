// Executors panel API (Task 20160).
//
// This file makes the execution model — which until now was config an operator
// could only inspect by reading YAML and grepping the state database — into
// something visible and manageable from the dashboard: what backends exist,
// which of them are alive, what they can do, how loaded they are, which
// project runs where, and (the point of the whole exercise) whether this
// control plane is still allowed to fork harnesses next to itself.
//
// Three sources are joined into one view:
//
//   - the live registry (pkg/executor), which knows capabilities, health, and
//     current handles but forgets everything on restart;
//   - the executors table in statedb, which knows enrollment, heartbeats, and
//     the rich agent-advertised capabilities, and survives restarts; and
//   - the project→executor bindings, also in statedb.
//
// The registry is the source of truth for "can this run work right now"; the
// table is the source of truth for "does this exist at all". An enrolled edge
// device that is currently offline appears in the table and (thanks to
// Hub.Restore) in the registry as an offline executor, which is exactly the
// distinction the status dot renders.

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/reconcile"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// executorHealthTimeout bounds a single driver's HealthCheck while rendering
// the panel. A container runtime with a wedged socket is a realistic failure,
// and it must degrade one card's status dot rather than hang the request that
// draws every card.
const executorHealthTimeout = 2 * time.Second

// enrollTTL bounds are the UI's mirror of remote.MaxEnrollTTL. The lower bound
// exists because a token that expires before the operator can paste it into a
// terminal is indistinguishable, from the device, from a token that never
// worked.
const (
	enrollTTLMinutesLower = 1
	enrollTTLMinutesUpper = int(remote.MaxEnrollTTL / time.Minute)
)

// executorView is one card in the Executors panel.
type executorView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	Endpoint string `json:"endpoint,omitempty"`

	// Registered reports presence in the live registry. False means the
	// backend is recorded but this process cannot dispatch to it — a
	// container executor whose config section was removed, say.
	Registered bool `json:"registered"`
	// Enrolled reports presence in the executors table, which is what makes
	// an executor revocable through the API. Built-in drivers configured in
	// YAML are not.
	Enrolled bool `json:"enrolled"`
	// Default marks the registry's fallback for unbound projects.
	Default bool `json:"default"`

	Isolation    string                 `json:"isolation"`
	Capabilities *executor.Capabilities `json:"capabilities,omitempty"`
	// AgentCapabilities is the device's full advertisement (CPU count,
	// memory, container runtimes, installed harnesses) as stored at
	// enrollment. Opaque here; the panel renders it as extra chips.
	AgentCapabilities json.RawMessage   `json:"agent_capabilities,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`

	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
	EnrolledBy    string     `json:"enrolled_by,omitempty"`

	// Running counts non-terminal handles. RunningKnown is false for drivers
	// that cannot enumerate; the panel then renders "—" rather than "0",
	// because claiming an executor is idle when it might be saturated is the
	// worse of the two wrong answers.
	Running      int  `json:"running"`
	RunningKnown bool `json:"running_known"`

	// Projects lists the project paths bound to this executor.
	Projects []string `json:"projects,omitempty"`

	// Health is the HealthCheck error, empty when healthy or unregistered.
	Health string `json:"health,omitempty"`

	// Blocked reports that strict no-host-execution mode forbids dispatching
	// here, with BlockedReason carrying the sentence to show the operator.
	Blocked       bool   `json:"blocked"`
	BlockedReason string `json:"blocked_reason,omitempty"`

	// ---- scheduling state (Task 20162) -------------------------------------
	//
	// Status above is about the *device* ("is it connected"); the fields below
	// are about the *scheduler* ("would we place work here"). They differ in
	// exactly the case that matters: a cordoned node is online, healthy, and
	// deliberately not taking work, and a panel that showed only a green dot
	// would make an operator's own decision look like a bug.

	// SchedState is the NodeState: ready|degraded|unreachable|cordoned|draining.
	SchedState string `json:"sched_state"`
	// SchedReason explains the state — the probe error for unreachable, the
	// operator's note for cordoned.
	SchedReason string `json:"sched_reason,omitempty"`
	// Schedulable is whether placement would consider this node right now.
	// Degraded is schedulable; cordoned and draining are not.
	Schedulable bool `json:"schedulable"`
	// AdminHeld marks a state an operator set, which no probe result can lift.
	// It is what decides whether the card offers Cordon or Uncordon.
	AdminHeld bool `json:"admin_held"`
	// ConsecutiveFailures counts probe failures since the last success.
	ConsecutiveFailures int `json:"consecutive_failures,omitempty"`
	// LastSeen is the most recent successful probe, nil when never observed.
	LastSeen *time.Time `json:"last_seen,omitempty"`
	// InFlight counts sessions the scheduler believes are running here, valid
	// only when InFlightKnown. As with RunningKnown, an unreadable count is
	// rendered "—" rather than "0".
	InFlight      int  `json:"in_flight"`
	InFlightKnown bool `json:"in_flight_known"`

	// ---- startup reconciliation (Task 20170) -------------------------------
	//
	// Health above is a live probe of a *registered* executor. These describe
	// what happened when this hub tried to bring the executor up from config
	// at all, which is the only thing there is to say about one that failed:
	// it has no registry entry to probe.

	// ReconcileStatus is ok|degraded|failed|skipped, empty when this executor
	// was not configured in this hub's config (an enrolled remote agent).
	ReconcileStatus string `json:"reconcile_status,omitempty"`
	// ReconcileMessage summarises the outcome.
	ReconcileMessage string `json:"reconcile_message,omitempty"`
	// ReconcileRemediation is the concrete fix for a non-OK status.
	ReconcileRemediation string `json:"reconcile_remediation,omitempty"`
	// PreflightFindings is the driver's startup checklist.
	PreflightFindings []reconcile.Finding `json:"preflight_findings,omitempty"`
}

// executorPolicyView is the banner state for the Executors tab.
type executorPolicyView struct {
	// AllowHostProcess is the effective policy.
	AllowHostProcess bool `json:"allow_host_process"`
	// Explicit distinguishes "an operator decided this" from "nobody has
	// set it and the back-compat default applies".
	Explicit bool `json:"explicit"`
	// StrictMode is the inverse of AllowHostProcess, named for the mode the
	// UI talks about rather than the flag it is derived from.
	StrictMode bool `json:"strict_mode"`
	// Alternatives are the isolated executors a blocked project can move to.
	Alternatives []string `json:"alternatives,omitempty"`
	// Warnings are advisory config problems (see config.ExecutorWarnings).
	Warnings []string `json:"warnings,omitempty"`
	// Banner is the one-sentence summary the tab renders.
	Banner string `json:"banner"`
	// Severity drives the banner colour: "ok", "warn", or "info".
	Severity string `json:"severity"`
}

// executorProjectView describes the requesting project's execution target.
type executorProjectView struct {
	Path string `json:"path"`
	// ExecutorID is the explicit binding, empty when the project inherits
	// the registry default.
	ExecutorID string `json:"executor_id,omitempty"`
	Bound      bool   `json:"bound"`
	// EffectiveID is what would actually run the next workload, binding or
	// default. Empty when nothing can.
	EffectiveID string `json:"effective_id,omitempty"`
	// Blocked reports that the effective executor is forbidden by policy.
	Blocked       bool   `json:"blocked"`
	BlockedReason string `json:"blocked_reason,omitempty"`
}

// executorsResponse is the GET /api/executors payload.
type executorsResponse struct {
	Executors []executorView       `json:"executors"`
	Policy    executorPolicyView   `json:"policy"`
	Project   *executorProjectView `json:"project,omitempty"`
	DefaultID string               `json:"default_id,omitempty"`

	// Reconciliation is the startup diagnostic for every executor this hub's
	// config asked for (Task 20170). It is the only place a *failed* driver
	// appears: one that could not be built has no registry entry and no
	// executors-table row, so without this the panel's answer to "why is my
	// container executor not here" was an empty list.
	Reconciliation *reconciliationView `json:"reconciliation,omitempty"`

	// Ready mirrors what /readyz reports about the execution path, so the
	// panel can show the same verdict an orchestrator acts on rather than
	// leaving an operator to infer it from the card list.
	Ready bool `json:"ready"`
	// NotReadyReason and Remediation are set only when Ready is false.
	NotReadyReason string `json:"not_ready_reason,omitempty"`
	Remediation    string `json:"remediation,omitempty"`
}

// reconciliationView is the last startup reconciliation, rendered for the
// Executors tab.
type reconciliationView struct {
	Diagnostics  []reconcile.Diagnostic `json:"diagnostics"`
	ReconciledAt time.Time              `json:"reconciled_at"`
	// Problems counts diagnostics that are failed or degraded, so the tab can
	// badge the section without walking the list.
	Problems int `json:"problems"`
}

// controlPlaneDB opens the control plane's own state database.
//
// Every executor concern (enrollment, bindings, heartbeats) lives there rather
// than in a managed project's database, because an executor is not owned by a
// project: one device runs work for many, and a project pinned to a remote
// executor may have no readable local .cloop directory at all.
func (s *Server) controlPlaneDB() (*statedb.DB, error) {
	db, err := statedb.Open(state.DBPath(s.WorkDir))
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}
	return db, nil
}

// executorPolicy renders the current host-execution policy for the banner.
//
// The effective policy is read from the process-wide switch rather than
// re-read from disk: that switch is what Resolve actually consults, and a
// banner that disagreed with enforcement would be worse than no banner.
// Config is consulted only for the things the switch does not carry — whether
// the value was explicit, and the advisory warnings.
func (s *Server) executorPolicy() executorPolicyView {
	allowed := executor.HostExecutionAllowed()
	view := executorPolicyView{
		AllowHostProcess: allowed,
		StrictMode:       !allowed,
		Alternatives:     executor.IsolatedIDs(),
	}
	if cfg, err := config.Load(s.WorkDir); err == nil && cfg != nil {
		view.Explicit = cfg.Executors.HostProcessExplicit()
		view.Warnings = config.ExecutorWarnings(cfg.Executors)
	}

	switch {
	case !allowed && len(view.Alternatives) > 0:
		view.Severity = "ok"
		view.Banner = "Strict mode: host execution is disabled. Workloads run only on " +
			strings.Join(view.Alternatives, ", ") + "."
	case !allowed:
		view.Severity = "warn"
		view.Banner = "Strict mode: host execution is disabled and no isolated executor is " +
			"available. Every run is refused until a container executor is enabled or a " +
			"remote agent enrolls."
	case view.Explicit:
		view.Severity = "warn"
		view.Banner = "Host execution is enabled (executors.allow_host_process: true). " +
			"Workloads run as child processes of this server with its user, filesystem, and network."
	default:
		view.Severity = "info"
		view.Banner = "Host execution is enabled by default. Hardened deployments set " +
			"executors.allow_host_process: false so the dashboard can never spawn a harness on this host."
	}
	return view
}

// blockedFor reports whether policy forbids dispatching to ex, and why.
func blockedFor(ex executor.Executor) (bool, string) {
	if ex == nil || executor.HostExecutionAllowed() {
		return false, ""
	}
	if ex.Capabilities().Isolation != executor.IsolationNone {
		return false, ""
	}
	denied := &executor.HostExecutionDeniedError{
		ExecutorID:   ex.ID(),
		Alternatives: executor.IsolatedIDs(),
	}
	return true, denied.Remediation()
}

// collectExecutorViews joins the registry, the executors table, and the
// bindings table into the panel's card list.
func (s *Server) collectExecutorViews(ctx context.Context, db *statedb.DB) []executorView {
	registered := map[string]executor.Executor{}
	for _, ex := range executor.List() {
		registered[ex.ID()] = ex
	}
	defaultID := executor.DefaultRegistry.DefaultID()

	rows := map[string]statedb.ExecutorRow{}
	if db != nil {
		if list, err := db.ListExecutors(); err == nil {
			for _, row := range list {
				rows[row.ID] = row
			}
		} else {
			fmt.Fprintf(os.Stderr, "ui: list executors: %v\n", err)
		}
	}

	bound := map[string][]string{}
	if db != nil {
		if bindings, err := db.ListProjectExecutorBindings(); err == nil {
			for _, b := range bindings {
				bound[b.ExecutorID] = append(bound[b.ExecutorID], b.ProjectPath)
			}
		}
	}

	ids := make([]string, 0, len(registered)+len(rows))
	seen := map[string]bool{}
	for id := range registered {
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	for id := range rows {
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	sort.Strings(ids)

	// One Scheduler over the database this request already opened, rather than
	// one handle per card: statedb.DB serialises internally, and N file opens
	// to answer one panel refresh is a cost with nothing to show for it.
	sched := schedulerFor(db)

	views := make([]executorView, len(ids))
	// Health checks fan out: a wedged container runtime must cost one
	// timeout, not one timeout per executor serialised behind it.
	var wg sync.WaitGroup
	for i, id := range ids {
		i, id := i, id
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverGoroutine("executor view " + id)
			views[i] = s.buildExecutorView(ctx, id, registered[id], rows[id], bound[id], defaultID, sched)
		}()
	}
	wg.Wait()
	return views
}

// schedulerFor adapts an already-open control-plane database to the scheduling
// store, or returns nil when there is no database to read.
//
// Nil is a legitimate value here and every caller treats it as "the in-flight
// count is unknown". The panel already renders without a database (the registry
// alone describes the built-in drivers), and losing a load number must not lose
// the card that carries it.
func schedulerFor(db *statedb.DB) *executorstore.Scheduler {
	if db == nil {
		return nil
	}
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: executor scheduler unavailable: %v\n", err)
		return nil
	}
	return sched
}

// countInFlight reports how many sessions are running on an executor, and
// whether the count could be determined at all.
//
// The two return values are not redundant: "no sessions running" and "we cannot
// tell" are different facts, and a UI that collapses them tells an operator a
// saturated node is idle.
func countInFlight(sched *executorstore.Scheduler, id string) (int, bool) {
	if sched == nil {
		return 0, false
	}
	n, err := sched.CountRunning(id)
	if err != nil {
		return 0, false
	}
	return n, true
}

// schedulingHealth returns the supervisor's view of one executor.
//
// A nil supervisor yields the normalized zero value, which is "ready". That is
// the same answer Supervisor.Health gives for a node it has never probed, and
// it is the right one: a control plane whose supervision failed to start must
// still be able to run work, so its panel must not paint the whole fleet as
// broken.
func schedulingHealth(id string) executor.Health {
	if sv := executorSupervisor(); sv != nil {
		return sv.Health(id)
	}
	return executor.Health{ExecutorID: id}.Normalize()
}

// applyScheduling copies the scheduling state onto a card.
func applyScheduling(view *executorView, h executor.Health, inFlight int, inFlightKnown bool) {
	view.SchedState = string(h.State)
	view.SchedReason = h.Reason
	view.Schedulable = h.State.Schedulable()
	view.AdminHeld = h.State.AdminHeld()
	view.ConsecutiveFailures = h.ConsecutiveFailures
	if !h.LastSeen.IsZero() {
		seen := h.LastSeen
		view.LastSeen = &seen
	}
	view.InFlight = inFlight
	view.InFlightKnown = inFlightKnown
}

// buildExecutorView assembles a single card. ex may be nil (recorded but not
// registered) and row may be the zero value (registered but not enrolled).
func (s *Server) buildExecutorView(
	ctx context.Context,
	id string,
	ex executor.Executor,
	row statedb.ExecutorRow,
	projects []string,
	defaultID string,
	sched *executorstore.Scheduler,
) executorView {
	view := executorView{
		ID:         id,
		Name:       row.Name,
		Kind:       row.Kind,
		Endpoint:   row.Endpoint,
		Registered: ex != nil,
		// Enrolled means "came through the enrollment flow", not merely "has
		// a row": syncRegistryToStore writes rows for the built-in drivers
		// too, and reporting those as enrolled would offer a Revoke button
		// that the delete handler is going to refuse.
		Enrolled:   row.Kind == executor.KindRemoteAgent,
		Default:    id == defaultID,
		Labels:     row.Labels,
		EnrolledBy: row.EnrolledBy,
		Projects:   projects,
		Status:     row.Status,
	}
	// Only a device advertises capabilities. For a local driver the stored
	// blob is just a copy of executor.Capabilities, and echoing it back under
	// a second name invites the panel to render the same chips twice.
	if row.Kind == executor.KindRemoteAgent {
		view.AgentCapabilities = row.Capabilities
	}
	sort.Strings(view.Projects)
	if view.Name == "" {
		view.Name = id
	}
	if !row.LastHeartbeat.IsZero() {
		hb := row.LastHeartbeat
		view.LastHeartbeat = &hb
	}
	if !row.CreatedAt.IsZero() {
		created := row.CreatedAt
		view.CreatedAt = &created
	}

	// Before the unregistered early-return on purpose: a cordon outlives the
	// config section that defined the executor, and hiding the cordon on the
	// one card that no longer has a driver is how an operator loses track of a
	// decision they made.
	inFlight, inFlightKnown := countInFlight(sched, id)
	applyScheduling(&view, schedulingHealth(id), inFlight, inFlightKnown)

	if ex == nil {
		// Recorded but not dispatchable in this process. Never report it as
		// online: the table's last-known status is about the device, and the
		// missing registration is about us.
		view.Status = statedb.ExecutorStatusUnknown
		view.Health = "not registered in this control plane — check that its config section still exists"
		return view
	}

	view.Kind = ex.Kind()
	caps := ex.Capabilities()
	view.Capabilities = &caps
	view.Isolation = string(caps.Isolation)

	healthCtx, cancel := context.WithTimeout(ctx, executorHealthTimeout)
	defer cancel()
	if err := ex.HealthCheck(healthCtx); err != nil {
		view.Health = err.Error()
		// A remote agent that has cleanly disconnected is "offline", not
		// "degraded": the distinction is whether something is wrong or
		// whether the device is simply not here right now.
		if view.Status == "" || view.Status == statedb.ExecutorStatusOnline {
			if ex.Kind() == executor.KindRemoteAgent {
				view.Status = statedb.ExecutorStatusOffline
			} else {
				view.Status = statedb.ExecutorStatusDegraded
			}
		}
	} else {
		view.Status = statedb.ExecutorStatusOnline
	}

	if live, ok := executor.LiveHandles(healthCtx, ex); ok {
		view.Running = len(live)
		view.RunningKnown = true
	}

	view.Blocked, view.BlockedReason = blockedFor(ex)
	return view
}

// projectExecutorView describes where workDir's next workload would run.
func (s *Server) projectExecutorView(workDir string, db *statedb.DB) *executorProjectView {
	if strings.TrimSpace(workDir) == "" {
		return nil
	}
	view := &executorProjectView{Path: workDir}
	if db != nil {
		if id, ok, err := db.ProjectExecutor(workDir); err == nil && ok {
			view.ExecutorID = id
			view.Bound = true
		}
	}
	// ResolveBinding rather than Resolve: the panel must be able to say
	// "this project points at the host executor, which is currently
	// forbidden" — Resolve would only say "denied" and lose the target.
	ex, err := executor.ResolveBinding(workDir)
	if err != nil {
		view.BlockedReason = err.Error()
		view.Blocked = true
		return view
	}
	view.EffectiveID = ex.ID()
	view.Blocked, view.BlockedReason = blockedFor(ex)
	return view
}

// applyDiagnostics folds the startup reconciliation into the cards, and adds
// a card for any configured executor that failed to register.
//
// The second half is the point. A driver that could not be built has no
// registry entry and no executors-table row, so it appeared in the panel as
// nothing at all — the operator saw an empty Executors tab and no indication
// that the container section they wrote had been read, tried, and rejected.
func applyDiagnostics(views []executorView, rec *reconciliationView) []executorView {
	if rec == nil {
		return views
	}
	byID := make(map[string]int, len(views))
	for i, v := range views {
		byID[v.ID] = i
	}
	for _, d := range rec.Diagnostics {
		i, ok := byID[d.ID]
		if !ok {
			continue
		}
		views[i].ReconcileStatus = string(d.Status)
		views[i].ReconcileMessage = d.Message
		views[i].ReconcileRemediation = d.Remediation
		views[i].PreflightFindings = d.Findings
	}
	return views
}

// missingExecutorViews builds cards for configured executors that never made
// it into the registry, so a failed driver is visible rather than absent.
func missingExecutorViews(views []executorView, rec *reconciliationView) []executorView {
	if rec == nil {
		return views
	}
	present := make(map[string]bool, len(views))
	for _, v := range views {
		present[v.ID] = true
	}
	for _, d := range rec.Diagnostics {
		if present[d.ID] {
			continue
		}
		views = append(views, executorView{
			ID:                   d.ID,
			Name:                 d.ID,
			Kind:                 d.Kind,
			Registered:           false,
			Status:               statedb.ExecutorStatusUnknown,
			Health:               d.Message,
			SchedState:           "unreachable",
			ReconcileStatus:      string(d.Status),
			ReconcileMessage:     d.Message,
			ReconcileRemediation: d.Remediation,
			PreflightFindings:    d.Findings,
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })
	return views
}

// handleExecutorsList serves GET /api/executors.
func (s *Server) handleExecutorsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	workDir := s.resolveWorkDir(r)

	// A missing or unopenable database is not fatal here: the registry alone
	// still describes the built-in drivers, and a panel that renders the
	// host executor beats a panel that renders an error.
	db, err := s.controlPlaneDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: executors: control-plane database unavailable: %v\n", err)
	} else {
		defer db.Close()
	}

	resp := executorsResponse{
		Executors: s.collectExecutorViews(r.Context(), db),
		Policy:    s.executorPolicy(),
		Project:   s.projectExecutorView(workDir, db),
		DefaultID: executor.DefaultRegistry.DefaultID(),
		Ready:     true,
	}
	if resp.Executors == nil {
		resp.Executors = []executorView{}
	}
	if report, ok := reconcile.LastReport(); ok {
		resp.Reconciliation = &reconciliationView{
			Diagnostics:  report.Diagnostics,
			ReconciledAt: report.ReconciledAt,
			Problems:     len(report.Problems()),
		}
		if resp.Reconciliation.Diagnostics == nil {
			resp.Reconciliation.Diagnostics = []reconcile.Diagnostic{}
		}
	}
	if err := reconcile.Ready(); err != nil {
		resp.Ready = false
		resp.NotReadyReason = err.Error()
		var notReady *reconcile.NotReadyError
		if errors.As(err, &notReady) {
			resp.NotReadyReason = notReady.Reason
			resp.Remediation = notReady.Remediation
		}
	}
	// Attach each driver's diagnostic to its own card, so an operator reading
	// a degraded executor sees why on the card rather than having to correlate
	// it with a separate list, then add cards for the ones that never
	// registered and would otherwise be invisible.
	resp.Executors = missingExecutorViews(applyDiagnostics(resp.Executors, resp.Reconciliation), resp.Reconciliation)
	jsonOK(w, resp)
}

// enrollRequest is the POST /api/executors/enroll body.
type enrollRequest struct {
	Name        string            `json:"name"`
	TTLMinutes  int               `json:"ttl_minutes"`
	WorkDirRoot string            `json:"workdir_root"`
	Labels      map[string]string `json:"labels"`
}

// enrollResponse carries the one and only sight of the token.
type enrollResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Token       string            `json:"token"`
	Command     string            `json:"command"`
	ServerURL   string            `json:"server_url"`
	ExpiresAt   time.Time         `json:"expires_at"`
	WorkDirRoot string            `json:"workdir_root,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	// Bundle packs the server URL, the token and the pin into one blob, so
	// the three cannot be pasted out of step with each other.
	Bundle string `json:"bundle,omitempty"`
	// Pin is the hub's SPKI fingerprint, or "" when it has no certificate
	// configured. Surfaced separately from Bundle so the panel can say when
	// there is none rather than leaving the operator to notice its absence.
	Pin string `json:"pin,omitempty"`
	// InstallCommand is the one-command onboarding snippet: fetch
	// /install.sh and run it with the bundle in the environment. Empty when
	// the dashboard is being served over plaintext HTTP, since /install.sh
	// refuses to answer such a request and offering the command anyway would
	// send the operator to a device to watch it fail.
	InstallCommand string `json:"install_command,omitempty"`
	// InstallUnavailable explains an empty InstallCommand.
	InstallUnavailable string `json:"install_unavailable,omitempty"`
	// Notice is shown next to the token. It is part of the payload rather
	// than hard-coded in the frontend so the CLI and the UI cannot drift on
	// what they promise about recoverability.
	Notice string `json:"notice"`
}

// handleExecutorEnroll serves POST /api/executors/enroll.
//
// It mints a single-use, expiring token and returns the exact command to paste
// on the device. It never contacts anything: the device is assumed unreachable
// (that is the entire premise of the outbound-enrollment design in Task
// 20158), so the operator carries the token there.
//
// With OIDC enabled this is admin-only. Minting an enrollment token is
// attaching an arbitrary machine to the control plane and granting it the
// right to execute project workloads — a fleet-level action, not a
// project-level one.
func (s *Server) handleExecutorEnroll(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if !s.requireExecutorAdmin(w, r) {
		return
	}

	var req enrollRequest
	limitJSONBody(w, r, maxJSONBodyBytes)
	// An empty body is legitimate: every field has a usable default, and
	// "enroll a device with default settings" should not require a payload.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !isEmptyBody(err) {
		jsonErr(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	ttl := remote.DefaultEnrollTTL
	if req.TTLMinutes != 0 {
		if req.TTLMinutes < enrollTTLMinutesLower || req.TTLMinutes > enrollTTLMinutesUpper {
			jsonErr(w, fmt.Sprintf("ttl_minutes must be between %d and %d (got %d)",
				enrollTTLMinutesLower, enrollTTLMinutesUpper, req.TTLMinutes), http.StatusBadRequest)
			return
		}
		ttl = time.Duration(req.TTLMinutes) * time.Minute
	}
	if root := strings.TrimSpace(req.WorkDirRoot); root != "" && !filepath.IsAbs(root) {
		jsonErr(w, "workdir_root must be an absolute path on the device", http.StatusBadRequest)
		return
	}

	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	store, err := executorstore.New(db)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// MintBundle rather than Mint: the bundle carries the server URL and the
	// hub's certificate pin alongside the token, which is what lets the
	// panel offer a one-command install (Task 20172) and what stops a device
	// from trusting whichever server answers at that hostname.
	serverURL := agentConnectURL(r)
	pin := s.transportPin()
	bundle, rec, err := remote.MintBundle(store, remote.MintOptions{
		Name:        strings.TrimSpace(req.Name),
		TTL:         ttl,
		WorkDirRoot: strings.TrimSpace(req.WorkDirRoot),
		Labels:      req.Labels,
		Server:      serverURL,
		Pin:         pin,
	})
	if err != nil {
		jsonErr(w, "mint enrollment token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := bundle.Encode()
	if err != nil {
		jsonErr(w, "encode enrollment bundle: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := enrollResponse{
		ID:          rec.ID,
		Name:        rec.Name,
		Token:       bundle.Token,
		ServerURL:   serverURL,
		Command:     bundle.Command(),
		ExpiresAt:   rec.ExpiresAt,
		WorkDirRoot: rec.WorkDirRoot,
		Labels:      rec.Labels,
		Bundle:      encoded,
		Pin:         pin,
		Notice: "This token is shown once and cannot be recovered — only its hash is stored. " +
			"It is single-use and expires at the time above. If it leaks, revoke it from this panel.",
	}
	if requestIsTLS(r) {
		resp.InstallCommand = installCommandFor(r, encoded)
	} else {
		resp.InstallUnavailable = "The one-command installer is served only over HTTPS, because it is piped " +
			"into a root shell on a device that does not yet know which control plane to trust. " +
			"Use the command above, or serve this hub over TLS."
	}
	// The ID and name are logged; the token deliberately is not, not even at
	// debug level. A token in a log file is a token that outlives its single
	// use and its expiry.
	fmt.Fprintf(os.Stderr, "ui: minted executor enrollment token %s (%s)\n", rec.ID, rec.Name)
	// The token is deliberately absent from the audit row for the same
	// reason it is absent from the log line above: the trail outlives the
	// token's single use, and a credential in an append-only table cannot be
	// removed later without breaking the hash chain.
	statedb.AuditExecutorLifecycle(db, statedb.ExecutorAuditInput{
		Action:     "enroll",
		ExecutorID: rec.ID,
		Actor:      s.auditActor(r),
		Detail: map[string]any{
			"name":         rec.Name,
			"expires_at":   rec.ExpiresAt.UTC().Format(time.RFC3339),
			"workdir_root": rec.WorkDirRoot,
			"labels":       rec.Labels,
		},
	})
	s.broadcastAuditAppend("enroll")
	s.broadcastExecutorUpdate("enrolled", rec.ID)
	jsonOK(w, resp)
}

// agentConnectURL builds the wss:// URL an agent should dial, from the request
// the operator's browser made.
//
// Deriving it from the request rather than from config is what makes the
// pasted command correct behind a reverse proxy, which is where a hosted
// deployment always lives. X-Forwarded-Proto is honoured for the same reason:
// the TLS terminates at the proxy, so r.TLS is nil on a connection the browser
// nonetheless made over HTTPS.
func agentConnectURL(r *http.Request) string {
	scheme := "ws"
	if r.TLS != nil {
		scheme = "wss"
	}
	if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto != "" {
		// Take the first entry: proxies chain this header.
		if i := strings.Index(proto, ","); i >= 0 {
			proto = strings.TrimSpace(proto[:i])
		}
		if strings.EqualFold(proto, "https") {
			scheme = "wss"
		}
	}
	host := r.Host
	if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwd != "" {
		if i := strings.Index(fwd, ","); i >= 0 {
			fwd = strings.TrimSpace(fwd[:i])
		}
		host = fwd
	}
	if host == "" {
		host = "YOUR-CONTROL-PLANE"
	}
	return scheme + "://" + host + executorConnectPath
}

// handleExecutorDelete serves DELETE /api/executors/{id}: revoke an enrolled
// agent's credential, drop its session, and forget it.
//
// Only enrolled executors are deletable. A container executor comes from
// .cloop/config.yaml, so "deleting" it here would remove a row that the next
// startup recreates — an action that appears to work and silently does not.
// Saying so is better than pretending.
func (s *Server) handleExecutorDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "executor id is required", http.StatusBadRequest)
		return
	}

	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()

	row, rowErr := db.GetExecutor(id)
	if errors.Is(rowErr, statedb.ErrExecutorNotFound) {
		if ex, regErr := executor.Get(id); regErr == nil {
			jsonErr(w, fmt.Sprintf("executor %q is not an enrolled agent — %s", id, configRemedyFor(ex.Kind())),
				http.StatusBadRequest)
			return
		}
		jsonErr(w, fmt.Sprintf("executor %q not found", id), http.StatusNotFound)
		return
	}
	if rowErr != nil {
		jsonErr(w, rowErr.Error(), http.StatusInternalServerError)
		return
	}
	if row.Kind != executor.KindRemoteAgent {
		jsonErr(w, fmt.Sprintf("executor %q is not an enrolled agent — %s", id, configRemedyFor(row.Kind)),
			http.StatusBadRequest)
		return
	}

	// Revoke the credential first. If the later steps fail, the device has
	// already lost its ability to authenticate, which is the half of this
	// operation that actually matters for security.
	store, storeErr := executorstore.New(db)
	if storeErr == nil {
		if _, err := remote.Revoke(store, id, time.Now()); err != nil && !errors.Is(err, remote.ErrAgentNotFound) {
			fmt.Fprintf(os.Stderr, "ui: revoke agent credential %s: %v\n", id, err)
		}
	}
	if hub, hubErr := s.remoteHub(); hubErr == nil && hub != nil {
		if err := hub.Revoke(id); err != nil {
			fmt.Fprintf(os.Stderr, "ui: revoke agent session %s: %v\n", id, err)
		}
	}
	// DeleteExecutor also drops every project binding that pointed here, so
	// a project pinned to a revoked device fails Resolve with "no executor"
	// rather than silently falling back to host execution.
	if err := db.DeleteExecutor(id); err != nil {
		jsonErr(w, "delete executor: "+err.Error(), http.StatusInternalServerError)
		return
	}
	executor.DefaultRegistry.Unregister(id)

	fmt.Fprintf(os.Stderr, "ui: revoked executor %s (%s)\n", id, row.Name)
	statedb.AuditExecutorLifecycle(db, statedb.ExecutorAuditInput{
		Action:     "revoke",
		ExecutorID: id,
		Actor:      s.auditActor(r),
		Detail:     map[string]any{"name": row.Name, "kind": string(row.Kind)},
	})
	s.broadcastAuditAppend("revoke")
	s.broadcastExecutorUpdate("revoked", id)
	jsonOK(w, map[string]any{"ok": true, "id": id, "revoked": true})
}

// -------------------------------------------------- scheduling state (20162)
//
// Cordon, uncordon, and drain are the Web UI half of `cloop executor cordon|
// uncordon|drain`. They write the same persisted health rows the CLI writes and
// the supervisor maintains, which is what makes a cordon set from the dashboard
// survive a restart and be honoured by a run started from a terminal.
//
// They exist as their own endpoints rather than as a mode of DELETE because the
// distinction is the entire point of the feature: revoking an executor kills
// what it is running, cordoning it does not.

// maxDrainWaitSeconds bounds how long a drain request may block.
//
// The drain itself is not bounded — the node stays draining regardless. This
// caps only how long one HTTP request sits open, because a browser fetch that
// hangs for an hour is indistinguishable from a broken dashboard, and the
// operator can simply ask again.
const maxDrainWaitSeconds = 300

// drainPollInterval is how often a waiting drain re-reads the in-flight count.
const drainPollInterval = 2 * time.Second

// executorReasonRequest is the optional body of the cordon endpoint.
type executorReasonRequest struct {
	Reason string `json:"reason"`
}

// executorDrainRequest is the POST /api/executors/{id}/drain body.
type executorDrainRequest struct {
	Reason string `json:"reason"`
	// TimeoutSeconds is how long to wait for in-flight work to finish. Zero —
	// the default — does not wait at all: the state change has already taken
	// effect, and blocking a dashboard request on a task that may run for an
	// hour is not a service to anyone.
	TimeoutSeconds int `json:"timeout_seconds"`
	// Force means "do not wait", equivalent to TimeoutSeconds 0. It is spelled
	// separately so the UI can offer the CLI's --force semantics verbatim.
	Force bool `json:"force"`
}

// executorSchedResponse is the body of the cordon and uncordon endpoints. The
// full Health rides along so the client never has to re-fetch the list to learn
// what its own action produced.
type executorSchedResponse struct {
	OK          bool            `json:"ok"`
	ExecutorID  string          `json:"executor_id"`
	Health      executor.Health `json:"health"`
	State       string          `json:"state"`
	Schedulable bool            `json:"schedulable"`
	AdminHeld   bool            `json:"admin_held"`
	Reason      string          `json:"reason,omitempty"`
}

// executorDrainResponse adds the drain-specific outcome. Drained false is not
// an error: the node is draining either way, and the flag reports only whether
// this request's wait saw it reach zero.
type executorDrainResponse struct {
	executorSchedResponse
	Drained       bool `json:"drained"`
	InFlight      int  `json:"in_flight"`
	InFlightKnown bool `json:"in_flight_known"`
}

func newExecutorSchedResponse(h executor.Health) executorSchedResponse {
	return executorSchedResponse{
		OK:          true,
		ExecutorID:  h.ExecutorID,
		Health:      h,
		State:       string(h.State),
		Schedulable: h.State.Schedulable(),
		AdminHeld:   h.State.AdminHeld(),
		Reason:      h.Reason,
	}
}

// executorSchedTarget runs the preamble shared by the three scheduling
// endpoints: the admin gate, a usable executor ID, and a live supervisor. It
// writes the error response itself and reports false when the caller must stop.
//
// The supervisor check is not defensive padding. executorSupervisor() returns
// nil whenever supervision failed to start — an unopenable control-plane
// database is the realistic case — and a handler that dereferenced it would
// turn "we cannot persist your cordon" into a panic and a 500. 503 says the
// truth: the capability is missing right now, and the request was not applied.
func (s *Server) executorSchedTarget(w http.ResponseWriter, r *http.Request) (*executor.Supervisor, string, bool) {
	if !s.requireExecutorAdmin(w, r) {
		return nil, "", false
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonErr(w, "executor id is required", http.StatusBadRequest)
		return nil, "", false
	}
	sv := executorSupervisor()
	if sv == nil {
		jsonErr(w, "executor supervision is not running on this control plane, so scheduling "+
			"state cannot be changed and nothing was applied. It starts with the dashboard; "+
			"check the server log for \"executor supervisor disabled\".",
			http.StatusServiceUnavailable)
		return nil, "", false
	}
	return sv, id, true
}

// decodeExecutorBody decodes an all-optional JSON body, treating an empty one
// as "use the defaults".
func decodeExecutorBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil && !isEmptyBody(err) {
		jsonErr(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// writeExecutorSchedErr maps a supervisor admin error onto a status code.
//
// ErrExecutorNotFound is matched through the sentinel rather than by string:
// the registry wraps it with the ID, and a 500 for "you named a device that
// does not exist" would read as a server fault instead of as a typo.
func writeExecutorSchedErr(w http.ResponseWriter, id string, err error) {
	if errors.Is(err, executor.ErrExecutorNotFound) {
		jsonErr(w, fmt.Sprintf("executor %q is not registered on this control plane — "+
			"only a registered backend has a scheduling state to change", id), http.StatusNotFound)
		return
	}
	jsonErr(w, err.Error(), http.StatusInternalServerError)
}

// handleExecutorCordon serves POST /api/executors/{id}/cordon: stop placing new
// work here, without touching what is already running.
func (s *Server) handleExecutorCordon(w http.ResponseWriter, r *http.Request) {
	sv, id, ok := s.executorSchedTarget(w, r)
	if !ok {
		return
	}
	var req executorReasonRequest
	if !decodeExecutorBody(w, r, &req) {
		return
	}

	h, err := sv.Cordon(id, strings.TrimSpace(req.Reason))
	if err != nil {
		writeExecutorSchedErr(w, id, err)
		return
	}
	fmt.Fprintf(os.Stderr, "ui: cordoned executor %s (%s)\n", id, h.Reason)
	s.auditExecutorAction(r, "cordon", id, map[string]any{"reason": h.Reason, "state": string(h.State)})
	s.broadcastExecutorUpdate("cordoned", id)
	jsonOK(w, newExecutorSchedResponse(h))
}

// handleExecutorUncordon serves POST /api/executors/{id}/uncordon.
//
// The resulting state is deliberately not always ready — Uncordon returns the
// node to what its probe history justifies — so the response carries the real
// state and the frontend reports it rather than assuming success means healthy.
func (s *Server) handleExecutorUncordon(w http.ResponseWriter, r *http.Request) {
	sv, id, ok := s.executorSchedTarget(w, r)
	if !ok {
		return
	}
	h, err := sv.Uncordon(id)
	if err != nil {
		writeExecutorSchedErr(w, id, err)
		return
	}
	fmt.Fprintf(os.Stderr, "ui: uncordoned executor %s (now %s)\n", id, h.State)
	s.auditExecutorAction(r, "uncordon", id, map[string]any{"state": string(h.State)})
	s.broadcastExecutorUpdate("uncordoned", id)
	jsonOK(w, newExecutorSchedResponse(h))
}

// handleExecutorDrain serves POST /api/executors/{id}/drain: refuse new work
// and optionally wait for the in-flight count to reach zero.
//
// The ordering matters. The state is set first and unconditionally, because
// that is the part the operator asked for and it takes effect immediately; the
// wait is a convenience of this particular HTTP call. A timeout therefore comes
// back 200 with drained:false rather than as an error — the drain worked, the
// waiting did not finish, and reporting that as a failure would invite an
// operator to "retry" something that is already in effect.
func (s *Server) handleExecutorDrain(w http.ResponseWriter, r *http.Request) {
	sv, id, ok := s.executorSchedTarget(w, r)
	if !ok {
		return
	}
	var req executorDrainRequest
	if !decodeExecutorBody(w, r, &req) {
		return
	}
	if req.TimeoutSeconds < 0 || req.TimeoutSeconds > maxDrainWaitSeconds {
		jsonErr(w, fmt.Sprintf("timeout_seconds must be between 0 and %d (got %d) — "+
			"the drain itself is not time-limited, only how long this request waits for it",
			maxDrainWaitSeconds, req.TimeoutSeconds), http.StatusBadRequest)
		return
	}

	h, err := sv.Drain(id, strings.TrimSpace(req.Reason))
	if err != nil {
		writeExecutorSchedErr(w, id, err)
		return
	}
	fmt.Fprintf(os.Stderr, "ui: draining executor %s (%s)\n", id, h.Reason)
	s.auditExecutorAction(r, "drain", id, map[string]any{"reason": h.Reason, "state": string(h.State)})
	s.broadcastExecutorUpdate("draining", id)

	resp := executorDrainResponse{executorSchedResponse: newExecutorSchedResponse(h)}

	if req.Force || req.TimeoutSeconds == 0 {
		// Do not block at all, but still report what is out there: "draining,
		// 3 still running" is the number the operator came for.
		db, dbErr := s.controlPlaneDB()
		if dbErr == nil {
			defer db.Close()
			resp.InFlight, resp.InFlightKnown = countInFlight(schedulerFor(db), id)
		}
		resp.Drained = resp.InFlightKnown && resp.InFlight == 0
		jsonOK(w, resp)
		return
	}

	// Bounded by the request context as well as by the timeout, so a browser
	// that navigates away releases the handler immediately instead of holding
	// a goroutine and a database handle for the rest of the budget.
	wait := time.Duration(req.TimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(r.Context(), wait)
	defer cancel()

	remaining, waitErr := sv.WaitForDrain(ctx, id, wait, drainPollInterval)
	switch {
	case waitErr == nil:
		resp.Drained, resp.InFlight, resp.InFlightKnown = true, 0, true
	case errors.Is(waitErr, executor.ErrDrainTimeout),
		errors.Is(waitErr, context.DeadlineExceeded),
		errors.Is(waitErr, context.Canceled):
		// Still draining, just not finished inside this request's budget.
		resp.Drained, resp.InFlight, resp.InFlightKnown = false, remaining, true
	default:
		// The count itself could not be read. Report "unknown" rather than
		// zero, and leave Reason carrying the node's state reason — the drain
		// is in force, and overwriting it with a database error would tell the
		// operator the wrong story about why their node is out of rotation.
		resp.Drained, resp.InFlightKnown = false, false
		fmt.Fprintf(os.Stderr, "ui: wait for drain of %s: %v\n", id, waitErr)
	}
	jsonOK(w, resp)
}

// configRemedyFor says how to remove a config-defined backend, per kind.
//
// A generic "remove its executors.<kind> section" would be wrong for the host
// driver in particular: there is no executors.localprocess section, and an
// operator who went looking for one would conclude the API was confused. The
// host driver is built in and turned off by policy, not by deletion.
func configRemedyFor(kind string) string {
	switch kind {
	case executor.KindLocalProcess:
		return "it is the built-in host driver and cannot be deleted. To stop this control " +
			"plane from executing on the host, set executors.allow_host_process: false in " +
			".cloop/config.yaml."
	case executor.KindContainer:
		return "it is configured in .cloop/config.yaml. Set executors.container.enabled: false " +
			"(or remove the section) and restart."
	case executor.KindKubernetes:
		return "it is configured in .cloop/config.yaml. Set executors.kubernetes.enabled: false " +
			"(or remove the section) and restart. To revoke its cluster access without touching " +
			"the config, revoke the kubeconfig grant instead: `cloop secret revoke <grant-id>`."
	default:
		return "it is defined by configuration rather than by enrollment. Remove its " +
			"executors.* section from .cloop/config.yaml and restart."
	}
}

// bindExecutorRequest is the POST /api/projects/{idx}/executor body.
type bindExecutorRequest struct {
	// ExecutorID pins the project. An empty value clears the binding so the
	// project falls back to the registry default.
	ExecutorID string `json:"executor_id"`
}

// handleProjectExecutorBind serves POST /api/projects/{idx}/executor: make a
// project's execution target a one-click setting.
func (s *Server) handleProjectExecutorBind(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	entry, ok := s.projectEntryFromPath(w, r)
	if !ok {
		return
	}

	var req bindExecutorRequest
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !isEmptyBody(err) {
		jsonErr(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(req.ExecutorID)

	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()

	if id == "" {
		if err := db.UnbindProjectExecutor(entry.Path); err != nil {
			jsonErr(w, "unbind executor: "+err.Error(), http.StatusInternalServerError)
			return
		}
		executor.DefaultRegistry.Unbind(entry.Path)
		statedb.AuditExecutorLifecycle(db, statedb.ExecutorAuditInput{
			Action: "unbind",
			Actor:  s.auditActor(r),
			Detail: map[string]any{"project": entry.Name, "project_path": entry.Path},
		})
		s.broadcastAuditAppend("unbind")
		s.broadcastExecutorUpdate("unbound", "")
		jsonOK(w, map[string]any{"ok": true, "project": entry.Name, "executor_id": ""})
		return
	}

	ex, getErr := executor.Get(id)
	if getErr != nil {
		// An enrolled-but-unregistered executor is still a legitimate
		// target: Hub.Restore re-registers agents at startup, so this only
		// happens for a backend whose config section was removed. Refusing
		// tells the operator something real; accepting would create a
		// binding that fails at the next run with a worse message.
		jsonErr(w, fmt.Sprintf("executor %q is not available on this control plane: %v", id, getErr),
			http.StatusBadRequest)
		return
	}
	if blocked, reason := blockedFor(ex); blocked {
		// 409 rather than 400: the request is well-formed and would have
		// been accepted under a different policy. This is the same status
		// the run paths return, so the frontend has one thing to handle.
		writeHostExecutionDenied(w, &executor.HostExecutionDeniedError{
			ExecutorID:   id,
			ProjectPath:  entry.Path,
			Alternatives: executor.IsolatedIDs(),
		}, reason)
		return
	}

	if err := db.BindProjectExecutor(entry.Path, id, s.sessionIdentity(r).OwnerKey()); err != nil {
		if errors.Is(err, statedb.ErrExecutorNotFound) {
			jsonErr(w, fmt.Sprintf("executor %q has no record in the control-plane database", id),
				http.StatusBadRequest)
			return
		}
		jsonErr(w, "bind executor: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Mirror into the in-memory registry so the very next run honours the
	// binding without waiting for the persistent lookup's next read.
	if err := executor.Bind(entry.Path, id); err != nil {
		fmt.Fprintf(os.Stderr, "ui: in-memory bind of %s to %s: %v\n", entry.Path, id, err)
	}

	fmt.Fprintf(os.Stderr, "ui: project %s bound to executor %s\n", entry.Path, id)
	// Where a project's code runs is the single most consequential setting
	// on this hub — it decides which machine sees the repository and which
	// credentials get brokered to it — so the binding is recorded with both
	// the project and the target.
	statedb.AuditExecutorLifecycle(db, statedb.ExecutorAuditInput{
		Action:     "bind",
		ExecutorID: id,
		Actor:      s.auditActor(r),
		Detail: map[string]any{
			"project":      entry.Name,
			"project_path": entry.Path,
			"kind":         string(ex.Kind()),
		},
	})
	s.broadcastAuditAppend("bind")
	s.broadcastExecutorUpdate("bound", id)
	jsonOK(w, map[string]any{"ok": true, "project": entry.Name, "executor_id": id})
}

// projectEntryFromPath resolves the {idx} path wildcard shared by the project
// routes, writing the error response itself when it cannot.
func (s *Server) projectEntryFromPath(w http.ResponseWriter, r *http.Request) (projectEntry, bool) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		jsonErr(w, "invalid project index", http.StatusBadRequest)
		return projectEntry{}, false
	}
	// Resolved against the *visible* list so a user cannot repoint a project
	// they cannot see by guessing an index.
	entries := s.visibleProjectEntries(r)
	if idx < 0 || idx >= len(entries) {
		jsonErr(w, "project index out of range", http.StatusBadRequest)
		return projectEntry{}, false
	}
	e := entries[idx]
	return projectEntry{Name: e.Name, Path: e.Path}, true
}

// projectEntry is the minimal shape the executor handlers need from the
// multi-project registry.
type projectEntry struct {
	Name string
	Path string
}

// isEmptyBody reports whether a JSON decode failed because there was nothing
// to decode, as opposed to because what was there was malformed. Handlers
// whose fields are all optional treat the former as "use the defaults".
func isEmptyBody(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// requireExecutorAdmin gates fleet-level mutations. With OIDC disabled the
// dashboard has a single trust level and the existing auth middleware has
// already vouched for the caller, so there is nothing further to check.
func (s *Server) requireExecutorAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !s.oidcEnabled() {
		return true
	}
	// With RBAC configured — or with an API token, which carries its own
	// roles — the route gate already required executor.manage: a richer
	// decision than the admin_emails list, and one an operator can grant by
	// group. Re-checking admin_emails here would silently override the
	// configured policy, and for a token there is no email to check at all.
	if s.authzActiveFor(r) {
		return true
	}
	id := s.sessionIdentity(r)
	if id == nil {
		// Authenticated via the static bearer token, which is an operator
		// credential by definition (it is the deployment's own secret).
		return true
	}
	if s.OIDC.IsAdmin(id) {
		return true
	}
	jsonErr(w, "managing executors requires an administrator account — "+
		"enrolling a device grants it the right to run project workloads",
		http.StatusForbidden)
	return false
}

// writeHostExecutionDenied writes the 409 that strict no-host-execution mode
// produces, with the remediation in a dedicated field so the frontend can
// render "what went wrong" and "what to do" as separate elements instead of
// regex-ing one sentence apart.
func writeHostExecutionDenied(w http.ResponseWriter, denied *executor.HostExecutionDeniedError, remediation string) {
	if remediation == "" && denied != nil {
		remediation = denied.Remediation()
	}
	body := map[string]any{
		"error":       denied.Error(),
		"code":        "host_execution_denied",
		"remediation": remediation,
	}
	if len(denied.Alternatives) > 0 {
		body["alternatives"] = denied.Alternatives
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(body)
}

// jsonWorkloadErr writes the response for a failure to start or run a
// workload, mapping a policy refusal to 409 and everything else to 500.
//
// It exists so every UI code path that dispatches work reports a blocked host
// the same way. A handler that fell back to a bare 500 would tell the operator
// "something broke" about the one failure mode that is not a break at all.
func jsonWorkloadErr(w http.ResponseWriter, err error) {
	var denied *executor.HostExecutionDeniedError
	if errors.As(err, &denied) {
		writeHostExecutionDenied(w, denied, "")
		return
	}
	if errors.Is(err, executor.ErrHostExecutionDenied) {
		writeHostExecutionDenied(w, &executor.HostExecutionDeniedError{
			Alternatives: executor.IsolatedIDs(),
		}, "")
		return
	}

	// A project's .cloop/sandbox.yaml asked for something the deployment does
	// not offer. These are 409s for the same reason the policy refusal is: the
	// request was well-formed, and what conflicts is the repo's spec with the
	// hub's configuration. A 500 would send the operator looking for a fault
	// where there is only a disagreement.
	var grantDenied *sandbox.GrantDeniedError
	if errors.As(err, &grantDenied) {
		writeSandboxDenied(w, "sandbox_grant_denied", grantDenied.Error(), grantDenied.Remediation(), nil)
		return
	}
	var placement *executor.PlacementError
	if errors.As(err, &placement) {
		writeSandboxDenied(w, "sandbox_unsupported", placement.Error(),
			fmt.Sprintf("Bind this project to an executor that supports %s, or remove the "+
				"requirement from %s.", placement.Constraint, sandbox.FileName),
			executor.IsolatedIDs())
		return
	}
	if errors.Is(err, sandbox.ErrInvalidSpec) {
		// The file itself is wrong. 400: the author can fix it by editing the
		// repo, without anything on the hub changing.
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonErr(w, err.Error(), http.StatusInternalServerError)
}

// writeSandboxDenied writes a 409 for a sandbox spec the deployment cannot
// honour, in the same envelope as writeHostExecutionDenied so the frontend has
// one shape to render rather than two.
func writeSandboxDenied(w http.ResponseWriter, code, message, remediation string, alternatives []string) {
	body := map[string]any{
		"error":       message,
		"code":        code,
		"remediation": remediation,
	}
	if len(alternatives) > 0 {
		body["alternatives"] = alternatives
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(body)
}

// broadcastExecutorUpdate pushes an executor_update event to every connected
// dashboard, over the same WebSocket the state diffs ride (Tasks 20126/20134).
//
// It is a global fan-out rather than a per-project broadcast because the
// executor fleet is global: a device enrolling is news for every open tab, not
// only for tabs viewing some particular project. The payload deliberately
// carries no executor detail — clients re-read GET /api/executors, which is
// the one place the registry/table/binding join lives.
func (s *Server) broadcastExecutorUpdate(event, executorID string) {
	payload, err := json.Marshal(map[string]any{
		"event":       event,
		"executor_id": executorID,
	})
	if err != nil {
		return
	}
	msg := wsMessage{Type: "executor_update", Data: json.RawMessage(payload)}

	s.hubMu.Lock()
	for _, clients := range s.hubClients {
		for hc := range clients {
			s.sendOrLag(hc, msg)
		}
	}
	s.hubMu.Unlock()
}

// makeExecutorStatusBroadcaster wraps a status mirror so a device going
// online or offline reaches open dashboards immediately.
//
// Without this the Executors panel would show a stale status dot until
// something else happened to trigger a refresh — the polling behaviour Tasks
// 20126 and 20134 removed everywhere else.
func (s *Server) makeExecutorStatusBroadcaster(inner func(string, string, time.Time)) func(string, string, time.Time) {
	return func(executorID, status string, at time.Time) {
		if inner != nil {
			inner(executorID, status, at)
		}
		s.broadcastExecutorUpdate("status:"+status, executorID)
	}
}

// makeExecutorEnrollBroadcaster wraps the enrollment recorder so a device that
// redeems its token appears on open dashboards immediately, rather than the
// next time somebody happens to reload the page.
func (s *Server) makeExecutorEnrollBroadcaster(
	inner func(remote.AgentRecord, remote.AgentCapabilities),
) func(remote.AgentRecord, remote.AgentCapabilities) {
	return func(agent remote.AgentRecord, caps remote.AgentCapabilities) {
		if inner != nil {
			inner(agent, caps)
		}
		s.broadcastExecutorUpdate("redeemed", agent.AgentID)
	}
}

// syncRegistryToStore records a row for every executor the registry knows
// about, so the executors table is a superset of what can run work.
//
// Two things depend on it. BindProjectExecutor enforces referential integrity
// against that table, so without a row for the host driver a project could
// not be pinned to it at all. And the Executors panel needs a stable
// created-at and name for backends that were configured rather than enrolled.
//
// Enrolled agents are skipped: their rows carry heartbeats and
// device-advertised capabilities that this function has no way to reproduce
// and would overwrite.
func syncRegistryToStore(dir string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		// No control-plane database yet (a fresh directory, or a test that
		// never initialised one). Nothing to sync into; the panel falls back
		// to the registry alone.
		return
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: executor registry sync: %v\n", err)
		return
	}
	defer db.Close()

	now := time.Now()
	for _, ex := range executor.List() {
		if ex.Kind() == executor.KindRemoteAgent {
			continue
		}
		if existing, err := db.GetExecutor(ex.ID()); err == nil && existing.Kind == executor.KindRemoteAgent {
			continue
		}
		caps, _ := json.Marshal(ex.Capabilities())
		row := statedb.ExecutorRow{
			ID:            ex.ID(),
			Name:          ex.ID(),
			Kind:          ex.Kind(),
			Status:        statedb.ExecutorStatusOnline,
			Capabilities:  caps,
			LastHeartbeat: now,
			CreatedAt:     now,
		}
		if err := db.UpsertExecutor(row); err != nil {
			fmt.Fprintf(os.Stderr, "ui: record executor %s: %v\n", ex.ID(), err)
		}
	}
}
