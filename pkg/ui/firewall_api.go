package ui

// firewall_api.go is the dashboard's surface for the stored levels of the
// IP-layer egress firewall (Task 20363, re-landing Task 20319):
//
//	what any sandbox on this device may ever reach — /api/executors/{id}/firewall
//	what this project's sandboxes may reach        — /api/firewall?project_idx=N
//
// The device's rule set is the superset. An admin sets it, and every sandbox on
// the device must fit inside it: a virtual executor's firewall (checked when
// that is saved, in virtual_executors_api.go) and a project's rule set, which
// its maintainers edit here and which may only narrow its executor's.
//
// Each save is checked against the levels above it inside one transaction, so
// the error lands on the form while whoever typed the range is still looking.
// A device that is tightened narrows what was saved under it in the same
// transaction — every virtual executor and project rule set that no longer
// fits is rewritten to the part of it the device still allows, and each
// rewrite is audited and listed back to the admin. The dispatch step and the
// drivers prove the containment again; see firewall_dispatch.go.
//
// # Why the project half is not in .cloop/sandbox.yaml
//
// Because it can name addresses. A repository-committed file that could name
// 10.0.0.0/8 would put the operator's network one pull request away, which is
// why pkg/sandbox has only the two-value `capabilities.egress`. A rule set saved
// here comes from an identity the hub authenticated and authorized for this
// project, and it is still only ever a narrowing.

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// firewallRequest is the PUT body for either level. It replaces the whole rule
// set: the form shows every field and saving it stores what the person was
// looking at, including the fields they cleared.
type firewallRequest struct {
	AllowPublicInternet bool     `json:"allow_public_internet"`
	AllowCIDRs          []string `json:"allow_cidrs"`
	DenyCIDRs           []string `json:"deny_cidrs"`
	AllowPorts          []int    `json:"allow_ports"`
	Resolvers           []string `json:"resolvers"`
	// Clear removes the rule set, leaving the level to the ones above it.
	// Distinct from saving an empty rule set, which means "reach nothing" — the
	// strongest thing a firewall can say, and one the form must be able to say.
	Clear bool `json:"clear"`
}

// rules is the request as a rule set, refused (ErrInvalidSpec, so 400) unless
// it normalizes and every allowlist entry that contains a cloud metadata
// service names it or denies it (Task 20397). Stored rule sets are read back
// with Normalize alone, so one saved before the rule keeps loading; this is
// the only place a new one is written from.
func (req firewallRequest) rules() (executor.FirewallRules, error) {
	r, err := executor.FirewallRules{
		AllowPublicInternet: req.AllowPublicInternet,
		AllowCIDRs:          req.AllowCIDRs,
		DenyCIDRs:           req.DenyCIDRs,
		AllowPorts:          req.AllowPorts,
		Resolvers:           req.Resolvers,
	}.Normalize()
	if err != nil {
		return executor.FirewallRules{}, err
	}
	if err := r.CheckMetadata(); err != nil {
		return executor.FirewallRules{}, err
	}
	return r, nil
}

// firewallChange is one rule set a save narrowed to fit.
type firewallChange struct {
	// Kind is "virtual" or "project".
	Kind    string   `json:"kind"`
	Subject string   `json:"subject"`
	Name    string   `json:"name,omitempty"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Notes   []string `json:"notes"`
	// executorID is the executor a constrained project resolved to, for its
	// audit row.
	executorID string
}

// firewallChild is one thing a device's rule set bounds, for its card.
type firewallChild struct {
	Kind     string   `json:"kind"`
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	Describe string   `json:"describe"`
	Fits     bool     `json:"fits"`
	Reasons  []string `json:"reasons,omitempty"`
	// Metadata is the child's own metadata findings (Task 20397).
	Metadata []string `json:"metadata,omitempty"`
}

// deviceFirewallView is the device card's GET body and the answer to a write.
type deviceFirewallView struct {
	ExecutorID string                 `json:"executor_id"`
	Kind       string                 `json:"kind"`
	Configured bool                   `json:"configured"`
	Rules      executor.FirewallRules `json:"rules"`
	Describe   string                 `json:"describe"`
	// Config is the bound the executor's configuration file sets, which the
	// device's rule set must itself fit inside; null when it sets none.
	Config *executor.FirewallRules `json:"config"`
	// Enforced reports whether a workload placed on the device itself can be
	// held to firewall rules; Warning says what happens when it cannot.
	Enforced bool   `json:"enforced"`
	Warning  string `json:"warning,omitempty"`
	SetAt    string `json:"set_at,omitempty"`
	SetBy    string `json:"set_by,omitempty"`
	// Children are the virtual executors and project rule sets the device's
	// rule set bounds, and whether each fits inside it now.
	Children []firewallChild `json:"children"`
	// Constrained lists what a save narrowed to fit, on a write's answer.
	Constrained []firewallChange `json:"constrained,omitempty"`
	// Metadata says which allowlist entries of the stored rule set contain a
	// cloud metadata service without naming it (Task 20397): rules saved
	// before the rule, which keep the service closed and cannot be saved
	// again unchanged.
	Metadata []string `json:"metadata,omitempty"`
}

// projectFirewallView is the project card's GET body and the answer to a write.
type projectFirewallView struct {
	Project string `json:"project"`
	// Visible is false for a reader who may not change the project's
	// configuration, and then nothing else is filled in.
	Visible bool `json:"visible"`
	// PolicyProject is the project whose rule set this is when it is not the
	// one asked about: a feature worktree runs under its parent's.
	PolicyProject string                 `json:"policy_project,omitempty"`
	Configured    bool                   `json:"configured"`
	Rules         executor.FirewallRules `json:"rules"`
	Describe      string                 `json:"describe"`
	ExecutorID    string                 `json:"executor_id,omitempty"`
	ExecutorKind  string                 `json:"executor_kind,omitempty"`
	// Levels are the rule sets above the project, outermost first — what the
	// card shows beside the editable form.
	Levels []fwpolicy.Level `json:"levels"`
	// Governing is what those levels come to: the rule set the project's must
	// fit inside, null when nothing bounds it.
	Governing *executor.FirewallRules `json:"governing"`
	// Fits reports whether the stored rule set fits inside Governing now.
	Fits    bool     `json:"fits"`
	Reasons []string `json:"reasons,omitempty"`
	// Enforced reports whether the executor can install rules for a run;
	// Warning says what happens to the project's runs when it cannot.
	Enforced bool   `json:"enforced"`
	Warning  string `json:"warning,omitempty"`
	SetAt    string `json:"set_at,omitempty"`
	SetBy    string `json:"set_by,omitempty"`
	// Metadata is the stored rule set's metadata findings, as on the device's
	// view.
	Metadata []string `json:"metadata,omitempty"`
}

// errFirewallExceeds carries a refused save from inside a transaction to the
// handler that renders it.
type errFirewallExceeds struct {
	what    string
	bound   *executor.FirewallRules
	reasons []string
	remedy  string
}

func (e *errFirewallExceeds) Error() string {
	return fmt.Sprintf("%s reaches further than %s: %s", e.what, describeBound(e.bound),
		strings.Join(e.reasons, "; "))
}

func describeBound(r *executor.FirewallRules) string {
	if r == nil {
		return "nothing"
	}
	return "the rule set above it (" + fwpolicy.Describe(r) + ")"
}

// writeFirewallErr renders an error from a firewall save.
func writeFirewallErr(w http.ResponseWriter, err error) {
	var ex *errFirewallExceeds
	switch {
	case errors.As(err, &ex):
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error":       err.Error(),
			"code":        "firewall_exceeds_bound",
			"reasons":     ex.reasons,
			"bound":       ex.bound,
			"remediation": ex.remedy,
		})
	case fwpolicy.IsExceeds(err):
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error": err.Error(),
			"code":  "firewall_exceeds_bound",
		})
	case errors.Is(err, executor.ErrInvalidSpec):
		jsonErr(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, statedb.ErrDBLocked):
		jsonErr(w, "the control plane is busy; retry: "+err.Error(), http.StatusServiceUnavailable)
	default:
		writeVirtualExecutorErr(w, err)
	}
}

// firewallReader is what the database and a firewall transaction both offer.
type firewallReader interface {
	ExecutorFirewall(id string) (statedb.FirewallRecord, bool, error)
	VirtualExecutor(id string) (statedb.VirtualExecutor, bool, error)
}

// governingLevels returns the levels above a workload on ex, outermost first,
// reading the stored ones through rd — inside a save's transaction, so the
// check and the write see the same rows.
//
// override, when non-nil, stands in for a virtual executor's stored
// configuration: a save narrowing it checks its projects against what it is
// about to become.
func governingLevels(rd firewallReader, ex executor.Executor, deviceRules *executor.FirewallRules,
	override map[string]executor.VirtualSpec) ([]fwpolicy.Level, executor.EgressPosture, error) {
	pos := executor.PostureOf(ex)
	device := deviceRules
	if device == nil {
		rec, ok, err := rd.ExecutorFirewall(pos.DeviceID)
		if err != nil {
			return nil, pos, err
		}
		if ok {
			r := rec.Rules
			device = &r
		}
	}
	own := pos.Own
	ownName := pos.OwnName
	if ex.Kind() == executor.KindVirtual {
		if vs, ok := override[ex.ID()]; ok {
			own = fwpolicy.VirtualLevel(vs)
		} else if v, found, err := rd.VirtualExecutor(ex.ID()); err != nil {
			return nil, pos, err
		} else if found {
			own = fwpolicy.VirtualLevel(v.Spec)
		}
	}
	if ownName == "" {
		ownName = "executor " + ex.ID() + "'s own network"
	}
	levels := []fwpolicy.Level{
		{Kind: "config", Name: "executor " + ex.ID() + "'s configuration", Rules: pos.Config},
		{Kind: "device", Name: "device " + pos.DeviceID + "'s firewall", Rules: device},
		{Kind: "own", Name: ownName, Rules: own},
	}
	return levels, pos, nil
}

// setLevels drops the levels that set nothing, for a view.
func setLevels(levels []fwpolicy.Level) []fwpolicy.Level {
	out := []fwpolicy.Level{}
	for _, l := range levels {
		if l.Rules != nil {
			out = append(out, l)
		}
	}
	return out
}

// projectExecutorFor resolves the executor a project's runs go to, the way
// dispatch does, or nil when none resolves.
func projectExecutorFor(projectPath string) executor.Executor {
	registerBuiltinExecutors()
	ex, err := executor.Resolve(projectPath)
	if err != nil || ex == nil {
		return nil
	}
	return ex
}

// projectExecutorIn resolves a project's executor inside a firewall
// transaction, the way executor.Resolve does — the persisted binding, else the
// registry's default — but reading the binding through tx. Resolve's own lookup
// opens a second database handle, which would wait on tx's write lock.
func projectExecutorIn(tx *statedb.FirewallTx, projectPath string) executor.Executor {
	registerBuiltinExecutors()
	key := executor.PolicyProjectPath(projectPath)
	if abs, err := filepath.Abs(key); err == nil {
		key = filepath.Clean(abs)
	}
	id, ok, err := tx.ProjectExecutor(key)
	if err != nil {
		return nil
	}
	var ex executor.Executor
	if ok {
		ex, err = executor.Get(id)
	} else {
		ex, err = executor.DefaultRegistry.Default()
	}
	if err != nil {
		return nil
	}
	return ex
}

// ─── device level ───────────────────────────────────────────────────────────

// handleExecutorFirewall serves GET and PUT /api/executors/{id}/firewall.
func (s *Server) handleExecutorFirewall(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	ex, status, msg := deviceFirewallTarget(id)
	if ex == nil {
		jsonErr(w, msg, status)
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()

	switch r.Method {
	case http.MethodGet:
		view, err := s.deviceFirewallView(db, ex)
		if err != nil {
			jsonErr(w, "read firewall rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, view)
	case http.MethodPut, http.MethodPost:
		s.serveDeviceFirewallPut(w, r, db, ex)
	default:
		w.Header().Set("Allow", "GET, PUT")
		jsonErr(w, "method not allowed: use GET to read or PUT to set a device's firewall rules",
			http.StatusMethodNotAllowed)
	}
}

// deviceFirewallTarget resolves the executor a device rule set is for, refusing
// the two kinds that cannot carry one.
func deviceFirewallTarget(id string) (executor.Executor, int, string) {
	if id == "" {
		return nil, http.StatusBadRequest, "executor id is required"
	}
	registerBuiltinExecutors()
	ex, err := executor.Get(id)
	if err != nil || ex == nil {
		return nil, http.StatusNotFound, fmt.Sprintf("executor %q is not registered on this control plane", id)
	}
	switch ex.Kind() {
	case executor.KindVirtual:
		return nil, http.StatusConflict, fmt.Sprintf("%q is a virtual executor: its firewall is part of its "+
			"definition and is edited in its own dialog, inside the rules of the device it runs on", id)
	case executor.KindLocalProcess:
		return nil, http.StatusConflict, fmt.Sprintf("%q runs payloads in the hub's own network namespace, "+
			"where no firewall can be installed for one workload; a rule set here could only refuse every "+
			"run. Firewall a container, Kubernetes or remote executor instead", id)
	}
	return ex, 0, ""
}

func (s *Server) deviceFirewallView(db *statedb.DB, ex executor.Executor) (deviceFirewallView, error) {
	id := ex.ID()
	pos := executor.PostureOf(ex)
	view := deviceFirewallView{ExecutorID: id, Kind: ex.Kind(), Config: pos.Config, Enforced: pos.Enforceable,
		Children: []firewallChild{}}
	rec, ok, err := db.ExecutorFirewall(id)
	if err != nil {
		return view, err
	}
	view.Configured, view.Rules = ok, rec.Rules
	view.Describe = fwpolicy.Describe(&rec.Rules)
	if ok {
		view.SetAt, view.SetBy = formatSetAt(rec.SetAt), rec.SetBy
		view.Metadata = rec.Rules.MetadataNotes()
	}
	if !pos.Enforceable {
		view.Warning = pos.Reason + ". Its rules still bound its virtual executors; work placed on the " +
			"device itself is refused while a rule set applies"
		if ex.Kind() != executor.KindRemoteAgent {
			view.Warning = pos.Reason + ". Work placed on it is refused while a rule set applies"
		}
	}

	var bound *executor.FirewallRules
	if ok {
		r := rec.Rules
		bound = &r
	}
	if ex.Kind() == executor.KindRemoteAgent {
		vxs, err := db.ListVirtualExecutors()
		if err != nil {
			return view, err
		}
		for _, v := range vxs {
			if v.ParentID != id {
				continue
			}
			child := firewallChild{Kind: "virtual", ID: v.ID, Name: v.Name,
				Describe: fwpolicy.Describe(fwpolicy.VirtualLevel(v.Spec)), Fits: true}
			if v.Spec.Firewall != nil {
				child.Metadata = v.Spec.Firewall.MetadataNotes()
			}
			if reasons := virtualExceeds(bound, id, v.Spec); len(reasons) > 0 {
				child.Fits, child.Reasons = false, reasons
			}
			view.Children = append(view.Children, child)
		}
	}
	projects, err := db.ListProjectFirewalls()
	if err != nil {
		return view, err
	}
	for _, p := range projects {
		pex := projectExecutorFor(p.Subject)
		if pex == nil || executor.PostureOf(pex).DeviceID != id {
			continue
		}
		child := firewallChild{Kind: "project", ID: p.Subject, Describe: fwpolicy.Describe(&p.Rules), Fits: true,
			Metadata: p.Rules.MetadataNotes()}
		levels, _, err := governingLevels(db, pex, nil, nil)
		if err == nil {
			var gov *executor.FirewallRules
			if gov, err = fwpolicy.Chain(levels); err == nil {
				if reasons := fwpolicy.Permits(gov, p.Rules); len(reasons) > 0 {
					child.Fits, child.Reasons = false, reasons
				}
			}
		}
		if err != nil {
			child.Fits, child.Reasons = false, []string{err.Error()}
		}
		view.Children = append(view.Children, child)
	}
	return view, nil
}

// virtualExceeds reports why a virtual executor's configuration does not fit
// inside its device's rule set, or nil when it does or there is none.
func virtualExceeds(device *executor.FirewallRules, deviceID string, vs executor.VirtualSpec) []string {
	if device == nil {
		return nil
	}
	if vs.Firewall != nil {
		return fwpolicy.Permits(device, *vs.Firewall)
	}
	if fwpolicy.NetworkLevel(vs.Sandbox.Network) != nil {
		return nil // no network fits inside anything
	}
	return []string{fmt.Sprintf("device %s has a firewall, so a virtual executor on it cannot give its sandboxes "+
		"the unfiltered network %q; choose Firewalled, within the device's rules, or No network",
		deviceID, vs.Sandbox.Network)}
}

func (s *Server) serveDeviceFirewallPut(w http.ResponseWriter, r *http.Request, db *statedb.DB, ex executor.Executor) {
	var req firewallRequest
	if !decodeExecutorBody(w, r, &req) {
		return
	}
	id, actor := ex.ID(), s.auditActor(r)

	var (
		want    executor.FirewallRules
		before  statedb.FirewallRecord
		had     bool
		changes []firewallChange
	)
	if !req.Clear {
		var err error
		if want, err = req.rules(); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	err := db.UpdateFirewalls(func(tx *statedb.FirewallTx) error {
		var err error
		if before, had, err = tx.ExecutorFirewall(id); err != nil {
			return err
		}
		if req.Clear {
			// Clearing widens, so nothing saved underneath can stop fitting.
			return tx.ClearExecutorFirewall(id)
		}
		// The device's own rule set may only narrow what its configuration
		// already permits: an admin with the dashboard must not be able to
		// widen a firewall a GitOps-managed config.yaml closed on purpose.
		pos := executor.PostureOf(ex)
		if reasons := fwpolicy.Permits(pos.Config, want); len(reasons) > 0 {
			return &errFirewallExceeds{what: "this device's rule set", bound: pos.Config, reasons: reasons,
				remedy: "widen executors.*.egress_filter in the hub's configuration first, or narrow these rules"}
		}
		if err := tx.SetExecutorFirewall(id, want, actor); err != nil {
			return err
		}
		changes, err = constrainUnderDevice(tx, ex, want, actor)
		return err
	})
	if err != nil {
		writeFirewallErr(w, err)
		return
	}

	detail := map[string]any{"from": describeStored(before, had)}
	if req.Clear {
		detail["cleared"] = true
		detail["to"] = "no rule set (only the executor's configuration bounds it)"
	} else {
		detail["to"] = fwpolicy.Describe(&want)
		detail["fingerprint"] = fwpolicy.Fingerprint(want)
		detail["constrained"] = len(changes)
	}
	s.auditExecutorAction(r, auditaction.ActionExecutorFirewall.Verb(), id, detail)
	s.auditFirewallChanges(r, db, id, changes)
	s.broadcastExecutorUpdate("firewall", id)

	view, err := s.deviceFirewallView(db, ex)
	if err != nil {
		jsonErr(w, "saved, but reading it back failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	view.Constrained = changes
	jsonOK(w, view)
}

// describeStored renders a stored rule set for an audit row. An absent one is
// "no rule set": the level is left to the ones above it, which is not the same
// as unfiltered — a project with no rules of its own is still bounded by its
// executor's.
func describeStored(rec statedb.FirewallRecord, ok bool) string {
	if !ok {
		return "no rule set"
	}
	return fwpolicy.Describe(&rec.Rules)
}

// recRules returns a stored rule set, or nil when there was none.
func recRules(rec statedb.FirewallRecord, ok bool) *executor.FirewallRules {
	if !ok {
		return nil
	}
	r := rec.Rules
	return &r
}

// constrainUnderDevice narrows every virtual executor and project rule set
// saved under ex to fit inside its new rule set, inside tx, and returns what
// it changed. ex is the device: a remote device's virtual executors are its
// children, and so is every project whose runs resolve to it or to one of them.
func constrainUnderDevice(tx *statedb.FirewallTx, ex executor.Executor, rules executor.FirewallRules,
	actor string) ([]firewallChange, error) {
	id := ex.ID()
	pos := executor.PostureOf(ex)
	gov, err := fwpolicy.Chain([]fwpolicy.Level{
		{Name: "executor " + id + "'s configuration", Rules: pos.Config},
		{Name: "device " + id + "'s firewall", Rules: &rules},
	})
	if err != nil {
		return nil, err
	}
	var changes []firewallChange
	override := map[string]executor.VirtualSpec{}
	if ex.Kind() == executor.KindRemoteAgent {
		vxs, err := tx.VirtualExecutorsOf(id)
		if err != nil {
			return nil, err
		}
		for _, v := range vxs {
			spec, notes := constrainVirtualSpec(gov, v.Spec)
			if len(notes) == 0 {
				continue
			}
			if err := tx.SetVirtualExecutorSpec(v.ID, spec, actor); err != nil {
				return nil, fmt.Errorf("narrow virtual executor %s: %w", v.ID, err)
			}
			override[v.ID] = spec
			changes = append(changes, firewallChange{Kind: "virtual", Subject: v.ID, Name: v.Name,
				From: v.Spec.Describe(), To: spec.Describe(), Notes: notes, executorID: id})
		}
	}
	more, err := constrainProjects(tx, func(_ string, pex executor.Executor) bool {
		return executor.PostureOf(pex).DeviceID == id
	}, &rules, override, actor)
	if err != nil {
		return nil, err
	}
	return append(changes, more...), nil
}

// constrainProjects narrows every stored project rule set whose runs resolve
// to an executor match accepts, against that executor's levels as they are
// about to be.
func constrainProjects(tx *statedb.FirewallTx, match func(path string, ex executor.Executor) bool,
	deviceRules *executor.FirewallRules, override map[string]executor.VirtualSpec,
	actor string) ([]firewallChange, error) {
	recs, err := tx.ListProjectFirewalls()
	if err != nil {
		return nil, err
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Subject < recs[j].Subject })
	var changes []firewallChange
	for _, rec := range recs {
		pex := projectExecutorIn(tx, rec.Subject)
		if pex == nil || !match(rec.Subject, pex) {
			continue
		}
		levels, _, err := governingLevels(tx, pex, deviceRules, override)
		if err != nil {
			return nil, err
		}
		gov, err := fwpolicy.Chain(levels)
		if err != nil {
			return nil, err
		}
		narrowed, notes := fwpolicy.Constrain(gov, rec.Rules)
		if len(notes) == 0 {
			continue
		}
		if err := tx.SetProjectFirewall(rec.Subject, narrowed, actor); err != nil {
			return nil, fmt.Errorf("narrow the firewall of project %s: %w", rec.Subject, err)
		}
		changes = append(changes, firewallChange{Kind: "project", Subject: rec.Subject,
			From: fwpolicy.Describe(&rec.Rules), To: fwpolicy.Describe(&narrowed), Notes: notes,
			executorID: pex.ID()})
	}
	return changes, nil
}

// constrainVirtualSpec narrows a virtual executor's configuration to fit inside
// its device's rule set, saying what it took away.
//
// A firewall is narrowed by fwpolicy.Constrain. No network fits inside
// anything. An unfiltered network — the engine's bridge or a named one — cannot
// be bounded at all, so it is replaced by a firewalled bridge carrying the
// device's own rules: the most a sandbox on that device may now reach.
func constrainVirtualSpec(device *executor.FirewallRules, vs executor.VirtualSpec) (executor.VirtualSpec, []string) {
	if device == nil {
		return vs, nil
	}
	out := vs
	var notes []string
	switch {
	case vs.Firewall != nil:
		fw, n := fwpolicy.Constrain(device, *vs.Firewall)
		if len(n) == 0 {
			return vs, nil
		}
		out.Firewall, notes = &fw, n
	case fwpolicy.NetworkLevel(vs.Sandbox.Network) != nil:
		return vs, nil
	default:
		fw := *device
		out.Firewall = &fw
		notes = []string{fmt.Sprintf("its unfiltered network (%s) was replaced by a firewalled bridge carrying "+
			"the device's rules", vs.Sandbox.Network)}
		out.Sandbox.Network = ""
	}
	n, err := out.Normalize()
	if err != nil {
		// Unreachable for a configuration that normalized before; if a future
		// field makes it reachable, no network is the answer that cannot widen.
		out.Firewall = &executor.FirewallRules{}
		out.Sandbox.Network = ""
		if n, err = out.Normalize(); err != nil {
			return vs, append(notes, "it could not be narrowed: "+err.Error())
		}
		notes = append(notes, "its network was removed: the narrowed configuration was not valid")
	}
	return n, notes
}

// auditFirewallChanges records each rule set a save narrowed, after the save
// committed: a virtual executor as executor.virtual "constrain", a project as
// project.firewall "constrain".
func (s *Server) auditFirewallChanges(r *http.Request, db *statedb.DB, cause string, changes []firewallChange) {
	for _, c := range changes {
		reason := cause + "'s firewall was tightened: " + strings.Join(c.Notes, "; ")
		switch c.Kind {
		case "virtual":
			s.auditExecutorAction(r, auditaction.ActionExecutorVirtual.Verb(), c.Subject, map[string]any{
				"action":    "constrain",
				"parent_id": c.executorID,
				"name":      c.Name,
				"from":      c.From,
				"to":        c.To,
				"reason":    reason,
			})
		case "project":
			statedb.AuditProjectFirewall(db, statedb.ProjectFirewallAuditInput{
				Action:      "constrain",
				ProjectPath: c.Subject,
				ExecutorID:  c.executorID,
				Actor:       s.auditActor(r),
				Detail:      map[string]any{"from": c.From, "to": c.To, "reason": reason},
			})
		}
	}
	if len(changes) > 0 {
		s.broadcastAuditAppend(auditaction.ActionProjectFirewall.String())
	}
}

// ─── project level ──────────────────────────────────────────────────────────

// handleProjectFirewall serves GET and PUT /api/firewall?project_idx=N.
func (s *Server) handleProjectFirewall(w http.ResponseWriter, r *http.Request) {
	workDir := strings.TrimSpace(s.resolveWorkDir(r))
	if workDir == "" {
		jsonErr(w, "no project selected", http.StatusBadRequest)
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()

	switch r.Method {
	case http.MethodGet:
		// The route admits the project's readers so the card can ask quietly;
		// the rules, and the device rules governing them, are only for those
		// who may change them.
		if !s.permissionsFor(r, s.projectScope(r)).Allows(authz.PermConfigWrite) {
			jsonOK(w, map[string]any{"project": workDir, "visible": false})
			return
		}
		view, err := s.projectFirewallView(db, workDir)
		if err != nil {
			jsonErr(w, "read firewall rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, view)
	case http.MethodPut, http.MethodPost:
		s.serveProjectFirewallPut(w, r, db, workDir)
	default:
		w.Header().Set("Allow", "GET, PUT")
		jsonErr(w, "method not allowed: use GET to read or PUT to set this project's firewall rules",
			http.StatusMethodNotAllowed)
	}
}

func (s *Server) projectFirewallView(db *statedb.DB, workDir string) (projectFirewallView, error) {
	policy := executor.PolicyProjectPath(workDir)
	view := projectFirewallView{Project: workDir, Visible: true, Levels: []fwpolicy.Level{}, Fits: true}
	if policy != workDir {
		view.PolicyProject = policy
	}
	rec, ok, err := db.ProjectFirewall(policy)
	if err != nil {
		return view, err
	}
	view.Configured, view.Rules = ok, rec.Rules
	view.Describe = fwpolicy.Describe(&rec.Rules)
	if ok {
		view.SetAt, view.SetBy = formatSetAt(rec.SetAt), rec.SetBy
		view.Metadata = rec.Rules.MetadataNotes()
	}

	ex := projectExecutorFor(policy)
	if ex == nil {
		view.Warning = "no executor resolves for this project, so its rules are checked when it is next dispatched"
		return view, nil
	}
	view.ExecutorID, view.ExecutorKind = ex.ID(), ex.Kind()
	levels, pos, err := governingLevels(db, ex, nil, nil)
	if err != nil {
		return view, err
	}
	view.Levels = setLevels(levels)
	view.Enforced = pos.Enforceable
	gov, err := fwpolicy.Chain(levels)
	if err != nil {
		view.Fits, view.Reasons = false, []string{err.Error()}
		view.Warning = "the levels above this project do not nest, so its runs are refused until an admin " +
			"fixes them: " + err.Error()
		return view, nil
	}
	view.Governing = gov
	if ok {
		if reasons := fwpolicy.Permits(gov, rec.Rules); len(reasons) > 0 {
			view.Fits, view.Reasons = false, reasons
		}
	}
	if !pos.Enforceable && (ok || len(view.Levels) > 0) {
		view.Warning = pos.Reason + ". Runs of this project are refused while rules apply to them"
	}
	return view, nil
}

func (s *Server) serveProjectFirewallPut(w http.ResponseWriter, r *http.Request, db *statedb.DB, workDir string) {
	var req firewallRequest
	if !decodeExecutorBody(w, r, &req) {
		return
	}
	policy := executor.PolicyProjectPath(workDir)
	actor := s.auditActor(r)
	var (
		want   executor.FirewallRules
		before statedb.FirewallRecord
		had    bool
		exID   string
	)
	if !req.Clear {
		var err error
		if want, err = req.rules(); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	ex := projectExecutorFor(policy)
	if ex != nil {
		exID = ex.ID()
	}
	err := db.UpdateFirewalls(func(tx *statedb.FirewallTx) error {
		var err error
		if before, had, err = tx.ProjectFirewall(policy); err != nil {
			return err
		}
		if req.Clear {
			return tx.ClearProjectFirewall(policy)
		}
		// The containment rule, at the earliest moment it can be applied —
		// against the executor this project's runs go to now. Dispatch and the
		// driver check again against wherever the run actually lands.
		if ex != nil {
			levels, _, err := governingLevels(tx, ex, nil, nil)
			if err != nil {
				return err
			}
			gov, err := fwpolicy.Chain(levels)
			if err != nil {
				return err
			}
			if reasons := fwpolicy.Permits(gov, want); len(reasons) > 0 {
				return &errFirewallExceeds{what: "this project's rule set", bound: gov, reasons: reasons,
					remedy: "a project's firewall can only narrow its executor's: remove what is listed, or ask " +
						"an admin to widen the device's or the virtual executor's rules"}
			}
		}
		return tx.SetProjectFirewall(policy, want, actor)
	})
	if err != nil {
		writeFirewallErr(w, err)
		return
	}

	in := statedb.ProjectFirewallAuditInput{Action: "set", ProjectPath: policy, ExecutorID: exID, Actor: actor,
		Detail: map[string]any{"from": describeStored(before, had)}}
	if req.Clear {
		in.Action = "clear"
		in.Detail["cleared"] = true
		in.Detail["to"] = "no rule set (its executor's rules apply)"
	} else {
		in.Detail["to"] = fwpolicy.Describe(&want)
		in.Detail["fingerprint"] = fwpolicy.Fingerprint(want)
	}
	statedb.AuditProjectFirewall(db, in)
	s.broadcastAuditAppend(auditaction.ActionProjectFirewall.String())

	view, err := s.projectFirewallView(db, workDir)
	if err != nil {
		jsonErr(w, "saved, but reading it back failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, view)
}

// constrainProjectToExecutor narrows a project's rule set to fit the executor
// its runs now go to, after an admin rebinds it: a project's firewall always
// fits its executor, whichever way the executor came to change. Best-effort —
// the binding has already happened, and a rule set left too wide is refused at
// dispatch, which says why.
func (s *Server) constrainProjectToExecutor(r *http.Request, db *statedb.DB, projectPath string) {
	key := executor.PolicyProjectPath(projectPath)
	if abs, err := filepath.Abs(key); err == nil {
		key = filepath.Clean(abs)
	}
	var changes []firewallChange
	err := db.UpdateFirewalls(func(tx *statedb.FirewallTx) error {
		var err error
		changes, err = constrainProjects(tx, func(path string, _ executor.Executor) bool {
			p := path
			if abs, err := filepath.Abs(p); err == nil {
				p = filepath.Clean(abs)
			}
			return p == key
		}, nil, nil, s.auditActor(r))
		return err
	})
	if err != nil {
		s.log().Warn(logger.EventStateWrite, 0, "narrow a rebound project's firewall rules",
			map[string]interface{}{"project": projectPath, "error": err.Error()})
		return
	}
	for i := range changes {
		changes[i].Notes = append([]string{"the project was moved to executor " + changes[i].executorID}, changes[i].Notes...)
	}
	s.auditFirewallChanges(r, db, "project "+projectPath, changes)
}

// formatSetAt renders provenance the way the other executor panels do, and a
// zero time as absent rather than as year 1.
func formatSetAt(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
