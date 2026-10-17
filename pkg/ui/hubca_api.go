package ui

// hubca_api.go is Settings → Hub health's certificate authority section (Task
// 20438): where a rotation of the hub's own CA stands, and its steps, for an
// administrator without a shell on the hub host. The steps are pkg/hubca's,
// the same ones `cloop hub ca rotate` takes; this file reads the hub's
// configuration for the names a stage constrains the new CA to, names the
// caller on the audit trail, and tells every member to re-read its CAs.
//
// GET  /api/hub/ca         where the rotation stands
// POST /api/hub/ca/rotate  {"step": "stage" | "activate" | "retire_previous" |
//                           "abort" | "now", ...}
//
// A step that destroys a key or breaks running runs — retire_previous,
// abort, now, and activate with force — is taken only when the body repeats
// its name in "confirm", which the dashboard sends from a dialog that says
// what will happen. config.write at global scope, as Hub health itself.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hubdoctor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// hubCARoutes are the rotation's routes.
func (s *Server) hubCARoutes() []routeSpec {
	return []routeSpec{
		{Pattern: "GET /api/hub/ca", Handler: s.handleHubCAStatus, Perm: authz.PermConfigWrite, Scope: scopeGlobal},
		{Pattern: "POST /api/hub/ca/rotate", Handler: s.handleHubCARotate, Perm: authz.PermConfigWrite, Scope: scopeGlobal},
	}
}

// hubCAStatusResponse is GET /api/hub/ca.
type hubCAStatusResponse struct {
	hubca.Status
	// Configured reports that a monitor here runs under tls: auto: a hub
	// whose monitors serve an operator's certificate has a CA only if one
	// ran under auto before.
	Configured bool `json:"configured"`
	// LongestSessionMinutes is the longest session a monitor grants, which a
	// stage that lasts longer is warned about.
	LongestSessionMinutes int `json:"longest_session_minutes"`
	// StepAgeSeconds is how long ago the rotation under way took its last
	// step; 0 when none is.
	StepAgeSeconds int64 `json:"step_age_seconds"`
	// ConfigNames are the names a stage would constrain the new CA to, beside
	// those every stored leaf carries.
	ConfigNames []string `json:"config_names"`
	// History is the most recent rotations.
	History []hubCARotationJSON `json:"history"`
}

// hubCARotationJSON is a rotation journal row for the dashboard.
type hubCARotationJSON struct {
	ID          string    `json:"id"`
	State       string    `json:"state"`
	FromSerial  string    `json:"from"`
	ToSerial    string    `json:"to"`
	Names       []string  `json:"names,omitempty"`
	Emergency   bool      `json:"emergency,omitempty"`
	StagedAt    time.Time `json:"staged_at"`
	StagedBy    string    `json:"staged_by,omitempty"`
	ActivatedAt time.Time `json:"activated_at,omitzero"`
	ActivatedBy string    `json:"activated_by,omitempty"`
	EndedAt     time.Time `json:"ended_at,omitzero"`
	EndedBy     string    `json:"ended_by,omitempty"`
	Forced      []string  `json:"forced,omitempty"`
	CutRuns     []string  `json:"cut_runs,omitempty"`
	Detail      string    `json:"detail,omitempty"`
}

func rotationJSON(r statedb.HubCARotationRow) hubCARotationJSON {
	return hubCARotationJSON{ID: r.ID, State: r.State, FromSerial: r.FromSerial, ToSerial: r.ToSerial,
		Names: r.Names, Emergency: r.Emergency, StagedAt: r.StagedAt, StagedBy: r.StagedBy,
		ActivatedAt: r.ActivatedAt, ActivatedBy: r.ActivatedBy, EndedAt: r.EndedAt, EndedBy: r.EndedBy,
		Forced: r.Forced, CutRuns: r.CutRuns, Detail: r.Detail}
}

// hubCAEnv is what a step works against in this process: the control plane's
// CA store, and its sealing keys when a step needs them — this process's own
// when a monitor here issues from the CA, opened for the call otherwise.
func (s *Server) hubCAEnv(actor string, write bool) (hubca.Env, func(), error) {
	var (
		db      *statedb.DB
		store   *hubca.Store
		sealer  hubca.Sealer
		closeFn = func() {}
	)
	if c := processHubCA(); c != nil {
		db, store, sealer = c.db, c.store, c.keyring
	} else {
		var err error
		if db, err = s.controlPlaneDB(); err != nil {
			return hubca.Env{}, nil, err
		}
		closeFn = func() { _ = db.Close() }
		if store, err = hubca.NewStore(db); err != nil {
			closeFn()
			return hubca.Env{}, nil, err
		}
		if write {
			ks, err := secretstore.New(db)
			if err != nil {
				closeFn()
				return hubca.Env{}, nil, err
			}
			kr, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringActor("hub"))
			if err != nil {
				closeFn()
				if errors.Is(err, secretbroker.ErrNoKey) {
					return hubca.Env{}, nil, hubca.ErrNoKey
				}
				return hubca.Env{}, nil, fmt.Errorf("open the sealing keys: %w", err)
			}
			sealer = kr
		}
	}
	opts := hubCAOptions(db)
	opts.Actor = actor
	opts.Rotation = func(e hubca.RotationEvent) { auditRotationStep(db, actor, e, "dashboard") }
	return hubca.Env{Store: store, Sealer: sealer, Options: opts, Alive: memberAlive()}, closeFn, nil
}

// memberAlive judges a hub member the way this process does: by its cluster
// node's view when it has one, and by the member table's heartbeats otherwise.
func memberAlive() func(statedb.HubMemberRow) bool {
	n := currentCluster()
	if n == nil {
		return func(r statedb.HubMemberRow) bool { return hubcluster.RowAlive(r, time.Now()) }
	}
	live := map[string]bool{}
	for _, m := range n.LiveMembers() {
		live[m.ID] = true
	}
	return func(r statedb.HubMemberRow) bool { return live[r.InstanceID] }
}

// GET /api/hub/ca
func (s *Server) handleHubCAStatus(w http.ResponseWriter, r *http.Request) {
	env, done, err := s.hubCAEnv(s.auditActor(r), false)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer done()
	out, err := s.hubCAStatus(env)
	if err != nil {
		jsonErr(w, "where the hub CA's rotation stands could not be read: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, out)
}

func (s *Server) hubCAStatus(env hubca.Env) (hubCAStatusResponse, error) {
	st, err := hubca.ReadStatus(env)
	if err != nil {
		return hubCAStatusResponse{}, err
	}
	out := hubCAStatusResponse{Status: st}
	cfg, _ := controlPlaneConfig()
	if cfg != nil {
		out.Configured = (cfg.Executors.GitProxy.Enabled && cfg.Executors.GitProxy.AutoTLS()) ||
			(cfg.Executors.KubeGuard.Enabled && cfg.Executors.KubeGuard.AutoTLS())
		out.LongestSessionMinutes = int(hubdoctor.LongestMonitorSession(cfg) / time.Minute)
	}
	out.ConfigNames = s.hubCANames(cfg)
	if r := st.Rotation; r != nil {
		last := r.StagedAt
		if !r.ActivatedAt.IsZero() {
			last = r.ActivatedAt
		}
		out.StepAgeSeconds = int64(time.Since(last) / time.Second)
	}
	if out.Members == nil {
		out.Members = []hubca.MemberStatus{}
	}
	if out.Leaves == nil {
		out.Leaves = []hubca.LeafStatus{}
	}
	if hist, err := env.Store.Rotations(10); err == nil {
		for _, h := range hist {
			out.History = append(out.History, rotationJSON(h))
		}
	}
	if out.History == nil {
		out.History = []hubCARotationJSON{}
	}
	return out, nil
}

// hubCANames are the names a stage constrains the new CA to from here: what
// the configuration says the monitors are reached at, and what the running
// monitors of this process are — an advertise URL left empty is the address
// the monitor bound, which only the running process knows.
func (s *Server) hubCANames(cfg *config.Config) []string {
	names := hubdoctor.HubCAConfigNames(cfg)
	if gp := activeGitProxy(); gp != nil && gp.certs != nil {
		names = append(names, gp.certs.srv.Want()...)
	}
	if kg := activeKubeGuard(); kg != nil && kg.certs != nil {
		names = append(names, kg.certs.srv.Want()...)
	}
	out, err := hubca.NormalizeSANs(names)
	if err != nil {
		return names
	}
	return out
}

// hubCARotateRequest is POST /api/hub/ca/rotate.
type hubCARotateRequest struct {
	Step string `json:"step"`
	// Force activates past runs dispatched before the stage, naming them.
	Force bool `json:"force,omitempty"`
	// Names are names the new CA's constraints permit beside the configured
	// ones (stage, now).
	Names []string `json:"names,omitempty"`
	// NoNameConstraints mints the new CA unconstrained (stage, now).
	NoNameConstraints bool `json:"no_name_constraints,omitempty"`
	// Confirm repeats Step for a step that destroys a key or breaks runs.
	Confirm string `json:"confirm,omitempty"`
	// Reason is why, for an abort.
	Reason string `json:"reason,omitempty"`
}

const (
	hubCAStepStage    = "stage"
	hubCAStepActivate = "activate"
	hubCAStepRetire   = "retire_previous"
	hubCAStepAbort    = "abort"
	hubCAStepNow      = "now"
)

// POST /api/hub/ca/rotate
func (s *Server) handleHubCARotate(w http.ResponseWriter, r *http.Request) {
	var req hubCARotateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	step := strings.TrimSpace(req.Step)
	switch step {
	case hubCAStepStage, hubCAStepActivate, hubCAStepRetire, hubCAStepAbort, hubCAStepNow:
	default:
		jsonErr(w, "step must be one of stage, activate, retire_previous, abort and now", http.StatusBadRequest)
		return
	}
	if len(req.Names) > hubca.MaxConstraintNames {
		jsonErr(w, fmt.Sprintf("at most %d names", hubca.MaxConstraintNames), http.StatusBadRequest)
		return
	}
	if _, err := hubca.NormalizeSANs(req.Names); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	destructive := step == hubCAStepRetire || step == hubCAStepAbort || step == hubCAStepNow ||
		(step == hubCAStepActivate && req.Force)
	if destructive && req.Confirm != step {
		jsonErr(w, "this step destroys a key or breaks running runs: repeat its name in \"confirm\" to take it",
			http.StatusPreconditionRequired)
		return
	}
	actor := s.auditActor(r)
	// A retirement may reissue the leaf of a monitor no member serves any
	// more, so it opens the sealing keys too.
	env, done, err := s.hubCAEnv(actor, step == hubCAStepStage || step == hubCAStepNow || step == hubCAStepRetire)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer done()
	cfg, _ := controlPlaneConfig()
	names := append(s.hubCANames(cfg), req.Names...)

	var result any
	switch step {
	case hubCAStepStage:
		result, err = hubca.Stage(env, hubca.StageRequest{Names: names, NoNameConstraints: req.NoNameConstraints})
	case hubCAStepActivate:
		result, err = hubca.Activate(env, hubca.ActivateRequest{Force: req.Force})
	case hubCAStepRetire:
		result, err = hubca.RetirePrevious(env)
	case hubCAStepAbort:
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "aborted from the dashboard"
		}
		result, err = hubca.Abort(env, reason)
	case hubCAStepNow:
		result, err = hubca.Emergency(env, hubca.StageRequest{Names: names, NoNameConstraints: req.NoNameConstraints})
	}
	if err != nil {
		writeHubCAStepError(w, err)
		return
	}
	// Every member re-reads its CAs now, this one too.
	publishHubCAStep(step)
	kickHubCA()
	status, serr := s.hubCAStatus(env)
	resp := map[string]any{"step": step, "result": result}
	if serr == nil {
		resp["status"] = status
	}
	jsonOK(w, resp)
}

// writeHubCAStepError answers a refused step with what refused it: the runs
// an activation would break, the members a step waits for.
func writeHubCAStepError(w http.ResponseWriter, err error) {
	var re *hubca.RunsError
	var me *hubca.MembersError
	switch {
	case errors.As(err, &re):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "runs": re.Runs})
	case errors.As(err, &me):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "members": me.Members, "old_members": me.Old})
	case errors.Is(err, hubca.ErrWrongPhase), errors.Is(err, hubca.ErrNoCA), errors.Is(err, hubca.ErrLeavesBehind),
		errors.Is(err, statedb.ErrHubCARotationConflict):
		jsonErr(w, err.Error(), http.StatusConflict)
	case errors.Is(err, hubca.ErrNoKey):
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
	default:
		jsonErr(w, "the step failed: "+err.Error(), http.StatusInternalServerError)
	}
}
