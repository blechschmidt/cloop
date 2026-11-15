package ui

// projectmove_api.go serves a project move's preflight (Task 20493):
//
//	GET /api/projects/{idx}/move/preflight?target=<binding>[&abandon_source=1]
//
// It answers what moving the project from the executor it is bound to onto
// target would lose or break — runs in flight, work in the source's trees that
// no remote holds, files no database holds, whether the source can be reached,
// whether the target can run the project, and which records are keyed by the
// project's path — as pkg/projectmove's report. Nothing changes: the decision
// functions this file hands the preflight are the read-only halves of the
// dispatch path (harnessPreflight, governingLevels, resolveForwardedBindings'
// rules, workspaceGrantFor), never the halves that lease, attach, journal or
// rewrite.
//
// The route is project.write — a maintainer's — because a move reshapes where
// the project's code runs and which credentials follow it; and the caller must
// be on the target's access list, as for binding (admitExecutorAudience), so a
// preflight cannot be used to look into an executor or pool the caller may not
// use.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// handleProjectMovePreflight serves GET /api/projects/{idx}/move/preflight.
func (s *Server) handleProjectMovePreflight(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return
	}
	if entry.IsFeature() {
		jsonErr(w, fmt.Sprintf("feature %s runs where its project is bound and moves with it: "+
			"run the preflight on %s", entry.Feature, entry.Parent), http.StatusConflict)
		return
	}
	q := r.URL.Query()
	target, err := projectmove.ParseTarget(q.Get("target"))
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	abandon := false
	if raw := strings.TrimSpace(q.Get("abandon_source")); raw != "" {
		if abandon, err = strconv.ParseBool(raw); err != nil {
			jsonErr(w, "abandon_source must be true or false", http.StatusBadRequest)
			return
		}
	}
	// quiesce=1 asks what a move would find (Task 20494): a move stops the
	// project's runs itself, so a run in progress is not a blocker then.
	quiesce := false
	if raw := strings.TrimSpace(q.Get("quiesce")); raw != "" {
		if quiesce, err = strconv.ParseBool(raw); err != nil {
			jsonErr(w, "quiesce must be true or false", http.StatusBadRequest)
			return
		}
	}
	// The access list, as for a bind: a preflight describes the target —
	// where it keeps working copies, whether it answers, what it can run — and
	// that is not for someone who may not use it.
	switch {
	case target.ExecutorID != "":
		if !s.admitExecutorAudience(w, r, target.ExecutorID) {
			return
		}
	case target.PoolID != "":
		if !s.admitPoolAudience(w, r, target.PoolID) {
			return
		}
	}
	registerBuiltinExecutors()
	env := &moveEnv{s: s, r: r, now: time.Now()}
	defer env.close()
	rep, err := projectmove.Preflight(r.Context(), env, projectmove.Project{Name: entry.Name, Path: entry.Path},
		target.Binding, projectmove.Options{AbandonSource: abandon, Quiesce: quiesce})
	switch {
	case errors.Is(err, projectmove.ErrInvalidTarget), errors.Is(err, projectmove.ErrInvalidProject):
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, projectmove.ErrFeature):
		jsonErr(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		jsonErr(w, "cannot plan a move of "+entry.Name+" right now: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	jsonOK(w, rep)
}

// admitPoolAudience is admitExecutorAudience for an executor pool: it writes
// the refusal and returns false when the caller is not on the pool's access
// list. A pool that does not exist has no list; the preflight reports it.
func (s *Server) admitPoolAudience(w http.ResponseWriter, r *http.Request, poolID string) bool {
	store, err := s.poolStore()
	if err != nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"error": "cannot determine who may use executor pool " + poolID + " right now",
			"code":  "executor_pool_audience_unavailable", "remediation": err.Error(), "pool_id": poolID})
		return false
	}
	entries, err := store.Audience(poolID)
	if err != nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"error": "cannot determine who may use executor pool " + poolID + " right now",
			"code":  "executor_pool_audience_unavailable", "remediation": err.Error(), "pool_id": poolID})
		return false
	}
	if members := audienceMembers(entries); len(members) > 0 && !authz.Admits(members, s.callerSubject(r)) {
		writeJSONStatus(w, http.StatusForbidden, map[string]any{
			"error": fmt.Sprintf("executor pool %s is restricted and your account is not on its access list", poolID),
			"code":  "executor_pool_audience_denied", "pool_id": poolID})
		return false
	}
	return true
}

// moveEnv is projectmove.Env over this hub, for one request's caller.
type moveEnv struct {
	s   *Server
	r   *http.Request
	now time.Time

	// The control plane's database, opened on first use and closed by close.
	db     *statedb.DB
	dbErr  error
	opened bool
}

var _ projectmove.Env = (*moveEnv)(nil)

func (e *moveEnv) cp() (*statedb.DB, error) {
	if !e.opened {
		e.opened = true
		e.db, e.dbErr = e.s.controlPlaneDB()
	}
	return e.db, e.dbErr
}

func (e *moveEnv) close() {
	if e.db != nil {
		_ = e.db.Close()
	}
}

func (e *moveEnv) Executor(id string) (executor.Executor, error) { return executor.Get(id) }

func (e *moveEnv) DefaultExecutor() (executor.Executor, error) {
	return executor.DefaultRegistry.Default()
}

func (e *moveEnv) HostExecutionAllowed() bool { return executor.HostExecutionAllowed() }

// Binding reads the stored binding, failing on a read error rather than
// reading it as "unbound": a preflight that guessed the source would describe
// the wrong one.
func (e *moveEnv) Binding(_ context.Context, p projectmove.Project) (string, error) {
	db, err := e.cp()
	if err != nil {
		return "", err
	}
	id, ok, err := db.ProjectExecutor(p.Path)
	if err != nil {
		return "", err
	}
	if ok {
		return strings.TrimSpace(id), nil
	}
	// A binding applied at runtime without a stored row.
	if id, ok := executor.DefaultRegistry.Binding(p.Path); ok {
		return strings.TrimSpace(id), nil
	}
	return "", nil
}

// Reachable asks the executor, unless another member of this hub's cluster
// holds its device's connection: then this member has no session for it and
// its own health check would fail on a device that is fine.
func (e *moveEnv) Reachable(ctx context.Context, ex executor.Executor) error {
	if _, held := e.s.agentHeldByPeer(ex); held {
		return nil
	}
	return ex.HealthCheck(ctx)
}

func (e *moveEnv) DeviceRoot(_ context.Context, deviceID string) string {
	db, err := e.cp()
	if err != nil {
		return ""
	}
	row, err := db.GetExecutor(deviceID)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(row.Inventory.WorkDirRoot)
}

func (e *moveEnv) Features(_ context.Context, p projectmove.Project) ([]projectmove.Feature, error) {
	infos, err := feature.List(p.Path)
	if err != nil {
		return nil, err
	}
	out := make([]projectmove.Feature, 0, len(infos))
	for _, in := range infos {
		slug := ""
		if in.Meta != nil {
			slug = in.Meta.Slug
		}
		if slug == "" {
			_, slug, _ = feature.ParentOf(in.Path)
		}
		out = append(out, projectmove.Feature{Slug: slug, Path: in.Path})
	}
	return out, nil
}

// Runs reads what the hub knows about the runs of the project or feature at
// path, the way the run and stop handlers decide it.
func (e *moveEnv) Runs(_ context.Context, path string) projectmove.RunFacts {
	var f projectmove.RunFacts
	if e.s.projectExecuting(path) {
		f.Executing = true
		f.ExecutingDetail = e.s.executingDetail(path)
	}
	if store, err := e.s.poolStore(); err != nil {
		f.Error = "the executor pools' queue could not be read: " + err.Error()
		return f
	} else if row, ok, err := store.DB().OpenPoolQueueEntry(path); err != nil {
		f.Error = "the executor pools' queue could not be read: " + err.Error()
		return f
	} else if ok {
		f.Queued = &projectmove.QueuedRun{PoolID: row.PoolID, State: row.State, Since: row.CreatedAt}
	}
	ps, err := state.LoadLite(path)
	switch {
	case errors.Is(err, statedb.ErrProjectNotFound):
	case err != nil:
		f.Error = err.Error()
	case ps != nil:
		f.Status, f.Pause, f.Plan = ps.Status, ps.PauseReason, ps.Plan
	}
	return f
}

// executingDetail says what makes projectExecuting answer yes, from the cheap
// sources only: it has already asked the driver.
func (s *Server) executingDetail(path string) string {
	switch {
	case multiui.IsCloopRunningInDir(path):
		return "a cloop run process on the hub"
	}
	if run, ok := s.trackedRun(path); ok && run.ex != nil {
		return "a workload on executor " + run.ex.ID()
	}
	return "a run another member of this hub's cluster owns, or one this hub is still streaming"
}

func (e *moveEnv) SourceTree(ctx context.Context, p projectmove.Project, features []projectmove.Feature,
	src projectmove.Endpoint) (projectmove.Tree, error) {
	switch src.Workspace {
	case projectmove.WorkspaceHubTree:
		return projectmove.ReadHubTree(ctx, p, features)
	case projectmove.WorkspaceDevice:
		// Asked of the device's agent (Task 20495), when this member holds
		// its connection.
		return e.s.inspectDevice(ctx, p, src)
	}
	// A pool's volume is read only by a runner attached to it, which the
	// move asks the pool for when it captures.
	return projectmove.Tree{}, projectmove.ErrUnseen
}

func (e *moveEnv) HubDirEntries(_ context.Context, p projectmove.Project) ([]string, error) {
	return projectmove.HubDirEntries(p.Path)
}

// Pool answers what bindProjectToPool checks before a bind.
func (e *moveEnv) Pool(_ context.Context, poolID string, p projectmove.Project) (projectmove.PoolFacts, error) {
	store, err := e.s.poolStore()
	if err != nil {
		return projectmove.PoolFacts{}, err
	}
	pool, err := store.Get(poolID)
	if errors.Is(err, statedb.ErrExecutorPoolNotFound) {
		return projectmove.PoolFacts{}, nil
	}
	if err != nil {
		return projectmove.PoolFacts{}, err
	}
	f := projectmove.PoolFacts{Found: true, Name: pool.Name, Revoked: pool.Revoked(), OwnerMayRead: true}
	if entries, err := store.Audience(pool.ID); err != nil {
		f.AudienceErr = err.Error()
	} else {
		members := audienceMembers(entries)
		f.Admitted = len(members) == 0 || authz.Admits(members, e.s.callerSubject(e.r))
	}
	if pool.Owner != "" {
		ok, err := e.s.identityMayReadProject(pool.Owner, p.Path)
		f.OwnerMayRead = err == nil && ok
	}
	if req, err := poolRunRequirements(p.Path); err != nil {
		f.Fits = "the project's .cloop/sandbox.yaml could not be read (" + err.Error() + "), so whether its runners fit cannot be judged"
	} else if rej, rejected := pool.Admits(req); rejected {
		f.Fits = fmt.Sprintf("its runners fail the %s constraint: %s", rej.Constraint, rej.Detail)
	}
	f.Template = pool.Template().Executor
	f.Volumes = e.s.poolVolumes(pool.ID)
	f.Cordoned = pool.Cordoned()
	if trouble, ok := e.s.poolControllerTrouble(store, pool.ID); ok {
		f.Trouble = trouble
	}
	policy := policyProjectPath(p.Path)
	f.Tenant = executorpool.ProjectTenant(pool.ID, policy, e.s.projectOwnerKey(policy))
	return f, nil
}

func (e *moveEnv) Audience(_ context.Context, executorID string) (bool, error) {
	return e.s.callerMayUseExecutor(e.r, executorID)
}

// HarnessCredential is the harness-credential card's report, for the target
// rather than the current binding.
func (e *moveEnv) HarnessCredential(_ context.Context, p projectmove.Project, target executor.Executor) (projectmove.HarnessFacts, error) {
	who := harnessWho{}
	if executor.IsolatesFromHost(target) || e.s.copilotPerPerson(p.Path) {
		who = e.s.harnessWhoFor(e.r)
	}
	rep := harnessPreflight(p.Path, target, who, "", true)
	h := projectmove.HarnessFacts{Applies: rep.Applies, State: rep.State, Provider: rep.Provider}
	if rep.Applies && rep.State != "ok" {
		h.Detail, h.Remedy = rep.explain()
	}
	for _, ref := range rep.Satisfied {
		if !ref.Foreign {
			h.Sources = append(h.Sources, fmt.Sprintf("%s (grant %s)", ref.SecretName, ref.GrantID))
		}
	}
	if rep.HubRelay {
		h.Sources = append(h.Sources, "the hub's model relay")
	}
	return h, nil
}

// fileKinds are the grants delivered as files: a credential helper and token
// file, a kubeconfig, a registry auth file, a proxy configuration.
var fileKinds = map[secretbroker.Kind]bool{
	secretbroker.KindGitHubPAT: true, secretbroker.KindGitHubApp: true, secretbroker.KindKubeconfig: true,
	secretbroker.KindRegistry: true, secretbroker.KindEgressProxy: true,
}

// Grants lists the project's active grants and matches each against the
// requester a run on either end would lease as. Read from the store, not
// through the broker: listing needs no sealing key, and nothing is leased.
func (e *moveEnv) Grants(_ context.Context, p projectmove.Project, source, target executor.Executor) ([]projectmove.GrantFacts, error) {
	db, err := e.cp()
	if err != nil {
		return nil, err
	}
	store, err := secretstore.New(db)
	if err != nil {
		return nil, err
	}
	grants, err := store.ListGrants()
	if err != nil {
		return nil, err
	}
	secrets, err := store.ListSecrets()
	if err != nil {
		return nil, err
	}
	byID := make(map[string]secretbroker.Secret, len(secrets))
	for _, sec := range secrets {
		byID[sec.ID] = sec
	}
	var reqSrc, reqTgt *secretbroker.Requester
	if source != nil {
		r, err := leaseRequester(db, p.Path, source, "", nil)
		if err != nil {
			return nil, err
		}
		reqSrc = &r
	}
	var poolLabels map[string]string
	if target != nil {
		r, err := leaseRequester(db, p.Path, target, "", nil)
		if err != nil {
			return nil, err
		}
		reqTgt = &r
		if poolID, isPool := executor.PoolOf(target.ID()); isPool {
			poolLabels = e.poolLabels(poolID)
		}
	}
	// On a hub with single sign-on a personal grant counts only for its
	// owner's runs (Requester.Withhold); anyone else's is not theirs to see.
	caller := ""
	if e.s.oidcEnabled() {
		caller = secretbroker.NormalizeOwner(e.s.recipientIdentity(e.r).OwnerKey())
	}
	var out []projectmove.GrantFacts
	for _, g := range grants {
		if !g.Active(e.now) {
			continue
		}
		if g.Personal() && e.s.oidcEnabled() && secretbroker.NormalizeOwner(g.Owner) != caller {
			continue
		}
		rs := reqSrc != nil && g.Subject.Matches(*reqSrc)
		rt := reqTgt != nil && g.Subject.Matches(*reqTgt)
		if !rt && poolLabels != nil && g.Subject.Type == secretbroker.SubjectLabel {
			// A runner enrolls carrying its pool's labels, so a label grant
			// reaches the pool's runs when the pool's labels hold its selector.
			rt = labelsHold(g.Subject.Labels, poolLabels)
		}
		if !rs && !rt {
			continue
		}
		sec := byID[g.SecretID]
		name := sec.Name
		if name == "" {
			name = g.SecretID
		}
		out = append(out, projectmove.GrantFacts{
			ID: g.ID, SecretRef: name, Kind: string(sec.Kind), Subject: g.Subject.String(), ExpiresAt: g.ExpiresAt,
			ReachesSource: rs, ReachesTarget: rt, Files: fileKinds[sec.Kind],
			Devices: g.Constraints.Devices, Interfaces: g.Constraints.Interfaces,
			HostPath: sec.Kind == secretbroker.KindLocalRepo,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SecretRef < out[j].SecretRef })
	return out, nil
}

// poolLabels returns an executor pool's labels, or nil.
func (e *moveEnv) poolLabels(poolID string) map[string]string {
	store, err := e.s.poolStore()
	if err != nil {
		return nil
	}
	pool, err := store.Get(poolID)
	if err != nil {
		return nil
	}
	if pool.Labels == nil {
		return map[string]string{}
	}
	return pool.Labels
}

// labelsHold reports whether labels carry every key=value of sel.
func labelsHold(sel, labels map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	for k, want := range sel {
		if got, ok := labels[k]; !ok || got != want {
			return false
		}
	}
	return true
}

// Firewall reads the project's rule set and composes the levels that govern
// target, as the project's firewall card does for the bound executor.
func (e *moveEnv) Firewall(_ context.Context, p projectmove.Project, target executor.Executor) (projectmove.FirewallFacts, error) {
	db, err := e.cp()
	if err != nil {
		return projectmove.FirewallFacts{}, err
	}
	rec, ok, err := db.ProjectFirewall(executor.PolicyProjectPath(p.Path))
	if err != nil {
		return projectmove.FirewallFacts{}, err
	}
	levels, pos, err := governingLevels(db, target, nil, nil)
	if err != nil {
		return projectmove.FirewallFacts{}, err
	}
	f := projectmove.FirewallFacts{Enforceable: pos.Enforceable, RemovesNetwork: pos.RemovesNetwork, Reason: pos.Reason}
	if ok {
		rules := rec.Rules
		f.Project = &rules
	}
	gov, err := fwpolicy.Chain(levels)
	if err != nil {
		f.Error = err.Error()
	} else {
		f.Target = gov
	}
	return f, nil
}

// ForwardedDevices lists the project's forwarder bindings in force, whatever
// executor each is scoped to: the preflight decides which apply on the target.
func (e *moveEnv) ForwardedDevices(_ context.Context, p projectmove.Project) ([]projectmove.ForwardedFacts, error) {
	db, err := e.cp()
	if err != nil {
		return nil, err
	}
	rows, err := db.ListForwarderBindings(statedb.ForwarderBindingFilter{Project: policyProjectPath(p.Path), ActiveAt: e.now})
	if err != nil {
		return nil, err
	}
	var out []projectmove.ForwardedFacts
	for _, row := range rows {
		fwd, err := db.GetForwarder(row.ForwarderID)
		if err != nil || !fwd.RevokedAt.IsZero() {
			continue
		}
		dev := unmarshalForwarderDevice(fwd.DeviceJSON)
		online, _ := forwarderOnline(fwd.ForwarderID)
		name := dev.DefaultLabel()
		if name == "" {
			name = fwd.Name
		}
		forwarder := fwd.Name
		if forwarder == "" {
			forwarder = fwd.ForwarderID
		}
		out = append(out, projectmove.ForwardedFacts{ID: row.ID, Name: name, Kind: string(dev.Kind),
			Forwarder: forwarder, Online: online, Executor: row.VirtualExecutor})
	}
	return out, nil
}

// TakesForwarded is applyForwardedDevices' decision without the attaching.
func (e *moveEnv) TakesForwarded(_ context.Context, target executor.Executor, kinds []string) error {
	if taker, ok := executor.AsForwardedDeviceTaker(target); ok {
		return taker.CanTakeForwardedDevices(kinds)
	}
	if target.Kind() != executor.KindContainer {
		return fmt.Errorf("a %s executor runs payloads with no sandbox a device could be given to", target.Kind())
	}
	return canAttachHere(target, kinds)
}

func (e *moveEnv) VirtualDevices(_ context.Context, executorID string) []string {
	db, err := e.cp()
	if err != nil {
		return nil
	}
	v, ok, err := db.VirtualExecutor(executorID)
	if err != nil || !ok {
		return nil
	}
	var out []string
	for _, d := range v.Spec.Devices {
		out = append(out, d.Name)
	}
	return out
}

func (e *moveEnv) SandboxRequirements(_ context.Context, p projectmove.Project) (executor.Requirements, error) {
	resolved, err := sandbox.Resolve(p.Path)
	if err != nil {
		return executor.Requirements{}, err
	}
	return resolved.Requirements(), nil
}

// Workspace asks whether the hub could hand target the project's source, and
// each feature's, by the rules a dispatch applies.
func (e *moveEnv) Workspace(_ context.Context, p projectmove.Project, features []projectmove.Feature,
	target executor.Executor) []projectmove.WorkspaceIssue {
	var out []projectmove.WorkspaceIssue
	if err := workspaceFit(target, p.Path); err != nil {
		out = append(out, workspaceIssue("the project", err))
	}
	for _, f := range features {
		if err := checkFeatureExecutor(f.Path, target); err != nil {
			out = append(out, workspaceIssue("feature "+f.Slug, err))
		}
	}
	return out
}

func workspaceIssue(who string, err error) projectmove.WorkspaceIssue {
	is := projectmove.WorkspaceIssue{Who: who, Problem: err.Error()}
	var rem interface{ Remediation() string }
	if errors.As(err, &rem) {
		is.Remedy = rem.Remediation()
	}
	return is
}

// workspaceFit is applyWorkspace's decision for the project's own tree,
// without what applyWorkspace does besides deciding: it builds no seed, writes
// no bundle and journals nothing.
func workspaceFit(ex executor.Executor, workDir string) error {
	if ex.Capabilities().SharesHostFilesystem {
		return nil
	}
	origin, err := readGitOrigin(workDir)
	if errors.Is(err, errNoGitRepo) {
		// The executor keeps the working directory between runs; only the
		// project's state crosses, as its seed.
		if ex.Kind() == executor.KindKubernetes {
			// The Pod driver refuses this kind outright: a Pod's tree is gone
			// with the Pod, so it cannot keep the promise.
			return &workspaceSourceError{ProjectPath: workDir, ExecutorID: ex.ID(), ExecutorKind: ex.Kind(),
				Reason: "this project has no git repository, so its working directory has to be kept on the " +
					"executor between runs, and a Pod's tree is gone with the Pod",
				SuppressRemoteFix: true}
		}
		if !ex.Capabilities().SupportsProjectSeed {
			return &workspaceSourceError{ProjectPath: workDir, ExecutorID: ex.ID(), ExecutorKind: ex.Kind(),
				Reason: "this project has no git remote, so its project state is the only thing that can carry it " +
					"to an executor — and this one cannot accept a project state. " +
					strings.TrimSuffix(projectSeedRemedy(ex), "."),
				SuppressRemoteFix: true}
		}
		spec := executor.Spec{Workspace: executor.Workspace{Kind: executor.WorkspaceExecutor}}
		return executor.CheckSandboxSupport(ex, spec.SandboxRequirements(), workDir)
	}
	if err != nil {
		return &workspaceSourceError{ProjectPath: workDir, ExecutorID: ex.ID(), ExecutorKind: ex.Kind(), Reason: err.Error()}
	}
	repo, err := normalizeRemoteToHTTPS(origin.Remote)
	if err != nil {
		return &workspaceSourceError{ProjectPath: workDir, ExecutorID: ex.ID(), ExecutorKind: ex.Kind(),
			Remote: origin.Remote, Reason: err.Error()}
	}
	ws := executor.Workspace{Kind: executor.WorkspaceGit, Repo: repo, Ref: origin.Ref}
	grant, err := workspaceGrantFor(ws, ex, workDir)
	if err != nil {
		return err
	}
	ws.CredentialGrant = grant
	if err := ws.Validate(); err != nil {
		return &workspaceSourceError{ProjectPath: workDir, ExecutorID: ex.ID(), ExecutorKind: ex.Kind(),
			Remote: origin.Remote, Reason: err.Error()}
	}
	spec := executor.Spec{Workspace: ws}
	return executor.CheckSandboxSupport(ex, spec.SandboxRequirements(), workDir)
}

// PathBindings counts the hub's records keyed by the project's path. Each
// store is read on its own; one that cannot be read fails the list, since a
// partial one would read as complete.
func (e *moveEnv) PathBindings(_ context.Context, p projectmove.Project) ([]projectmove.PathBinding, error) {
	db, err := e.cp()
	if err != nil {
		return nil, err
	}
	path := p.Path
	policy := policyProjectPath(path)
	var out []projectmove.PathBinding
	add := func(store, what string, n int) {
		out = append(out, projectmove.PathBinding{Store: store, What: what, Count: n})
	}
	one := func(ok bool) int {
		if ok {
			return 1
		}
		return 0
	}

	if _, ok, err := db.ProjectExecutor(path); err != nil {
		return nil, err
	} else {
		add("project_executors", "the project's executor binding, which the move switches", one(ok))
	}
	kb, err := db.ListKnowledgeBindings(statedb.KnowledgeBindingFilter{ProjectPath: path})
	if err != nil {
		return nil, err
	}
	add("knowledge_bindings", "knowledge sources the project searches", len(kb))
	members, err := db.ListProjectMembers()
	if err != nil {
		return nil, err
	}
	n := 0
	for _, m := range members {
		if sameProjectKey(m.ProjectPath, policy) {
			n++
		}
	}
	add("project_members", "people and teams the project is shared with", n)
	if _, ok, err := db.ProjectFirewall(executor.PolicyProjectPath(path)); err != nil {
		return nil, err
	} else {
		add("project_firewall_rules", "the project's firewall rule set", one(ok))
	}
	if _, ok, err := db.ProjectResourceCeiling(path); err != nil {
		return nil, err
	} else {
		add("project_resource_limits", "the project's resource ceiling", one(ok))
	}
	store, err := secretstore.New(db)
	if err != nil {
		return nil, err
	}
	grants, err := store.ListGrants()
	if err != nil {
		return nil, err
	}
	n = 0
	for _, g := range grants {
		if g.Active(e.now) && g.Subject.Type == secretbroker.SubjectProject && g.Subject.Value == secretbroker.NormalizeProjectID(policy) {
			n++
		}
	}
	add("broker_grants", "secret grants issued to the project (project:<path>)", n)
	egress, err := db.ListEgressGrants()
	if err != nil {
		return nil, err
	}
	n = 0
	for _, g := range egress {
		if g.SubjectType == string(secretbroker.SubjectProject) && sameProjectKey(g.SubjectValue, policy) && g.RevokedAt == "" {
			n++
		}
	}
	add("egress_grants", "egress grants issued to the project", n)
	requests, err := db.ListGrantRequests()
	if err != nil {
		return nil, err
	}
	n = 0
	for _, rq := range requests {
		if rq.SubjectType == string(secretbroker.SubjectProject) && sameProjectKey(rq.SubjectValue, policy) && rq.State == "pending" {
			n++
		}
	}
	add("secret_grant_requests", "pending requests for a grant to the project", n)
	fwd, err := db.ListForwarderBindings(statedb.ForwarderBindingFilter{Project: policy, ActiveAt: e.now})
	if err != nil {
		return nil, err
	}
	add("forwarder_bindings", "forwarded devices bound to the project", len(fwd))
	roles, err := db.ListRoleBindings()
	if err != nil {
		return nil, err
	}
	n = 0
	for _, rb := range roles {
		if sameProjectKey(rb.Project, path) {
			n++
		}
	}
	add("role_bindings", "role bindings that name the project by its path", n)
	tokens, err := db.ListAPITokens()
	if err != nil {
		return nil, err
	}
	n = 0
	for _, t := range tokens {
		if !t.RevokedAt.IsZero() || (!t.ExpiresAt.IsZero() && !e.now.Before(t.ExpiresAt)) {
			continue
		}
		for _, sc := range t.ProjectScope {
			if sameProjectKey(sc, path) {
				n++
				break
			}
		}
	}
	add("api_tokens", "API tokens scoped to the project by its path", n)
	if _, ok, err := db.LoadSpendCursor(path); err != nil {
		return nil, err
	} else {
		add("project_spend_cursor", "where the project's spend was last booked", one(ok))
	}
	if _, ok, err := db.ProjectClaimAt(path); err != nil {
		return nil, err
	} else {
		add("project_claims", "the project's directory claim", one(ok))
	}
	meta := 0
	for _, key := range []string{harnessInitiatorKey(path), projectRelayModelsKey(policy)} {
		if _, ok, err := db.HubMeta(key); err != nil {
			return nil, err
		} else if ok {
			meta++
		}
	}
	add("hub metadata", "whom the last run was started for, and the model relay's allowlist", meta)
	return out, nil
}

// sameProjectKey compares two project paths as the stores write them.
func sameProjectKey(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	return a != "" && b != "" && secretbroker.NormalizeProjectID(a) == secretbroker.NormalizeProjectID(b)
}
