package ui

// features_api.go is the dashboard's surface for parallel features (Task
// 20341): list a project's features, start a new one, remove one, and propose
// one as a GitHub pull request.
//
// Every route is addressed through the *parent* project — its {idx} plus the
// feature's slug — so each is authorized against the project the feature
// belongs to, by the same scopeProjectIdx rule as every other project route.
// Once created, a feature is also a project in its own right with its own
// index, and running it, stopping it, editing its tasks and toggling its
// options all go through the ordinary project routes.
//
// None of these handlers runs git. pkg/ui may not spawn processes, and the
// operations that need git — creating a worktree, removing one, pushing a
// branch — are `cloop feature` subcommands dispatched to the project's
// executor like any other workload, with the executor's credentials. What the
// hub does itself is only what needs no process: reading the feature records
// that list features, and deciding whether a request may happen at all.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/featureops"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Bounds on a create request. The CLI validates the same things; checking
// here as well turns a bad request into a 400 before an executor is asked to
// run anything.
const (
	maxFeatureNameLen = 120
	maxFeatureDescLen = 8000
	maxFeatureBaseLen = 200
	maxFeatureTasks   = 200
	maxFeatureTaskLen = 500
	maxFeatureBody    = 64 << 10
)

// Timeouts for the dispatched subcommands. Creating a worktree checks out the
// whole tree, and publishing pushes the branch over the network.
const (
	featureCreateTimeout = 4 * time.Minute
	featureRemoveTimeout = 3 * time.Minute
	featurePRTimeout     = 10 * time.Minute
	featureRefreshTimout = 2 * time.Minute
)

// featureView is one feature as the API returns it.
type featureView struct {
	// ProjectIdx is the feature's own index in the caller's project list —
	// what its run, tasks and options are addressed by.
	ProjectIdx int    `json:"project_idx"`
	Path       string `json:"path"`
	multiui.ProjectStatus
}

// parentEntry resolves {idx} to a project that may have features, writing
// the refusal itself when it cannot.
func (s *Server) parentEntry(w http.ResponseWriter, r *http.Request) (multiui.ProjectEntry, bool) {
	e, ok := s.projectAtIdx(w, r)
	if !ok {
		return multiui.ProjectEntry{}, false
	}
	if e.IsFeature() {
		jsonErr(w, "a feature cannot have features of its own — use the project it belongs to", http.StatusBadRequest)
		return multiui.ProjectEntry{}, false
	}
	return e, true
}

// featureOf resolves {slug} to an existing feature of parent.
func featureOf(w http.ResponseWriter, r *http.Request, parent multiui.ProjectEntry) (string, string, bool) {
	slug := strings.TrimSpace(r.PathValue("slug"))
	if err := feature.ValidSlug(slug); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return "", "", false
	}
	dir := feature.Path(parent.Path, slug)
	if !feature.IsFeature(dir) {
		jsonErr(w, "no feature "+strconv.Quote(slug)+" in "+parent.Name, http.StatusNotFound)
		return "", "", false
	}
	return slug, dir, true
}

// indexOfPath returns path's index in the caller's project list, or -1.
func (s *Server) indexOfPath(r *http.Request, path string) int {
	for i, e := range s.visibleProjectEntries(r) {
		if e.Path == path {
			return i
		}
	}
	return -1
}

// handleProjectFeatures serves GET /api/projects/{idx}/features.
func (s *Server) handleProjectFeatures(w http.ResponseWriter, r *http.Request) {
	parent, ok := s.parentEntry(w, r)
	if !ok {
		return
	}
	s.refreshProjectStatuses()
	entries, statuses := s.cachedProjectView()
	statuses, _ = s.filterStatusesForRecipient(s.recipientIdentity(r), tokenFromRequest(r), entries, statuses)
	visible := s.visibleProjectEntries(r)
	index := make(map[string]int, len(visible))
	for i, e := range visible {
		index[e.Path] = i
	}
	out := make([]featureView, 0, 4)
	for _, st := range statuses {
		if st.Parent != parent.Path {
			continue
		}
		i, listed := index[st.Path]
		if !listed {
			continue
		}
		out = append(out, featureView{ProjectIdx: i, Path: st.Path, ProjectStatus: st})
	}
	jsonOK(w, map[string]any{
		"project":  parent.Name,
		"path":     parent.Path,
		"features": out,
		"max":      feature.MaxPerProject,
	})
}

// createFeatureRequest is what the New Feature dialog posts.
type createFeatureRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Base        string   `json:"base"`
	Tasks       []string `json:"tasks"`
	AutoEvolve  bool     `json:"auto_evolve"`
	Innovate    bool     `json:"innovate"`
	Parallel    bool     `json:"parallel"`
	MaxParallel int      `json:"max_parallel"`
	AutoPR      bool     `json:"auto_pr"`
}

// validate checks the request's shape and returns the slug it would create.
func (req *createFeatureRequest) validate() (string, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	req.Base = strings.TrimSpace(req.Base)
	switch {
	case req.Name == "":
		return "", errors.New("a feature needs a name")
	case len(req.Name) > maxFeatureNameLen:
		return "", fmt.Errorf("the name is longer than %d characters", maxFeatureNameLen)
	case len(req.Description) > maxFeatureDescLen:
		return "", fmt.Errorf("the description is longer than %d characters", maxFeatureDescLen)
	case len(req.Base) > maxFeatureBaseLen:
		return "", fmt.Errorf("the base branch name is longer than %d characters", maxFeatureBaseLen)
	case strings.HasPrefix(req.Base, "-") || strings.ContainsAny(req.Base, " \t\n\\~^:?*["):
		return "", fmt.Errorf("%q is not a valid branch name", req.Base)
	case req.MaxParallel < 0 || req.MaxParallel > config.MaxParallelUpper:
		return "", fmt.Errorf("max_parallel must be between 0 and %d", config.MaxParallelUpper)
	}
	tasks := make([]string, 0, len(req.Tasks))
	for _, t := range req.Tasks {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len(t) > maxFeatureTaskLen {
			return "", fmt.Errorf("a task is longer than %d characters", maxFeatureTaskLen)
		}
		tasks = append(tasks, t)
	}
	if len(tasks) > maxFeatureTasks {
		return "", fmt.Errorf("at most %d initial tasks", maxFeatureTasks)
	}
	req.Tasks = tasks
	slug := feature.Slugify(req.Name)
	if err := feature.ValidSlug(slug); err != nil {
		return "", fmt.Errorf("%q cannot name a feature: %w", req.Name, err)
	}
	return slug, nil
}

// handleProjectFeatureCreate serves POST /api/projects/{idx}/features.
func (s *Server) handleProjectFeatureCreate(w http.ResponseWriter, r *http.Request) {
	parent, ok := s.parentEntry(w, r)
	if !ok {
		return
	}
	var req createFeatureRequest
	limitJSONBody(w, r, maxFeatureBody)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	slug, err := req.validate()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Refusals the hub can decide without dispatching anything.
	if _, err := state.LoadLite(parent.Path); err != nil {
		if errors.Is(err, statedb.ErrProjectNotFound) {
			jsonErr(w, "initialise the project before creating features of it", http.StatusConflict)
			return
		}
		jsonErr(w, "the project's state could not be read: "+err.Error(), http.StatusInternalServerError)
		return
	}
	existing, err := feature.List(parent.Path)
	if err != nil {
		jsonErr(w, "list the project's features: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if len(existing) >= feature.MaxPerProject {
		jsonErr(w, fmt.Sprintf("this project already has %d features, the most one may hold — remove one first", len(existing)), http.StatusConflict)
		return
	}
	for _, in := range existing {
		if in.Meta.Slug == slug {
			jsonErr(w, "a feature named "+strconv.Quote(slug)+" already exists", http.StatusConflict)
			return
		}
	}
	registerBuiltinExecutors()
	if ex, err := executor.ResolveBinding(parent.Path); err == nil && executor.IsolatesFromHost(ex) {
		// Checked for the parent before anything is created: the worktree
		// would be made on the hub, and then the feature could never run
		// where its project does. See featureExecutorError.
		jsonWorkloadErr(w, &featureExecutorError{
			FeaturePath: feature.Path(parent.Path, slug), ExecutorID: ex.ID(), ExecutorKind: string(ex.Kind()),
		})
		return
	}

	// Values ride in the --flag=value form: user text must never be able to
	// be read as a flag of its own.
	args := []string{"feature", "new", "--json",
		"--description=" + req.Description,
		"--created-by=" + s.auditActor(r)}
	if req.Base != "" {
		args = append(args, "--base="+req.Base)
	}
	for _, t := range req.Tasks {
		args = append(args, "--task="+t)
	}
	if req.AutoEvolve {
		args = append(args, "--auto-evolve")
	}
	if req.Innovate {
		args = append(args, "--innovate")
	}
	if req.Parallel {
		args = append(args, "--parallel")
	}
	if req.MaxParallel > 0 {
		args = append(args, "--max-parallel="+strconv.Itoa(req.MaxParallel))
	}
	if req.AutoPR {
		args = append(args, "--auto-pr")
	}
	// "--" before the name: a name is user input, and one starting with a
	// dash must be a name rather than a flag.
	args = append(args, "--", req.Name)

	var result struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Code    string `json:"code"`
		Feature struct {
			Slug   string `json:"slug"`
			Branch string `json:"branch"`
			Base   string `json:"base"`
			Path   string `json:"path"`
		} `json:"feature"`
	}
	if !s.dispatchFeatureCommand(w, r, parent.Path, featureCreateTimeout, nil, &result, args...) {
		return
	}
	if !result.OK {
		writeFeatureCommandError(w, result.Error, result.Code, nil)
		return
	}

	path := feature.Path(parent.Path, result.Feature.Slug)
	s.recordFeatureEvent(r, parent.Path, auditaction.ActionFeatureCreate, result.Feature.Slug, map[string]any{
		"slug": result.Feature.Slug, "branch": result.Feature.Branch, "base": result.Feature.Base,
		"path": path, "auto_evolve": req.AutoEvolve, "innovate": req.Innovate, "tasks": len(req.Tasks),
	})
	state.LogEvent(parent.Path, state.EventRow{
		Type: state.EventFeatureCreated, Step: state.NoStep,
		Message: fmt.Sprintf("Feature %q created on branch %s from %s", req.Name, result.Feature.Branch, result.Feature.Base),
	})

	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
	jsonOK(w, map[string]any{
		"ok":          true,
		"slug":        result.Feature.Slug,
		"branch":      result.Feature.Branch,
		"base":        result.Feature.Base,
		"path":        path,
		"project_idx": s.indexOfPath(r, path),
	})
}

// handleProjectFeatureDelete serves DELETE /api/projects/{idx}/features/{slug}.
func (s *Server) handleProjectFeatureDelete(w http.ResponseWriter, r *http.Request) {
	parent, ok := s.parentEntry(w, r)
	if !ok {
		return
	}
	slug, workDir, ok := featureOf(w, r, parent)
	if !ok {
		return
	}
	q := r.URL.Query()
	deleteBranch := q.Get("delete_branch") == "true"
	force := q.Get("force") == "true"
	if r.ContentLength != 0 {
		var body struct {
			DeleteBranch bool `json:"delete_branch"`
			Force        bool `json:"force"`
		}
		limitJSONBody(w, r, maxJSONBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !isEmptyBody(err) {
			respondToBodyError(w, err)
			return
		}
		deleteBranch = deleteBranch || body.DeleteBranch
		force = force || body.Force
	}
	// Anything executing inside the feature — its own run, or a parallel
	// task in its .cloop/worktrees — would have its directory removed.
	if s.projectExecuting(workDir) || multiui.IsCloopRunningUnder(workDir) {
		jsonErr(w, "the feature has a run in progress — stop it first", http.StatusConflict)
		return
	}

	args := []string{"feature", "remove", "--json"}
	if deleteBranch {
		args = append(args, "--delete-branch")
	}
	if force {
		args = append(args, "--force")
	}
	args = append(args, "--", slug)
	var result struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Code    string `json:"code"`
		Removed struct {
			Branch        string `json:"branch"`
			BranchDeleted bool   `json:"branch_deleted"`
			BranchKept    string `json:"branch_kept"`
		} `json:"removed"`
	}
	if !s.dispatchFeatureCommand(w, r, parent.Path, featureRemoveTimeout, nil, &result, args...) {
		return
	}
	if !result.OK {
		writeFeatureCommandError(w, result.Error, result.Code, nil)
		return
	}
	s.liveLogEvict(workDir)
	s.recordFeatureEvent(r, parent.Path, auditaction.ActionFeatureRemove, slug, map[string]any{
		"slug": slug, "branch": result.Removed.Branch, "branch_deleted": result.Removed.BranchDeleted, "force": force,
	})
	msg := fmt.Sprintf("Feature %s removed; branch %s kept", slug, result.Removed.Branch)
	if result.Removed.BranchDeleted {
		msg = fmt.Sprintf("Feature %s removed with its branch %s", slug, result.Removed.Branch)
	}
	state.LogEvent(parent.Path, state.EventRow{Type: state.EventFeatureRemoved, Step: state.NoStep, Message: msg})

	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
	jsonOK(w, map[string]any{
		"ok":             true,
		"slug":           slug,
		"branch":         result.Removed.Branch,
		"branch_deleted": result.Removed.BranchDeleted,
		"branch_kept":    result.Removed.BranchKept,
	})
}

// featurePRRequest is what the Open Pull Request dialog posts.
type featurePRRequest struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	Draft bool   `json:"draft"`
}

// featurePROutcome is the subcommand's --json result for `cloop feature pr`.
type featurePROutcome struct {
	OK      bool                 `json:"ok"`
	Error   string               `json:"error"`
	Code    string               `json:"code"`
	Result  *featureops.PRResult `json:"result"`
	Partial *featureops.PRResult `json:"partial"`
}

// handleProjectFeaturePR serves POST /api/projects/{idx}/features/{slug}/pr.
func (s *Server) handleProjectFeaturePR(w http.ResponseWriter, r *http.Request) {
	parent, ok := s.parentEntry(w, r)
	if !ok {
		return
	}
	slug, dir, ok := featureOf(w, r, parent)
	if !ok {
		return
	}
	var req featurePRRequest
	if r.ContentLength != 0 {
		limitJSONBody(w, r, maxFeatureBody)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !isEmptyBody(err) {
			respondToBodyError(w, err)
			return
		}
	}
	req.Title = strings.TrimSpace(req.Title)
	if len(req.Title) > 256 {
		jsonErr(w, "the title is longer than 256 characters", http.StatusBadRequest)
		return
	}

	out, status, err := s.openFeaturePR(context.WithoutCancel(r.Context()), dir, req, s.auditActor(r))
	if err != nil {
		if status == 0 {
			jsonWorkloadErr(w, err)
			return
		}
		jsonErr(w, err.Error(), status)
		return
	}
	if !out.OK || out.Result == nil || out.Result.PR == nil {
		writeFeatureCommandError(w, out.Error, out.Code, out.Partial)
		return
	}
	s.afterFeaturePR(parent.Path, dir, slug, out.Result, false, r)
	jsonOK(w, map[string]any{"ok": true, "result": out.Result})
}

// openFeaturePR dispatches `cloop feature pr` for the feature at dir. A
// non-zero status is a refusal decided here; status 0 with an error is a
// dispatch failure for jsonWorkloadErr.
func (s *Server) openFeaturePR(ctx context.Context, dir string, req featurePRRequest, actor string) (*featurePROutcome, int, error) {
	args := []string{"feature", "pr", "--json"}
	if req.Title != "" {
		args = append(args, "--title="+req.Title)
	}
	if strings.TrimSpace(req.Body) != "" {
		args = append(args, "--body="+req.Body)
	}
	if req.Draft {
		args = append(args, "--draft")
	}
	var out featurePROutcome
	// Dispatched in the feature's own directory, so it resolves the same
	// executor and leases the same credentials the feature's runs do.
	raw, err := runCloopSubcommandFor(ctx, s.selfExe(), dir, featurePRTimeout, s.featureTokenEnv(), args...)
	if perr := clijson.Unmarshal(raw, &out); perr != nil {
		if err != nil {
			return nil, 0, err
		}
		return nil, http.StatusInternalServerError, fmt.Errorf("could not read the result of opening the pull request: %v", perr)
	}
	return &out, 0, nil
}

// featureTokenEnv hands the hub's own GitHub token, when one is configured,
// to a PR dispatch — as the last resort after the project's own credentials
// (see featureops.ResolveToken), and only where it widens nothing:
//
//   - not to an executor that isolates from the host, where the token would
//     enter the sandbox — what grants and the git proxy exist to prevent;
//   - not on a hub with sign-in, where projects belong to different people:
//     the hub's token reaches repositories no one project was granted, and
//     handing it to whoever can open a pull request would let a project push
//     with authority its grants withhold. There each project uses its own.
func (s *Server) featureTokenEnv() func(executor.Executor) []string {
	return func(ex executor.Executor) []string {
		if ex == nil || executor.IsolatesFromHost(ex) || s.oidcEnabled() {
			return nil
		}
		cfg, err := config.Load(s.WorkDir)
		if err != nil || cfg == nil || strings.TrimSpace(cfg.GitHub.Token) == "" {
			return nil
		}
		return []string{featureops.EnvToken + "=" + strings.TrimSpace(cfg.GitHub.Token)}
	}
}

// afterFeaturePR records an opened pull request everywhere it should be seen.
func (s *Server) afterFeaturePR(parentPath, dir, slug string, res *featureops.PRResult, automatic bool, r *http.Request) {
	verb := "opened"
	if res.Existing {
		verb = "updated"
	}
	msg := fmt.Sprintf("Pull request #%d %s: %s", res.PR.Number, verb, res.PR.URL)
	if automatic {
		msg += " (automatically, on completion)"
	}
	for _, p := range []string{dir, parentPath} {
		state.LogEventDetails(p, state.EventRow{Type: state.EventFeaturePR, Step: state.NoStep, Message: msg},
			map[string]any{"feature": slug, "number": res.PR.Number, "url": res.PR.URL, "existing": res.Existing})
	}
	s.recordFeatureEvent(r, parentPath, auditaction.ActionFeaturePROpen, slug, map[string]any{
		"slug": slug, "number": res.PR.Number, "url": res.PR.URL, "base": res.PR.Base,
		"existing": res.Existing, "automatic": automatic,
	})
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
}

// handleProjectFeaturePRRefresh serves POST
// /api/projects/{idx}/features/{slug}/pr/refresh: re-read the pull request's
// state from GitHub, so a merged one says so.
func (s *Server) handleProjectFeaturePRRefresh(w http.ResponseWriter, r *http.Request) {
	parent, ok := s.parentEntry(w, r)
	if !ok {
		return
	}
	_, dir, ok := featureOf(w, r, parent)
	if !ok {
		return
	}
	m, err := feature.LoadMeta(dir)
	if err != nil || m.PR == nil {
		jsonErr(w, "the feature has no pull request yet", http.StatusConflict)
		return
	}
	var out struct {
		OK    bool        `json:"ok"`
		Error string      `json:"error"`
		Code  string      `json:"code"`
		PR    *feature.PR `json:"pr"`
	}
	raw, err := runCloopSubcommandFor(context.WithoutCancel(r.Context()), s.selfExe(), dir, featureRefreshTimout, s.featureTokenEnv(),
		"feature", "pr-status", "--json")
	if perr := clijson.Unmarshal(raw, &out); perr != nil {
		if err != nil {
			jsonWorkloadErr(w, err)
			return
		}
		jsonErr(w, "could not read the pull request's state: "+perr.Error(), http.StatusInternalServerError)
		return
	}
	if !out.OK {
		writeFeatureCommandError(w, out.Error, out.Code, nil)
		return
	}
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
	jsonOK(w, map[string]any{"ok": true, "pr": out.PR})
}

// dispatchFeatureCommand runs a `cloop feature` subcommand in dir through the
// project's executor and decodes its framed JSON result into out. It writes
// the error response itself and returns false when there is no result to
// read.
func (s *Server) dispatchFeatureCommand(w http.ResponseWriter, r *http.Request, dir string, timeout time.Duration,
	envFor func(executor.Executor) []string, out any, args ...string) bool {
	// Not cancelled with the request: a browser tab closed while a worktree
	// is being created or removed must not kill git halfway through, which
	// would leave a half-made feature for the next attempt to trip over. The
	// timeout still bounds it.
	raw, err := runCloopSubcommandFor(context.WithoutCancel(r.Context()), s.selfExe(), dir, timeout, envFor, args...)
	// The subcommand exits non-zero on every refusal and still prints a
	// framed result saying why, so the frame is read before the exit status.
	if perr := clijson.Unmarshal(raw, out); perr == nil {
		return true
	}
	if err != nil {
		jsonWorkloadErr(w, err)
		return false
	}
	jsonErr(w, "the feature command produced no result", http.StatusInternalServerError)
	return false
}

// writeFeatureCommandError maps a `cloop feature --json` failure onto HTTP.
func writeFeatureCommandError(w http.ResponseWriter, msg, code string, partial any) {
	if msg == "" {
		msg = "the feature command failed"
	}
	status := http.StatusInternalServerError
	switch code {
	case "exists", "dirty", "running", "nothing_to_propose", "no_token":
		status = http.StatusConflict
	case "nested":
		status = http.StatusBadRequest
	case "not_found":
		status = http.StatusNotFound
	}
	body := map[string]any{"error": msg, "code": code}
	if partial != nil {
		body["partial"] = partial
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// recordFeatureEvent writes a feature lifecycle row to the parent project's
// audit trail. r may be nil for an action the hub took on its own.
func (s *Server) recordFeatureEvent(r *http.Request, parentPath string, action auditaction.Action, slug string, payload map[string]any) {
	actor := "hub"
	if r != nil {
		if a := s.auditActor(r); a != "" {
			actor = a
		}
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		return
	}
	log, err := eventlog.Open(parentPath)
	if err != nil {
		if err != eventlog.ErrNoProject {
			s.log().Warn(logger.EventAuthz, 0, "feature audit: open event log",
				map[string]interface{}{"error": err.Error(), "workdir": parentPath})
		}
		return
	}
	defer log.Close()
	if err := log.Append(&eventlog.AuditEvent{
		Actor:      actor,
		EventType:  string(action),
		EntityType: "feature",
		EntityID:   slug,
		Payload:    string(blob),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "feature audit: append",
			map[string]interface{}{"error": err.Error()})
	}
}

// ── automatic pull requests ─────────────────────────────────────────────────

// autoPRInFlight holds the features an automatic pull request is being opened
// for, so two run endings in quick succession cannot open two.
var autoPRInFlight sync.Map

// autoPRLastTry records when an automatic attempt last started per feature.
// A run's end is seen twice — by the handler that dispatched it and by the
// sweep that watched it stop — and a failed attempt (no token, say) would
// otherwise be repeated, and reported, once for each.
var autoPRLastTry sync.Map

// autoPRCooldown is how long after an attempt another is not made.
const autoPRCooldown = 5 * time.Minute

// maybeAutoOpenFeaturePR opens a feature's pull request once its plan has
// completed, when the feature asked for that at creation (auto_pr). Called
// when a run ends; returns at once, doing the work in the background.
//
// It only ever opens the first one. A feature that already has a pull request
// is left alone — pushing new commits to it is a person's decision, taken from
// the dashboard — and so is one whose run ended in any state but complete.
func (s *Server) maybeAutoOpenFeaturePR(workDir string) {
	parentPath, slug, ok := feature.ParentOf(workDir)
	if !ok {
		return
	}
	m, err := feature.LoadMeta(workDir)
	if err != nil || !m.AutoPR || m.PR != nil {
		return
	}
	st, err := state.LoadLite(workDir)
	if err != nil || st.Status != "complete" {
		return
	}
	if last, ok := autoPRLastTry.Load(workDir); ok && time.Since(last.(time.Time)) < autoPRCooldown {
		return
	}
	if _, busy := autoPRInFlight.LoadOrStore(workDir, true); busy {
		return
	}
	// Every hub member sees a run end (Task 20354) — the one that streamed it
	// and every one whose sweep watched it stop. One of them opens the pull
	// request; the claim decides which, and the rest see its owner and stand
	// aside.
	if n := s.clusterNode(); n != nil {
		if _, won, err := n.Claim(ownerAutoPR, workDir, nil); err == nil && !won {
			autoPRInFlight.Delete(workDir)
			return
		}
	}
	autoPRLastTry.Store(workDir, time.Now())
	go func() {
		defer autoPRInFlight.Delete(workDir)
		defer func() {
			if n := s.clusterNode(); n != nil {
				_, _ = n.Release(ownerAutoPR, workDir)
			}
		}()
		defer recoverGoroutine("automatic feature pull request")
		ctx, cancel := context.WithTimeout(context.Background(), featurePRTimeout+time.Minute)
		defer cancel()
		out, _, err := s.openFeaturePR(ctx, workDir, featurePRRequest{}, "hub")
		if err != nil || out == nil || !out.OK || out.Result == nil || out.Result.PR == nil {
			reason := "unknown error"
			switch {
			case err != nil:
				reason = err.Error()
			case out != nil && out.Error != "":
				reason = out.Error
			}
			state.LogEvent(workDir, state.EventRow{Type: state.EventFeaturePR, Step: state.NoStep,
				Message: "Opening the pull request automatically failed: " + reason})
			return
		}
		s.afterFeaturePR(parentPath, workDir, slug, out.Result, true, nil)
	}()
}
