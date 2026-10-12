package ui

// Where a project may live, and the hub's side of keeping it there (Task 20418).
//
// pkg/projectconfine owns the invariant. This file is where the hub applies
// it: to a creation (handleProjectNew, which `cloop remote init` also calls),
// to every dispatch before a driver binds or forks in the directory, to the
// registry write that ends a creation, and to the rows the Projects tab shows.
// See the package documentation there for the rules themselves.
//
// # What a refused caller is told
//
// An administrator is told exactly what collided with what. Anyone else is
// told the same sentence for every refusal that depends on what exists on the
// host — a project they cannot see at that path, one inside it, the hub's own
// directory, another hub's, a creation already holding it — because a
// different answer for each would let them map the host's projects one
// request at a time; the 409 that used to say "a cloop project already exists
// at …" was exactly that oracle. Refusals that depend only on the path and the
// hub's configuration (a system directory, outside the projects root) are
// explained, since the caller can work those out without asking. The audit
// row always carries the whole reason.

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectconfine"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ruleTaken is the audit `rule` of a creation refused because another creation
// holds the path, or one inside it or above it.
const ruleTaken = "taken"

// canonicalDir resolves dir the way pkg/projectconfine does, falling back to
// its cleaned absolute form when it cannot be resolved (a dangling link) — so
// a comparison against it fails rather than matching something else.
func canonicalDir(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	if c, err := projectconfine.Canonical(dir); err == nil {
		return c
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return filepath.Clean(dir)
}

// hubHome is the hub user's home directory, "" when it has none.
func hubHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// projectsRootFrom is the directory a project created by name is placed in,
// read from cfg: ui.projects_root, or projects/ in the hub's home.
func projectsRootFrom(cfg *config.Config, cfgErr error) (string, error) {
	if cfgErr != nil || cfg == nil {
		if cfgErr == nil {
			cfgErr = errors.New("no configuration")
		}
		return "", fmt.Errorf("this hub's configuration could not be read to find ui.projects_root: %v — "+
			"name a directory instead", cfgErr)
	}
	root := strings.TrimSpace(cfg.UI.ProjectsRoot)
	if root == "" {
		home := hubHome()
		if strings.TrimSpace(home) == "" {
			return "", fmt.Errorf("this hub has no ui.projects_root and no home directory to keep projects in: " +
				"set ui.projects_root, or name a directory")
		}
		root = filepath.Join(home, "projects")
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("ui.projects_root is %q, which is not an absolute path: fix it in the hub's "+
			"configuration, or name a directory", root)
	}
	return filepath.Clean(root), nil
}

// ── Running hubs ────────────────────────────────────────────────────────────

// hubDirCacheTTL bounds how stale the list of running hubs may be. Reading it
// walks /proc, which is cheap once and not on every status refresh.
const hubDirCacheTTL = 30 * time.Second

var hubDirCache struct {
	mu   sync.Mutex
	at   time.Time
	dirs []string
}

// runningHubDirs returns the working directories of the `cloop ui` processes
// on this host — every hub's control plane, whether or not it keeps a hub.env.
func runningHubDirs() []string {
	hubDirCache.mu.Lock()
	defer hubDirCache.mu.Unlock()
	if time.Since(hubDirCache.at) < hubDirCacheTTL && hubDirCache.at != (time.Time{}) {
		return hubDirCache.dirs
	}
	var dirs []string
	seen := map[string]bool{}
	for _, h := range multiui.HubProcesses() {
		d := canonicalDir(h.Dir)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	hubDirCache.dirs, hubDirCache.at = dirs, time.Now()
	return dirs
}

// ── The registered projects, for code with no Server ───────────────────────

// projectListSource lists every project this hub serves. Set by the Server
// that bootstrapped the control plane, like controlPlaneDir, for the dispatch
// helpers that are reached without one. Nil falls back to the registry file.
var projectListSource struct {
	mu sync.RWMutex
	fn func() []multiui.ProjectEntry
}

func setProjectListSource(fn func() []multiui.ProjectEntry) {
	projectListSource.mu.Lock()
	projectListSource.fn = fn
	projectListSource.mu.Unlock()
}

// registeredProjectDirs returns every registered project's directory,
// canonical, features excluded: a feature lives in its project's tree.
func registeredProjectDirs() []string {
	projectListSource.mu.RLock()
	fn := projectListSource.fn
	projectListSource.mu.RUnlock()
	var entries []multiui.ProjectEntry
	if fn != nil {
		entries = fn()
	} else {
		entries, _ = multiui.Load()
	}
	return projectDirsOf(entries)
}

func projectDirsOf(entries []multiui.ProjectEntry) []string {
	out := make([]string, 0, len(entries))
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsFeature() {
			continue
		}
		d := canonicalDir(e.Path)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// ── At dispatch ─────────────────────────────────────────────────────────────

// existingRowPolicy is the invariant for a directory that is already a
// project, against this process's control plane.
func existingRowPolicy(controlPlane, root string, projects []string) projectconfine.Policy {
	return projectconfine.Policy{
		ControlPlane: canonicalDir(controlPlane),
		ProjectsRoot: canonicalDir(root),
		Projects:     projects,
		HubDirs:      runningHubDirs(),
		Home:         hubHome(),
		Existing:     true,
	}
}

// confinementError is a dispatch refused because the project's directory
// breaks the invariant. It names what the directory overlaps, but not another
// tenant's project: the person starting a run may not be able to see it, and
// `cloop hub doctor` names it to the operator.
type confinementError struct {
	Project string
	V       *projectconfine.Violation
}

func (e *confinementError) Unwrap() error { return e.V }

func (e *confinementError) Error() string {
	return "the hub will not run the project at " + e.Project + ": " + confinementReason(e.V)
}

// Remediation says how the refusal ends.
func (e *confinementError) Remediation() string {
	return "An administrator moves the project out of the overlap, or removes it from the hub; " +
		"nothing is bound or started until then. `cloop hub doctor` lists every project whose " +
		"directory breaks the rule, with what it overlaps."
}

// confinementReason describes a violation without naming another tenant's
// project.
func confinementReason(v *projectconfine.Violation) string {
	switch v.Rule {
	case projectconfine.RuleControlPlane:
		if v.Relation == projectconfine.Contains {
			return "its directory contains the hub's control plane (" + v.Other + ")"
		}
		return "its directory is inside the hub's control plane (" + v.Other + ")"
	case projectconfine.RuleHub:
		if v.Relation == projectconfine.Contains {
			return "its directory contains a hub's control plane (" + v.Other + ")"
		}
		return "its directory is inside a hub's control plane (" + v.Other + ")"
	case projectconfine.RuleProject:
		if v.Relation == projectconfine.Contains {
			return "its directory contains another registered project"
		}
		return "its directory is inside another registered project"
	case projectconfine.RuleProjectsRoot:
		if v.Relation == projectconfine.Same {
			return "its directory is the hub's projects root (" + v.Other + ")"
		}
		return "its directory contains the hub's projects root (" + v.Other + ")"
	case projectconfine.RuleUnsafe, projectconfine.RuleUnresolvable:
		return v.Reason
	case projectconfine.RuleRelocated:
		return "its .cloop is a link out of its directory"
	}
	return v.Error()
}

// checkDispatchConfinement re-checks the invariant for the project a workload
// is about to be dispatched for, before anything is minted, bound or forked.
//
// A row can break it without ever having been created through the hub: an
// operator's `cloop ui --projects`, a registry written before Task 20418, or a
// projects root moved under it. Those rows are listed and flagged, and this is
// where they stop. A feature is checked as its project. An empty workDir is a
// workload with no project, which binds nothing.
func checkDispatchConfinement(workDir string) error {
	if strings.TrimSpace(workDir) == "" {
		return nil
	}
	cp, _ := controlPlaneSource()
	if strings.TrimSpace(cp) == "" {
		return nil // no hub in this process: nothing registered to protect
	}
	project := policyProjectPath(workDir)
	root, _ := projectsRootFrom(controlPlaneConfig())
	_, err := existingRowPolicy(cp, root, registeredProjectDirs()).Check(project)
	if v, ok := projectconfine.IsViolation(err); ok {
		return &confinementError{Project: project, V: v}
	}
	return err
}

// refuseUnconfined answers a run request for a project whose directory breaks
// the invariant, before any other admission gate: no credential, slot or
// audience entry would let the hub run it. startWorkloadAs checks again; this
// is the same answer given before anything is claimed.
func (s *Server) refuseUnconfined(w http.ResponseWriter, workDir string) bool {
	if strings.TrimSpace(workDir) == "" {
		return false
	}
	project := policyProjectPath(workDir)
	root, _ := projectsRootFrom(s.loadHubConfig())
	_, err := existingRowPolicy(s.WorkDir, root, projectDirsOf(s.allProjectEntries())).Check(project)
	if v, ok := projectconfine.IsViolation(err); ok {
		jsonWorkloadErr(w, &confinementError{Project: project, V: v})
		return true
	}
	return false
}

// ── On the Projects tab ─────────────────────────────────────────────────────

// projectFlagTTL bounds how long the flags computed for one set of rows are
// reused. The rows rarely change; the rule's inputs on disk (a hub.env, a
// symbolic link) change more rarely still.
const projectFlagTTL = 15 * time.Second

type projectFlagCache struct {
	mu   sync.Mutex
	key  string
	at   time.Time
	flag map[string]string
}

// confinementFlags returns, for every row in entries that breaks the
// invariant, the sentence its card shows. Features are judged as their
// project, so a flagged project's features are flagged with it.
func (s *Server) confinementFlags(entries []multiui.ProjectEntry) map[string]string {
	key := entriesKey(entries)
	s.projFlags.mu.Lock()
	defer s.projFlags.mu.Unlock()
	if s.projFlags.key == key && time.Since(s.projFlags.at) < projectFlagTTL {
		return s.projFlags.flag
	}
	cfg, cfgErr := s.loadHubConfig()
	root, _ := projectsRootFrom(cfg, cfgErr)
	policy := existingRowPolicy(s.WorkDir, root, projectDirsOf(entries))
	flags := map[string]string{}
	verdict := map[string]string{}
	for _, e := range entries {
		project := policyProjectPath(e.Path)
		msg, done := verdict[project]
		if !done {
			if _, err := policy.Check(project); err != nil {
				if v, ok := projectconfine.IsViolation(err); ok {
					msg = "The hub will not run this project: " + confinementReason(v) +
						". An administrator has to move it."
				}
			}
			verdict[project] = msg
		}
		if msg != "" {
			flags[e.Path] = msg
		}
	}
	s.projFlags.key, s.projFlags.at, s.projFlags.flag = key, time.Now(), flags
	return flags
}

func entriesKey(entries []multiui.ProjectEntry) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Path)
		b.WriteByte(0)
	}
	return b.String()
}

// ── At creation ─────────────────────────────────────────────────────────────

// placesProjectsAnywhere reports whether the caller may create a project
// outside the projects root. executor.manage, the administrator's permission
// over the fleet: a project's directory is a host directory every sandbox it
// runs in is given, so where one goes is the same kind of decision as which
// machines run work. On a hub without sign-in everyone holds it, as before.
func (s *Server) placesProjectsAnywhere(r *http.Request) bool {
	return s.permissionsFor(r, authz.GlobalScope).Allows(authz.PermExecutorManage)
}

// projectPlace is a creation's directory, decided.
type projectPlace struct {
	// Path is the canonical directory to create, register and bind.
	Path string
	// Requested is the absolute path the caller asked for.
	Requested string
	// Root is the projects root, "" when it could not be determined.
	Root  string
	Admin bool
	// visible are the projects the caller can see, canonical.
	visible map[string]bool
	// registered are every registered project, canonical.
	registered []string
}

// placeNewProject applies the invariant to a creation's directory. It writes
// the refusal and returns false when the directory may not be used.
func (s *Server) placeNewProject(w http.ResponseWriter, r *http.Request, requested string) (projectPlace, bool) {
	p := projectPlace{Requested: requested, Admin: s.placesProjectsAnywhere(r)}
	cfg, cfgErr := s.loadHubConfig()
	root, rootErr := projectsRootFrom(cfg, cfgErr)
	if rootErr == nil {
		p.Root = canonicalDir(root)
	} else if !p.Admin {
		// A caller who must stay inside the root cannot be placed without
		// one; an administrator can, and is held to everything else.
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, rootErr.Error()))
		return p, false
	}
	p.registered = projectDirsOf(s.allProjectEntries())
	p.visible = map[string]bool{}
	for _, d := range projectDirsOf(s.visibleProjectEntries(r)) {
		p.visible[d] = true
	}
	policy := projectconfine.Policy{
		ControlPlane:  canonicalDir(s.WorkDir),
		ProjectsRoot:  p.Root,
		ConfineToRoot: !p.Admin,
		Projects:      p.registered,
		HubDirs:       runningHubDirs(),
		Home:          hubHome(),
		Scan:          projectconfine.DefaultScan,
	}
	canon, err := policy.Check(requested)
	p.Path = canon
	if err == nil {
		return p, true
	}
	v, ok := projectconfine.IsViolation(err)
	if !ok {
		jsonErr(w, "invalid dir: "+err.Error(), http.StatusBadRequest)
		return p, false
	}
	s.refuseNewProject(w, r, p, string(v.Rule), v.Error(), v)
	return p, false
}

// refuseNewProject writes a creation's refusal and records it. reason is the
// whole story, for the audit row and an administrator; v is nil for a refusal
// that is not a violation (a path another creation holds, a project found on
// disk).
func (s *Server) refuseNewProject(w http.ResponseWriter, r *http.Request, p projectPlace, rule, reason string, v *projectconfine.Violation) {
	s.auditProjectCreate(r, p, map[string]any{"outcome": "refused", "rule": rule, "reason": reason})
	if v != nil {
		switch v.Rule {
		case projectconfine.RuleUnsafe, projectconfine.RuleUnresolvable:
			// Wrong wherever the hub stands, and said as before (Task 20188).
			jsonErr(w, "refusing to create a project at "+p.Requested+": "+v.Reason, http.StatusBadRequest)
			return
		case projectconfine.RuleOutsideRoot:
			d := s.permissionsFor(r, authz.GlobalScope)
			msg := "only an administrator places a project outside the hub's projects root (" + p.Root +
				"): create it by name, or name a directory inside the root"
			if v.Reason != "" {
				msg = p.Requested + " cannot hold a project: " + v.Reason + " — create it by name, or name " +
					"another directory inside the hub's projects root (" + p.Root + ")"
			}
			apierror.WriteError(w, apierror.New(apierror.CodeForbidden, msg).WithDetails(map[string]any{
				"required_permission": string(authz.PermExecutorManage),
				"role":                string(d.Role),
				"scope":               authz.GlobalScope.String(),
				"projects_root":       p.Root,
				"dir":                 p.Requested,
			}))
			return
		case projectconfine.RuleProjectsRoot:
			// Depends on the configuration alone, which the caller learns from
			// any creation by name anyway.
			apierror.WriteError(w, apierror.New(apierror.CodeConflict, v.Error()).
				WithDetails(map[string]any{"dir": p.Requested}))
			return
		case projectconfine.RuleProject:
			if p.Admin || p.visible[v.Other] {
				msg := v.Error()
				if v.Relation == projectconfine.Same {
					msg = "a cloop project already exists at " + v.Path +
						" — open that one, or create this one under another name or directory"
				}
				apierror.WriteError(w, apierror.New(apierror.CodeConflict, msg).
					WithDetails(map[string]any{"dir": p.Requested}))
				return
			}
		}
	}
	if p.Admin {
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, reason).
			WithDetails(map[string]any{"dir": p.Requested}))
		return
	}
	writeProjectUnavailable(w, p.Requested)
}

// writeProjectUnavailable is the one answer a caller who is not an
// administrator gets for every refusal that depends on what exists on the
// host. Its words must not vary with the cause.
func writeProjectUnavailable(w http.ResponseWriter, requested string) {
	apierror.WriteError(w, apierror.New(apierror.CodeConflict,
		requested+" cannot hold a new project: the directory is in use or protected by this hub — "+
			"choose another name or directory").
		WithDetails(map[string]any{"dir": requested}))
}

// claimStaleAfter is how long a creation may hold a path without finishing:
// longer than any `cloop init` is allowed to run (initSubprocessTimeout), so a
// live creation is never taken for a dead one.
const claimStaleAfter = 2*initSubprocessTimeout + time.Minute

// claimNewProject claims p.Path in the control plane, so that no other
// creation can use it, or a directory inside it or above it, until this one
// has finished. It writes the refusal and returns false when the path is
// taken. release gives the claim back; it is safe to call more than once.
func (s *Server) claimNewProject(w http.ResponseWriter, r *http.Request, p projectPlace) (release func(), ok bool) {
	noop := func() {}
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, "could not claim the project's directory: "+err.Error(), http.StatusInternalServerError)
		return noop, false
	}
	defer db.Close()
	registered := map[string]bool{}
	for _, d := range p.registered {
		registered[d] = true
	}
	stale := func(c statedb.ProjectClaim) bool {
		switch c.State {
		case statedb.ProjectClaimCreating:
			return time.Since(c.ClaimedAt) > claimStaleAfter
		case statedb.ProjectClaimCreated:
			// A project removed from the registry by hand leaves its claim
			// behind; a claim completed a moment ago may not be listed yet.
			return !registered[c.Path] && time.Since(c.UpdatedAt) > claimStaleAfter
		}
		return true
	}
	held, err := db.ClaimProjectPath(statedb.ProjectClaim{
		Path:      p.Path,
		Owner:     s.sessionIdentity(r).OwnerKey(),
		ClaimedBy: s.auditActor(r),
	}, stale)
	if err != nil {
		jsonErr(w, "could not claim the project's directory: "+err.Error(), http.StatusInternalServerError)
		return noop, false
	}
	if held != nil {
		s.refuseNewProject(w, r, p, ruleTaken, fmt.Sprintf(
			"%s is held by another creation: %s claimed %s at %s (state %s)",
			p.Path, held.ClaimedBy, held.Path, held.ClaimedAt.Format(time.RFC3339), held.State), nil)
		return noop, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if db, err := s.controlPlaneDB(); err == nil {
				if err := db.ReleaseProjectClaim(p.Path); err != nil {
					fmt.Fprintf(os.Stderr, "ui: release the claim on %s: %v\n", p.Path, err)
				}
				db.Close()
			}
		})
	}, true
}

// completeNewProject records that the claimed directory is now a project, and
// whether this hub made the directory itself.
func (s *Server) completeNewProject(p projectPlace, hubMade bool) error {
	db, err := s.controlPlaneDB()
	if err != nil {
		return err
	}
	defer db.Close()
	root := ""
	if hubMade {
		root = p.Root
	}
	return db.CompleteProjectClaim(p.Path, hubMade, root)
}

// hubMakes reports whether a creation at p.Path makes the directory itself,
// inside the projects root — the only directories ?delete_root=true may later
// remove. Asked before the directory is made.
func hubMakes(p projectPlace) bool {
	if p.Root == "" || !projectconfine.Within(p.Path, p.Root) {
		return false
	}
	_, err := os.Lstat(p.Path)
	return errors.Is(err, os.ErrNotExist)
}

// admitToRegistry registers the created project, re-checking the invariant
// against the registry as it stands under the registry's own lock: a row an
// operator added since the check — `cloop ui --projects` on another hub
// sharing this registry — is not something a claim in this control plane
// could have seen.
func (s *Server) admitToRegistry(r *http.Request, p projectPlace) error {
	cp := canonicalDir(s.WorkDir)
	return multiui.AdmitOwned(p.Path, s.sessionIdentity(r).OwnerKey(), func(existing []multiui.ProjectEntry) error {
		policy := projectconfine.Policy{ControlPlane: cp, ProjectsRoot: p.Root, Projects: projectDirsOf(existing)}
		_, err := policy.Check(p.Path)
		return err
	})
}

// auditProjectCreate records a creation or its refusal in the control plane.
func (s *Server) auditProjectCreate(r *http.Request, p projectPlace, detail map[string]any) {
	path := p.Path
	if path == "" {
		path = p.Requested
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["requested"] = p.Requested
	detail["name"] = filepath.Base(path)
	if p.Root != "" {
		detail["projects_root"] = p.Root
	}
	if owner := s.sessionIdentity(r).OwnerKey(); owner != "" {
		detail["owner"] = owner
	}
	s.auditProjectLifecycle(r, auditaction.ActionProjectCreate, path, detail)
}

// auditProjectLifecycle appends one project.create or project.delete row.
func (s *Server) auditProjectLifecycle(r *http.Request, action auditaction.Action, path string, detail map[string]any) {
	db, err := s.controlPlaneDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: audit %s for %s: %v\n", action, path, err)
		return
	}
	defer db.Close()
	statedb.AuditProjectLifecycle(db, statedb.ProjectAuditInput{
		Action: action,
		Path:   path,
		Actor:  s.auditActor(r),
		Detail: detail,
	})
	s.broadcastAuditAppend(action.String())
}

// ── At deletion ─────────────────────────────────────────────────────────────

// deletableRoot decides whether ?delete_root=true may remove a project's
// directory, and says why not when it may not.
//
// Only a directory this hub made itself, inside its projects root, recorded
// when it was made (claimNewProject → completeNewProject), and still that
// directory: not replaced by a link, not grown into a parent of another
// project, the hub or anything the invariant protects. An adopted directory —
// one that existed before its project did, or one an operator registered —
// is never the hub's to delete.
func (s *Server) deletableRoot(path string) (statedb.ProjectClaim, error) {
	canon := canonicalDir(path)
	db, err := s.controlPlaneDB()
	if err != nil {
		return statedb.ProjectClaim{}, err
	}
	claim, found, err := db.ProjectClaimAt(canon)
	db.Close()
	if err != nil {
		return statedb.ProjectClaim{}, err
	}
	if !found || claim.State != statedb.ProjectClaimCreated || !claim.HubMade {
		return claim, fmt.Errorf("this hub did not create %s, so it will not delete it: remove the project "+
			"without deleting its directory, then delete the directory yourself if you mean to", path)
	}
	if info, err := os.Lstat(path); err != nil || !info.IsDir() || canon != claim.Path {
		return claim, fmt.Errorf("%s is no longer the directory this hub created at %s, so it will not delete it",
			path, claim.Path)
	}
	if claim.Root == "" || !projectconfine.Within(claim.Path, canonicalDir(claim.Root)) {
		return claim, fmt.Errorf("%s is not inside the projects root it was created under, so it will not be deleted", path)
	}
	others := projectDirsOf(s.allProjectEntries())
	root, _ := projectsRootFrom(s.loadHubConfig())
	if _, err := existingRowPolicy(s.WorkDir, root, others).Check(claim.Path); err != nil {
		return claim, fmt.Errorf("%s will not be deleted: %v", path, err)
	}
	return claim, nil
}

// releaseProjectClaim drops a removed project's claim, so its path can be
// created again.
func (s *Server) releaseProjectClaim(path string) {
	db, err := s.controlPlaneDB()
	if err != nil {
		return
	}
	defer db.Close()
	if err := db.ReleaseProjectClaim(canonicalDir(path)); err != nil {
		fmt.Fprintf(os.Stderr, "ui: release the claim on %s: %v\n", path, err)
	}
}

// ── On the command line ─────────────────────────────────────────────────────

// OperatorProjectWarnings checks the directories an operator named on `cloop
// ui`'s command line (--projects, --scan) against the invariant, beside the
// projects already registered, and returns one warning per directory that
// breaks it. They are registered anyway — the operator owns the host and may
// mean it — and then flagged on the Projects tab and by `cloop hub doctor`,
// and refused at every dispatch until they are moved (Task 20418).
func OperatorProjectWarnings(workdir string, cfg *config.Config, paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	root, _ := projectsRootFrom(cfg, nil)
	registered, _ := multiui.Load()
	all := projectDirsOf(registered)
	for _, p := range paths {
		all = append(all, canonicalDir(p))
	}
	policy := existingRowPolicy(workdir, root, all)
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		canon := canonicalDir(p)
		if seen[canon] {
			continue
		}
		seen[canon] = true
		if _, err := policy.Check(p); err != nil {
			out = append(out, fmt.Sprintf("%s: %v — it is listed, but the hub will not run it until it is moved "+
				"(see `cloop hub doctor`)", p, err))
		}
	}
	return out
}
