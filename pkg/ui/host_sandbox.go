package ui

// host_sandbox.go decides which workloads the hub forks on its own host run in
// the host sandbox, and what each may reach (Task 20480).
//
// pkg/hostsandbox is the mechanism: Landlock, no_new_privs, and on a hub
// running as root fresh namespaces and a capability bounding set. This file is
// the policy. A hub with sign-in serves several people, and the host-process
// driver forks every one of their runs as the hub's own user — so without the
// sandbox one person's agent could read every other person's projects, their
// Claude logins under the identity root, the lease files of their runs and the
// hub's database. With it, a run reaches the files of its own project and of
// the person it acts for, and the system's read-only directories.
//
// Who is sandboxed is executors.host_sandbox.mode:
//
//   - auto (the default): on a hub with sign-in, every dispatch acting for a
//     person who is not a hub administrator. Administrators configure the
//     executors and this setting itself, and their runs keep the host as
//     before; without sign-in there is one person and nobody to keep apart.
//   - all: every dispatch that acts for anyone, administrators and the hub's
//     own login included.
//   - off: none.
//
// The hub's own directory cannot be sandboxed from itself: its run needs the
// project's state, and that state is the control plane. A dispatch of it that
// the mode would sandbox is refused instead, which on an auto hub leaves it to
// the administrators.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/provider/claudecode"
	"github.com/blechschmidt/cloop/pkg/provider/copilot"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// sandboxHomeDir is the home a person's sandboxed runs share, inside their
// Claude home, so that what removes the one — offboarding, the sweep of denied
// identities — removes the other.
const sandboxHomeDir = "sandbox-home"

// hostSandboxModeOverride replaces the configured mode for a test whose
// fixture runs people's work on the hub's own directory, which the sandbox
// refuses, to test something the sandbox does not change. Nil in production.
var hostSandboxModeOverride atomic.Pointer[string]

// hostSandboxSettings reads executors.host_sandbox from the hub's own
// configuration. A configuration that cannot be read gives the default,
// which sandboxes people.
func hostSandboxSettings() config.HostSandboxConfig {
	var hs config.HostSandboxConfig
	if cfg, err := controlPlaneConfig(); err == nil && cfg != nil {
		hs = cfg.Executors.HostSandbox
	}
	if m := hostSandboxModeOverride.Load(); m != nil {
		hs.Mode = *m
	}
	return hs
}

// sandboxesWho reports whether mode puts a dispatch of project acting for who
// in the host sandbox. A dispatch with no clearance at all — `cloop init` for
// a new project, a version probe — runs cloop's own code for nobody and is
// never sandboxed.
func sandboxesWho(mode string, clear *harnessClearance, project string) bool {
	if clear == nil {
		return false
	}
	return sandboxesPerson(mode, clear.who, project)
}

// sandboxesPerson is sandboxesWho for a person.
//
// Under auto a hub administrator's dispatch — and one acting for no one, the
// static token's or the hub's own — is left on the host only for a project
// that nobody whose runs are sandboxed may write. Otherwise it would run, with
// the hub's whole filesystem, whatever such a person's agent left in the
// project: a hook in .claude/settings.json, a git hook, a build script.
func sandboxesPerson(mode string, who harnessWho, project string) bool {
	switch mode {
	case config.HostSandboxOff:
		return false
	case config.HostSandboxAll:
		return true
	}
	// auto, and anything Validate let through
	if !who.personal {
		return false
	}
	if who.identity != "" && !who.hubAdmin {
		return true
	}
	return project != "" && hostSandboxExposure(project)
}

// hostSandboxExposureFn answers whether people whose runs are sandboxed may
// write a project; set by the Server that bootstrapped the control plane.
var hostSandboxExposureFn atomic.Pointer[func(string) bool]

func setHostSandboxExposure(fn func(string) bool) {
	if fn == nil {
		hostSandboxExposureFn.Store(nil)
		return
	}
	hostSandboxExposureFn.Store(&fn)
}

// hostSandboxExposure is the installed answer, or true when no Server has
// installed one: a dispatch nothing can vouch for is sandboxed.
func hostSandboxExposure(project string) bool {
	fn := hostSandboxExposureFn.Load()
	if fn == nil {
		return true
	}
	return (*fn)(project)
}

// hostSandboxRefusal refuses a dispatch the host sandbox cannot be given.
type hostSandboxRefusal struct {
	Project string
	Reason  string
}

func (e *hostSandboxRefusal) Error() string {
	return fmt.Sprintf("%s cannot run in the host sandbox: %s", e.Project, e.Reason)
}

// Unwrap makes the refusal an unsupported dispatch, which the dashboard
// answers with 409 and its reason.
func (e *hostSandboxRefusal) Unwrap() error { return executor.ErrUnsupported }

// applyHostSandbox puts a dispatch to an executor that shares this host in the
// host sandbox when the policy says its person needs one. It runs after every
// step that shapes the environment, and before the dispatch is recorded and
// started: the sandbox's grants are worked out from the person and the lease,
// never from what the environment says, so no grant can point a run at another
// person's files.
func applyHostSandbox(spec executor.Spec, ex executor.Executor, workDir string, clear *harnessClearance, lease *secretLease) (executor.Spec, error) {
	if ex == nil || executor.IsolatesFromHost(ex) {
		return spec, nil
	}
	settings := hostSandboxSettings()
	mode := settings.EffectiveMode()
	project := dispatchProject(workDir)
	if !sandboxesWho(mode, clear, project) {
		return spec, nil
	}
	if cp := strings.TrimSpace(controlPlaneDir()); cp != "" && sameDir(project, cp) {
		reason := "it is the hub's own directory, which holds the control plane — the database every " +
			"person's sealed credentials and sessions are in — and a run of it needs that state. "
		if mode == config.HostSandboxAll {
			reason += "With executors.host_sandbox.mode all, nobody may run it on the hub's host: " +
				"bind it to a container executor."
		} else {
			reason += "Only a hub administrator may run it on the hub's host."
		}
		return spec, &hostSandboxRefusal{Project: project, Reason: reason}
	}
	sb, err := buildHostSandbox(project, clear.who, lease, settings.ReadOnly)
	if err != nil {
		return spec, err
	}
	sb.PassEnv = append([]string(nil), settings.PassEnv...)
	spec.HostSandbox = sb
	labels := make(map[string]string, len(spec.Labels)+1)
	for k, v := range spec.Labels {
		labels[k] = v
	}
	labels[executor.LabelHostSandbox] = "on"
	spec.Labels = labels
	return spec, nil
}

// buildHostSandbox works out what a sandboxed dispatch of project acting for
// who may reach beyond its work directory and the system's directories.
func buildHostSandbox(project string, who harnessWho, lease *secretLease, extra []string) (*executor.HostSandbox, error) {
	sb := &executor.HostSandbox{Person: who.identity, ReadWrite: []string{project}}
	if who.identity != "" {
		home, err := claudecodeauth.HomePath(who.identity)
		if err != nil {
			return nil, &hostSandboxRefusal{Project: project, Reason: "no Claude home can be named for " +
				who.identity + ": " + err.Error()}
		}
		// The person's Claude home — Copilot's is inside it — and the home
		// directory their sandboxed runs share, made here and never anywhere
		// else. A person without a Claude home (they never signed in on this
		// hub's host, or were offboarded) gets neither: their run has a fresh
		// home for itself alone, and no login to find in it.
		if fi, err := os.Stat(home); err == nil && fi.IsDir() {
			sandboxHome, err := prepareSandboxHome(home)
			if err != nil {
				return nil, fmt.Errorf("prepare the sandbox home of %s: %w", who.identity, err)
			}
			sb.ReadWrite = append(sb.ReadWrite, home)
			sb.Home = sandboxHome
		}
	} else if claudeDir := hubClaudeDir(); claudeDir != "" {
		// The hub's own login, for a dispatch acting for no one under mode
		// all: its Claude directory and nothing else of the hub user's home,
		// named in the environment because the run's HOME is not the hub
		// user's.
		if fi, err := os.Stat(claudeDir); err == nil && fi.IsDir() {
			sb.ReadWrite = append(sb.ReadWrite, claudeDir)
			sb.Env = append(sb.Env, "CLAUDE_CONFIG_DIR="+claudeDir)
		}
	}
	// Repositories the lease opened on this host, as their grants say: on the
	// host, a read-only local_repo grant used to be advice the run could
	// ignore, and here it is enforced.
	for _, m := range lease.Mounts() {
		if m.ReadOnly {
			sb.ReadOnly = append(sb.ReadOnly, m.Source)
		} else {
			sb.ReadWrite = append(sb.ReadWrite, m.Source)
		}
	}
	path, ro := harnessInstallations()
	sb.Path = path
	sb.ReadOnly = append(sb.ReadOnly, ro...)
	kept, _ := safeSandboxExtras(extra, project)
	sb.ReadOnly = append(sb.ReadOnly, kept...)
	return sb, nil
}

// prepareSandboxHome makes sure sandbox-home inside a person's Claude home is
// a directory. The person's runs may write their Claude home, so an earlier
// one could have replaced it with a link or a file: that is removed — the
// link, never what it points to — and a directory made in its place. The
// helper does not follow a link out of the home either (pkg/hostsandbox
// openGrant); this keeps the run working rather than refused.
func prepareSandboxHome(home string) (string, error) {
	dir := filepath.Join(home, sandboxHomeDir)
	if fi, err := os.Lstat(dir); err == nil && !fi.IsDir() {
		if err := os.Remove(dir); err != nil {
			return "", err
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	return dir, nil
}

// hubClaudeDir is where the hub's own Claude login lives: CLAUDE_CONFIG_DIR
// in its environment, or ~/.claude.
func hubClaudeDir() string {
	if d := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); filepath.IsAbs(d) {
		return filepath.Clean(d)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".claude")
	}
	return ""
}

// harnessInstallations finds the harness binaries the way a run does, in the
// hub's own environment, and returns the directories to put in front of the
// sandboxed run's PATH (where each was found) and to let it read and execute
// (where each really is). A sandboxed run's HOME is not the hub user's, so the
// installers' locations under that home no longer lead to them.
func harnessInstallations() (path, readOnly []string) {
	for _, found := range []string{claudecode.FindBinary(), copilot.FindBinary()} {
		if !filepath.IsAbs(found) {
			continue // not installed on this host: the run reports it by name
		}
		path = append(path, filepath.Dir(found))
		resolved, err := filepath.EvalSymlinks(found)
		if err != nil {
			continue
		}
		readOnly = append(readOnly, filepath.Dir(resolved))
	}
	return path, readOnly
}

// safeSandboxExtras splits executors.host_sandbox.read_only into what may be
// granted to a sandboxed dispatch of project and what would hand it the hub's
// files or another person's: the filesystem's root, the control plane, the
// identity root holding every person's Claude login, another registered
// project, or a directory above any of them.
func safeSandboxExtras(extra []string, project string) (kept, dropped []string) {
	protected := []string{}
	if cp := strings.TrimSpace(controlPlaneDir()); cp != "" {
		protected = append(protected, filepath.Clean(cp))
	}
	if root, err := claudecodeauth.HomeRootPath(); err == nil {
		protected = append(protected, filepath.Clean(root))
	}
	for _, d := range registeredProjectDirs() {
		if d = filepath.Clean(d); d != project {
			protected = append(protected, d)
		}
	}
	resolved := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	for i, p := range protected {
		protected = append(protected, resolved(p))
		_ = i
	}
	for _, e := range extra {
		e = filepath.Clean(strings.TrimSpace(e))
		real := resolved(e)
		bad := !filepath.IsAbs(e) || e == "/" || real == "/"
		for _, p := range protected {
			if bad || pathWithin(e, p) || pathWithin(p, e) || pathWithin(real, p) || pathWithin(p, real) {
				bad = true
				break
			}
		}
		if bad {
			dropped = append(dropped, e)
		} else {
			kept = append(kept, e)
		}
	}
	return kept, dropped
}

// repoGrantRefusal refuses a dispatch whose lease would open, as a local
// repository, a directory that is the hub's or another person's.
type repoGrantRefusal struct {
	Repo, Source, Reason string
}

func (e *repoGrantRefusal) Error() string {
	return fmt.Sprintf("the local_repo grant %q names %s, which %s; a person's run is never given it, on any "+
		"executor — grant the repository's own directory instead", e.Repo, e.Source, e.Reason)
}

// Unwrap makes the refusal an unsupported dispatch, answered with 409.
func (e *repoGrantRefusal) Unwrap() error { return executor.ErrUnsupported }

// checkRepoGrants refuses a dispatch acting for a person who is not a hub
// administrator whose lease opens, as a local repository, a directory that is
// not theirs to give a run: the filesystem's root, the hub's own directory,
// the identity root that holds every person's Claude login, or another
// person's project — or a directory above one of them. A local_repo secret is
// a path anyone with secret.own may mint and grant to their own project, so
// without this one person could mount another's project, or the control
// plane, into their sandbox. A project the person owns may be granted to
// another of theirs.
func checkRepoGrants(lease *secretLease, workDir string, clear *harnessClearance) error {
	if clear == nil {
		return nil
	}
	return checkRepoMounts(lease.Mounts(), workDir, clear.who)
}

// checkRepoMounts is checkRepoGrants for the mounts a lease opened.
func checkRepoMounts(mounts []secretbroker.RepoMount, workDir string, who harnessWho) error {
	if !who.personal || who.identity == "" || who.hubAdmin || len(mounts) == 0 {
		return nil
	}
	own := dispatchProject(workDir)
	type protectedPath struct{ path, reason string }
	var protected []protectedPath
	if cp := strings.TrimSpace(controlPlaneDir()); cp != "" {
		protected = append(protected, protectedPath{cp, "holds the hub's control plane"})
	}
	if root, err := claudecodeauth.HomeRootPath(); err == nil {
		protected = append(protected, protectedPath{root, "holds every person's Claude login"})
	}
	projectListSource.mu.RLock()
	fn := projectListSource.fn
	projectListSource.mu.RUnlock()
	var entries []multiui.ProjectEntry
	if fn != nil {
		entries = fn()
	} else {
		entries, _ = multiui.Load()
	}
	for _, e := range entries {
		abs, err := filepath.Abs(e.Path)
		if err != nil || sameDir(abs, own) {
			continue
		}
		if e.Owner != "" && ownedBy(e.Owner, who.identity) {
			continue
		}
		protected = append(protected, protectedPath{abs, "is another project on this hub"})
	}
	resolve := func(p string) string {
		p = filepath.Clean(p)
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	for _, m := range mounts {
		src := resolve(m.Source)
		if src == "/" {
			return &repoGrantRefusal{Repo: m.Name, Source: m.Source, Reason: "is the root of the filesystem"}
		}
		for _, p := range protected {
			pp := resolve(p.path)
			if pathWithin(src, pp) || pathWithin(pp, src) {
				reason := p.reason
				if pathWithin(pp, src) && pp != src {
					reason = "contains " + pp + ", which " + p.reason
				}
				return &repoGrantRefusal{Repo: m.Name, Source: m.Source, Reason: reason}
			}
		}
	}
	return nil
}

// pathWithin reports whether path is dir or beneath it.
func pathWithin(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// hostSandboxApplies reports whether who's dispatches of workDir to the hub's
// host run in the host sandbox — for a call the hub would make in its own
// process, where there is no sandbox to make it in.
func hostSandboxApplies(who harnessWho, workDir string) bool {
	return sandboxesPerson(hostSandboxSettings().EffectiveMode(), who, dispatchProject(workDir))
}

// dispatchProject is the project directory a dispatch of workDir works in: a
// feature's parent, and for a dispatch that names none — the voice modal's
// `cloop listen`, which carries out what it heard where the hub runs — the
// hub's own working directory, which the host driver gives it.
func dispatchProject(workDir string) string {
	if strings.TrimSpace(workDir) == "" {
		if cwd, err := os.Getwd(); err == nil {
			return filepath.Clean(cwd)
		}
		return ""
	}
	return filepath.Clean(policyProjectPath(workDir))
}

// projectExposedToSandboxedPeople reports whether somebody whose runs on this
// host are sandboxed may write project, so that an administrator's run of it
// must be sandboxed too. It answers from the access model's own facts — the
// owner, the people and teams it is shared with, and the role policy — and
// errs towards yes: a fact it cannot read sandboxes the run.
func (s *Server) projectExposedToSandboxedPeople(project string) bool {
	if !s.oidcEnabled() {
		return false
	}
	// The hub's own directory: nobody whose runs are sandboxed may run it.
	if primary := s.primaryProjectPath(); primary != "" && sameDir(project, primary) {
		return false
	}
	// Without a role policy everyone who signs in may run anything.
	if !s.authzActive() {
		return true
	}
	runs := func(role string) bool { return authz.Role(role).AtLeast(authz.RoleOperator) }
	owner := s.projectOwner(project)
	if owner != "" && !s.ownerKeyIsHubAdmin(owner) {
		return true
	}
	names := map[string]bool{strings.ToLower(project): true, strings.ToLower(filepath.Base(project)): true}
	for _, e := range s.allProjectEntries() {
		if abs, err := filepath.Abs(e.Path); err == nil && sameDir(abs, project) && e.Name != "" {
			names[strings.ToLower(e.Name)] = true
		}
	}
	reaches := func(bindingProject string) bool {
		if bindingProject == "" {
			return owner == "" // a hub-wide role reaches only a project nobody owns
		}
		return names[strings.ToLower(strings.TrimSpace(bindingProject))]
	}
	if owner == "" && runs(string(s.Authz.DefaultRole())) {
		return true
	}
	for _, b := range s.Authz.ConfiguredBindings() {
		if b.Deny || b.Executor != "" || !runs(string(b.Role)) || !reaches(b.Project) {
			continue
		}
		// A hub-wide admin is an administrator, whose runs are not the
		// sandboxed ones; anything less, or admin on one project, is.
		if b.Project == "" && b.Role == authz.RoleAdmin {
			continue
		}
		return true
	}
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		return true
	}
	defer db.Close() //nolint:errcheck
	runtime, err := db.ListRoleBindings()
	if err != nil {
		return true
	}
	for _, b := range runtime {
		if b.Effect == "deny" || b.Executor != "" || !runs(b.Role) || !reaches(b.Project) {
			continue
		}
		if b.Project == "" && authz.Role(b.Role) == authz.RoleAdmin {
			continue
		}
		return true
	}
	members, err := db.ListProjectMembers()
	if err != nil {
		return true
	}
	for _, m := range members {
		if !sameDir(m.ProjectPath, project) || !runs(m.Role) {
			continue
		}
		if strings.HasPrefix(m.IdentityKey, "team:") || !s.ownerKeyIsHubAdmin(m.IdentityKey) {
			return true
		}
	}
	return false
}

// ownerKeyIsHubAdmin reports whether the person an owner key names is a hub
// administrator, for a dispatch with no request to ask: an automatic resume,
// a failover. It knows what the key says — the address admin_emails and the
// role mappings match, or the subject — and not the groups a session would
// carry, so an administrator by group alone is not one here, and their
// resumed run is sandboxed like anyone's.
func (s *Server) ownerKeyIsHubAdmin(owner string) bool {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return false
	}
	id := &oidcauth.Identity{}
	if sub, ok := strings.CutPrefix(owner, "sub:"); ok {
		id.Sub = sub
	} else {
		id.Email = owner
	}
	return s.identityIsHubAdmin(id)
}

// errHostSandboxRefused is how tests and callers recognise the refusal.
var errHostSandboxRefused = errors.New("host sandbox refused")

// Is lets errors.Is find a refusal by errHostSandboxRefused.
func (e *hostSandboxRefusal) Is(target error) bool { return target == errHostSandboxRefused }
