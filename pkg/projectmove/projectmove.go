// Package projectmove decides what moving a project from the executor it is
// bound to onto another one would lose or break, before anything moves
// (Task 20493).
//
// A project's binding is one row (pkg/executor Registry.Binding, stored in the
// control plane's project_executors), and changing it only repoints the
// project's later dispatches. Work on the old side is left where it is: the
// hub's own tree, a remote device's working copy (which the device keeps
// between runs, under its agent's root, at DeviceWorkDir of the project's
// path), or an executor pool's runner volume. Preflight lists all of it, as
// findings, each with a severity and a remedy:
//
//   - blocker: the move must not happen until this is resolved. It would
//     interrupt a run, lose work that cannot be captured, or leave the
//     project on a target that cannot run it.
//   - will-carry: something the source holds that the move takes with it, or
//     that stays valid where the project goes. Nothing needs doing.
//   - warning: the move can go ahead, and this is lost, changed or could not
//     be checked.
//
// The findings answer seven questions: (a) whether a run is active, paused or
// waiting at a human review gate; (b) whether the source's working trees hold
// uncommitted changes or untracked files; (c) whether local branches hold
// commits no remote has; (d) which files under .cloop no database holds; (e)
// whether the source can be reached at all, and with AbandonSource, exactly
// what is lost by not capturing it; (f) whether the target can run the project
// — the caller on its access list, a harness credential for a sandboxed
// target, the project's secret grants, firewall rules, devices and isolation
// demands valid there; and (g) which bindings are keyed by the project's path.
//
// # What a move is assumed to do
//
// The severities describe the move the rest of this work builds: quiesce the
// project, capture the source (its working trees, its commits and its .cloop
// files) as a bundle, switch the binding, seed the target and verify it. So
// what can be captured and delivered is will-carry; what cannot be captured
// — a source the hub cannot reach or read — or cannot be delivered — work a
// Pod would never see, because it builds its tree from the forge — is a
// blocker or a warning. The project's path does not change: it is the
// project's identity on the hub, and a device derives its working copy's name
// from it.
//
// # Reading only
//
// Preflight changes nothing. It reads through Env, which the hub implements
// over its databases, its executor registry and the request's caller; nothing
// it calls starts a workload, mints or leases a credential, rewrites a rule or
// writes a row. The hub tree is read with hardened, lock-free git
// (pkg/executor/gitstate) and a stat-only walk (InventoryFiles).
package projectmove

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
)

// Project is the project a move is for, as the hub registers it.
type Project struct {
	Name string `json:"name"`
	// Path is the project's directory on the hub, which is its identity:
	// bindings, grants and policy are keyed by it.
	Path string `json:"path"`
}

// Feature is one of a project's parallel features: a worktree inside the
// project, with its own runs.
type Feature struct {
	Slug string `json:"slug"`
	Path string `json:"path"`
}

// Options adjusts a preflight.
type Options struct {
	// AbandonSource asks what a move that does not capture its source would
	// lose — the way off a device that is gone for good. An unreachable
	// source is then a warning rather than a blocker, and everything the
	// source holds is reported as lost rather than carried.
	AbandonSource bool
	// Quiesce describes a move that stops the project's runs itself, as Move
	// does (Task 20494): a run executing, one waiting in a pool's queue and a
	// restart the hub has scheduled are then what the move resolves rather
	// than blockers. A run a pool's runner was just handed still blocks: it
	// cannot be taken back.
	Quiesce bool
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// ProbeTimeout bounds each reachability probe; zero means
	// DefaultProbeTimeout.
	ProbeTimeout time.Duration
}

// DefaultProbeTimeout bounds asking an executor whether it answers.
const DefaultProbeTimeout = 10 * time.Second

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Env is what Preflight reads. The hub implements it (pkg/ui); tests fake it.
//
// Methods that answer about the caller (Audience, and the pool access in
// Pool) answer for whoever asked for the preflight: a move is planned by a
// person, and the target must be one they may use.
type Env interface {
	// Executor returns a registered executor by ID.
	Executor(id string) (executor.Executor, error)
	// DefaultExecutor returns the executor a project with no binding runs on.
	DefaultExecutor() (executor.Executor, error)
	// HostExecutionAllowed reports the hub's executors.allow_host_process.
	HostExecutionAllowed() bool
	// Binding returns the project's binding: an executor ID, pool:<id>, or
	// "" when it has none.
	Binding(ctx context.Context, project Project) (string, error)
	// Reachable reports whether ex answers now: nil when it does.
	Reachable(ctx context.Context, ex executor.Executor) error
	// DeviceRoot returns the directory a device's agent keeps working copies
	// under, as it last reported it; "" when unknown.
	DeviceRoot(ctx context.Context, deviceID string) string
	// Features lists the project's features.
	Features(ctx context.Context, project Project) ([]Feature, error)
	// Runs returns what the hub knows about the runs of the project or
	// feature at path.
	Runs(ctx context.Context, path string) RunFacts
	// SourceTree reads what the source's working copy holds: its git state
	// and its .cloop files, and its features'. For a source on the hub's own
	// filesystem ReadHubTree is the implementation; a source whose working
	// copy the hub cannot read answers ErrUnseen.
	SourceTree(ctx context.Context, project Project, features []Feature, source Endpoint) (Tree, error)
	// Pool returns what the hub knows about an executor pool, for this
	// project and caller.
	Pool(ctx context.Context, poolID string, project Project) (PoolFacts, error)
	// Audience reports whether the caller is on executorID's access list.
	Audience(ctx context.Context, executorID string) (bool, error)
	// HarnessCredential reports whether a run of the project on target
	// would receive the credential its harness needs.
	HarnessCredential(ctx context.Context, project Project, target executor.Executor) (HarnessFacts, error)
	// Grants lists the project's active secret grants, each with whether it
	// reaches the source and the target. source is nil for a pool or an
	// unregistered source.
	Grants(ctx context.Context, project Project, source, target executor.Executor) ([]GrantFacts, error)
	// Firewall returns the project's stored firewall rules and the rules
	// that govern target.
	Firewall(ctx context.Context, project Project, target executor.Executor) (FirewallFacts, error)
	// ForwardedDevices lists the forwarded-device bindings that apply to the
	// project, and whether each forwarder is online.
	ForwardedDevices(ctx context.Context, project Project) ([]ForwardedFacts, error)
	// VirtualDevices lists the host devices a virtual executor passes into
	// every sandbox; nil for any other executor.
	VirtualDevices(ctx context.Context, executorID string) []string
	// TakesForwarded reports nil when target can give a run forwarded
	// devices of these kinds ("usb", "l2"), and otherwise why not.
	TakesForwarded(ctx context.Context, target executor.Executor, kinds []string) error
	// SandboxRequirements returns the placement requirements the project's
	// .cloop/sandbox.yaml demands.
	SandboxRequirements(ctx context.Context, project Project) (executor.Requirements, error)
	// Workspace reports what would stop the hub handing target the source of
	// the project and of each feature; none when it can.
	Workspace(ctx context.Context, project Project, features []Feature, target executor.Executor) []WorkspaceIssue
	// PathBindings lists the hub's records keyed by the project's path.
	PathBindings(ctx context.Context, project Project) ([]PathBinding, error)
}

// Tree is what the project's directory on the hub holds.
type Tree struct {
	// Git is the repository's state: what its working trees hold and which
	// commits no remote has.
	Git GitState
	// Files is the project's own .cloop inventory; FeatureFiles each
	// feature's, by slug.
	Files        FileInventory
	FeatureFiles map[string]FileInventory
}

// PoolFacts is what the hub knows about an executor pool.
type PoolFacts struct {
	// Found reports the pool exists; nothing else is set when it does not.
	Found bool
	Name  string
	// Revoked reports the pool was revoked: it takes no more runs.
	Revoked bool
	// Admitted reports the caller is on the pool's access list; AudienceErr
	// says why that could not be read.
	Admitted    bool
	AudienceErr string
	// OwnerMayRead is false when the pool belongs to someone who may not
	// read the project: its runners would hold the project's code.
	OwnerMayRead bool
	// Fits is why the pool's runners cannot meet the project's
	// requirements, or "" when they can.
	Fits string
	// Template is an executor shaped like the pool's runners, for the
	// checks that need one; nil when unknown.
	Template executor.Executor
	// Tenant is the tenant the project's runs would hold the pool's volumes
	// under.
	Tenant string
}

// HarnessFacts is whether a run on an executor would get its harness's
// credential.
type HarnessFacts struct {
	// Applies is false when no credential is needed there: a provider with
	// no login, an executor sharing the hub's home, or one exempted.
	Applies bool
	// State is "ok", "expiring" or "missing" when Applies.
	State string
	// Provider is the harness's provider (claudecode, copilot).
	Provider string
	// Detail and Remedy are the hub's own explanation of a refusal.
	Detail string
	Remedy string
	// Sources names the grants that satisfy it, when State is ok.
	Sources []string
}

// Harness credential states.
const (
	HarnessOK       = "ok"
	HarnessExpiring = "expiring"
	HarnessMissing  = "missing"
)

// GrantFacts is one active secret grant that reaches the project somewhere.
type GrantFacts struct {
	ID        string
	SecretRef string
	// Kind is the secret's kind (secretbroker.Kind: env, github_pat,
	// kubeconfig, host_device, ...).
	Kind string
	// Subject is the grant's subject as written: project:<path>,
	// executor:<id>, label:<k=v,...>.
	Subject   string
	ExpiresAt time.Time
	// ReachesSource and ReachesTarget report whether a run of the project on
	// each end would be issued this grant.
	ReachesSource bool
	ReachesTarget bool
	// Files reports the grant is delivered as files: a credential helper, a
	// token file, a kubeconfig.
	Files bool
	// Devices and Interfaces are the host devices and network interfaces a
	// host_device or host_interface grant passes through.
	Devices    []string
	Interfaces []string
	// HostPath reports a local_repo grant: a directory on the hub bound into
	// the sandbox.
	HostPath bool
}

// FirewallFacts is the project's firewall against a target's.
type FirewallFacts struct {
	// Project is the project's stored rule set; nil when it has none.
	Project *fwpolicy.Rules
	// Target is the rule set that governs the target — its configuration,
	// its device's rules and a virtual executor's own, chained; nil when
	// nothing bounds it.
	Target *fwpolicy.Rules
	// Enforceable reports the target can install a firewall;
	// RemovesNetwork that it can at least take the network away. Reason
	// says why it cannot enforce, when it cannot.
	Enforceable    bool
	RemovesNetwork bool
	Reason         string
	// Error is why the target's rules could not be composed, when they
	// could not.
	Error string
}

// ForwardedFacts is one forwarded device bound to the project.
type ForwardedFacts struct {
	ID string
	// Name is what the device is called; Kind is "usb" or "l2".
	Name string
	Kind string
	// Forwarder is the edge device that forwards it, and Online whether it
	// is connected now.
	Forwarder string
	Online    bool
	// Executor scopes the binding to one executor; "" applies it anywhere.
	Executor string
}

// WorkspaceIssue is one reason the hub could not hand a target the source of
// the project or of one of its features.
type WorkspaceIssue struct {
	// Who is "the project" or "feature <slug>".
	Who     string
	Problem string
	Remedy  string
}

// PathBinding is one kind of record the hub keys by the project's path.
type PathBinding struct {
	// Store names where the records live: a table, a file, a metadata key.
	Store string
	// What says what they are.
	What string
	// Count is how many there are.
	Count int
}

// ErrFeature refuses a preflight for a feature: a feature runs where its
// project is bound and moves with it.
var ErrFeature = errors.New("projectmove: a feature moves with its project")

// ErrInvalidProject refuses a preflight for a project the request named
// wrongly.
var ErrInvalidProject = errors.New("projectmove: invalid project")

// Preflight reports what moving project onto target would lose or break.
// target is a binding string: an executor ID, pool:<id>, or "local"; see
// ParseTarget.
//
// An error means the preflight could not be made at all — the target is not a
// binding (ErrInvalidTarget), the project is a feature (ErrFeature), or the
// hub could not say where the project is bound now. Everything else, including
// a check that could not be completed, is a finding.
func Preflight(ctx context.Context, env Env, project Project, target string, opts Options) (*Report, error) {
	if env == nil {
		return nil, errors.New("projectmove: no environment")
	}
	project.Path = strings.TrimSpace(project.Path)
	if project.Path == "" || !filepath.IsAbs(project.Path) {
		return nil, fmt.Errorf("%w: %q is not an absolute path", ErrInvalidProject, project.Path)
	}
	project.Path = filepath.Clean(project.Path)
	if parent, _, ok := feature.ParentOf(project.Path); ok {
		return nil, fmt.Errorf("%w: run the preflight on %s", ErrFeature, parent)
	}
	if project.Name == "" {
		project.Name = filepath.Base(project.Path)
	}
	tgt, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}
	p := &preflight{ctx: ctx, env: env, project: project, target: tgt, opts: opts, now: opts.now()}
	if err := p.run(); err != nil {
		return nil, err
	}
	return p.report, nil
}

// preflight is one run of Preflight.
type preflight struct {
	ctx     context.Context
	env     Env
	project Project
	target  Target
	opts    Options
	now     time.Time

	report   *Report
	features []Feature

	// The source: its binding, its executor (nil for a pool or one that is
	// not registered), its pool.
	sourceBinding string
	sourceEx      executor.Executor
	sourcePool    *PoolFacts
	sourceErr     string

	// The target: its executor, or the pool and its runners' template.
	targetEx   executor.Executor
	targetPool *PoolFacts
	// targetOK is false once the target is known to be unusable, which ends
	// the checks that need one.
	targetOK bool
}

func (p *preflight) add(f Finding) { p.report.Findings = append(p.report.Findings, f) }

func (p *preflight) run() error {
	p.report = &Report{Project: p.project, AbandonSource: p.opts.AbandonSource, CheckedAt: p.now.UTC()}
	binding, err := p.env.Binding(p.ctx, p.project)
	if err != nil {
		return fmt.Errorf("projectmove: where %s is bound now: %w", p.project.Path, err)
	}
	p.sourceBinding = strings.TrimSpace(binding)
	if feats, err := p.env.Features(p.ctx, p.project); err != nil {
		p.add(Finding{
			Kind: KindRun, Severity: SeverityBlocker, Side: SideSource,
			Title:   "Could not list the project's features",
			Message: "The project's features could not be listed: " + err.Error() + ". Each feature has runs and a worktree of its own, and none of them was checked.",
			Remedy:  "Fix what stops the hub reading .cloop/features, then run the preflight again.",
		})
	} else {
		p.features = feats
	}

	p.resolveSource()
	p.resolveTarget()

	p.checkRuns()
	p.checkSource()
	if p.targetOK {
		p.checkTarget()
	}
	p.checkPathBindings()
	p.report.finish()
	return nil
}

// probeCtx bounds one reachability probe.
func (p *preflight) probeCtx() (context.Context, context.CancelFunc) {
	d := p.opts.ProbeTimeout
	if d <= 0 {
		d = DefaultProbeTimeout
	}
	return context.WithTimeout(p.ctx, d)
}

// checkRuns is (a), for the project and each of its features.
func (p *preflight) checkRuns() {
	for _, f := range checkRuns("the project", p.env.Runs(p.ctx, p.project.Path), p.opts.Quiesce) {
		p.add(f)
	}
	for _, ft := range p.features {
		for _, f := range checkRuns("feature "+ft.Slug, p.env.Runs(p.ctx, ft.Path), p.opts.Quiesce) {
			p.add(f)
		}
	}
}

// checkPathBindings is (g).
func (p *preflight) checkPathBindings() {
	bindings, err := p.env.PathBindings(p.ctx, p.project)
	if err != nil {
		p.add(Finding{
			Kind: KindPathBindings, Severity: SeverityWarning, Side: SideProject,
			Title:   "Could not list the records keyed by the project's path",
			Message: "Reading the hub's records keyed by " + p.project.Path + " failed: " + err.Error() + ".",
			Remedy:  "Nothing is lost by this: a move keeps the project's path. Run the preflight again to see them listed.",
		})
		return
	}
	var items []Item
	total := 0
	for _, b := range bindings {
		if b.Count <= 0 {
			continue
		}
		total += b.Count
		items = append(items, Item{Name: b.Store, Count: b.Count, Detail: b.What})
	}
	if len(items) == 0 {
		return
	}
	p.add(Finding{
		Kind: KindPathBindings, Severity: SeverityWillCarry, Side: SideProject,
		Title: fmt.Sprintf("%d record(s) are keyed by the project's path", total),
		Message: "Knowledge and policy records name the project by its path, " + p.project.Path +
			". A move keeps that path — it is the project's identity on the hub, and a device names its working copy after it — so every one of them stays valid. " +
			"A move that changed the path would have to rewrite each of these. " +
			"The project's requirements name no path: they are kept in its own database, and its spec file is named relative to the project, so they move with it.",
		Items: items,
	})
}
