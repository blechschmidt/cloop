package projectmove

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitstate"
)

// GitState is what a repository on the hub holds that its remotes do not.
type GitState = gitstate.State

// ErrUnseen is what Env.SourceTree answers for a source whose working copy the
// hub cannot read: a device's, or a pool runner volume's.
var ErrUnseen = errors.New("projectmove: the hub cannot read this source's working copy")

// parented is implemented by a virtual executor, which runs on a device.
type parented interface{ ParentID() string }

// deviceOf returns the device an executor's work lands on: its parent for a
// virtual executor, itself otherwise.
func deviceOf(ex executor.Executor) string {
	if v, ok := ex.(parented); ok {
		if id := strings.TrimSpace(v.ParentID()); id != "" {
			return id
		}
	}
	return ex.ID()
}

// describeExecutor fills an endpoint from the executor it resolves to, and
// says where the project's work lives there.
func (p *preflight) describeExecutor(e *Endpoint, ex executor.Executor) {
	e.ExecutorID = ex.ID()
	e.Kind = ex.Kind()
	if v, ok := ex.(parented); ok {
		e.Parent = strings.TrimSpace(v.ParentID())
	}
	caps := ex.Capabilities()
	switch {
	case caps.SharesHostFilesystem:
		e.Workspace = WorkspaceHubTree
		e.WorkDir = p.project.Path
	case ex.Kind() == executor.KindKubernetes:
		e.Workspace = WorkspaceEphemeral
	case ex.Kind() == executor.KindRemoteAgent || ex.Kind() == executor.KindVirtual || e.Parent != "":
		e.Workspace = WorkspaceDevice
		name := executor.DeviceWorkDir(p.project.Path)
		if root := strings.TrimSpace(p.env.DeviceRoot(p.ctx, deviceOf(ex))); root != "" {
			e.WorkDir = path.Join(root, name)
		} else {
			e.WorkDir = "<agent root>/" + name
		}
	}
}

// resolveSource works out where the project runs now.
func (p *preflight) resolveSource() {
	src := Endpoint{Binding: p.sourceBinding}
	if poolID, isPool := executor.PoolOf(p.sourceBinding); isPool {
		src.PoolID, src.Kind, src.Workspace = poolID, "pool", WorkspacePool
		pf, err := p.env.Pool(p.ctx, poolID, p.project)
		switch {
		case err != nil:
			p.sourceErr = fmt.Sprintf("executor pool %s could not be read: %v", poolID, err)
		case !pf.Found:
			p.sourceErr = fmt.Sprintf("executor pool %s no longer exists on this hub", poolID)
		default:
			p.sourcePool = &pf
			src.Name = pf.Name
		}
		p.report.Source = src
		return
	}
	var (
		ex  executor.Executor
		err error
	)
	if p.sourceBinding == "" {
		ex, err = p.env.DefaultExecutor()
		if err != nil {
			p.sourceErr = "the hub has no default executor for an unbound project: " + err.Error()
		}
	} else {
		ex, err = p.env.Executor(p.sourceBinding)
		if err != nil {
			src.ExecutorID = p.sourceBinding
			p.sourceErr = fmt.Sprintf("the project is bound to executor %s, which is not registered on this hub: %v", p.sourceBinding, err)
		}
	}
	if ex != nil {
		p.sourceEx = ex
		p.describeExecutor(&src, ex)
	}
	p.report.Source = src
}

// carry is what happens to the source's working trees in this move.
type carry int

const (
	// carryCaptured: the move captures the work and seeds the target with it.
	carryCaptured carry = iota
	// carryStays: source and target work in the same tree; nothing moves.
	carryStays
	// carryUndeliverable: the target builds its tree from the forge, so
	// work the forge does not have would never reach it.
	carryUndeliverable
)

// carryMode decides what the move does with the source's working trees.
func (p *preflight) carryMode() carry {
	t := p.report.Target
	s := p.report.Source
	if s.Workspace != "" && s.Workspace == t.Workspace {
		switch s.Workspace {
		case WorkspaceHubTree:
			return carryStays
		case WorkspaceDevice:
			// A device and its virtual executors share one working copy.
			if p.sourceEx != nil && p.targetEx != nil && deviceOf(p.sourceEx) == deviceOf(p.targetEx) {
				return carryStays
			}
		}
	}
	var caps executor.Capabilities
	switch {
	case p.targetEx != nil:
		caps = p.targetEx.Capabilities()
	case p.targetPool != nil:
		// A pool's runner takes its run from the queue and builds the tree
		// from the forge (or a kept checkout it resets to the forge's
		// commit): there is no runner to hand a bundle to ahead of the run.
		return carryUndeliverable
	default:
		// No usable target: say what the move would do with a target that
		// can take it; the target's own finding blocks the move.
		return carryCaptured
	}
	if caps.SharesHostFilesystem || caps.SupportsBranchBundle {
		return carryCaptured
	}
	return carryUndeliverable
}

// checkSource is (b) through (e).
func (p *preflight) checkSource() {
	src := &p.report.Source
	if p.sourceErr != "" {
		no := false
		src.Reachable = &no
		p.sourceUnreachable(p.sourceErr)
		p.abandoned(nil)
		return
	}
	switch src.Workspace {
	case WorkspaceEphemeral:
		p.add(Finding{
			Kind: KindWorkingTree, Severity: SeverityWillCarry, Side: SideSource,
			Title: "Nothing is kept on " + describeEndpoint(*src),
			Message: "Each run on " + src.ExecutorID + " builds its tree in a Pod and the tree goes with the Pod: " +
				"what a run did reached the hub or the forge when it ended, and nothing is left behind.",
		})
		return
	case WorkspaceDevice:
		ctx, cancel := p.probeCtx()
		err := p.env.Reachable(ctx, p.sourceEx)
		cancel()
		ok := err == nil
		src.Reachable = &ok
		if !ok {
			p.sourceUnreachable(fmt.Sprintf("device %s does not answer: %v", deviceOf(p.sourceEx), err))
			p.abandoned(nil)
			return
		}
	case WorkspaceHubTree:
		ok := true
		src.Reachable = &ok
	}

	tree, err := p.env.SourceTree(p.ctx, p.project, p.features, *src)
	var upgrade *AgentUpgradeError
	switch {
	case errors.As(err, &upgrade):
		p.agentTooOld(upgrade)
		p.abandoned(nil)
	case errors.Is(err, ErrUnseen):
		p.sourceUnseen()
		p.abandoned(nil)
		if !p.opts.AbandonSource {
			// What the source holds is read when the move captures it; where
			// it goes can be checked now.
			p.checkHubDir(p.carryMode())
		}
	case err != nil:
		where := src.WorkDir
		if where == "" {
			where = "the source's working copy"
		}
		f := Finding{
			Kind: KindWorkingTree, Severity: SeverityBlocker, Side: SideSource,
			Title:   "Could not read what the source holds",
			Message: "Reading " + where + " failed: " + err.Error() + ". Nothing can say what a move would leave behind.",
			Remedy:  "Fix what stops the hub reading the project's directory, then run the preflight again.",
		}
		if src.Workspace == WorkspaceDevice {
			f.Remedy = "Fix what the device refused (its answer is above) on the device, then run the preflight again; " +
				"a working copy that reaches outside itself is never read."
		}
		if p.opts.AbandonSource {
			f.Severity = SeverityWarning
			f.Remedy = "Abandoning the source leaves behind whatever the directory holds."
		}
		p.add(f)
		p.abandoned(nil)
	case tree.Absent:
		p.add(Finding{
			Kind: KindWorkingTree, Severity: SeverityWillCarry, Side: SideSource,
			Title: "The source holds no working copy of the project",
			Message: "There is nothing at " + src.WorkDir + ": no run of the project has worked there, " +
				"so nothing is captured and nothing is lost.",
		})
	default:
		if p.opts.AbandonSource {
			p.abandoned(&tree)
			return
		}
		mode := p.carryMode()
		p.checkWorkingTrees(tree.Git, mode)
		p.checkLocalCommits(tree.Git, mode)
		p.checkFiles(tree, mode)
		p.checkHubDir(mode)
	}
}

// agentTooOld is (e) for a device whose agent cannot capture: the move needs
// the capture, and nothing short of the agent's upgrade gives it one.
func (p *preflight) agentTooOld(e *AgentUpgradeError) {
	f := Finding{
		Kind: KindSourceAgent, Severity: SeverityBlocker, Side: SideSource,
		Title: "The device's agent is too old to capture the project",
		Message: e.Message + " A move captures the device's working copy before anything switches, " +
			"and an agent this old cannot be asked for it: a move now would leave the working copy behind unseen.",
		Remedy: e.Remedy,
	}
	if strings.TrimSpace(f.Remedy) == "" {
		f.Remedy = "Upgrade the device's agent (the Executors panel's Upgrade), then run the preflight again."
	}
	if p.opts.AbandonSource {
		f.Severity = SeverityWarning
		f.Remedy = "Abandoning the source: the move goes ahead without the device's working copy. Upgrade the agent first to capture it instead."
	}
	p.add(f)
}

// checkHubDir is (f) for a move from a device, or a pool's volume, onto an
// executor that works in the hub's own directory for the project: the seed
// builds the working copy there, and never over files the hub already holds.
func (p *preflight) checkHubDir(mode carry) {
	src := p.report.Source
	if mode != carryCaptured || (src.Workspace != WorkspaceDevice && src.Workspace != WorkspacePool) ||
		p.targetEx == nil || !p.targetEx.Capabilities().SharesHostFilesystem {
		return
	}
	entries, err := p.env.HubDirEntries(p.ctx, p.project)
	if err != nil {
		p.add(Finding{
			Kind: KindTarget, Severity: SeverityBlocker, Side: SideTarget,
			Title:   "Could not read the hub's directory for the project",
			Message: "The move builds the project's working copy in " + p.project.Path + " and reading it failed: " + err.Error() + ".",
			Remedy:  "Fix what stops the hub reading the directory, then run the preflight again.",
		})
		return
	}
	if len(entries) == 0 {
		return
	}
	shown := entries
	if len(shown) > maxExamples {
		shown = shown[:maxExamples]
	}
	p.add(Finding{
		Kind: KindTarget, Severity: SeverityBlocker, Side: SideTarget,
		Title: fmt.Sprintf("The hub's directory for the project already holds %d entr(ies) besides .cloop", len(entries)),
		Message: "The target works in " + p.project.Path + ", where the move builds the working copy it captures from the source. " +
			"That directory already holds files the move did not put there, and a move never overwrites them.",
		Remedy: "Move those entries aside (they are the hub's copy, not the source's), then run the preflight again — " +
			"or move the project to an executor that keeps a working copy of its own.",
		Items: []Item{{Name: "entries", Path: p.project.Path, Count: len(entries), Examples: shown}},
	})
}

// sourceUnreachable is (e) for a source that cannot be reached.
func (p *preflight) sourceUnreachable(why string) {
	f := Finding{
		Kind: KindSourceUnreachable, Severity: SeverityBlocker, Side: SideSource,
		Title: "The source cannot be reached",
		Message: why + ". What the source holds — its working copy, commits it never pushed, files its runs wrote — " +
			"cannot be captured, so a move now would leave it behind without anyone seeing what it was.",
		Remedy: "Bring the source back (start the device's agent, reconnect it) and run the preflight again. " +
			"If it is gone for good, run the preflight with abandon_source to see exactly what a move without it loses.",
	}
	if p.opts.AbandonSource {
		f.Severity = SeverityWarning
		f.Remedy = "Abandoning the source: the move goes ahead without it. The finding below lists what is lost."
	}
	p.add(f)
}

// sourceUnseen describes a source that can be reached but whose working copy
// the hub cannot read.
func (p *preflight) sourceUnseen() {
	src := p.report.Source
	if p.opts.AbandonSource {
		return
	}
	switch src.Workspace {
	case WorkspacePool:
		tenant := ""
		if p.sourcePool != nil && p.sourcePool.Tenant != "" {
			tenant = " under tenant " + p.sourcePool.Tenant
		}
		if p.sourcePool != nil && p.sourcePool.Volumes == VolumesNone {
			p.add(Finding{
				Kind: KindWorkingTree, Severity: SeverityWillCarry, Side: SideSource,
				Title: "Executor pool " + src.PoolID + " keeps nothing between runs",
				Message: "Its controller keeps no runner volumes: each run builds its tree in a runner that goes with it, " +
					"and what a run did reached the hub or the forge when it ended.",
			})
			return
		}
		if why := poolCannotAttach(p.sourcePool); why != "" {
			p.add(Finding{
				Kind: KindSourceUnreachable, Severity: SeverityBlocker, Side: SideSource,
				Title: "Executor pool " + src.PoolID + " cannot attach the project's volume to a runner",
				Message: fmt.Sprintf("The move captures the project's working copy from a runner on the volume holding it%s, "+
					"and %s.", tenant, why),
				Remedy: "Fix the pool (uncordon it, or what keeps its controller from starting runners), then run the preflight again; " +
					"to leave the volume behind, move the project with abandon_source.",
			})
			return
		}
		p.add(Finding{
			Kind: KindSourceUnseen, Severity: SeverityWarning, Side: SideSource,
			Title: "The pool's volume is read when the move captures it",
			Message: fmt.Sprintf("Executor pool %s keeps the project's working copy on a runner volume%s between runs. "+
				"Only a runner attached to that volume can read it, so this preflight cannot say what it holds. "+
				"The move asks the pool for a runner on it — the pool hands the project's volume to no other project's runner — "+
				"and captures the working copy there. If no runner attached to the volume comes up, the move fails at its capture, before anything switches.",
				src.PoolID, tenant),
			Remedy: "Nothing needs doing. If the pool has lost the volume, move the project with abandon_source instead.",
		})
	case WorkspaceDevice:
		p.add(Finding{
			Kind: KindSourceUnseen, Severity: SeverityWarning, Side: SideSource,
			Title: "The device's working copy is read by the hub member holding its connection",
			Message: fmt.Sprintf("Device %s keeps the project's working copy at %s between runs. "+
				"Another member of this hub's cluster holds the device's connection, so this preflight cannot ask it what the copy holds. "+
				"The move captures it on that member, before anything switches.",
				deviceOf(p.sourceEx), src.WorkDir),
			Remedy: "Run the preflight again on the member that holds the device's connection to see what it holds; the move itself needs nothing.",
		})
	default:
		who := "the source"
		if src.ExecutorID != "" {
			who = "executor " + src.ExecutorID
		}
		p.add(Finding{
			Kind: KindSourceUnseen, Severity: SeverityWarning, Side: SideSource,
			Title:   "The source's working copy cannot be read from the hub",
			Message: "Runs on " + who + " work in a tree the hub cannot read, so it cannot say whether it holds work no remote has. A move leaves it there.",
			Remedy:  "Before the move, push what you want to keep from where the runs worked.",
		})
	}
}

// poolCannotAttach says why a pool cannot give a move's capture a runner on
// the project's volume now; "" when nothing stops it.
func poolCannotAttach(pf *PoolFacts) string {
	switch {
	case pf == nil:
		return ""
	case pf.Revoked:
		return "the pool was revoked"
	case pf.Cordoned:
		return "an administrator has cordoned the pool, so its runners are handed nothing"
	case strings.TrimSpace(pf.Trouble) != "":
		return "its controller reports it cannot start runners: " + strings.TrimSpace(pf.Trouble)
	}
	return ""
}

// checkWorkingTrees is (b): changes no commit holds yet.
func (p *preflight) checkWorkingTrees(g GitState, mode carry) {
	if !g.Repository {
		return
	}
	var (
		items          []Item
		changed, loose int
		problems       []Item
	)
	for _, w := range g.Worktrees {
		name := worktreeName(w)
		switch {
		case w.Error != "":
			problems = append(problems, Item{Name: name, Path: w.Path, Detail: "could not be inspected: " + w.Error})
		case w.Missing:
			problems = append(problems, Item{Name: name, Path: w.Path, Detail: "git records it, but its directory is gone"})
		case w.Dirty():
			changed += w.Changed
			loose += w.Untracked
			detail := fmt.Sprintf("%d changed, %d untracked", w.Changed, w.Untracked)
			if w.Truncated {
				detail += " (at least: git's output was cut)"
			}
			if w.Locked != "" {
				detail += "; locked: " + w.Locked
			}
			items = append(items, Item{Name: name, Path: w.Path, Count: w.Changed + w.Untracked, Detail: detail,
				Examples: append(append([]string(nil), w.ChangedPaths...), w.UntrackedPaths...)})
		}
	}
	if len(problems) > 0 {
		p.add(Finding{
			Kind: KindWorkingTree, Severity: SeverityWarning, Side: SideSource,
			Title:   fmt.Sprintf("%d worktree(s) could not be inspected", len(problems)),
			Message: "What these worktrees hold is unknown, so it is not counted below.",
			Remedy:  "Check them by hand (`git -C <path> status`), or remove a worktree that is gone with `git worktree prune`.",
			Items:   problems,
		})
	}
	if len(items) == 0 {
		return
	}
	f := Finding{
		Kind: KindWorkingTree, Side: SideSource, Items: items,
		Title: fmt.Sprintf("%d changed and %d untracked path(s) no commit holds", changed, loose),
	}
	switch mode {
	case carryStays:
		f.Severity = SeverityWillCarry
		f.Message = "The target works in the same tree as the source, so these changes stay where they are."
	case carryUndeliverable:
		f.Severity = SeverityBlocker
		f.Message = "The target builds each run's tree from the forge, so changes that exist only in this tree would never reach a run there."
		f.Remedy = "Commit these changes and push them, or discard them, then run the preflight again."
	default:
		f.Severity = SeverityWillCarry
		f.Message = "The move captures these changes with the tree and seeds the target with them."
		f.Remedy = "To choose what goes into which commit, commit them yourself before the move."
	}
	p.add(f)
}

// checkLocalCommits is (c): commits no remote holds.
func (p *preflight) checkLocalCommits(g GitState, mode carry) {
	if !g.Repository {
		return
	}
	var (
		items   []Item
		commits int
	)
	for _, b := range g.Branches {
		switch {
		case b.Error != "":
			items = append(items, Item{Name: b.Name, Detail: "could not be counted: " + b.Error})
		case b.Unpushed > 0:
			commits += b.Unpushed
			detail := "no upstream"
			if b.Upstream != "" {
				detail = "upstream " + strings.TrimPrefix(b.Upstream, "refs/remotes/")
			}
			items = append(items, Item{Name: b.Name, Count: b.Unpushed, Detail: detail})
		}
	}
	for _, w := range g.Worktrees {
		if w.Orphaned > 0 {
			commits += w.Orphaned
			items = append(items, Item{Name: "detached HEAD in " + worktreeName(w), Path: w.Path, Count: w.Orphaned,
				Detail: "on no branch: only this worktree's HEAD holds them"})
		}
	}
	if g.Stash > 0 {
		items = append(items, Item{Name: "stash", Count: g.Stash, Detail: "stash entries, which no push carries"})
	}
	if g.BranchesSkipped > 0 {
		items = append(items, Item{Name: "more branches", Count: g.BranchesSkipped, Detail: "not counted: past the limit"})
	}
	if len(items) == 0 {
		return
	}
	title := fmt.Sprintf("%d commit(s) on local branches no remote holds", commits)
	if len(g.Remotes) == 0 {
		title = fmt.Sprintf("%d commit(s), and the repository has no remote at all", commits)
	}
	f := Finding{
		Kind: KindLocalCommits, Side: SideSource, Items: items, Title: title,
	}
	asOf := " (as of the hub's last fetch: nothing was fetched for this preflight)"
	switch mode {
	case carryStays:
		f.Severity = SeverityWillCarry
		f.Message = "The target works in the same repository as the source, so these commits stay where they are" + asOf + "."
	case carryUndeliverable:
		f.Severity = SeverityBlocker
		f.Message = "The target builds each run's tree from the forge, so commits the forge does not have would never reach a run there" + asOf + "."
		f.Remedy = "Push these branches (and anything you want from the stash), then run the preflight again."
		if len(g.Remotes) == 0 {
			f.Remedy = "Give the repository a remote and push it, then run the preflight again."
		}
	default:
		f.Severity = SeverityWillCarry
		f.Message = "The move bundles these commits with the tree and seeds the target with them" + asOf + "."
		f.Remedy = "Push them first if the forge should have them too."
	}
	p.add(f)
}

// checkFiles is (d): files under .cloop no database holds.
func (p *preflight) checkFiles(t Tree, mode carry) {
	invs := []struct {
		who string
		inv FileInventory
	}{{"the project", t.Files}}
	for _, ft := range p.features {
		if inv, ok := t.FeatureFiles[ft.Slug]; ok {
			invs = append(invs, struct {
				who string
				inv FileInventory
			}{"feature " + ft.Slug, inv})
		}
	}
	var (
		items, outbox []Item
		files         int
		bytes         int64
		problems      []Item
	)
	for _, x := range invs {
		if x.inv.Error != "" {
			problems = append(problems, Item{Name: x.who, Path: x.inv.Dir, Detail: x.inv.Error})
		}
		for _, c := range x.inv.Categories {
			it := Item{Name: c.Name, Path: x.inv.Dir, Count: c.Files, Bytes: c.Bytes, Detail: categoryLabels[c.Name], Examples: c.Examples}
			if x.who != "the project" {
				it.Name = x.who + ": " + c.Name
			}
			if x.inv.Truncated {
				it.Detail += " (at least: the walk stopped early)"
			}
			files += c.Files
			bytes += c.Bytes
			items = append(items, it)
			if c.Name == FilesAttachmentOutbox {
				outbox = append(outbox, it)
			}
		}
		if x.inv.Links > 0 {
			items = append(items, Item{Name: x.who + ": symbolic links", Path: x.inv.Dir, Count: x.inv.Links, Detail: "not followed and not counted"})
		}
	}
	if len(problems) > 0 {
		p.add(Finding{
			Kind: KindProjectFiles, Severity: SeverityWarning, Side: SideSource,
			Title:   "Some .cloop directories could not be walked",
			Message: "Their files are not counted below.",
			Remedy:  "Check the directories' permissions, then run the preflight again.",
			Items:   problems,
		})
	}
	if len(items) == 0 {
		return
	}
	f := Finding{
		Kind: KindProjectFiles, Severity: SeverityWillCarry, Side: SideSource, Items: items,
		Title: fmt.Sprintf("%d file(s), %s, under .cloop that no database holds", files, humanBytes(bytes)),
	}
	switch mode {
	case carryStays:
		f.Message = "The target works in the same directory, so these files stay where they are."
	case carryUndeliverable:
		f.Message = "These stay in the hub's copy of the project, where the hub reads them: the sandbox spec and the requirements spec still apply to runs on the target, and the dashboard still shows the artifacts."
	default:
		f.Message = "The move captures these with the tree. The hub's copy of the project keeps them too: the sandbox spec and the requirements spec go on applying to runs, and the dashboard goes on showing the artifacts."
		if w := p.report.Source.Workspace; w == WorkspaceDevice || w == WorkspacePool {
			f.Message = "These are the source's own, written by runs there. The move captures them with the working copy and delivers them to the target, " +
				"beside the hub's copy of the project, which keeps its own."
		}
	}
	p.add(f)
	if len(outbox) > 0 && mode != carryStays {
		p.add(Finding{
			Kind: KindProjectFiles, Severity: SeverityWarning, Side: SideSource, Items: outbox,
			Title: "Files a run left for attaching were never attached",
			Message: "A run copied these into its attachment outbox and ended before they were attached to its task. " +
				"Runs drain the outbox of the tree they run in, so once the project runs elsewhere nothing attaches these.",
			Remedy: "Copy out what you need from the outbox before the move, or let one more run on the current executor attach them.",
		})
	}
}

// abandoned is (e) with AbandonSource: exactly what a move that does not
// capture the source loses. t is the source's tree when it could be read.
func (p *preflight) abandoned(t *Tree) {
	if !p.opts.AbandonSource {
		return
	}
	src := p.report.Source
	f := Finding{Kind: KindAbandoned, Severity: SeverityWarning, Side: SideSource,
		Remedy: "The hub's own records of the project — its plan, history, requirements, attachments it received and settings — are kept. " +
			"Push or copy anything else you want before the move."}
	switch {
	case t != nil:
		f.Title = "Abandoning the source leaves this behind in the hub's tree"
		f.Message = "Nothing is captured from " + src.WorkDir + ". The directory stays on the hub; runs on the target do not see what it holds."
		for _, w := range t.Git.Worktrees {
			if w.Dirty() {
				f.Items = append(f.Items, Item{Name: "changes in " + worktreeName(w), Path: w.Path, Count: w.Changed + w.Untracked,
					Detail: fmt.Sprintf("%d changed, %d untracked", w.Changed, w.Untracked)})
			}
			if w.Orphaned > 0 {
				f.Items = append(f.Items, Item{Name: "detached HEAD in " + worktreeName(w), Path: w.Path, Count: w.Orphaned, Detail: "commits on no branch"})
			}
		}
		for _, b := range t.Git.Branches {
			if b.Unpushed > 0 {
				f.Items = append(f.Items, Item{Name: "branch " + b.Name, Count: b.Unpushed, Detail: "commits no remote holds"})
			}
		}
		if t.Git.Stash > 0 {
			f.Items = append(f.Items, Item{Name: "stash", Count: t.Git.Stash})
		}
		for _, c := range t.Files.Categories {
			f.Items = append(f.Items, Item{Name: c.Name, Path: t.Files.Dir, Count: c.Files, Bytes: c.Bytes, Detail: categoryLabels[c.Name]})
		}
		if len(f.Items) == 0 {
			f.Severity = SeverityWillCarry
			f.Title = "Abandoning the source loses nothing the hub can see"
			f.Message = "The hub's tree holds no uncommitted change, no commit a remote lacks and no file outside the databases."
			f.Remedy = ""
		}
	case src.Workspace == WorkspaceDevice:
		f.Title = "Abandoning the device loses its working copy"
		f.Message = "Everything in the device's working copy that the hub never received is lost to the project: uncommitted changes, commits no remote has, files its runs wrote under .cloop, and its runs' home directories (their harness sessions)."
		device := src.ExecutorID
		if src.Parent != "" {
			device = src.Parent
		}
		f.Items = []Item{{Name: "working copy", Path: src.WorkDir, Detail: "on device " + device}}
		f.Items = append(f.Items, Item{Name: "run homes", Path: path.Dir(src.WorkDir) + "/." + path.Base(src.WorkDir) + ".home", Detail: "the harness's login state and transcripts"})
	case src.Workspace == WorkspacePool:
		f.Title = "Abandoning the pool loses the project's runner volumes"
		f.Message = "Whatever the pool's volumes hold for the project — a working copy, caches — stays with the pool, which wipes a volume before giving it to another project."
		if p.sourcePool != nil && p.sourcePool.Tenant != "" {
			f.Items = []Item{{Name: "volumes held by tenant " + p.sourcePool.Tenant, Detail: "on executor pool " + src.PoolID}}
		}
	default:
		f.Title = "Abandoning the source"
		f.Message = "Nothing is captured from the source. The hub cannot say what it holds."
		if src.ExecutorID != "" {
			f.Items = []Item{{Name: "executor " + src.ExecutorID, Path: src.WorkDir}}
		}
	}
	p.add(f)
}

// worktreeName names a worktree for a reader: "the project", or the path it
// has inside the project.
func worktreeName(w gitstate.Worktree) string {
	if w.Rel == "" {
		return "the project"
	}
	if rest, ok := strings.CutPrefix(w.Rel, ".cloop/features/"); ok && !strings.Contains(rest, "/") {
		return "feature " + rest
	}
	return w.Rel
}

// ReadHubTree reads what a project's directory on the hub holds: the git
// state of the repository (the project's worktree and every worktree inside
// it, its features' among them) and the .cloop inventories of the project and
// each feature. It is Env.SourceTree for a source whose work is on the hub.
func ReadHubTree(ctx context.Context, project Project, features []Feature) (Tree, error) {
	t := Tree{FeatureFiles: map[string]FileInventory{}}
	g, err := gitstate.Inspect(ctx, project.Path, gitstate.Options{Exclude: []string{".cloop"}})
	if err != nil {
		return t, err
	}
	t.Git = g
	t.Files = InventoryFiles(project.Path)
	for _, f := range features {
		t.FeatureFiles[f.Slug] = InventoryFiles(f.Path)
	}
	return t, nil
}
