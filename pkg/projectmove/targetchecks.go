package projectmove

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// blockTarget records a blocker about the target and marks it unusable, which
// ends the checks that need a target.
func (p *preflight) blockTarget(kind Kind, title, message, remedy string) {
	p.add(Finding{Kind: kind, Severity: SeverityBlocker, Side: SideTarget, Title: title, Message: message, Remedy: remedy})
	p.targetOK = false
}

// sameAsSource reports whether the target names where the project runs now.
func (p *preflight) sameAsSource() bool {
	if p.target.Binding == p.sourceBinding {
		return true
	}
	return p.sourceBinding == "" && p.sourceEx != nil && p.target.ExecutorID == p.sourceEx.ID()
}

// resolveTarget validates the target and works out what it is.
func (p *preflight) resolveTarget() {
	t := Endpoint{Binding: p.target.Binding, ExecutorID: p.target.ExecutorID, PoolID: p.target.PoolID}
	p.targetOK = true
	defer func() { p.report.Target = t }()

	if p.sameAsSource() {
		p.blockTarget(KindTarget, "The project already runs there",
			fmt.Sprintf("The project's binding already resolves to %s, so there is nothing to move.", p.target.Binding),
			"Pick another executor or pool as the target.")
	}

	if p.target.PoolID != "" {
		t.Kind, t.Workspace = "pool", WorkspacePool
		pf, err := p.env.Pool(p.ctx, p.target.PoolID, p.project)
		switch {
		case err != nil:
			p.blockTarget(KindTarget, "Could not read the target pool",
				fmt.Sprintf("Executor pool %s could not be read: %v.", p.target.PoolID, err),
				"Try again; if it persists, check the hub's control-plane database.")
			return
		case !pf.Found:
			p.blockTarget(KindTarget, "No such executor pool",
				fmt.Sprintf("This hub has no executor pool %s.", p.target.PoolID),
				"Name an existing pool as pool:<id>; the Executors panel lists them.")
			return
		}
		t.Name = pf.Name
		p.targetPool = &pf
		if pf.Revoked {
			p.blockTarget(KindTarget, "The target pool was revoked",
				fmt.Sprintf("Executor pool %s was revoked and takes no more runs.", p.target.PoolID),
				"Pick another target.")
		}
		switch {
		case pf.AudienceErr != "":
			p.blockTarget(KindAudience, "Could not determine who may use the target pool",
				fmt.Sprintf("Executor pool %s's access list could not be read: %s.", p.target.PoolID, pf.AudienceErr),
				"Try again; a move is never planned onto a pool whose access list could not be read.")
		case !pf.Admitted:
			p.blockTarget(KindAudience, "You are not on the target pool's access list",
				fmt.Sprintf("Executor pool %s is restricted, and your account is not on its access list.", p.target.PoolID),
				"Ask an administrator to admit you to the pool, or pick another target.")
		}
		if !pf.OwnerMayRead {
			p.blockTarget(KindTarget, "The target pool belongs to someone who may not read this project",
				fmt.Sprintf("Executor pool %s is owned by an account that may not read this project, and its runners would hold the project's code.", p.target.PoolID),
				"Share the project with the pool's owner, or pick another target.")
		}
		if pf.Fits != "" {
			p.blockTarget(KindTarget, "The target pool's runners cannot run this project",
				fmt.Sprintf("Executor pool %s: %s.", p.target.PoolID, strings.TrimSuffix(pf.Fits, ".")),
				"Pick a pool whose runners meet the project's requirements, or change the project's .cloop/sandbox.yaml.")
		}
		return
	}

	if p.target.Local && !p.env.HostExecutionAllowed() {
		p.blockTarget(KindTarget, "This hub does not run projects on its own host",
			"\"local\" names the hub's own host, and this hub's executors.allow_host_process is off: no harness runs there.",
			"Pick an executor that isolates runs from the hub — a container, a device, a Kubernetes cluster or a pool.")
		return
	}
	ex, err := p.env.Executor(p.target.ExecutorID)
	if err != nil {
		p.blockTarget(KindTarget, "No such executor",
			fmt.Sprintf("Executor %s is not registered on this hub: %v.", p.target.ExecutorID, err),
			"Name an executor the Executors panel lists, or a pool as pool:<id>.")
		return
	}
	p.describeExecutor(&t, ex)
	if executor.IsEphemeral(ex) {
		p.blockTarget(KindTarget, "The target is an executor pool's runner",
			fmt.Sprintf("Executor %s is a runner: it takes only the run its pool hands it.", ex.ID()),
			"Name the runner's pool as pool:<id> instead.")
		return
	}
	if blocked, reason := executor.BlockedByBuildFloor(ex); blocked {
		p.blockTarget(KindTarget, "The target is below this hub's minimum agent build", reason,
			"Upgrade the device's agent ("+executor.AgentUpgradeProcedure+"), then run the preflight again.")
		return
	}
	if !p.env.HostExecutionAllowed() && !executor.IsolatesFromHost(ex) {
		p.blockTarget(KindTarget, "This hub does not run projects on its own host",
			fmt.Sprintf("Executor %s runs payloads on the hub's host, and this hub's executors.allow_host_process is off.", ex.ID()),
			"Pick an executor that isolates runs from the hub.")
		return
	}
	ctx, cancel := p.probeCtx()
	err = p.env.Reachable(ctx, ex)
	cancel()
	ok := err == nil
	t.Reachable = &ok
	if !ok {
		p.blockTarget(KindTarget, "The target does not answer",
			fmt.Sprintf("Executor %s did not answer: %v. A move seeds the target and checks it before switching the binding.", ex.ID(), err),
			"Bring the target online, then run the preflight again.")
		return
	}
	p.targetEx = ex
}

// targetExecutor is the executor the target checks judge: the target itself,
// or a pool's runner template.
func (p *preflight) targetExecutor() executor.Executor {
	if p.targetEx != nil {
		return p.targetEx
	}
	if p.targetPool != nil {
		return p.targetPool.Template
	}
	return nil
}

func (p *preflight) targetName() string {
	if p.target.PoolID != "" {
		return "executor pool " + p.target.PoolID
	}
	return "executor " + p.target.ExecutorID
}

// checkTarget is (f).
func (p *preflight) checkTarget() {
	tex := p.targetExecutor()
	if p.targetEx != nil {
		p.checkAudience()
	}
	if tex != nil {
		p.checkHarness(tex)
	}
	grants := p.checkGrants(tex)
	if p.targetEx != nil {
		p.checkFirewall()
		p.checkSandboxFit()
		p.checkWorkspace()
	}
	p.checkDevices(tex, grants)
}

// checkAudience asks whether the caller may use the target executor.
func (p *preflight) checkAudience() {
	ok, err := p.env.Audience(p.ctx, p.targetEx.ID())
	switch {
	case err != nil:
		p.add(Finding{Kind: KindAudience, Severity: SeverityBlocker, Side: SideTarget,
			Title:   "Could not determine who may use the target",
			Message: fmt.Sprintf("Executor %s's access list could not be read: %v.", p.targetEx.ID(), err),
			Remedy:  "Try again. A move is never planned onto an executor whose access list could not be read.",
		})
	case !ok:
		p.add(Finding{Kind: KindAudience, Severity: SeverityBlocker, Side: SideTarget,
			Title:   "You are not on the target's access list",
			Message: fmt.Sprintf("Executor %s is restricted, and your account is not on its access list.", p.targetEx.ID()),
			Remedy:  "Ask an administrator to admit you to the executor, or pick another target.",
		})
	}
}

// checkHarness asks whether a run on the target would get its harness's
// credential.
func (p *preflight) checkHarness(tex executor.Executor) {
	h, err := p.env.HarnessCredential(p.ctx, p.project, tex)
	if err != nil {
		p.add(Finding{Kind: KindHarnessCredential, Severity: SeverityWarning, Side: SideTarget,
			Title:   "Could not check the harness credential on the target",
			Message: "Checking whether a run on " + p.targetName() + " would get its harness's credential failed: " + err.Error() + ".",
			Remedy:  "Run the preflight again; the run itself checks before it starts.",
		})
		return
	}
	if !h.Applies {
		return
	}
	provider := h.Provider
	if provider == "" {
		provider = "the harness"
	}
	switch h.State {
	case HarnessOK:
		f := Finding{Kind: KindHarnessCredential, Severity: SeverityWillCarry, Side: SideTarget,
			Title:   "A run on the target gets its " + provider + " credential",
			Message: "The project's grants deliver the credential " + provider + " needs inside " + p.targetName() + "'s sandbox.",
		}
		for _, s := range h.Sources {
			f.Items = append(f.Items, Item{Name: s})
		}
		p.add(f)
	case HarnessExpiring:
		p.add(Finding{Kind: KindHarnessCredential, Severity: SeverityWarning, Side: SideTarget,
			Title:   "The harness credential for the target is about to lapse",
			Message: nonEmpty(h.Detail, "The grant that would carry "+provider+"'s credential to "+p.targetName()+" ends within ten minutes."),
			Remedy:  nonEmpty(h.Remedy, "Re-grant the credential on the project's Overview before starting a run on the target."),
		})
	default:
		p.add(Finding{Kind: KindHarnessCredential, Severity: SeverityBlocker, Side: SideTarget,
			Title:   "A run on the target would get no harness credential",
			Message: nonEmpty(h.Detail, p.targetName()+" isolates runs from the hub, and the hub never forwards its own login: a run there needs a grant carrying "+provider+"'s credential, and the project has none that reaches it."),
			Remedy:  nonEmpty(h.Remedy, "Grant a credential on the project's Overview (Claude credential), then run the preflight again."),
		})
	}
}

// checkGrants is the project's secret grants against the target. It returns
// them all, for the device check, which judges the device and interface grants
// this one leaves alone.
func (p *preflight) checkGrants(tex executor.Executor) []GrantFacts {
	grants, err := p.env.Grants(p.ctx, p.project, p.sourceEx, tex)
	if err != nil {
		p.add(Finding{Kind: KindSecretGrants, Severity: SeverityWarning, Side: SideTarget,
			Title:   "Could not check the project's secret grants",
			Message: "Listing the project's grants failed: " + err.Error() + ".",
			Remedy:  "Run the preflight again before moving; a grant that does not reach the target leaves its runs without that credential.",
		})
		return nil
	}
	var caps executor.Capabilities
	revocable := true
	if tex != nil {
		caps = tex.Capabilities()
		if p.targetEx != nil {
			revocable = executor.SupportsRevocation(p.targetEx)
		}
	}
	var carried, lost, refused []Item
	for _, g := range grants {
		it := grantItem(g)
		switch {
		case g.ReachesTarget:
			if len(g.Devices) > 0 || len(g.Interfaces) > 0 {
				// Judged with the devices below.
				continue
			}
			switch {
			case tex == nil:
				carried = append(carried, it)
			case g.Files && !caps.SupportsSecretFiles:
				it.Detail = "delivered as files, which " + p.targetName() + " cannot receive"
				refused = append(refused, it)
			case g.HostPath && !caps.SupportsHostMounts && !caps.SharesHostFilesystem:
				it.Detail = "binds a directory of the hub into the sandbox, which " + p.targetName() + " cannot do"
				refused = append(refused, it)
			case !revocable:
				it.Detail = p.targetName() + " cannot take a credential back mid-run, so no run carrying one is placed there"
				refused = append(refused, it)
			default:
				carried = append(carried, it)
			}
		case g.ReachesSource:
			if len(g.Devices) > 0 || len(g.Interfaces) > 0 {
				continue
			}
			it.Detail = "issued to the source by its subject " + g.Subject + ", which does not match the target"
			lost = append(lost, it)
		}
	}
	if len(refused) > 0 {
		p.add(Finding{Kind: KindSecretGrants, Severity: SeverityBlocker, Side: SideTarget, Items: refused,
			Title:   fmt.Sprintf("%d grant(s) cannot be delivered on the target", len(refused)),
			Message: "Every run dispatched to " + p.targetName() + " would be refused: it cannot receive these grants the way they are delivered.",
			Remedy:  "Pick a target that can receive them, or withdraw the grants the project does not need there.",
		})
	}
	if len(lost) > 0 {
		p.add(Finding{Kind: KindSecretGrants, Severity: SeverityWarning, Side: SideTarget, Items: lost,
			Title:   fmt.Sprintf("%d grant(s) reach the source but not the target", len(lost)),
			Message: "These grants are issued by executor or label, and the target does not match: runs on the target go without them.",
			Remedy:  "Grant them to the project (project:" + p.project.Path + "), or to the target, if runs there need them.",
		})
	}
	if len(carried) > 0 {
		p.add(Finding{Kind: KindSecretGrants, Severity: SeverityWillCarry, Side: SideTarget, Items: carried,
			Title:   fmt.Sprintf("%d grant(s) reach the target", len(carried)),
			Message: "Runs on the target are issued these grants as runs on the source are.",
		})
	}
	return grants
}

func grantItem(g GrantFacts) Item {
	it := Item{Name: g.SecretRef, Detail: g.Kind + ", " + g.Subject}
	if g.ID != "" {
		it.Path = g.ID
	}
	if !g.ExpiresAt.IsZero() {
		it.Detail += ", until " + g.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return it
}

// checkFirewall is the project's firewall rules against the target's.
func (p *preflight) checkFirewall() {
	ff, err := p.env.Firewall(p.ctx, p.project, p.targetEx)
	if err != nil {
		p.add(Finding{Kind: KindFirewall, Severity: SeverityWarning, Side: SideTarget,
			Title:   "Could not check the firewall rules",
			Message: "Reading the project's and the target's firewall rules failed: " + err.Error() + ".",
			Remedy:  "Run the preflight again; a run is refused at dispatch if the rules cannot be composed.",
		})
		return
	}
	if ff.Error != "" {
		p.add(Finding{Kind: KindFirewall, Severity: SeverityBlocker, Side: SideTarget,
			Title:   "The target's firewall rules do not compose",
			Message: "The rules that govern " + p.targetName() + " cannot be composed: " + ff.Error + ". Every run there would be refused.",
			Remedy:  "Fix the executor's and its device's rules on the Executors panel, then run the preflight again.",
		})
		return
	}
	effective := ff.Target
	if ff.Project != nil {
		outside := fwpolicy.Permits(ff.Target, *ff.Project)
		if len(outside) > 0 {
			narrowed, _ := fwpolicy.Constrain(ff.Target, *ff.Project)
			effective = &narrowed
			f := Finding{Kind: KindFirewall, Severity: SeverityWarning, Side: SideTarget,
				Title: "The project's firewall rules reach further than the target allows",
				Message: "A project's rules always fit inside its executor's, so binding the project to " + p.targetName() +
					" narrows them: what lies outside the target's rules is dropped from the project's.",
				Remedy: "Review what is dropped. If runs need it, ask an administrator to widen the target's rules first.",
			}
			for _, r := range outside {
				f.Items = append(f.Items, Item{Name: r})
			}
			p.add(f)
		} else {
			effective = ff.Project
			p.add(Finding{Kind: KindFirewall, Severity: SeverityWillCarry, Side: SideTarget,
				Title:   "The project's firewall rules fit the target's",
				Message: "Everything the project's rules allow, " + p.targetName() + "'s rules allow too, so they carry unchanged.",
			})
		}
	}
	if effective == nil {
		return
	}
	switch {
	case effective.HasDestination() && !ff.Enforceable:
		p.add(Finding{Kind: KindFirewall, Severity: SeverityBlocker, Side: SideTarget,
			Title: "The target cannot enforce the firewall its runs would be bound by",
			Message: p.targetName() + " cannot install a firewall (" + nonEmpty(ff.Reason, "no packet filter") +
				"), and runs there would be bound by rules: every one would be refused rather than run unfiltered.",
			Remedy: "Pick a target that can enforce the rules, or clear them.",
		})
	case !effective.HasDestination() && !ff.Enforceable && !ff.RemovesNetwork:
		p.add(Finding{Kind: KindFirewall, Severity: SeverityBlocker, Side: SideTarget,
			Title:   "The target cannot take the network away as its rules require",
			Message: "The rules runs on " + p.targetName() + " would be bound by allow no destination, and it can neither filter nor remove the network (" + nonEmpty(ff.Reason, "no packet filter") + ").",
			Remedy:  "Pick a target that can enforce the rules, or clear them.",
		})
	}
}

// clearConstraint clears what a constraint checks, so the next match finds
// the next unmet one. It reports false for a constraint it does not know, which
// ends the search.
func clearConstraint(req *executor.Requirements, c executor.Constraint) bool {
	switch c {
	case executor.ConstraintVirtualization:
		req.RequireVirtualization = false
	case executor.ConstraintKernelIsolation:
		req.RequireKernelIsolation = false
	case executor.ConstraintIsolationEvidence:
		req.RequireVirtualization, req.RequireKernelIsolation = false, false
	case executor.ConstraintIsolation:
		req.RequireIsolation, req.AllowedIsolations = false, nil
	case executor.ConstraintLabels:
		req.Labels = nil
	case executor.ConstraintPlatform:
		req.Platform = ""
	case executor.ConstraintArch:
		req.Arch = ""
	case executor.ConstraintHarness:
		req.Harnesses = nil
	case executor.ConstraintContainerRuntime:
		req.RequireContainerRuntime = false
	case executor.ConstraintNetworkEgress:
		req.RequireNetworkEgress = false
	case executor.ConstraintResourceLimits:
		req.RequireResourceLimits = false
	case executor.ConstraintDiskLimit:
		req.RequireDiskLimit = false
	case executor.ConstraintImageOverride:
		req.RequireImageOverride = false
	case executor.ConstraintSandboxBuild:
		req.RequireSandboxBuild = false
	case executor.ConstraintSandboxMounts:
		req.RequireSandboxMounts = false
	case executor.ConstraintHostMounts:
		req.RequireHostMounts = false
	case executor.ConstraintDevices:
		req.RequireDevices = false
	case executor.ConstraintInterfaces:
		req.RequireInterfaces = false
	case executor.ConstraintEgressScope:
		req.RequireEgressScope = false
	case executor.ConstraintWorkspace:
		req.RequireWorkspaceProvisioning, req.RequireHostFilesystemWorkspace = false, false
		req.RequireBranchBundle, req.RequireProjectSeed = false, false
	case executor.ConstraintWriteBack:
		req.RequireWriteBack = false
	case executor.ConstraintSecretFiles:
		req.RequireSecretFiles = false
	case executor.ConstraintRevocation:
		req.RequireRevocation = false
	case executor.ConstraintStream:
		req.RequireStream = false
	case executor.ConstraintSignal:
		req.RequireSignal = false
	case executor.ConstraintMemory:
		req.MinMemoryMB = 0
	case executor.ConstraintCapacity:
		req.IgnoreCapacity = true
	default:
		return false
	}
	return true
}

// unmet returns every constraint of req the target does not meet, in the
// order placement checks them.
func unmet(ex executor.Executor, req executor.Requirements) []executor.Rejection {
	req.IgnoreCapacity = true
	var out []executor.Rejection
	for i := 0; i < 64; i++ {
		rej, rejected := executor.MatchCandidate(executor.Candidate{Executor: ex}, req)
		if !rejected {
			break
		}
		out = append(out, rej)
		if !clearConstraint(&req, rej.Constraint) {
			break
		}
	}
	return out
}

// isolationConstraints are the rejections the isolation finding reports.
var isolationConstraints = map[executor.Constraint]bool{
	executor.ConstraintVirtualization:    true,
	executor.ConstraintKernelIsolation:   true,
	executor.ConstraintIsolationEvidence: true,
	executor.ConstraintIsolation:         true,
}

// deviceConstraints are the rejections the device finding reports.
var deviceConstraints = map[executor.Constraint]bool{
	executor.ConstraintDevices:    true,
	executor.ConstraintInterfaces: true,
}

// checkSandboxFit is the project's .cloop/sandbox.yaml against the target, and
// whether the target's own isolation claims hold.
func (p *preflight) checkSandboxFit() {
	req, err := p.env.SandboxRequirements(p.ctx, p.project)
	if err != nil {
		p.add(Finding{Kind: KindTarget, Severity: SeverityWarning, Side: SideProject,
			Title:   "The project's sandbox spec could not be read",
			Message: "Reading .cloop/sandbox.yaml failed: " + err.Error() + ". Runs are refused anywhere until it is fixed, so nothing about the target can be judged from it.",
			Remedy:  "Fix .cloop/sandbox.yaml where the error points, then run the preflight again.",
		})
		return
	}
	var iso, dev, other []Item
	for _, rej := range unmet(p.targetEx, req) {
		if rej.Constraint == executor.ConstraintHostPolicy || rej.Constraint == executor.ConstraintAgentBuild {
			// Reported as the target's own finding.
			continue
		}
		it := Item{Name: string(rej.Constraint), Detail: rej.Detail}
		switch {
		case isolationConstraints[rej.Constraint]:
			iso = append(iso, it)
		case deviceConstraints[rej.Constraint]:
			dev = append(dev, it)
		default:
			other = append(other, it)
		}
	}
	if len(other) > 0 {
		p.add(Finding{Kind: KindTarget, Severity: SeverityBlocker, Side: SideTarget, Items: other,
			Title:   "The target cannot honour the project's sandbox spec",
			Message: p.targetName() + " does not meet what the project's .cloop/sandbox.yaml asks for, so placement would refuse every run there.",
			Remedy:  "Pick a target that meets it, or change .cloop/sandbox.yaml.",
		})
	}
	if len(dev) > 0 {
		p.add(Finding{Kind: KindDeviceFeatures, Severity: SeverityBlocker, Side: SideTarget, Items: dev,
			Title:   "The target cannot pass the project's devices through",
			Message: "The project's .cloop/sandbox.yaml selects host devices or interfaces, which " + p.targetName() + " cannot give a sandbox.",
			Remedy:  "Pick a target on the host the hardware is attached to, with a driver that can pass it through.",
		})
	}
	needsIsolation := req.RequireVirtualization || req.RequireKernelIsolation
	if len(iso) > 0 {
		p.add(Finding{Kind: KindIsolation, Severity: SeverityBlocker, Side: SideTarget, Items: iso,
			Title:   "The target does not isolate runs as the project requires",
			Message: "The project's .cloop/sandbox.yaml requires " + isolationNeed(req) + ", and " + p.targetName() + " does not provide it, or its claim to was contradicted by its isolation probe.",
			Remedy:  "Pick a target whose runtime provides it and whose probe verified it.",
		})
	} else if needsIsolation {
		if w := executor.IsolationAdmissionWarning(p.targetEx, req); w != "" {
			p.add(Finding{Kind: KindIsolation, Severity: SeverityWarning, Side: SideTarget,
				Title:   "The target's isolation claim is unverified",
				Message: w,
				Remedy:  "Run the isolation probe on the target (Executors panel, Probe), or pick one whose claim is verified.",
			})
		} else {
			st := executor.JudgeIsolation(p.targetEx)
			p.add(Finding{Kind: KindIsolation, Severity: SeverityWillCarry, Side: SideTarget,
				Title:   "The target isolates runs as the project requires",
				Message: p.targetName() + " " + st.Summary() + ".",
			})
		}
	}
	p.compareIsolation(needsIsolation)
}

func isolationNeed(req executor.Requirements) string {
	if req.RequireVirtualization {
		return "a hypervisor-backed sandbox"
	}
	if req.RequireKernelIsolation {
		return "a kernel-isolated sandbox"
	}
	return "isolation from the host"
}

// isolationRank orders how strongly an executor separates a run from the
// machine it runs on.
func isolationRank(c executor.Capabilities) int {
	switch {
	case c.Virtualized:
		return 3
	case c.KernelIsolated:
		return 2
	case c.Isolation != executor.IsolationNone && c.Isolation != "":
		return 1
	default:
		return 0
	}
}

func isolationPhrase(c executor.Capabilities) string {
	switch isolationRank(c) {
	case 3:
		return "in a virtual machine"
	case 2:
		return "under a kernel of their own"
	case 1:
		return "in a sandbox sharing the machine's kernel"
	default:
		return "on the host with no sandbox"
	}
}

// compareIsolation warns when the target isolates less than the source, or
// claims an isolation its probe contradicted, though the project does not
// demand it.
func (p *preflight) compareIsolation(demanded bool) {
	tc := p.targetEx.Capabilities()
	if st := executor.JudgeIsolation(p.targetEx); st.Status == isolationprobe.StatusContradicted && !demanded {
		p.add(Finding{Kind: KindIsolation, Severity: SeverityWarning, Side: SideTarget,
			Title:   "The target's isolation claim was contradicted by its probe",
			Message: p.targetName() + " " + st.Summary() + ": runs there are not as isolated as its runtime's name says.",
			Remedy:  "Ask an administrator to fix the target's runtime, or pick another target.",
		})
	}
	if p.sourceEx == nil {
		return
	}
	sc := p.sourceEx.Capabilities()
	if isolationRank(tc) < isolationRank(sc) {
		p.add(Finding{Kind: KindIsolation, Severity: SeverityWarning, Side: SideTarget,
			Title: "The target isolates runs less than the source",
			Message: "Runs on the source run " + isolationPhrase(sc) + "; on " + p.targetName() + " they would run " + isolationPhrase(tc) +
				". The project does not require more, so the move is allowed.",
			Remedy: "If the project should keep its isolation, require it in .cloop/sandbox.yaml (capabilities.kernel_isolated or virtualized) and pick a target that provides it.",
		})
	}
}

// checkWorkspace asks whether the target can get the project's source.
func (p *preflight) checkWorkspace() {
	issues := p.env.Workspace(p.ctx, p.project, p.features, p.targetEx)
	if len(issues) == 0 {
		return
	}
	f := Finding{Kind: KindTarget, Severity: SeverityBlocker, Side: SideTarget,
		Title:   "The target cannot get this project's source",
		Message: "Every run dispatched to " + p.targetName() + " would be refused before it starts: the hub could not hand it the project's tree.",
	}
	var remedies []string
	for _, is := range issues {
		f.Items = append(f.Items, Item{Name: is.Who, Detail: is.Problem})
		if is.Remedy != "" && !contains(remedies, is.Remedy) {
			remedies = append(remedies, is.Remedy)
		}
	}
	f.Remedy = strings.Join(remedies, " ")
	if f.Remedy == "" {
		f.Remedy = "Pick another target."
	}
	p.add(f)
}

// checkDevices is the devices, interfaces and forwarded hardware the project
// uses, against the target. grants are the project's grants, as checkGrants
// read them.
func (p *preflight) checkDevices(tex executor.Executor, grants []GrantFacts) {
	var caps executor.Capabilities
	if tex != nil {
		caps = tex.Capabilities()
	}
	var carried, refused, lost []Item
	for _, g := range grants {
		if len(g.Devices) == 0 && len(g.Interfaces) == 0 {
			continue
		}
		it := grantItem(g)
		it.Examples = append(append([]string(nil), g.Devices...), g.Interfaces...)
		switch {
		case !g.ReachesTarget:
			if g.ReachesSource {
				it.Detail = "reaches the source only, by its subject " + g.Subject
				lost = append(lost, it)
			}
		case tex == nil:
			carried = append(carried, it)
		case len(g.Devices) > 0 && !caps.SupportsDevices:
			it.Detail = "host device(s): " + p.targetName() + " cannot expose host devices in a sandbox"
			refused = append(refused, it)
		case len(g.Interfaces) > 0 && !caps.SupportsInterfaces:
			it.Detail = "network interface(s): " + p.targetName() + " cannot move a host interface into a sandbox"
			refused = append(refused, it)
		default:
			carried = append(carried, it)
		}
	}
	// What a virtual executor at the source passes through itself.
	if p.sourceEx != nil && (p.targetEx == nil || p.targetEx.ID() != p.sourceEx.ID()) {
		if devs := p.env.VirtualDevices(p.ctx, p.sourceEx.ID()); len(devs) > 0 {
			lost = append(lost, Item{Name: "executor " + p.sourceEx.ID(), Count: len(devs), Examples: devs,
				Detail: "devices the source virtual executor passes into every sandbox"})
		}
	}
	if p.targetEx != nil {
		if devs := p.env.VirtualDevices(p.ctx, p.targetEx.ID()); len(devs) > 0 {
			carried = append(carried, Item{Name: "executor " + p.targetEx.ID(), Count: len(devs), Examples: devs,
				Detail: "devices the target virtual executor passes into every sandbox"})
		}
	}
	fc, fr, fl := p.checkForwarded(tex)
	carried, refused, lost = append(carried, fc...), append(refused, fr...), append(lost, fl...)

	if len(refused) > 0 {
		p.add(Finding{Kind: KindDeviceFeatures, Severity: SeverityBlocker, Side: SideTarget, Items: refused,
			Title:   "The target cannot give runs the project's devices",
			Message: "Every run dispatched to " + p.targetName() + " would be refused: it cannot pass through hardware the project is granted.",
			Remedy:  "Pick a target on the machine the hardware is attached to, with a driver that can pass it through, or withdraw the grants the project does not need there.",
		})
	}
	if len(lost) > 0 {
		p.add(Finding{Kind: KindDeviceFeatures, Severity: SeverityWarning, Side: SideTarget, Items: lost,
			Title:   "Runs on the target lose hardware runs on the source have",
			Message: "These devices reach runs on the source and would not reach runs on " + p.targetName() + ".",
			Remedy:  "If runs need them, grant them to the project or the target, or bind the forwarded devices to the target.",
		})
	}
	if len(carried) > 0 {
		p.add(Finding{Kind: KindDeviceFeatures, Severity: SeverityWillCarry, Side: SideTarget, Items: carried,
			Title:   "Runs on the target get these devices",
			Message: "These reach runs on " + p.targetName() + ".",
		})
	}
}

// checkForwarded judges the project's forwarded devices against the target,
// returning those that reach runs there, those the target refuses, and those
// bound to another executor only.
func (p *preflight) checkForwarded(tex executor.Executor) (carried, refused, lost []Item) {
	fwd, err := p.env.ForwardedDevices(p.ctx, p.project)
	if err != nil {
		p.add(Finding{Kind: KindDeviceFeatures, Severity: SeverityWarning, Side: SideTarget,
			Title:   "Could not list the project's forwarded devices",
			Message: "Reading the project's forwarded-device bindings failed: " + err.Error() + ".",
			Remedy:  "Run the preflight again before moving.",
		})
		return nil, nil, nil
	}
	var (
		applying []Item
		kinds    = map[string]bool{}
	)
	for _, f := range fwd {
		it := Item{Name: f.Name, Path: f.ID, Detail: f.Kind + " device forwarded by " + f.Forwarder}
		if f.Executor != "" && (p.targetEx == nil || f.Executor != p.targetEx.ID()) {
			it.Detail += ", bound to executor " + f.Executor + " only"
			lost = append(lost, it)
			continue
		}
		if !f.Online {
			it.Detail += " (the forwarder is offline now)"
		}
		applying = append(applying, it)
		kinds[f.Kind] = true
	}
	if len(applying) == 0 || tex == nil {
		return applying, nil, lost
	}
	list := make([]string, 0, len(kinds))
	for k := range kinds {
		list = append(list, k)
	}
	sort.Strings(list)
	if err := p.env.TakesForwarded(p.ctx, tex, list); err != nil {
		for i := range applying {
			applying[i].Detail += ": " + err.Error()
		}
		return nil, applying, lost
	}
	return applying, nil, lost
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) != "" {
		return s
	}
	return fallback
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
