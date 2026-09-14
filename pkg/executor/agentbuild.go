package executor

// agentbuild.go makes a remote agent's *build version* a placement input
// (Task 20252).
//
// Protocol version and build version answer different questions, and until now
// only the first one was ever asked. The negotiated protocol version says what
// the wire between the hub and a device can carry, and placement already honours
// it precisely: Capabilities() is intersected with what the live session
// supports, so a pre-v6 agent is not handed a lease that delivers credential
// files. The build version says what the *device* is running, and it was
// decorative — decoded at hello, stored, rendered as a skew label in the
// Executors panel, and consulted by nothing.
//
// That gap has a shape. Two agents can both speak protocol v6 and differ by a
// year of fixes, because the protocol only changes when a frame changes. Every
// defect that is not a wire change — a workspace that is cleaned up wrongly, a
// credential that is not wiped, a signal that is not forwarded — is invisible to
// the protocol number and visible only in the build. An operator who has patched
// such a defect has no way to say "stop scheduling onto devices that predate the
// fix", and finds out which devices those were from the failures.
//
// So the floor is deliberately a *deployment policy* rather than a per-workload
// requirement, and it is expressed the same way the no-host-execution switch is
// (see policy.go): a process-wide value applied as a ratchet at bootstrap and
// consulted inside reject(). That placement has exactly one enforcement point is
// the property worth having — reject() is shared by Select (scheduling) and
// CheckSandboxSupport (the bound-executor check that runs on every dispatch), so
// a floor set once is honoured on both paths and cannot be bypassed by a caller
// who forgot to thread a field through.
//
// Deny-by-default applies to the unprovable case as well as the failing one. A
// device that reports no build, or the legacy "1" placeholder, or anything
// pkg/version cannot order, has not shown that it satisfies the floor — and an
// operator who set a floor asked for devices that can prove their build, not for
// devices that decline to say. The rejection reason says which of the two
// happened, because "it is too old" and "it will not tell me" have different
// fixes.

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/blechschmidt/cloop/pkg/version"
)

// BuildReporter is implemented by drivers whose workload runs on a machine with
// a cloop binary of its own, and which can therefore report a build distinct
// from the control plane's.
//
// The interface, rather than a Capabilities bool, for the same reason Revoker is
// an interface (see revoke.go): a bool in a struct is a claim anybody can set,
// and the direction the two would drift is a driver asserting a build it cannot
// substantiate. Only a driver that genuinely has a separate binary to ask about
// can implement a method that returns its version.
//
// remote.Executor satisfies this already — AgentVersion() has existed since the
// fleet inventory landed. Nothing had to change on the driver side; what was
// missing was a reader in the scheduler.
type BuildReporter interface {
	Executor
	// AgentVersion returns the cloop build the connected device advertised,
	// or "" when there is no live session to ask.
	AgentVersion() string
}

// AgentBuild reports the cloop build running on ex's node, and whether ex is a
// driver that has a build of its own at all.
//
// The second return is the important one. A container or Kubernetes executor
// runs *this* binary — it has no separate build, and comparing it against the
// hub would be comparing the hub with itself. Those drivers must never be
// rejected for build skew, and reporting them as "build unknown" would reject
// every one of them the moment a floor was configured.
func AgentBuild(ex Executor) (build string, reports bool) {
	br, ok := ex.(BuildReporter)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(br.AgentVersion()), true
}

// ---------------------------------------------------------------------------
// The fleet-wide floor
// ---------------------------------------------------------------------------

// minAgentBuild is the process-wide minimum build. The empty string — the
// starting value — means no floor, so a binary that never touches this policy
// places exactly as it did before this file existed.
var minAgentBuild atomic.Pointer[string]

// SetMinAgentBuild sets the minimum cloop build a remote agent may be running
// to receive work, returning the previous value so callers — tests especially —
// can restore it without keeping a separate copy.
//
// An empty string clears the floor. This is the raw switch; bootstrap paths
// should call ApplyMinAgentBuild.
func SetMinAgentBuild(v string) string {
	v = strings.TrimSpace(v)
	old := minAgentBuild.Swap(&v)
	if old == nil {
		return ""
	}
	return *old
}

// MinAgentBuild returns the configured minimum agent build, or "" for no floor.
func MinAgentBuild() string {
	if p := minAgentBuild.Load(); p != nil {
		return *p
	}
	return ""
}

// ApplyMinAgentBuild installs a configured floor as a ratchet: it can only ever
// rise. A config naming an older floor than the one already in force, or naming
// none at all, leaves the switch alone.
//
// This is what every bootstrap path should call, for the reason spelled out on
// ApplyHostExecutionPolicy: a control plane reads many projects' config.yaml,
// and applying them symmetrically would let one tenant's file lower a
// fleet-wide security floor for the whole process. Lowering is deliberate and
// explicit — restart with the looser config, the same ceremony every other
// security-relevant setting asks for.
//
// An unparseable floor is ignored rather than treated as infinitely high. The
// safe reading of "I cannot understand this rule" is not "refuse the entire
// fleet" — that turns a typo into an outage. It is not silent either:
// config.ValidateExecutors rejects one arriving through `cloop config set`, and
// config.ExecutorWarnings surfaces a hand-edited one as a banner saying no floor
// is being enforced, which is the fact an operator must not be left to assume
// the other way round.
func ApplyMinAgentBuild(v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	if _, ok := version.Compare(v, v); !ok {
		return
	}
	for {
		cur := MinAgentBuild()
		if cur != "" {
			if cmp, ok := version.Compare(v, cur); !ok || cmp <= 0 {
				return
			}
		}
		old := minAgentBuild.Load()
		if minAgentBuild.CompareAndSwap(old, &v) {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// The placement decision
// ---------------------------------------------------------------------------

// rejectForBuild decides whether ex's reported build disqualifies it under
// floor, returning the operator-facing reason when it does.
//
// Every message names the remediation, because the person reading a placement
// failure in the Executors panel is rarely the person who set the floor. The
// procedure named is real and verified: `--upgrade` now checks the binary it is
// about to install and rolls back if the service does not come back, which is
// what makes it safe to recommend for a critical host.
func rejectForBuild(ex Executor, floor string) (detail string, rejected bool) {
	floor = strings.TrimSpace(floor)
	if floor == "" {
		return "", false
	}
	build, reports := AgentBuild(ex)
	if !reports {
		// Not a device. It runs the control plane's own binary, so the floor
		// is satisfied by construction.
		return "", false
	}

	switch {
	case build == "":
		return fmt.Sprintf("does not report a build version, so it cannot be shown to meet the "+
			"fleet's minimum of %s; it predates build-version reporting entirely. Upgrade it "+
			"with `%s` on the device, or clear executors.min_agent_build", floor, AgentUpgradeProcedure), true
	case build == version.LegacyAgentVersion:
		return fmt.Sprintf("reports the placeholder build %q that agents sent before they knew "+
			"their own version, so it cannot be shown to meet the fleet's minimum of %s. Upgrade "+
			"it with `%s` on the device", version.LegacyAgentVersion, floor, AgentUpgradeProcedure), true
	}

	cmp, ok := version.Compare(build, floor)
	if !ok {
		return fmt.Sprintf("reports build %q, which cannot be ordered against the fleet's minimum "+
			"of %s — an unreleased build carries no version to compare. Install a released build "+
			"with `%s` on the device, or clear executors.min_agent_build",
			build, floor, AgentUpgradeProcedure), true
	}
	if cmp < 0 {
		return fmt.Sprintf("runs cloop %s, below the fleet's minimum of %s. Copy the new binary to "+
			"the device and run `%s` there", build, floor, AgentUpgradeProcedure), true
	}
	return "", false
}

// BlockedByBuildFloor reports whether the fleet's minimum agent build forbids
// dispatching to ex, and the sentence to show an operator when it does.
//
// It exists so the Executors panel and the scheduler cannot disagree. A device
// that placement silently skips looks identical on the panel to one that is
// merely idle, and the operator's next move — waiting — is the one thing that
// will not help. Rendering the *same* decision function the scheduler runs means
// the card explains the refusal that is actually happening, rather than a second
// implementation of the rule that will drift from the first.
func BlockedByBuildFloor(ex Executor) (bool, string) {
	if ex == nil {
		return false, ""
	}
	detail, rejected := rejectForBuild(ex, MinAgentBuild())
	if !rejected {
		return false, ""
	}
	// reject() renders "<id> <detail>"; a card has the ID in its heading
	// already, so the standalone form needs its own subject.
	return true, "This device " + detail + "."
}

// AgentUpgradeProcedure is the command that rolls a device forward.
//
// It lives here, at the bottom of the import graph, because three layers name
// it: this package's placement refusals, the Executors panel, and the CLI's own
// help. It used to be a string in pkg/ui describing a flag that did not exist,
// which is how an operator came to run the one command the UI recommended and
// get an unknown-flag error. One definition, imported upward, is what keeps the
// advice and the flag from drifting apart again.
//
// The flag now exists and is safe to recommend for a critical host: it verifies
// the binary before the swap and restores the previous one if the service does
// not come back. See pkg/executor/install.
const AgentUpgradeProcedure = "cloop executor agent install --upgrade"

// buildRank orders two candidates by how current their build is, for ranking
// rather than rejection. It reports whether a precedes b, and whether the two
// could be ordered at all.
//
// Unorderable pairs report ok=false so the caller falls through to the next
// tiebreak instead of inventing an order — a fleet where half the devices run
// unreleased builds must still place deterministically.
func buildRank(a, b Candidate) (aFirst bool, ok bool) {
	av, aReports := AgentBuild(a.Executor)
	bv, bReports := AgentBuild(b.Executor)
	// A non-device runs the hub's own build. Ranking it against a device's
	// reported version would compare two things that are not the same
	// measurement, so leave that pair to the next tiebreak.
	if !aReports || !bReports {
		return false, false
	}
	cmp, comparable := version.Compare(av, bv)
	if !comparable || cmp == 0 {
		return false, false
	}
	// Newer first: among otherwise-equal nodes a fleet should drain onto its
	// current builds, so the stale ones go idle and get noticed.
	return cmp > 0, true
}
