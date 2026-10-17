package hubdoctor

// The checks as a list (Task 20434).
//
// Run used to call each check in turn. A hub now runs the same checks on
// itself (live.go), each on a goroutine of its own and against a deadline of
// its own, so the sequence is data that both read: one place says what is
// checked and in which order, and a check added here reaches `cloop hub doctor`
// and the dashboard's Hub health panel at once.
//
// What the two diagnoses do differently is passed in as a stepSet rather than
// chosen by a flag in here. The dashboard's must not start work — no smoke
// dispatch, no probe Pods — and must not reconcile executors, which in a
// serving hub would replace the drivers it dispatches to. A flag would leave
// that code referenced from the request path all the same, and tests/security
// proves that no HTTP handler can reach process execution by following every
// function a handler names; reconciliation's worktree sweep runs git. With the
// variants injected by the caller, the request path names none of them.

import (
	"context"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// step is one check in the order Run makes them. id and title describe the
// step itself, for a live run's report about a step that did not finish or
// panicked; the findings it adds carry their own check ids.
type step struct {
	id, title string
	run       func(ctx context.Context, add addFn)
}

// liveEvery is how often a live run makes a step at most, for the steps too
// heavy to make on every report; a report in between carries the findings the
// step made last. Run ignores it: an operator's run is a run of everything.
var liveEvery = map[string]time.Duration{
	// quick_check and foreign_key_check read the whole database file: half a
	// gigabyte on a hub with a long audit trail, and seconds once it has left
	// the page cache.
	"storage.integrity": 15 * time.Minute,
	// Sums the size of every row of the largest tables, which reads them.
	"retention": 15 * time.Minute,
	// Walks every registered project's tree, up to 20,000 directories each:
	// forty thousand on this repository's own hub, twelve seconds cold.
	"projects.confinement": 15 * time.Minute,
	// Each dials the address sandboxes reach the monitor at, which is often
	// this very process's listener: a connection opened and closed with no
	// TLS handshake, which the listener logs as a handshake error.
	"gitproxy":  15 * time.Minute,
	"kubeguard": 15 * time.Minute,
	"egress":    15 * time.Minute,
}

// stepSet is what differs between the diagnosis an operator runs and the one
// a hub makes of itself: how the executor check finds the drivers, and the two
// steps that start work. A nil step is not run.
type stepSet struct {
	executors     func(ctx context.Context, dir string, cfg *config.Config, opts Options, add addFn)
	networkPolicy func(ctx context.Context, dir string, cfg *config.Config, opts Options, add addFn)
	smoke         func(ctx context.Context, dir string, cfg *config.Config, opts Options, rep *Report, add addFn)
}

// steps returns every check for cfg, in report order. cfg must not be nil:
// Run and Live report a missing configuration themselves.
func steps(dir string, cfg *config.Config, opts Options, wal walSample, rep *Report, set stepSet) []step {
	s := []step{
		{"policy", "Host execution policy", func(_ context.Context, add addFn) { checkExecutionPolicy(cfg, add) }},
		// What loading changed comes first: every check below reads the result.
		{"config.repaired", "Configuration repairs", func(_ context.Context, add addFn) { checkLoadRepairs(cfg, add) }},
		{"oidc", "Single sign-on", func(ctx context.Context, add addFn) { checkOIDC(ctx, cfg, opts, add) }},
		{"tls", "Transport security", func(_ context.Context, add addFn) { checkTLS(cfg, opts, add) }},
		// Beside the transport checks: whether a hub that cannot tell people
		// apart is reachable from the network (Task 20393).
		{"ui.exposure", "Network exposure", func(ctx context.Context, add addFn) { checkExposure(ctx, dir, cfg, opts, add) }},
		{"secret_key", "Sealing key", func(ctx context.Context, add addFn) { checkSecretKey(ctx, dir, cfg, opts, add) }},
		{"rbac", "Role policy", func(_ context.Context, add addFn) { checkRBAC(cfg, add) }},
		// Beside the policy it feeds: provisioned groups are a claim source the
		// policy's bindings may name (Task 20415).
		{"scim", "SCIM provisioning", func(_ context.Context, add addFn) { checkSCIM(dir, cfg, add) }},
		// After the policy it would bypass: whether the static admin token is
		// still accepted beside an enforced one, and how long it has gone unused
		// (Task 20406).
		{"ui.static_token", "Static admin token", func(_ context.Context, add addFn) { checkStaticToken(dir, cfg, opts, add) }},
		// Beside it: the API tokens the enforced policy suspends because they
		// were minted while there was none (Task 20422).
		{"api_tokens.unapproved", "API tokens awaiting approval", func(_ context.Context, add addFn) {
			checkUnapprovedTokens(dir, cfg, opts, add)
		}},
		// What an offboarding could not reach: the Claude Code homes of
		// identities the control plane denies, still on this host (Task 20422).
		{"offboard.claude_homes", "Claude homes of denied identities", func(_ context.Context, add addFn) {
			checkClaudeLeftovers(dir, opts, add)
		}},
		{"images", "Image trust", func(ctx context.Context, add addFn) { checkImagePolicy(ctx, dir, cfg, opts, add) }},
		{"executors", "Executors", func(ctx context.Context, add addFn) { set.executors(ctx, dir, cfg, opts, add) }},
		{"executors.edge_lag", "Edge devices against this hub's build", func(_ context.Context, add addFn) {
			checkEdgeLag(dir, add)
		}},
		{"executors.rollback_protection", "Rollback protection of enrolled devices", func(_ context.Context, add addFn) {
			checkRollbackProtection(dir, add)
		}},
		// After the executor step, whose registry it reads for executors never
		// probed. Reads the evidence rows only; it starts no probe.
		{"executors.isolation", "Executor isolation evidence", func(_ context.Context, add addFn) {
			checkIsolationEvidence(dir, add)
		}},
		{"runs.build_lag", "Builds of the runs on this host", func(_ context.Context, add addFn) { checkRunBuilds(add) }},
	}
	if set.networkPolicy != nil {
		// After the executor check, and not optional about the ordering: the
		// probe needs a driver in the registry holding a live cluster
		// credential, and reconciliation is what puts one there.
		s = append(s, step{"executors.network_policy_probe", "NetworkPolicy enforcement",
			func(ctx context.Context, add addFn) { set.networkPolicy(ctx, dir, cfg, opts, add) }})
	}
	s = append(s,
		// Beside the other egress-confinement checks: an allowlist that
		// contains a cloud metadata service without naming it (Task 20397).
		step{"firewall.metadata", "Cloud metadata services in allowlists", func(_ context.Context, add addFn) {
			checkMetadataExposure(dir, cfg, add)
		}},
		step{"gitproxy", "Git proxy", func(ctx context.Context, add addFn) { checkGitProxy(ctx, dir, cfg, opts, add) }},
		// Which GitHub grants a strict hub with no proxy hands into sandboxes
		// as the credential itself (Task 20409).
		step{"gitproxy.forge_credentials", "Forge credentials without the git proxy", func(_ context.Context, add addFn) {
			checkForgeCredentials(dir, cfg, add)
		}},
		step{"gitproxy.branch_grants", "Branch-restricted grants", func(_ context.Context, add addFn) {
			checkBranchRestrictedGrants(dir, cfg, add)
		}},
		step{"kubeguard", "Kubernetes access monitor", func(ctx context.Context, add addFn) {
			checkKubeGuard(ctx, dir, cfg, opts, add)
		}},
		// After both monitors whose certificates it issues: a rotation of the
		// hub's own CA under way, the members taking part, and its name
		// constraints against the names the monitors are configured at (Task
		// 20438).
		step{"hubca", "Hub certificate authority", func(_ context.Context, add addFn) { checkHubCA(dir, cfg, opts, add) }},
		step{"egress", "Egress proxy", func(ctx context.Context, add addFn) { checkEgressBroker(ctx, dir, cfg, opts, add) }},
		// Beside the storage the projects live in: whether any registered
		// project's directory overlaps what the hub must never bind (Task 20418).
		step{"projects.confinement", "Project directories", func(_ context.Context, add addFn) {
			checkProjectConfinement(dir, cfg, add)
		}},
		// Before the schema and the log, as one check used to report them.
		step{"storage.integrity", "Database integrity", func(_ context.Context, add addFn) { checkIntegrity(dir, add) }},
		step{"storage", "State database", func(_ context.Context, add addFn) { checkStorage(dir, wal, add) }},
		step{"storage.free_space", "Free disk space", func(_ context.Context, add addFn) { checkFreeSpace(dir, cfg, opts, add) }},
		step{"config.drift", "Configuration drift", func(_ context.Context, add addFn) { checkConfigDrift(dir, add) }},
		step{"retention", "Disk retention", func(_ context.Context, add addFn) { checkRetention(dir, cfg, add) }},
		// Beside retention, which is the other half of what the trail keeps:
		// whether it is complete, and whether shortening it would be noticed
		// (Task 20404).
		step{"audit", "Audit trail", func(_ context.Context, add addFn) { checkAuditTrail(dir, cfg, opts, add) }},
		// Beside it: whether the trail's content leaves the box, and whether
		// every sink it goes to keeps up (Task 20426).
		step{"audit.forward", "Audit forwarding", func(_ context.Context, add addFn) { checkAuditForward(dir, cfg, opts, add) }},
		step{"admission", "Quotas and budgets", func(_ context.Context, add addFn) { checkAdmission(dir, cfg, opts, add) }},
	)
	if set.smoke != nil {
		// Last, and after the executor check for the same reason the
		// NetworkPolicy probe is: it dispatches to the registry reconciliation
		// builds. Running it last also means an operator watching a terminal
		// has read every configuration verdict before the slow part starts.
		s = append(s, step{"smoke", "Dispatch smoke test",
			func(ctx context.Context, add addFn) { set.smoke(ctx, dir, cfg, opts, rep, add) }})
	}
	return s
}
