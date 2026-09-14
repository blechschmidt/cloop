package hubmetrics

// The hub's metric catalog.
//
// Every metric the control plane exports is declared here rather than at its
// call site. That is a deliberate trade: a subsystem gains a package-level
// reference it has to reach for, and in exchange the label schema of the whole
// hub is one file an operator or a reviewer can read end to end.
//
// The property that buys is cardinality review. "Does this metric label by
// anything unbounded?" is answerable by reading this file, where scattered
// declarations would make it a question about the whole repository — and the
// answer would rot the first time someone added a label in a subsystem nobody
// re-read. The registry's ceiling is the backstop for when this review fails;
// this file is the thing that makes the review possible in the first place.
//
// Rules for adding a metric here:
//
//   - Label values come from a closed enumeration declared in Go source.
//     If you cannot point at the constant block the values come from, the
//     label is unbounded and does not belong.
//   - Never label by task ID, project path, identity subject, executor ID,
//     branch name, commit SHA, or host. Those are per-request, per-tenant, or
//     per-object identities; a hub with real traffic turns each into
//     unbounded series. Aggregate instead, or use a collector-backed gauge
//     that resets each scrape.
//   - Counters end in _total and only ever go up. A counter that resets makes
//     rate() report a spike that never happened.
//   - Document it in docs/operations/metrics.md. TestCatalogIsDocumented
//     fails the build if you do not.

import "sync"

// Default is the process-wide registry. A hub has exactly one.
//
// A package-level registry is the shape every metrics library converges on for
// the same reason: the alternative is threading a *Registry through
// constructors in a dozen packages that otherwise have no reason to know
// metrics exist, and the first constructor that cannot take a new parameter
// gets a global anyway. The cost — that instrumentation is not injectable —
// is bounded here because the registry is the only global and tests can build
// their own with New.
var Default = New()

// Executor and task lifecycle.
//
// executor_kind is pkg/executor.Kind* (4 values); isolation is
// pkg/executor.Isolation (4 values). Neither carries an executor ID: a hub
// fronting a fleet of edge devices would turn that into one series per device
// per metric, which is exactly the unbounded-by-tenant-behaviour case the
// ceiling exists to catch.
var (
	TaskStarts = Default.MustRegister(Definition{
		Name:   "cloop_executor_task_starts_total",
		Help:   "Workloads dispatched to an executor, by driver kind and isolation level.",
		Type:   TypeCounter,
		Labels: []string{"executor_kind", "isolation"},
	})

	TaskCompletions = Default.MustRegister(Definition{
		Name:   "cloop_executor_task_completions_total",
		Help:   "Workloads that ran to completion and exited zero.",
		Type:   TypeCounter,
		Labels: []string{"executor_kind", "isolation"},
	})

	TaskFailures = Default.MustRegister(Definition{
		Name:   "cloop_executor_task_failures_total",
		Help:   "Workloads that did not complete successfully. reason is one of start (the executor refused to launch it), run (it launched and failed), cancelled (the control plane withdrew it).",
		Type:   TypeCounter,
		Labels: []string{"executor_kind", "isolation", "reason"},
	})

	// Buckets span a second to two hours because that is the real range: a
	// `cloop suggest` subcommand returns in seconds, an agent task on a
	// remote sandbox runs for an hour. Linear buckets would put every
	// interesting value in one bin at one end or the other.
	TaskDuration = Default.MustRegister(Definition{
		Name:    "cloop_executor_task_duration_seconds",
		Help:    "Wall-clock duration of workloads that reached a terminal state.",
		Type:    TypeHistogram,
		Labels:  []string{"executor_kind", "isolation"},
		Buckets: []float64{1, 5, 15, 60, 300, 900, 1800, 3600, 7200},
	})
)

// Executor fleet health. Collector-backed: the truth is the registry and the
// supervisor's health store, and a shadow copy maintained at mutation time
// would be a second source of truth with drift.
var (
	ExecutorsByState = Default.MustRegister(Definition{
		Name:   "cloop_executors",
		Help:   "Registered executors by driver kind and scheduling state (ready, degraded, unreachable, cordoned, draining).",
		Type:   TypeGauge,
		Labels: []string{"kind", "state"},
	})

	// The oldest heartbeat per kind rather than one gauge per executor.
	// The alert that matters is "some executor of this kind has gone
	// quiet", and a max answers it in one series instead of one per device
	// — which for an edge fleet is the difference between a bounded metric
	// and a per-device one.
	ExecutorHeartbeatAgeMax = Default.MustRegister(Definition{
		Name:   "cloop_executor_heartbeat_age_seconds_max",
		Help:   "Age of the least-recently-successful liveness probe across executors of this kind. Rises without bound while a node is unreachable.",
		Type:   TypeGauge,
		Labels: []string{"kind"},
	})

	Placements = Default.MustRegister(Definition{
		Name:   "cloop_executor_placements_total",
		Help:   "Placement decisions, by result (placed or failed).",
		Type:   TypeCounter,
		Labels: []string{"result"},
	})

	// constraint is pkg/executor.Constraint (24 values), the headline
	// reason Select reports. The per-candidate Detail string is not a label:
	// it interpolates executor IDs and byte counts.
	PlacementFailures = Default.MustRegister(Definition{
		Name:   "cloop_executor_placement_failures_total",
		Help:   "Placement attempts that found no eligible executor, by the constraint that rejected the most candidates.",
		Type:   TypeCounter,
		Labels: []string{"constraint"},
	})
)

// Secret broker leases. kind is pkg/secretbroker.Kind* (7 values).
var (
	LeaseEvents = Default.MustRegister(Definition{
		Name:   "cloop_secret_lease_events_total",
		Help:   "Lease lifecycle transitions by credential kind and event (issued, renewed, revoked, expired).",
		Type:   TypeCounter,
		Labels: []string{"kind", "event"},
	})

	LeasesLive = Default.MustRegister(Definition{
		Name:   "cloop_secret_leases_live",
		Help:   "Leases the broker currently considers valid, by credential kind.",
		Type:   TypeGauge,
		Labels: []string{"kind"},
	})
)

// Sealing key health. An unseal failure is the signal that the hub can no
// longer read its own secrets — a wrong passphrase, a retired key still
// referenced, or ciphertext that failed authentication. All three are
// operator-visible emergencies and none of them is self-healing.
var (
	UnsealFailures = Default.MustRegister(Definition{
		Name:   "cloop_secret_unseal_failures_total",
		Help:   "Envelope opens that failed, by reason (key_unknown, key_retired, key_unavailable, seal_failed). Any non-zero rate means secrets are unreadable.",
		Type:   TypeCounter,
		Labels: []string{"reason"},
	})

	KEKRotationRecords = Default.MustRegister(Definition{
		Name:   "cloop_secret_kek_rotation_records",
		Help:   "Progress of the current or most recent key-encryption-key rotation, by phase (total, rewrapped, skipped, failed).",
		Type:   TypeGauge,
		Labels: []string{"phase"},
	})

	KEKRotationActive = Default.MustRegister(Definition{
		Name: "cloop_secret_kek_rotation_active",
		Help: "1 while a key-encryption-key rotation is in progress, 0 otherwise. A rotation that stays at 1 across scrapes has stalled with records still wrapped under the old key.",
		Type: TypeGauge,
	})
)

// Sessions. Deliberately unlabelled by subject: the count of sessions is
// operational, the roster of who holds them is in the audit trail behind
// audit.read, and putting subjects in a scrape would copy that roster into
// every monitoring system that touches it.
var (
	SessionsCreated = Default.MustRegister(Definition{
		Name: "cloop_sessions_created_total",
		Help: "Browser sessions established after a successful OIDC exchange.",
		Type: TypeCounter,
	})

	SessionsTerminated = Default.MustRegister(Definition{
		Name:   "cloop_sessions_terminated_total",
		Help:   "Sessions ended, by reason (idle_evicted, absolute_expired, admin_revoked, self_logout).",
		Type:   TypeCounter,
		Labels: []string{"reason"},
	})

	SessionsLive = Default.MustRegister(Definition{
		Name: "cloop_sessions_live",
		Help: "Sessions currently valid: neither past their absolute expiry nor idle beyond the timeout.",
		Type: TypeGauge,
	})
)

// OIDC sign-in. The credential path a human uses, which until Task 20247 was
// the only one with no metric at all while API tokens had two.
//
// The outcomes are oidcauth.Login* — a closed set declared in Go source, which
// is what makes them admissible as a label. They are worth separating rather
// than folding into success/failure because they name different problems with
// different owners: discovery_failed is the hub's config, exchange_failed is
// the client registration at the provider, invalid_state at any volume is
// somebody replaying callbacks, and idp_error is the provider's own decision.
var (
	OIDCLogins = Default.MustRegister(Definition{
		Name:   "cloop_oidc_login_total",
		Help:   "Sign-in attempts that reached a verdict, by outcome (success, discovery_failed, idp_error, invalid_request, invalid_state, exchange_failed, token_invalid, session_error, state_error). A redirect to the provider is not counted until it comes back.",
		Type:   TypeCounter,
		Labels: []string{"outcome"},
	})

	// Unlabelled deliberately. The reason for a discovery failure is in the
	// hub's log and in `cloop hub doctor`, both of which can afford prose;
	// what a scrape needs is the single number an alert fires on, because
	// any non-zero rate means nobody new can sign in.
	OIDCDiscoveryFailures = Default.MustRegister(Definition{
		Name: "cloop_oidc_discovery_failures_total",
		Help: "Failures to resolve the OIDC issuer (discovery or JWKS). Any non-zero rate means no new sign-in can complete; run `cloop hub doctor` for which of the two failed and why.",
		Type: TypeCounter,
	})
)

// API token authentication. The failure reasons are pkg/apitoken's sentinel
// errors, which is what makes them a closed set.
var (
	TokenAuth = Default.MustRegister(Definition{
		Name:   "cloop_apitoken_auth_total",
		Help:   "API token verification attempts, by result (success or failure).",
		Type:   TypeCounter,
		Labels: []string{"result"},
	})

	TokenAuthFailures = Default.MustRegister(Definition{
		Name:   "cloop_apitoken_auth_failures_total",
		Help:   "API token verifications that failed, by reason (malformed, not_found, bad_secret, revoked, expired, no_roles). A bad_secret spike against many token IDs is credential stuffing.",
		Type:   TypeCounter,
		Labels: []string{"reason"},
	})
)

// Result write-back. The distinction the labels carry is the one the code
// makes: a rejection is the hub refusing what a sandbox returned, an outage is
// the hub being unable to find out. They page differently — the first is a
// misbehaving or compromised sandbox, the second is broken infrastructure.
var (
	WriteBackBundles = Default.MustRegister(Definition{
		Name:   "cloop_writeback_bundles_total",
		Help:   "Write-back bundles offered by executors, by result (accepted, rejected, unavailable).",
		Type:   TypeCounter,
		Labels: []string{"result"},
	})

	WriteBackRejections = Default.MustRegister(Definition{
		Name:   "cloop_writeback_rejections_total",
		Help:   "Bundles refused on their content, by reason code. Reasons are executor.WriteBackReason*; the prose refusal is in the audit trail, not here, because it interpolates branch names and commit SHAs.",
		Type:   TypeCounter,
		Labels: []string{"reason"},
	})
)

// Merge queue.
var (
	MergeQueueDepth = Default.MustRegister(Definition{
		Name: "cloop_mergequeue_depth",
		Help: "Merges waiting to be applied. The queue is serial, so sustained depth is the integration path falling behind task completion.",
		Type: TypeGauge,
	})

	MergeOutcomes = Default.MustRegister(Definition{
		Name:   "cloop_mergequeue_merges_total",
		Help:   "Completed merge attempts, by outcome (clean, auto_resolved, unresolved, error).",
		Type:   TypeCounter,
		Labels: []string{"outcome"},
	})
)

// Git interception proxy. This is the boundary a sandbox pushes through, so
// its denial counter is a security signal and not only an operational one.
var (
	GitProxyPushes = Default.MustRegister(Definition{
		Name:   "cloop_gitproxy_pushes_total",
		Help:   "Pushes evaluated by the interception proxy, by result (allowed or denied).",
		Type:   TypeCounter,
		Labels: []string{"result"},
	})

	GitProxyDenials = Default.MustRegister(Definition{
		Name:   "cloop_gitproxy_push_denials_total",
		Help:   "Pushes refused, by reason (ref_not_allowed, delete_denied, create_denied, update_denied, no_write, too_many_commands, push_cert). A sandbox repeatedly hitting ref_not_allowed is probing the allowlist.",
		Type:   TypeCounter,
		Labels: []string{"reason"},
	})
)

// Egress broker: the hub's Internet connection, leased to sandboxes.
var (
	EgressRequests = Default.MustRegister(Definition{
		Name:   "cloop_egress_requests_total",
		Help:   "Requests through the egress broker, by result (allowed or denied).",
		Type:   TypeCounter,
		Labels: []string{"result"},
	})

	EgressDenials = Default.MustRegister(Definition{
		Name:   "cloop_egress_denials_total",
		Help:   "Egress requests refused, by reason (no_grant, revoked, expired, host_not_allowed, port_not_allowed, method_not_allowed, destination_blocked, quota_exhausted).",
		Type:   TypeCounter,
		Labels: []string{"reason"},
	})

	EgressBytes = Default.MustRegister(Definition{
		Name:   "cloop_egress_bytes_total",
		Help:   "Bytes proxied on behalf of sandboxes, by direction (up or down).",
		Type:   TypeCounter,
		Labels: []string{"direction"},
	})

	EgressSessionsLive = Default.MustRegister(Definition{
		Name: "cloop_egress_sessions_live",
		Help: "Egress leases currently redeemable.",
		Type: TypeGauge,
	})
)

// Quotas and admission control.
//
// These four preserve the names and label schemas the hand-built exposition
// used before this registry existed, because an operator's scrape config and
// recording rules are already written against them. Moving them here changes
// nothing an operator sees and gains them the ceiling, the escaping, and the
// stable ordering that every other metric gets.
//
// cloop_quota_limit and cloop_quota_usage are the one place the hub labels by
// identity, and they are the exception that the collector-reset rule makes
// safe: both Reset before every scrape, so their cardinality is the number of
// identities the hub is accounting *right now*, not the number it has ever
// seen. A tenant cannot grow them by churning. The raised ceiling bounds even
// that, at a hub far larger than the ceiling on identities a single hub is
// expected to serve.
const quotaIdentityCeiling = 4096

var (
	QuotaEnforcementEnabled = Default.MustRegister(Definition{
		Name: "cloop_quota_enforcement_enabled",
		Help: "Whether a per-identity quota policy is in force.",
		Type: TypeGauge,
	})

	QuotaLimit = Default.MustRegister(Definition{
		Name:      "cloop_quota_limit",
		Help:      "Configured ceiling per identity and resource.",
		Type:      TypeGauge,
		Labels:    []string{"identity", "resource"},
		MaxSeries: quotaIdentityCeiling,
	})

	QuotaUsage = Default.MustRegister(Definition{
		Name:      "cloop_quota_usage",
		Help:      "Live consumption per identity and resource.",
		Type:      TypeGauge,
		Labels:    []string{"identity", "resource"},
		MaxSeries: quotaIdentityCeiling,
	})

	QuotaDenials = Default.MustRegister(Definition{
		Name:   "cloop_quota_denials_total",
		Help:   "Admission refusals since this hub started, by resource.",
		Type:   TypeCounter,
		Labels: []string{"resource"},
	})

	QuotaIdentities = Default.MustRegister(Definition{
		Name: "cloop_quota_identities",
		Help: "Identities the hub is currently accounting.",
		Type: TypeGauge,
	})

	ProjectsRegistered = Default.MustRegister(Definition{
		Name: "cloop_projects_registered",
		Help: "Projects in the hub registry.",
		Type: TypeGauge,
	})
)

// Bounded reason vocabularies used by call sites whose own packages have no
// enumeration to borrow. Declaring them here rather than as string literals at
// the call site is what keeps the label a closed set: a typo becomes a compile
// error instead of a new series.
const (
	// Task failure reasons.
	FailStart     = "start"
	FailRun       = "run"
	FailCancelled = "cancelled"

	// Lease lifecycle events.
	LeaseIssued  = "issued"
	LeaseRenewed = "renewed"
	LeaseRevoked = "revoked"
	LeaseExpired = "expired"

	// Session termination reasons.
	SessionIdleEvicted     = "idle_evicted"
	SessionAbsoluteExpired = "absolute_expired"
	SessionAdminRevoked    = "admin_revoked"
	SessionSelfLogout      = "self_logout"

	// Generic binary results.
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultAllowed = "allowed"
	ResultDenied  = "denied"

	// Placement results.
	PlacementPlaced = "placed"
	PlacementFailed = "failed"

	// Write-back results.
	WriteBackAccepted    = "accepted"
	WriteBackRejected    = "rejected"
	WriteBackUnavailable = "unavailable"

	// Merge outcomes.
	MergeClean        = "clean"
	MergeAutoResolved = "auto_resolved"
	MergeUnresolved   = "unresolved"
	MergeError        = "error"

	// KEK rotation phases.
	RotationTotal     = "total"
	RotationRewrapped = "rewrapped"
	RotationSkipped   = "skipped"
	RotationFailed    = "failed"

	// Egress directions.
	EgressUp   = "up"
	EgressDown = "down"
)

// collectorsOnce guards RegisterCollectors so a hub that constructs more than
// one Server — every test in pkg/ui does — does not stack duplicate collectors
// on the process registry and double-count every gauge.
var collectorsOnce sync.Once

// RegisterCollectors installs scrape-time collectors on the default registry,
// at most once per process.
func RegisterCollectors(fns map[string]Collector) {
	collectorsOnce.Do(func() {
		for name, fn := range fns {
			Default.RegisterCollector(name, fn)
		}
	})
}
