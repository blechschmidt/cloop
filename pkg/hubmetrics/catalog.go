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
//   - Record it. A family with no call site and no collector renders as HELP
//     and TYPE with no samples forever, and every alert written against it is
//     one that can never fire. TestEveryFamilyIsRecorded fails the build when
//     a family has neither (see recorded_test.go).
//   - A gauge read from the shared database is exported by the cluster leader
//     only. Every member of a hub cluster sees the same rows, so a gauge each
//     of them reported would read N times its value under sum(). Counters
//     need no such rule: each member counts what it did, and the sum is the
//     cluster's total.

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

// Executor and task lifecycle: the harness runs the hub dispatches to an
// executor and settles when they end (pkg/ui startWorkloadAs and runEnded).
//
// executor_kind is pkg/executor.Kind* (5 values); isolation is
// pkg/executor.Isolation (4 values). Neither carries an executor ID: a hub
// fronting a fleet of edge devices would turn that into one series per device
// per metric, which is exactly the unbounded-by-tenant-behaviour case the
// ceiling exists to catch.
//
// Every start is counted once more when the run is settled — as a completion,
// or as a failure with one of the Fail* reasons — so starts minus completions
// minus failures is the number of runs in flight.
var (
	TaskStarts = Default.MustRegister(Definition{
		Name:   "cloop_executor_task_starts_total",
		Help:   "Runs dispatched to an executor, by driver kind and isolation level, counted once the executor is chosen whether or not it then launches the run.",
		Type:   TypeCounter,
		Labels: []string{"executor_kind", "isolation"},
	})

	TaskCompletions = Default.MustRegister(Definition{
		Name:   "cloop_executor_task_completions_total",
		Help:   "Dispatched runs whose workload ran to completion and exited zero.",
		Type:   TypeCounter,
		Labels: []string{"executor_kind", "isolation"},
	})

	TaskFailures = Default.MustRegister(Definition{
		Name:   "cloop_executor_task_failures_total",
		Help:   "Dispatched runs that did not complete successfully. reason is one of start (it never began: the executor refused it or could not launch it), run (it launched and failed, or ended in a way its executor could not account for), cancelled (the control plane stopped it).",
		Type:   TypeCounter,
		Labels: []string{"executor_kind", "isolation", "reason"},
	})

	// Buckets span a second to two hours because that is the real range: a
	// run with nothing left to do, or one that crashes on start, is over in
	// seconds; an agent task on a remote sandbox runs for an hour. Linear
	// buckets would put every interesting value in one bin at one end or the
	// other.
	TaskDuration = Default.MustRegister(Definition{
		Name:    "cloop_executor_task_duration_seconds",
		Help:    "Wall-clock duration of dispatched runs that launched and reached a terminal state, as the executor timed them.",
		Type:    TypeHistogram,
		Labels:  []string{"executor_kind", "isolation"},
		Buckets: []float64{1, 5, 15, 60, 300, 900, 1800, 3600, 7200},
	})
)

// Executor fleet health. Collector-backed: the truth is the registry and the
// supervisor's health store, and a shadow copy maintained at mutation time
// would be a second source of truth with drift. The health store is the shared
// database, so a hub cluster exports both from its leader only.
var (
	ExecutorsByState = Default.MustRegister(Definition{
		Name:   "cloop_executors",
		Help:   "Registered executors by driver kind and scheduling state (ready, degraded, unreachable, cordoned, draining). Exported by the cluster leader only.",
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
		Help:   "Age of the least-recently-successful liveness probe across executors of this kind. Rises without bound while a node is unreachable. Exported by the cluster leader only.",
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

// Secret broker leases. kind is pkg/secretbroker.Kind* (9 values).
var (
	LeaseEvents = Default.MustRegister(Definition{
		Name:   "cloop_secret_lease_events_total",
		Help:   "Lease lifecycle transitions by credential kind and event (issued, renewed, revoked, expired).",
		Type:   TypeCounter,
		Labels: []string{"kind", "event"},
	})

	// Per process, not per cluster: a lease's material lives with the member
	// that materialised it, so each member reports the leases it holds and
	// the sum is the cluster's.
	LeasesLive = Default.MustRegister(Definition{
		Name:   "cloop_secret_leases_live",
		Help:   "Leases this hub process issued, still holds and has not seen expire, by credential kind. Each cluster member reports its own.",
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

	// Both read the rotation history `cloop hub key rotate` writes to the
	// shared database, so a hub cluster exports them from its leader only.
	KEKRotationRecords = Default.MustRegister(Definition{
		Name:   "cloop_secret_kek_rotation_records",
		Help:   "Progress of the current or most recent key-encryption-key rotation, by phase (total, rewrapped, skipped, failed). Exported by the cluster leader only.",
		Type:   TypeGauge,
		Labels: []string{"phase"},
	})

	KEKRotationActive = Default.MustRegister(Definition{
		Name: "cloop_secret_kek_rotation_active",
		Help: "1 while a key-encryption-key rotation is in progress, 0 otherwise. A rotation that stays at 1 across scrapes has stalled with records still wrapped under the old key. Exported by the cluster leader only.",
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

	// Counted where the session store's delete is the arbiter, so a session
	// two requests both found expired, or a janitor pass racing a sign-out,
	// ends once in this counter as it does in the audit trail.
	SessionsTerminated = Default.MustRegister(Definition{
		Name:   "cloop_sessions_terminated_total",
		Help:   "Sessions ended, by reason (idle_evicted, absolute_expired, admin_revoked, self_logout, idp_revoked, quota_evicted).",
		Type:   TypeCounter,
		Labels: []string{"reason"},
	})

	SessionsLive = Default.MustRegister(Definition{
		Name: "cloop_sessions_live",
		Help: "Sessions currently valid: neither past their absolute expiry nor idle beyond the timeout. Exported by the cluster leader only.",
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

	// Silent claim renewals (Task 20359): the prompt=none round trip a
	// signed-in dashboard makes from a hidden frame when the hub holds no
	// refresh token to re-assert the session's claims with. The outcomes are
	// oidcauth.Renew*, a closed set.
	//
	// Separate from OIDCLogins rather than another outcome on it: a renewal
	// runs every few minutes per open tab, so folding it in would swamp the
	// sign-in ratio an operator reads as "can people sign in". The ratio worth
	// watching here is interaction_required against ok — a hub where it climbs
	// is one whose users are being sent back to the provider mid-session, most
	// often because their browser blocks the provider's cookies inside a frame.
	OIDCRenewals = Default.MustRegister(Definition{
		Name:   "cloop_oidc_renewal_total",
		Help:   "Silent claim renewals that reached a verdict, by outcome (ok, interaction_required, no_session, not_enabled, idp_error, discovery_failed, state_error, invalid_state, exchange_failed, token_invalid, subject_mismatch, store_error). A rising interaction_required rate means users are being sent back to the provider mid-session.",
		Type:   TypeCounter,
		Labels: []string{"outcome"},
	})
)

// API token authentication. The failure reasons are pkg/apitoken's sentinel
// errors, which is what makes them a closed set, plus store_error for a token
// the hub could not check because its own store failed.
var (
	TokenAuth = Default.MustRegister(Definition{
		Name:   "cloop_apitoken_auth_total",
		Help:   "API token verification attempts, by result (success or failure).",
		Type:   TypeCounter,
		Labels: []string{"result"},
	})

	TokenAuthFailures = Default.MustRegister(Definition{
		Name:   "cloop_apitoken_auth_failures_total",
		Help:   "API token verifications that failed, by reason (malformed, not_found, bad_secret, revoked, expired, no_roles, store_error). A bad_secret spike against many token IDs is credential stuffing; store_error is the hub, not the caller.",
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

	// Counted rather than audited: see Proxy.reject.
	GitProxyAnonymous = Default.MustRegister(Definition{
		Name: "cloop_gitproxy_anonymous_requests_total",
		Help: "Requests to the git proxy that presented no credential and were refused before reaching a session. Most are git's own authentication challenge, answered with 401 before it retries with the session credential; a rate far above the proxy's request rate is something other than git reaching the port.",
		Type: TypeCounter,
	})
)

// Kubernetes access monitor. Same shape and same reasoning as the git proxy
// above: this is the boundary a sandbox's kubectl passes through, so the
// denial counter says whether the boundary is being tested.
var (
	KubeGuardRequests = Default.MustRegister(Definition{
		Name:   "cloop_kubeguard_requests_total",
		Help:   "Kubernetes API requests evaluated by the access monitor, by result (allowed or denied).",
		Type:   TypeCounter,
		Labels: []string{"result"},
	})

	KubeGuardDenials = Default.MustRegister(Definition{
		Name:   "cloop_kubeguard_denials_total",
		Help:   "Kubernetes API requests refused, by reason (verb_not_allowed, namespace_not_allowed, cluster_scope, resource_not_allowed, dangerous_subresource, non_resource_path, protocol_upgrade, body_too_large, unauthenticated). Sustained verb_not_allowed is a workload that expects write access it was not granted; dangerous_subresource is an attempt to exec into a pod.",
		Type:   TypeCounter,
		Labels: []string{"reason"},
	})
)

// Egress broker: the hub's Internet connection, leased to sandboxes. Recorded
// by pkg/egressbroker in whichever process runs the broker and its proxy, so
// all four are per process; a session lives in the broker that issued it.
var (
	EgressRequests = Default.MustRegister(Definition{
		Name:   "cloop_egress_requests_total",
		Help:   "Requests through the egress proxy that reached a policy verdict, by result (allowed or denied). A request that failed for want of DNS or a route is neither.",
		Type:   TypeCounter,
		Labels: []string{"result"},
	})

	// Every refusal the broker makes, which is more than the denied requests:
	// no_grant, revoked and an expired grant refuse a session before any
	// request exists, and quota_exhausted and expired also cut transfers
	// already under way.
	EgressDenials = Default.MustRegister(Definition{
		Name:   "cloop_egress_denials_total",
		Help:   "Egress refusals, by reason (no_grant, revoked, expired, host_not_allowed, port_not_allowed, method_not_allowed, destination_blocked, quota_exhausted).",
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
		Help: "Egress proxy sessions this process has issued and not yet closed. An expired session is closed within the proxy's reap interval.",
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
//
// The gauges here describe state every member of a hub cluster shares — the
// policy, the usage the enforcers synchronise through the database, the
// project registry — so they are exported by the leader only. The denials
// counter is each member's own refusals and is exported by all of them.
const quotaIdentityCeiling = 4096

var (
	QuotaEnforcementEnabled = Default.MustRegister(Definition{
		Name: "cloop_quota_enforcement_enabled",
		Help: "Whether a per-identity quota policy is in force. Exported by the cluster leader only.",
		Type: TypeGauge,
	})

	QuotaLimit = Default.MustRegister(Definition{
		Name:      "cloop_quota_limit",
		Help:      "Configured ceiling per identity and resource. Exported by the cluster leader only.",
		Type:      TypeGauge,
		Labels:    []string{"identity", "resource"},
		MaxSeries: quotaIdentityCeiling,
	})

	QuotaUsage = Default.MustRegister(Definition{
		Name:      "cloop_quota_usage",
		Help:      "Live consumption per identity and resource. Exported by the cluster leader only.",
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
		Help: "Identities the hub is currently accounting. Exported by the cluster leader only.",
		Type: TypeGauge,
	})

	ProjectsRegistered = Default.MustRegister(Definition{
		Name: "cloop_projects_registered",
		Help: "Projects in the hub registry. Exported by the cluster leader only.",
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

	// Session termination reasons. The last two are the endings neither the
	// user nor an operator chose: the identity provider refusing to renew the
	// grant, and the per-identity session quota making room for a new one.
	SessionIdleEvicted     = "idle_evicted"
	SessionAbsoluteExpired = "absolute_expired"
	SessionAdminRevoked    = "admin_revoked"
	SessionSelfLogout      = "self_logout"
	SessionIdPRevoked      = "idp_revoked"
	SessionQuotaEvicted    = "quota_evicted"

	// API token verification failures: one per pkg/apitoken sentinel, and
	// store_error for a token the hub could not check at all.
	TokenMalformed  = "malformed"
	TokenNotFound   = "not_found"
	TokenBadSecret  = "bad_secret"
	TokenRevoked    = "revoked"
	TokenExpired    = "expired"
	TokenNoRoles    = "no_roles"
	TokenStoreError = "store_error"

	// Egress refusals: one per pkg/egressbroker denial sentinel. expired
	// covers both an expired grant and an expired session.
	EgressNoGrant            = "no_grant"
	EgressRevoked            = "revoked"
	EgressExpired            = "expired"
	EgressHostNotAllowed     = "host_not_allowed"
	EgressPortNotAllowed     = "port_not_allowed"
	EgressMethodNotAllowed   = "method_not_allowed"
	EgressDestinationBlocked = "destination_blocked"
	EgressQuotaExhausted     = "quota_exhausted"

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

// CollectorSpec is one scrape-time collector for the default registry and the
// gauges it owns (see Registry.RegisterCollector, which Resets them before
// every run).
//
// Families is also how TestEveryFamilyIsRecorded knows a gauge is populated:
// a family named here counts as recorded even where no Set call names it.
type CollectorSpec struct {
	Name     string
	Families []*Metric
	Collect  Collector
}

// collectorsOnce guards RegisterCollectors so a hub that constructs more than
// one Server — every test in pkg/ui does — does not stack duplicate collectors
// on the process registry and double-count every gauge.
var collectorsOnce sync.Once

// RegisterCollectors installs scrape-time collectors on the default registry,
// at most once per process and in the order given. Calls after the first are
// no-ops, so the hub registers every collector it has in one call.
func RegisterCollectors(specs ...CollectorSpec) {
	collectorsOnce.Do(func() {
		for _, s := range specs {
			Default.RegisterCollector(s.Name, s.Collect, s.Families...)
		}
	})
}
