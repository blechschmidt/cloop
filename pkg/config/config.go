// Package config manages the .cloop/config.yaml project configuration file.
//
// Storage model (Task 20075): the canonical source remains the human-readable
// .cloop/config.yaml file, but every Save() also mirrors the serialised YAML
// into a metadata row of the project's SQLite state.db (when one exists).
// This makes config queryable alongside cost and step data, and provides a
// recovery fallback if the YAML file is lost or quarantined for corruption.
// Load() prefers YAML when present; if YAML is missing, it transparently
// rehydrates from the SQLite mirror so the project keeps working.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const configFile = ".cloop/config.yaml"

// Bounds for numeric config values. Centralised here so both Load()'s
// warn-and-clamp path and `cloop config set`'s reject path agree on the
// same limits, and so pkg/configvalidate can import them without hard-coding
// constants in three places.
const (
	// MaxParallel: 1..MaxParallelUpper. Zero in YAML means "not set"
	// (omitempty zero value) and stays untouched — runtime treats 0 as
	// "use default". Anything else outside the range is pathological:
	// negative spawns no workers; an absurdly large value would create
	// thousands of goroutines per parallel tick.
	MaxParallelLower = 1
	MaxParallelUpper = 64

	// Rate limiter: zero means "use HTTP server default", but if the user
	// sets a value it must be a sane positive rate / burst.
	RateLimitRPSLower   = 1.0
	RateLimitBurstLower = 1

	// Budget alert threshold percent must be 0..100. 0 is allowed and
	// disables alerting; >100 is meaningless.
	AlertThresholdMin = 0
	AlertThresholdMax = 100

	// WebSocket connection caps for the cloop ui server (Task 20090).
	// Zero in YAML means "not set" — runtime substitutes the *Default*
	// values below. Non-zero values outside the allowed band are clamped
	// back to zero (validateAndClamp) and rejected by `cloop config set`
	// (ValidateNumeric) to keep the goroutine pool bounded.
	//
	// Upper bounds are intentionally generous: 4096 total connections is
	// far above any realistic single-tenant dashboard load (a browser
	// opens at most a handful of WebSocket peers per tab) but below the
	// default Linux open-file ulimit (1024 → 4096 with `ulimit -n`).
	// Per-IP cap of 1024 is similarly headroom-laden but stops a single
	// misbehaving client from monopolising the total budget.
	WebSocketConnsLower        = 1
	WebSocketConnsUpper        = 4096
	WebSocketConnsPerIPLower   = 1
	WebSocketConnsPerIPUpper   = 1024
	WebSocketConnsDefault      = 256
	WebSocketConnsPerIPDefault = 8

	// HTTP request body cap for the cloop ui and cloop serve servers
	// (Task 20102). The cap protects against memory-exhaustion DoS via
	// oversized POST/PUT/PATCH payloads on the long-running daemon. Zero
	// in YAML means "not set" — runtime substitutes MaxRequestBodyBytesDefault.
	// Non-zero values outside the allowed band are clamped back to zero
	// (validateAndClamp) and rejected by `cloop config set` (ValidateNumeric).
	//
	// Bounds: 1 KiB lower (anything smaller would reject normal task PATCHes)
	// and 1 GiB upper (anything larger defeats the protection while being
	// well above any legitimate JSON payload). Default 10 MiB covers chat
	// transcripts and large bulk-edit JSON arrays with comfortable headroom.
	MaxRequestBodyBytesLower   int64 = 1 << 10  // 1 KiB
	MaxRequestBodyBytesUpper   int64 = 1 << 30  // 1 GiB
	MaxRequestBodyBytesDefault int64 = 10 << 20 // 10 MiB

	// Orchestrator per-task wall-clock timeout bounds. Zero in YAML means no
	// task timeout (Task 20148); a positive value is an explicit opt-in that
	// must fall within [Lower, Upper] (otherwise it is treated as 0 / no
	// timeout). OrchestratorTaskTimeoutMinutesDefault is retained only for
	// validation error messages and is no longer applied as a fallback.
	//
	// Lower bound is 1 minute: anything smaller would race the AI's first
	// token on every call. Upper bound is one week (7*24*60), well above
	// any legitimate single-task budget but a hard ceiling against an
	// operator hand-editing nonsense like "1000000 minutes".
	OrchestratorTaskTimeoutMinutesLower   = 1
	OrchestratorTaskTimeoutMinutesUpper   = 7 * 24 * 60
	OrchestratorTaskTimeoutMinutesDefault = 30

	// Container executor limits (Task 20157). Zero means "no limit
	// requested" for every one of these; a non-zero value must be usable.
	//
	// The upper bounds are not a guess at what a host has — they are a
	// guard against a typo becoming a silent non-limit. A container asked
	// for 100000 CPUs does not get them; the runtime clamps or errors, and
	// the operator believes a cap is in force that is not. Refusing the
	// value is the only outcome that keeps config honest.
	ContainerCPUsUpper = 1024.0
	// Memory floor: below ~64 MiB a Go binary cannot even start, so a
	// smaller cap would make every run fail with an unrelated-looking OOM.
	ContainerMemoryMBLower = 64
	ContainerMemoryMBUpper = 1 << 20 // 1 TiB
	// PID cap: 1 is enough for a single process; the ceiling is well above
	// any build's fan-out but below the kernel's default pid_max.
	ContainerPIDsLower = 1
	ContainerPIDsUpper = 1 << 16
	// Workspace/scratch disk bounds (Task 20179). Deliberately the same
	// numbers as the memory pair rather than a second opinion about what a
	// machine has: both bound a repo-committed request against a ceiling that
	// exists to stop a typo becoming a silent non-limit, and two different
	// sets would only invite the question of which one is authoritative.
	//
	// The floor is an error rather than a clamp, for the same reason the
	// memory floor is: clamping *up* would hand the project more than it
	// asked for, which is the direction a sandbox spec never moves in. Below
	// it, a checkout plus the harness's own scratch does not fit, and the run
	// fails on the fetch with a message about the repository rather than
	// about the limit that actually refused it.
	ContainerDiskMBLower = 64
	ContainerDiskMBUpper = 1 << 20 // 1 TiB

	// Kubernetes executor bounds (Task 20161).
	//
	// One week, matching OrchestratorTaskTimeoutMinutesUpper. Every duration
	// in the section is a deadline or a grace period, and none of them has a
	// legitimate value beyond that; a larger number is a units mistake
	// (milliseconds typed into a seconds field) that would otherwise become
	// an effectively-unbounded Pod.
	KubernetesSecondsUpper = 7 * 24 * 60 * 60
	// Concurrency ceiling. Not a claim about cluster capacity — the
	// namespace's ResourceQuota is that — but a guard against a runaway loop
	// asking for a Pod count no operator typed on purpose.
	KubernetesMaxConcurrentUpper = 1024

	// Egress broker bounds (Task 20163).
	//
	// A proxy session is a live credential, so its ceiling is the security
	// control and not a convenience. Four hours is already generous for
	// something whose whole point is to be short-lived; beyond that the value
	// is not a lease, it is a configuration, and the broker's own
	// MaxSessionTTLCeiling refuses it a second time.
	EgressMaxSessionMinutesUpper = 4 * 60
	// Dial ceiling. A destination that has not answered in five minutes is
	// not going to, and a larger value only holds a sandbox's request open
	// while it waits to fail.
	EgressDialTimeoutSecondsUpper = 300
)

// permWarnedPaths tracks which config paths have already emitted the
// "wide permissions" warning. Long-running processes (the Web UI, daemon,
// auto-evolve loops) call Load() many times per second; without dedup the
// warning floods stderr and the journal. Each unique path warns at most once
// per process lifetime.
var (
	permWarnedMu    sync.Mutex
	permWarnedPaths = map[string]struct{}{}
)

// clampWarnedMu serialises the once-per-(path,field) clamp warnings emitted by
// validateAndClamp. Same dedup rationale as permWarnedPaths: Load() runs hot
// and we don't want to flood stderr with the same "max_parallel out of range"
// line every second.
var (
	clampWarnedMu    sync.Mutex
	clampWarnedPairs = map[string]struct{}{}
)

// Config is the project configuration loaded from .cloop/config.yaml.
type Config struct {
	// Default provider: anthropic, openai, ollama, claudecode, mock
	Provider string `yaml:"provider"`

	Anthropic  AnthropicConfig  `yaml:"anthropic"`
	OpenAI     OpenAIConfig     `yaml:"openai"`
	Ollama     OllamaConfig     `yaml:"ollama"`
	ClaudeCode ClaudeCodeConfig `yaml:"claudecode"`
	Mock       MockConfig       `yaml:"mock,omitempty"`
	Webhook    WebhookConfig    `yaml:"webhook,omitempty"`
	GitHub     GitHubConfig     `yaml:"github,omitempty"`
	// Router maps task roles to provider names for heterogeneous multi-agent execution.
	// Example: router.backend = "anthropic", router.frontend = "openai"
	Router RouterConfig `yaml:"router,omitempty"`
	// Hooks defines shell commands to run at task and plan lifecycle events.
	Hooks HooksConfig `yaml:"hooks,omitempty"`

	// MaxParallel sets the default worker pool size for parallel PM mode.
	// 0 means no limit (all ready tasks run concurrently).
	// Overridden by --max-parallel / -j on the command line.
	MaxParallel int `yaml:"max_parallel,omitempty"`

	// StepTimeout is the maximum duration per task step (e.g. "10m", "30m", "0").
	// "0" or empty means no timeout. Overridden by --step-timeout on the command line.
	StepTimeout string `yaml:"step_timeout,omitempty"`

	// Watch configures the file-watch mode for `cloop watch --glob`.
	Watch WatchConfig `yaml:"watch,omitempty"`

	// Notify configures Slack and Discord incoming webhook notifications.
	Notify NotifyConfig `yaml:"notify,omitempty"`

	// Sync configures git-based team plan sharing and merging.
	Sync SyncConfig `yaml:"sync,omitempty"`

	// LogJSON switches all cloop output to newline-delimited JSON (NDJSON).
	// Equivalent to passing --log-json on the command line.
	// Each structured event is emitted as a JSON object with fields:
	//   time, level, event, task_id, message, data
	LogJSON bool `yaml:"log_json,omitempty"`

	// Budget configures monthly spend limits.
	Budget BudgetConfig `yaml:"budget,omitempty"`

	// CalibrationFactor is set by 'cloop task effort-calibrate --apply'.
	// When non-zero and != 1.0, Decompose() multiplies every AI-generated
	// time_estimate_minutes value by this factor before storing the task.
	// This closes the feedback loop between historical actuals and future plans.
	CalibrationFactor float64 `yaml:"calibration_factor,omitempty"`

	// RateLimit configures the per-IP token-bucket rate limiter for HTTP servers
	// (cloop serve and cloop ui). Zero values use built-in defaults.
	RateLimit RateLimitConfig `yaml:"rate_limit,omitempty"`

	// Tracing configures OTLP distributed trace export.
	// When Tracing.Enabled is true and Tracing.Endpoint is set, cloop exports
	// per-call spans to the specified OTLP HTTP endpoint (e.g. Jaeger, Tempo,
	// or an OTel Collector). Disabled by default (zero overhead when off).
	Tracing TracingConfig `yaml:"tracing,omitempty"`

	// Orchestrator configures the PM orchestrator's wall-clock execution
	// budgets. See OrchestratorConfig.TaskTimeoutMinutes for the default
	// per-task timeout applied when neither the task nor the project state
	// has a more specific budget set.
	Orchestrator OrchestratorConfig `yaml:"orchestrator,omitempty"`

	// UI configures the cloop ui Web dashboard server. See UIConfig.
	UI UIConfig `yaml:"ui,omitempty"`

	// Backup configures hot backups of .cloop/state.db (Task 20115).
	// When AutoBackup is true, the long-running cloop ui server runs a
	// daily backup and prunes old files. Disabled by default.
	Backup BackupConfig `yaml:"backup,omitempty"`

	// Executors configures the pluggable execution backends (Task 20156+).
	// Absent means "host process only", which is the zero-configuration
	// single-machine default.
	Executors ExecutorsConfig `yaml:"executors,omitempty"`

	// Sandbox configures the envelope around a project's own
	// .cloop/sandbox.yaml (Task 20177). It is a separate section from
	// Executors because it governs what a *project* may ask for, not what
	// backends the operator runs — and it applies identically to every
	// backend that honours an image override.
	Sandbox SandboxConfig `yaml:"sandbox,omitempty"`
}

// ExecutorsConfig groups the execution backends a control plane offers.
//
// Each sub-struct configures one driver. A driver is registered only when its
// section is present and enabled, so adding a backend is an explicit
// operator decision rather than something that materialises because a binary
// happened to be on PATH.
type ExecutorsConfig struct {
	// AllowHostProcess permits the localprocess driver — running agent
	// workloads as child processes of the control plane, with its user, its
	// filesystem, and its network. Absent means true, so an existing
	// single-machine install keeps working across an upgrade.
	//
	// This is the one setting an enterprise deployment must flip. With it
	// false, cloop enters strict no-host-execution mode: the localprocess
	// driver refuses to Start, executor.Resolve refuses to hand it out, and
	// every Web UI path that would have spawned a harness returns 409 naming
	// the configured alternatives. That is what turns "the web UI never
	// directly spawns a harness on the host" from a convention into an
	// enforced invariant.
	//
	// It is a *bool rather than a bool because all three states are
	// distinguishable and matter: absent (legacy default, permissive),
	// explicitly true (an operator decided), explicitly false (hardened). A
	// plain bool with omitempty would drop an explicit false on the next
	// Save, silently re-opening host execution.
	AllowHostProcess *bool `yaml:"allow_host_process,omitempty"`

	// Container configures the Docker/Podman sandbox executor.
	Container ContainerExecutorConfig `yaml:"container,omitempty"`

	// Kubernetes configures the ephemeral-Pod executor.
	Kubernetes KubernetesExecutorConfig `yaml:"kubernetes,omitempty"`

	// Egress configures the scoped forward proxy that lends the control
	// plane's Internet connection to isolated sandboxes.
	Egress EgressConfig `yaml:"egress,omitempty"`
}

// EgressConfig configures the egress broker's forward proxy.
//
// The proxy is what makes network-isolated execution usable rather than
// merely safe. A container started with network "none" cannot fetch a
// dependency, and the usual alternative is to give the sandbox a real network
// and hope; with this enabled it reaches exactly the hosts an egress grant
// names, brokered per connection by the control plane.
type EgressConfig struct {
	// Enabled starts the proxy with the control plane. Off by default: a
	// control plane should not acquire a new outbound path because a config
	// file grew a section.
	Enabled bool `yaml:"enabled,omitempty"`

	// ListenAddr is the proxy's bind address. Empty binds an ephemeral
	// loopback port.
	//
	// Loopback is the safe default and frequently an unusable one: a
	// container on a bridge network cannot reach the host's 127.0.0.1, so an
	// operator running sandboxes sets an address the sandbox can route to —
	// at which point the proxy is reachable by everything else on that
	// network, and the per-session credential is what holds. Bind as
	// narrowly as the sandbox network allows.
	ListenAddr string `yaml:"listen_addr,omitempty"`

	// AdvertiseAddr is what goes into the sandbox's HTTPS_PROXY. Empty uses
	// the bound address.
	//
	// It exists because the two are routinely different: podman reaches the
	// host at host.containers.internal, docker at host.docker.internal, and
	// a remote edge executor at whatever address the control plane has on
	// the network between them. Getting it wrong produces a sandbox whose
	// every outbound request times out, which is a slow thing to diagnose.
	AdvertiseAddr string `yaml:"advertise_addr,omitempty"`

	// MaxSessionMinutes bounds one redemption regardless of what a grant
	// asks for. Zero uses the broker's 15-minute default; values outside
	// [1, EgressMaxSessionMinutesUpper] are clamped.
	MaxSessionMinutes int `yaml:"max_session_minutes,omitempty"`

	// DialTimeoutSeconds bounds the connection to an authorised origin.
	// Zero uses the broker's default.
	DialTimeoutSeconds int `yaml:"dial_timeout_seconds,omitempty"`

	// DefaultMaxBytesUp and DefaultMaxBytesDown are the per-session transfer
	// quotas applied to a grant created without explicit ones, as size
	// strings ("100m", "2g"). Empty means unlimited.
	DefaultMaxBytesUp   string `yaml:"default_max_bytes_up,omitempty"`
	DefaultMaxBytesDown string `yaml:"default_max_bytes_down,omitempty"`
}

// HostProcessAllowed reports the effective policy, applying the
// permissive-by-default rule for an absent setting.
func (e ExecutorsConfig) HostProcessAllowed() bool {
	return e.AllowHostProcess == nil || *e.AllowHostProcess
}

// HostProcessExplicit reports whether an operator stated the policy, as
// opposed to inheriting the back-compat default. The UI banner uses it to
// distinguish "permissive because nobody has decided yet" from "permissive on
// purpose".
func (e ExecutorsConfig) HostProcessExplicit() bool { return e.AllowHostProcess != nil }

// SetHostProcessAllowed records an explicit policy decision.
func (e *ExecutorsConfig) SetHostProcessAllowed(allowed bool) {
	v := allowed
	e.AllowHostProcess = &v
}

// ContainerExecutorConfig configures the container sandbox executor
// (pkg/executor/container).
//
// Every field here narrows what a workload can do, so a malformed value must
// never widen it. That is why parsing is strict — an unparsable memory limit
// is an error, not a silently-dropped limit — while the *absence* of a value
// falls back to the driver's own conservative defaults (no network, all
// capabilities dropped, a process cap).
type ContainerExecutorConfig struct {
	// Enabled registers the container executor at startup. Off by default:
	// a control plane should not gain a new way to execute code because a
	// container runtime appeared on the host.
	Enabled bool `yaml:"enabled,omitempty"`

	// ID is the executor's registry identifier, used by `cloop executor
	// test <id>` and by project bindings. Empty means "container".
	ID string `yaml:"id,omitempty"`

	// Runtime pins the container runtime: "podman" or "docker". Empty
	// auto-detects, preferring podman (rootless podman confines a workload
	// with a user namespace as well as with flags).
	Runtime string `yaml:"runtime,omitempty"`

	// OCIRuntime pins the low-level runtime that Runtime delegates to, as a
	// name that runtime already knows: "kata", "kata-qemu", "crun". Empty
	// leaves the CLI's default (runc or crun).
	//
	// A Kata name here is how a *local* Kata sandbox is configured: each
	// workload boots in a lightweight VM with its own kernel, so a kernel
	// exploit reaches the guest rather than the host. The executor then
	// reports isolation "vm" and is eligible for projects that require a
	// virtualized sandbox.
	//
	// It must be a registered runtime name and never a path — docker resolves
	// it against /etc/docker/daemon.json and podman against containers.conf,
	// both root-owned. Kata also needs /dev/kvm on the host, which `cloop
	// executor test <id>` checks.
	OCIRuntime string `yaml:"oci_runtime,omitempty"`

	// Image is the sandbox image reference. Empty uses the driver's
	// documented default; see container.DefaultImage for the contract an
	// image must satisfy.
	Image string `yaml:"image,omitempty"`

	// CPUs is the default core allowance per workload (1.5 = one and a half
	// cores). Zero means unlimited. Bounded by ContainerCPUsUpper.
	CPUs float64 `yaml:"cpus,omitempty"`

	// Memory is the default memory ceiling per workload, as a size string:
	// "512m", "2g", "1024k". A bare integer is read as megabytes. Empty
	// means unlimited. Swap is pinned to the same value, so a workload
	// cannot page past its ceiling.
	Memory string `yaml:"memory,omitempty"`

	// PIDsLimit caps processes and threads per workload. Zero uses the
	// driver default (1024); -1 disables the cap.
	PIDsLimit int `yaml:"pids_limit,omitempty"`

	// Network is "none" (default), "bridge", or an operator-defined network
	// name. "host" is rejected: it removes network isolation entirely and
	// exposes services bound to the host loopback, including the control
	// plane's own API.
	//
	// cloop does not filter egress itself. Anything other than "none" grants
	// unrestricted outbound access unless the named network carries its own
	// policy (a podman --internal network, a CNI plugin, an egress proxy).
	Network string `yaml:"network,omitempty"`

	// AllowHosts pins name resolution inside the sandbox as "host:address"
	// entries. Only valid when Network is not "none".
	AllowHosts []string `yaml:"allow_hosts,omitempty"`

	// ExtraArgs are additional runtime flags. Each must be a flag in
	// --flag=value form, and flags that would dismantle the sandbox
	// (--privileged, --cap-add, --volume, --network, ...) are rejected.
	ExtraArgs []string `yaml:"extra_args,omitempty"`

	// SELinuxLabel is the relabel option applied to bind mounts on SELinux
	// hosts: "z" (shared) or "Z" (private). Required for the workspace to be
	// readable inside the container when SELinux is enforcing.
	SELinuxLabel string `yaml:"selinux_label,omitempty"`

	// AllowRootUser permits the sandbox to run as uid 0. Default false.
	//
	// The workload's UID is derived from the project directory's owner, so a
	// control plane running as root over a root-owned project would otherwise
	// get a root sandbox without anyone having chosen one. Root in a container
	// defeats --cap-drop=ALL and turns a runtime escape into host root, so
	// that configuration is refused unless this is set deliberately. The
	// better fix is almost always to chown the project directory to an
	// unprivileged user.
	AllowRootUser bool `yaml:"allow_root_user,omitempty"`

	// EgressFilter bounds what a sandbox on this executor can reach, at the
	// IP layer. Disabled means the configured Network is used as-is, with
	// whatever egress it happens to provide.
	EgressFilter ContainerEgressFilterConfig `yaml:"egress_filter,omitempty"`
}

// ContainerEgressFilterConfig turns a sandbox's outbound access into an
// enforced allowlist rather than an advisory one.
//
// The distinction is the whole point. The egress broker
// (executors.egress / `cloop egress grant`) is an HTTP proxy: it enforces
// hostnames, methods and byte quotas, and it only sees traffic a workload
// chose to send through $HTTP_PROXY. A harness that opens a raw socket walks
// past all of it. This section is what binds that harness.
//
// The recommended shape is two lines:
//
//	egress_filter:
//	  enabled: true
//	  internal: true
//
// which puts sandboxes on a runtime network with no route off the host. The
// broker then becomes the only way out, which is what makes its host
// allowlist meaningful — and it needs no host privileges. Everything else
// here describes *direct* egress, needs nft(8) and CAP_NET_ADMIN, and is for
// destinations a sandbox must dial itself: a Kubernetes API server, an
// internal registry.
type ContainerEgressFilterConfig struct {
	// Enabled turns the filter on. Default false, deliberately: switching it
	// on under a running deployment is a change an operator makes, not one
	// an upgrade makes for them — the symptom would be a sandbox that can no
	// longer reach anything, which reads as a network outage.
	Enabled bool `yaml:"enabled,omitempty"`

	// Internal routes sandboxes onto a network with no route off the host.
	Internal bool `yaml:"internal,omitempty"`

	// AllowCIDRs are address ranges a sandbox may dial directly. This is the
	// only setting that opens private space, and it opens exactly what it
	// names: listing 10.8.0.0/24 does not lift the block on the rest of
	// 10.0.0.0/8, and no entry may cover the cloud metadata service without
	// naming its address outright.
	AllowCIDRs []string `yaml:"allow_cidrs,omitempty"`

	// AllowPorts bounds every allowed destination. Required whenever
	// AllowCIDRs or AllowPublicInternet is set: an allow rule with no port
	// restriction is a hole, and defaulting to 80 and 443 would be this file
	// guessing at a security boundary.
	AllowPorts []int `yaml:"allow_ports,omitempty"`

	// AllowPublicInternet opens every address outside the blocked ranges on
	// AllowPorts. It is what a hostname allowlist necessarily becomes at
	// layer 3, and it is spelled out here rather than inferred so that
	// widening a sandbox to the whole Internet is written down.
	AllowPublicInternet bool `yaml:"allow_public_internet,omitempty"`

	// Resolvers are DNS servers a sandbox may query directly, as address
	// literals ("10.7.0.10" or "10.7.0.10:53"). Without one, a direct-egress
	// filter drops UDP/53 and every name lookup fails — which is the single
	// most common way this section gets misconfigured.
	Resolvers []string `yaml:"resolvers,omitempty"`

	// Broker is the egress proxy endpoint, as an address:port literal. Only
	// needed alongside direct egress; on an internal network the broker is
	// reachable because it shares the bridge.
	//
	// Names are not accepted. A packet filter matches addresses, so a name
	// here would be resolved once at configuration time and pinned silently,
	// which is the DNS rebinding hazard the broker's own resolve-once
	// discipline exists to prevent.
	Broker string `yaml:"broker,omitempty"`

	// HostPatterns records the L7 allowlist this filter cannot enforce, so
	// that the rendered ruleset and the preflight report can say which
	// allowlist was widened into "the public Internet".
	HostPatterns []string `yaml:"host_patterns,omitempty"`
}

// KubernetesExecutorConfig configures the ephemeral-Pod executor
// (pkg/executor/kubernetes).
//
// One field is unlike anything in the container section: KubeconfigSecret
// names a *secret-broker reference*, not a path. This executor has no
// "kubeconfig file" setting and never will — the credential is leased from
// pkg/secretbroker for the duration of a run and consumed in memory, so that
// a control-plane host compromise does not hand over standing cluster access.
// An operator mints it with `cloop secret mint --kind kubeconfig` and grants
// it with `cloop secret grant ... --to executor:<id>`.
type KubernetesExecutorConfig struct {
	// Enabled registers the executor at startup. Off by default.
	Enabled bool `yaml:"enabled,omitempty"`

	// ID is the executor's registry identifier, used by `cloop executor
	// test <id>`, by grants (`--to executor:<id>`) and by project bindings.
	// Empty means "kubernetes".
	ID string `yaml:"id,omitempty"`

	// KubeconfigSecret names the brokered kubeconfig secret, by name or ID.
	// Empty accepts the first kubeconfig grant issued to this executor,
	// which is the common single-cluster case.
	KubeconfigSecret string `yaml:"kubeconfig_secret,omitempty"`

	// InCluster authenticates as the hub Pod's own ServiceAccount instead of
	// leasing a kubeconfig from the broker. Only meaningful when the hub is
	// itself running in the cluster it schedules into, which is what the
	// Helm chart in deploy/helm/cloop-hub sets up.
	//
	// It is not a weaker boundary than a brokered kubeconfig, it is a
	// different one: what the executor may do is a Role in the cluster,
	// enforced by the API server, rather than a grant in cloop's database
	// enforced by cloop. Mutually exclusive with KubeconfigSecret, because
	// "which identity is this executor using" must have one answer.
	InCluster bool `yaml:"in_cluster,omitempty"`

	// Context selects a kubeconfig context. Empty uses current-context.
	// Rarely needed: the broker already minimizes a kubeconfig to the
	// contexts a grant permits, usually leaving exactly one.
	Context string `yaml:"context,omitempty"`

	// Namespace is where Pods are created. Empty falls back to the grant's
	// pinned namespace, then the kubeconfig context's, then "cloop".
	Namespace string `yaml:"namespace,omitempty"`

	// Image is the harness image. Unlike the container executor there is no
	// bind-mounted host binary to fall back on, so this image must contain
	// cloop. Pin it by digest.
	Image string `yaml:"image,omitempty"`

	// ImagePullPolicy is "Always", "IfNotPresent" or "Never". Empty uses the
	// cluster default.
	ImagePullPolicy string `yaml:"image_pull_policy,omitempty"`

	// ImagePullSecrets names Secrets in Namespace holding registry auth.
	ImagePullSecrets []string `yaml:"image_pull_secrets,omitempty"`

	// ServiceAccount runs Pods under a named ServiceAccount. Its token is
	// still never mounted — automountServiceAccountToken is forced false —
	// so this is for image-pull secrets and Pod Security admission, not for
	// granting the workload cluster access.
	ServiceAccount string `yaml:"service_account,omitempty"`

	// CPURequest/CPULimit/MemoryRequest/MemoryLimit are Kubernetes quantity
	// strings: "500m", "2", "512Mi", "4Gi".
	CPURequest    string `yaml:"cpu_request,omitempty"`
	CPULimit      string `yaml:"cpu_limit,omitempty"`
	MemoryRequest string `yaml:"memory_request,omitempty"`
	MemoryLimit   string `yaml:"memory_limit,omitempty"`

	// EphemeralStorageLimit bounds writable scratch and logs ("10Gi").
	EphemeralStorageLimit string `yaml:"ephemeral_storage_limit,omitempty"`
	// WorkspaceSizeLimit bounds the workspace emptyDir specifically.
	WorkspaceSizeLimit string `yaml:"workspace_size_limit,omitempty"`

	// NodeSelector pins scheduling to labelled nodes.
	NodeSelector map[string]string `yaml:"node_selector,omitempty"`

	// Tolerations lets Pods schedule onto tainted nodes — the usual way to
	// reach a dedicated, untrusted-workload node pool.
	Tolerations []kubernetes.Toleration `yaml:"tolerations,omitempty"`

	// RuntimeClass names a RuntimeClass for every Pod, e.g. "kata",
	// "kata-qemu" or "kata-clh". Empty leaves the cluster default (runc).
	//
	// This is how a *remote* Kata sandbox is configured: kube-scheduler places
	// the Pod on a node advertising that handler and the workload boots in a
	// VM with its own kernel, on a machine that is not the control plane's.
	// The executor then reports virtualized: true.
	//
	// Kata node pools are conventionally tainted, so this usually appears
	// alongside tolerations and node_selector. The class must already exist in
	// the cluster; cloop does not create it.
	RuntimeClass string `yaml:"runtime_class,omitempty"`

	// ActiveDeadlineSeconds is the server-side wall-clock ceiling applied
	// when a run requests no timeout of its own. Zero means unbounded,
	// matching cloop's project-wide decision that runs are long-lived.
	// Enforced by the API server, so it survives a control-plane restart.
	ActiveDeadlineSeconds int64 `yaml:"active_deadline_seconds,omitempty"`

	// TerminationGracePeriodSeconds is how long a Pod gets between SIGTERM
	// and SIGKILL on a graceful stop. Zero means 30.
	TerminationGracePeriodSeconds int64 `yaml:"termination_grace_period_seconds,omitempty"`

	// KillGracePeriodSeconds is used for a hard stop. Zero means 5.
	KillGracePeriodSeconds int64 `yaml:"kill_grace_period_seconds,omitempty"`

	// RunAsUser/RunAsGroup override the non-root UID/GID the harness runs
	// as. Zero uses the distroless "nonroot" defaults (65532). Zero is not
	// an accepted *value*: this executor always sets runAsNonRoot.
	RunAsUser  int64 `yaml:"run_as_user,omitempty"`
	RunAsGroup int64 `yaml:"run_as_group,omitempty"`

	// KeepCompletedPods leaves finished Pods in the cluster for debugging
	// instead of deleting them once their logs and status are captured.
	KeepCompletedPods bool `yaml:"keep_completed_pods,omitempty"`

	// OrphanGracePeriodSeconds protects a young Pod from the startup
	// reconcile sweep. Zero means 600.
	OrphanGracePeriodSeconds int64 `yaml:"orphan_grace_period_seconds,omitempty"`

	// MaxConcurrent caps simultaneously-running Pods. Zero means unbounded;
	// the namespace's ResourceQuota is the real ceiling.
	MaxConcurrent int `yaml:"max_concurrent,omitempty"`

	// EgressFilter enforces an egress allowlist with a NetworkPolicy per Pod.
	// Absent means no policy is created and Pods keep the cluster's default
	// egress, which is what an upgrade must not change under an operator.
	EgressFilter KubernetesEgressFilterConfig `yaml:"egress_filter,omitempty"`
}

// KubernetesEgressFilterConfig turns a Pod's cluster egress into an enforced
// allowlist.
//
// It exists because the label was not enough. This executor has always set
// cloop.dev/egress on its Pods to say whether the workload was supposed to
// reach the network, and has always admitted that the label enforced nothing: a
// Pod joins the pod network, and no field in a Pod spec takes that away.
// Everything a sandbox could reach — other tenants' Pods, the node's kubelet,
// an internal service that trusts its network position, the Internet — it
// reached, whatever .cloop/sandbox.yaml asked for.
//
// The section is off by default and that default is load-bearing: an existing
// deployment upgrading into this code must not have its workloads firewalled by
// a field nobody set, and a security control that arrives switched on without
// being asked for is one operators learn to switch off. Enabling it is a
// decision, made once, in a file.
//
// The allowlist compiles to the same pkg/netfilter policy the container
// executor's nftables ruleset compiles from, so "allowed" means the same thing
// on both backends rather than being two rule sets that agree until they do
// not. What it cannot promise is enforcement: a NetworkPolicy is applied by the
// cluster's CNI, and `cloop executor test` warns that cloop cannot tell from
// the API whether yours implements one.
type KubernetesEgressFilterConfig struct {
	// Enabled creates a NetworkPolicy alongside every Pod. Off means no policy
	// object at all, not an empty one — an empty one denies everything.
	Enabled bool `yaml:"enabled,omitempty"`

	// CIDRs are the destination ranges a workload may reach ("10.8.0.0/24").
	//
	// They are also the only thing that waives the hard-block set — loopback,
	// RFC1918, link-local, CGNAT, multicast and the cloud metadata endpoint —
	// exactly as in the egress proxy: naming a private range explicitly buys
	// that range and nothing else. A /0 is refused; see allow_public_internet,
	// which says the same thing and attaches a warning to it.
	CIDRs []string `yaml:"cidrs,omitempty"`

	// Ports bound every destination allow, as destination port numbers.
	// Naming destinations without ports is an error rather than a guess: an
	// allow rule with no port restriction is a hole, and "they probably meant
	// 443" is not a decision a firewall compiler should make on an operator's
	// behalf.
	Ports []int `yaml:"ports,omitempty"`

	// AllowPublicInternet opens every address outside the block set, on Ports.
	//
	// It is the only way to express a hostname allowlist at layer 3, because
	// hostnames do not exist there — "*.github.com" resolves to addresses a
	// packet filter cannot enumerate. Setting it states that the sandbox may
	// dial the Internet directly; the narrow alternative is to route it through
	// the egress broker, which enforces hosts where they can be enforced.
	AllowPublicInternet bool `yaml:"allow_public_internet,omitempty"`

	// Resolvers are DNS servers the sandbox may query directly, as
	// "10.96.0.10" or "10.96.0.10:53". Needed only when the workload resolves
	// somewhere other than cluster DNS.
	Resolvers []string `yaml:"resolvers,omitempty"`

	// AllowClusterDNS opens UDP and TCP 53 to the kube-system namespace.
	// Unset means true, which is why it is a pointer: a default-deny egress
	// policy without it breaks name resolution, and that failure reads to
	// everyone involved as "the network is broken" rather than "DNS is denied".
	AllowClusterDNS *bool `yaml:"allow_cluster_dns,omitempty"`
}

// BackupConfig configures hot backups of the SQLite state database.
//
// AutoBackup is opt-in: cloop never spawns a backup goroutine without
// explicit consent because backups consume disk space and can occasionally
// pause writers briefly during the WAL checkpoint. Operators who want
// rolling daily snapshots set `backup.auto_backup: true` and (optionally)
// `backup.dir` to relocate them off the project working directory.
type BackupConfig struct {
	// AutoBackup, when true, instructs the cloop ui server to run a daily
	// backup of .cloop/state.db. Off by default.
	AutoBackup bool `yaml:"auto_backup,omitempty"`

	// Dir is the destination directory for automatic backups. When empty,
	// "<workdir>/.cloop/backups" is used. May be absolute or relative;
	// relative paths resolve against the project working directory.
	Dir string `yaml:"dir,omitempty"`

	// IntervalHours is the period between consecutive automatic backups.
	// Zero substitutes 24 (daily). Minimum 1, capped at 168 (weekly) so a
	// hand-edited config can't disable backups without setting AutoBackup
	// to false.
	IntervalHours int `yaml:"interval_hours,omitempty"`

	// KeepCount is the number of automatic backup files to retain in Dir.
	// Older files (matched by the "state-*.db" naming convention) are
	// removed after each successful run. Zero substitutes 7. A value of
	// -1 disables pruning entirely.
	KeepCount int `yaml:"keep_count,omitempty"`
}

// EffectiveIntervalHours returns the configured interval, substituting 24
// when zero. Out-of-range values fall back to the default so a corrupt
// config can't accidentally suppress all automatic backups.
func (b BackupConfig) EffectiveIntervalHours() int {
	if b.IntervalHours <= 0 || b.IntervalHours > 168 {
		return 24
	}
	return b.IntervalHours
}

// EffectiveKeepCount returns the configured retention count. -1 means
// "keep everything"; zero substitutes 7.
func (b BackupConfig) EffectiveKeepCount() int {
	if b.KeepCount == 0 {
		return 7
	}
	return b.KeepCount
}

// OrchestratorConfig holds wall-clock budgets and other knobs that bound the
// per-task execution of the PM orchestrator (Task 20108).
//
// The orchestrator already supported a per-task budget via Task.MaxMinutes
// (Task 99) and a per-project default via state.DefaultMaxMinutes. This
// config layer adds an optional process-wide default. The lookup order is:
//
//	task.MaxMinutes > state.DefaultMaxMinutes > config.Orchestrator.TaskTimeoutMinutes
//
// The first positive value wins; if all are zero there is NO task timeout
// (Task 20148): by default tasks run until they finish, are killed manually,
// or the parent run is cancelled. A positive value is an explicit opt-in that
// caps how long a single task may run; the deadline cancels the per-task
// context, which propagates into the provider HTTP call (Task 20081 made
// provider Complete() implementations honor ctx) and the task is marked
// timed_out.
type OrchestratorConfig struct {
	// TaskTimeoutMinutes is an optional process-wide wall-clock budget for a
	// single task, used when neither Task.MaxMinutes nor state.DefaultMaxMinutes
	// is set. Zero means no task timeout (Task 20148). A positive value is
	// validated to OrchestratorTaskTimeoutMinutesLower..OrchestratorTaskTimeoutMinutesUpper.
	TaskTimeoutMinutes int `yaml:"task_timeout_minutes,omitempty"`
}

// EffectiveTaskTimeoutMinutes returns the configured task timeout. Zero (the
// default) means no timeout (Task 20148). Out-of-band positive values are
// coerced to 0 (no timeout) rather than honoured, matching the orchestrator's
// effectiveTaskBudgetMinutes resolution.
func (o OrchestratorConfig) EffectiveTaskTimeoutMinutes() int {
	if o.TaskTimeoutMinutes < OrchestratorTaskTimeoutMinutesLower ||
		o.TaskTimeoutMinutes > OrchestratorTaskTimeoutMinutesUpper {
		return 0
	}
	return o.TaskTimeoutMinutes
}

// UIConfig holds settings for the cloop ui Web dashboard server.
//
// WebSocket caps (Task 20090) protect the server from goroutine exhaustion
// caused by accidental browser tab storms or deliberate connection floods.
// Each accepted upgrade spawns at least three goroutines (handler, drain,
// writer-loop ticker) plus an entry in the per-project hub registry; without
// caps a single client can register thousands of simultaneous peers.
type UIConfig struct {
	// MaxWebSocketConns caps the total number of concurrent WebSocket
	// connections the UI server will accept across all remote IPs.
	// Zero substitutes WebSocketConnsDefault (256).
	// Validated to WebSocketConnsLower..WebSocketConnsUpper.
	MaxWebSocketConns int `yaml:"max_websocket_conns,omitempty"`

	// MaxWebSocketConnsPerIP caps the number of concurrent WebSocket
	// connections accepted from any single remote IP. A breached cap
	// returns HTTP 429 with a Retry-After header; the connection is
	// rejected before nhooyr.Accept hijacks the request.
	// Zero substitutes WebSocketConnsPerIPDefault (8).
	// Validated to WebSocketConnsPerIPLower..WebSocketConnsPerIPUpper.
	MaxWebSocketConnsPerIP int `yaml:"max_websocket_conns_per_ip,omitempty"`

	// MaxRequestBodyBytes caps the size of any incoming HTTP request body
	// the UI server will accept (POST/PUT/PATCH on every /api/* endpoint).
	// Zero substitutes MaxRequestBodyBytesDefault (10 MiB). Validated to
	// MaxRequestBodyBytesLower..MaxRequestBodyBytesUpper. A breached cap
	// returns HTTP 413 (Request Entity Too Large) before the handler runs,
	// so a malicious or buggy client cannot OOM the daemon by streaming
	// a multi-GB body. Applies to both cloop ui and cloop serve.
	MaxRequestBodyBytes int64 `yaml:"max_request_body_bytes,omitempty"`

	// AllowedWSOrigins lists additional Origin hosts permitted to open a
	// WebSocket to the dashboard, on top of the always-allowed loopback
	// origins and same-origin requests (where the Origin host matches the
	// request Host). This is required when the dashboard is served behind a
	// reverse proxy on a public hostname AND the browser's Origin differs
	// from the Host the server sees (e.g. proxy rewrites Host). Each entry
	// is a host or host:port pattern accepted by the websocket library,
	// e.g. "aiden.example.com" or "aiden.example.com:1234". Same-origin
	// requests already work without listing anything here.
	AllowedWSOrigins []string `yaml:"allowed_ws_origins,omitempty"`

	// AllowedOrigins lists browser Origins permitted to open a WebSocket to
	// *any* endpoint of this hub, including the executor-agent endpoint at
	// /api/executors/connect. It is the deployment-wide setting;
	// AllowedWSOrigins remains the dashboard-only one and both are honoured
	// for the dashboard. Entries may be full origins
	// ("https://cloop.example.com"), host:port, or bare hosts.
	//
	// Loopback and same-origin requests are always allowed and need no entry
	// here — this exists for the reverse-proxy case where the browser's
	// Origin and the Host the server sees genuinely differ.
	AllowedOrigins []string `yaml:"allowed_origins,omitempty"`

	// ExternalURL is what this deployment calls itself, e.g.
	// https://cloop.example.com. Its host is always an accepted Origin, so a
	// correctly-set external URL usually makes allowed_origins unnecessary.
	// It is also what `cloop executor enroll` puts in enrollment bundles when
	// --server is not passed.
	ExternalURL string `yaml:"external_url,omitempty"`

	// TLS configures native HTTPS for `cloop ui` and `cloop serve`.
	// Disabled (plaintext) when cert_file and key_file are unset, which is
	// correct for loopback development and for a deployment that terminates
	// TLS in a reverse proxy.
	TLS TLSConfig `yaml:"tls,omitempty"`

	// OIDC configures optional OpenID Connect single sign-on for the web
	// dashboard. Disabled by default; see OIDCConfig.
	OIDC OIDCConfig `yaml:"oidc,omitempty"`

	// Quotas caps how much each identity may consume on a shared hub.
	// Empty (the default) means unlimited, which is what keeps a
	// single-tenant deployment untouched. See QuotasConfig.
	Quotas QuotasConfig `yaml:"quotas,omitempty"`
}

// QuotasConfig is the per-identity admission policy (Task 20182).
//
// It lives next to ui.oidc.role_mappings on purpose: RBAC decides whether an
// identity may act, this decides how much, and the two are read together when
// answering "what can this tenant do to my hub?". Keeping the bulk of quota
// policy in config rather than in the database also means it is reviewable,
// diffable and deployable like the role mappings it sits beside; the Quotas
// panel's per-identity edits are the escape hatch, stored separately and
// stamped with who made them.
//
//	ui:
//	  quotas:
//	    defaults:
//	      max_projects: 3
//	      max_concurrent_tasks: 1
//	      daily_token_budget: 500000
//	    bindings:
//	      - claim: group
//	        value: engineering
//	        limits:
//	          max_projects: 25
//	          max_concurrent_tasks: 4
//	      - claim: email
//	        value: sre@example.com
//	        limits:
//	          max_executors: 50
//
// Resolution is per-resource and most-specific-wins (sub > email > role >
// group > defaults). Within one tier the *smallest* ceiling wins, so joining
// another group can never raise a tenant's own cap. See pkg/quota.
type QuotasConfig struct {
	// Defaults apply to every identity no binding covers.
	Defaults map[string]float64 `yaml:"defaults,omitempty"`

	// Bindings narrow (or widen) limits per claim value.
	Bindings []QuotaBinding `yaml:"bindings,omitempty"`
}

// Configured reports whether any quota policy was written.
func (q QuotasConfig) Configured() bool {
	return len(q.Defaults) > 0 || len(q.Bindings) > 0
}

// QuotaBinding is one claim→limits binding in ui.quotas.bindings. It mirrors
// quota.Binding; cmd/ui_cmd.go converts between the two so pkg/config stays
// free of quota logic and pkg/quota stays free of YAML — the same split
// RoleMapping has with authz.Binding.
type QuotaBinding struct {
	// Claim selects what Value is compared against: group, role, email,
	// or sub. Same vocabulary as ui.oidc.role_mappings.
	Claim string `yaml:"claim"`

	// Value is the claim value to match. Group and role values are
	// compared case-insensitively and a leading "/" is ignored, so
	// Keycloak's group-path form works as written.
	Value string `yaml:"value"`

	// Limits are the ceilings this binding contributes. Valid keys are
	// max_projects, max_concurrent_tasks, max_executors, max_sessions,
	// daily_token_budget and daily_cost_usd. Only the keys present are
	// affected; the rest keep resolving from less specific bindings.
	Limits map[string]float64 `yaml:"limits,omitempty"`
}

// TLSConfig configures native TLS termination for cloop's HTTP servers.
//
// cloop can serve HTTPS itself, or sit behind a proxy that does. Both are
// supported; what is not supported is a half-configuration. Setting exactly
// one of cert_file/key_file is an error at startup rather than a silent
// fallback to plaintext, because "the operator asked for TLS and got HTTP
// without being told" is precisely the failure this exists to prevent.
type TLSConfig struct {
	// CertFile is the PEM certificate chain, leaf first.
	CertFile string `yaml:"cert_file,omitempty"`

	// KeyFile is the PEM private key. It should be mode 0600; a
	// world-readable server key is a complete impersonation of the control
	// plane, so cloop warns loudly (but still starts) when it is not.
	KeyFile string `yaml:"key_file,omitempty"`

	// MinVersion is the TLS floor: "1.2" (default) or "1.3". TLS 1.0 and 1.1
	// are rejected — they have no safe configuration left.
	MinVersion string `yaml:"min_version,omitempty"`
}

// Enabled reports whether native TLS is configured.
func (t TLSConfig) Enabled() bool {
	return strings.TrimSpace(t.CertFile) != "" || strings.TrimSpace(t.KeyFile) != ""
}

// Validate rejects a half-configured TLS block. Called by the ui/serve
// commands before binding a listener.
func (t TLSConfig) Validate() error {
	cert, key := strings.TrimSpace(t.CertFile), strings.TrimSpace(t.KeyFile)
	switch {
	case cert == "" && key == "":
		return nil
	case cert == "":
		return fmt.Errorf("ui.tls.key_file is set but ui.tls.cert_file is not; " +
			"both are required to serve HTTPS")
	case key == "":
		return fmt.Errorf("ui.tls.cert_file is set but ui.tls.key_file is not; " +
			"both are required to serve HTTPS")
	}
	return nil
}

// EnvOIDCClientSecret is the environment variable that supplies the OIDC
// client secret, overriding ui.oidc.client_secret.
//
// Named rather than repeated because two things have to agree about it: Load,
// which applies the override, and `cloop hub doctor`, which reports a hub whose
// secret came from the config file instead — and the whole point of the
// override is that config.yaml is the file an operator commits.
const EnvOIDCClientSecret = "CLOOP_OIDC_CLIENT_SECRET"

// OIDCConfig configures optional OpenID Connect single sign-on for the web
// dashboard (cloop ui). When Enabled, every browser request must carry a
// session established via the IdP authorization-code flow; the static
// bearer token (--token / CLOOP_UI_TOKEN) keeps working for API automation.
// Projects created through the UI are stamped with the signed-in user's
// identity and are only visible to that user (and admins); projects without
// an owner remain shared. Disabled by default — enabling requires issuer,
// client_id, client_secret, and redirect_url to all be set, otherwise
// `cloop ui` refuses to start (fail closed).
type OIDCConfig struct {
	// Enabled turns OIDC authentication on. Default false.
	Enabled bool `yaml:"enabled,omitempty"`

	// Issuer is the IdP base URL, e.g. https://auth.example.com/realms/main.
	// Discovery is performed at <issuer>/.well-known/openid-configuration.
	// Plain http is only accepted for localhost development IdPs.
	Issuer string `yaml:"issuer,omitempty"`

	// ClientID / ClientSecret identify cloop as a confidential client.
	ClientID     string `yaml:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty"`

	// RedirectURL is the externally reachable callback,
	// e.g. https://cloop.example.com/auth/callback.
	RedirectURL string `yaml:"redirect_url,omitempty"`

	// Scopes requested from the IdP. Default: openid profile email.
	// "openid" is always included.
	Scopes []string `yaml:"scopes,omitempty"`

	// AdminEmails lists users who see and manage every project regardless
	// of per-project ownership. Matched case-insensitively against the
	// email claim. Equivalent to a role_mappings entry with
	// claim: email, role: admin and no scope.
	AdminEmails []string `yaml:"admin_emails,omitempty"`

	// DefaultRole is the role granted to an authenticated identity that
	// matches no entry in RoleMappings. Empty (the default) means "none":
	// deny by default. Set to "viewer" for a read-only-by-default
	// deployment. Valid: none, viewer, operator, maintainer, admin.
	DefaultRole string `yaml:"default_role,omitempty"`

	// RoleMappings maps OIDC claim values to cloop roles, optionally
	// scoped to a single project or executor. See pkg/authz for the
	// permission ladder and the precedence rules.
	//
	//	oidc:
	//	  default_role: none
	//	  role_mappings:
	//	    - claim: group
	//	      value: cloop-admins
	//	      role: admin
	//	    - claim: group
	//	      value: engineering
	//	      role: operator
	//	    - claim: email          # narrower scope overrides the broader
	//	      value: dana@example.com
	//	      role: maintainer
	//	      project: payments
	RoleMappings []RoleMapping `yaml:"role_mappings,omitempty"`

	// SessionTTLHours is the absolute lifetime of a dashboard session — the
	// ceiling set at sign-in, which no amount of activity extends. Zero uses
	// the default (24); values are clamped to 1..720 (30 days).
	SessionTTLHours int `yaml:"session_ttl_hours,omitempty"`

	// IdleTimeoutHours ends a session that has gone unused for this long,
	// even though its absolute ceiling has not been reached. Zero uses the
	// default (8); values are clamped to 1..720 and additionally to
	// SessionTTLHours, since an idle window longer than the ceiling could
	// never fire.
	//
	// This is the clock that bounds an unattended browser, and it is the one
	// most deployments should tighten first: shortening it costs a re-login
	// after a long meeting, while shortening SessionTTLHours interrupts people
	// mid-task.
	IdleTimeoutHours int `yaml:"idle_timeout_hours,omitempty"`

	// RefreshIntervalMinutes is how often cloop re-checks a session against
	// the identity provider using the refresh token issued at sign-in. Zero
	// uses the default (15); values are clamped to 1..1440.
	//
	// It is the worst-case delay between the IdP disabling a user and their
	// cloop session ending, so it is the knob to turn when that lag matters.
	// Set it to -1 to disable the check entirely, which also disables
	// IdP-initiated revocation: the two timeouts then become the only way a
	// session ends. Requires CLOOP_SECRET_KEY, without which refresh tokens
	// are not retained — see docs/security/model.md.
	RefreshIntervalMinutes int `yaml:"refresh_interval_minutes,omitempty"`

	// CookieSecure controls the session cookie's Secure flag:
	// "auto" (default — set when the request arrived over TLS or with
	// X-Forwarded-Proto: https), "always", or "never".
	CookieSecure string `yaml:"cookie_secure,omitempty"`
}

// RoleMapping is one claim→role binding in oidc.role_mappings. It mirrors
// authz.Binding; pkg/ui converts between the two so pkg/config stays free of
// authorization logic and pkg/authz stays free of YAML.
type RoleMapping struct {
	// Claim selects what Value is compared against: group, role, email,
	// or sub.
	Claim string `yaml:"claim"`

	// Value is the claim value to match. Group and role values are
	// compared case-insensitively; a leading "/" is ignored so Keycloak's
	// "/cloop-admins" group-path form works as written.
	Value string `yaml:"value"`

	// Role is granted to matching identities: viewer, operator,
	// maintainer, or admin (or none, to explicitly deny within a scope).
	Role string `yaml:"role"`

	// Project narrows the binding to one project, matched against either
	// the project's registry name or its filesystem path. Empty means
	// every project.
	Project string `yaml:"project,omitempty"`

	// Executor narrows the binding to one executor ID. Empty means every
	// executor.
	Executor string `yaml:"executor,omitempty"`
}

// OIDC session TTL bounds (hours).
const (
	OIDCSessionTTLHoursDefault = 24
	OIDCSessionTTLHoursLower   = 1
	OIDCSessionTTLHoursUpper   = 720
)

// OIDC idle-timeout bounds (hours). The upper bound matches the absolute TTL's
// because the effective value is clamped to it anyway.
const (
	OIDCIdleTimeoutHoursDefault = 8
	OIDCIdleTimeoutHoursLower   = 1
	OIDCIdleTimeoutHoursUpper   = 720
)

// OIDC IdP-revalidation bounds (minutes).
//
// The lower bound is one minute rather than zero seconds: a hub that asked the
// provider about every session every few seconds would be indistinguishable
// from a denial-of-service against its own IdP. The upper bound is a day,
// beyond which the check no longer meaningfully bounds revocation lag.
const (
	OIDCRefreshIntervalMinutesDefault = 15
	OIDCRefreshIntervalMinutesLower   = 1
	OIDCRefreshIntervalMinutesUpper   = 1440
)

// EffectiveSessionTTLHours returns the configured session lifetime with the
// zero-default substituted and out-of-band values clamped.
func (o OIDCConfig) EffectiveSessionTTLHours() int {
	switch {
	case o.SessionTTLHours <= 0:
		return OIDCSessionTTLHoursDefault
	case o.SessionTTLHours < OIDCSessionTTLHoursLower:
		return OIDCSessionTTLHoursLower
	case o.SessionTTLHours > OIDCSessionTTLHoursUpper:
		return OIDCSessionTTLHoursUpper
	}
	return o.SessionTTLHours
}

// EffectiveIdleTimeoutHours returns the configured idle window with the
// zero-default substituted, out-of-band values clamped, and the result held
// down to the absolute TTL.
//
// The final clamp is what keeps a half-edited config coherent: lowering
// session_ttl_hours below idle_timeout_hours would otherwise leave an idle
// clock that can never fire, silently removing the protection the operator
// most likely believes is on.
func (o OIDCConfig) EffectiveIdleTimeoutHours() int {
	h := o.IdleTimeoutHours
	switch {
	case h <= 0:
		h = OIDCIdleTimeoutHoursDefault
	case h < OIDCIdleTimeoutHoursLower:
		h = OIDCIdleTimeoutHoursLower
	case h > OIDCIdleTimeoutHoursUpper:
		h = OIDCIdleTimeoutHoursUpper
	}
	if ttl := o.EffectiveSessionTTLHours(); h > ttl {
		h = ttl
	}
	return h
}

// EffectiveRefreshIntervalMinutes returns how often a session is revalidated
// against the IdP. A negative configured value is passed through as -1, the
// explicit "never re-check" opt-out; every other out-of-band value is clamped.
func (o OIDCConfig) EffectiveRefreshIntervalMinutes() int {
	switch {
	case o.RefreshIntervalMinutes < 0:
		return -1
	case o.RefreshIntervalMinutes == 0:
		return OIDCRefreshIntervalMinutesDefault
	case o.RefreshIntervalMinutes < OIDCRefreshIntervalMinutesLower:
		return OIDCRefreshIntervalMinutesLower
	case o.RefreshIntervalMinutes > OIDCRefreshIntervalMinutesUpper:
		return OIDCRefreshIntervalMinutesUpper
	}
	return o.RefreshIntervalMinutes
}

// EffectiveMaxWebSocketConns returns the configured total cap, substituting
// WebSocketConnsDefault when the field is zero (the YAML "not set" sentinel).
func (u UIConfig) EffectiveMaxWebSocketConns() int {
	if u.MaxWebSocketConns <= 0 {
		return WebSocketConnsDefault
	}
	return u.MaxWebSocketConns
}

// EffectiveMaxWebSocketConnsPerIP returns the configured per-IP cap,
// substituting WebSocketConnsPerIPDefault when the field is zero.
func (u UIConfig) EffectiveMaxWebSocketConnsPerIP() int {
	if u.MaxWebSocketConnsPerIP <= 0 {
		return WebSocketConnsPerIPDefault
	}
	return u.MaxWebSocketConnsPerIP
}

// EffectiveMaxRequestBodyBytes returns the configured request-body cap,
// substituting MaxRequestBodyBytesDefault (10 MiB) when the field is zero.
// Used by both pkg/ui and pkg/apiserver to size their http.MaxBytesReader
// wrappers.
func (u UIConfig) EffectiveMaxRequestBodyBytes() int64 {
	if u.MaxRequestBodyBytes <= 0 {
		return MaxRequestBodyBytesDefault
	}
	return u.MaxRequestBodyBytes
}

// TracingConfig holds OpenTelemetry tracing settings.
type TracingConfig struct {
	// Enabled activates OTLP trace export. Default: false (no-op).
	Enabled bool `yaml:"enabled,omitempty"`
	// Endpoint is the OTLP HTTP receiver base URL, e.g. "http://localhost:4318".
	// The exporter appends /v1/traces automatically.
	Endpoint string `yaml:"endpoint,omitempty"`
	// ServiceName is reported as the OTel service.name resource attribute.
	// Defaults to "cloop".
	ServiceName string `yaml:"service_name,omitempty"`
}

// RateLimitConfig controls the per-IP token-bucket rate limiter applied to
// the REST API server (cloop serve) and the Web UI server (cloop ui).
type RateLimitConfig struct {
	// RequestsPerSecond is the sustained request rate allowed per remote IP.
	// Default: 20 requests/second.
	RequestsPerSecond float64 `yaml:"requests_per_second,omitempty"`
	// Burst is the maximum burst size (bucket capacity) per remote IP.
	// Default: 50 requests.
	Burst int `yaml:"burst,omitempty"`
}

// WatchConfig configures file-triggered plan re-evaluation.
type WatchConfig struct {
	// Globs are file patterns to monitor (e.g. "**/*.go").
	// Used as defaults when --glob is not specified on the command line.
	Globs []string `yaml:"globs,omitempty"`
	// Debounce is the duration to wait after the last change before triggering
	// (e.g. "2s", "500ms"). Defaults to 2s.
	Debounce string `yaml:"debounce,omitempty"`
}

// HooksConfig holds shell commands executed at task and plan lifecycle events.
// Commands run via "sh -c" with context passed as environment variables.
type HooksConfig struct {
	// PreTask runs before each task. Exit non-zero causes the task to be skipped.
	// Env: CLOOP_TASK_ID, CLOOP_TASK_TITLE, CLOOP_TASK_STATUS, CLOOP_TASK_ROLE
	PreTask string `yaml:"pre_task,omitempty"`
	// PostTask runs after each task completes (regardless of outcome).
	// Same env vars as PreTask, with CLOOP_TASK_STATUS set to the final status.
	PostTask string `yaml:"post_task,omitempty"`
	// PrePlan runs once before plan execution begins.
	// Env: CLOOP_PLAN_GOAL, CLOOP_PLAN_TOTAL
	PrePlan string `yaml:"pre_plan,omitempty"`
	// PostPlan runs once after the plan finishes.
	// Env: CLOOP_PLAN_GOAL, CLOOP_PLAN_TOTAL, CLOOP_PLAN_DONE, CLOOP_PLAN_FAILED, CLOOP_PLAN_SKIPPED
	PostPlan string `yaml:"post_plan,omitempty"`
	// PostTaskReview enables AI code review annotations after each successful task.
	// Equivalent to passing --post-review on the command line.
	PostTaskReview bool `yaml:"post_task_review,omitempty"`
	// Timeout caps the wall-clock duration of every hook invocation, parsed via
	// time.ParseDuration (e.g. "30s", "5m", "2h"). Empty defaults to 10 minutes.
	// Use "-1s" (or any negative duration) to disable the timeout for hooks
	// that legitimately exceed the default.
	Timeout string `yaml:"timeout,omitempty"`
}

// RouterConfig maps AgentRole names to provider names.
// Roles not listed here use the default provider.
type RouterConfig struct {
	// Routes maps role name (backend, frontend, testing, security, devops, data, docs, review)
	// to a provider name (anthropic, openai, ollama, claudecode).
	Routes map[string]string `yaml:"routes,omitempty"`
}

// WebhookConfig holds outbound notification settings.
type WebhookConfig struct {
	// URL to POST events to (empty = disabled).
	URL string `yaml:"url,omitempty"`
	// Events to fire (empty = all). Valid values:
	//   session_started, session_complete, session_failed,
	//   task_started, task_done, task_failed, task_skipped,
	//   plan_complete, evolve_discovered
	Events []string `yaml:"events,omitempty"`
	// Optional HTTP headers added to every request (e.g. Authorization).
	Headers map[string]string `yaml:"headers,omitempty"`
	// Secret, if set, signs every request with HMAC-SHA256 in the
	// X-Hub-Signature-256 header (GitHub-style webhook signing).
	Secret string `yaml:"secret,omitempty"`
}

type AnthropicConfig struct {
	// API key (falls back to ANTHROPIC_API_KEY env var)
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
	BaseURL string `yaml:"base_url"`

	// Inference parameters (nil = use provider default)
	Temperature *float64 `yaml:"temperature,omitempty"`
	TopP        *float64 `yaml:"top_p,omitempty"`
	MaxTokens   int      `yaml:"max_tokens,omitempty"`
}

type OpenAIConfig struct {
	// API key (falls back to OPENAI_API_KEY env var)
	APIKey string `yaml:"api_key"`
	Model  string `yaml:"model"`
	// Optional: set for Azure OpenAI or OpenAI-compatible servers
	BaseURL string `yaml:"base_url"`

	// Inference parameters (nil = use provider default)
	Temperature      *float64 `yaml:"temperature,omitempty"`
	TopP             *float64 `yaml:"top_p,omitempty"`
	FrequencyPenalty *float64 `yaml:"frequency_penalty,omitempty"`
	MaxTokens        int      `yaml:"max_tokens,omitempty"`
}

type OllamaConfig struct {
	BaseURL string `yaml:"base_url"`
	Model   string `yaml:"model"`

	// Inference parameters (nil = use provider default)
	Temperature *float64 `yaml:"temperature,omitempty"`
	TopP        *float64 `yaml:"top_p,omitempty"`
	MaxTokens   int      `yaml:"max_tokens,omitempty"`
}

type ClaudeCodeConfig struct {
	Model string `yaml:"model"`

	// Effort is the default reasoning-effort level passed to the claude CLI
	// as --effort. Valid: low, medium, high, xhigh, max; empty = CLI default.
	// The per-project effort persisted in project state (set via the Web UI,
	// cloop init --effort, or cloop run --effort) takes precedence.
	Effort string `yaml:"effort,omitempty"`

	// MaxWeeklyPct, when > 0, blocks new runs once the global Anthropic weekly
	// (7-day) utilization reported by the OAuth usage API reaches this percent.
	// Example: 50 means "stop running this project once 50% of the weekly limit
	// has been consumed across all your Claude usage" — useful to reserve
	// headroom for other work.
	MaxWeeklyPct float64 `yaml:"max_weekly_pct,omitempty"`

	// MaxFiveHourPct, when > 0, blocks new runs once the global 5-hour window
	// utilization reaches this percent.
	MaxFiveHourPct float64 `yaml:"max_five_hour_pct,omitempty"`

	// MaxWeeklyOpusPct, when > 0, blocks new runs once the weekly Opus
	// utilization reaches this percent.
	MaxWeeklyOpusPct float64 `yaml:"max_weekly_opus_pct,omitempty"`

	// MaxWeeklySonnetPct, when > 0, blocks new runs once the weekly Sonnet
	// utilization reaches this percent.
	MaxWeeklySonnetPct float64 `yaml:"max_weekly_sonnet_pct,omitempty"`
}

// MockConfig holds settings for the deterministic offline mock provider.
type MockConfig struct {
	// ResponsesFile is the path (absolute or relative to workdir) to a YAML file
	// mapping prompt substrings/hashes to canned responses.
	// Defaults to .cloop/mock_responses.yaml when empty.
	ResponsesFile string `yaml:"responses_file,omitempty"`
	// Default is the response returned when no rule matches.
	// Defaults to "TASK_DONE".
	Default string `yaml:"default,omitempty"`
}

// NotifyConfig holds notification channel settings.
type NotifyConfig struct {
	// Desktop enables OS desktop notifications (notify-send on Linux, osascript on macOS).
	Desktop bool `yaml:"desktop,omitempty"`
	// SlackWebhook is the Slack incoming webhook URL.
	// Format: https://hooks.slack.com/services/...
	SlackWebhook string `yaml:"slack_webhook,omitempty"`
	// DiscordWebhook is the Discord webhook URL.
	// Format: https://discord.com/api/webhooks/...
	DiscordWebhook string `yaml:"discord_webhook,omitempty"`
	// CustomWebhook is a generic HTTP webhook URL for custom integrations.
	// cloop POSTs JSON: {"title":"...", "body":"...", "source":"cloop"}
	CustomWebhook string `yaml:"custom_webhook,omitempty"`
}

// SyncConfig configures git-based team plan sharing.
type SyncConfig struct {
	// Remote is the git remote name to sync with (default "origin").
	Remote string `yaml:"remote,omitempty"`
	// Branch is the branch name used to push/pull cloop state (default "cloop-state").
	Branch string `yaml:"branch,omitempty"`
}

// GitHubConfig holds GitHub integration settings.
type GitHubConfig struct {
	// Personal access token (falls back to GITHUB_TOKEN env var)
	Token string `yaml:"token,omitempty"`
	// Default repo in "owner/repo" format (falls back to git remote detection)
	Repo string `yaml:"repo,omitempty"`
	// Labels added to issues created by cloop push
	Labels []string `yaml:"labels,omitempty"`
}

// BudgetConfig holds spend limit settings.
type BudgetConfig struct {
	// MonthlyUSD is the maximum allowed API spend per calendar month.
	// 0 means no limit. When exceeded, cloop warns (or blocks) new task runs.
	MonthlyUSD float64 `yaml:"monthly_usd,omitempty"`

	// DailyUSDLimit is the maximum allowed API spend per calendar day (UTC).
	// 0 means no limit. When exceeded, cloop aborts task execution.
	DailyUSDLimit float64 `yaml:"daily_usd_limit,omitempty"`

	// DailyTokenLimit is the maximum total tokens (input + output) allowed per
	// calendar day (UTC). 0 means no limit.
	DailyTokenLimit int `yaml:"daily_token_limit,omitempty"`

	// AlertThresholdPct is the percentage of the daily budget at which cloop
	// fires a desktop/webhook alert. Default 80 (80%).
	AlertThresholdPct int `yaml:"alert_threshold_pct,omitempty"`

	// GlobalUSDPct caps this project's daily USD spend to a percentage of the
	// global daily USD limit defined in ~/.config/cloop/budget.yaml.
	// E.g. 80 means this project may not exceed 80% of the global daily USD cap.
	// 0 means no percentage cap.
	GlobalUSDPct float64 `yaml:"global_usd_pct,omitempty"`

	// GlobalTokenPct caps this project's daily token usage to a percentage of
	// the global daily token limit defined in ~/.config/cloop/budget.yaml.
	// 0 means no percentage cap.
	GlobalTokenPct float64 `yaml:"global_token_pct,omitempty"`

	// BlockExtraUsage, when true (default), prevents cloop from running tasks
	// when doing so would incur Claude Code extra usage (per-token billing
	// beyond the subscription). Set to false to allow extra usage.
	BlockExtraUsage *bool `yaml:"block_extra_usage,omitempty"`
}

// ShouldBlockExtraUsage returns true if extra usage should be blocked.
// Defaults to true when not explicitly set.
func (b BudgetConfig) ShouldBlockExtraUsage() bool {
	if b.BlockExtraUsage == nil {
		return true // default: block
	}
	return *b.BlockExtraUsage
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Provider: "claudecode",
		Anthropic: AnthropicConfig{
			Model: "claude-opus-4-6",
		},
		OpenAI: OpenAIConfig{
			Model: "gpt-4o",
		},
		Ollama: OllamaConfig{
			BaseURL: "http://localhost:11434",
			Model:   "llama3.2",
		},
		// Step timeout is disabled by default (Task 20147): a long task step
		// (e.g. a slow provider call or a large refactor) should not be killed
		// by an arbitrary wall-clock cap unless the user opts in. "0" means
		// "no per-step timeout"; cmd/run treats "0" and "" identically.
		StepTimeout: "0",
	}
}

// ConfigPath returns the path to the config file.
func ConfigPath(workdir string) string {
	return filepath.Join(workdir, configFile)
}

// stateDBPath returns the SQLite state database path for the given workdir.
// Mirrors the location used by pkg/state.effectiveDBPath for the default
// (non-session) case, which is sufficient for Save/Load mirroring: sessions
// have their own state.db and load their own per-session config separately.
func stateDBPath(workdir string) string {
	return filepath.Join(workdir, ".cloop", "state.db")
}

// mirrorToSQLite stores the YAML-serialised config in the project's state.db.
// Best-effort: if state.db doesn't exist or can't be opened, returns nil
// silently — the YAML file is the authoritative store and the SQLite mirror
// is an enhancement, not a requirement. We deliberately do NOT create
// state.db here: that would make Save() a side-effecting init for every
// directory the user happens to pass in.
func mirrorToSQLite(workdir string, data []byte) {
	dbPath := stateDBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return
	}
	defer db.Close()
	_ = db.SetConfigBlob(string(data))
	// Tighten permissions defensively — config blob may include API keys.
	// state.db is created with the umask default (often 0644); on Unix we
	// shrink to 0600 once it carries credentials. Errors are ignored: this
	// is a hardening pass, not a precondition.
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dbPath, 0o600)
	}
}

// loadFromSQLite returns the YAML-serialised config previously mirrored into
// state.db, or "" if no mirror exists. Used by Load() as a fallback when the
// .cloop/config.yaml file is missing — a config-set followed by a stray
// `rm config.yaml` no longer wipes the user's API keys, model picks, and
// budget caps. Errors are swallowed: the YAML-missing path must keep working
// even if the SQLite mirror is unreadable.
func loadFromSQLite(workdir string) string {
	dbPath := stateDBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return ""
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return ""
	}
	defer db.Close()
	blob, err := db.GetConfigBlob()
	if err != nil {
		return ""
	}
	return blob
}

// Load reads config from .cloop/config.yaml. Returns defaults if missing.
// Environment variables override file values: ANTHROPIC_API_KEY, OPENAI_API_KEY,
// ANTHROPIC_BASE_URL, OPENAI_BASE_URL, OLLAMA_BASE_URL, CLOOP_PROVIDER,
// GITHUB_TOKEN, CLOOP_OIDC_CLIENT_SECRET.
// On Unix systems, Load prints a warning when the config file is world-readable
// (permissions wider than 0600) because it may contain API keys.
//
// When the YAML file is missing, Load transparently falls back to the SQLite
// mirror written by Save() (see stateDBPath / mirrorToSQLite). The SQLite
// mirror is a recovery store, not the authoritative one — a present YAML
// file always wins so manual edits keep the expected semantics.
func Load(workdir string) (*Config, error) {
	cfg := Default()
	path := ConfigPath(workdir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// Fall back to the SQLite mirror so a missing config.yaml doesn't
		// silently revert API keys and budget caps to defaults.
		if blob := loadFromSQLite(workdir); blob != "" {
			if err := yaml.Unmarshal([]byte(blob), cfg); err == nil {
				cfg.validateAndClamp(path)
				cfg.applyEnvVars()
				return cfg, nil
			}
		}
		cfg.applyEnvVars()
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	// Warn on Unix if the config file is world- or group-readable. The warning
	// fires once per path per process — Load() is hot in long-running processes
	// (UI, daemon, auto-evolve) and an unconditional Fprintf would flood stderr.
	if runtime.GOOS != "windows" {
		if fi, statErr := os.Stat(path); statErr == nil {
			if fi.Mode().Perm()&0o077 != 0 {
				permWarnedMu.Lock()
				_, already := permWarnedPaths[path]
				if !already {
					permWarnedPaths[path] = struct{}{}
				}
				permWarnedMu.Unlock()
				if !already {
					fmt.Fprintf(os.Stderr, "warning: %s has permissions %o — it may contain API keys. Run: chmod 600 %s\n",
						path, fi.Mode().Perm(), path)
				}
			}
		}
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.validateAndClamp(path)
	cfg.applyEnvVars()
	return cfg, nil
}

// validateAndClamp inspects user-supplied numeric values, warns once per
// (path, field) when a value is outside the safe range, and resets the field
// to its zero value (= "use default") so the runtime cannot be steered into
// pathological behaviour by a bad config. This is the *defensive* path —
// `cloop config set` rejects bad values up front; this function exists so a
// hand-edited or migrated YAML can never spawn 5000 goroutines, push
// negative budgets, or emit nonsensical alert thresholds.
func (c *Config) validateAndClamp(path string) {
	warn := func(field, msg string) {
		key := path + "::" + field
		clampWarnedMu.Lock()
		_, already := clampWarnedPairs[key]
		if !already {
			clampWarnedPairs[key] = struct{}{}
		}
		clampWarnedMu.Unlock()
		if already {
			return
		}
		// "clamped to default" is the outcome for almost every repair here, but
		// not all: a few sections disable themselves instead, because for them
		// the default is *weaker* than the value being rejected (an executor
		// whose oci_runtime is malformed must not fall back to runc). Those
		// messages state their own outcome, and appending the generic one would
		// contradict it in the same sentence.
		if strings.Contains(msg, "disabled") {
			fmt.Fprintf(os.Stderr, "warning: config %s: %s\n", field, msg)
			return
		}
		fmt.Fprintf(os.Stderr, "warning: config %s: %s — clamped to default\n", field, msg)
	}
	// max_parallel: zero is "not set"; non-zero must be in [1, 64].
	if c.MaxParallel != 0 && (c.MaxParallel < MaxParallelLower || c.MaxParallel > MaxParallelUpper) {
		warn("max_parallel", fmt.Sprintf("value %d outside [%d, %d]", c.MaxParallel, MaxParallelLower, MaxParallelUpper))
		c.MaxParallel = 0
	}
	// rate_limit.requests_per_second: zero = use HTTP default; non-zero must be positive.
	if c.RateLimit.RequestsPerSecond < 0 || (c.RateLimit.RequestsPerSecond > 0 && c.RateLimit.RequestsPerSecond < RateLimitRPSLower) {
		warn("rate_limit.requests_per_second", fmt.Sprintf("value %.4f must be >= %.0f (or 0 for default)", c.RateLimit.RequestsPerSecond, RateLimitRPSLower))
		c.RateLimit.RequestsPerSecond = 0
	}
	// rate_limit.burst: zero = use HTTP default; non-zero must be positive.
	if c.RateLimit.Burst < 0 || (c.RateLimit.Burst > 0 && c.RateLimit.Burst < RateLimitBurstLower) {
		warn("rate_limit.burst", fmt.Sprintf("value %d must be >= %d (or 0 for default)", c.RateLimit.Burst, RateLimitBurstLower))
		c.RateLimit.Burst = 0
	}
	// Budget caps: must be >= 0. Zero means "no limit"; negative is meaningless.
	if c.Budget.MonthlyUSD < 0 {
		warn("budget.monthly_usd", fmt.Sprintf("value %.4f must be >= 0", c.Budget.MonthlyUSD))
		c.Budget.MonthlyUSD = 0
	}
	if c.Budget.DailyUSDLimit < 0 {
		warn("budget.daily_usd_limit", fmt.Sprintf("value %.4f must be >= 0", c.Budget.DailyUSDLimit))
		c.Budget.DailyUSDLimit = 0
	}
	if c.Budget.DailyTokenLimit < 0 {
		warn("budget.daily_token_limit", fmt.Sprintf("value %d must be >= 0", c.Budget.DailyTokenLimit))
		c.Budget.DailyTokenLimit = 0
	}
	if c.Budget.AlertThresholdPct < AlertThresholdMin || c.Budget.AlertThresholdPct > AlertThresholdMax {
		warn("budget.alert_threshold_pct", fmt.Sprintf("value %d outside [%d, %d]", c.Budget.AlertThresholdPct, AlertThresholdMin, AlertThresholdMax))
		c.Budget.AlertThresholdPct = 0
	}
	if c.Budget.GlobalUSDPct < 0 || c.Budget.GlobalUSDPct > 100 {
		warn("budget.global_usd_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.Budget.GlobalUSDPct))
		c.Budget.GlobalUSDPct = 0
	}
	if c.Budget.GlobalTokenPct < 0 || c.Budget.GlobalTokenPct > 100 {
		warn("budget.global_token_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.Budget.GlobalTokenPct))
		c.Budget.GlobalTokenPct = 0
	}
	// Claude Code subscription caps: 0..100 percent.
	if c.ClaudeCode.MaxWeeklyPct < 0 || c.ClaudeCode.MaxWeeklyPct > 100 {
		warn("claudecode.max_weekly_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.ClaudeCode.MaxWeeklyPct))
		c.ClaudeCode.MaxWeeklyPct = 0
	}
	if c.ClaudeCode.MaxFiveHourPct < 0 || c.ClaudeCode.MaxFiveHourPct > 100 {
		warn("claudecode.max_five_hour_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.ClaudeCode.MaxFiveHourPct))
		c.ClaudeCode.MaxFiveHourPct = 0
	}
	if c.ClaudeCode.MaxWeeklyOpusPct < 0 || c.ClaudeCode.MaxWeeklyOpusPct > 100 {
		warn("claudecode.max_weekly_opus_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.ClaudeCode.MaxWeeklyOpusPct))
		c.ClaudeCode.MaxWeeklyOpusPct = 0
	}
	if c.ClaudeCode.MaxWeeklySonnetPct < 0 || c.ClaudeCode.MaxWeeklySonnetPct > 100 {
		warn("claudecode.max_weekly_sonnet_pct", fmt.Sprintf("value %.4f outside [0, 100]", c.ClaudeCode.MaxWeeklySonnetPct))
		c.ClaudeCode.MaxWeeklySonnetPct = 0
	}
	// UI WebSocket caps: zero means "use default"; non-zero must lie inside
	// the allowed band. Out-of-range values fall back to zero so the
	// runtime substitutes the sane default rather than honouring a
	// pathological "0 connections" or "10M per IP" hand-edit.
	if c.UI.MaxWebSocketConns != 0 && (c.UI.MaxWebSocketConns < WebSocketConnsLower || c.UI.MaxWebSocketConns > WebSocketConnsUpper) {
		warn("ui.max_websocket_conns", fmt.Sprintf("value %d outside [%d, %d]", c.UI.MaxWebSocketConns, WebSocketConnsLower, WebSocketConnsUpper))
		c.UI.MaxWebSocketConns = 0
	}
	if c.UI.MaxWebSocketConnsPerIP != 0 && (c.UI.MaxWebSocketConnsPerIP < WebSocketConnsPerIPLower || c.UI.MaxWebSocketConnsPerIP > WebSocketConnsPerIPUpper) {
		warn("ui.max_websocket_conns_per_ip", fmt.Sprintf("value %d outside [%d, %d]", c.UI.MaxWebSocketConnsPerIP, WebSocketConnsPerIPLower, WebSocketConnsPerIPUpper))
		c.UI.MaxWebSocketConnsPerIP = 0
	}
	// A per-IP cap larger than the total cap is meaningless: a single IP
	// could never reach it. Surface the misconfiguration and reset both
	// to defaults so the operator notices.
	if c.UI.MaxWebSocketConns != 0 && c.UI.MaxWebSocketConnsPerIP != 0 && c.UI.MaxWebSocketConnsPerIP > c.UI.MaxWebSocketConns {
		warn("ui.max_websocket_conns_per_ip", fmt.Sprintf("value %d exceeds ui.max_websocket_conns %d", c.UI.MaxWebSocketConnsPerIP, c.UI.MaxWebSocketConns))
		c.UI.MaxWebSocketConnsPerIP = 0
	}
	// Request body cap: zero means default; out-of-range falls back to zero
	// so the runtime substitutes MaxRequestBodyBytesDefault. Pathological
	// values (negative, microscopically small, or absurdly large) are
	// silently corrected rather than left in place.
	if c.UI.MaxRequestBodyBytes != 0 && (c.UI.MaxRequestBodyBytes < MaxRequestBodyBytesLower || c.UI.MaxRequestBodyBytes > MaxRequestBodyBytesUpper) {
		warn("ui.max_request_body_bytes", fmt.Sprintf("value %d outside [%d, %d]", c.UI.MaxRequestBodyBytes, MaxRequestBodyBytesLower, MaxRequestBodyBytesUpper))
		c.UI.MaxRequestBodyBytes = 0
	}
	// orchestrator.task_timeout_minutes: zero means "use default"; non-zero must
	// be in [1, 7*24*60]. Out-of-range falls back to zero so the runtime
	// substitutes OrchestratorTaskTimeoutMinutesDefault rather than honouring a
	// pathological 0-second or week-spanning budget.
	if c.Orchestrator.TaskTimeoutMinutes != 0 && (c.Orchestrator.TaskTimeoutMinutes < OrchestratorTaskTimeoutMinutesLower || c.Orchestrator.TaskTimeoutMinutes > OrchestratorTaskTimeoutMinutesUpper) {
		warn("orchestrator.task_timeout_minutes", fmt.Sprintf("value %d outside [%d, %d]", c.Orchestrator.TaskTimeoutMinutes, OrchestratorTaskTimeoutMinutesLower, OrchestratorTaskTimeoutMinutesUpper))
		c.Orchestrator.TaskTimeoutMinutes = 0
	}
	// Container executor: every repair resets to the driver's default, which
	// is always the more confined choice, so a bad value can never widen the
	// sandbox. The field name is included in the warning key so each distinct
	// problem is reported once rather than the section as a whole.
	for _, msg := range clampContainerExecutor(&c.Executors.Container) {
		field, detail, found := strings.Cut(msg, ": ")
		if !found {
			field, detail = "executors.container", msg
		}
		warn(field, detail)
	}
	// Kubernetes executor: same rule, same reason — a repaired field falls
	// back to the driver's confining default rather than being honoured.
	for _, msg := range clampKubernetesExecutor(&c.Executors.Kubernetes) {
		field, detail, found := strings.Cut(msg, ": ")
		if !found {
			field, detail = "executors.kubernetes", msg
		}
		warn(field, detail)
	}
	// Egress broker: same rule again. Every repair resets to the broker's
	// default, and every broker default is the tighter one — a shorter
	// session, a shorter dial, an unusable listen address disabling the proxy
	// rather than binding somewhere nobody chose.
	for _, msg := range clampEgressConfig(&c.Executors.Egress) {
		field, detail, found := strings.Cut(msg, ": ")
		if !found {
			field, detail = "executors.egress", msg
		}
		warn(field, detail)
	}
}

// ValidateNumeric returns a non-nil error describing the first numeric range
// violation found in c, if any. Unlike validateAndClamp it does not mutate;
// callers (`cloop config set`, the Web UI options endpoints) use it to reject
// invalid inputs up front rather than silently clamping them. The returned
// error message is suitable for showing to a user.
func (c *Config) ValidateNumeric() error {
	if c.MaxParallel != 0 && (c.MaxParallel < MaxParallelLower || c.MaxParallel > MaxParallelUpper) {
		return fmt.Errorf("max_parallel must be between %d and %d (got %d)", MaxParallelLower, MaxParallelUpper, c.MaxParallel)
	}
	if c.RateLimit.RequestsPerSecond < 0 || (c.RateLimit.RequestsPerSecond > 0 && c.RateLimit.RequestsPerSecond < RateLimitRPSLower) {
		return fmt.Errorf("rate_limit.requests_per_second must be >= %.0f or 0 to use the default (got %.4f)", RateLimitRPSLower, c.RateLimit.RequestsPerSecond)
	}
	if c.RateLimit.Burst < 0 || (c.RateLimit.Burst > 0 && c.RateLimit.Burst < RateLimitBurstLower) {
		return fmt.Errorf("rate_limit.burst must be >= %d or 0 to use the default (got %d)", RateLimitBurstLower, c.RateLimit.Burst)
	}
	if c.Budget.MonthlyUSD < 0 {
		return fmt.Errorf("budget.monthly_usd must be >= 0 (got %.4f)", c.Budget.MonthlyUSD)
	}
	if c.Budget.DailyUSDLimit < 0 {
		return fmt.Errorf("budget.daily_usd_limit must be >= 0 (got %.4f)", c.Budget.DailyUSDLimit)
	}
	if c.Budget.DailyTokenLimit < 0 {
		return fmt.Errorf("budget.daily_token_limit must be >= 0 (got %d)", c.Budget.DailyTokenLimit)
	}
	if c.Budget.AlertThresholdPct < AlertThresholdMin || c.Budget.AlertThresholdPct > AlertThresholdMax {
		return fmt.Errorf("budget.alert_threshold_pct must be between %d and %d (got %d)", AlertThresholdMin, AlertThresholdMax, c.Budget.AlertThresholdPct)
	}
	if c.Budget.GlobalUSDPct < 0 || c.Budget.GlobalUSDPct > 100 {
		return fmt.Errorf("budget.global_usd_pct must be between 0 and 100 (got %.4f)", c.Budget.GlobalUSDPct)
	}
	if c.Budget.GlobalTokenPct < 0 || c.Budget.GlobalTokenPct > 100 {
		return fmt.Errorf("budget.global_token_pct must be between 0 and 100 (got %.4f)", c.Budget.GlobalTokenPct)
	}
	if c.ClaudeCode.MaxWeeklyPct < 0 || c.ClaudeCode.MaxWeeklyPct > 100 {
		return fmt.Errorf("claudecode.max_weekly_pct must be between 0 and 100 (got %.4f)", c.ClaudeCode.MaxWeeklyPct)
	}
	if c.ClaudeCode.MaxFiveHourPct < 0 || c.ClaudeCode.MaxFiveHourPct > 100 {
		return fmt.Errorf("claudecode.max_five_hour_pct must be between 0 and 100 (got %.4f)", c.ClaudeCode.MaxFiveHourPct)
	}
	if c.ClaudeCode.MaxWeeklyOpusPct < 0 || c.ClaudeCode.MaxWeeklyOpusPct > 100 {
		return fmt.Errorf("claudecode.max_weekly_opus_pct must be between 0 and 100 (got %.4f)", c.ClaudeCode.MaxWeeklyOpusPct)
	}
	if c.ClaudeCode.MaxWeeklySonnetPct < 0 || c.ClaudeCode.MaxWeeklySonnetPct > 100 {
		return fmt.Errorf("claudecode.max_weekly_sonnet_pct must be between 0 and 100 (got %.4f)", c.ClaudeCode.MaxWeeklySonnetPct)
	}
	if c.UI.MaxWebSocketConns != 0 && (c.UI.MaxWebSocketConns < WebSocketConnsLower || c.UI.MaxWebSocketConns > WebSocketConnsUpper) {
		return fmt.Errorf("ui.max_websocket_conns must be between %d and %d (or 0 for the default %d) (got %d)",
			WebSocketConnsLower, WebSocketConnsUpper, WebSocketConnsDefault, c.UI.MaxWebSocketConns)
	}
	if c.UI.MaxWebSocketConnsPerIP != 0 && (c.UI.MaxWebSocketConnsPerIP < WebSocketConnsPerIPLower || c.UI.MaxWebSocketConnsPerIP > WebSocketConnsPerIPUpper) {
		return fmt.Errorf("ui.max_websocket_conns_per_ip must be between %d and %d (or 0 for the default %d) (got %d)",
			WebSocketConnsPerIPLower, WebSocketConnsPerIPUpper, WebSocketConnsPerIPDefault, c.UI.MaxWebSocketConnsPerIP)
	}
	if c.UI.MaxWebSocketConns != 0 && c.UI.MaxWebSocketConnsPerIP != 0 && c.UI.MaxWebSocketConnsPerIP > c.UI.MaxWebSocketConns {
		return fmt.Errorf("ui.max_websocket_conns_per_ip (%d) must not exceed ui.max_websocket_conns (%d)",
			c.UI.MaxWebSocketConnsPerIP, c.UI.MaxWebSocketConns)
	}
	if c.UI.MaxRequestBodyBytes != 0 && (c.UI.MaxRequestBodyBytes < MaxRequestBodyBytesLower || c.UI.MaxRequestBodyBytes > MaxRequestBodyBytesUpper) {
		return fmt.Errorf("ui.max_request_body_bytes must be between %d and %d (or 0 for the default %d) (got %d)",
			MaxRequestBodyBytesLower, MaxRequestBodyBytesUpper, MaxRequestBodyBytesDefault, c.UI.MaxRequestBodyBytes)
	}
	if c.Orchestrator.TaskTimeoutMinutes != 0 && (c.Orchestrator.TaskTimeoutMinutes < OrchestratorTaskTimeoutMinutesLower || c.Orchestrator.TaskTimeoutMinutes > OrchestratorTaskTimeoutMinutesUpper) {
		return fmt.Errorf("orchestrator.task_timeout_minutes must be between %d and %d (or 0 for the default %d) (got %d)",
			OrchestratorTaskTimeoutMinutesLower, OrchestratorTaskTimeoutMinutesUpper, OrchestratorTaskTimeoutMinutesDefault, c.Orchestrator.TaskTimeoutMinutes)
	}
	if err := ValidateExecutors(c.Executors); err != nil {
		return err
	}
	return ValidateSandbox(c.Sandbox)
}

// applyEnvVars overlays environment variable values onto config fields.
// Env vars take precedence over file-based config values.
func (c *Config) applyEnvVars() {
	if v := os.Getenv("CLOOP_PROVIDER"); v != "" {
		c.Provider = v
	}
	if v := os.Getenv("ANTHROPIC_API_KEY"); v != "" {
		c.Anthropic.APIKey = v
	}
	if v := os.Getenv("ANTHROPIC_BASE_URL"); v != "" {
		c.Anthropic.BaseURL = v
	}
	if v := os.Getenv("OPENAI_API_KEY"); v != "" {
		c.OpenAI.APIKey = v
	}
	if v := os.Getenv("OPENAI_BASE_URL"); v != "" {
		c.OpenAI.BaseURL = v
	}
	if v := os.Getenv("OLLAMA_BASE_URL"); v != "" {
		c.Ollama.BaseURL = v
	}
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		c.GitHub.Token = v
	}
	// The OIDC client secret is the one credential a *hosted* deployment
	// cannot keep in this file. config.yaml is the thing an operator templates
	// into a ConfigMap, commits to a config repo and diffs in a pull request;
	// the client secret is the thing that must arrive from a Kubernetes Secret
	// or a systemd EnvironmentFile. Without this override the two requirements
	// are in direct conflict and the secret ends up committed.
	if v := os.Getenv(EnvOIDCClientSecret); v != "" {
		c.UI.OIDC.ClientSecret = v
	}
}

// Save writes the config to .cloop/config.yaml.
//
// The write is atomic — data is staged in a sibling .tmp file, fsynced, then
// renamed into place. A crash, ENOSPC, or `cloop config set` racing with a
// reader can no longer leave the file half-written and lose the user's API
// keys / provider settings.
func Save(workdir string, cfg *Config) error {
	dir := filepath.Join(workdir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	// 0o600: owner read/write only — the file may contain API keys.
	path := ConfigPath(workdir)
	tmp, err := os.CreateTemp(dir, ".config.yaml.*.tmp")
	if err != nil {
		return fmt.Errorf("config: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("config: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("config: rename tmp: %w", err)
	}
	// Mirror into SQLite (best-effort). Failure here doesn't roll back the
	// YAML write — YAML is the canonical store, SQLite is a queryable mirror.
	mirrorToSQLite(workdir, data)
	return nil
}

// WriteDefault creates a default config.yaml if one doesn't exist.
func WriteDefault(workdir string) error {
	path := ConfigPath(workdir)
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}
	return Save(workdir, Default())
}
