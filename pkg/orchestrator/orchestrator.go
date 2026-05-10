package orchestrator

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	goOtelAttr "go.opentelemetry.io/otel/attribute"

	"github.com/blechschmidt/cloop/pkg/alert"
	"github.com/blechschmidt/cloop/pkg/approvalgate"
	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/budget"
	"github.com/blechschmidt/cloop/pkg/checkpoint"
	"github.com/blechschmidt/cloop/pkg/clarify"
	"github.com/blechschmidt/cloop/pkg/coach"
	"github.com/blechschmidt/cloop/pkg/condition"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/consensus"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/ctxedit"
	"github.com/blechschmidt/cloop/pkg/diagnosis"
	cloopdocs "github.com/blechschmidt/cloop/pkg/docs"
	cloopenv "github.com/blechschmidt/cloop/pkg/env"
	"github.com/blechschmidt/cloop/pkg/eval"
	cloopgit "github.com/blechschmidt/cloop/pkg/git"
	"github.com/blechschmidt/cloop/pkg/hooks"
	"github.com/blechschmidt/cloop/pkg/learning"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/memory"
	"github.com/blechschmidt/cloop/pkg/mergequeue"
	"github.com/blechschmidt/cloop/pkg/mergeresolve"
	"github.com/blechschmidt/cloop/pkg/metrics"
	"github.com/blechschmidt/cloop/pkg/multiagent"
	"github.com/blechschmidt/cloop/pkg/notify"
	"github.com/blechschmidt/cloop/pkg/optimizer"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/promote"
	"github.com/blechschmidt/cloop/pkg/promptopt"
	"github.com/blechschmidt/cloop/pkg/promptstats"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/provideraudit"
	"github.com/blechschmidt/cloop/pkg/ratelimit"
	"github.com/blechschmidt/cloop/pkg/replay"
	"github.com/blechschmidt/cloop/pkg/reqid"
	"github.com/blechschmidt/cloop/pkg/review"
	"github.com/blechschmidt/cloop/pkg/risk"
	"github.com/blechschmidt/cloop/pkg/router"
	"github.com/blechschmidt/cloop/pkg/secret"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskqueue"
	clooptracing "github.com/blechschmidt/cloop/pkg/tracing"
	"github.com/blechschmidt/cloop/pkg/verify"
	"github.com/blechschmidt/cloop/pkg/watchdog"
	"github.com/blechschmidt/cloop/pkg/webhook"
	"github.com/blechschmidt/cloop/pkg/worktree"
	"github.com/fatih/color"
)

type Config struct {
	WorkDir     string
	Model       string
	MaxTokens   int
	StepTimeout time.Duration

	// Inference parameter overrides (nil = use provider default).
	Temperature      *float64
	TopP             *float64
	FrequencyPenalty *float64

	// ExtendedThinking enables reasoning/thinking mode for supported providers.
	// Anthropic: adds the "thinking" block; OpenAI o-series: sets reasoning_effort.
	ExtendedThinking bool

	// ThinkingBudget is the token budget for reasoning content (default 8000).
	// See provider.Options.ThinkingBudget for per-provider semantics.
	ThinkingBudget int
	Verbose        bool
	DryRun         bool
	PMMode         bool
	PlanOnly       bool // only decompose tasks, don't execute them
	RetryFailed    bool // retry failed tasks in PM mode
	Replan         bool // force re-decompose goal (wipes existing plan, keeps history)

	// MaxFailures is the number of consecutive task failures before PM mode stops (0 = default 3).
	MaxFailures int

	// ContextSteps is the number of recent steps to include in prompts (0 = default 3).
	ContextSteps int

	// StepsLimit is the maximum number of steps to run in this session only (not persisted).
	// 0 means no session limit. Takes precedence over MaxSteps when both are set.
	StepsLimit int

	// StepDelay is the duration to wait between steps (0 = no delay).
	StepDelay time.Duration

	// TokenBudget is the maximum total tokens (input + output) for the session (0 = unlimited).
	// When the cumulative token count reaches or exceeds this value the session pauses.
	TokenBudget int

	// CostLimit is the maximum estimated cost in USD for the session (0 = unlimited).
	// The session warns at 80% of the limit and pauses when the limit is reached.
	CostLimit float64

	// Provider to use. If empty, falls back to state.Provider, then config.yaml, then claudecode.
	ProviderName string

	// Provider config for building providers
	ProviderCfg provider.ProviderConfig

	// InnovateMode enables creative/experimental feature exploration in evolve prompts.
	InnovateMode bool

	// Parallel enables concurrent task execution in PM mode.
	// Independent tasks (all deps satisfied) run simultaneously.
	Parallel bool

	// MaxParallel is the maximum number of tasks to execute concurrently in PM
	// parallel mode. 0 (or unset) means no limit — all ready tasks run at once.
	// Setting this to 1 is equivalent to sequential execution.
	MaxParallel int

	// InjectContext enables project context injection (git status, file tree) into task prompts.
	InjectContext bool

	// AdaptiveReplan enables AI-driven replanning after task failures.
	// When enabled and a task fails, the provider re-thinks the remaining work.
	AdaptiveReplan bool

	// ReviewMode pauses before each task and waits for human approval (y/n/skip/quit).
	ReviewMode bool

	// Verify enables post-task verification: after TASK_DONE, run a second AI pass to confirm
	// the task was genuinely completed. If verification fails, the task is re-queued (up to 2 retries).
	Verify bool

	// MaxVerifyRetries is the max number of times a task can be re-queued by the verifier (default 2).
	MaxVerifyRetries int

	// UseMemory injects past session learnings into prompts.
	UseMemory bool

	// Learn extracts key learnings at end of session and saves them to memory.
	Learn bool

	// MemoryLimit is the max number of memory entries to inject into prompts (0 = all).
	MemoryLimit int

	// WebhookURL overrides the config-file webhook URL for this run (optional).
	WebhookURL string

	// WebhookEvents is the list of event types to fire (empty = all).
	WebhookEvents []string

	// WebhookSecret is used to sign each webhook POST body with HMAC-SHA256
	// in the X-Hub-Signature-256 header (GitHub-style). Empty = no signing.
	WebhookSecret string

	// Streaming enables token-by-token output to the terminal for providers that
	// support SSE streaming (anthropic, openai, ollama). When true, the orchestrator
	// passes an OnToken callback to Complete(); providers that do not support
	// streaming (e.g. claudecode) simply ignore it and fall back to buffered output.
	Streaming bool

	// Notify enables OS desktop notifications for key events: task done, task failed,
	// and session complete. Uses notify-send on Linux and osascript on macOS.
	Notify bool

	// Hooks configures shell commands run at task and plan lifecycle events.
	Hooks hooks.Config

	// DiagnoseFailures enables AI-powered failure diagnosis in PM mode (sequential only).
	// When a task emits TASK_FAILED, a second AI call analyzes the failure output and
	// stores a diagnosis in task.FailureDiagnosis. On retry (--retry-failed), the
	// diagnosis is injected into the retry prompt so the AI can correct its approach.
	DiagnoseFailures bool

	// GitMode enables per-task git branch workflow in PM mode (sequential only).
	// Each task is executed on a dedicated branch cloop/task-<id>-<slug>.
	// On TASK_DONE the branch is committed and merged back to the original branch.
	// On TASK_FAILED the branch is left open for inspection.
	GitMode bool

	// WorktreeParallel enables per-task git worktrees in PM parallel mode.
	// When true and WorkDir is a git repo, each parallel task is executed in an
	// isolated worktree at .cloop/worktrees/task-<id>/ on its own branch
	// (cloop/task-<id>-<slug>). On TASK_DONE the worktree's changes are
	// committed and a merge request is enqueued into a serialized merge queue
	// that merges branches back into the original base branch one at a time,
	// avoiding conflicts between concurrent tasks. On TASK_FAILED/skipped the
	// worktree is removed but the branch is kept for inspection.
	WorktreeParallel bool

	// ContextTokenLimit is the maximum estimated token count for step/task-result history
	// included in prompts. When the accumulated history exceeds this limit the orchestrator
	// prunes oldest intermediate entries (keeping the first and last two) before building
	// the prompt. 0 means no limit. Default when unset: 100000.
	ContextTokenLimit int

	// Optimize runs the AI plan optimizer before task execution begins.
	// The optimizer reviews the full task list and suggests reordering, splits,
	// merges, and flags. In non-interactive mode the reordering is applied automatically;
	// in interactive mode the user is prompted to approve.
	Optimize bool

	// OptimizeInteractive prompts the user before applying optimizer suggestions.
	// When false (default), reordering is applied automatically and other suggestions
	// are printed for awareness.
	OptimizeInteractive bool

	// Metrics is the metrics registry for this run. When non-nil the orchestrator records
	// task/step/token/cost events into it. The caller is responsible for starting any HTTP
	// server and writing the final JSON summary — the orchestrator writes metrics.json at
	// plan completion via Metrics.WriteJSON. Pass nil to disable metrics collection.
	Metrics *metrics.Metrics

	// NoDedup disables semantic task deduplication in auto-evolve mode.
	// By default, before injecting newly discovered tasks the orchestrator asks the
	// AI to filter out candidates that duplicate existing (completed or pending) work.
	// Set this to true to skip that check and inject all discovered tasks as-is.
	NoDedup bool

	// TagFilter restricts PM mode execution to tasks that have at least one matching tag.
	// Tasks that do not match any tag in the filter are skipped for this run.
	// An empty filter (default) executes all ready tasks regardless of tags.
	TagFilter []string

	// SlackWebhookURL is the Slack incoming webhook URL for rich notifications.
	// When set, the orchestrator sends a Slack attachment on task_done, task_failed,
	// and plan_complete events. Empty = disabled.
	SlackWebhookURL string

	// DiscordWebhookURL is the Discord webhook URL for rich notifications.
	// When set, the orchestrator sends a Discord embed on task_done, task_failed,
	// and plan_complete events. Empty = disabled.
	DiscordWebhookURL string

	// ScriptVerify enables AI-generated shell verification scripts in PM mode
	// (sequential only). After each task completes with TASK_DONE the provider
	// generates a 5-15 line bash script that confirms the task was accomplished
	// (new files exist, commands succeed, etc.). The script and its result are
	// stored as a verification artifact. If the script exits non-zero the task
	// is marked failed and failure diagnosis is triggered.
	ScriptVerify bool

	// AutoSplit enables automatic AI-powered task splitting in PM mode (sequential only).
	// When a task's FailCount reaches 2, the orchestrator asks the AI to decompose
	// it into smaller subtasks that replace it in the plan. This prevents repeated
	// failures on tasks that are too large or ambiguous.
	AutoSplit bool

	// MultiAgent enables the three-pass specialist sub-agent pipeline in PM mode
	// (sequential only). Each task is processed by an architect (designs the
	// approach), a coder (implements the design), and a reviewer (critiques and
	// confirms). Sub-agent responses are stored as separate artifact files
	// (.cloop/tasks/<id>-<slug>-multiagent/{architect,coder,reviewer}.txt).
	// The reviewer's verdict overrides the coder's task signal.
	MultiAgent bool

	// PostReview enables automatic AI code review after each successful task in PM
	// mode (sequential only). After TASK_DONE the orchestrator runs `git diff HEAD~1`,
	// calls the provider for a correctness/security/style review, and stores the
	// result as a task annotation with author "ai-reviewer". The verdict (PASS/FAIL)
	// is surfaced in `cloop status`.
	PostReview bool

	// HealRetries is the maximum number of auto-heal re-attempts after a TASK_FAILED
	// signal in PM sequential mode. On each attempt the orchestrator diagnoses the
	// failure, builds a mutated retry prompt incorporating the root cause and fix
	// strategy, and re-executes the task. 0 means use the default (2). When NoHeal
	// is true this field is ignored entirely.
	HealRetries int

	// NoHeal disables the auto-heal loop. When true, TASK_FAILED immediately
	// proceeds to permanent failure handling without any re-attempt.
	NoHeal bool

	// LogJSON switches all structured event output to newline-delimited JSON (NDJSON).
	// When true, key lifecycle events (session_start, task_start, task_done, task_failed,
	// task_skipped, step, heal, session_done) are emitted as JSON objects to stdout.
	// Decorative color/text output is suppressed so the stream is machine-parseable.
	// Equivalent to the --log-json CLI flag.
	LogJSON bool

	// RiskCheck enables pre-execution AI risk assessment for each task in PM mode
	// (sequential only). Before a task begins executing the orchestrator calls the
	// risk package to assess findings. Tasks with at least one CRITICAL finding are
	// aborted (marked failed) unless RiskForce is also set.
	RiskCheck bool

	// RiskForce overrides CRITICAL risk findings when RiskCheck is enabled. When
	// true, CRITICAL tasks are executed anyway with a prominent warning instead of
	// being aborted. Has no effect when RiskCheck is false.
	RiskForce bool

	// ConsensusN, when > 0, enables multi-model consensus for critical tasks
	// (priority P0/P1 or tagged "critical"). The task prompt is fanned out to up
	// to N configured providers in parallel; an AI judge then scores each response
	// on correctness, safety, and completeness, and the highest-scoring response
	// is used. The judge call uses the primary provider. The consensus decision
	// and runner-up scores are appended to the task artifact.
	ConsensusN int

	// NoCodeContextInject disables automatic codebase context snippet injection
	// in PM mode task prompts. When false (default), CollectRelevantContext scans
	// the working directory for files matching the task keywords and prepends up
	// to ~2000 tokens of relevant snippets to each task prompt. Set this to true
	// (via --no-context-inject) to disable the feature entirely.
	NoCodeContextInject bool

	// RequireApproval enables the human-in-the-loop approval gate for P0/P1 tasks
	// in PM sequential mode. When true, any task with priority <= 1 OR
	// RequiresApproval:true is paused before execution and the user is prompted
	// with [y/n/skip/edit]. Pre-approved tasks (task.Approved:true set via
	// 'cloop task approve') bypass the interactive prompt automatically.
	RequireApproval bool

	// SkipClarify disables the interactive goal clarification Q&A dialog that
	// normally runs before pm.Decompose() when stdin is a TTY. Set this to true
	// for automation, CI, or when the goal is already fully specified.
	SkipClarify bool

	// AutoEval enables automatic AI quality scoring after each successful task
	// in PM sequential mode. After TASK_DONE the orchestrator scores the task
	// output against the default rubric and saves the result to
	// .cloop/evals/<task-id>.json. The weighted average is printed to the terminal.
	AutoEval bool

	// Budget configures daily token and USD spend limits. When set, the
	// orchestrator checks the budget before each task and aborts with a clear
	// message when any limit is exceeded. Threshold alerts are fired via
	// desktop/webhook notifications when AlertThresholdPct is crossed.
	Budget config.BudgetConfig

	// NotifyCfg holds notification channel settings used by the budget enforcer
	// to send threshold alerts. It mirrors config.NotifyConfig.
	NotifyCfg config.NotifyConfig

	// ClaudeCode holds claudecode-specific configuration including per-project
	// caps on the global Anthropic subscription utilization. When MaxWeeklyPct
	// (or any of the other per-window caps) is > 0, the orchestrator queries
	// the Anthropic OAuth usage API before each task and aborts when the cap
	// has been reached. Only enforced when the active provider is "claudecode".
	ClaudeCode config.ClaudeCodeConfig

	// DocsUpdateOnComplete runs `cloop docs update --yes` after the plan
	// finishes. When true, all tracked documentation files are AI-refreshed
	// automatically at the end of a successful PM run.
	DocsUpdateOnComplete bool

	// DocsUpdateFile limits the post-plan docs update to a single file.
	// Empty means all tracked docs files are updated.
	DocsUpdateFile string

	// CalibrationFactor scales AI-generated time estimates in new plans.
	// Set by 'cloop task effort-calibrate --apply'. 0 and 1.0 are equivalent (no scaling).
	// Values > 1.0 inflate estimates (AI historically underestimates), < 1.0 deflate.
	CalibrationFactor float64

	// TracingEnabled wraps the provider with an OTel tracing decorator when true.
	// Spans are exported to the endpoint configured in config.yaml under the
	// "tracing" key. When false (default), no tracing overhead is incurred.
	TracingEnabled bool

	// AutoPromote enables deadline-aware automatic priority escalation at the
	// start of each task-selection cycle in PM sequential mode.
	// For each pending/in-progress task whose deadline is within
	// AutoPromoteThresholdDays days, the priority is escalated by 1.
	// Tasks that are direct prerequisites of overdue tasks are also promoted.
	AutoPromote bool

	// AutoPromoteThresholdDays is the number of days remaining before the
	// deadline at which auto-promotion kicks in (default 3).
	AutoPromoteThresholdDays int

	// CoachMode runs a pre-task AI coaching session before each task in PM
	// sequential mode. The AI plays the role of a senior engineer and gives
	// 3-5 concrete, actionable tips specific to the task: how to approach it
	// well, what to watch out for, and what done looks like.
	CoachMode bool

	// Watchdog configures the in-flight stuck-task detector that runs as a
	// background goroutine alongside runPM/runPMParallel. The orchestrator
	// applies WatchdogDefaults() at start time, so a zero value enables the
	// detector with sensible defaults (interval=30s, threshold=10min,
	// artifact-quiet=5min, auto-kill disabled). See pkg/watchdog.
	Watchdog config.WatchdogConfig

	// TaskTimeoutMinutes is the process-wide default per-task wall-clock
	// budget applied when neither Task.MaxMinutes nor state.DefaultMaxMinutes
	// is set (Task 20108). Zero means "use OrchestratorTaskTimeoutMinutesDefault"
	// (30 minutes), so every cloop run has a hard upper bound on how long a
	// single hung provider call can pin a task. Sourced from
	// config.Orchestrator.TaskTimeoutMinutes by cmd/run.go.
	TaskTimeoutMinutes int
}

type Orchestrator struct {
	config      Config
	state       *state.ProjectState
	provider    provider.Provider
	router      *router.Router // routes tasks to role-specific providers
	memory      *memory.Memory
	webhook     *webhook.Client
	metrics     *metrics.Metrics
	envVars     []cloopenv.Var
	secretStore *secret.Store
	log         logger.Logger
	queue       *taskqueue.Queue   // central work queue; nil-safe (Mark*/Enqueue tolerate nil)
	statedb     *statedb.DB        // shared SQLite handle for forensics (stuck_tasks); nil-safe
	watchdog    *watchdog.Watchdog // stuck-task detector; nil if disabled or queue/db unavailable

	// killWG tracks the goroutine that polls kill_requests for manual aborts
	// (Task 20140). The orchestrator's Run() spawns it under the run context
	// and waits on this group during Close so the loop exits cleanly.
	killWG sync.WaitGroup
}

func New(cfg Config, prov provider.Provider) (*Orchestrator, error) {
	s, err := state.Load(cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	if cfg.Model != "" {
		s.Model = cfg.Model
	}
	// All work is tracked through the PM task pipeline; non-PM mode was removed
	// in Task 20067 so every change is visible in the task list and auditable.
	s.PMMode = true
	s.InnovateMode = cfg.InnovateMode
	if cfg.Parallel {
		s.Parallel = true
	}
	if cfg.MaxParallel > 0 {
		s.MaxParallel = cfg.MaxParallel
	}
	// A configured cap > 1 is itself an "I want parallel" signal (Task 20111),
	// so promote s.Parallel even if the caller forgot to set cfg.Parallel.
	// Without this the dispatcher in runPM falls through to runPMSequential
	// and the cap is silently ignored.
	if s.MaxParallel > 1 {
		s.Parallel = true
	}
	if cfg.WorktreeParallel {
		s.WorktreeParallel = true
	}
	// Persist CLI-driven overrides so the running loop's SyncFromDisk reads them
	// back instead of overwriting the in-memory values from a stale on-disk state
	// (mergeExternalTasks copies disk → memory for these toggles, so without this
	// SaveDirect the overrides would be silently clobbered on the first Save).
	_ = s.SaveDirect()
	mem, _ := memory.Load(cfg.WorkDir)
	if mem == nil {
		mem = &memory.Memory{}
	}

	// Load per-project env vars (best-effort; errors are non-fatal).
	envVars, _ := cloopenv.Load(cfg.WorkDir)

	// Load encrypted secrets (best-effort; only succeeds when CLOOP_SECRET_KEY is set).
	secretStore, _ := secret.Open(cfg.WorkDir)

	// Build webhook client (flag URL overrides config URL).
	var wh *webhook.Client
	if cfg.WebhookURL != "" {
		wh = webhook.New(cfg.WebhookURL, cfg.WebhookEvents, nil, cfg.WebhookSecret)
	}

	// Wrap provider with OTel tracing decorator when tracing is enabled.
	if cfg.TracingEnabled {
		prov = clooptracing.WrapProvider(prov)
	}

	r := router.New(prov)
	// Bind project + provider as default attributes on every emitted entry so
	// downstream tooling can filter logs per project/provider without each
	// call site having to thread them through the data map.
	log := logger.New(cfg.LogJSON).
		With("project", s.WorkDir).
		With("provider", prov.Name())

	// Open the central work queue. All work cloop performs (task executions,
	// heal retries, evolve discoveries, externally-merged tasks) is recorded
	// here so the UI can render a single auditable activity log. If opening
	// fails we log a warning and continue with queue=nil — every queue call
	// is nil-safe so degraded operation is harmless.
	queue, qErr := taskqueue.Open(s.WorkDir)
	if qErr != nil {
		log.Warn(logger.EventSessionStart, 0, "task queue unavailable", map[string]interface{}{
			"error": qErr.Error(),
		})
		queue = nil
	}

	// Open the shared state DB for stuck-task forensics (Task 20088). The
	// watchdog appends rows here; readers (Web UI) use the same path. Open
	// failure is non-fatal — the watchdog is still useful with logging only.
	stateDBPath := filepath.Join(s.WorkDir, ".cloop", "state.db")
	sdb, dbErr := statedb.Open(stateDBPath)
	if dbErr != nil {
		log.Warn(logger.EventSessionStart, 0, "statedb unavailable for watchdog", map[string]interface{}{
			"error": dbErr.Error(),
			"path":  stateDBPath,
		})
		sdb = nil
	}

	o := &Orchestrator{config: cfg, state: s, provider: prov, router: r, memory: mem, webhook: wh, metrics: cfg.Metrics, envVars: envVars, secretStore: secretStore, log: log, queue: queue, statedb: sdb}

	// Build (but do NOT start) the stuck-task watchdog (Task 20088). Run()
	// starts it so its goroutine is bound to the run context and exits on
	// cancellation. Passing GetPlan over the in-memory plan is much cheaper
	// than re-reading state.db every tick.
	wdCfg := cfg.Watchdog.WatchdogDefaults()
	if wdCfg.Enabled != nil && *wdCfg.Enabled {
		o.watchdog = &watchdog.Watchdog{
			WorkDir:        s.WorkDir,
			Interval:       time.Duration(wdCfg.IntervalSeconds) * time.Second,
			StuckThreshold: time.Duration(wdCfg.StuckThresholdMinutes) * time.Minute,
			ArtifactQuiet:  time.Duration(wdCfg.ArtifactIdleMinutes) * time.Minute,
			AutoKillAfter:  time.Duration(wdCfg.AutoKillAfterMinutes) * time.Minute,
			Logger:         log,
			DB:             sdb,
			GetPlan:        func() *pm.Plan { return o.state.Plan },
		}
	}

	return o, nil
}

// Close releases resources held by the orchestrator. Safe to call multiple times.
// Any queue entries still in "running" are marked failed (interrupted) before
// the database is closed.
func (o *Orchestrator) Close() error {
	if o == nil {
		return nil
	}
	// Stop the watchdog before tearing down its DB handle so an in-flight
	// AppendStuck cannot race a Close. Watchdog.Stop is idempotent and waits
	// for the loop goroutine to exit (Task 20088).
	if o.watchdog != nil {
		o.watchdog.Wait()
	}
	// Wait for the manual-abort poller to exit before tearing down statedb
	// so a final tick cannot race the DB close (Task 20140).
	o.killWG.Wait()
	if o.statedb != nil {
		_ = o.statedb.Close()
		o.statedb = nil
	}
	if o.queue == nil {
		return nil
	}
	// Mark any entries we left running as interrupted.
	o.recoverStaleQueueEntries()
	err := o.queue.Close()
	o.queue = nil
	return err
}

// enqueueWork records a new work item in the central queue and returns its id.
// Returns 0 (no-op) when the queue is unavailable so callers can pass the id
// through unconditionally.
func (o *Orchestrator) enqueueWork(e taskqueue.Entry) int64 {
	if o == nil || o.queue == nil {
		return 0
	}
	id, err := o.queue.Enqueue(e)
	if err != nil {
		o.log.Warn(logger.EventSessionStart, e.TaskID, "queue enqueue failed", map[string]interface{}{
			"error": err.Error(),
			"kind":  e.Kind,
		})
		return 0
	}
	return id
}

// taskTimeoutUnit is the wall-clock duration that one "minute" of task budget
// resolves to when context.WithTimeout is built (Task 20108). Production code
// always leaves this at time.Minute so the budget reads naturally in YAML
// (orchestrator.task_timeout_minutes: 30 → 30 minutes). Tests override it via
// withTaskTimeoutUnit() to compress full-minute budgets into milliseconds so
// timeout assertions complete in well under a second instead of waiting on a
// real wall clock. Variable instead of constant so the override pattern is
// the same as parallelShutdownGracePeriod.
var taskTimeoutUnit = time.Minute

// withTaskTimeoutUnit installs unit as the per-task budget unit and returns a
// restore function. Intended for tests only; the only caller of the restore
// function should be t.Cleanup. Not safe for concurrent test use without
// t.Parallel discipline (the variable is process-wide).
func withTaskTimeoutUnit(unit time.Duration) func() {
	prev := taskTimeoutUnit
	taskTimeoutUnit = unit
	return func() { taskTimeoutUnit = prev }
}

// effectiveTaskBudgetMinutes returns the per-task wall-clock budget that
// taskContextWithTimeout will apply, in minutes. The lookup order is:
//
//  1. task.MaxMinutes (per-task override; Task 99)
//  2. state.DefaultMaxMinutes (per-project default)
//  3. config.Orchestrator.TaskTimeoutMinutes (process-wide default; Task 20108)
//  4. config.OrchestratorTaskTimeoutMinutesDefault (30 minutes hard fallback)
//
// The first non-zero value wins. Zero or negative inputs at every layer
// resolve to the hard default so a stuck provider can never pin a task
// indefinitely. This helper is exported (lowercase but accessible from the
// package) so handleTaskTimeout and the on-screen timeout banner can report
// the same number that the deadline actually used.
func (o *Orchestrator) effectiveTaskBudgetMinutes(task *pm.Task) int {
	if task != nil && task.MaxMinutes > 0 {
		return task.MaxMinutes
	}
	if o.state != nil && o.state.DefaultMaxMinutes > 0 {
		return o.state.DefaultMaxMinutes
	}
	if o.config.TaskTimeoutMinutes > 0 {
		// Defensively clamp to the same band the loader enforces so a hand-
		// constructed Config{TaskTimeoutMinutes: -1} (in tests, callers that
		// bypass cmd/run.go) doesn't degrade to a no-timeout context.
		if o.config.TaskTimeoutMinutes >= config.OrchestratorTaskTimeoutMinutesLower &&
			o.config.TaskTimeoutMinutes <= config.OrchestratorTaskTimeoutMinutesUpper {
			return o.config.TaskTimeoutMinutes
		}
	}
	return config.OrchestratorTaskTimeoutMinutesDefault
}

// taskContextWithTimeout returns a context (and cancel) scoped to the given task's
// time budget. The budget is resolved by effectiveTaskBudgetMinutes, which always
// returns a positive value (Task 20108): no execution path produces an unbounded
// context, so a hung provider HTTP call is guaranteed to be cancelled. When a
// watchdog is active the returned cancel is registered under task.ID and
// de-registered when invoked, so the same cancel cannot accidentally fire twice.
//
// A fresh request ID is bound to the returned context unless the parent ctx
// already carries one (in which case the inherited ID is preserved so an
// HTTP-initiated `cloop run` keeps a single trace identity all the way down
// to the provider call). The ID is logged on task entry by the caller so
// operators can grep server logs and orchestrator logs by the same key.
func (o *Orchestrator) taskContextWithTimeout(ctx context.Context, task *pm.Task) (context.Context, context.CancelFunc) {
	ctx, _ = reqid.EnsureContext(ctx)

	// Install a per-task retry budget so a runaway task cannot consume
	// unbounded provider attempts. The budget is shared across every
	// DoWithRetry call made under taskCtx (sub-agents, consensus, heal
	// retries) — they all see the same *RetryBudget via context. The
	// limit comes from task.RetryBudget when set, otherwise the
	// provider default. taskCtx inherits this binding.
	budgetLimit := provider.DefaultRetryBudget
	if task != nil && task.RetryBudget > 0 {
		budgetLimit = task.RetryBudget
	}
	ctx = provider.WithRetryBudget(ctx, provider.NewRetryBudget(budgetLimit))

	maxMin := o.effectiveTaskBudgetMinutes(task)
	taskCtx, taskCancel := context.WithTimeout(ctx, time.Duration(maxMin)*taskTimeoutUnit)
	if o.watchdog != nil && task != nil {
		o.watchdog.Register(task.ID, taskCancel)
		taskID := task.ID
		wrapped := func() {
			o.watchdog.Unregister(taskID)
			taskCancel()
		}
		return taskCtx, wrapped
	}
	return taskCtx, taskCancel
}

// isTimeoutErr returns true when err is a context deadline-exceeded error and
// the per-task context (not the parent session context) was the one that expired.
func isTimeoutErr(taskCtx context.Context, err error) bool {
	if err == nil {
		return false
	}
	return taskCtx.Err() == context.DeadlineExceeded
}

// handleTaskTimeout marks the task as timed_out, fires desktop and webhook
// notifications, and persists a final artifact line indicating the timeout
// (Task 20108). Always writes an artifact entry even when the provider
// returned no partial output, so post-mortem inspection always finds a
// trace of the timeout. The effective budget is resolved via
// effectiveTaskBudgetMinutes so the value reported to the user, the
// annotation, and the webhook all match the deadline that actually fired —
// task.MaxMinutes alone may be 0 when the cancellation was triggered by the
// project-level or process-wide default.
func (o *Orchestrator) handleTaskTimeout(_ context.Context, s *state.ProjectState, task *pm.Task, partialOutput string, dimColor *color.Color) {
	task.Status = pm.TaskTimedOut
	completedAt := time.Now()
	task.CompletedAt = &completedAt
	if task.StartedAt != nil {
		task.ActualMinutes = int(completedAt.Sub(*task.StartedAt).Minutes())
	}

	budgetMin := o.effectiveTaskBudgetMinutes(task)
	reasonMsg := fmt.Sprintf("Task timed out after %d minute(s) budget exceeded", budgetMin)
	pm.AddAnnotation(task, "ai", reasonMsg)
	// FailureDiagnosis is the canonical machine-readable failure reason field
	// surfaced by `cloop status`, the Web UI, and webhook payloads. Populate
	// it so operators can distinguish a timeout from a generic provider error
	// without parsing annotations.
	task.FailureDiagnosis = reasonMsg

	// Always write a final artifact line indicating the timeout (Task 20108
	// requirement (3)). When the provider produced partial output we prefix
	// it with the timeout marker; when it produced nothing at all we still
	// write a single-line marker so downstream tooling never has to guess
	// whether the task ran. Errors are logged to the dim console only — they
	// must not block the timeout-handling path.
	artifactBody := fmt.Sprintf("[TIMEOUT — task exceeded %d minute(s) budget at %s]\n",
		budgetMin, completedAt.UTC().Format(time.RFC3339))
	if partialOutput != "" {
		artifactBody += partialOutput + "\n"
	}
	artifactBody += "TASK_FAILED (timeout)\n"
	if ap, aErr := artifact.WriteTaskArtifact(o.config.WorkDir, task, artifactBody); aErr != nil {
		dimColor.Printf("  artifact write error (ignored): %v\n", aErr)
	} else {
		task.ArtifactPath = ap
		if partialOutput != "" {
			dimColor.Printf("  partial artifact: %s\n", ap)
		} else {
			dimColor.Printf("  timeout marker artifact: %s\n", ap)
		}
	}

	// Desktop notification.
	if o.config.Notify {
		notify.Send("cloop: Task Timed Out", fmt.Sprintf("%s (budget: %dm)", task.Title, budgetMin))
	}
	// Slack/Discord webhook notifications.
	o.notifyWebhooks(
		"cloop: Task Timed Out",
		fmt.Sprintf("Task #%d: %s\nGoal: %s\nBudget: %dm", task.ID, task.Title, s.Goal, budgetMin),
	)
	// Structured event webhook.
	done, failed := s.Plan.CountByStatus()
	o.webhook.Send(webhook.EventTaskFailed, webhook.Payload{
		Goal: s.Goal,
		Task: &webhook.TaskInfo{
			ID:     task.ID,
			Title:  task.Title,
			Status: "timed_out",
		},
		Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
		Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
	})
	o.log.Error(logger.EventTaskFailed, task.ID, task.Title, map[string]interface{}{
		"reason":         "timed_out",
		"budget_minutes": budgetMin,
	})
}

// allEnvLines returns the combined KEY=value env lines from per-project env vars
// and the encrypted secrets store, suitable for os/exec Env injection.
func (o *Orchestrator) allEnvLines() []string {
	lines := cloopenv.EnvLines(o.envVars)
	if o.secretStore != nil {
		lines = append(lines, o.secretStore.EnvLines()...)
	}
	return lines
}

// notifyWebhooks sends a rich notification to the configured Slack and/or Discord
// webhook URLs. Errors are printed as dim warnings and never interrupt execution.
func (o *Orchestrator) notifyWebhooks(title, body string) {
	dimColor := color.New(color.Faint)
	if u := o.config.SlackWebhookURL; u != "" {
		if err := notify.SendWebhook(u, title, body); err != nil {
			dimColor.Printf("  slack notify error (ignored): %v\n", err)
		}
	}
	if u := o.config.DiscordWebhookURL; u != "" {
		if err := notify.SendWebhook(u, title, body); err != nil {
			dimColor.Printf("  discord notify error (ignored): %v\n", err)
		}
	}
}

// evaluateAlerts loads alert rules and fires notifications for any violations
// after a task completes. Errors are silently ignored (best-effort).
func (o *Orchestrator) evaluateAlerts(s *state.ProjectState, task *pm.Task) {
	rules, err := alert.Load(o.config.WorkDir)
	if err != nil || len(rules) == 0 {
		return
	}

	lastMinutes := float64(task.ActualMinutes)
	ctx := alert.EvalContext{
		Plan:            s.Plan,
		LastTaskMinutes: lastMinutes,
		TotalCostUSD:    alert.SessionCostUSD(o.config.WorkDir),
	}

	violations := alert.Evaluate(o.config.WorkDir, rules, ctx)
	if len(violations) == 0 {
		return
	}

	dimColor := color.New(color.Faint)
	alertColor := color.New(color.FgRed, color.Bold)
	for _, v := range violations {
		alertColor.Printf("  ALERT %q: %s %s %.4g (observed %.4g)\n",
			v.Rule.Name, v.Rule.Metric, v.Rule.Op, v.Rule.Threshold, v.ObservedValue)
		fireViolationNotification(v, dimColor)
	}
}

// fireViolationNotification dispatches the notification for a triggered alert.
func fireViolationNotification(v alert.Violation, dimColor *color.Color) {
	title := fmt.Sprintf("cloop alert: %s", v.Rule.Name)
	body := fmt.Sprintf("Metric %s %s %.4g (observed %.4g)",
		v.Rule.Metric, v.Rule.Op, v.Rule.Threshold, v.ObservedValue)

	ch := v.Rule.Notify
	switch {
	case ch == "" || ch == "desktop":
		notify.Send(title, body)
	case len(ch) > 8 && ch[:8] == "webhook:":
		url := ch[8:]
		if err := notify.SendWebhook(url, title, body); err != nil {
			dimColor.Printf("  alert webhook error (ignored): %v\n", err)
		}
	case len(ch) > 6 && ch[:6] == "slack:":
		url := ch[6:]
		if err := notify.SendWebhook(url, title, body); err != nil {
			dimColor.Printf("  alert slack error (ignored): %v\n", err)
		}
	}
}

// RegisterRoute adds a role→provider binding to the orchestrator's router.
// Must be called before Run().
func (o *Orchestrator) RegisterRoute(role pm.AgentRole, prov provider.Provider) {
	o.router.Register(role, prov)
}

func (o *Orchestrator) AddSteps(n int) {
	o.state.MaxSteps += n
	o.state.Save()
}

// logTaskOutcomeEvent appends one terminal event row to the events journal
// reflecting the final task status. Best-effort: never returns an error.
// Called from both the sequential and parallel PM loops (Task 20118).
func (o *Orchestrator) logTaskOutcomeEvent(task *pm.Task, taskDur string, step int) {
	if task == nil || o.config.WorkDir == "" {
		return
	}
	var typ state.EventType
	var msg string
	switch task.Status {
	case pm.TaskDone:
		typ = state.EventTaskDone
		msg = fmt.Sprintf("Task #%d completed in %s", task.ID, taskDur)
	case pm.TaskFailed:
		typ = state.EventTaskFailed
		msg = fmt.Sprintf("Task #%d failed after %s", task.ID, taskDur)
	case pm.TaskSkipped:
		typ = state.EventTaskSkipped
		msg = fmt.Sprintf("Task #%d skipped after %s", task.ID, taskDur)
	case pm.TaskTimedOut:
		typ = state.EventTaskKilled
		msg = fmt.Sprintf("Task #%d timed out after %s", task.ID, taskDur)
	default:
		// Implicit-done and other terminal states use the done event.
		typ = state.EventTaskDone
		msg = fmt.Sprintf("Task #%d completed (implicit) in %s", task.ID, taskDur)
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:      typ,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      step,
		Message:   msg,
	}, map[string]any{
		"status":         string(task.Status),
		"duration":       taskDur,
		"heal_attempts":  task.HealAttempts,
		"verify_retries": task.VerifyRetries,
		"fail_count":     task.FailCount,
	})
}

func (o *Orchestrator) SetAutoEvolve(enabled bool) {
	o.state.AutoEvolve = enabled
	o.state.Save()
}

// SetProvider persists the provider name in state so subsequent runs default to the same provider.
func (o *Orchestrator) SetProvider(name string) {
	if name != "" {
		o.state.Provider = name
		o.state.Save()
	}
}

// enforceClaudeCodeLimits checks the per-project claudecode subscription caps
// against the latest cached usage data (refreshing from the OAuth API if no
// cache is available). Returns nil when the active provider is not claudecode,
// when no caps are configured, when usage data is unavailable, or when no cap
// has been reached.
func (o *Orchestrator) enforceClaudeCodeLimits() error {
	cc := o.config.ClaudeCode
	if cc.MaxWeeklyPct <= 0 && cc.MaxFiveHourPct <= 0 &&
		cc.MaxWeeklyOpusPct <= 0 && cc.MaxWeeklySonnetPct <= 0 {
		return nil
	}
	// Only enforce when the active provider is claudecode.
	active := o.state.Provider
	if active == "" {
		active = o.config.ProviderName
	}
	if active != "claudecode" {
		return nil
	}
	// Coalesces concurrent fetches and serves the cached snapshot for at
	// least ratelimit.MinUsageCacheTTL (currently one minute) — important
	// because enforceClaudeCodeLimits runs before *every* task in a parallel
	// PM plan and would otherwise hammer the OAuth usage API.
	usage, err := ratelimit.FetchOrCachedUsage("", ratelimit.MinUsageCacheTTL)
	if err != nil && usage == nil {
		// Best-effort: when both fresh fetch and cache fail, skip enforcement.
		return nil
	}
	return ratelimit.EnforceClaudeCodeLimits(cc, usage)
}

func (o *Orchestrator) Run(ctx context.Context) error {
	// Start the stuck-task watchdog (Task 20088). Bound to a child context
	// that we cancel before Close() so Watchdog.Wait() doesn't deadlock when
	// the caller passed an unbounded ctx (e.g. context.Background() in tests).
	wdCtx, wdCancel := context.WithCancel(ctx)
	if o.watchdog != nil {
		o.watchdog.Start(wdCtx)
	}
	// Manual-abort poller (Task 20140): polls kill_requests rows the UI
	// inserts when an operator changes a running task's status, and fires
	// the watchdog-registered cancel for that task. Bound to wdCtx so it
	// dies with the watchdog on Close.
	o.startKillPoller(wdCtx)
	// Close the central work queue on Run() exit so the underlying SQLite
	// connection (and any goroutines it owns) is released. The orchestrator
	// is a one-shot value — callers Build → Run → discard. Re-using the
	// orchestrator after Run would already misbehave (state/plan are baked
	// in at New time), so closing here is safe.
	defer o.Close()
	defer wdCancel()
	return o.runPM(ctx)
}

// errSwitchMode is returned by the runPMSequential / runPMParallel loops when
// a UI-driven mid-run toggle of the Parallel / MaxParallel state warrants
// re-dispatching to the other execution mode. The dispatch loop in runPM
// catches it and re-enters the appropriate handler without restarting cloop
// (Task 20111: honour the parallelization setting at all times).
var errSwitchMode = errors.New("orchestrator: switching execution mode")

// wantParallel decides whether the PM loop should run in parallel mode based
// on both the immutable CLI/config flag (o.config.Parallel) and the mutable
// persisted state (s.Parallel / s.MaxParallel) that the Web UI updates. Either
// signal is sufficient — once the user has expressed intent for concurrency,
// either via flag or via UI toggle, the orchestrator obeys it.
func (o *Orchestrator) wantParallel() bool {
	if o.config.Parallel {
		return true
	}
	if o.state == nil {
		return false
	}
	if o.state.Parallel {
		return true
	}
	// A configured cap > 1 is itself an unambiguous "I want parallel" signal —
	// without this the dispatcher silently ignores a UI-set max-parallel of 4
	// when the Parallel boolean was never flipped.
	return o.state.MaxParallel > 1
}

// runPM dispatches to sequential or parallel task execution based on config
// and state. It loops on errSwitchMode so a UI-driven toggle of the Parallel
// flag mid-run triggers a re-dispatch instead of being silently ignored.
func (o *Orchestrator) runPM(ctx context.Context) error {
	// Root span for the entire PM run. All task_execute and provider_call spans
	// are children of this span, providing causality and latency drill-down.
	spanCtx, span := clooptracing.StartSpan(ctx, "plan_run",
		goOtelAttr.String("provider", o.provider.Name()),
		goOtelAttr.String("model", o.config.Model),
	)
	defer span.End()
	ctx = spanCtx

	// Start the stuck-task watchdog (Task 20088). Watchdog.Start is idempotent,
	// so calling it here in addition to Run() is safe — this covers callers
	// (notably tests) that invoke runPM directly without going through Run.
	if o.watchdog != nil {
		o.watchdog.Start(ctx)
	}

	for {
		var runErr error
		if o.wantParallel() {
			runErr = o.runPMParallel(ctx)
		} else {
			runErr = o.runPMSequential(ctx)
		}
		if errors.Is(runErr, errSwitchMode) {
			color.New(color.FgMagenta, color.Bold).Printf("↻ Mode switch (parallel=%v, max_parallel=%d) — re-dispatching loop\n",
				o.state.Parallel, o.state.MaxParallel)
			continue
		}
		// Best-effort: surface any final stuck event count in the logs once the
		// PM loop has unwound. Watchdog.Wait is invoked from Close().
		return runErr
	}
}

// runPMSequential runs PM tasks one at a time (original behaviour).
func (o *Orchestrator) runPMSequential(ctx context.Context) error {
	s := o.state

	// Recover stale tasks from prior interrupted runs.
	o.recoverStaleTasks(s)

	s.Status = "running"
	if err := s.Save(); err != nil {
		return err
	}

	sessionStart := time.Now()
	startStep := s.CurrentStep
	defer func() {
		newSteps := s.Steps
		if startStep < len(newSteps) {
			newSteps = newSteps[startStep:]
		} else {
			newSteps = nil
		}
		o.learnFromSession(ctx, newSteps)
		printSessionSummary(sessionStart, startStep, s)
	}()

	header := color.New(color.FgCyan, color.Bold)
	stepColor := color.New(color.FgYellow, color.Bold)
	successColor := color.New(color.FgGreen, color.Bold)
	failColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)
	pmColor := color.New(color.FgMagenta, color.Bold)

	if !o.log.IsJSON() {
		header.Printf("\n🧠 cloop PM — AI Product Manager Mode\n")
		fmt.Printf("   Provider: %s\n", o.provider.Name())
		fmt.Printf("   Goal: %s\n", s.Goal)
		fmt.Println()
	}
	o.log.Info(logger.EventSessionStart, 0, "session started", map[string]interface{}{
		"goal":     s.Goal,
		"mode":     "pm",
		"trace_id": clooptracing.TraceIDFromContext(ctx),
	})

	o.webhook.Send(webhook.EventSessionStarted, webhook.Payload{Goal: s.Goal})
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:    state.EventSessionStarted,
		Message: "Run started",
	}, map[string]any{
		"goal":         s.Goal,
		"provider":     o.provider.Name(),
		"model":        s.Model,
		"auto_evolve":  s.AutoEvolve,
		"innovate":     s.InnovateMode,
		"parallel":     s.Parallel,
		"max_parallel": s.MaxParallel,
	})

	// If --replan requested, clear existing plan and force re-decomposition.
	if o.config.Replan && s.Plan != nil {
		pmColor.Printf("Replanning: clearing existing plan (%d tasks) and re-decomposing.\n\n", len(s.Plan.Tasks))
		s.Plan = nil
		s.Save()
	}

	// Phase 1: Decompose goal into tasks (if not already done)
	if s.Plan == nil || len(s.Plan.Tasks) == 0 {
		// Run interactive goal clarification when stdin is a TTY and not skipped.
		// If clarification was already performed at 'cloop init' time, load from disk.
		var clarifyCtx string
		if !o.config.SkipClarify {
			if existing, loadErr := clarify.Load(o.config.WorkDir); loadErr == nil && len(existing) > 0 {
				// Re-use answers gathered at init time.
				clarifyCtx = clarify.BuildContext(existing)
				color.New(color.Faint).Printf("(Using goal clarification from previous session)\n\n")
			} else if clarify.IsTTY() {
				scanner := bufio.NewScanner(os.Stdin)
				qas, clarifyErr := clarify.Run(ctx, o.provider, s.Model, o.config.StepTimeout, s.Goal, s.Instructions, o.config.WorkDir, scanner)
				if clarifyErr != nil {
					// Non-fatal: log and continue without clarification.
					color.New(color.Faint).Printf("(Clarification skipped: %v)\n\n", clarifyErr)
				} else {
					clarifyCtx = clarify.BuildContext(qas)
				}
			}
		}

		pmColor.Printf("Decomposing goal into tasks...\n")
		decomposeQueueID := o.enqueueWork(taskqueue.Entry{
			Kind:        taskqueue.KindSession,
			Title:       "Decompose goal into tasks",
			Description: truncate(s.Goal, 300),
			Source:      "orchestrator",
		})
		_ = o.queue.MarkRunning(decomposeQueueID)
		plan, err := pm.Decompose(ctx, o.provider, s.Goal, s.Instructions, s.Model, o.config.StepTimeout, clarifyCtx)
		if err != nil {
			_ = o.queue.MarkFailed(decomposeQueueID, truncate(err.Error(), 200))
			failColor.Printf("x Failed to decompose goal: %v\n", err)
			s.Status = "failed"
			s.Save()
			return err
		}
		_ = o.queue.MarkDone(decomposeQueueID, fmt.Sprintf("decomposed into %d task(s)", len(plan.Tasks)))
		if o.config.CalibrationFactor != 0 && o.config.CalibrationFactor != 1.0 {
			pm.ApplyCalibrationFactor(plan, o.config.CalibrationFactor)
		}
		s.Plan = plan
		s.Save()

		fmt.Printf("\n")
		pmColor.Printf("Task Plan (%d tasks):\n", len(plan.Tasks))
		for _, t := range plan.Tasks {
			fmt.Printf("  %d. [P%d] %s\n", t.ID, t.Priority, t.Title)
			dimColor.Printf("       %s\n", truncate(t.Description, 120))
		}
		fmt.Println()
	} else {
		// If retry-failed is set, reset failed tasks to pending
		if o.config.RetryFailed {
			retried := 0
			for _, t := range s.Plan.Tasks {
				if t.Status == pm.TaskFailed {
					t.Status = pm.TaskPending
					retried++
				}
			}
			if retried > 0 {
				pmColor.Printf("Retrying %d failed task(s).\n\n", retried)
				s.Save()
			}
		}
		pmColor.Printf("Resuming plan: %s\n\n", s.Plan.Summary())
	}

	// Optimization pass: AI reviews the plan before execution.
	if o.config.Optimize && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		o.runOptimizer(ctx, s, pmColor, dimColor)
	}

	// Plan-only mode: just show the plan, don't execute
	if o.config.PlanOnly {
		s.Status = "paused"
		s.Save()
		return nil
	}

	// Stale checkpoint detection: if a checkpoint.json exists for a task that is
	// still marked in_progress (e.g. the previous run was killed), ask the user
	// whether to resume or restart that task.
	// Note: NextTask() only returns pending tasks, so an in_progress task would be
	// permanently skipped without intervention. The checkpoint ensures we notice and
	// give the user control.
	if cp, cpErr := checkpoint.Load(o.config.WorkDir); cpErr == nil && cp != nil {
		// Find the matching task in the current plan.
		var staleTask *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == cp.TaskID && t.Status == pm.TaskInProgress {
				staleTask = t
				break
			}
		}
		if staleTask != nil {
			color.New(color.FgYellow, color.Bold).Printf("\n⚠ Stale checkpoint detected: Task %d — %s\n", cp.TaskID, cp.TaskTitle)
			dimColor.Printf("  The previous run was interrupted while executing this task.\n")
			dimColor.Printf("  Started: %s ago\n\n", time.Since(cp.StartTimestamp).Round(time.Second))
			fmt.Printf("Retry this task or skip it? [r]etry / [s]kip: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
				if answer == "s" || answer == "skip" {
					staleTask.Status = pm.TaskSkipped
					staleTask.StartedAt = nil
					pm.AddAnnotation(staleTask, "ai", "Task skipped at stale-checkpoint recovery (user chose 'skip' after a previously interrupted run).")
					s.Save()
					_ = checkpoint.Clear(o.config.WorkDir)
					dimColor.Printf("→ Task %d skipped.\n\n", staleTask.ID)
				} else {
					// Default: retry — reset to pending so NextTask() picks it up.
					staleTask.Status = pm.TaskPending
					staleTask.StartedAt = nil
					s.Save()
					_ = checkpoint.Clear(o.config.WorkDir)
					dimColor.Printf("→ Retrying task %d.\n\n", staleTask.ID)
				}
			} else {
				// EOF / non-interactive: default to retry.
				staleTask.Status = pm.TaskPending
				staleTask.StartedAt = nil
				s.Save()
				_ = checkpoint.Clear(o.config.WorkDir)
			}
		} else {
			// No matching in-progress task — checkpoint is fully stale; remove it.
			_ = checkpoint.Clear(o.config.WorkDir)
		}
	}

	// Pre-plan hook: run once before execution starts.
	if err := hooks.RunPrePlan(o.config.Hooks, hooks.PlanContext{
		Goal:  s.Goal,
		Total: len(s.Plan.Tasks),
	}, o.allEnvLines()...); err != nil {
		failColor.Printf("✗ pre_plan hook failed: %v — aborting plan execution.\n", err)
		s.Status = "failed"
		s.Save()
		return err
	}

	// Post-plan hook: runs when plan finishes (done or paused).
	defer func() {
		done, failed := s.Plan.CountByStatus()
		skipped := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskSkipped {
				skipped++
			}
		}
		if hookErr := hooks.RunPostPlan(o.config.Hooks, hooks.PlanContext{
			Goal:    s.Goal,
			Total:   len(s.Plan.Tasks),
			Done:    done,
			Failed:  failed,
			Skipped: skipped,
		}, o.allEnvLines()...); hookErr != nil {
			dimColor.Printf("  post_plan hook error (ignored): %v\n", hookErr)
		}

		// Optional docs update hook: AI-refresh documentation after plan completes.
		if o.config.DocsUpdateOnComplete {
			dimColor.Printf("Running post-plan docs update...\n")
			pd, docsErr := cloopdocs.Collect(o.config.WorkDir, o.config.WorkDir)
			if docsErr == nil {
				docsCtx := context.Background()
				for _, df := range pd.Files {
					if o.config.DocsUpdateFile != "" && df.RelPath != o.config.DocsUpdateFile {
						continue
					}
					if !df.Exists {
						continue
					}
					updated, refreshErr := cloopdocs.Refresh(docsCtx, o.provider, o.config.Model, 3*time.Minute, df, pd)
					if refreshErr != nil {
						dimColor.Printf("  docs update error (%s): %v\n", df.RelPath, refreshErr)
						continue
					}
					if writeErr := atomicfile.Write(df.AbsPath, []byte(updated), 0o644); writeErr != nil {
						dimColor.Printf("  docs write error (%s): %v\n", df.RelPath, writeErr)
						continue
					}
					dimColor.Printf("  docs updated: %s\n", df.RelPath)
				}
			} else {
				dimColor.Printf("  docs collect error (ignored): %v\n", docsErr)
			}
		}
	}()

	// Phase 2: Execute tasks in priority order

	// Capture the original git branch once before execution so we can merge back.
	var gitOriginalBranch string
	if o.config.GitMode {
		var gitErr error
		gitOriginalBranch, gitErr = cloopgit.CurrentBranch(o.config.WorkDir)
		if gitErr != nil {
			failColor.Printf("✗ --git: could not determine current branch: %v — disabling git mode.\n", gitErr)
			o.config.GitMode = false
		}
	}

	consecutiveErrors := 0
	maxConsecutiveErrors := o.config.MaxFailures
	if maxConsecutiveErrors <= 0 {
		maxConsecutiveErrors = 3
	}

	// Auto-evolve safety net: if N consecutive evolve attempts add no new tasks
	// AND no explicit abort condition (token/step budget) is configured, stop
	// rather than spin forever burning tokens. When the user has set a budget,
	// the budget itself is the abort condition and we keep evolving until it
	// trips, regardless of how many empty evolves occur — that is the intended
	// behaviour for long-running auto-evolve sessions.
	consecutiveEmptyEvolves := 0
	const maxEmptyEvolves = 3

	for {
		select {
		case <-ctx.Done():
			s.Status = "paused"
			s.Save()
			return ctx.Err()
		default:
		}

		if o.config.StepsLimit > 0 && s.CurrentStep >= startStep+o.config.StepsLimit {
			color.New(color.FgYellow).Printf("⏸ Reached --steps limit (%d). Run 'cloop run' to continue.\n", o.config.StepsLimit)
			s.Status = "paused"
			s.Save()
			return nil
		}

		// Token budget check at the top of the loop so it fires during evolve cycles
		// (where the work-execution path's check would otherwise be skipped).
		if o.config.TokenBudget > 0 && s.TotalInputTokens+s.TotalOutputTokens >= o.config.TokenBudget {
			color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
			s.Status = "paused"
			s.Save()
			return nil
		}

		// Snapshot in-memory task IDs before SyncFromDisk so we can detect any
		// externally-added tasks that landed since the last iteration and record
		// them as KindExternal queue entries — this is the only place an
		// externally-added task gets surfaced into the central activity log.
		preMergeIDs := make(map[int]struct{}, len(s.Plan.Tasks))
		for _, t := range s.Plan.Tasks {
			preMergeIDs[t.ID] = struct{}{}
		}
		s.SyncFromDisk()
		for _, t := range s.Plan.Tasks {
			if _, existed := preMergeIDs[t.ID]; existed {
				continue
			}
			extID := o.enqueueWork(taskqueue.Entry{
				Kind:        taskqueue.KindExternal,
				TaskID:      t.ID,
				Title:       fmt.Sprintf("External task added: %s", t.Title),
				Description: truncate(t.Description, 300),
				Source:      "external",
			})
			_ = o.queue.MarkDone(extID, fmt.Sprintf("merged from disk (status=%s)", t.Status))
		}
		// Reactivate recurring tasks whose schedule has fired.
		for _, t := range s.Plan.Tasks {
			if pm.ResetIfDue(t, time.Now()) {
				dimColor.Printf("↺ Task %d recurring: reset to pending (%s)\n", t.ID, t.Recurrence)
				s.Save()
			}
		}
		// Mid-run mode switch: if the user enabled parallel mode (or set
		// max_parallel > 1) via the Web UI while we were sequential, surrender
		// so runPM can re-dispatch into runPMParallel without a process restart
		// (Task 20111). We're at the top of the loop with no task in flight, so
		// switching is safe — the next iteration starts fresh in the new mode.
		if o.wantParallel() {
			return errSwitchMode
		}
		if s.Plan.IsComplete() {
			if !o.log.IsJSON() {
				if s.AutoEvolve {
					successColor.Printf("🎉 All tasks complete! Auto-evolve enabled — discovering more work.\n")
				} else {
					successColor.Printf("🎉 All tasks complete! Goal achieved.\n")
				}
				successColor.Printf("   %s\n\n", s.Plan.Summary())
			}
			o.log.Info(logger.EventSessionDone, 0, "all tasks complete", map[string]interface{}{
				"summary": s.Plan.Summary(),
			})
			if o.config.Notify {
				notify.Send("cloop: All Tasks Complete", s.Goal)
			}
			o.notifyWebhooks("cloop: Plan Complete", fmt.Sprintf("Goal: %s\n%s", s.Goal, s.Plan.Summary()))
			if o.metrics != nil {
				if err := o.metrics.WriteJSON(o.config.WorkDir); err != nil {
					dimColor.Printf("  metrics write error (ignored): %v\n", err)
				}
			}
			done, failed := s.Plan.CountByStatus()
			o.webhook.Send(webhook.EventPlanComplete, webhook.Payload{
				Goal:     s.Goal,
				Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
				Session: &webhook.SessionInfo{
					TotalTasks:   len(s.Plan.Tasks),
					DoneTasks:    done,
					FailedTasks:  failed,
					InputTokens:  s.TotalInputTokens,
					OutputTokens: s.TotalOutputTokens,
					Duration:     time.Since(sessionStart).Round(time.Second).String(),
				},
			})
			state.LogEventDetails(o.config.WorkDir, state.EventRow{
				Type:    state.EventPlanComplete,
				Message: fmt.Sprintf("All %d tasks complete", len(s.Plan.Tasks)),
			}, map[string]any{
				"total":    len(s.Plan.Tasks),
				"done":     done,
				"failed":   failed,
				"duration": time.Since(sessionStart).Round(time.Second).String(),
			})
			if s.AutoEvolve {
				s.Status = "evolving"
				s.Save()
				n, err := o.evolvePM(ctx)
				if err != nil {
					color.New(color.FgMagenta, color.Bold).Printf("\n⏹ Evolve stopped: %v\n", err)
					s.Status = "complete"
					s.Save()
					return nil
				}
				if n == 0 {
					consecutiveEmptyEvolves++
					// When the user has configured a budget abort condition
					// (token or step limit), keep evolving — that condition
					// will eventually trip and terminate the loop. Without a
					// budget, fall back to the empty-evolves cap so we don't
					// spin forever burning tokens.
					hasBudget := o.config.TokenBudget > 0 || o.config.StepsLimit > 0
					if !hasBudget && consecutiveEmptyEvolves >= maxEmptyEvolves {
						color.New(color.FgYellow).Printf("⏸ Auto-evolve found no new tasks in %d consecutive attempts and no token/step budget is set. Stopping.\n", maxEmptyEvolves)
						s.Status = "complete"
						s.Save()
						return nil
					}
					if hasBudget {
						dimColor.Printf("  Auto-evolve: 0 new tasks (attempt %d). Continuing — abort controlled by configured budget.\n", consecutiveEmptyEvolves)
					} else {
						dimColor.Printf("  Auto-evolve: 0 new tasks (%d/%d). Retrying...\n", consecutiveEmptyEvolves, maxEmptyEvolves)
					}
					s.Status = "running"
					continue
				}
				consecutiveEmptyEvolves = 0
				s.Status = "running"
				continue
			}
			s.Status = "complete"
			s.Save()
			return nil
		}

		// Deadline check: boost overdue task priorities and fire notifications each iteration.
		{
			results := pm.CheckAndBoostOverdue(s.Plan)
			for _, r := range results {
				if r.Boosted {
					s.Save()
					color.New(color.FgRed, color.Bold).Printf("\u26a0 Task %d overdue and boosted to P1: %s\n", r.Task.ID, r.Task.Title)
				}
				if o.config.Notify {
					notify.Send(
						fmt.Sprintf("cloop: Overdue Task #%d", r.Task.ID),
						fmt.Sprintf("%s — %s", r.Task.Title, pm.FormatCountdown(pm.TimeUntilDeadlineD(r.Task))),
					)
				}
				o.notifyWebhooks(
					fmt.Sprintf("cloop: Overdue Task #%d", r.Task.ID),
					fmt.Sprintf("%s is overdue (%s)", r.Task.Title, pm.FormatCountdown(pm.TimeUntilDeadlineD(r.Task))),
				)
			}
		}

		// Auto-promote: escalate priorities for tasks approaching their deadlines.
		if o.config.AutoPromote {
			promotions := promote.Run(s.Plan, o.config.AutoPromoteThresholdDays, false)
			if len(promotions) > 0 {
				s.Save()
				for _, p := range promotions {
					color.New(color.FgYellow, color.Bold).Printf(
						"\u2191 Task %d promoted P%d→P%d (%s): %s\n",
						p.TaskID, p.OldPriority, p.NewPriority, p.Reason, p.Title,
					)
				}
			}
		}

		task := s.Plan.NextTask()
		if task == nil {
			// Auto-skip tasks that are permanently blocked by failed deps
			skipped := 0
			for _, t := range s.Plan.Tasks {
				if t.Status == pm.TaskPending && s.Plan.PermanentlyBlocked(t) {
					failColor.Printf("⊘ Task %d skipped (blocked by failed dependency): %s\n", t.ID, t.Title)
					t.Status = pm.TaskSkipped
					pm.AddAnnotation(t, "ai", "Task skipped: permanently blocked by failed dependency.")
					skipped++
				}
			}
			if skipped > 0 {
				s.Save()
				continue
			}
			break
		}

		// Tag filter: skip tasks that don't match any of the requested tags.
		if len(o.config.TagFilter) > 0 && !pm.TaskMatchesTags(task, o.config.TagFilter) {
			color.New(color.Faint).Printf("⊘ Task %d skipped (no matching tag): %s\n", task.ID, task.Title)
			task.Status = pm.TaskSkipped
			pm.AddAnnotation(task, "ai", fmt.Sprintf("Task skipped: did not match active tag filter %v.", o.config.TagFilter))
			s.Save()
			continue
		}

		// Condition gate: evaluate the task's condition before execution.
		if task.Condition != "" {
			condOpts := provider.Options{
				Model:   s.Model,
				Timeout: o.config.StepTimeout,
			}
			res, condErr := condition.Evaluate(ctx, task, s.Plan, o.provider, condOpts, o.config.WorkDir)
			if condErr != nil {
				dimColor.Printf("  condition eval error for task %d (proceeding): %v\n", task.ID, condErr)
			}
			if !res.Proceed {
				color.New(color.Faint).Printf("⊘ Task %d skipped (condition not met): %s\n  Condition: %s\n  Reason: %s\n",
					task.ID, task.Title, task.Condition, res.Reason)
				task.Status = pm.TaskSkipped
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task skipped: condition gate %q not met. Reason: %s", task.Condition, res.Reason))
				s.Save()
				continue
			}
			dimColor.Printf("  Condition met for task %d: %s\n", task.ID, res.Reason)
		}

		// Check max steps limit
		if s.MaxSteps > 0 && s.CurrentStep >= s.MaxSteps {
			color.New(color.FgYellow).Printf("⏸ Reached max steps (%d). Run 'cloop run' to continue.\n", s.MaxSteps)
			s.Status = "paused"
			s.Save()
			return nil
		}

		// Daily budget enforcement: abort before spending tokens if any limit is exceeded.
		if budgetErr := budget.Enforce(o.config.WorkDir, o.config.Budget, o.config.NotifyCfg); budgetErr != nil {
			failColor.Printf("\n✗ Budget limit reached: %v\n", budgetErr)
			s.Status = "paused"
			s.Save()
			return budgetErr
		}

		// Per-project claudecode subscription cap enforcement.
		if ccErr := o.enforceClaudeCodeLimits(); ccErr != nil {
			failColor.Printf("\n✗ %v\n", ccErr)
			s.Status = "paused"
			s.Save()
			return ccErr
		}

		// Ensure a request ID is bound to ctx for this task iteration before
		// the first log line is emitted. taskContextWithTimeout below derives
		// from ctx (so it inherits the ID); the EnsureContext call returns
		// the existing ID when the loop's parent context already carries one
		// (e.g. invoked from the Web UI middleware) and mints a fresh one
		// otherwise. Logs keyed off `request_id` can then be grouped per task.
		ctx, taskRequestID := reqid.EnsureContext(ctx)
		if !o.log.IsJSON() {
			stepColor.Printf("━━━ Task %d/%d: %s ━━━\n", task.ID, len(s.Plan.Tasks), task.Title)
			dimColor.Printf("       %s\n\n", truncate(task.Description, 150))
		}
		o.log.Info(logger.EventTaskStart, task.ID, task.Title, map[string]interface{}{
			"priority":    task.Priority,
			"description": task.Description,
			"role":        string(task.Role),
			"trace_id":    clooptracing.TraceIDFromContext(ctx),
			"request_id":  taskRequestID,
		})

		// Pre-execution risk assessment: evaluate risks and optionally abort on CRITICAL findings.
		if o.config.RiskCheck {
			riskCtx, riskCancel := context.WithTimeout(ctx, 2*time.Minute)
			riskReport, riskErr := risk.AssessTask(riskCtx, o.provider, o.config.Model, s.Plan, task)
			riskCancel()
			if riskErr != nil {
				dimColor.Printf("⚠  Risk assessment failed for task %d: %v (continuing)\n\n", task.ID, riskErr)
			} else if riskReport != nil && len(riskReport.Findings) > 0 {
				printRiskBanner(riskReport)
				if riskReport.HasCritical() && !o.config.RiskForce {
					failColor.Printf("✗ Task %d aborted: CRITICAL risk finding(s). Use --force to override.\n\n", task.ID)
					task.Status = pm.TaskFailed
					pm.AddAnnotation(task, "ai", "Task failed: pre-execution risk assessment flagged CRITICAL finding(s); aborted before provider call. Use --force to override.")
					s.Save()
					continue
				}
			}
		}

		// Human-in-the-loop approval gate: fires when RequireApproval config is set
		// (gates P0/P1 and tasks with RequiresApproval:true) or per-task flag.
		needsGate := task.RequiresApproval ||
			(o.config.RequireApproval && task.Priority <= 1)
		if needsGate {
			gate := approvalgate.New()
			res := gate.Approve(task)
			switch {
			case res.Skipped:
				task.Status = pm.TaskSkipped
				pm.AddAnnotation(task, "ai", "Task skipped at human approval gate (operator declined to approve before execution).")
				dimColor.Printf("→ Task %d skipped at approval gate.\n\n", task.ID)
				s.Save()
				continue
			case res.Paused:
				s.Status = "paused"
				s.Save()
				color.New(color.FgYellow).Printf("⏸ Approval gate: execution declined. Run 'cloop run' to resume.\n")
				return nil
			default:
				// Approved (possibly with edited description)
				if res.EditedDesc != "" {
					task.Description = res.EditedDesc
					s.Save()
					dimColor.Printf("  Task %d description updated via editor.\n", task.ID)
				}
				// Mark as approved so unattended reruns skip the gate.
				task.Approved = true
				s.Save()
			}
		}

		// Human-in-the-loop review mode: ask before executing each task.
		if o.config.ReviewMode {
			action := reviewTask(task)
			switch action {
			case "skip":
				task.Status = pm.TaskSkipped
				pm.AddAnnotation(task, "ai", "Task skipped by user in interactive review mode.")
				dimColor.Printf("→ Task %d skipped by user.\n\n", task.ID)
				s.Save()
				continue
			case "quit":
				s.Status = "paused"
				s.Save()
				color.New(color.FgYellow).Printf("⏸ Review mode: user quit. Run 'cloop run' to resume.\n")
				return nil
			case "no":
				s.Status = "paused"
				s.Save()
				color.New(color.FgYellow).Printf("⏸ Task execution declined. Run 'cloop run' to resume.\n")
				return nil
			}
			// "yes" falls through
		}

		// Pre-task coaching: give the executor AI-generated coaching tips.
		if o.config.CoachMode {
			coachCtx, coachCancel := context.WithTimeout(ctx, 3*time.Minute)
			session, coachErr := coach.Coach(coachCtx, o.provider, o.config.Model, task, s.Plan, o.config.WorkDir)
			coachCancel()
			if coachErr != nil {
				dimColor.Printf("⚠  Coaching failed for task %d: %v (continuing)\n\n", task.ID, coachErr)
			} else {
				printCoachBanner(session)
			}
		}

		// Pre-task hook: skip the task if it exits non-zero.
		if hookErr := hooks.RunPreTask(o.config.Hooks, hooks.TaskContext{
			ID:     task.ID,
			Title:  task.Title,
			Status: "pending",
			Role:   string(task.Role),
		}, o.allEnvLines()...); hookErr != nil {
			dimColor.Printf("⊘ pre_task hook failed for task %d (%s): %v — skipping task.\n", task.ID, task.Title, hookErr)
			task.Status = pm.TaskSkipped
			pm.AddAnnotation(task, "ai", fmt.Sprintf("Task skipped: pre_task hook exited non-zero: %v", hookErr))
			s.Save()
			continue
		}

		now := time.Now()
		task.Status = pm.TaskInProgress
		task.StartedAt = &now
		pm.AddAnnotation(task, "ai", fmt.Sprintf("Task started by executor (provider: %s)", o.provider.Name()))
		s.Save()

		// Central queue: record this task execution as a work item BEFORE the
		// provider call. The id is carried forward so we can mark the entry
		// done/failed/skipped after the call returns. Every work path in the
		// orchestrator routes through the queue — the UI relies on it for
		// full activity auditability.
		queueID := o.enqueueWork(taskqueue.Entry{
			Kind:        taskqueue.KindTask,
			TaskID:      task.ID,
			Title:       task.Title,
			Description: task.Description,
			Source:      "orchestrator",
		})
		_ = o.queue.MarkRunning(queueID)

		if o.metrics != nil {
			o.metrics.RecordTaskStarted()
		}

		// Write mid-execution checkpoint so an interrupted run can resume.
		cp := &checkpoint.Checkpoint{
			TaskID:         task.ID,
			TaskTitle:      task.Title,
			StepNumber:     s.CurrentStep,
			StartTimestamp: now,
			Provider:       o.provider.Name(),
		}
		if cpErr := checkpoint.Save(o.config.WorkDir, cp); cpErr != nil {
			dimColor.Printf("  checkpoint write error (ignored): %v\n", cpErr)
		}
		// Persist a history entry so checkpoint-diff can show what changed over time.
		histCP := *cp
		histCP.Event = "start"
		histCP.Status = string(pm.TaskInProgress)
		histCP.Timestamp = now
		histCP.TokenCount = s.TotalInputTokens + s.TotalOutputTokens
		if hErr := checkpoint.SaveHistoryEntry(o.config.WorkDir, &histCP); hErr != nil {
			dimColor.Printf("  checkpoint history write error (ignored): %v\n", hErr)
		}

		{
			done, failed := s.Plan.CountByStatus()
			o.webhook.Send(webhook.EventTaskStarted, webhook.Payload{
				Goal:     s.Goal,
				Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Description: task.Description, Status: "in_progress"},
				Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
				Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
			})
		}
		state.LogEventDetails(o.config.WorkDir, state.EventRow{
			Type:      state.EventTaskStarted,
			TaskID:    task.ID,
			TaskTitle: task.Title,
			Step:      s.CurrentStep,
			Message:   fmt.Sprintf("Task #%d started", task.ID),
		}, map[string]any{
			"priority": task.Priority,
			"role":     task.Role,
		})

		// Build prompt with optional project context injection.
		var projCtx *pm.ProjectContext
		if o.config.InjectContext {
			projCtx = pm.BuildProjectContext(o.config.WorkDir)
		}
		promptPlan, keptResults, totalResults := o.prunePlanForPrompt(s.Plan)
		if keptResults < totalResults {
			color.New(color.FgYellow).Printf("Context pruned: kept %d of %d steps to fit token budget\n", keptResults, totalResults)
		}
		prompt := pm.ExecuteTaskPrompt(s.Goal, s.Instructions, o.config.WorkDir, promptPlan, task, o.config.NoCodeContextInject, projCtx)
		// Check for a user-edited context override. If one exists, use it instead.
		if override, overrideErr := ctxedit.LoadOverride(o.config.WorkDir, task.ID); overrideErr == nil && override != "" {
			color.New(color.FgYellow).Printf("  Using context override for task %d (from .cloop/context_override_%d.txt)\n", task.ID, task.ID)
			prompt = override
		}
		prompt = cloopenv.InjectIntoPrompt(prompt, o.envVars)
		if o.secretStore != nil {
			prompt = o.secretStore.InjectIntoPrompt(prompt)
		}
		// Prepend memory if enabled
		if o.config.UseMemory && o.memory != nil {
			limit := o.config.MemoryLimit
			if limit == 0 {
				limit = 20
			}
			if mem := o.memory.FormatForPrompt(limit); mem != "" {
				prompt = mem + prompt
			}
		}
		// Always prepend cross-session narrative memory from .cloop/memory.md.
		if learningMem := learning.FormatForPrompt(o.config.WorkDir); learningMem != "" {
			prompt = learningMem + prompt
		}

		// Prompt A/B testing: track the currently recommended variant for this
		// task's role. Used to record outcomes and to select a replacement on
		// heal retries. Does not modify the main task prompt — variant injection
		// only happens in the heal loop below.
		activeVariant := promptopt.BestVariant(o.config.WorkDir, task.Role)

		if o.config.DryRun {
			dimColor.Printf("[dry-run] Task prompt:\n%s\n\n", prompt)
			task.Status = pm.TaskDone
			s.Save()
			continue
		}

		// Git mode: create a dedicated branch for this task before execution.
		var gitTaskBranch string
		if o.config.GitMode {
			var gitErr error
			gitTaskBranch, gitErr = cloopgit.CreateTaskBranch(o.config.WorkDir, task)
			if gitErr != nil {
				dimColor.Printf("  git branch error (ignored): %v\n", gitErr)
				gitTaskBranch = ""
			} else {
				dimColor.Printf("  git: checked out branch %s\n", gitTaskBranch)
			}
		}

		// Select provider: role-specific route takes precedence over default.
		taskProvider := o.router.For(task.Role)
		start := time.Now()

		// Apply per-task time budget.
		taskCtx, taskCancel := o.taskContextWithTimeout(ctx, task)
		defer taskCancel()

		// Register the per-task cancel with the watchdog (Task 20088). When
		// AutoKillAfter is configured, this lets the watchdog cancel a wedged
		// provider call. Unregister fires before the next iteration via the
		// inner-loop continue/break paths since `defer` runs on function
		// return; for tasks-loop iterations we still rely on the watchdog
		// dropping flagged-state once Status leaves in_progress (handled in
		// watchdog.tick). This is intentional — Register/Unregister is for
		// the cancel registry, not flagged-state lifecycle.
		o.watchdog.Register(task.ID, taskCancel)

		// ── Multi-agent path ───────────────────────────────────────────────
		// When --multi-agent is set, run the three-pass pipeline instead of a
		// single provider call. The combined reviewer output becomes the task
		// result for signal detection and artifact storage.
		var taskOutput string
		var taskInputTokens, taskOutputTokens, taskThinkingTokens int
		var taskProviderName, taskModelName string
		var consensusReport *consensus.Report // non-nil when consensus was used

		if o.config.MultiAgent {
			dimColor.Printf("→ Running multi-agent pipeline on task %d (architect→coder→reviewer)...\n", task.ID)

			// Build optional project context string for the multi-agent prompt.
			var projCtxStr string
			if projCtx != nil {
				projCtxStr = projCtx.Format()
			}

			maRes, maErr := multiagent.RunTask(
				taskCtx,
				taskProvider,
				s.Model,
				o.config.StepTimeout,
				task,
				s.Goal,
				s.Instructions,
				projCtxStr,
			)
			if maErr != nil {
				if isTimeoutErr(taskCtx, maErr) {
					budgetMin := o.effectiveTaskBudgetMinutes(task)
					color.New(color.FgYellow).Printf("⏱ Task %d timed out (%dm): %s\n", task.ID, budgetMin, task.Title)
					o.handleTaskTimeout(ctx, s, task, "", dimColor)
					_ = o.queue.MarkFailed(queueID, fmt.Sprintf("multi-agent timeout (%dm)", budgetMin))
					consecutiveErrors++
					s.Save()
					if consecutiveErrors >= maxConsecutiveErrors {
						s.Status = "failed"
						s.Save()
						return fmt.Errorf("%d consecutive errors", consecutiveErrors)
					}
					continue
				}
				failColor.Printf("✗ Multi-agent error: %v\n", maErr)
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: multi-agent pipeline error — %s", truncate(maErr.Error(), 200)))
				task.Status = pm.TaskFailed
				_ = o.queue.MarkFailed(queueID, truncate(maErr.Error(), 200))
				consecutiveErrors++
				s.Save()
				if consecutiveErrors >= maxConsecutiveErrors {
					s.Status = "failed"
					s.Save()
					return fmt.Errorf("%d consecutive errors", consecutiveErrors)
				}
				continue
			}

			// Persist sub-agent artifacts.
			if artifactDir, aErr := multiagent.WriteArtifacts(o.config.WorkDir, task, maRes); aErr != nil {
				dimColor.Printf("  multi-agent artifact write error (ignored): %v\n", aErr)
			} else {
				dimColor.Printf("  sub-agent artifacts: %s/{architect,coder,reviewer}.txt\n", artifactDir)
			}

			// The reviewer output is the canonical task result.
			taskOutput = maRes.ReviewerOutput
			taskProviderName = taskProvider.Name()
			taskModelName = s.Model
		} else {
			// ── Standard single-agent path ─────────────────────────────────

			// Consensus mode: fan out to multiple providers for critical tasks.
			useConsensus := o.config.ConsensusN > 0 && consensus.IsCritical(task.Priority, task.Tags)
			if useConsensus {
				dimColor.Printf("→ Running consensus (n=%d) on critical task %d...\n", o.config.ConsensusN, task.ID)
				consensusProviders := o.buildConsensusProviders(taskProvider)
				opts, _ := o.makeOpts(s.Model, false) // no streaming in consensus mode
				cOutput, cReport, cErr := consensus.RunConsensus(
					taskCtx,
					consensusProviders,
					prompt,
					opts,
					taskProvider, // judge = primary provider
					s.Model,
					o.config.ConsensusN,
					task.ID,
					task.Title,
				)
				if cErr != nil {
					if isTimeoutErr(taskCtx, cErr) {
						budgetMin := o.effectiveTaskBudgetMinutes(task)
						color.New(color.FgYellow).Printf("⏱ Task %d timed out (%dm): %s\n", task.ID, budgetMin, task.Title)
						o.handleTaskTimeout(ctx, s, task, "", dimColor)
						_ = o.queue.MarkFailed(queueID, fmt.Sprintf("consensus timeout (%dm)", budgetMin))
						consecutiveErrors++
						s.Save()
						if consecutiveErrors >= maxConsecutiveErrors {
							s.Status = "failed"
							s.Save()
							return fmt.Errorf("%d consecutive errors", consecutiveErrors)
						}
						continue
					}
					failColor.Printf("✗ Consensus error: %v\n", cErr)
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: consensus error — %s", truncate(cErr.Error(), 200)))
					task.Status = pm.TaskFailed
					_ = o.queue.MarkFailed(queueID, truncate(cErr.Error(), 200))
					consecutiveErrors++
					s.Save()
					if consecutiveErrors >= maxConsecutiveErrors {
						s.Status = "failed"
						s.Save()
						return fmt.Errorf("%d consecutive errors", consecutiveErrors)
					}
					continue
				}
				taskOutput = cOutput
				taskProviderName = cReport.Winner
				taskModelName = s.Model
				printOutput(cOutput, dimColor, o.config.Verbose)
				dimColor.Printf("  consensus winner: %s\n", cReport.Winner)
				// Store the report for artifact appending after signal detection.
				consensusReport = cReport
			} else {
				dimColor.Printf("→ Running %s on task %d...\n", taskProvider.Name(), task.ID)

				opts, wasStreamed := o.makeOpts(s.Model, true)
				// Open live artifact file so `cloop task watch` can tail output.
				liveFile, liveErr := artifact.OpenLiveArtifact(o.config.WorkDir, task.ID)
				if liveErr != nil {
					dimColor.Printf("  live artifact open error (ignored): %v\n", liveErr)
					liveFile = nil
				}
				if liveFile != nil {
					prevOnToken := opts.OnToken
					opts.OnToken = func(token string) {
						if prevOnToken != nil {
							prevOnToken(token)
						}
						_, _ = liveFile.WriteString(token)
					}
				}
				// task_execute span: covers the provider call, giving the hierarchy
				// plan_run > task_execute > provider_call when tracing is enabled.
				taskExecCtx, taskExecSpan := clooptracing.StartSpan(taskCtx, "task_execute",
					goOtelAttr.Int("task.id", task.ID),
					goOtelAttr.String("task.title", task.Title),
					goOtelAttr.Int("task.priority", task.Priority),
					goOtelAttr.String("task.role", string(task.Role)),
				)
				// Tag the call context with the active task so the provider
				// audit log (Task 20105 / Task 20123) can correlate the row.
				auditCtx := provideraudit.WithTaskContext(taskExecCtx, task.ID, task.Title)
				result, err := safeComplete(auditCtx, taskProvider, prompt, opts)
				taskExecSpan.End()
				if liveFile != nil {
					if err == nil && !wasStreamed() {
						// Non-streaming provider: write full output so watchers can read it.
						_, _ = liveFile.WriteString(result.Output)
					}
					_ = liveFile.Close()
				}
				if err != nil {
					if isTimeoutErr(taskCtx, err) {
						budgetMin := o.effectiveTaskBudgetMinutes(task)
						color.New(color.FgYellow).Printf("⏱ Task %d timed out (%dm): %s\n", task.ID, budgetMin, task.Title)
						o.handleTaskTimeout(ctx, s, task, "", dimColor)
						_ = o.queue.MarkFailed(queueID, fmt.Sprintf("provider timeout (%dm)", budgetMin))
						consecutiveErrors++
						s.Save()
						if consecutiveErrors >= maxConsecutiveErrors {
							s.Status = "failed"
							s.Save()
							return fmt.Errorf("%d consecutive errors", consecutiveErrors)
						}
						continue
					}
					if provider.IsRetryBudgetExhausted(err) {
						// Per-task retry budget hit: surface as a distinct failure
						// mode. We do not auto-heal because every heal would consume
						// further attempts the budget already refused; instead the
						// task is marked failed and the operator must raise
						// task.RetryBudget or address the underlying flake.
						failColor.Printf("✗ Task %d: retry budget exhausted — %v\n", task.ID, err)
						pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: retry budget exhausted (limit reached) — %s", truncate(err.Error(), 200)))
						task.Status = pm.TaskFailed
						_ = o.queue.MarkFailed(queueID, "retry budget exhausted")
						consecutiveErrors++
						s.Save()
						if consecutiveErrors >= maxConsecutiveErrors {
							s.Status = "failed"
							s.Save()
							return fmt.Errorf("%d consecutive errors", consecutiveErrors)
						}
						continue
					}
					failColor.Printf("✗ Provider error: %v\n", err)
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: provider error — %s", truncate(err.Error(), 200)))
					task.Status = pm.TaskFailed
					_ = o.queue.MarkFailed(queueID, truncate(err.Error(), 200))
					consecutiveErrors++
					s.Save()
					if consecutiveErrors >= maxConsecutiveErrors {
						s.Status = "failed"
						s.Save()
						return fmt.Errorf("%d consecutive errors", consecutiveErrors)
					}
					continue
				}

				taskOutput = result.Output
				taskInputTokens = result.InputTokens
				taskOutputTokens = result.OutputTokens
				taskThinkingTokens = result.ThinkingTokens
				taskProviderName = result.Provider
				taskModelName = result.Model

				if wasStreamed() {
					fmt.Println()
				} else {
					printOutput(result.Output, dimColor, o.config.Verbose)
				}
			}
		}

		// Empty-output watchdog: a provider returning (Result{Output:""}, nil)
		// produces no signal, so the switch below falls into `default:` and
		// silently marks the task DONE — a single transient hiccup can then
		// drain the entire plan in a tight loop. Mirror the decorator
		// behaviour in pkg/provider/cached and pkg/provider/fallback:
		// re-queue the task as pending, increment consecutiveErrors, and
		// abort once the threshold trips.
		if strings.TrimSpace(taskOutput) == "" {
			consecutiveErrors++
			failColor.Printf("✗ Task %d: provider returned empty output (consecutive errors: %d/%d)\n",
				task.ID, consecutiveErrors, maxConsecutiveErrors)
			pm.AddAnnotation(task, "ai", fmt.Sprintf("Task re-queued: provider returned empty output (consecutive errors: %d/%d).", consecutiveErrors, maxConsecutiveErrors))
			task.Status = pm.TaskPending
			_ = o.queue.MarkFailed(queueID, "provider returned empty output")
			s.Save()
			if consecutiveErrors >= maxConsecutiveErrors {
				s.Status = "failed"
				s.Save()
				abortErr := fmt.Errorf("%d consecutive task failures (empty provider output)", consecutiveErrors)
				o.webhook.Send(webhook.EventSessionFailed, webhook.Payload{
					Goal:    s.Goal,
					Session: &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					Error:   webhook.TruncateError(abortErr.Error()),
				})
				return abortErr
			}
			continue
		}

		duration := time.Since(start)
		stepResult := state.StepResult{
			Task:         fmt.Sprintf("Task %d: %s", task.ID, task.Title),
			Output:       taskOutput,
			Duration:     duration.Round(time.Second).String(),
			Time:         time.Now(),
			InputTokens:  taskInputTokens,
			OutputTokens: taskOutputTokens,
		}
		s.TotalInputTokens += taskInputTokens
		s.TotalOutputTokens += taskOutputTokens
		replayStep := s.CurrentStep
		s.AddStep(stepResult)
		if err := replay.Append(o.config.WorkDir, replay.Entry{
			Ts:        time.Now(),
			TaskID:    task.ID,
			TaskTitle: task.Title,
			Step:      replayStep,
			Content:   taskOutput,
		}); err != nil {
			dimColor.Printf("  replay log write error (ignored): %v\n", err)
		}

		// Record step tokens/cost into metrics.
		if o.metrics != nil {
			o.metrics.RecordStep()
			o.metrics.RecordTokens(taskProviderName, taskModelName, taskInputTokens, taskOutputTokens)
			if usd, ok := cost.Estimate(strings.ToLower(taskModelName), taskInputTokens, taskOutputTokens); ok {
				o.metrics.RecordCost(taskProviderName, taskModelName, usd)
			}
		}

		if !o.config.MultiAgent {
			dimColor.Printf("  [%s, provider: %s]\n\n", duration.Round(time.Second), taskProviderName)
		} else {
			dimColor.Printf("  [%s, multi-agent, provider: %s]\n\n", duration.Round(time.Second), taskProviderName)
		}

		if o.config.TokenBudget > 0 && s.TotalInputTokens+s.TotalOutputTokens >= o.config.TokenBudget {
			color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
			// Mark the in-progress task as pending so it retries next time
			task.Status = pm.TaskPending
			s.Status = "paused"
			s.Save()
			return nil
		}
		if o.checkCostLimit(s) {
			task.Status = pm.TaskPending
			s.Status = "paused"
			s.Save()
			return nil
		}

		// Update task status based on signal in output
		signal := pm.CheckTaskSignal(taskOutput)

		// Auto-heal: when a task emits TASK_FAILED, diagnose the failure and
		// re-attempt with a mutated prompt up to HealRetries times (default 2)
		// before permanently marking the task failed. Disabled by --no-heal.
		if signal == pm.TaskFailed && !o.config.NoHeal {
			healColor := color.New(color.FgCyan, color.Bold)
			maxHealRetries := o.config.HealRetries
			if maxHealRetries <= 0 {
				maxHealRetries = 2
			}
			// currentHealVariant tracks the variant used across heal iterations.
			currentHealVariant := activeVariant
			for healAttempt := 1; healAttempt <= maxHealRetries && signal == pm.TaskFailed; healAttempt++ {
				task.HealAttempts++
				// Enqueue this heal attempt as its own queue entry so the UI shows
				// every retry (not just the parent task) — heals are a distinct
				// unit of work that consume tokens and can themselves succeed/fail.
				healQueueID := o.enqueueWork(taskqueue.Entry{
					Kind:        taskqueue.KindHeal,
					TaskID:      task.ID,
					Attempt:     healAttempt,
					ParentID:    queueID,
					Title:       fmt.Sprintf("Heal task %d (attempt %d/%d): %s", task.ID, healAttempt, maxHealRetries, task.Title),
					Description: fmt.Sprintf("Auto-heal retry triggered by TASK_FAILED signal. Diagnosing and re-prompting with mutated prompt."),
					Source:      "orchestrator",
				})
				_ = o.queue.MarkRunning(healQueueID)
				if !o.log.IsJSON() {
					healColor.Printf("[HEAL attempt %d/%d] Diagnosing failure for task %d: %s\n", healAttempt, maxHealRetries, task.ID, task.Title)
				}
				o.log.Warn(logger.EventHeal, task.ID, "heal attempt", map[string]interface{}{
					"attempt": healAttempt,
					"max":     maxHealRetries,
				})
				state.LogEventDetails(o.config.WorkDir, state.EventRow{
					Type:      state.EventTaskHeal,
					TaskID:    task.ID,
					TaskTitle: task.Title,
					Step:      s.CurrentStep,
					Message:   fmt.Sprintf("Heal attempt %d/%d for task #%d", healAttempt, maxHealRetries, task.ID),
				}, map[string]any{
					"attempt":    healAttempt,
					"max":        maxHealRetries,
					"variant_id": currentHealVariant.ID,
				})

				diag, diagErr := diagnosis.AnalyzeFailure(ctx, o.provider, s.Model, o.config.StepTimeout, task, taskOutput)
				if diagErr != nil {
					_ = o.queue.MarkFailed(healQueueID, fmt.Sprintf("diagnosis error: %v", diagErr))
					dimColor.Printf("  [HEAL] Diagnosis error — aborting heal: %v\n", diagErr)
					// Audit-trail accuracy: without this annotation, operators
					// see only the diagnosis stdout line — the task's history
					// shows the original failure with no record of why heal
					// stopped trying. Mirrors the clarify-loop annotation
					// shape so log-grepping for "[HEAL" surfaces every outcome.
					pm.AddAnnotation(task, "ai", fmt.Sprintf("[HEAL %d/%d] Aborted — diagnosis error: %v", healAttempt, maxHealRetries, diagErr))
					break
				}
				task.FailureDiagnosis = diag
				pm.AddAnnotation(task, "ai", fmt.Sprintf("[HEAL %d/%d] Diagnosis: %s", healAttempt, maxHealRetries, diag))
				healColor.Printf("[HEAL attempt %d/%d] Diagnosis: %s\n\n", healAttempt, maxHealRetries, truncate(diag, 300))

				// Switch to the next best prompt variant so a different instruction style
				// gets a chance when the current one failed.
				nextVariant := promptopt.NextBestVariant(o.config.WorkDir, task.Role, currentHealVariant.ID)
				if nextVariant.ID != currentHealVariant.ID {
					healColor.Printf("[HEAL attempt %d/%d] Switching prompt variant: %s -> %s (%s)\n",
						healAttempt, maxHealRetries, currentHealVariant.ID, nextVariant.ID, nextVariant.Name)
					pm.AddAnnotation(task, "ai", fmt.Sprintf("[HEAL %d/%d] Prompt variant switched to %s", healAttempt, maxHealRetries, nextVariant.ID))
					currentHealVariant = nextVariant
				}
				// Inject the variant system prompt as prefix for this heal attempt.
				healBasePrompt := prompt
				if vp := currentHealVariant.SystemPrompt; vp != "" {
					healBasePrompt = vp + prompt
				}
				healPrompt := buildHealPrompt(healBasePrompt, diag, healAttempt, maxHealRetries)
				healColor.Printf("[HEAL attempt %d/%d] Re-attempting task %d (variant: %s)...\n", healAttempt, maxHealRetries, task.ID, currentHealVariant.ID)

				healOpts, healWasStreamed := o.makeOpts(s.Model, true)
				healResult, healErr := safeComplete(ctx, taskProvider, healPrompt, healOpts)
				if healErr != nil {
					_ = o.queue.MarkFailed(healQueueID, truncate(healErr.Error(), 200))
					healColor.Printf("[HEAL attempt %d/%d] Provider error: %v\n", healAttempt, maxHealRetries, healErr)
					pm.AddAnnotation(task, "ai", fmt.Sprintf("[HEAL %d/%d] Skipped — provider error: %v", healAttempt, maxHealRetries, healErr))
					continue
				}
				// Empty-output protection: when the heal provider returns
				// (*Result{Output:""}, nil), assigning it to taskOutput would
				// reset signal to TaskInProgress, exit the heal loop (signal !=
				// TaskFailed), skip the clarify check (looksLikeClarificationQuestion("")
				// is false), and fall through to the `default:` arm of the
				// signal switch below — silently marking the previously-failed
				// task DONE with no audit trail of the empty hiccup. Treat
				// empty/nil as the same kind of soft retry as healErr.
				if healResult == nil || strings.TrimSpace(healResult.Output) == "" {
					_ = o.queue.MarkFailed(healQueueID, "provider returned empty output")
					healColor.Printf("[HEAL attempt %d/%d] Provider returned empty output — treating as transient failure\n", healAttempt, maxHealRetries)
					pm.AddAnnotation(task, "ai", fmt.Sprintf("[HEAL %d/%d] Skipped — provider returned empty output", healAttempt, maxHealRetries))
					continue
				}
				if healWasStreamed() {
					fmt.Println()
				} else {
					printOutput(healResult.Output, dimColor, o.config.Verbose)
				}
				taskOutput = healResult.Output

				// Account for tokens used by heal attempts.
				s.TotalInputTokens += healResult.InputTokens
				s.TotalOutputTokens += healResult.OutputTokens

				signal = pm.CheckTaskSignal(taskOutput)
				if signal != pm.TaskFailed {
					_ = o.queue.MarkDone(healQueueID, fmt.Sprintf("healed: signal=%s", signal))
					pm.AddAnnotation(task, "ai", fmt.Sprintf("[HEAL %d/%d] Succeeded — task signal: %s", healAttempt, maxHealRetries, signal))
					healColor.Printf("[HEAL attempt %d/%d] ✓ Task %d healed successfully (signal: %s)\n\n", healAttempt, maxHealRetries, task.ID, signal)
				} else {
					_ = o.queue.MarkFailed(healQueueID, "task still emitted TASK_FAILED")
					pm.AddAnnotation(task, "ai", fmt.Sprintf("[HEAL %d/%d] Still failing — task emitted TASK_FAILED again", healAttempt, maxHealRetries))
					healColor.Printf("[HEAL attempt %d/%d] Task %d still failing — %s\n\n", healAttempt, maxHealRetries, task.ID, truncate(taskOutput, 120))
				}
			}
			// Heal exhaustion: when every attempt was made and the task is
			// still TaskFailed, emit a single summary annotation so operators
			// can grep for "Heal exhausted" without having to count per-attempt
			// "Still failing" lines. Mirrors the clarify-loop's
			// "Clarification auto-resolve exhausted" annotation.
			if signal == pm.TaskFailed && task.HealAttempts >= maxHealRetries {
				pm.AddAnnotation(task, "ai", fmt.Sprintf("[HEAL] Exhausted after %d attempts — task remains failed", maxHealRetries))
			}
		}

		completedAt := time.Now()
		task.CompletedAt = &completedAt
		task.Result = truncate(taskOutput, 500)
		if task.StartedAt != nil {
			task.ActualMinutes = int(completedAt.Sub(*task.StartedAt).Minutes())
		}

		taskDuration := time.Since(*task.StartedAt)
		taskDur := taskDuration.Round(time.Second).String()
		taskDurMs := taskDuration.Milliseconds()

		// Auto-resolve clarification questions: when the LLM asked questions
		// instead of completing the task, re-prompt it to use its best judgment.
		if signal != pm.TaskDone && signal != pm.TaskSkipped && signal != pm.TaskFailed {
			if looksLikeClarificationQuestion(taskOutput) {
				const maxClarifyRetries = 2
				// Track the actual outcome so the audit-trail annotation
				// reflects what happened — not a generic "auto-resolved"
				// claim that misleads when the loop errored, returned
				// empty, or exhausted retries with the LLM still asking.
				clarifyOutcome := fmt.Sprintf("Clarification auto-resolve exhausted: LLM still asked questions after %d attempts.", maxClarifyRetries)
				for clarifyAttempt := 1; clarifyAttempt <= maxClarifyRetries; clarifyAttempt++ {
					if !o.log.IsJSON() {
						color.New(color.FgCyan).Printf("[AUTO-RESOLVE %d/%d] LLM asked questions instead of completing task %d — re-prompting to proceed autonomously\n", clarifyAttempt, maxClarifyRetries, task.ID)
					}
					clarifyPrompt := prompt + "\n\n" +
						"--- PREVIOUS RESPONSE ---\n" + taskOutput + "\n--- END PREVIOUS RESPONSE ---\n\n" +
						"You asked clarification questions instead of completing the task. " +
						"Make your best judgment for ALL decisions and proceed to full completion. " +
						"Do NOT ask for clarification or confirmation. Just do the work and finish with TASK_DONE."
					clarifyOpts, clarifyWasStreamed := o.makeOpts(s.Model, true)
					clarifyResult, clarifyErr := safeComplete(ctx, taskProvider, clarifyPrompt, clarifyOpts)
					if clarifyErr != nil {
						clarifyOutcome = fmt.Sprintf("Clarification auto-resolve aborted on attempt %d/%d: provider error: %v.", clarifyAttempt, maxClarifyRetries, clarifyErr)
						break
					}
					// Empty-output protection: matches the heal-loop guard above.
					// On (*Result{Output:""}, nil) we'd otherwise overwrite a
					// real clarification-asking taskOutput with "", let
					// CheckTaskSignal("") return TaskInProgress, exit this
					// retry loop, and silently fall through to the switch's
					// `default:` arm that marks the task DONE — laundering
					// "the LLM asked questions" into "task complete" via a
					// transient hiccup. Match the existing clarifyErr branch
					// shape (break, preserve the prior taskOutput).
					if clarifyResult == nil || strings.TrimSpace(clarifyResult.Output) == "" {
						clarifyOutcome = fmt.Sprintf("Clarification auto-resolve aborted on attempt %d/%d: provider returned empty output.", clarifyAttempt, maxClarifyRetries)
						break
					}
					if clarifyWasStreamed() {
						fmt.Println()
					} else {
						printOutput(clarifyResult.Output, dimColor, o.config.Verbose)
					}
					taskOutput = clarifyResult.Output
					s.TotalInputTokens += clarifyResult.InputTokens
					s.TotalOutputTokens += clarifyResult.OutputTokens
					signal = pm.CheckTaskSignal(taskOutput)
					if signal == pm.TaskDone || signal == pm.TaskFailed || signal == pm.TaskSkipped || !looksLikeClarificationQuestion(taskOutput) {
						clarifyOutcome = fmt.Sprintf("Clarification auto-resolved on attempt %d/%d — LLM proceeded autonomously.", clarifyAttempt, maxClarifyRetries)
						break
					}
				}
				pm.AddAnnotation(task, "ai", clarifyOutcome)
			}
		}

		// Fail-closed for unanswered clarification questions: if signal is
		// still TaskInProgress (no TASK_* token) and the output still looks
		// like clarification questions, the auto-resolve loop above either
		// wasn't entered, exhausted its retries, or broke out early
		// (clarifyErr / empty result). Without this reroute, the default arm
		// of the switch below would silently mark the task DONE — laundering
		// "the LLM only asked questions" into "task complete".
		clarificationReroute := false
		if signal == pm.TaskInProgress && looksLikeClarificationQuestion(taskOutput) {
			signal = pm.TaskFailed
			clarificationReroute = true
		}

		switch signal {
		case pm.TaskDone:
			// Optionally verify the task was genuinely completed before accepting it.
			if o.config.Verify {
				maxRetries := o.config.MaxVerifyRetries
				if maxRetries <= 0 {
					maxRetries = 2
				}
				dimColor.Printf("  Verifying task %d...\n", task.ID)
				pass, verifyErr := pm.VerifyTask(ctx, o.provider, s.Goal, s.Instructions, s.Model, o.config.StepTimeout, task, taskOutput)
				verifyErrored := false
				if verifyErr != nil {
					dimColor.Printf("  Verification error (treating as pass): %v\n", verifyErr)
					pass = true
					verifyErrored = true
				}
				if !pass {
					task.VerifyRetries++
					if task.VerifyRetries <= maxRetries {
						pm.AddAnnotation(task, "ai", fmt.Sprintf("AI verification failed — re-queuing (attempt %d/%d).", task.VerifyRetries, maxRetries))
						failColor.Printf("✗ Verification FAILED for task %d (%s) — re-queuing (attempt %d/%d)\n\n", task.ID, task.Title, task.VerifyRetries, maxRetries)
						task.Status = pm.TaskPending
						s.Save()
						continue
					}
					failColor.Printf("✗ Verification failed %d time(s) for task %d — marking failed.\n\n", task.VerifyRetries, task.ID)
					pm.AddAnnotation(task, "ai", fmt.Sprintf("AI verification failed %d time(s) — exceeded retry budget, marking task failed.", task.VerifyRetries))
					task.Status = pm.TaskFailed
					{
						done, failed := s.Plan.CountByStatus()
						o.webhook.Send(webhook.EventTaskFailed, webhook.Payload{
							Goal:     s.Goal,
							Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "failed", Duration: taskDur},
							Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
							Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
						})
					}
					consecutiveErrors++
					s.Save()
					if consecutiveErrors >= maxConsecutiveErrors {
						s.Status = "failed"
						s.Save()
						abortErr := fmt.Errorf("%d consecutive task failures", consecutiveErrors)
						o.webhook.Send(webhook.EventSessionFailed, webhook.Payload{
							Goal:    s.Goal,
							Session: &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
							Error:   webhook.TruncateError(abortErr.Error()),
						})
						return abortErr
					}
					continue
				}
				if verifyErrored {
					pm.AddAnnotation(task, "ai", fmt.Sprintf("AI verification errored — treated as pass: %v", verifyErr))
				} else {
					pm.AddAnnotation(task, "ai", "AI verification passed: task was genuinely completed.")
				}
				pmColor.Printf("✓ Verification PASSED for task %d: %s\n\n", task.ID, task.Title)
			}

			// Script-verify: generate and run a shell verification script to confirm
			// the task was genuinely accomplished beyond the AI's own claim.
			scriptVerifyFailed := false
			if o.config.ScriptVerify {
				dimColor.Printf("  Running shell verification for task %d...\n", task.ID)
				vr, svErr := verify.GenerateAndRun(ctx, o.provider, s.Model, o.config.StepTimeout, o.config.WorkDir, task, taskOutput)
				if svErr != nil {
					dimColor.Printf("  Script verification error (treating as pass): %v\n", svErr)
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Shell verification errored — treated as pass: %v", svErr))
				} else {
					// Persist script + result as artifact regardless of outcome.
					if artPath, artErr := artifact.WriteVerificationArtifact(o.config.WorkDir, task, vr.Script, vr.Output, vr.Passed); artErr != nil {
						dimColor.Printf("  verification artifact write error (ignored): %v\n", artErr)
					} else {
						dimColor.Printf("  verification artifact: %s\n", artPath)
					}
					if !vr.Passed {
						scriptVerifyFailed = true
						failColor.Printf("✗ Shell verification FAILED for task %d (%s)\n", task.ID, task.Title)
						if vr.Output != "" {
							failColor.Printf("  Script output:\n%s\n\n", vr.Output)
						}
						pm.AddAnnotation(task, "ai", "Shell verification reported failure — marking task failed.")
						task.Status = pm.TaskFailed
						// Trigger failure diagnosis so retry prompts can learn from the failure.
						if o.config.DiagnoseFailures {
							dimColor.Printf("  Diagnosing script-verify failure for task %d...\n", task.ID)
							diagInput := "Shell verification script exited non-zero.\n\nScript output:\n" + vr.Output + "\n\nTask output:\n" + taskOutput
							diag, diagErr := diagnosis.AnalyzeFailure(ctx, o.provider, s.Model, o.config.StepTimeout, task, diagInput)
							if diagErr != nil {
								dimColor.Printf("  Diagnosis error (ignored): %v\n", diagErr)
							} else if diag != "" {
								task.FailureDiagnosis = diag
								pm.AddAnnotation(task, "ai", fmt.Sprintf("Failure diagnosis: %s", diag))
								dimColor.Printf("  Diagnosis: %s\n\n", diag)
							}
						}
						{
							done, failed := s.Plan.CountByStatus()
							o.webhook.Send(webhook.EventTaskFailed, webhook.Payload{
								Goal:     s.Goal,
								Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "failed", Duration: taskDur},
								Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
								Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
							})
						}
						consecutiveErrors++
						s.Save()
						// Mirror the verify-failure path above (line ~1923) and the
						// task-failed path below (line ~2117): script-verify failures
						// must also trip MaxFailures, otherwise consecutive flaky or
						// genuinely-broken script-verify runs would burn budget without
						// the loop ever aborting.
						if consecutiveErrors >= maxConsecutiveErrors {
							s.Status = "failed"
							s.Save()
							abortErr := fmt.Errorf("%d consecutive task failures", consecutiveErrors)
							o.webhook.Send(webhook.EventSessionFailed, webhook.Payload{
								Goal:    s.Goal,
								Session: &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
								Error:   webhook.TruncateError(abortErr.Error()),
							})
							return abortErr
						}
					} else {
						pmColor.Printf("✓ Shell verification PASSED for task %d: %s\n\n", task.ID, task.Title)
					}
				}
			}

			if !scriptVerifyFailed {
				task.Status = pm.TaskDone
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task completed successfully in %s.", taskDur))
				if !o.log.IsJSON() {
					successColor.Printf("✓ Task %d complete: %s\n\n", task.ID, task.Title)
				}
				o.log.Info(logger.EventTaskDone, task.ID, task.Title, map[string]interface{}{
					"duration_ms": taskDurMs,
					"request_id":  taskRequestID,
				})
				if o.config.Notify {
					notify.Send("cloop: Task Done", task.Title)
				}
				o.notifyWebhooks("cloop: Task Done", fmt.Sprintf("Task #%d: %s\nGoal: %s\nElapsed: %s", task.ID, task.Title, s.Goal, taskDur))
				{
					done, failed := s.Plan.CountByStatus()
					o.webhook.Send(webhook.EventTaskDone, webhook.Payload{
						Goal:     s.Goal,
						Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "done", Duration: taskDur},
						Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
						Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					})
				}
				consecutiveErrors = 0
			}
		case pm.TaskSkipped:
			task.Status = pm.TaskSkipped
			pm.AddAnnotation(task, "ai", fmt.Sprintf("Task skipped per AI TASK_SKIPPED signal after %s.", taskDur))
			if !o.log.IsJSON() {
				dimColor.Printf("→ Task %d skipped: %s\n\n", task.ID, task.Title)
			}
			o.log.Info(logger.EventTaskSkipped, task.ID, task.Title, nil)
			{
				done, failed := s.Plan.CountByStatus()
				o.webhook.Send(webhook.EventTaskSkipped, webhook.Payload{
					Goal:     s.Goal,
					Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "skipped"},
					Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
					Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
				})
			}
			consecutiveErrors = 0
		case pm.TaskFailed:
			task.Status = pm.TaskFailed
			task.FailCount++
			// Skip the explicit-signal annotation when the failure came from the
			// clarification reroute above — the auto-resolve loop's outcome
			// annotation (line ~1993) already captures the real root cause, and
			// claiming "per AI TASK_FAILED signal" would misattribute it.
			if !clarificationReroute {
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed per AI TASK_FAILED signal after %s.", taskDur))
			}
			if !o.log.IsJSON() {
				failColor.Printf("✗ Task %d failed: %s\n\n", task.ID, task.Title)
			}
			o.log.Error(logger.EventTaskFailed, task.ID, task.Title, map[string]interface{}{
				"duration_ms": taskDurMs,
				"fail_count":  task.FailCount,
				"request_id":  taskRequestID,
			})
			{
				done, failed := s.Plan.CountByStatus()
				o.webhook.Send(webhook.EventTaskFailed, webhook.Payload{
					Goal:     s.Goal,
					Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "failed", Duration: taskDur},
					Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
					Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
				})
			}
			if o.config.Notify {
				notify.Send("cloop: Task Failed", task.Title)
			}
			o.notifyWebhooks("cloop: Task Failed", fmt.Sprintf("Task #%d: %s\nGoal: %s\nElapsed: %s", task.ID, task.Title, s.Goal, taskDur))
			consecutiveErrors++

			// AI failure diagnosis: analyze what went wrong and store it on the task.
			// This runs before adaptive replan so the diagnosis can inform replanning too.
			if o.config.DiagnoseFailures {
				dimColor.Printf("  Diagnosing failure for task %d...\n", task.ID)
				diag, diagErr := diagnosis.AnalyzeFailure(ctx, o.provider, s.Model, o.config.StepTimeout, task, taskOutput)
				if diagErr != nil {
					dimColor.Printf("  Diagnosis error (ignored): %v\n", diagErr)
				} else if diag != "" {
					task.FailureDiagnosis = diag
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Failure diagnosis: %s", diag))
					dimColor.Printf("  Diagnosis: %s\n\n", truncate(diag, 200))
				}
				s.Save()
			}

			// Auto-split: if a task has failed 2+ times, decompose it into smaller subtasks.
			if o.config.AutoSplit && task.FailCount >= 2 {
				pmColor.Printf("Auto-split: task %d has failed %d times — decomposing into subtasks...\n", task.ID, task.FailCount)
				splitReason := fmt.Sprintf("Task failed %d times. Last failure output:\n%s", task.FailCount, truncate(taskOutput, 400))
				splitOpts := provider.Options{
					Model:   s.Model,
					Timeout: o.config.StepTimeout,
				}
				subtasks, splitErr := pm.SplitTask(ctx, o.provider, splitOpts, s.Plan, task.ID, splitReason)
				if splitErr != nil {
					dimColor.Printf("  Auto-split error (ignored): %v\n", splitErr)
				} else if len(subtasks) > 0 {
					pmColor.Printf("  Split into %d subtasks. Continuing plan...\n\n", len(subtasks))
					consecutiveErrors = 0
					// SaveDirect: SplitTask removes the original task; plain Save would
					// re-merge it from disk and undo the split.
					s.SaveDirect()
					continue
				}
			}

			// Adaptive replanning: re-think remaining tasks on failure.
			if o.config.AdaptiveReplan {
				pmColor.Printf("Adaptive replan: re-thinking remaining tasks after failure...\n")
				failureReason := truncate(taskOutput, 400)
				newTasks, replanErr := pm.AdaptiveReplan(ctx, o.provider, s.Goal, s.Instructions, s.Model, o.config.StepTimeout, s.Plan, task, failureReason)
				if replanErr != nil {
					failColor.Printf("  Replan failed: %v — continuing with existing plan.\n\n", replanErr)
				} else if len(newTasks) > 0 {
					// Replace remaining pending tasks with replanned tasks.
					kept := []*pm.Task{}
					for _, t := range s.Plan.Tasks {
						if t.Status != pm.TaskPending {
							kept = append(kept, t)
						}
					}
					s.Plan.Tasks = append(kept, newTasks...)
					pmColor.Printf("  Replanned: added %d revised task(s).\n\n", len(newTasks))
					consecutiveErrors = 0 // reset after successful replan
					// SaveDirect: AdaptiveReplan drops pending tasks and replaces them
					// with new ones; plain Save would re-merge the dropped pendings from disk.
					s.SaveDirect()
					continue
				} else {
					pmColor.Printf("  Replan: no new tasks — plan is complete or blocked.\n\n")
				}
			}

			if consecutiveErrors >= maxConsecutiveErrors {
				s.Status = "failed"
				s.Save()
				abortErr := fmt.Errorf("%d consecutive task failures", consecutiveErrors)
				o.webhook.Send(webhook.EventSessionFailed, webhook.Payload{
					Goal:    s.Goal,
					Session: &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					Error:   webhook.TruncateError(abortErr.Error()),
				})
				return abortErr
			}
		default:
			// No signal found — treat as done (AI finished without explicit signal)
			task.Status = pm.TaskDone
			pm.AddAnnotation(task, "ai", "Task implicitly completed: AI finished without an explicit TASK_DONE/TASK_FAILED/TASK_SKIPPED signal — treated as done.")
			if !o.log.IsJSON() {
				successColor.Printf("✓ Task %d complete (no explicit signal): %s\n\n", task.ID, task.Title)
			}
			o.log.Info(logger.EventTaskDone, task.ID, task.Title, map[string]interface{}{
				"duration_ms": taskDurMs,
				"implicit":    true,
			})
			if o.config.Notify {
				notify.Send("cloop: Task Done", task.Title)
			}
			o.notifyWebhooks("cloop: Task Done", fmt.Sprintf("Task #%d: %s\nGoal: %s\nElapsed: %s", task.ID, task.Title, s.Goal, taskDur))
			{
				done, failed := s.Plan.CountByStatus()
				o.webhook.Send(webhook.EventTaskDone, webhook.Payload{
					Goal:     s.Goal,
					Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "done", Duration: taskDur},
					Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
					Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
				})
			}
			consecutiveErrors = 0
		}

		// Central queue: mark this work item terminal. The status mirrors the
		// pm.Task status so the queue stays consistent with the plan.
		switch task.Status {
		case pm.TaskDone:
			_ = o.queue.MarkDone(queueID, stepSummaryLine(taskOutput, 200))
		case pm.TaskFailed:
			_ = o.queue.MarkFailed(queueID, stepSummaryLine(taskOutput, 200))
		case pm.TaskSkipped:
			_ = o.queue.MarkSkipped(queueID, "AI emitted TASK_SKIPPED")
		default:
			// Implicit-done / timed-out / other terminal states record as done
			// to match the plan-task accounting above.
			_ = o.queue.MarkDone(queueID, stepSummaryLine(taskOutput, 200))
		}

		// Unified event journal — one terminal event per task outcome (Task 20118).
		o.logTaskOutcomeEvent(task, taskDur, s.CurrentStep)

		// Record task outcome into metrics.
		if o.metrics != nil && task.StartedAt != nil {
			durSecs := time.Since(*task.StartedAt).Seconds()
			switch task.Status {
			case pm.TaskDone:
				o.metrics.RecordTaskCompleted(durSecs)
			case pm.TaskFailed:
				o.metrics.RecordTaskFailed(durSecs)
			case pm.TaskSkipped:
				o.metrics.RecordTaskSkipped()
			}
		}

		// Record task cost to ledger.
		{
			usd, _ := cost.Estimate(strings.ToLower(taskModelName), taskInputTokens, taskOutputTokens)
			entry := cost.LedgerEntry{
				TaskID:         task.ID,
				TaskTitle:      task.Title,
				Provider:       taskProviderName,
				Model:          taskModelName,
				InputTokens:    taskInputTokens,
				OutputTokens:   taskOutputTokens,
				ThinkingTokens: taskThinkingTokens,
				EstimatedUSD:   usd,
			}
			if lErr := cost.AppendLedger(o.config.WorkDir, entry); lErr != nil {
				dimColor.Printf("  cost ledger write error (ignored): %v\n", lErr)
			}
		}

		// Record prompt outcome for adaptive hint learning.
		{
			outcomeStr := strings.ToLower(string(task.Status))
			durMs := duration.Milliseconds()
			rec := promptstats.Record{
				TaskTitle:  task.Title,
				PromptHash: promptstats.HashPrompt(prompt),
				Outcome:    outcomeStr,
				DurationMs: durMs,
			}
			if psErr := promptstats.Append(o.config.WorkDir, rec); psErr != nil {
				dimColor.Printf("  prompt-stats write error (ignored): %v\n", psErr)
			}
			// Record outcome for A/B variant testing.
			success := task.Status == pm.TaskDone || task.Status == pm.TaskSkipped
			if optErr := promptopt.RecordOutcome(o.config.WorkDir, activeVariant.ID, success, int(durMs)); optErr != nil {
				dimColor.Printf("  prompt-opt write error (ignored): %v\n", optErr)
			}
		}

		// Persist full AI response as a Markdown artifact file.
		o.writeTaskArtifact(task, taskOutput)
		// If consensus was used, append the decision report to the artifact.
		if consensusReport != nil {
			o.appendConsensusReport(task, consensusReport)
		}

		// Chain pipeline: propagate this task's output to downstream chained tasks.
		o.injectChainOutput(s.Plan, task, taskOutput)

		// Save a history entry for the task completion before clearing the checkpoint.
		{
			var elapsedSec float64
			if task.StartedAt != nil {
				elapsedSec = time.Since(*task.StartedAt).Seconds()
			}
			event := "complete"
			switch task.Status {
			case pm.TaskFailed:
				event = "fail"
			case pm.TaskSkipped:
				event = "skip"
			}
			doneCP := &checkpoint.Checkpoint{
				TaskID:     task.ID,
				TaskTitle:  task.Title,
				Event:      event,
				Status:     string(task.Status),
				Timestamp:  time.Now(),
				Provider:   o.provider.Name(),
				TokenCount: s.TotalInputTokens + s.TotalOutputTokens,
				ElapsedSec: elapsedSec,
			}
			if taskOutput != "" {
				doneCP.AccumulatedOutput = taskOutput
				doneCP.OutputHash = checkpoint.HashOutput(taskOutput)
				doneCP.OutputLength = len(taskOutput)
			}
			if hErr := checkpoint.SaveHistoryEntry(o.config.WorkDir, doneCP); hErr != nil {
				dimColor.Printf("  checkpoint history write error (ignored): %v\n", hErr)
			}
		}

		// Task completed (done/skipped/failed) — clear the mid-execution checkpoint.
		if cpClearErr := checkpoint.Clear(o.config.WorkDir); cpClearErr != nil {
			dimColor.Printf("  checkpoint clear error (ignored): %v\n", cpClearErr)
		}

		// Git mode: commit and merge on success; leave branch open on failure.
		if o.config.GitMode && gitTaskBranch != "" {
			switch task.Status {
			case pm.TaskDone, pm.TaskSkipped:
				if commitErr := cloopgit.CommitTaskArtifacts(o.config.WorkDir, task); commitErr != nil {
					dimColor.Printf("  git commit error (ignored): %v\n", commitErr)
				} else if mergeErr := cloopgit.MergeBranch(o.config.WorkDir, gitOriginalBranch, gitTaskBranch); mergeErr != nil {
					dimColor.Printf("  git merge error (ignored): %v\n", mergeErr)
				} else {
					dimColor.Printf("  git: merged %s → %s\n", gitTaskBranch, gitOriginalBranch)
				}
			case pm.TaskFailed:
				dimColor.Printf("  git: leaving branch %s open for inspection (task failed)\n", gitTaskBranch)
				// Return to original branch so the next task can start from it.
				if checkoutErr := cloopgit.CheckoutBranch(o.config.WorkDir, gitOriginalBranch); checkoutErr != nil {
					dimColor.Printf("  git checkout original branch error (ignored): %v\n", checkoutErr)
				}
			}
		}

		// Post-task AI code review: run on successful tasks when enabled.
		if (o.config.PostReview || o.config.Hooks.PostTaskReview) && task.Status == pm.TaskDone {
			reviewDiff, diffErr := review.GetDiff(o.config.WorkDir)
			if diffErr != nil {
				dimColor.Printf("  post-review: git diff error (ignored): %v\n", diffErr)
			} else {
				dimColor.Printf("  Running post-task AI code review...\n")
				reviewText, reviewErr := review.ReviewDiff(ctx, o.provider, s.Model, o.config.StepTimeout, reviewDiff, task.Title)
				if reviewErr != nil {
					dimColor.Printf("  post-review error (ignored): %v\n", reviewErr)
				} else {
					verdict := review.ExtractVerdict(reviewText)
					verdictColor := successColor
					if verdict == review.VerdictFail {
						verdictColor = failColor
					}
					verdictColor.Printf("  Code review verdict: %s\n", verdict)
					// Truncate annotation text if very long.
					annotText := reviewText
					if len(annotText) > 2000 {
						annotText = annotText[:2000] + "\n...(truncated)"
					}
					pm.AddAnnotation(task, review.Author, fmt.Sprintf("[%s] %s", verdict, annotText))
					s.Save()
				}
			}
		}

		// Auto-eval: score task output against default rubric after successful completion.
		if o.config.AutoEval && task.Status == pm.TaskDone {
			evalOutput := task.Result
			if task.ArtifactPath != "" {
				if data, readErr := os.ReadFile(task.ArtifactPath); readErr == nil {
					evalOutput = string(data)
				}
			}
			if evalOutput != "" {
				dimColor.Printf("  Running post-task quality evaluation...\n")
				evalResult, evalErr := eval.Evaluate(ctx, o.provider, s.Model, o.config.StepTimeout, o.config.WorkDir, task, evalOutput, eval.DefaultRubric())
				if evalErr != nil {
					dimColor.Printf("  eval error (ignored): %v\n", evalErr)
				} else {
					scoreColor := successColor
					if evalResult.Weighted < 5 {
						scoreColor = failColor
					} else if evalResult.Weighted < 7 {
						scoreColor = color.New(color.FgYellow, color.Bold)
					}
					scoreColor.Printf("  Eval score: %.2f/10 (saved to .cloop/evals/%d.json)\n", evalResult.Weighted, task.ID)
				}
			}
		}

		// Post-task hook: always run regardless of task outcome.
		if hookErr := hooks.RunPostTask(o.config.Hooks, hooks.TaskContext{
			ID:     task.ID,
			Title:  task.Title,
			Status: string(task.Status),
			Role:   string(task.Role),
		}, o.allEnvLines()...); hookErr != nil {
			dimColor.Printf("  post_task hook error (ignored): %v\n", hookErr)
		}

		// Alert rule evaluation: check thresholds after each task completion.
		o.evaluateAlerts(s, task)

		// Conditional branching: activate the matching branch, skip the other.
		if activations := pm.ResolveBranch(s.Plan, task); len(activations) > 0 {
			branchColor := color.New(color.FgCyan)
			for _, a := range activations {
				if a.Activated {
					branchColor.Printf("  branch [%s] activated  -> task %d: %s\n", a.Branch, a.TaskID, a.Title)
				} else {
					color.New(color.Faint).Printf("  branch [%s] skipped    -> task %d: %s\n", a.Branch, a.TaskID, a.Title)
				}
			}
		}

		s.Save()

		if o.config.StepDelay > 0 {
			select {
			case <-ctx.Done():
				s.Status = "paused"
				s.Save()
				return ctx.Err()
			case <-time.After(o.config.StepDelay):
			}
		}
	}

	s.Status = "paused"
	s.Save()

	// Distil cross-session learnings into .cloop/memory.md after the plan completes.
	o.distillLearnings(ctx, s.Plan)

	return nil
}

// reviewTask prompts the user to approve, skip, or quit before executing a task.
// Returns "yes", "no", "skip", or "quit".
func reviewTask(task *pm.Task) string {
	reviewColor := color.New(color.FgCyan)
	reviewColor.Printf("Review: Task %d [P%d] — %s\n", task.ID, task.Priority, task.Title)
	if task.Description != "" {
		color.New(color.Faint).Printf("  %s\n", truncate(task.Description, 200))
	}
	fmt.Printf("Execute this task? [y]es / [n]o (pause) / [s]kip / [q]uit: ")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
		switch answer {
		case "y", "yes", "":
			return "yes"
		case "n", "no":
			return "no"
		case "s", "skip":
			return "skip"
		case "q", "quit":
			return "quit"
		}
		fmt.Printf("Please enter y, n, s, or q: ")
	}
	return "quit" // EOF or error
}

// recoverStaleTasks resets any tasks left in `in_progress` from a prior crashed
// or killed run back to `pending` so they re-enter the scheduling pool. Without
// this, NextTask() (which only returns pending tasks) would skip them forever
// and any dependent tasks would stay blocked.
//
// Used by the parallel runner — the sequential runner does its own interactive
// stale-checkpoint prompt earlier in runPMSequential.
func (o *Orchestrator) recoverStaleTasks(s *state.ProjectState) {
	if s == nil || s.Plan == nil {
		return
	}
	recovered := 0
	for _, t := range s.Plan.Tasks {
		if t == nil {
			continue
		}
		if t.Status == pm.TaskInProgress {
			t.Status = pm.TaskPending
			t.StartedAt = nil
			pm.AddAnnotation(t, "ai", "Task reset to pending: previous run was interrupted while this task was in_progress (parallel-mode stale-task recovery).")
			recovered++
		}
	}
	if recovered > 0 {
		// Drop any stale checkpoint pointing at a task we just reset.
		_ = checkpoint.Clear(o.config.WorkDir)
		if err := s.Save(); err != nil {
			color.New(color.Faint).Printf("(stale-task recovery save failed: %v)\n", err)
			return
		}
		color.New(color.Faint).Printf("Recovered %d in-progress task(s) from prior run.\n", recovered)
	}

	// Also recover stale queue entries left in "running" from a prior crash.
	o.recoverStaleQueueEntries()
}

// recoverStaleQueueEntries marks any queue entries stuck in "running" as failed,
// since the process that was executing them no longer exists.
func (o *Orchestrator) recoverStaleQueueEntries() {
	if o == nil || o.queue == nil {
		return
	}
	entries, err := o.queue.List(taskqueue.ListOptions{Status: taskqueue.StatusRunning, Limit: 500})
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = o.queue.MarkFailed(e.ID, "interrupted: previous run was killed or crashed")
	}
	if len(entries) > 0 {
		color.New(color.Faint).Printf("Recovered %d stale queue entries from prior run.\n", len(entries))
	}
}

// taskResult holds the output of a single parallel task execution.
type taskResult struct {
	task        *pm.Task
	result      *provider.Result
	err         error
	duration    time.Duration
	bufferedOut string
	timedOut    bool   // true when the task's per-task budget was exceeded
	partialOut  string // partial output captured before timeout
}

// parallelShutdownGracePeriod bounds how long runPMParallel will wait for
// in-flight task goroutines to exit after the parent context is cancelled.
// Workers' per-task contexts are derived from the parent, so a well-behaved
// provider should return promptly on cancellation. This watchdog defends
// against a misbehaving provider that ignores ctx.Done() and would otherwise
// block wg.Wait() (and thus the orchestrator) indefinitely. Declared as var
// so tests can shrink it.
var parallelShutdownGracePeriod = 30 * time.Second

// runPMParallel runs all dependency-ready tasks concurrently in each round,
// then waits for them to complete before starting the next round.
func (o *Orchestrator) runPMParallel(ctx context.Context) error {
	s := o.state
	s.Status = "running"
	if err := s.Save(); err != nil {
		return err
	}

	sessionStart := time.Now()
	startStep := s.CurrentStep
	defer func() { printSessionSummary(sessionStart, startStep, s) }()

	header := color.New(color.FgCyan, color.Bold)
	successColor := color.New(color.FgGreen, color.Bold)
	failColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)
	pmColor := color.New(color.FgMagenta, color.Bold)
	stepColor := color.New(color.FgYellow, color.Bold)

	header.Printf("\n🧠 cloop PM — AI Product Manager Mode (parallel)\n")
	fmt.Printf("   Provider: %s\n", o.provider.Name())
	fmt.Printf("   Goal: %s\n", s.Goal)
	fmt.Println()

	// Worktree-parallel mode: each task runs in an isolated git worktree under
	// .cloop/worktrees/task-<id>/ and its changes are merged back to the base
	// branch through a serialized merge queue. Disabled silently when WorkDir
	// is not a git repo so non-git projects still work in parallel mode.
	var (
		mergeQ          *mergequeue.Queue
		worktreeMode    bool
		worktreeBase    string
		activeWorktrees = map[int]*worktree.Worktree{}
		worktreeMu      sync.Mutex
	)
	if o.config.WorktreeParallel {
		if !worktree.IsGitRepo(o.config.WorkDir) {
			dimColor.Printf("  worktree-parallel: %q is not a git repo — falling back to shared workdir.\n", o.config.WorkDir)
		} else {
			base, baseErr := cloopgit.CurrentBranch(o.config.WorkDir)
			if baseErr != nil {
				dimColor.Printf("  worktree-parallel: cannot resolve base branch (%v) — falling back to shared workdir.\n", baseErr)
			} else {
				worktreeMode = true
				worktreeBase = base
				mergeQ = mergequeue.New(o.config.WorkDir, worktreeBase)
				// Install an AI-driven conflict resolver so merges that would
				// otherwise leave a branch in manual-resolution limbo can
				// proceed automatically. We use the orchestrator's main
				// provider/model; the resolver itself imposes per-file caps
				// and rejects unsafe AI output (Task 20141).
				if o.provider != nil {
					mergeQ.SetResolver(mergeresolve.New(o.provider, s.Model, 0))
					dimColor.Printf("  worktree-parallel: AI conflict resolver enabled (%s)\n", o.provider.Name())
				}
				mergeQ.Start(ctx)
				dimColor.Printf("  worktree-parallel: ON (base=%s, merge queue running)\n", worktreeBase)
				defer func() {
					// Drain the merge queue before tearing down any remaining
					// worktrees so in-flight merges always see their source
					// branch's working dir on disk.
					mergeQ.Stop()
					worktreeMu.Lock()
					for _, w := range activeWorktrees {
						_ = w.Remove(o.config.WorkDir)
					}
					activeWorktrees = nil
					worktreeMu.Unlock()
				}()
			}
		}
	}

	// Replan / decompose phase (same as sequential).
	if o.config.Replan && s.Plan != nil {
		pmColor.Printf("Replanning: clearing existing plan (%d tasks) and re-decomposing.\n\n", len(s.Plan.Tasks))
		s.Plan = nil
		s.Save()
	}

	if s.Plan == nil || len(s.Plan.Tasks) == 0 {
		// Run interactive goal clarification when stdin is a TTY and not skipped.
		// If clarification was already performed at 'cloop init' time, load from disk.
		var clarifyCtx string
		if !o.config.SkipClarify {
			if existing, loadErr := clarify.Load(o.config.WorkDir); loadErr == nil && len(existing) > 0 {
				clarifyCtx = clarify.BuildContext(existing)
				color.New(color.Faint).Printf("(Using goal clarification from previous session)\n\n")
			} else if clarify.IsTTY() {
				scanner := bufio.NewScanner(os.Stdin)
				qas, clarifyErr := clarify.Run(ctx, o.provider, s.Model, o.config.StepTimeout, s.Goal, s.Instructions, o.config.WorkDir, scanner)
				if clarifyErr != nil {
					color.New(color.Faint).Printf("(Clarification skipped: %v)\n\n", clarifyErr)
				} else {
					clarifyCtx = clarify.BuildContext(qas)
				}
			}
		}

		pmColor.Printf("Decomposing goal into tasks...\n")
		plan, err := pm.Decompose(ctx, o.provider, s.Goal, s.Instructions, s.Model, o.config.StepTimeout, clarifyCtx)
		if err != nil {
			failColor.Printf("x Failed to decompose goal: %v\n", err)
			s.Status = "failed"
			s.Save()
			return err
		}
		if o.config.CalibrationFactor != 0 && o.config.CalibrationFactor != 1.0 {
			pm.ApplyCalibrationFactor(plan, o.config.CalibrationFactor)
		}
		s.Plan = plan
		s.Save()
		fmt.Printf("\n")
		pmColor.Printf("Task Plan (%d tasks):\n", len(plan.Tasks))
		for _, t := range plan.Tasks {
			fmt.Printf("  %d. [P%d] %s\n", t.ID, t.Priority, t.Title)
			dimColor.Printf("       %s\n", truncate(t.Description, 120))
		}
		fmt.Println()
	} else {
		if o.config.RetryFailed {
			retried := 0
			for _, t := range s.Plan.Tasks {
				if t.Status == pm.TaskFailed {
					t.Status = pm.TaskPending
					retried++
				}
			}
			if retried > 0 {
				pmColor.Printf("Retrying %d failed task(s).\n\n", retried)
				s.Save()
			}
		}
		pmColor.Printf("Resuming plan: %s\n\n", s.Plan.Summary())
	}

	// Optimization pass (parallel mode).
	if o.config.Optimize && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		o.runOptimizer(ctx, s, pmColor, dimColor)
	}

	if o.config.PlanOnly {
		s.Status = "paused"
		s.Save()
		return nil
	}

	// Recover any tasks left in_progress from a prior crashed/killed run before
	// scheduling work, so their slots in the dependency graph free up.
	o.recoverStaleTasks(s)

	consecutiveErrors := 0
	maxConsecutiveErrors := o.config.MaxFailures
	if maxConsecutiveErrors <= 0 {
		maxConsecutiveErrors = 3
	}

	// Auto-evolve safety net: if N consecutive evolve attempts add no new tasks
	// AND no explicit abort condition (token/step budget) is configured, stop
	// rather than spin forever burning tokens. When the user has set a budget,
	// the budget itself is the abort condition and we keep evolving until it
	// trips, regardless of how many empty evolves occur — that is the intended
	// behaviour for long-running auto-evolve sessions.
	consecutiveEmptyEvolves := 0
	const maxEmptyEvolves = 3

	var mu sync.Mutex

	for {
		select {
		case <-ctx.Done():
			s.Status = "paused"
			s.Save()
			return ctx.Err()
		default:
		}

		if o.config.StepsLimit > 0 && s.CurrentStep >= startStep+o.config.StepsLimit {
			color.New(color.FgYellow).Printf("⏸ Reached --steps limit (%d). Run 'cloop run' to continue.\n", o.config.StepsLimit)
			s.Status = "paused"
			s.Save()
			return nil
		}

		// Token budget check at the top of the loop so it fires during evolve cycles
		// (where the work-execution path's check would otherwise be skipped).
		if o.config.TokenBudget > 0 && s.TotalInputTokens+s.TotalOutputTokens >= o.config.TokenBudget {
			color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
			s.Status = "paused"
			s.Save()
			return nil
		}

		// Snapshot in-memory task IDs before SyncFromDisk so we can detect any
		// externally-added tasks that landed since the last iteration and record
		// them as KindExternal queue entries — this is the only place an
		// externally-added task gets surfaced into the central activity log.
		preMergeIDs := make(map[int]struct{}, len(s.Plan.Tasks))
		for _, t := range s.Plan.Tasks {
			preMergeIDs[t.ID] = struct{}{}
		}
		s.SyncFromDisk()
		for _, t := range s.Plan.Tasks {
			if _, existed := preMergeIDs[t.ID]; existed {
				continue
			}
			extID := o.enqueueWork(taskqueue.Entry{
				Kind:        taskqueue.KindExternal,
				TaskID:      t.ID,
				Title:       fmt.Sprintf("External task added: %s", t.Title),
				Description: truncate(t.Description, 300),
				Source:      "external",
			})
			_ = o.queue.MarkDone(extID, fmt.Sprintf("merged from disk (status=%s)", t.Status))
		}
		// Reactivate recurring tasks whose schedule has fired.
		for _, t := range s.Plan.Tasks {
			if pm.ResetIfDue(t, time.Now()) {
				dimColor.Printf("↺ Task %d recurring: reset to pending (%s)\n", t.ID, t.Recurrence)
				s.Save()
			}
		}
		// Mid-run mode switch: if the user disabled parallel mode (and lowered
		// max_parallel back to ≤1) via the Web UI, surrender so runPM can
		// re-dispatch into runPMSequential without a process restart
		// (Task 20111). Safe at the top of the loop with no batch in flight.
		// CLI flag wins — if --parallel was passed, stay parallel.
		if !o.config.Parallel && !o.wantParallel() {
			return errSwitchMode
		}
		if s.Plan.IsComplete() {
			if s.AutoEvolve {
				successColor.Printf("🎉 All tasks complete! Auto-evolve enabled — discovering more work.\n")
			} else {
				successColor.Printf("🎉 All tasks complete! Goal achieved.\n")
			}
			successColor.Printf("   %s\n\n", s.Plan.Summary())
			if o.config.Notify {
				notify.Send("cloop: All Tasks Complete", s.Goal)
			}
			o.notifyWebhooks("cloop: Plan Complete", fmt.Sprintf("Goal: %s\n%s", s.Goal, s.Plan.Summary()))
			if o.metrics != nil {
				if err := o.metrics.WriteJSON(o.config.WorkDir); err != nil {
					dimColor.Printf("  metrics write error (ignored): %v\n", err)
				}
			}
			{
				done, failed := s.Plan.CountByStatus()
				o.webhook.Send(webhook.EventPlanComplete, webhook.Payload{
					Goal:     s.Goal,
					Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
					Session: &webhook.SessionInfo{
						TotalTasks:   len(s.Plan.Tasks),
						DoneTasks:    done,
						FailedTasks:  failed,
						InputTokens:  s.TotalInputTokens,
						OutputTokens: s.TotalOutputTokens,
					},
				})
			}
			if s.AutoEvolve {
				s.Status = "evolving"
				s.Save()
				n, err := o.evolvePM(ctx)
				if err != nil {
					color.New(color.FgMagenta, color.Bold).Printf("\n⏹ Evolve stopped: %v\n", err)
					s.Status = "complete"
					s.Save()
					return nil
				}
				if n == 0 {
					consecutiveEmptyEvolves++
					// When the user has configured a budget abort condition
					// (token or step limit), keep evolving — that condition
					// will eventually trip and terminate the loop. Without a
					// budget, fall back to the empty-evolves cap so we don't
					// spin forever burning tokens.
					hasBudget := o.config.TokenBudget > 0 || o.config.StepsLimit > 0
					if !hasBudget && consecutiveEmptyEvolves >= maxEmptyEvolves {
						color.New(color.FgYellow).Printf("⏸ Auto-evolve found no new tasks in %d consecutive attempts and no token/step budget is set. Stopping.\n", maxEmptyEvolves)
						s.Status = "complete"
						s.Save()
						return nil
					}
					if hasBudget {
						dimColor.Printf("  Auto-evolve: 0 new tasks (attempt %d). Continuing — abort controlled by configured budget.\n", consecutiveEmptyEvolves)
					} else {
						dimColor.Printf("  Auto-evolve: 0 new tasks (%d/%d). Retrying...\n", consecutiveEmptyEvolves, maxEmptyEvolves)
					}
					s.Status = "running"
					continue
				}
				consecutiveEmptyEvolves = 0
				s.Status = "running"
				continue
			}
			s.Status = "complete"
			s.Save()
			return nil
		}

		// Auto-skip permanently blocked tasks.
		skipped := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskPending && s.Plan.PermanentlyBlocked(t) {
				failColor.Printf("⊘ Task %d skipped (blocked by failed dependency): %s\n", t.ID, t.Title)
				t.Status = pm.TaskSkipped
				pm.AddAnnotation(t, "ai", "Task skipped: permanently blocked by failed dependency (parallel mode).")
				skipped++
			}
		}
		if skipped > 0 {
			s.Save()
			continue
		}

		ready := s.Plan.ReadyTasks()
		if len(ready) == 0 {
			break
		}

		// Tag filter: skip tasks that don't match any of the requested tags.
		if len(o.config.TagFilter) > 0 {
			filtered := ready[:0]
			for _, t := range ready {
				if pm.TaskMatchesTags(t, o.config.TagFilter) {
					filtered = append(filtered, t)
				} else {
					color.New(color.Faint).Printf("⊘ Task %d skipped (no matching tag): %s\n", t.ID, t.Title)
					t.Status = pm.TaskSkipped
					pm.AddAnnotation(t, "ai", fmt.Sprintf("Task skipped: did not match active tag filter %v (parallel mode).", o.config.TagFilter))
				}
			}
			if len(ready) != len(filtered) {
				s.Save()
			}
			ready = filtered
			if len(ready) == 0 {
				continue
			}
		}

		// Condition gate: evaluate each task's condition and skip those that fail.
		{
			condOpts := provider.Options{
				Model:   s.Model,
				Timeout: o.config.StepTimeout,
			}
			gated := ready[:0]
			for _, t := range ready {
				if t.Condition == "" {
					gated = append(gated, t)
					continue
				}
				res, condErr := condition.Evaluate(ctx, t, s.Plan, o.provider, condOpts, o.config.WorkDir)
				if condErr != nil {
					dimColor.Printf("  condition eval error for task %d (proceeding): %v\n", t.ID, condErr)
				}
				if !res.Proceed {
					color.New(color.Faint).Printf("⊘ Task %d skipped (condition not met): %s\n  Condition: %s\n  Reason: %s\n",
						t.ID, t.Title, t.Condition, res.Reason)
					t.Status = pm.TaskSkipped
					pm.AddAnnotation(t, "ai", fmt.Sprintf("Task skipped: condition gate %q not met (parallel mode). Reason: %s", t.Condition, res.Reason))
				} else {
					dimColor.Printf("  Condition met for task %d: %s\n", t.ID, res.Reason)
					gated = append(gated, t)
				}
			}
			if len(ready) != len(gated) {
				s.Save()
			}
			ready = gated
			if len(ready) == 0 {
				continue
			}
		}

		// Daily budget enforcement: abort before spending tokens if any limit is exceeded.
		if budgetErr := budget.Enforce(o.config.WorkDir, o.config.Budget, o.config.NotifyCfg); budgetErr != nil {
			failColor.Printf("\n✗ Budget limit reached: %v\n", budgetErr)
			s.Status = "paused"
			s.Save()
			return budgetErr
		}

		// Per-project claudecode subscription cap enforcement.
		if ccErr := o.enforceClaudeCodeLimits(); ccErr != nil {
			failColor.Printf("\n✗ %v\n", ccErr)
			s.Status = "paused"
			s.Save()
			return ccErr
		}

		// Apply worker pool limit: cap the batch to MaxParallel if set.
		// Read from live state (refreshed via SyncFromDisk above) so UI changes
		// to max-parallel take effect on the next iteration without a restart.
		// readyTotal is preserved for the launch-summary log so the operator
		// can see how many tasks were eligible vs. actually launched.
		readyTotal := len(ready)
		maxParallel := s.MaxParallel
		if maxParallel > 0 && len(ready) > maxParallel {
			ready = ready[:maxParallel]
		}

		// Mark all ready tasks as in-progress before starting goroutines.
		// Each ready task is also enqueued in the central queue so the UI shows
		// a row per parallel task. queueIDs[i] is the id of ready[i] — we reuse
		// the slice index when marking results below to avoid an extra map.
		queueIDs := make([]int64, len(ready))
		now := time.Now()
		for i, t := range ready {
			t.Status = pm.TaskInProgress
			t.StartedAt = &now
			queueIDs[i] = o.enqueueWork(taskqueue.Entry{
				Kind:        taskqueue.KindTask,
				TaskID:      t.ID,
				Title:       t.Title,
				Description: t.Description,
				Source:      "orchestrator",
			})
			_ = o.queue.MarkRunning(queueIDs[i])
			if o.metrics != nil {
				o.metrics.RecordTaskStarted()
			}
			state.LogEventDetails(o.config.WorkDir, state.EventRow{
				Type:      state.EventTaskStarted,
				TaskID:    t.ID,
				TaskTitle: t.Title,
				Step:      s.CurrentStep,
				Message:   fmt.Sprintf("Task #%d started (parallel)", t.ID),
			}, map[string]any{
				"priority": t.Priority,
				"role":     t.Role,
				"parallel": true,
			})
		}
		s.Save()

		if len(ready) == 1 {
			// One ready task may mean a 1-deep chain or simply that no other
			// tasks were unblocked. Surface readyTotal/cap so the operator can
			// distinguish "parallelism not triggered" from "parallelism broken".
			suffix := ""
			if readyTotal > 1 || maxParallel > 0 {
				suffix = fmt.Sprintf("  (ready=%d, cap=%d)", readyTotal, maxParallel)
			}
			stepColor.Printf("━━━ Task %d/%d: %s%s ━━━\n", ready[0].ID, len(s.Plan.Tasks), ready[0].Title, suffix)
		} else {
			stepColor.Printf("━━━ Running %d tasks in parallel  (ready=%d, cap=%d) ━━━\n", len(ready), readyTotal, maxParallel)
			for _, t := range ready {
				dimColor.Printf("   • Task %d: %s\n", t.ID, t.Title)
			}
		}

		// Apply token-budget pruning to the plan once before launching parallel tasks.
		parallelPromptPlan, keptPar, totalPar := o.prunePlanForPrompt(s.Plan)
		if keptPar < totalPar {
			color.New(color.FgYellow).Printf("Context pruned: kept %d of %d steps to fit token budget\n", keptPar, totalPar)
		}

		// Pre-build all prompts in the main goroutine (Task 20129) before
		// launching workers. Otherwise workers would read plan task statuses
		// (via pm.ExecuteTaskPrompt's "completed tasks for context" section)
		// concurrently with the main goroutine's writes to task.Status as it
		// processes results in completion order — a data race the race
		// detector flags. Workers receive a fully-built prompt string and
		// touch no shared plan state during the provider call.
		prebuiltPrompts := make([]string, len(ready))
		for i, t := range ready {
			prompt := pm.ExecuteTaskPrompt(s.Goal, s.Instructions, o.config.WorkDir, parallelPromptPlan, t, o.config.NoCodeContextInject)
			if override, overrideErr := ctxedit.LoadOverride(o.config.WorkDir, t.ID); overrideErr == nil && override != "" {
				prompt = override
			}
			prompt = cloopenv.InjectIntoPrompt(prompt, o.envVars)
			if o.secretStore != nil {
				prompt = o.secretStore.InjectIntoPrompt(prompt)
			}
			if learningMem := learning.FormatForPrompt(o.config.WorkDir); learningMem != "" {
				prompt = learningMem + prompt
			}
			prebuiltPrompts[i] = prompt
		}

		// Worktree-parallel: provision one isolated worktree per task before
		// launching workers. Each task gets its own branch + filesystem path
		// so concurrent edits do not overwrite each other. If creation fails
		// for any task we skip worktree mode for that task only (the worker
		// falls back to the shared WorkDir). taskWorkDirs[i] holds the path
		// passed to the provider for ready[i].
		taskWorkDirs := make([]string, len(ready))
		for i := range ready {
			taskWorkDirs[i] = o.config.WorkDir
		}
		if worktreeMode {
			for i, t := range ready {
				wt, wErr := worktree.Create(o.config.WorkDir, t)
				if wErr != nil {
					dimColor.Printf("  worktree create failed for task %d (%v) — using shared workdir\n", t.ID, wErr)
					continue
				}
				taskWorkDirs[i] = wt.Path
				worktreeMu.Lock()
				activeWorktrees[t.ID] = wt
				worktreeMu.Unlock()
				dimColor.Printf("  worktree[task %d]: %s (branch %s)\n", t.ID, wt.Path, wt.Branch)
			}
		}

		// Launch goroutines for each ready task and stream their results back
		// through resultsCh as each one finishes (Task 20129) so a fast task's
		// terminal status is persisted/broadcast immediately rather than after
		// the slowest peer in the batch drains. Without this, the UI shows a
		// completed task as still in_progress for as long as the slowest task
		// in the round takes.
		//
		// Buffered to len(ready) so:
		//   - a slow consumer never blocks a fast worker on send
		//   - workers leaked past an early return (ctx cancelled, tooManyErrors)
		//     can still complete their send and exit cleanly
		// Streaming is disabled in parallel mode to avoid interleaved token output.
		type indexedResult struct {
			idx int
			res taskResult
		}
		resultsCh := make(chan indexedResult, len(ready))
		var wg sync.WaitGroup
		for i, task := range ready {
			wg.Add(1)
			go func(idx int, t *pm.Task, prompt string, workDir string) {
				defer wg.Done()
				// Send exactly one result whether the body completes normally
				// or panics. The defer below runs in LIFO order before
				// wg.Done(), and recovers any panic from the provider call.
				// Panic recovery: a panic inside a provider implementation
				// (e.g. nil-pointer in a third-party SDK, malformed JSON
				// deref) would otherwise crash the entire orchestrator
				// process, killing every peer task in the same parallel
				// round. Convert it into a task failure so the caller can
				// mark this single task failed and keep the loop alive.
				res := taskResult{task: t}
				defer func() {
					if r := recover(); r != nil {
						res = taskResult{
							task: t,
							err:  fmt.Errorf("provider panic on task %d: %v", t.ID, r),
						}
					}
					resultsCh <- indexedResult{idx: idx, res: res}
				}()
				start := time.Now()
				// Use role-specific provider if configured.
				taskProvider := o.router.For(t.Role)
				opts, _ := o.makeOpts(s.Model, false) // no streaming in parallel
				// Worktree-parallel: override the provider's working directory
				// so file edits land in this task's isolated worktree instead
				// of the shared project root. Falls through to o.config.WorkDir
				// when worktree mode is off or creation failed for this task.
				opts.WorkDir = workDir
				// Apply per-task time budget in parallel mode.
				tTaskCtx, tTaskCancel := o.taskContextWithTimeout(ctx, t)
				defer tTaskCancel()
				// Register the cancel with the watchdog so AutoKillAfter can
				// fire on a wedged provider call (Task 20088). The watchdog's
				// per-tick sweep drops cancels for tasks no longer
				// in_progress, so no explicit Unregister is required here.
				o.watchdog.Register(t.ID, tTaskCancel)
				// Tag context for the audit log so the call lands against this task.
				tAuditCtx := provideraudit.WithTaskContext(tTaskCtx, t.ID, t.Title)
				result, err := safeComplete(tAuditCtx, taskProvider, prompt, opts)
				// Write live artifact for parallel task (non-streaming).
				if err == nil {
					if lf, lfErr := artifact.OpenLiveArtifact(o.config.WorkDir, t.ID); lfErr == nil {
						_, _ = lf.WriteString(result.Output)
						_ = lf.Close()
					}
				}
				dur := time.Since(start)
				timedOut := isTimeoutErr(tTaskCtx, err)
				res = taskResult{task: t, result: result, err: err, duration: dur, timedOut: timedOut}
			}(i, task, prebuiltPrompts[i], taskWorkDirs[i])
		}
		// Closer: signal end-of-batch once every worker has emitted its
		// result. Used by the cancellation path's grace-period drain.
		waitDone := make(chan struct{})
		go func() {
			wg.Wait()
			close(waitDone)
		}()

		// Consume results in completion order so each task's terminal status
		// is persisted (and pushed to the UI via WebSocket) the moment it
		// finishes — fixes the "task still in_progress after completion" bug
		// when running multiple tasks in parallel.
		parallelTotal := len(ready)
		parallelDone := 0
		for parallelDone < parallelTotal {
			var ir indexedResult
			select {
			case ir = <-resultsCh:
				// fall through to per-result processing below
			case <-ctx.Done():
				// Bounded wait: if a misbehaving provider ignores the per-task
				// ctx, give workers a grace period to exit, then return early
				// so the caller regains control. Leaked goroutines may still
				// send to resultsCh afterward; the channel is buffered to
				// len(ready) so the send never blocks, and no one reads it
				// after we return.
				select {
				case <-waitDone:
					// Workers honored cancellation within the grace period
					// implicitly (drained before we even started the timer).
				case <-time.After(parallelShutdownGracePeriod):
					color.New(color.FgYellow).Printf("⚠ %d task goroutine(s) did not exit within %s of cancellation; returning anyway\n", parallelTotal-parallelDone, parallelShutdownGracePeriod)
				}
				s.Status = "paused"
				s.Save()
				return ctx.Err()
			}
			parallelDone++
			res := ir.res
			resIdx := ir.idx
			task := res.task
			parallelQueueID := int64(0)
			if resIdx < len(queueIDs) {
				parallelQueueID = queueIDs[resIdx]
			}
			// cleanupWorktree removes any active worktree for the given task
			// without merging. Used on error/early-exit paths where the task
			// did not produce a mergeable result. Branch ref is preserved so
			// developers can still inspect partial work.
			cleanupWorktree := func(taskID int) {
				if !worktreeMode {
					return
				}
				worktreeMu.Lock()
				wt, ok := activeWorktrees[taskID]
				if ok {
					delete(activeWorktrees, taskID)
				}
				worktreeMu.Unlock()
				if ok && wt != nil {
					if rmErr := wt.Remove(o.config.WorkDir); rmErr != nil {
						dimColor.Printf("  worktree remove task %d: %v\n", taskID, rmErr)
					}
				}
			}
			if res.err != nil {
				if res.timedOut {
					budgetMin := o.effectiveTaskBudgetMinutes(task)
					color.New(color.FgYellow).Printf("⏱ Task %d timed out (%dm): %s\n", task.ID, budgetMin, task.Title)
					o.handleTaskTimeout(ctx, s, task, res.partialOut, dimColor)
					_ = o.queue.MarkFailed(parallelQueueID, fmt.Sprintf("timeout (%dm)", budgetMin))
					cleanupWorktree(task.ID)
					mu.Lock()
					consecutiveErrors++
					s.Save()
					tooManyErrors := consecutiveErrors >= maxConsecutiveErrors
					mu.Unlock()
					if tooManyErrors {
						s.Status = "failed"
						s.Save()
						return fmt.Errorf("%d consecutive errors", consecutiveErrors)
					}
					continue
				}
				if provider.IsRetryBudgetExhausted(res.err) {
					failColor.Printf("✗ Task %d: retry budget exhausted (parallel) — %v\n", task.ID, res.err)
					_ = o.queue.MarkFailed(parallelQueueID, "retry budget exhausted")
					cleanupWorktree(task.ID)
					mu.Lock()
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: retry budget exhausted (parallel mode) — %s", truncate(res.err.Error(), 200)))
					task.Status = pm.TaskFailed
					consecutiveErrors++
					s.Save()
					tooManyErrors := consecutiveErrors >= maxConsecutiveErrors
					mu.Unlock()
					if tooManyErrors {
						s.Status = "failed"
						s.Save()
						return fmt.Errorf("%d consecutive errors", consecutiveErrors)
					}
					continue
				}
				failColor.Printf("✗ Provider error on task %d: %v\n", task.ID, res.err)
				_ = o.queue.MarkFailed(parallelQueueID, truncate(res.err.Error(), 200))
				cleanupWorktree(task.ID)
				mu.Lock()
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: provider error (parallel mode) — %s", truncate(res.err.Error(), 200)))
				task.Status = pm.TaskFailed
				consecutiveErrors++
				s.Save()
				tooManyErrors := consecutiveErrors >= maxConsecutiveErrors
				mu.Unlock()
				if tooManyErrors {
					s.Status = "failed"
					s.Save()
					return fmt.Errorf("%d consecutive errors", consecutiveErrors)
				}
				continue
			}

			result := res.result
			// Empty-output watchdog: same companion to runPMSequential's guard —
			// a (*Result{Output:""}, nil) on the parallel path otherwise falls
			// into the `default:` arm below and silently marks the task DONE,
			// draining the whole plan when the provider is hiccupping (auth
			// flaps, content-filtered completions, partial responses).
			if result == nil || strings.TrimSpace(result.Output) == "" {
				failColor.Printf("✗ Task %d: provider returned empty output\n", task.ID)
				_ = o.queue.MarkFailed(parallelQueueID, "provider returned empty output")
				cleanupWorktree(task.ID)
				mu.Lock()
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task re-queued: provider returned empty output (parallel mode, consecutive errors: %d/%d).", consecutiveErrors+1, maxConsecutiveErrors))
				task.Status = pm.TaskPending
				consecutiveErrors++
				s.Save()
				tooManyErrors := consecutiveErrors >= maxConsecutiveErrors
				mu.Unlock()
				if tooManyErrors {
					s.Status = "failed"
					s.Save()
					return fmt.Errorf("%d consecutive task failures (empty provider output)", consecutiveErrors)
				}
				continue
			}
			stepResult := state.StepResult{
				Task:         fmt.Sprintf("Task %d: %s", task.ID, task.Title),
				Output:       result.Output,
				Duration:     res.duration.Round(time.Second).String(),
				Time:         time.Now(),
				InputTokens:  result.InputTokens,
				OutputTokens: result.OutputTokens,
			}

			mu.Lock()
			s.TotalInputTokens += result.InputTokens
			s.TotalOutputTokens += result.OutputTokens
			parallelReplayStep := s.CurrentStep
			s.AddStep(stepResult)
			mu.Unlock()
			if err := replay.Append(o.config.WorkDir, replay.Entry{
				Ts:        time.Now(),
				TaskID:    task.ID,
				TaskTitle: task.Title,
				Step:      parallelReplayStep,
				Content:   result.Output,
			}); err != nil {
				dimColor.Printf("  replay log write error (ignored): %v\n", err)
			}

			// Record step metrics.
			if o.metrics != nil {
				o.metrics.RecordStep()
				o.metrics.RecordTokens(result.Provider, result.Model, result.InputTokens, result.OutputTokens)
				if usd, ok := cost.Estimate(strings.ToLower(result.Model), result.InputTokens, result.OutputTokens); ok {
					o.metrics.RecordCost(result.Provider, result.Model, usd)
				}
			}

			printOutput(result.Output, dimColor, o.config.Verbose)
			dimColor.Printf("  [%s, provider: %s]\n\n", res.duration.Round(time.Second), result.Provider)

			if o.config.TokenBudget > 0 && s.TotalInputTokens+s.TotalOutputTokens >= o.config.TokenBudget {
				color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
				task.Status = pm.TaskPending
				s.Status = "paused"
				s.Save()
				return nil
			}
			if o.checkCostLimit(s) {
				task.Status = pm.TaskPending
				s.Status = "paused"
				s.Save()
				return nil
			}

			signal := pm.CheckTaskSignal(result.Output)
			// Fail-closed for unanswered clarification questions: the parallel
			// path has no auto-resolve loop, so a TaskInProgress with
			// clarification questions would otherwise fall into the `default:`
			// arm of the switch below and be silently marked DONE.
			clarificationReroute := false
			if signal == pm.TaskInProgress && looksLikeClarificationQuestion(result.Output) {
				signal = pm.TaskFailed
				clarificationReroute = true
			}
			completedAt := time.Now()
			task.CompletedAt = &completedAt
			task.Result = truncate(result.Output, 500)
			if task.StartedAt != nil {
				task.ActualMinutes = int(completedAt.Sub(*task.StartedAt).Minutes())
			}

			taskDur := res.duration.Round(time.Second).String()
			taskDurMs := res.duration.Milliseconds()
			mu.Lock()
			if clarificationReroute {
				pm.AddAnnotation(task, "ai", "Task failed: LLM asked clarification questions instead of completing the work (parallel mode has no auto-resolve loop).")
			}
			switch signal {
			case pm.TaskDone:
				task.Status = pm.TaskDone
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task completed successfully in %s.", taskDur))
				if !o.log.IsJSON() {
					successColor.Printf("✓ Task %d complete: %s\n\n", task.ID, task.Title)
				}
				o.log.Info(logger.EventTaskDone, task.ID, task.Title, map[string]interface{}{"duration_ms": taskDurMs})
				if o.config.Notify {
					notify.Send("cloop: Task Done", task.Title)
				}
				o.notifyWebhooks("cloop: Task Done", fmt.Sprintf("Task #%d: %s\nGoal: %s\nElapsed: %s", task.ID, task.Title, s.Goal, taskDur))
				{
					done, failed := s.Plan.CountByStatus()
					o.webhook.Send(webhook.EventTaskDone, webhook.Payload{
						Goal:     s.Goal,
						Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "done", Duration: taskDur},
						Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
						Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					})
				}
				consecutiveErrors = 0
			case pm.TaskSkipped:
				task.Status = pm.TaskSkipped
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task skipped per AI TASK_SKIPPED signal after %s.", taskDur))
				if !o.log.IsJSON() {
					dimColor.Printf("→ Task %d skipped: %s\n\n", task.ID, task.Title)
				}
				o.log.Info(logger.EventTaskSkipped, task.ID, task.Title, nil)
				{
					done, failed := s.Plan.CountByStatus()
					o.webhook.Send(webhook.EventTaskSkipped, webhook.Payload{
						Goal:     s.Goal,
						Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "skipped"},
						Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
						Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					})
				}
				consecutiveErrors = 0
			case pm.TaskFailed:
				task.Status = pm.TaskFailed
				// Skip the explicit-signal annotation when the failure came from
				// the clarification reroute above — the reroute already added an
				// accurate annotation (line ~3137), and claiming "per AI
				// TASK_FAILED signal" would misattribute it.
				if !clarificationReroute {
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed per AI TASK_FAILED signal after %s.", taskDur))
				}
				if !o.log.IsJSON() {
					failColor.Printf("✗ Task %d failed: %s\n\n", task.ID, task.Title)
				}
				o.log.Error(logger.EventTaskFailed, task.ID, task.Title, map[string]interface{}{"duration_ms": taskDurMs})
				if o.config.Notify {
					notify.Send("cloop: Task Failed", task.Title)
				}
				o.notifyWebhooks("cloop: Task Failed", fmt.Sprintf("Task #%d: %s\nGoal: %s\nElapsed: %s", task.ID, task.Title, s.Goal, taskDur))
				{
					done, failed := s.Plan.CountByStatus()
					o.webhook.Send(webhook.EventTaskFailed, webhook.Payload{
						Goal:     s.Goal,
						Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "failed", Duration: taskDur},
						Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
						Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					})
				}
				consecutiveErrors++
			default:
				task.Status = pm.TaskDone
				pm.AddAnnotation(task, "ai", "Task implicitly completed (parallel mode): AI finished without an explicit TASK_DONE/TASK_FAILED/TASK_SKIPPED signal — treated as done.")
				if !o.log.IsJSON() {
					successColor.Printf("✓ Task %d complete (no explicit signal): %s\n\n", task.ID, task.Title)
				}
				o.log.Info(logger.EventTaskDone, task.ID, task.Title, map[string]interface{}{
					"duration_ms": taskDurMs,
					"implicit":    true,
				})
				if o.config.Notify {
					notify.Send("cloop: Task Done", task.Title)
				}
				o.notifyWebhooks("cloop: Task Done", fmt.Sprintf("Task #%d: %s\nGoal: %s\nElapsed: %s", task.ID, task.Title, s.Goal, taskDur))
				{
					done, failed := s.Plan.CountByStatus()
					o.webhook.Send(webhook.EventTaskDone, webhook.Payload{
						Goal:     s.Goal,
						Task:     &webhook.TaskInfo{ID: task.ID, Title: task.Title, Status: "done", Duration: taskDur},
						Progress: &webhook.Progress{Done: done, Total: len(s.Plan.Tasks), Failed: failed},
						Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
					})
				}
				consecutiveErrors = 0
			}

			// Central queue: mark this parallel work item terminal.
			switch task.Status {
			case pm.TaskDone:
				_ = o.queue.MarkDone(parallelQueueID, stepSummaryLine(result.Output, 200))
			case pm.TaskFailed:
				_ = o.queue.MarkFailed(parallelQueueID, stepSummaryLine(result.Output, 200))
			case pm.TaskSkipped:
				_ = o.queue.MarkSkipped(parallelQueueID, "AI emitted TASK_SKIPPED")
			default:
				_ = o.queue.MarkDone(parallelQueueID, stepSummaryLine(result.Output, 200))
			}

			// Worktree-parallel: commit changes and enqueue the merge for
			// successful tasks; clean up worktree for any terminal status.
			// The merge queue serializes merges so concurrent worktrees fan
			// back into the base branch one at a time without races.
			if worktreeMode {
				worktreeMu.Lock()
				wt, ok := activeWorktrees[task.ID]
				worktreeMu.Unlock()
				if ok && wt != nil {
					switch task.Status {
					case pm.TaskDone:
						if _, cErr := wt.Commit(task); cErr != nil {
							dimColor.Printf("  worktree commit task %d: %v\n", task.ID, cErr)
						}
						mr := mergeQ.Submit(mergequeue.Request{
							Branch: wt.Branch,
							TaskID: task.ID,
							Title:  task.Title,
						})
						// Block on the merge so the next round's worktrees see
						// the merged base. Submissions are FIFO inside the
						// queue, so this preserves the requested ordering.
						<-mr.Done
						if mr.Err != nil {
							dimColor.Printf("  worktree merge task %d: %v (branch %s left for manual resolution)\n", task.ID, mr.Err, wt.Branch)
							pm.AddAnnotation(task, "ai", fmt.Sprintf("Worktree merge conflict: %s — branch %s preserved.", truncate(mr.Err.Error(), 200), wt.Branch))
						} else {
							dimColor.Printf("  worktree merged: %s → %s (task %d)\n", wt.Branch, worktreeBase, task.ID)
						}
					case pm.TaskFailed, pm.TaskSkipped:
						dimColor.Printf("  worktree: keeping branch %s for inspection (task %s)\n", wt.Branch, task.Status)
					}
					// Always remove the on-disk worktree (branch ref survives).
					if rmErr := wt.Remove(o.config.WorkDir); rmErr != nil {
						dimColor.Printf("  worktree remove task %d: %v\n", task.ID, rmErr)
					}
					worktreeMu.Lock()
					delete(activeWorktrees, task.ID)
					worktreeMu.Unlock()
				}
			}

			// Unified event journal — one terminal event per task outcome
			// (Task 20118). mu is already held from the switch above, so
			// re-acquiring it here would deadlock; just read s.CurrentStep
			// under the existing lock.
			parallelStep := s.CurrentStep
			o.logTaskOutcomeEvent(task, taskDur, parallelStep)

			// Record task outcome into metrics.
			if o.metrics != nil && task.StartedAt != nil {
				durSecs := time.Since(*task.StartedAt).Seconds()
				switch task.Status {
				case pm.TaskDone:
					o.metrics.RecordTaskCompleted(durSecs)
				case pm.TaskFailed:
					o.metrics.RecordTaskFailed(durSecs)
				case pm.TaskSkipped:
					o.metrics.RecordTaskSkipped()
				}
			}

			// Persist full AI response as a Markdown artifact file.
			o.writeTaskArtifact(task, result.Output)

			// Conditional branching: activate the matching branch, skip the other.
			if activations := pm.ResolveBranch(s.Plan, task); len(activations) > 0 {
				branchColor := color.New(color.FgCyan)
				for _, a := range activations {
					if a.Activated {
						branchColor.Printf("  branch [%s] activated  -> task %d: %s\n", a.Branch, a.TaskID, a.Title)
					} else {
						color.New(color.Faint).Printf("  branch [%s] skipped    -> task %d: %s\n", a.Branch, a.TaskID, a.Title)
					}
				}
			}

			tooManyErrors := consecutiveErrors >= maxConsecutiveErrors
			s.Save()
			mu.Unlock()

			if tooManyErrors {
				s.Status = "failed"
				s.Save()
				return fmt.Errorf("%d consecutive task failures", consecutiveErrors)
			}
		}
	}

	s.Status = "paused"
	s.Save()

	// Distil cross-session learnings into .cloop/memory.md after the plan completes.
	o.distillLearnings(ctx, s.Plan)

	return nil
}

// injectChainOutput propagates a completed task's AI output to downstream tasks
// that are chained to it.  A task is "chained" when it carries a "chain:<uuid>"
// tag and lists the completed task in its DependsOn field.
// The output is stored in the runtime-only ChainInput field so that
// ExecuteTaskPrompt can prepend it as a "Previous step output:" section.
func (o *Orchestrator) injectChainOutput(plan *pm.Plan, completedTask *pm.Task, output string) {
	if completedTask.Status != pm.TaskDone {
		return
	}
	chainTag := chainTagOf(completedTask.Tags)
	if chainTag == "" {
		return
	}
	dimColor := color.New(color.Faint)
	for _, t := range plan.Tasks {
		if !hasChainTag(t.Tags, chainTag) {
			continue
		}
		if !sliceContains(t.DependsOn, completedTask.ID) {
			continue
		}
		t.ChainInput = artifact.ReadTaskOutput(o.config.WorkDir, completedTask)
		if t.ChainInput == "" {
			t.ChainInput = output
		}
		dimColor.Printf("  chain: injecting output of task %d → task %d\n", completedTask.ID, t.ID)
	}
}

// chainTagOf returns the first "chain:<uuid>" tag found in tags, or "".
func chainTagOf(tags []string) string {
	for _, t := range tags {
		if strings.HasPrefix(t, "chain:") {
			return t
		}
	}
	return ""
}

// hasChainTag reports whether tags contains the given chain tag.
func hasChainTag(tags []string, chainTag string) bool {
	for _, t := range tags {
		if t == chainTag {
			return true
		}
	}
	return false
}

// sliceContains reports whether id is present in ids.
func sliceContains(ids []int, id int) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// writeTaskArtifact persists the full AI response for a task to
// .cloop/tasks/<id>-<slug>.md and sets task.ArtifactPath. Errors are
// non-fatal — logged to stderr but do not abort the run.
func (o *Orchestrator) writeTaskArtifact(task *pm.Task, output string) {
	path, err := artifact.WriteTaskArtifact(o.config.WorkDir, task, output)
	if err != nil {
		color.New(color.Faint).Printf("  artifact write error (ignored): %v\n", err)
		return
	}
	task.ArtifactPath = path
}

// appendConsensusReport appends a formatted consensus decision section to the
// task's artifact file. Errors are non-fatal.
func (o *Orchestrator) appendConsensusReport(task *pm.Task, report *consensus.Report) {
	if report == nil || task.ArtifactPath == "" {
		return
	}
	absPath := task.ArtifactPath
	if !strings.HasPrefix(absPath, "/") {
		absPath = strings.Join([]string{o.config.WorkDir, task.ArtifactPath}, "/")
	}
	f, err := os.OpenFile(absPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		color.New(color.Faint).Printf("  consensus artifact append error (ignored): %v\n", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(consensus.FormatReport(report)); err != nil {
		color.New(color.Faint).Printf("  consensus report write error (ignored): %v\n", err)
	}
}

// buildConsensusProviders returns a deduplicated list of providers to use for
// consensus voting. It always includes the given primary provider. Other
// providers are built when their credentials are available.
func (o *Orchestrator) buildConsensusProviders(primary provider.Provider) []provider.Provider {
	ps := []provider.Provider{primary}
	seen := map[string]bool{primary.Name(): true}

	cfg := o.config.ProviderCfg
	candidates := []provider.ProviderConfig{
		{Name: "anthropic", AnthropicAPIKey: cfg.AnthropicAPIKey, AnthropicBaseURL: cfg.AnthropicBaseURL,
			OpenAIAPIKey: cfg.OpenAIAPIKey, OpenAIBaseURL: cfg.OpenAIBaseURL, OllamaBaseURL: cfg.OllamaBaseURL},
		{Name: "openai", AnthropicAPIKey: cfg.AnthropicAPIKey, AnthropicBaseURL: cfg.AnthropicBaseURL,
			OpenAIAPIKey: cfg.OpenAIAPIKey, OpenAIBaseURL: cfg.OpenAIBaseURL, OllamaBaseURL: cfg.OllamaBaseURL},
		{Name: "ollama", AnthropicAPIKey: cfg.AnthropicAPIKey, AnthropicBaseURL: cfg.AnthropicBaseURL,
			OpenAIAPIKey: cfg.OpenAIAPIKey, OpenAIBaseURL: cfg.OpenAIBaseURL, OllamaBaseURL: cfg.OllamaBaseURL},
		{Name: "claudecode", AnthropicAPIKey: cfg.AnthropicAPIKey, AnthropicBaseURL: cfg.AnthropicBaseURL,
			OpenAIAPIKey: cfg.OpenAIAPIKey, OpenAIBaseURL: cfg.OpenAIBaseURL, OllamaBaseURL: cfg.OllamaBaseURL},
	}
	for _, c := range candidates {
		if seen[c.Name] {
			continue
		}
		p, err := provider.Build(c)
		if err != nil {
			continue
		}
		seen[c.Name] = true
		ps = append(ps, p)
	}
	return ps
}

// makeOpts builds provider.Options for a completion call.
// When o.config.Streaming is true it attaches an OnToken callback that prints
// each token immediately to stdout; wasStreamed() returns true if at least one
// token was received that way.  Callers should call printOutput() only when
// wasStreamed() is false to avoid double-printing.
// For parallel execution pass streaming=false to avoid interleaved output.
func (o *Orchestrator) makeOpts(model string, streaming bool) (provider.Options, func() bool) {
	var streamed bool
	opts := provider.Options{
		Model:            model,
		MaxTokens:        o.config.MaxTokens,
		Timeout:          o.config.StepTimeout,
		WorkDir:          o.config.WorkDir,
		Temperature:      o.config.Temperature,
		TopP:             o.config.TopP,
		FrequencyPenalty: o.config.FrequencyPenalty,
		ExtendedThinking: o.config.ExtendedThinking,
		ThinkingBudget:   o.config.ThinkingBudget,
	}
	if streaming && o.config.Streaming {
		opts.OnToken = func(token string) {
			fmt.Print(token)
			streamed = true
		}
	}
	return opts, func() bool { return streamed }
}

// tokenLimit returns the effective ContextTokenLimit: the configured value or the default
// of 100000 when the field is zero.
func (o *Orchestrator) tokenLimit() int {
	if o.config.ContextTokenLimit > 0 {
		return o.config.ContextTokenLimit
	}
	return 100000
}

// pruneStepHistory applies token-budget pruning to a step slice.
// It collects the step outputs as strings, calls pm.PruneToTokenBudget, then
// reconstructs the []state.StepResult slice for the entries that were retained.
// Returns (prunedSteps, originalCount, keptCount).
func pruneStepHistory(steps []state.StepResult, budgetTokens int) ([]state.StepResult, int, int) {
	n := len(steps)
	if n == 0 {
		return steps, 0, 0
	}
	texts := make([]string, n)
	for i, step := range steps {
		texts[i] = step.Output
	}
	pruned := pm.PruneToTokenBudget(texts, budgetTokens)
	if len(pruned) == n {
		return steps, n, n
	}
	// Reconstruct the StepResult slice that corresponds to the pruned text slice.
	// PruneToTokenBudget always keeps index 0 and the last two; it drops oldest
	// intermediates from index 1 forward. The drop count equals n - len(pruned).
	dropCount := n - len(pruned)
	result := make([]state.StepResult, 0, len(pruned))
	result = append(result, steps[0])
	if n >= 3 {
		// Middle: steps[1:n-2]; kept = steps[1+dropCount:n-2]
		middleStart := 1 + dropCount
		if middleStart < n-2 {
			result = append(result, steps[middleStart:n-2]...)
		}
		result = append(result, steps[n-2:]...)
	} else if n == 2 {
		result = append(result, steps[1])
	}
	return result, n, len(result)
}

// prunePlanForPrompt returns a shallow copy of plan with the Result field of older
// completed tasks cleared so that the prompt fits within the token budget.
// Returns the (possibly modified) plan and counts (kept, total) for warning output.
// Returns the original plan unchanged when no pruning is needed.
func (o *Orchestrator) prunePlanForPrompt(plan *pm.Plan) (*pm.Plan, int, int) {
	budget := o.tokenLimit()
	if plan == nil {
		return plan, 0, 0
	}
	// Collect completed-task result strings and their indices in plan.Tasks.
	var results []string
	var completedIdx []int
	for i, t := range plan.Tasks {
		if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
			results = append(results, t.Result)
			completedIdx = append(completedIdx, i)
		}
	}
	total := len(results)
	if total == 0 {
		return plan, 0, 0
	}
	pruned := pm.PruneToTokenBudget(results, budget)
	if len(pruned) == total {
		return plan, total, total
	}
	// PruneToTokenBudget drops oldest intermediates: completedIdx[1..dropCount].
	dropCount := total - len(pruned)
	droppedSet := make(map[int]bool, dropCount)
	for i := 1; i <= dropCount && i < total; i++ {
		droppedSet[completedIdx[i]] = true
	}
	// Build a shallow copy of the plan with Result cleared for dropped tasks.
	newPlan := *plan
	newTasks := make([]*pm.Task, len(plan.Tasks))
	for i, t := range plan.Tasks {
		if droppedSet[i] {
			tc := *t
			tc.Result = ""
			newTasks[i] = &tc
		} else {
			newTasks[i] = t
		}
	}
	newPlan.Tasks = newTasks
	return &newPlan, len(pruned), total
}

// evolvePM discovers new tasks via AI and appends them to the plan.
// Returns the number of tasks added. Called when AutoEvolve is set and the PM plan is complete.
func (o *Orchestrator) evolvePM(ctx context.Context) (int, error) {
	s := o.state
	s.EvolveStep++

	evolveColor := color.New(color.FgMagenta, color.Bold)
	dimColor := color.New(color.Faint)

	evolveColor.Printf("━━━ Evolve #%d — Discovering new tasks ━━━\n", s.EvolveStep)
	dimColor.Printf("→ Asking AI for improvement ideas...\n")
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:    state.EventEvolveRoundStart,
		Message: fmt.Sprintf("Evolve round #%d started", s.EvolveStep),
	}, map[string]any{
		"evolve_step": s.EvolveStep,
		"innovate":    s.InnovateMode,
	})

	// Central queue: every evolve cycle is recorded as work, even when it
	// discovers zero new tasks. Failures in the discovery call still consume
	// tokens and must be visible in the activity log.
	evolveQueueID := o.enqueueWork(taskqueue.Entry{
		Kind:        taskqueue.KindEvolve,
		Attempt:     s.EvolveStep,
		Title:       fmt.Sprintf("Evolve #%d: discover new tasks", s.EvolveStep),
		Description: "AI is reviewing the plan to discover improvement tasks",
		Source:      "evolve",
	})
	_ = o.queue.MarkRunning(evolveQueueID)

	prompt := pm.EvolveDiscoverPrompt(s.Goal, s.Instructions, s.Plan, s.EvolveStep, s.InnovateMode)
	opts, _ := o.makeOpts(s.Model, true)
	result, err := safeComplete(ctx, o.provider, prompt, opts)
	if err != nil {
		_ = o.queue.MarkFailed(evolveQueueID, truncate(err.Error(), 200))
		return 0, err
	}

	stepResult := state.StepResult{
		Task:         fmt.Sprintf("Evolve #%d: discover tasks", s.EvolveStep),
		Output:       result.Output,
		Duration:     result.Duration.Round(time.Second).String(),
		Time:         time.Now(),
		InputTokens:  result.InputTokens,
		OutputTokens: result.OutputTokens,
	}
	s.TotalInputTokens += result.InputTokens
	s.TotalOutputTokens += result.OutputTokens
	s.AddStep(stepResult)

	// Sync from disk before computing maxID so that any tasks added externally
	// during the evolve AI call are accounted for — preventing ID reuse.
	s.SyncFromDisk()
	newTasks, err := pm.ParseEvolveTasks(s.Goal, result.Output, s.Plan)
	if err != nil {
		_ = o.queue.MarkFailed(evolveQueueID, fmt.Sprintf("parse error: %v", err))
		dimColor.Printf("  Task discovery parse error: %v\n", err)
		s.Save()
		return 0, nil
	}
	if len(newTasks) == 0 {
		_ = o.queue.MarkDone(evolveQueueID, "no new tasks discovered")
		dimColor.Printf("  No new tasks discovered — project is fully evolved.\n")
		state.LogEventDetails(o.config.WorkDir, state.EventRow{
			Type:    state.EventEvolveNoOp,
			Message: fmt.Sprintf("Evolve round #%d found no new tasks", s.EvolveStep),
		}, map[string]any{"evolve_step": s.EvolveStep})
		s.Save()
		return 0, nil
	}

	// Semantic deduplication: filter out candidates that duplicate existing work.
	if !o.config.NoDedup {
		dedupOpts, _ := o.makeOpts(s.Model, false)
		deduped, dedupErr := pm.DeduplicateTasks(ctx, o.provider, dedupOpts, s.Plan.Tasks, newTasks)
		if dedupErr != nil {
			dimColor.Printf("  Dedup warning: %v\n", dedupErr)
			// fail-open: deduped already contains all newTasks in this case
		}
		dropped := len(newTasks) - len(deduped)
		if dropped > 0 {
			dimColor.Printf("  Dedup: removed %d duplicate task(s), %d novel task(s) remain.\n", dropped, len(deduped))
		}
		newTasks = deduped
	}

	if len(newTasks) == 0 {
		_ = o.queue.MarkDone(evolveQueueID, "all candidates were duplicates")
		dimColor.Printf("  No novel tasks after deduplication — project is fully evolved.\n")
		state.LogEventDetails(o.config.WorkDir, state.EventRow{
			Type:    state.EventEvolveNoOp,
			Message: fmt.Sprintf("Evolve round #%d: all candidates duplicates", s.EvolveStep),
		}, map[string]any{"evolve_step": s.EvolveStep})
		s.Save()
		return 0, nil
	}

	s.Plan.Tasks = append(s.Plan.Tasks, newTasks...)
	s.Save()
	_ = o.queue.MarkDone(evolveQueueID, fmt.Sprintf("discovered %d new task(s)", len(newTasks)))

	o.webhook.Send(webhook.EventEvolveDiscovered, webhook.Payload{
		Goal: s.Goal,
		Session: &webhook.SessionInfo{
			NewTasksFound: len(newTasks),
			EvolveStep:    s.EvolveStep,
			InputTokens:   s.TotalInputTokens,
			OutputTokens:  s.TotalOutputTokens,
		},
	})
	{
		titles := make([]string, 0, len(newTasks))
		for _, t := range newTasks {
			titles = append(titles, fmt.Sprintf("#%d %s", t.ID, t.Title))
		}
		state.LogEventDetails(o.config.WorkDir, state.EventRow{
			Type:    state.EventEvolveDiscovered,
			Message: fmt.Sprintf("Evolve round #%d discovered %d new task(s)", s.EvolveStep, len(newTasks)),
		}, map[string]any{
			"evolve_step": s.EvolveStep,
			"count":       len(newTasks),
			"titles":      titles,
		})
	}

	evolveColor.Printf("  Discovered %d new task(s):\n", len(newTasks))
	for _, t := range newTasks {
		fmt.Printf("    + [P%d] %s\n", t.Priority, t.Title)
		dimColor.Printf("      %s\n", truncate(t.Description, 100))
	}
	fmt.Println()

	return len(newTasks), nil
}

func printOutput(output string, dimColor *color.Color, verbose bool) {
	printOutputTo(os.Stdout, output, dimColor, verbose)
}

func printOutputTo(w io.Writer, output string, dimColor *color.Color, verbose bool) {
	lines := strings.Split(output, "\n")
	if !verbose && len(lines) > 20 {
		for _, line := range lines[:10] {
			fmt.Fprintf(w, "  %s\n", line)
		}
		dimColor.Fprintf(w, "  ... (%d lines omitted, use --verbose to see all) ...\n", len(lines)-20)
		for _, line := range lines[len(lines)-10:] {
			fmt.Fprintf(w, "  %s\n", line)
		}
	} else {
		for _, line := range lines {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
}

// looksLikeClarificationQuestion returns true if the output appears to contain
// clarification questions rather than actual task completion work.
func looksLikeClarificationQuestion(output string) bool {
	lower := strings.ToLower(output)
	patterns := []string{
		"before i proceed",
		"would you like me to",
		"how would you like",
		"should i ",
		"could you clarify",
		"do you want me to",
		"which approach",
		"please confirm",
		"let me know if",
		"would you prefer",
		"i have a few questions",
		"couple of questions",
		"how should i",
		"what would you",
		"awaiting your",
		"need your input",
		"how do you want",
	}
	matches := 0
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			matches++
		}
	}
	// Need at least one pattern match, and the output should have question marks
	hasQuestions := strings.Count(output, "?") >= 1
	return matches >= 1 && hasQuestions
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// printRiskBanner prints a compact risk summary to the terminal for a single task.
func printRiskBanner(r *risk.RiskReport) {
	levelColor := func(l risk.Level) *color.Color {
		switch l {
		case risk.LevelCritical:
			return color.New(color.FgRed, color.Bold)
		case risk.LevelHigh:
			return color.New(color.FgRed)
		case risk.LevelMedium:
			return color.New(color.FgYellow)
		default:
			return color.New(color.FgGreen)
		}
	}

	color.New(color.FgCyan).Printf("  ⚑ Risk assessment — Task #%d: %s  (overall: ", r.TaskID, r.TaskTitle)
	levelColor(r.OverallLevel).Printf("%s", r.OverallLevel)
	color.New(color.FgCyan).Printf(")\n")
	for _, f := range r.Findings {
		levelColor(f.Level).Printf("    [%s]", f.Level)
		fmt.Printf(" %s — %s\n", f.Category, f.Rationale)
		color.New(color.Faint).Printf("    ↳ Mitigation: %s\n", f.Mitigation)
	}
	fmt.Println()
}

// printCoachBanner renders a compact coaching session card to the terminal.
func printCoachBanner(s *coach.CoachingSession) {
	cyan := color.New(color.FgCyan, color.Bold)
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	cyan.Printf("  ┌─ Coaching: Task #%d — %s\n", s.TaskID, s.TaskTitle)
	for i, tip := range s.Tips {
		bold.Printf("  │ [%s] ", strings.ToUpper(tip.Category))
		fmt.Printf("Tip %d: ", i+1)
		lines := wrapOrchestratorText(tip.Advice, 58)
		for j, line := range lines {
			if j == 0 {
				fmt.Printf("%s\n", line)
			} else {
				dim.Printf("  │         %s\n", line)
			}
		}
	}
	if s.KeyQuestion != "" {
		yellow.Printf("  │ ? KEY: ")
		fmt.Printf("%s\n", s.KeyQuestion)
	}
	if len(s.SuccessCriteria) > 0 {
		green.Printf("  │ ✓ DONE WHEN: ")
		fmt.Printf("%s\n", s.SuccessCriteria[0])
		for _, c := range s.SuccessCriteria[1:] {
			green.Printf("  │            ")
			fmt.Printf("%s\n", c)
		}
	}
	cyan.Printf("  └─────────────────────────────────────────────────────\n\n")
}

// wrapOrchestratorText wraps text to width runes, returning word-wrapped lines.
func wrapOrchestratorText(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len([]rune(line))+1+len([]rune(w)) <= width {
			line += " " + w
		} else {
			lines = append(lines, line)
			line = w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// buildHealPrompt constructs a modified retry prompt that incorporates the
// diagnosed root cause and suggested fix strategy from a prior failure.
// originalPrompt is the full prompt that produced TASK_FAILED; diagnosis is
// the concise root-cause / fix-strategy string from AnalyzeFailure.
func buildHealPrompt(originalPrompt, diagnosis string, attempt, maxAttempts int) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("## AUTO-HEAL RETRY (attempt %d of %d)\n", attempt, maxAttempts))
	b.WriteString("A previous attempt at this task failed. The failure was diagnosed and a fix\n")
	b.WriteString("strategy has been identified. You MUST address the root cause before proceeding.\n\n")
	b.WriteString("### FAILURE DIAGNOSIS AND FIX STRATEGY\n")
	b.WriteString(diagnosis)
	b.WriteString("\n\n")
	b.WriteString("### INSTRUCTIONS\n")
	b.WriteString("Apply the fix strategy above. Do not repeat the same approach that failed.\n")
	b.WriteString("When complete, end your response with TASK_DONE, TASK_SKIPPED, or TASK_FAILED.\n\n")
	b.WriteString("---\n\n")
	b.WriteString("## ORIGINAL TASK\n\n")
	b.WriteString(originalPrompt)
	return b.String()
}

// stepSummaryLine returns a short one-line summary of a step's output.
// It picks the last non-empty, non-signal line (avoiding TASK_* markers)
// and truncates it to maxLen runes.
func stepSummaryLine(output string, maxLen int) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	signals := map[string]bool{
		"TASK_DONE":    true,
		"TASK_SKIPPED": true,
		"TASK_FAILED":  true,
	}
	// Walk backwards to find the last meaningful line.
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || signals[line] {
			continue
		}
		if len([]rune(line)) > maxLen {
			runes := []rune(line)
			return string(runes[:maxLen]) + "..."
		}
		return line
	}
	return "(no summary)"
}

// distillLearnings calls the AI to distill plan outcomes into .cloop/memory.md.
// This always runs after a PM plan completes (no flag required).
func (o *Orchestrator) distillLearnings(ctx context.Context, plan *pm.Plan) {
	if plan == nil || len(plan.Tasks) == 0 {
		return
	}
	dimColor := color.New(color.Faint)
	dimColor.Printf("  Distilling session into project memory...\n")
	queueID := o.enqueueWork(taskqueue.Entry{
		Kind:        taskqueue.KindSession,
		Title:       "Distill session into project memory",
		Description: fmt.Sprintf("plan with %d task(s)", len(plan.Tasks)),
		Source:      "orchestrator",
	})
	_ = o.queue.MarkRunning(queueID)
	summary, err := learning.Distill(ctx, o.provider, o.state.Model, plan)
	if err != nil {
		_ = o.queue.MarkFailed(queueID, truncate(err.Error(), 200))
		dimColor.Printf("  Memory distillation failed (ignored): %v\n", err)
		return
	}
	if summary == "" {
		_ = o.queue.MarkDone(queueID, "no memory update needed")
		dimColor.Printf("  No memory update needed.\n")
		return
	}
	if err := learning.SaveMemory(o.config.WorkDir, summary); err != nil {
		_ = o.queue.MarkFailed(queueID, fmt.Sprintf("save memory: %v", err))
		dimColor.Printf("  Failed to save memory (ignored): %v\n", err)
		return
	}
	_ = o.queue.MarkDone(queueID, "memory updated")
	dimColor.Printf("  Project memory updated (.cloop/memory.md).\n")
}

// learnFromSession asks the AI to extract learnings from the session and saves them.
func (o *Orchestrator) learnFromSession(ctx context.Context, steps []state.StepResult) {
	if !o.config.Learn || o.memory == nil || len(steps) == 0 {
		return
	}
	// Build a compact session summary from step outputs.
	var sb strings.Builder
	for i, step := range steps {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... (%d more steps)\n", len(steps)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("Step %d (%s): %s\n", step.Step+1, step.Duration, truncate(step.Output, 300)))
	}
	summary := sb.String()

	dimColor := color.New(color.Faint)
	dimColor.Printf("  Extracting session learnings...\n")

	queueID := o.enqueueWork(taskqueue.Entry{
		Kind:        taskqueue.KindSession,
		Title:       "Extract session learnings",
		Description: fmt.Sprintf("%d step(s)", len(steps)),
		Source:      "orchestrator",
	})
	_ = o.queue.MarkRunning(queueID)

	learnings, err := memory.ExtractLearnings(ctx, o.provider, o.state.Model, o.state.Goal, summary, o.memory)
	if err != nil {
		_ = o.queue.MarkFailed(queueID, truncate(err.Error(), 200))
		dimColor.Printf("  Memory extraction failed: %v\n", err)
		return
	}
	if len(learnings) == 0 {
		_ = o.queue.MarkDone(queueID, "no new learnings extracted")
		dimColor.Printf("  No new learnings extracted.\n")
		return
	}
	if err := o.memory.Save(o.config.WorkDir); err != nil {
		_ = o.queue.MarkFailed(queueID, fmt.Sprintf("save memory: %v", err))
		dimColor.Printf("  Failed to save memory: %v\n", err)
		return
	}
	_ = o.queue.MarkDone(queueID, fmt.Sprintf("saved %d learning(s)", len(learnings)))
	dimColor.Printf("  Saved %d learning(s) to project memory.\n", len(learnings))
}

// checkCostLimit evaluates the current session cost against the configured
// CostLimit. It logs a warning at 80% and returns true (stop) when the limit
// is reached. model and provider come from state/config respectively.
func (o *Orchestrator) checkCostLimit(s *state.ProjectState) (stop bool) {
	if o.config.CostLimit <= 0 {
		return false
	}
	model := s.Model
	if model == "" {
		model = o.config.Model
	}
	usd := cost.EstimateSessionCost(o.config.ProviderName, model, s.TotalInputTokens, s.TotalOutputTokens)
	if usd >= o.config.CostLimit {
		color.New(color.FgRed).Printf(
			"⏸ Cost limit reached (%s). Run 'cloop run' to continue.\n",
			cost.FormatCostWithLimit(usd, o.config.CostLimit),
		)
		return true
	}
	if usd >= o.config.CostLimit*0.8 {
		color.New(color.FgYellow).Printf(
			"  Cost warning: %s (80%% of limit %s)\n",
			cost.FormatCost(usd), cost.FormatCost(o.config.CostLimit),
		)
	}
	return false
}

// printSessionSummary prints a one-line summary after a run session ends.
// It is called via defer so it always runs, even on error paths.
// runOptimizer calls the AI plan optimizer, prints suggestions, and applies
// the reordering automatically (or interactively if OptimizeInteractive is set).
// A snapshot of the pre-optimization plan is saved before any changes.
func (o *Orchestrator) runOptimizer(ctx context.Context, s *state.ProjectState, pmColor, dimColor *color.Color) {
	pmColor.Printf("Running AI plan optimizer...\n")

	queueID := o.enqueueWork(taskqueue.Entry{
		Kind:        taskqueue.KindSession,
		Title:       "AI plan optimizer",
		Description: fmt.Sprintf("optimize plan with %d task(s)", len(s.Plan.Tasks)),
		Source:      "orchestrator",
	})
	_ = o.queue.MarkRunning(queueID)

	result, err := optimizer.Optimize(ctx, o.provider, s.Model, o.config.StepTimeout, s.Plan)
	if err != nil {
		_ = o.queue.MarkFailed(queueID, truncate(err.Error(), 200))
		fmt.Printf("  optimizer: %v (skipping)\n\n", err)
		return
	}

	fmt.Printf("\n")
	pmColor.Printf("Optimizer Result:\n")
	fmt.Printf("  %s\n\n", result.Summary)

	if len(result.Suggestions) > 0 {
		pmColor.Printf("Suggestions:\n")
		for i, sg := range result.Suggestions {
			icon := "i"
			switch sg.Severity {
			case optimizer.SeverityWarning:
				icon = "!"
			case optimizer.SeverityError:
				icon = "x"
			}
			ids := ""
			if len(sg.TaskIDs) > 0 {
				parts := make([]string, len(sg.TaskIDs))
				for j, id := range sg.TaskIDs {
					parts[j] = fmt.Sprintf("#%d", id)
				}
				ids = " [" + strings.Join(parts, ", ") + "]"
			}
			fmt.Printf("  %d. [%s] [%s]%s %s\n", i+1, sg.Type, icon, ids, sg.Description)
		}
		fmt.Println()
	}

	if len(result.Splits) > 0 {
		pmColor.Printf("Suggested Splits:\n")
		for _, sp := range result.Splits {
			fmt.Printf("  Task #%d → %s\n", sp.OriginalID, strings.Join(sp.NewTasks, " | "))
		}
		fmt.Println()
	}

	if len(result.Merges) > 0 {
		pmColor.Printf("Suggested Merges:\n")
		for _, mg := range result.Merges {
			parts := make([]string, len(mg.TaskIDs))
			for i, id := range mg.TaskIDs {
				parts[i] = fmt.Sprintf("#%d", id)
			}
			fmt.Printf("  [%s] → %q\n", strings.Join(parts, " + "), mg.MergedTitle)
		}
		fmt.Println()
	}

	if len(result.ReorderedIDs) == 0 {
		_ = o.queue.MarkDone(queueID, "no reordering suggested")
		dimColor.Printf("  No reordering suggested.\n\n")
		return
	}

	// Show the reordering proposal.
	pmColor.Printf("Suggested Execution Order:\n")
	idToTitle := make(map[int]string, len(s.Plan.Tasks))
	for _, t := range s.Plan.Tasks {
		idToTitle[t.ID] = t.Title
	}
	for i, id := range result.ReorderedIDs {
		fmt.Printf("  %d. #%d %s\n", i+1, id, idToTitle[id])
	}
	fmt.Println()

	// Determine whether to apply the reordering.
	applyReorder := true
	if o.config.OptimizeInteractive {
		fmt.Print("Apply suggested reordering? [y/N] ")
		var answer string
		fmt.Scanln(&answer) //nolint:errcheck
		applyReorder = strings.ToLower(strings.TrimSpace(answer)) == "y"
	}

	if applyReorder {
		// Save pre-optimization snapshot before mutating the plan.
		if snapErr := pm.SaveSnapshot(o.config.WorkDir, s.Plan); snapErr != nil {
			fmt.Printf("  warning: could not save pre-optimization snapshot: %v\n", snapErr)
		}
		optimizer.ApplyReorder(s.Plan, result.ReorderedIDs)
		if err := s.Save(); err != nil {
			fmt.Printf("  warning: could not persist reordered plan: %v\n", err)
		}
		pmColor.Printf("Plan reordered. Updated Task Plan:\n")
		for _, t := range s.Plan.Tasks {
			fmt.Printf("  %d. [P%d] %s\n", t.ID, t.Priority, t.Title)
		}
		fmt.Println()
		_ = o.queue.MarkDone(queueID, fmt.Sprintf("reordered %d task(s)", len(result.ReorderedIDs)))
	} else {
		dimColor.Printf("  Reordering skipped.\n\n")
		_ = o.queue.MarkSkipped(queueID, "user declined reordering")
	}
}

func printSessionSummary(start time.Time, startStep int, s *state.ProjectState) {
	steps := s.CurrentStep - startStep
	elapsed := time.Since(start).Round(time.Second)
	dimColor := color.New(color.Faint)
	dimColor.Printf("Session: %d step(s) in %s", steps, elapsed)
	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		dimColor.Printf(", %d in / %d out tokens (cumulative)", s.TotalInputTokens, s.TotalOutputTokens)
		if s.Model != "" {
			if usd, ok := cost.Estimate(s.Model, s.TotalInputTokens, s.TotalOutputTokens); ok {
				dimColor.Printf(" ≈ %s", cost.FormatCost(usd))
			}
		}
	}
	dimColor.Printf("\n")
}
