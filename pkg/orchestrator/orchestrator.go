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
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/consensus"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/ctxedit"
	"github.com/blechschmidt/cloop/pkg/diagnosis"
	"github.com/blechschmidt/cloop/pkg/diskusage"
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
	"github.com/blechschmidt/cloop/pkg/pausereason"
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
	"github.com/blechschmidt/cloop/pkg/runbuild"
	"github.com/blechschmidt/cloop/pkg/secret"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskqueue"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
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

	// Effort is the reasoning-effort level (low/medium/high/xhigh/max; empty =
	// provider default). Non-empty overrides the effort persisted in project
	// state, mirroring how Model overrides state.Model.
	Effort string

	Verbose     bool
	DryRun      bool
	PMMode      bool
	PlanOnly    bool // only decompose tasks, don't execute them
	RetryFailed bool // retry failed tasks in PM mode
	Replan      bool // force re-decompose goal (wipes existing plan, keeps history)

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

	// TaskTimeoutMinutes is the process-wide default per-task wall-clock
	// budget applied when neither Task.MaxMinutes nor state.DefaultMaxMinutes
	// is set. Zero means "no task timeout" (Task 20148): by default tasks run
	// without any wall-clock deadline. A positive value is an explicit opt-in,
	// validated to [OrchestratorTaskTimeoutMinutesLower, ...Upper]. Sourced
	// from config.Orchestrator.TaskTimeoutMinutes by cmd/run.go.
	TaskTimeoutMinutes int

	// MinFreeDiskMB is the free-space floor in MiB (Task 20381): below it on
	// the volume holding the project's .cloop or the working tree's, no task
	// attempt or evolve round starts and the run pauses disk_low until there
	// is room again. Zero turns the check — and the .cloop/reserve file behind
	// it — off. cmd/run.go resolves it from orchestrator.min_free_disk_mb,
	// where unset means config.MinFreeDiskMBDefault; a Config built in code,
	// as tests build them, gets no check unless it asks for one.
	MinFreeDiskMB int

	// ProviderModels maps a provider name to the model config.yaml names for
	// it (anthropic.model, openai.model, ...). The review gate uses it when
	// its reviewer runs on another provider than the work and names no model
	// (Task 20357).
	ProviderModels map[string]string

	// ReviewProvider, when set, is the review gate's reviewer, whatever the
	// project's gate names; tests use it. Nil builds the reviewer from
	// ProviderCfg. ReviewGateHelper overrides the program that holds the
	// agent's pushes (default: this executable's review-gate-remote-helper).
	ReviewProvider   provider.Provider
	ReviewGateHelper []string

	// Handoff is what the image this process replaced handed over when it
	// adopted a newer build at a task boundary (Task 20389); cmd/run.go reads
	// it from CLOOP_RUN_HANDOFF. Resumed is set whenever that variable was
	// present, even when the file could not be read (HandoffError says why):
	// the process is continuing a run either way, so it must not do what a
	// fresh run does at its start — re-plan, reset failed tasks, optimise, run
	// the pre_plan hook, announce itself again.
	Handoff      *runbuild.Handoff
	Resumed      bool
	HandoffError string
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
	statedb     *statedb.DB        // shared SQLite handle (kill_requests, events journal); nil-safe
	watchdog    *watchdog.Watchdog // per-task cancel registry for manual aborts (Task 20140); nil-safe

	// testAbortWaitCeiling and testAbortBackoff narrow maxAbortWait and
	// abortBackoff so tests can exercise the abort paths without sleeping out
	// a real usage window. Zero means the production value. See
	// abortWaitCeiling and abortRetryBackoff.
	testAbortWaitCeiling time.Duration
	testAbortBackoff     time.Duration

	// testNow replaces the wall clock for the abort and subscription-cap
	// policy, so a test can put a usage window's reset in the past instead of
	// sleeping until one really rolls over. Nil means time.Now. See now().
	testNow func() time.Time

	// diskProbe replaces diskusage.Volumes for the free-space floor (Task
	// 20381), so a test can put a volume below the floor without filling one;
	// testDiskPoll shortens the minute a disk_low pause waits between checks.
	// Nil and zero mean the production behaviour. See diskfloor.go.
	diskProbe    func(paths ...string) ([]diskusage.Volume, error)
	testDiskPoll time.Duration

	// diskMu guards what the floor remembers between checks: the note left
	// by a write that needed the reserve (consumed by the next check, which
	// then pauses), and whether a probe or reserve failure was already
	// reported. Verdicts are written from parallel workers, so the reserve
	// can be spent off the main goroutine.
	diskMu          sync.Mutex
	reserveSpent    string
	diskProbeWarned bool
	reserveWarned   bool

	// capWarnMu guards the rate-limiting of the "subscription caps are not
	// being enforced" warning, which is reached before every task and so
	// would otherwise repeat once per task for as long as usage is
	// unreadable. See warnCapsUnenforced.
	capWarnMu   sync.Mutex
	capWarnAt   time.Time
	capWarnLast string

	// requeued records which tasks this run's stale-task recovery reset to
	// pending, so the interactive skip prompt is offered only for work that
	// still has to happen — never for a task whose finished outcome was
	// adopted from a dead run's live artifact. Guarded because recovery runs
	// before the worker pool starts but the map outlives it.
	requeuedMu sync.Mutex
	requeued   map[int]bool

	// killWG tracks the goroutine that polls kill_requests for manual aborts
	// (Task 20140). The orchestrator's Run() spawns it under the run context
	// and waits on this group during Close so the loop exits cleanly.
	killWG sync.WaitGroup

	// killObserved maps task ID → the attempt token this process has seen
	// running while that task's kill row was pending. A request may only
	// rewrite a task's status once its attempt appears here, which is what
	// keeps a row left over from an earlier run from re-applying itself to a
	// task the operator has since reset (Task 20203). Guarded by killMu
	// because tests drive processPendingKills off the poller goroutine.
	killMu       sync.Mutex
	killObserved map[int]string

	// liveDeadlines tracks per-task cancellable budgets so changes to
	// task.MaxMinutes / state.DefaultMaxMinutes made via the Web UI take
	// effect on the currently-running task within a few seconds rather
	// than only on the next one (Task 20143).
	liveDeadlines *liveDeadlineRegistry

	// reviewers caches the review gate's reviewer providers by provider
	// name for the run (Task 20357). Guarded: parallel workers review
	// concurrently.
	reviewersMu sync.Mutex
	reviewers   map[string]provider.Provider

	// Adopting newer builds at task boundaries (Task 20389); see adopt.go.
	// selfBuild is this image's build, owner the run-owner record it wrote,
	// carry the run's bookkeeping across loop entries and images,
	// refusedFiles the binaries already refused (so following new builds asks
	// each deployed file once), adoptNotes the conditions already journalled,
	// and handingOver tells the loops' deferred end-of-run work that the run
	// is not ending but moving.
	adopt         adoptHooks
	selfBuild     runbuild.Build
	owner         *runbuild.Owner
	carry         *runCarry
	refusedFiles  map[runbuild.FileID]bool
	adoptFailures map[runbuild.FileID]int
	adoptNotes    map[string]bool
	handingOver   bool
}

func New(cfg Config, prov provider.Provider) (*Orchestrator, error) {
	s, err := state.Load(cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	// All work is tracked through the PM task pipeline; non-PM mode was removed
	// in Task 20067 so every change is visible in the task list and auditable.
	s.PMMode = true
	// The command line's overrides are the run's first image's to apply. An
	// image that took the run over (Task 20389) continues on the settings as
	// stored, which the dashboard may have changed since — reapplying the
	// same flags or config defaults would quietly undo that.
	if !cfg.Resumed {
		if cfg.Model != "" {
			s.Model = cfg.Model
		}
		if cfg.Effort != "" {
			s.Effort = cfg.Effort
		}
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
	}
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

	// Open the shared state DB for the kill-request poller (Task 20140) and
	// the events journal. Open failure is non-fatal — every consumer is
	// nil-safe, so degraded operation just loses manual aborts and journal
	// rows for this run.
	stateDBPath := filepath.Join(s.WorkDir, ".cloop", "state.db")
	sdb, dbErr := statedb.Open(stateDBPath)
	if dbErr != nil {
		log.Warn(logger.EventSessionStart, 0, "statedb unavailable", map[string]interface{}{
			"error": dbErr.Error(),
			"path":  stateDBPath,
		})
		sdb = nil
	} else {
		// This is the handle every task.dispatch and task.finish row is written
		// through. Marking it as a project handle is what makes a fleet-homed
		// event emitted here — an executor or secret action that should have
		// gone to the hub — fail loudly instead of landing in the plan's chain.
		sdb.AsProject()
	}

	// The watchdog is a plain per-task cancel registry: the kill-request
	// poller fires the registered cancel when an operator aborts a running
	// task from the UI (Task 20140).
	o := &Orchestrator{config: cfg, state: s, provider: prov, router: r, memory: mem, webhook: wh, metrics: cfg.Metrics, envVars: envVars, secretStore: secretStore, log: log, queue: queue, statedb: sdb, watchdog: &watchdog.Watchdog{}, liveDeadlines: newLiveDeadlineRegistry()}
	o.adopt = defaultAdoptHooks()
	o.selfBuild = state.SelfBuild()
	o.refusedFiles = map[runbuild.FileID]bool{}
	o.adoptFailures = map[runbuild.FileID]int{}
	o.adoptNotes = map[string]bool{}
	// An image that took over from another continues its process: the same
	// start time for attribution, the same execution id for its tasks — from
	// the handoff, or, if that was lost, from the record the previous image
	// left about this very process.
	if cfg.Handoff != nil {
		inheritFromHandoff(cfg.Handoff)
	} else if cfg.Resumed && s.RunOwner != nil {
		if id, err := o.adopt.self(); err == nil && s.RunOwner.Ident.Same(id) {
			inheritFromHandoff(&runbuild.Handoff{RunID: s.RunOwner.RunID, ProcessStart: s.RunOwner.StartedAt})
		}
	}

	// Persist the command line's overrides so the loop's SyncFromDisk reads
	// them back rather than overwriting them from the stored state:
	// mergeExternalTasks copies these toggles disk → memory, so a merging
	// write — or none — would quietly put the run back on the stored settings.
	// A run that cannot store them would not run as asked, so it does not
	// start. An image that took the run over applied none (see above).
	if !cfg.Resumed {
		if err := o.persist(s, "this run's command-line settings (parallel, worktrees, innovate)", replacePlan); err != nil {
			o.closeStores()
			return nil, err
		}
	}
	return o, nil
}

// closeStores releases the database handles New opened, for a New that fails
// after opening them. Unlike Close it touches no queue entries: a run that
// never started has nothing to settle, and the entries it would mark could
// belong to a run that is very much alive.
func (o *Orchestrator) closeStores() {
	if o.statedb != nil {
		_ = o.statedb.Close()
		o.statedb = nil
	}
	if o.queue != nil {
		_ = o.queue.Close()
		o.queue = nil
	}
}

// Close releases resources held by the orchestrator. Safe to call multiple times.
// Any queue entries still in "running" are marked failed (interrupted) before
// the database is closed.
func (o *Orchestrator) Close() error {
	if o == nil {
		return nil
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
//  3. config.Orchestrator.TaskTimeoutMinutes (process-wide opt-in)
//
// The first positive value wins. When none is set the function returns 0,
// meaning "no task timeout" (Task 20148): by default tasks run without any
// wall-clock deadline, so a long-running task is never killed simply for
// taking a while. A timeout only applies when an operator explicitly opts in
// via one of the three layers above. This helper is accessible from the
// package so handleTaskTimeout and the on-screen timeout banner can report
// the same number that the deadline actually used.
func (o *Orchestrator) effectiveTaskBudgetMinutes(task *pm.Task) int {
	if task != nil && task.MaxMinutes > 0 {
		return task.MaxMinutes
	}
	if o.state != nil {
		// Locked read: parallel workers call this while the kill poller's
		// Save can rewrite DefaultMaxMinutes from a UI toggle.
		if def := o.state.LiveDefaultMaxMinutes(); def > 0 {
			return def
		}
	}
	if o.config.TaskTimeoutMinutes > 0 {
		// Defensively clamp to the same band the loader enforces so a hand-
		// constructed Config{TaskTimeoutMinutes: -1} (in tests, callers that
		// bypass cmd/run.go) doesn't arm a bogus deadline.
		if o.config.TaskTimeoutMinutes >= config.OrchestratorTaskTimeoutMinutesLower &&
			o.config.TaskTimeoutMinutes <= config.OrchestratorTaskTimeoutMinutesUpper {
			return o.config.TaskTimeoutMinutes
		}
	}
	// No explicit budget configured anywhere → no task timeout.
	return 0
}

// taskContextWithTimeout returns a context (and cancel) scoped to the given task's
// time budget. The budget is resolved by effectiveTaskBudgetMinutes. When that
// returns 0 (the default after Task 20148: tasks have no timeout), the returned
// context carries no wall-clock deadline — it is only cancelled by the parent
// context or a manual kill. A positive budget arms a deadline as before (the
// explicit opt-in path). The returned cancel is registered under task.ID in
// the watchdog cancel registry (for manual aborts, Task 20140) and
// de-registered when invoked, so the same cancel cannot accidentally fire
// twice.
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
	var (
		taskCtx    context.Context
		taskCancel context.CancelFunc
	)
	switch {
	case maxMin <= 0:
		// No timeout configured (the default; Task 20148). Inherit the parent
		// context with a plain cancel — the task runs until it finishes, the
		// parent is cancelled, or it is killed manually. We
		// still route ID-bearing tasks through liveDeadlines so an operator who
		// later opts a running task into a budget via the UI is picked up by the
		// poller (which arms a timer on the first positive budget it sees).
		if task != nil && task.ID > 0 && o.liveDeadlines != nil {
			taskCtx, taskCancel = o.liveDeadlines.startTaskDeadline(ctx, task.ID, 0, taskTimeoutUnit)
		} else {
			taskCtx, taskCancel = context.WithCancel(ctx)
		}
	case task != nil && task.ID > 0 && o.liveDeadlines != nil:
		// When a task ID is available we route through liveDeadlines so the
		// background poller can resize the deadline mid-flight (Task 20143).
		taskCtx, taskCancel = o.liveDeadlines.startTaskDeadline(ctx, task.ID, maxMin, taskTimeoutUnit)
	default:
		// Tasks without a usable ID (e.g. evolve discovery, plan compaction)
		// fall back to a vanilla context.WithTimeout — no UI ever points at
		// them, so a live deadline registry entry would just be dead weight.
		taskCtx, taskCancel = context.WithTimeout(ctx, time.Duration(maxMin)*taskTimeoutUnit)
	}
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
// the per-task context (not the parent session context) was the one that
// expired. The liveDeadlines path (Task 20143) uses context.WithCancelCause
// rather than context.WithTimeout so that mid-flight budget adjustments can
// shorten/extend the deadline; in that case taskCtx.Err() is context.Canceled,
// but context.Cause(taskCtx) carries the original DeadlineExceeded sentinel.
// Check both so timeouts are recognised on either code path.
func isTimeoutErr(taskCtx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if taskCtx.Err() == context.DeadlineExceeded {
		return true
	}
	return errors.Is(context.Cause(taskCtx), context.DeadlineExceeded)
}

// handleTaskTimeout marks the task as timed_out, stores that, and only then
// fires the desktop and webhook notifications (Task 20108). It always writes
// an artifact entry, even when the provider returned no partial output, so
// post-mortem inspection always finds a trace of the timeout. The effective
// budget is resolved via effectiveTaskBudgetMinutes so the value reported to
// the user, the annotation, and the webhook all match the deadline that
// actually fired — task.MaxMinutes alone may be 0 when the cancellation was
// triggered by the project-level or process-wide default.
//
// mu guards the task in the parallel loop, where other workers save while this
// runs; the sequential loop passes nil. It is held across the change and the
// write, and released before the notifications, which go out over the network.
// The returned error is the write's and must end the run.
func (o *Orchestrator) handleTaskTimeout(_ context.Context, s *state.ProjectState, task *pm.Task, partialOutput string, dimColor *color.Color, mu sync.Locker) error {
	if mu != nil {
		mu.Lock()
	}
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
	err := o.persistOutcome(s, task, "timeout", decidedBy(taskrecover.SourceTimeout, "task_timeout", reasonMsg))
	done, failed := s.Plan.CountByStatus()
	total := len(s.Plan.Tasks)
	if mu != nil {
		mu.Unlock()
	}
	if err != nil {
		return err
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
	o.webhook.Send(webhook.EventTaskFailed, webhook.Payload{
		Goal: s.Goal,
		Task: &webhook.TaskInfo{
			ID:     task.ID,
			Title:  task.Title,
			Status: "timed_out",
		},
		Progress: &webhook.Progress{Done: done, Total: total, Failed: failed},
		Session:  &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
	})
	o.log.Error(logger.EventTaskFailed, task.ID, task.Title, map[string]interface{}{
		"reason":         "timed_out",
		"budget_minutes": budgetMin,
	})
	return nil
}

// failRun ends the run as failed: it stores the status, then announces it —
// the session_failed webhook and a session_failed row in the event journal,
// so the dashboard's history says why the run ended — and returns cause. A
// status that cannot be stored ends the run all the same, with both errors.
func (o *Orchestrator) failRun(s *state.ProjectState, cause error) error {
	s.Status = "failed"
	if err := o.persist(s, fmt.Sprintf("the run's status (failed: %v)", cause)); err != nil {
		return errors.Join(cause, err)
	}
	o.webhook.Send(webhook.EventSessionFailed, webhook.Payload{
		Goal:    s.Goal,
		Session: &webhook.SessionInfo{InputTokens: s.TotalInputTokens, OutputTokens: s.TotalOutputTokens},
		Error:   webhook.TruncateError(cause.Error()),
	})
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:    state.EventSessionFailed,
		Step:    state.NoStep,
		Message: "Run failed: " + cause.Error(),
	}, map[string]any{"error": cause.Error()})
	return cause
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
	o.persistBestEffort(o.state, "a --continue raise of the step limit",
		"this run already honours it, and every later write stores it too")
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
	case pm.TaskPending:
		// Not a terminal outcome: the run aborted and the task was returned
		// to the queue. abortTask already journalled EventTaskAborted with
		// the reason, and emitting a "completed (implicit)" row here — which
		// the default arm below would do — is precisely the accounting error
		// this whole path exists to correct (Task 20211).
		return
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
		// Where the work ran, carried on the terminal record so the journal
		// answers "what ran on the host" without joining back to the task
		// table — and still answers it for a task later deleted (Task 20244).
		"executor_id":   task.ExecutorID,
		"executor_kind": task.ExecutorKind,
		"isolation":     task.Isolation,
	})
}

// SetAutoEvolve switches auto-evolve for this run and the ones after it.
//
// The write replaces rather than merges, for the reason New's does: a merging
// write starts by copying the stored toggles over the ones in memory, so on a
// project with a plan it stored the old setting straight back, and so does
// every SyncFromDisk after it. The error matters for the same reason — a
// setting that did not reach the database is gone at the loop's first sync.
func (o *Orchestrator) SetAutoEvolve(enabled bool) error {
	o.state.AutoEvolve = enabled
	return o.persist(o.state, "the auto-evolve setting", replacePlan)
}

// SetProvider persists the provider name in state so subsequent runs default to the same provider.
func (o *Orchestrator) SetProvider(name string) {
	if name != "" {
		o.state.Provider = name
		o.persistBestEffort(o.state, "the provider later runs default to",
			"this run already has its provider, and every later write stores it too")
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
		// Best-effort: when both fresh fetch and cache fail, skip enforcement
		// rather than blocking work on a monitoring outage. But say so — caps
		// the operator configured are not being applied right now, and a dead
		// credential can keep it that way indefinitely. This one went unnoticed
		// for four days (Task 20202) precisely because it was silent.
		o.warnCapsUnenforced(err)
		return nil
	}
	return ratelimit.EnforceClaudeCodeLimits(cc, usage)
}

// capWarnInterval throttles the unenforced-caps warning. The check runs before
// every task, so an unthrottled warning would bury the step log.
const capWarnInterval = 15 * time.Minute

// warnCapsUnenforced reports that configured subscription caps are not being
// applied because usage could not be read, at most once per capWarnInterval —
// and immediately whenever the reason changes, so a transient outage turning
// into "you must log in again" is never swallowed by the throttle.
func (o *Orchestrator) warnCapsUnenforced(cause error) {
	msg := cause.Error()

	o.capWarnMu.Lock()
	throttled := msg == o.capWarnLast && time.Since(o.capWarnAt) < capWarnInterval
	if !throttled {
		o.capWarnAt, o.capWarnLast = time.Now(), msg
	}
	o.capWarnMu.Unlock()
	if throttled {
		return
	}

	fields := map[string]interface{}{"error": msg}
	// Point at the fix when there is one, rather than leaving the operator to
	// infer that a monitoring error is really a login prompt.
	var authErr *ratelimit.AuthError
	if errors.As(cause, &authErr) {
		fields["reauth_required"] = true
		fields["hint"] = authErr.Hint()
	}
	o.log.Warn(logger.EventSessionStart, 0,
		"claude code subscription caps are NOT being enforced: usage is unreadable", fields)
}

func (o *Orchestrator) Run(ctx context.Context) error {
	// Close the central work queue on Run() exit so the underlying SQLite
	// connection (and any goroutines it owns) is released. The orchestrator
	// is a one-shot value — callers Build → Run → discard. Re-using the
	// orchestrator after Run would already misbehave (state/plan are baked
	// in at New time), so closing here is safe.
	defer o.Close()
	o.settleReserve()
	// Which process and build this run is (Task 20389), for the dashboard,
	// `cloop status` and hub doctor to compare with theirs.
	o.recordRunOwner()
	for {
		// Background pollers run under a child context that is cancelled
		// before Close() so their goroutines exit even when the caller passed
		// an unbounded ctx (e.g. context.Background() in tests).
		pollCtx, pollCancel := context.WithCancel(ctx)
		// Manual-abort poller (Task 20140): polls kill_requests rows the UI
		// inserts when an operator changes a running task's status, and fires
		// the watchdog-registered cancel for that task.
		o.startKillPoller(pollCtx)
		// Live-deadline poller (Task 20143): re-reads per-task / per-project
		// task-timeout values from disk every few seconds and adjusts the
		// timer on any in-flight task whose budget changed.
		o.startDeadlinePoller(pollCtx)
		err := o.runPM(ctx)
		// The pollers write state too, so they stop before the last word —
		// and before an exec, which would cut a write of theirs in half.
		pollCancel()
		o.killWG.Wait()
		var ad *adoptBuild
		if errors.As(err, &ad) {
			// Returns only if the exec failed or the run was stopped; the
			// loop then goes on here — or pauses, for a stop.
			o.handOver(ctx, ad)
			continue
		}
		if errors.Is(err, ErrStateNotPersisted) {
			o.recordAbort(err)
		}
		return err
	}
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
	return o.state.LiveMaxParallel() > 1
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

	for {
		var runErr error
		if o.wantParallel() {
			runErr = o.runPMParallel(ctx)
		} else {
			runErr = o.runPMSequential(ctx)
		}
		if errors.Is(runErr, errSwitchMode) {
			color.New(color.FgMagenta, color.Bold).Printf("↻ Mode switch (parallel=%v, max_parallel=%d) — re-dispatching loop\n",
				o.state.Parallel, o.state.LiveMaxParallel())
			continue
		}
		return runErr
	}
}

// runPMSequential runs PM tasks one at a time (original behaviour).
func (o *Orchestrator) runPMSequential(ctx context.Context) error {
	s := o.state

	// Recover stale tasks from prior interrupted runs.
	if err := o.recoverStaleTasks(s); err != nil {
		return err
	}

	s.Status = "running"
	if err := o.persist(s, "the run's status (running)"); err != nil {
		return err
	}

	// fresh is false when this loop is entered by a mode switch or by an
	// image that took the run over from another (Task 20389): the session,
	// its counters and its start-of-run work belong to the run, not the loop.
	fresh, carry := o.enterLoop(s)
	sessionStart := carry.sessionStart
	startStep := carry.sessionStartStep
	defer func() {
		// A run handing itself to a newer build is not ending: its next image
		// learns from the session and summarises it when the run does end.
		if o.handingOver {
			return
		}
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

	if !o.log.IsJSON() && fresh {
		header.Printf("\n🧠 cloop PM — AI Product Manager Mode\n")
		fmt.Printf("   Provider: %s\n", o.provider.Name())
		fmt.Printf("   Goal: %s\n", s.Goal)
		fmt.Println()
	}
	if fresh {
		o.log.Info(logger.EventSessionStart, 0, "session started", map[string]interface{}{
			"goal":     s.Goal,
			"mode":     "pm",
			"trace_id": clooptracing.TraceIDFromContext(ctx),
		})
		o.webhook.Send(webhook.EventSessionStarted, webhook.Payload{Goal: s.Goal})
		o.logRunStarted(s)
	}

	// If --replan requested, clear existing plan and force re-decomposition.
	if fresh && o.config.Replan && s.Plan != nil {
		pmColor.Printf("Replanning: clearing existing plan (%d tasks) and re-decomposing.\n\n", len(s.Plan.Tasks))
		s.Plan = nil
		if err := o.persist(s, "the plan cleared for --replan"); err != nil {
			return err
		}
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
		o.queueRunning(decomposeQueueID)
		plan, err := pm.Decompose(ctx, o.provider, s.Goal, s.Instructions, s.Model, o.config.StepTimeout, clarifyCtx)
		if err != nil {
			o.queueFailed(decomposeQueueID, truncate(err.Error(), 200))
			failColor.Printf("x Failed to decompose goal: %v\n", err)
			return o.failRun(s, fmt.Errorf("decomposing the goal: %w", err))
		}
		if o.config.CalibrationFactor != 0 && o.config.CalibrationFactor != 1.0 {
			pm.ApplyCalibrationFactor(plan, o.config.CalibrationFactor)
		}
		s.Plan = plan
		if err := o.persist(s, "the plan decomposed from the goal"); err != nil {
			return err
		}
		o.queueDone(decomposeQueueID, fmt.Sprintf("decomposed into %d task(s)", len(plan.Tasks)))

		fmt.Printf("\n")
		pmColor.Printf("Task Plan (%d tasks):\n", len(plan.Tasks))
		for _, t := range plan.Tasks {
			fmt.Printf("  %d. [P%d] %s\n", t.ID, t.Priority, t.Title)
			dimColor.Printf("       %s\n", truncate(t.Description, 120))
		}
		fmt.Println()
	} else {
		// If retry-failed is set, reset failed tasks to pending — except a
		// suspected node killer, which only an explicit reset releases
		// (Task 20391).
		if fresh && o.config.RetryFailed {
			retried := 0
			for _, t := range s.Plan.Tasks {
				if t.Status == pm.TaskFailed && !t.Quarantined() {
					t.Status = pm.TaskPending
					retried++
				}
			}
			if retried > 0 {
				if err := o.persist(s, "failed tasks reset to pending by --retry-failed"); err != nil {
					return err
				}
				pmColor.Printf("Retrying %d failed task(s).\n\n", retried)
			}
		}
		pmColor.Printf("Resuming plan: %s\n\n", s.Plan.Summary())
	}

	// Optimization pass: AI reviews the plan before execution.
	if fresh && o.config.Optimize && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		if err := o.runOptimizer(ctx, s, pmColor, dimColor); err != nil {
			return err
		}
	}

	// Plan-only mode: just show the plan, don't execute
	if fresh && o.config.PlanOnly {
		s.SetPaused(pausereason.New(pausereason.CodePlanOnly,
			"plan-only mode: the plan was generated but not executed"))
		return o.persist(s, "the pause (plan-only mode)")
	}

	// Stale in-progress recovery: a task still marked in_progress means the
	// previous run died while holding it. Recovery is adoption-first — where
	// the agent had already reported an outcome, that outcome is taken from the
	// live artifact instead of the task being executed a second time; where it
	// had not, the task returns to pending. See pkg/taskrecover for why the
	// live artifact is trustworthy evidence.
	//
	// This must happen before scheduling: NextTask() only returns pending
	// tasks, so an in_progress task is otherwise skipped forever.
	if err := o.recoverStaleTasks(s); err != nil {
		return err
	}

	// An operator at a terminal may prefer to skip a task that was re-queued
	// rather than watch it fail again. Adopted tasks are not offered — there is
	// nothing left to decide about work that is already finished.
	if fresh && clarify.IsTTY() {
		for _, t := range s.Plan.Tasks {
			if t == nil || t.Status != pm.TaskPending || !o.wasRequeued(t.ID) {
				continue
			}
			fmt.Printf("Retry task %d or skip it? [r]etry / [s]kip: ", t.ID)
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				break
			}
			if answer := strings.ToLower(strings.TrimSpace(scanner.Text())); answer == "s" || answer == "skip" {
				t.Status = pm.TaskSkipped
				pm.AddAnnotation(t, "ai", "Task skipped at stale-task recovery (operator chose 'skip' after a previously interrupted run).")
				if err := o.persistOutcome(s, t, "skip, chosen by the operator at stale-task recovery",
					decidedBy(taskrecover.SourceOperator, "operator_skip", "the operator chose to skip it at stale-task recovery")); err != nil {
					return err
				}
				dimColor.Printf("→ Task %d skipped.\n\n", t.ID)
			}
		}
	}

	// Pre-plan hook: run once before execution starts — once per run, not
	// again when a mode switch or an adopted build re-enters the loop.
	if fresh {
		if err := hooks.RunPrePlan(o.config.Hooks, hooks.PlanContext{
			Goal:  s.Goal,
			Total: len(s.Plan.Tasks),
		}, o.allEnvLines()...); err != nil {
			failColor.Printf("✗ pre_plan hook failed: %v — aborting plan execution.\n", err)
			return o.failRun(s, err)
		}
	}

	// Post-plan hook: runs when plan finishes (done or paused) — not when the
	// run hands itself to a newer build, which is neither (Task 20389).
	defer func() {
		if o.handingOver {
			return
		}
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

	consecutiveErrors := carry.errors
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
	consecutiveEmptyEvolves := carry.emptyEvolves
	const maxEmptyEvolves = 3

	// Per-task context bookkeeping. The cancel for each iteration is invoked
	// at the top of the next iteration (or by the deferred call on return)
	// rather than via a loop-local `defer` — a defer inside this unbounded
	// loop would accumulate cancels/timers/liveDeadline registry entries for
	// the whole run. All uses of taskCtx happen within a single iteration, so
	// releasing it once the next iteration begins is safe.
	var (
		taskCtx    context.Context
		taskCancel context.CancelFunc
		// activeGate is the review gate's hold on the current task's pushes
		// (Task 20357), released the same way and for the same reason.
		activeGate *gateRun
	)
	defer func() {
		if taskCancel != nil {
			taskCancel()
		}
		activeGate.close()
	}()

	for {
		// Release the previous iteration's per-task context before starting
		// a new one (see the declaration above for why this is not a defer).
		if taskCancel != nil {
			taskCancel()
			taskCancel = nil
		}
		activeGate.close()
		activeGate = nil

		select {
		case <-ctx.Done():
			s.SetPaused(pausereason.New(pausereason.CodeCancelled, "run interrupted"))
			if err := o.persist(s, "the pause (run interrupted)"); err != nil {
				return errors.Join(ctx.Err(), err)
			}
			return ctx.Err()
		default:
		}

		if o.config.StepsLimit > 0 && s.CurrentStep >= startStep+o.config.StepsLimit {
			s.SetPaused(pausereason.New(pausereason.CodeStepLimit,
				fmt.Sprintf("--steps limit of %d reached", o.config.StepsLimit)))
			if err := o.persist(s, "the pause (--steps limit reached)"); err != nil {
				return err
			}
			color.New(color.FgYellow).Printf("⏸ Reached --steps limit (%d). Run 'cloop run' to continue.\n", o.config.StepsLimit)
			return nil
		}

		// Token budget check at the top of the loop so it fires during evolve cycles
		// (where the work-execution path's check would otherwise be skipped).
		if o.config.TokenBudget > 0 && s.TotalInputTokens+s.TotalOutputTokens >= o.config.TokenBudget {
			s.SetPaused(pausereason.New(pausereason.CodeTokenBudget,
				fmt.Sprintf("token budget of %d tokens spent", o.config.TokenBudget)))
			if err := o.persist(s, "the pause (token budget reached)"); err != nil {
				return err
			}
			color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
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
			o.queueDone(extID, fmt.Sprintf("merged from disk (status=%s)", t.Status))
		}
		// Reactivate recurring tasks whose schedule has fired.
		for _, t := range s.Plan.Tasks {
			if pm.ResetIfDue(t, time.Now()) {
				dimColor.Printf("↺ Task %d recurring: reset to pending (%s)\n", t.ID, t.Recurrence)
				o.persistBestEffort(s, "a recurring task's reset to pending",
					"every later write stores it, and if none lands the schedule, still due on disk, fires again at the next start")
			}
		}
		// Mid-run mode switch: if the user enabled parallel mode (or set
		// max_parallel > 1) via the Web UI while we were sequential, surrender
		// so runPM can re-dispatch into runPMParallel without a process restart
		// (Task 20111). We're at the top of the loop with no task in flight, so
		// switching is safe — the next iteration starts fresh in the new mode.
		carry.errors, carry.emptyEvolves = consecutiveErrors, consecutiveEmptyEvolves
		if o.wantParallel() {
			return errSwitchMode
		}
		// A newer build of cloop, when the project follows new builds or the
		// run was asked to adopt one: the run hands itself over here, between
		// tasks and before any evolve round, with nothing in flight (Task 20389).
		if err := o.atTaskBoundary(ctx, s, carry, false); err != nil {
			return err
		}
		// A plan may not finish — or evolve — on the strength of an error
		// message. Any task recorded as done whose summary is a provider or
		// harness refusal goes back to pending here, before IsComplete is
		// asked (Task 20224).
		if n := o.sweepAbortedOutcomes(s); n > 0 {
			color.New(color.FgYellow).Printf(
				"↻ %d task(s) recorded as done never actually ran — reopened before checking completion\n", n)
			continue
		}
		if s.Plan.IsComplete() {
			// An evolve round is work like a task: it asks the provider for
			// more and writes what comes back. Checked before the plan's
			// completion is announced, so a run that waits for disk space
			// does not announce it twice (Task 20381).
			if s.AutoEvolve {
				if waited, err := o.awaitDiskSpace(ctx, s, nil, "an evolve round"); err != nil {
					return err
				} else if waited {
					continue
				}
			}
			// A run that ends here stores that it did before saying so. One
			// that goes on to evolve announces only what the tasks already
			// recorded.
			if !s.AutoEvolve {
				s.Status = "complete"
				if err := o.persist(s, "the run's status (complete)"); err != nil {
					return err
				}
			}
			if !o.log.IsJSON() {
				line, achieved := settlementLine(s.Plan, s.AutoEvolve)
				banner := successColor
				if !achieved {
					banner = color.New(color.FgYellow, color.Bold)
				}
				banner.Printf("%s\n", line)
				banner.Printf("   %s\n\n", s.Plan.Summary())
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
				Step:    state.NoStep,
				Message: fmt.Sprintf("All %d tasks complete", len(s.Plan.Tasks)),
			}, map[string]any{
				"total":    len(s.Plan.Tasks),
				"done":     done,
				"failed":   failed,
				"duration": time.Since(sessionStart).Round(time.Second).String(),
			})
			if s.AutoEvolve {
				s.Status = "evolving"
				o.persistBestEffort(s, "the run's status (evolving)",
					"it only tells the dashboard which phase is running, and the next write replaces it")
				n, err := o.evolvePM(ctx)
				if err != nil {
					// The discovered tasks did not reach the database: the
					// run stops on that, not on the evolve round.
					if errors.Is(err, ErrStateNotPersisted) {
						return err
					}
					// Cancellation (Ctrl-C, deadline) is an interruption, not a
					// completed session — pause so the next run resumes evolving.
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
						s.SetPaused(pausereason.New(pausereason.CodeCancelled,
							"run interrupted while evolving the plan"))
						if saveErr := o.persist(s, "the pause (run interrupted while evolving)"); saveErr != nil {
							return errors.Join(err, saveErr)
						}
						color.New(color.FgMagenta, color.Bold).Printf("\n⏹ Evolve interrupted: %v\n", err)
						if ctxErr := ctx.Err(); ctxErr != nil {
							return ctxErr
						}
						return err
					}
					s.Status = "complete"
					if saveErr := o.persist(s, "the run's status (complete: evolve stopped)"); saveErr != nil {
						return saveErr
					}
					color.New(color.FgMagenta, color.Bold).Printf("\n⏹ Evolve stopped: %v\n", err)
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
						s.Status = "complete"
						if err := o.persist(s, "the run's status (complete: auto-evolve found nothing new)"); err != nil {
							return err
						}
						color.New(color.FgYellow).Printf("⏸ Auto-evolve found no new tasks in %d consecutive attempts and no token/step budget is set. Stopping.\n", maxEmptyEvolves)
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
			// Stored before the announcements above it ran (see the top of
			// this block).
			return nil
		}

		// Deadline check: boost overdue task priorities and fire notifications each iteration.
		{
			results := pm.CheckAndBoostOverdue(s.Plan)
			for _, r := range results {
				if r.Boosted {
					o.persistBestEffort(s, "an overdue task's priority boost",
						"the deadline check recomputes it from the stored deadline every iteration")
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
				o.persistBestEffort(s, "auto-promoted task priorities",
					"auto-promote recomputes them from the stored deadlines every iteration")
				for _, p := range promotions {
					color.New(color.FgYellow, color.Bold).Printf(
						"\u2191 Task %d promoted P%d→P%d (%s): %s\n",
						p.TaskID, p.OldPriority, p.NewPriority, p.Reason, p.Title,
					)
				}
			}
		}

		// Decide what runs: dependencies, the blocked sweep, the tag filter and
		// the condition gate, all in GateTasks so this path and runPMParallel
		// cannot disagree about the outcome or how it is worded.
		gate := GateTasks(ctx, s.Plan, o.gateConfig(false))
		if gate.Skipped() > 0 {
			if err := o.persist(s, fmt.Sprintf("the execution gate's skips (tasks %v)", gate.SkippedIDs())); err != nil {
				return err
			}
		}
		printGateDecision(gate, failColor, dimColor)
		if len(gate.Runnable) == 0 {
			if gate.Exhausted {
				break
			}
			continue
		}
		task := gate.Runnable[0]

		// Check max steps limit
		if s.MaxSteps > 0 && s.CurrentStep >= s.MaxSteps {
			s.SetPaused(pausereason.New(pausereason.CodeStepLimit,
				fmt.Sprintf("project max-steps limit of %d reached", s.MaxSteps)))
			if err := o.persist(s, "the pause (project max-steps limit reached)"); err != nil {
				return err
			}
			color.New(color.FgYellow).Printf("⏸ Reached max steps (%d). Run 'cloop run' to continue.\n", s.MaxSteps)
			return nil
		}

		// Daily budget enforcement: abort before spending tokens if any limit is exceeded.
		if budgetErr := budget.Enforce(o.config.WorkDir, o.config.Budget, o.config.NotifyCfg); budgetErr != nil {
			s.SetPaused(pausereason.New(pausereason.CodeBudget, budgetErr.Error()))
			if err := o.persist(s, "the pause (budget limit reached)"); err != nil {
				return errors.Join(budgetErr, err)
			}
			failColor.Printf("\n✗ Budget limit reached: %v\n", budgetErr)
			return budgetErr
		}

		// Per-project claudecode subscription cap enforcement. A cap whose
		// window reopens soon is waited out in place rather than ending the
		// run; a distant one pauses with the reset recorded as resumes_at, so
		// the hub can restart it without a human (Task 20285). Shared by both
		// loops so the sequential and parallel paths cannot disagree about
		// what a cap means.
		if ccErr := o.enforceClaudeCodeLimits(); ccErr != nil {
			stop, err := o.handleUsageCap(ctx, s, ccErr)
			if err != nil {
				return errors.Join(ccErr, err)
			}
			if stop {
				return ccErr
			}
			continue
		}

		// The free-space floor (Task 20381): no attempt starts on a disk too
		// full to record what it does. A run that had to wait goes back to
		// the top, because the plan may have moved while it waited.
		if waited, err := o.awaitDiskSpace(ctx, s, nil, fmt.Sprintf("task #%d", task.ID)); err != nil {
			return err
		} else if waited {
			continue
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
					task.Status = pm.TaskFailed
					pm.AddAnnotation(task, "ai", "Task failed: pre-execution risk assessment flagged CRITICAL finding(s); aborted before provider call. Use --force to override.")
					if err := o.persistOutcome(s, task, "failure (CRITICAL pre-execution risk finding)",
						decidedBy(taskrecover.SourceOrchestrator, "risk_critical", "the pre-execution risk assessment flagged a CRITICAL finding")); err != nil {
						return err
					}
					failColor.Printf("✗ Task %d aborted: CRITICAL risk finding(s). Use --force to override.\n\n", task.ID)
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
				if err := o.persistOutcome(s, task, "skip at the approval gate",
					decidedBy(taskrecover.SourceOperator, "approval_declined", "skipped at the human approval gate")); err != nil {
					return err
				}
				dimColor.Printf("→ Task %d skipped at approval gate.\n\n", task.ID)
				continue
			case res.Paused:
				s.SetPaused(pausereason.New(pausereason.CodeApproval,
					fmt.Sprintf("approval declined for task #%d", task.ID)))
				if err := o.persist(s, "the pause (approval declined)"); err != nil {
					return err
				}
				color.New(color.FgYellow).Printf("⏸ Approval gate: execution declined. Run 'cloop run' to resume.\n")
				return nil
			default:
				// Approved (possibly with edited description)
				if res.EditedDesc != "" {
					task.Description = res.EditedDesc
					dimColor.Printf("  Task %d description updated via editor.\n", task.ID)
				}
				// Mark as approved so unattended reruns skip the gate.
				task.Approved = true
				o.persistBestEffort(s, "the approval (and any edited description)",
					"the next write — the task's start, or whatever ends the run first — stores it, and losing it only means the gate asks again")
			}
		}

		// Human-in-the-loop review mode: ask before executing each task.
		if o.config.ReviewMode {
			action := reviewTask(task)
			switch action {
			case "skip":
				task.Status = pm.TaskSkipped
				pm.AddAnnotation(task, "ai", "Task skipped by user in interactive review mode.")
				if err := o.persistOutcome(s, task, "skip, chosen by the operator in review mode",
					decidedBy(taskrecover.SourceOperator, "operator_skip", "skipped by the operator in review mode")); err != nil {
					return err
				}
				dimColor.Printf("→ Task %d skipped by user.\n\n", task.ID)
				continue
			case "quit":
				s.SetPaused(pausereason.New(pausereason.CodeApproval,
					"interactive review: operator quit"))
				if err := o.persist(s, "the pause (operator quit review mode)"); err != nil {
					return err
				}
				color.New(color.FgYellow).Printf("⏸ Review mode: user quit. Run 'cloop run' to resume.\n")
				return nil
			case "no":
				s.SetPaused(pausereason.New(pausereason.CodeApproval,
					fmt.Sprintf("interactive review: operator declined task #%d", task.ID)))
				if err := o.persist(s, "the pause (operator declined the task in review mode)"); err != nil {
					return err
				}
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

		// A stop that landed while the checks above ran must not start the
		// task: its provider call would fail at once, and the attempt recorded
		// would be one that never began. The top of the loop pauses the run.
		if runInterrupted(ctx) {
			continue
		}

		// Pre-task hook: skip the task if it exits non-zero.
		if hookErr := hooks.RunPreTask(o.config.Hooks, hooks.TaskContext{
			ID:     task.ID,
			Title:  task.Title,
			Status: "pending",
			Role:   string(task.Role),
		}, o.allEnvLines()...); hookErr != nil {
			task.Status = pm.TaskSkipped
			pm.AddAnnotation(task, "ai", fmt.Sprintf("Task skipped: pre_task hook exited non-zero: %v", hookErr))
			if err := o.persistOutcome(s, task, "skip (its pre_task hook failed)",
				decidedBy(taskrecover.SourceOrchestrator, "pre_task_hook_failed", fmt.Sprintf("its pre_task hook failed: %v", hookErr))); err != nil {
				return err
			}
			dimColor.Printf("⊘ pre_task hook failed for task %d (%s): %v — skipping task.\n", task.ID, task.Title, hookErr)
			continue
		}

		// A new attempt: whatever was decided about the last one must not be
		// read as this one's (Task 20365).
		o.clearVerdict(task.ID)
		now := time.Now()
		task.Status = pm.TaskInProgress
		task.StartedAt = &now
		// Stamp placement before the task runs, not after it finishes, so an
		// in-flight task is attributable too (Task 20244), and record the
		// dispatch in the audit trail while the placement facts are in hand
		// (Task 20282).
		f := o.beginTaskExecution(task)
		execID, execKind, execIso := f.ExecutorID, f.ExecutorKind, f.Isolation
		pm.AddAnnotation(task, "ai", fmt.Sprintf("Task started on executor %s (kind: %s, isolation: %s, provider: %s)",
			attributionLabel(execID), execKind, execIso, o.provider.Name()))
		// Stored before it is announced or run: a task the database does not
		// show running cannot be stopped from the dashboard, and the start is
		// what stale-task recovery reasons from if this process dies.
		if err := o.persist(s, fmt.Sprintf("task #%d's start (in progress on %s)", task.ID, attributionLabel(execID))); err != nil {
			return err
		}

		// Snapshot the repository so an unsignalled run can be judged on what
		// it changed rather than on the agent process having exited (Task
		// 20211). Taken before the provider call so it captures the
		// pre-existing tree, and cheap enough (two git invocations) to run
		// per task.
		repoBefore := repoFingerprint(o.config.WorkDir)

		// Review gate (Task 20357): record what the repositories look like and
		// start holding the agent's pushes, before the agent runs.
		activeGate = o.openGate(ctx, s.ReviewGate, o.config.WorkDir)
		if activeGate != nil {
			// Until the gate approves, the agent's TASK_DONE is not this
			// task's outcome — not even to a recovery after the run dies.
			o.awaitReview(task)
		}
		// Done means committed (Task 20370): record what the repository holds
		// before the agent touches it, so that what it leaves behind can be
		// told apart from what was already there.
		commit, commitNote := o.openCommitGuard(ctx, s.CommitPolicy, o.config.WorkDir, task, activeGate)
		if commitNote != "" {
			dimColor.Printf("  %s\n", commitNote)
		}
		var gateOut *gateOutcome
		// taskSessionID is the conversation the agent's latest turn ran in,
		// which a review sending it back resumes.
		taskSessionID := ""

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
		o.queueRunning(queueID)

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
		o.ensureChainInput(s.Plan, task)
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
		prompt = withGateSection(prompt, activeGate.promptSection())

		// Prompt A/B testing: track the currently recommended variant for this
		// task's role. Used to record outcomes and to select a replacement on
		// heal retries. Does not modify the main task prompt — variant injection
		// only happens in the heal loop below.
		activeVariant := promptopt.BestVariant(o.config.WorkDir, task.Role)

		if o.config.DryRun {
			dimColor.Printf("[dry-run] Task prompt:\n%s\n\n", prompt)
			task.Status = pm.TaskDone
			if err := o.persistOutcome(s, task, "dry-run completion",
				decidedBy(taskrecover.SourceOrchestrator, "dry_run", "a dry run marks every task done without executing it")); err != nil {
				return err
			}
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

		// requeueIfInterrupted returns the task to pending when the run has
		// stopped under it (Task 20348), and reports whether it did. Every
		// place below where an execution can end in an error asks it first,
		// because an error caused by the run ending is not the task's. Git
		// mode returns to the branch the run started from, as the failure path
		// does, so the next run branches from the same base rather than from
		// this task's branch.
		requeueIfInterrupted := func(stage string) bool {
			if !runInterrupted(ctx) {
				return false
			}
			o.requeueInterrupted(s, task, stage, s.CurrentStep)
			o.queueFailed(queueID, interruptedQueueNote)
			if gitTaskBranch != "" {
				if err := cloopgit.CheckoutBranch(o.config.WorkDir, gitOriginalBranch); err != nil {
					dimColor.Printf("  git checkout original branch error (ignored): %v\n", err)
				}
			}
			return true
		}

		// Select provider: role-specific route takes precedence over default.
		taskProvider := o.router.For(task.Role)
		start := time.Now()

		// Apply per-task time budget. The cancel is released at the top of the
		// next iteration (or by the function-level defer) so contexts don't
		// accumulate across the unbounded loop.
		taskCtx, taskCancel = o.taskContextWithTimeout(ctx, task)

		// Register the per-task cancel with the watchdog registry so a manual
		// abort from the UI (Task 20140) can cancel a wedged provider call.
		o.watchdog.Register(task.ID, taskCancel)

		// ── Multi-agent path ───────────────────────────────────────────────
		// When --multi-agent is set, run the three-pass pipeline instead of a
		// single provider call. The combined reviewer output becomes the task
		// result for signal detection and artifact storage.
		var taskOutput string
		var taskInputTokens, taskOutputTokens, taskThinkingTokens int
		var taskProviderName, taskModelName string
		var consensusReport *consensus.Report // non-nil when consensus was used
		// taskBackground carries work the agent left running (Task 20205). It
		// is reassigned alongside taskOutput on every path that produces a new
		// result — including heal and clarify retries — because it describes
		// that specific attempt, and a stale value would judge the new output
		// by the old attempt's leftovers.
		var taskBackground *provider.BackgroundActivity

		if o.config.MultiAgent {
			dimColor.Printf("→ Running multi-agent pipeline on task %d (architect→coder→reviewer)...\n", task.ID)

			// Build optional project context string for the multi-agent prompt.
			var projCtxStr string
			if projCtx != nil {
				projCtxStr = projCtx.Format()
			}

			// The options a single agent would run with — the review gate's
			// push hold among them — for every pass (Task 20365). Not
			// streamed: three passes interleaved on the terminal read as one.
			maOpts, _ := o.makeOpts(s.Model, s.LiveEffort(), false)
			maOpts = o.withBackgroundWaitNotice(maOpts, s, task, nil)
			maOpts.Env = activeGate.env()
			maRes, maErr := multiagent.RunTask(taskCtx, taskProvider, maOpts, multiagent.Brief{
				Task:           task,
				Goal:           s.Goal,
				Instructions:   s.Instructions,
				ProjectContext: projCtxStr,
				Notice:         activeGate.promptSection(),
			})
			if maErr != nil {
				if requeueIfInterrupted("while the multi-agent pipeline was running") {
					continue
				}
				if isTimeoutErr(taskCtx, maErr) {
					budgetMin := o.effectiveTaskBudgetMinutes(task)
					if err := o.handleTaskTimeout(ctx, s, task, "", dimColor, nil); err != nil {
						return err
					}
					color.New(color.FgYellow).Printf("⏱ Task %d timed out (%dm): %s\n", task.ID, budgetMin, task.Title)
					o.queueFailed(queueID, fmt.Sprintf("multi-agent timeout (%dm)", budgetMin))
					consecutiveErrors++
					if consecutiveErrors >= maxConsecutiveErrors {
						return o.failRun(s, fmt.Errorf("%d consecutive errors", consecutiveErrors))
					}
					continue
				}
				failColor.Printf("✗ Multi-agent error: %v\n", maErr)
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: multi-agent pipeline error — %s", truncate(maErr.Error(), 200)))
				task.Status = pm.TaskFailed
				if err := o.persistOutcome(s, task, "failure (multi-agent pipeline error)",
					decidedBy(taskrecover.SourceProvider, "multiagent_error", truncate(maErr.Error(), 200))); err != nil {
					return err
				}
				o.queueFailed(queueID, truncate(maErr.Error(), 200))
				consecutiveErrors++
				if consecutiveErrors >= maxConsecutiveErrors {
					return o.failRun(s, fmt.Errorf("%d consecutive errors", consecutiveErrors))
				}
				continue
			}

			taskBackground = maRes.Background
			taskSessionID = maRes.SessionID
			taskInputTokens, taskOutputTokens, taskThinkingTokens = maRes.InputTokens, maRes.OutputTokens, maRes.ThinkingTokens
			// Before the first line about the result (Task 20365).
			o.noteEarlyVerdict(task.ID, task.StartedAt, maRes.ReviewerOutput, taskBackground, true)

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
				opts, _ := o.makeOpts(s.Model, s.LiveEffort(), false) // no streaming in consensus mode
				opts.Env = activeGate.env()
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
					if requeueIfInterrupted("while the consensus providers were running") {
						continue
					}
					if isTimeoutErr(taskCtx, cErr) {
						budgetMin := o.effectiveTaskBudgetMinutes(task)
						if err := o.handleTaskTimeout(ctx, s, task, "", dimColor, nil); err != nil {
							return err
						}
						color.New(color.FgYellow).Printf("⏱ Task %d timed out (%dm): %s\n", task.ID, budgetMin, task.Title)
						o.queueFailed(queueID, fmt.Sprintf("consensus timeout (%dm)", budgetMin))
						consecutiveErrors++
						if consecutiveErrors >= maxConsecutiveErrors {
							return o.failRun(s, fmt.Errorf("%d consecutive errors", consecutiveErrors))
						}
						continue
					}
					failColor.Printf("✗ Consensus error: %v\n", cErr)
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: consensus error — %s", truncate(cErr.Error(), 200)))
					task.Status = pm.TaskFailed
					if err := o.persistOutcome(s, task, "failure (consensus error)",
						decidedBy(taskrecover.SourceProvider, "consensus_error", truncate(cErr.Error(), 200))); err != nil {
						return err
					}
					o.queueFailed(queueID, truncate(cErr.Error(), 200))
					consecutiveErrors++
					if consecutiveErrors >= maxConsecutiveErrors {
						return o.failRun(s, fmt.Errorf("%d consecutive errors", consecutiveErrors))
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

				opts, wasStreamed := o.makeOpts(s.Model, s.LiveEffort(), true)
				opts = o.withBackgroundWaitNotice(opts, s, task, nil)
				opts.Env = activeGate.env()
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
				// completeTask hands the turn back when the agent ends it
				// waiting on its own work (Task 20349); see unfinished.go.
				result, turns, err := completeTask(auditCtx, taskProvider, prompt, opts, commit)
				taskExecSpan.End()
				if turns.unfinished > 0 {
					pm.AddAnnotation(task, "cloop", continuedTurnNote(turns.unfinished))
				}
				if turns.uncommitted > 0 {
					pm.AddAnnotation(task, "cloop", uncommittedTurnNote(turns.uncommitted, commit.pushed()))
				}
				if liveFile != nil {
					if err == nil && !wasStreamed() {
						// Non-streaming provider: write full output so watchers can read it.
						_, _ = liveFile.WriteString(result.Output)
					}
					_ = liveFile.Close()
				}
				if err != nil {
					if requeueIfInterrupted("while the agent was working on it") {
						continue
					}
					if isTimeoutErr(taskCtx, err) {
						budgetMin := o.effectiveTaskBudgetMinutes(task)
						if saveErr := o.handleTaskTimeout(ctx, s, task, "", dimColor, nil); saveErr != nil {
							return saveErr
						}
						color.New(color.FgYellow).Printf("⏱ Task %d timed out (%dm): %s\n", task.ID, budgetMin, task.Title)
						o.queueFailed(queueID, fmt.Sprintf("provider timeout (%dm)", budgetMin))
						consecutiveErrors++
						if consecutiveErrors >= maxConsecutiveErrors {
							return o.failRun(s, fmt.Errorf("%d consecutive errors", consecutiveErrors))
						}
						continue
					}
					if provider.IsRetryBudgetExhausted(err) {
						// Per-task retry budget hit: surface as a distinct failure
						// mode. We do not auto-heal because every heal would consume
						// further attempts the budget already refused; instead the
						// task is marked failed and the operator must raise
						// task.RetryBudget or address the underlying flake.
						pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: retry budget exhausted (limit reached) — %s", truncate(err.Error(), 200)))
						task.Status = pm.TaskFailed
						if saveErr := o.persistOutcome(s, task, "failure (retry budget exhausted)",
							decidedBy(taskrecover.SourceProvider, "retry_budget_exhausted", truncate(err.Error(), 200))); saveErr != nil {
							return saveErr
						}
						failColor.Printf("✗ Task %d: retry budget exhausted — %v\n", task.ID, err)
						o.queueFailed(queueID, "retry budget exhausted")
						consecutiveErrors++
						if consecutiveErrors >= maxConsecutiveErrors {
							return o.failRun(s, fmt.Errorf("%d consecutive errors", consecutiveErrors))
						}
						continue
					}
					failColor.Printf("✗ Provider error: %v\n", err)
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: provider error — %s", truncate(err.Error(), 200)))
					task.Status = pm.TaskFailed
					if saveErr := o.persistOutcome(s, task, "failure (provider error)",
						decidedBy(taskrecover.SourceProvider, "provider_error", truncate(err.Error(), 200))); saveErr != nil {
						return saveErr
					}
					o.queueFailed(queueID, truncate(err.Error(), 200))
					consecutiveErrors++
					if consecutiveErrors >= maxConsecutiveErrors {
						return o.failRun(s, fmt.Errorf("%d consecutive errors", consecutiveErrors))
					}
					continue
				}

				taskOutput = result.Output
				taskBackground = result.Background
				taskSessionID = result.SessionID
				taskInputTokens = result.InputTokens
				taskOutputTokens = result.OutputTokens
				taskThinkingTokens = result.ThinkingTokens
				taskProviderName = result.Provider
				taskModelName = result.Model
				// Before the first line about the result (Task 20365).
				o.noteEarlyVerdict(task.ID, task.StartedAt, taskOutput, taskBackground, true)

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
			ab := Abort{Class: AbortEmptyOutput, Reason: fmt.Sprintf("provider returned empty output (consecutive errors: %d/%d)", consecutiveErrors, maxConsecutiveErrors)}
			if err := o.abortTask(s, task, ab, s.CurrentStep); err != nil {
				return err
			}
			o.queueFailed(queueID, abortSummaryForQueue(ab))
			if consecutiveErrors >= maxConsecutiveErrors {
				return o.failRun(s, fmt.Errorf("%d consecutive task failures (empty provider output)", consecutiveErrors))
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
			// Mark the in-progress task as pending so it retries next time
			task.Status = pm.TaskPending
			o.noteVerdict(task, pm.TaskPending, budgetWhy("token_budget", "the token budget ran out"))
			s.SetPaused(pausereason.New(pausereason.CodeTokenBudget,
				fmt.Sprintf("token budget of %d tokens spent", o.config.TokenBudget)))
			if err := o.persist(s, "the pause (token budget reached), with the task back to pending"); err != nil {
				return err
			}
			color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
			return nil
		}
		if spent, over := o.costLimitReached(s); over {
			task.Status = pm.TaskPending
			o.noteVerdict(task, pm.TaskPending, budgetWhy("cost_limit", "the cost limit was reached: "+spent))
			s.SetPaused(pausereason.New(pausereason.CodeBudget, "cost limit reached: "+spent))
			if err := o.persist(s, "the pause (cost limit reached), with the task back to pending"); err != nil {
				return err
			}
			color.New(color.FgRed).Printf("⏸ Cost limit reached (%s). Run 'cloop run' to continue.\n", spent)
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
			// healInterrupted is set when the run stopped in the middle of a
			// heal. The TASK_FAILED that started the heal is then not the
			// task's final word: it was denied the retries that would have
			// decided it, so it goes back to pending instead (Task 20348).
			healInterrupted := false
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
				o.queueRunning(healQueueID)
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

				diag, diagErr := diagnosis.AnalyzeFailure(taskCtx, o.provider, s.Model, o.config.StepTimeout, task, taskOutput)
				if diagErr != nil {
					if runInterrupted(ctx) {
						o.queueFailed(healQueueID, interruptedQueueNote)
						healInterrupted = true
						break
					}
					o.queueFailed(healQueueID, fmt.Sprintf("diagnosis error: %v", diagErr))
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

				healOpts, healWasStreamed := o.makeOpts(s.Model, s.LiveEffort(), true)
				healOpts.Env = activeGate.env()
				healResult, healErr := safeComplete(taskCtx, taskProvider, healPrompt, healOpts)
				if healErr != nil {
					if runInterrupted(ctx) {
						o.queueFailed(healQueueID, interruptedQueueNote)
						healInterrupted = true
						break
					}
					o.queueFailed(healQueueID, truncate(healErr.Error(), 200))
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
					o.queueFailed(healQueueID, "provider returned empty output")
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
				taskBackground = healResult.Background
				taskSessionID = healResult.SessionID

				// Account for tokens used by heal attempts.
				s.TotalInputTokens += healResult.InputTokens
				s.TotalOutputTokens += healResult.OutputTokens

				signal = pm.CheckTaskSignal(taskOutput)
				if signal != pm.TaskFailed {
					o.queueDone(healQueueID, fmt.Sprintf("healed: signal=%s", signal))
					pm.AddAnnotation(task, "ai", fmt.Sprintf("[HEAL %d/%d] Succeeded — task signal: %s", healAttempt, maxHealRetries, signal))
					healColor.Printf("[HEAL attempt %d/%d] ✓ Task %d healed successfully (signal: %s)\n\n", healAttempt, maxHealRetries, task.ID, signal)
				} else {
					o.queueFailed(healQueueID, "task still emitted TASK_FAILED")
					pm.AddAnnotation(task, "ai", fmt.Sprintf("[HEAL %d/%d] Still failing — task emitted TASK_FAILED again", healAttempt, maxHealRetries))
					healColor.Printf("[HEAL attempt %d/%d] Task %d still failing — %s\n\n", healAttempt, maxHealRetries, task.ID, truncate(taskOutput, 120))
				}
			}
			if healInterrupted && requeueIfInterrupted("during an auto-heal retry") {
				continue
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
				// Set when the run stopped during a re-prompt: the questions
				// were never answered, so the task has no outcome to judge.
				clarifyInterrupted := false
				for clarifyAttempt := 1; clarifyAttempt <= maxClarifyRetries; clarifyAttempt++ {
					if !o.log.IsJSON() {
						color.New(color.FgCyan).Printf("[AUTO-RESOLVE %d/%d] LLM asked questions instead of completing task %d — re-prompting to proceed autonomously\n", clarifyAttempt, maxClarifyRetries, task.ID)
					}
					clarifyPrompt := prompt + "\n\n" +
						"--- PREVIOUS RESPONSE ---\n" + taskOutput + "\n--- END PREVIOUS RESPONSE ---\n\n" +
						"You asked clarification questions instead of completing the task. " +
						"Make your best judgment for ALL decisions and proceed to full completion. " +
						"Do NOT ask for clarification or confirmation. Just do the work and finish with TASK_DONE."
					clarifyOpts, clarifyWasStreamed := o.makeOpts(s.Model, s.LiveEffort(), true)
					clarifyOpts.Env = activeGate.env()
					clarifyResult, clarifyErr := safeComplete(taskCtx, taskProvider, clarifyPrompt, clarifyOpts)
					if clarifyErr != nil {
						if runInterrupted(ctx) {
							clarifyInterrupted = true
							break
						}
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
					taskBackground = clarifyResult.Background
					taskSessionID = clarifyResult.SessionID
					s.TotalInputTokens += clarifyResult.InputTokens
					s.TotalOutputTokens += clarifyResult.OutputTokens
					signal = pm.CheckTaskSignal(taskOutput)
					if signal == pm.TaskDone || signal == pm.TaskFailed || signal == pm.TaskSkipped || !looksLikeClarificationQuestion(taskOutput) {
						clarifyOutcome = fmt.Sprintf("Clarification auto-resolved on attempt %d/%d — LLM proceeded autonomously.", clarifyAttempt, maxClarifyRetries)
						break
					}
				}
				if clarifyInterrupted && requeueIfInterrupted("while re-prompting after clarification questions") {
					continue
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
		//
		// decided is who settled the outcome, for the verdict stale-task
		// recovery reads (Task 20365): the agent's own signal, unless a check
		// below overrides it.
		decided := agentWhy(signal)
		clarificationReroute := false
		if signal == pm.TaskInProgress && looksLikeClarificationQuestion(taskOutput) {
			signal = pm.TaskFailed
			clarificationReroute = true
			decided = clarificationWhy()
		}

		// Background work the agent left running (Task 20205). This is applied
		// after the heal loop rather than before it on purpose: heal re-runs
		// the whole task, and the wait that detects abandonment is measured in
		// minutes, so feeding this into heal would spend that wait — and kill a
		// long job — once per retry. Failing once with a diagnosis that names
		// the remedy is both cheaper and more useful.
		beforeBackground := signal
		signal = applyBackgroundOutcome(task, taskBackground, signal)
		abandoned := task.Background != nil && task.Background.State == pm.BackgroundAbandoned
		if abandoned {
			task.FailureDiagnosis = backgroundFailureDiagnosis(task.Background)
		}
		if signal != beforeBackground {
			decided = backgroundWhy(task.Background)
		}
		// Done means committed (Task 20370): a turn about to be accepted as
		// done that left this attempt's changes uncommitted — or unpushed — is
		// not done, whatever it said. Checked before the decision is written
		// down, which it overrides, and before the review gate, which must not
		// publish work the task has not finished.
		var commitAbort *Abort
		if signal == pm.TaskDone || signal == pm.TaskInProgress {
			commitAbort = commit.abortFor(ctx, taskOutput, taskBackground)
		}
		// The decision so far is written down before anything announces it: a
		// run whose control plane has gone dies on its next line of output.
		if commitAbort == nil {
			o.noteDecision(task, signal, decided, activeGate != nil)
		}
		if task.Background != nil {
			o.logBackgroundEvent(s, task, task.Background)
			if abandoned {
				color.New(color.FgYellow).Printf(
					"⏳ Task %d left %d background process(es) running after %ds — not accepting it as complete\n",
					task.ID, task.Background.Detected, task.Background.WaitedSeconds)
			}
		}

		// Review gate (Task 20357). A task that says it is done — or ended
		// without a signal, which the default arm below may still promote —
		// has its changes reviewed before anything leaves the machine. What
		// the gate does not approve fails here, before any merge or push.
		reviewReroute := false
		if activeGate != nil && commitAbort == nil && (signal == pm.TaskDone || signal == pm.TaskInProgress) {
			if requeueIfInterrupted("before the review gate ran") {
				continue
			}
			if !o.log.IsJSON() {
				dimColor.Printf("  Review gate: reviewing task %d's changes...\n", task.ID)
			}
			fixOpts, _ := o.makeOpts(s.Model, s.LiveEffort(), false)
			fixOpts = o.withBackgroundWaitNotice(fixOpts, s, task, nil)
			fixOpts.Env = activeGate.env()
			gateOut = o.passGate(provideraudit.WithTaskContext(taskCtx, task.ID, task.Title), activeGate, gateInput{
				task: task, goal: s.Goal, conventions: s.Instructions, prompt: prompt,
				output: taskOutput, signal: signal, sessionID: taskSessionID, background: taskBackground,
				worker: taskProvider, workerOpts: fixOpts, model: s.Model, commit: commit,
			})
			if requeueIfInterrupted("while the review gate was running") {
				continue
			}
			for i, st := range gateOut.steps {
				s.AddStep(state.StepResult{
					Task:         fmt.Sprintf("Task %d: %s (review fix %d)", task.ID, task.Title, i+1),
					Output:       st.output,
					Duration:     st.duration.Round(time.Second).String(),
					Time:         time.Now(),
					InputTokens:  st.inputTok,
					OutputTokens: st.outputTok,
				})
			}
			s.TotalInputTokens += gateOut.workIn + gateOut.reviewIn
			s.TotalOutputTokens += gateOut.workOut + gateOut.reviewOut
			taskInputTokens += gateOut.workIn
			taskOutputTokens += gateOut.workOut
			taskThinkingTokens += gateOut.workThinking
			if len(gateOut.steps) > 0 {
				taskOutput, taskBackground, taskSessionID = gateOut.output, gateOut.background, gateOut.sessionID
				task.Result = truncate(taskOutput, 500)
				signal = applyBackgroundOutcome(task, taskBackground, gateOut.signal)
			}
			task.Review = gateOut.review
			pm.AddAnnotation(task, "reviewer", gateOut.note)
			if gateOut.fail {
				signal = pm.TaskFailed
				reviewReroute = true
				task.FailureDiagnosis = gateOut.review.Diagnosis()
				if !gateOut.review.Blocked {
					task.FailureDiagnosis = gateOut.note
				}
			}
			switch {
			case gateOut.fail, signal == pm.TaskDone:
				decided = gateWhy(gateOut)
			case len(gateOut.steps) > 0 && signal != gateOut.signal:
				// A fix turn left background work running.
				decided = backgroundWhy(task.Background)
			case signal == pm.TaskFailed || signal == pm.TaskSkipped:
				// A fix turn ended with the agent's own failure or skip.
				decided = agentWhy(signal)
			}
			o.noteDecision(task, signal, decided, false)
			o.persistBestEffort(s, "the review gate's verdict",
				"the task's outcome write below stores it as well, and the run stops there if it cannot")
			o.logReviewEvent(s, task, gateOut)
			o.recordReviewCost(task, gateOut)
			if !o.log.IsJSON() {
				if gateOut.fail {
					failColor.Printf("✗ %s\n", gateOut.note)
				} else {
					successColor.Printf("✓ %s\n", gateOut.note)
				}
			}
		}

		// The review gate's fix turns are the agent's turns too: what they left
		// is held to the same rule.
		if commitAbort == nil && gateOut != nil && len(gateOut.steps) > 0 && !gateOut.fail &&
			(signal == pm.TaskDone || signal == pm.TaskInProgress) {
			commitAbort = commit.abortFor(ctx, taskOutput, taskBackground)
		}
		if note := commit.passNote(); note != "" && commitAbort == nil {
			pm.AddAnnotation(task, "cloop", note)
		}
		// Done means committed (Task 20370): the attempt left work outstanding,
		// so it goes back to pending with that work where the agent left it,
		// bounded like every abort by the run's consecutive-abort ceiling.
		if commitAbort != nil {
			consecutiveErrors++
			if gateOut == nil {
				activeGate.withheldNote(task)
			}
			if err := o.abortTask(s, task, *commitAbort, s.CurrentStep); err != nil {
				return err
			}
			o.queueFailed(queueID, abortSummaryForQueue(*commitAbort))
			if consecutiveErrors >= maxConsecutiveErrors {
				return o.pauseForUncommittedWork(s, task, *commitAbort, consecutiveErrors, nil)
			}
			stop, err := o.scheduleAbortRetry(ctx, s, *commitAbort, nil)
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
			continue
		}

		// Each arm below stores the task's outcome before it announces it — the
		// terminal line, the log, the notifications and webhooks, the queue and
		// the journal after the switch — so a write that fails leaves nothing
		// claiming a status the database does not hold.
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
						task.Status = pm.TaskPending
						if err := o.persistOutcome(s, task, "return to pending after a failed AI verification",
							decidedBy(taskrecover.SourceVerify, "verify_failed", fmt.Sprintf("AI verification failed; re-queued (attempt %d/%d)", task.VerifyRetries, maxRetries))); err != nil {
							return err
						}
						failColor.Printf("✗ Verification FAILED for task %d (%s) — re-queuing (attempt %d/%d)\n\n", task.ID, task.Title, task.VerifyRetries, maxRetries)
						continue
					}
					pm.AddAnnotation(task, "ai", fmt.Sprintf("AI verification failed %d time(s) — exceeded retry budget, marking task failed.", task.VerifyRetries))
					task.Status = pm.TaskFailed
					if err := o.persistOutcome(s, task, "failure (AI verification exhausted its retries)",
						decidedBy(taskrecover.SourceVerify, "verify_failed", fmt.Sprintf("AI verification failed %d time(s), exhausting its retries", task.VerifyRetries))); err != nil {
						return err
					}
					failColor.Printf("✗ Verification failed %d time(s) for task %d — marking failed.\n\n", task.VerifyRetries, task.ID)
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
					if consecutiveErrors >= maxConsecutiveErrors {
						return o.failRun(s, fmt.Errorf("%d consecutive task failures", consecutiveErrors))
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
					if !vr.Passed {
						// Decided: written down before the lines below report it.
						o.noteVerdict(task, pm.TaskFailed, scriptVerifyWhy())
					}
					// Persist script + result as artifact regardless of outcome.
					if artPath, artErr := artifact.WriteVerificationArtifact(o.config.WorkDir, task, vr.Script, vr.Output, vr.Passed); artErr != nil {
						dimColor.Printf("  verification artifact write error (ignored): %v\n", artErr)
					} else {
						dimColor.Printf("  verification artifact: %s\n", artPath)
					}
					if !vr.Passed {
						scriptVerifyFailed = true
						pm.AddAnnotation(task, "ai", "Shell verification reported failure — marking task failed.")
						task.Status = pm.TaskFailed
						if err := o.persistOutcome(s, task, "failure (shell verification failed)", scriptVerifyWhy()); err != nil {
							return err
						}
						failColor.Printf("✗ Shell verification FAILED for task %d (%s)\n", task.ID, task.Title)
						if vr.Output != "" {
							failColor.Printf("  Script output:\n%s\n\n", vr.Output)
						}
						// Trigger failure diagnosis so retry prompts can learn from the
						// failure. Stored by the write at the end of this step.
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
						// Mirror the verify-failure path above and the task-failed
						// path below: script-verify failures must also trip
						// MaxFailures, otherwise consecutive flaky or
						// genuinely-broken script-verify runs would burn budget
						// without the loop ever aborting.
						if consecutiveErrors >= maxConsecutiveErrors {
							return o.failRun(s, fmt.Errorf("%d consecutive task failures", consecutiveErrors))
						}
					} else {
						pmColor.Printf("✓ Shell verification PASSED for task %d: %s\n\n", task.ID, task.Title)
					}
				}
			}

			if !scriptVerifyFailed {
				task.Status = pm.TaskDone
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task completed successfully in %s.", taskDur))
				if err := o.persistOutcome(s, task, "completion", decided); err != nil {
					return err
				}
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
			if err := o.persistOutcome(s, task, "skip", decided); err != nil {
				return err
			}
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
			// annotation already captures the real root cause, and claiming
			// "per AI TASK_FAILED signal" would misattribute it.
			if !clarificationReroute && !reviewReroute {
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed per AI TASK_FAILED signal after %s.", taskDur))
			}
			if err := o.persistOutcome(s, task, "failure", decided); err != nil {
				return err
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
			// A task the review gate failed already carries the reviewer's
			// findings as its diagnosis, which is the better account.
			if o.config.DiagnoseFailures && !reviewReroute {
				dimColor.Printf("  Diagnosing failure for task %d...\n", task.ID)
				diag, diagErr := diagnosis.AnalyzeFailure(taskCtx, o.provider, s.Model, o.config.StepTimeout, task, taskOutput)
				if diagErr != nil {
					dimColor.Printf("  Diagnosis error (ignored): %v\n", diagErr)
				} else if diag != "" {
					task.FailureDiagnosis = diag
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Failure diagnosis: %s", diag))
					dimColor.Printf("  Diagnosis: %s\n\n", truncate(diag, 200))
				}
				o.persistBestEffort(s, "the AI's failure diagnosis",
					"the failure itself is already stored, and the next write stores the diagnosis too")
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
					// Replacing: SplitTask removes the original task, and a
					// merging write would read it back from disk and undo the
					// split.
					if err := o.persist(s, fmt.Sprintf("the plan with task #%d split into %d subtasks", task.ID, len(subtasks)), replacePlan); err != nil {
						return err
					}
					pmColor.Printf("  Split into %d subtasks. Continuing plan...\n\n", len(subtasks))
					consecutiveErrors = 0
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
					// Replacing: the replan dropped the pending tasks, and a
					// merging write would read them back from disk.
					if err := o.persist(s, fmt.Sprintf("the replanned plan (%d revised task(s))", len(newTasks)), replacePlan); err != nil {
						return err
					}
					pmColor.Printf("  Replanned: added %d revised task(s).\n\n", len(newTasks))
					consecutiveErrors = 0 // reset after successful replan
					continue
				} else {
					pmColor.Printf("  Replan: no new tasks — plan is complete or blocked.\n\n")
				}
			}

			if consecutiveErrors >= maxConsecutiveErrors {
				return o.failRun(s, fmt.Errorf("%d consecutive task failures", consecutiveErrors))
			}
		default:
			// No signal found. Promotion to done needs positive evidence —
			// the agent process exiting is not evidence, and treating it as
			// such is what recorded provider refusals as completed work
			// (Task 20211). decideUnsignalled classifies the refusals it
			// recognises and otherwise demands a diff or an artifact.
			if ab, aborted := decideUnsignalled(o.config.WorkDir, task.ArtifactPath, taskOutput,
				repoChanged(repoBefore, repoFingerprint(o.config.WorkDir))); aborted {
				consecutiveErrors++
				if err := o.abortTask(s, task, ab, s.CurrentStep); err != nil {
					return err
				}
				o.queueFailed(queueID, abortSummaryForQueue(ab))
				if consecutiveErrors >= maxConsecutiveErrors {
					return o.failRun(s, fmt.Errorf("%d consecutive aborted tasks (last: %s)", consecutiveErrors, ab))
				}
				// Wait out a usage window rather than picking the same
				// now-pending task straight back up and hitting the same wall.
				stop, err := o.scheduleAbortRetry(ctx, s, ab, nil)
				if err != nil {
					return err
				}
				if stop {
					return nil
				}
				continue
			}
			task.Status = pm.TaskDone
			pm.AddAnnotation(task, "ai", "Task implicitly completed: AI finished without an explicit TASK_DONE/TASK_FAILED/TASK_SKIPPED signal — treated as done.")
			if err := o.persistOutcome(s, task, "completion (no explicit signal)", implicitDoneWhy()); err != nil {
				return err
			}
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
			o.queueDone(queueID, stepSummaryLine(taskOutput, 200))
		case pm.TaskFailed:
			o.queueFailed(queueID, stepSummaryLine(taskOutput, 200))
		case pm.TaskSkipped:
			o.queueSkipped(queueID, "AI emitted TASK_SKIPPED")
		default:
			// Implicit-done / timed-out / other terminal states record as done
			// to match the plan-task accounting above.
			o.queueDone(queueID, stepSummaryLine(taskOutput, 200))
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
				// Who to bill. Re-read per task rather than cached at start,
				// for the same reason the executor attribution is: a hub that
				// fails this plan over to another executor rewrites the record,
				// and the tasks after that point belong to whatever it now says.
				Identity: resolveRunIdentity(o.config.WorkDir),
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
				} else if ok, why := o.gateAllowsMergeOf(ctx, activeGate, gateOut, o.config.WorkDir, "HEAD"); !ok {
					// The review gate stands in front of this merge too: the
					// branch stays, unmerged, for a person to look at.
					dimColor.Printf("  git: not merging %s — %s\n", gitTaskBranch, why)
					pm.AddAnnotation(task, "reviewer", fmt.Sprintf("Review gate: branch %s was not merged — %s.", gitTaskBranch, why))
					if err := cloopgit.CheckoutBranch(o.config.WorkDir, gitOriginalBranch); err != nil {
						dimColor.Printf("  git checkout original branch error (ignored): %v\n", err)
					}
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

		// A task that ended without passing the review gate publishes nothing;
		// say so when the agent had pushes waiting (Task 20357).
		if activeGate != nil && gateOut == nil && activeGate.withheldNote(task) {
			o.persistBestEffort(s, "the note that the review gate withheld the task's pushes",
				"the write at the end of this step stores it too, and the pushes are dropped either way")
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
					o.persistBestEffort(s, "the post-task code review",
						"it is advisory, and the write at the end of this step stores it too")
				}
			}
		}

		// Auto-eval: score task output against default rubric after successful completion.
		if o.config.AutoEval && task.Status == pm.TaskDone {
			// Bounded, tail-biased, and falls back to task.Result when there
			// is no artifact. The previous inline read was unbounded and
			// resolved task.ArtifactPath — which is stored relative to the
			// project — against the process working directory, so it only
			// ever found the artifact when those happened to coincide.
			evalOutput := artifact.ReadTaskOutput(o.config.WorkDir, task)
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
		// Stored before it is announced, with the rest of this step: a branch
		// that was skipped in memory only would run at the next start.
		activations := pm.ResolveBranch(s.Plan, task)
		if err := o.saveOutcome(s, task, "step record: artifact, notes and the branch it chose"); err != nil {
			return err
		}
		if len(activations) > 0 {
			branchColor := color.New(color.FgCyan)
			for _, a := range activations {
				if a.Activated {
					branchColor.Printf("  branch [%s] activated  -> task %d: %s\n", a.Branch, a.TaskID, a.Title)
				} else {
					color.New(color.Faint).Printf("  branch [%s] skipped    -> task %d: %s\n", a.Branch, a.TaskID, a.Title)
				}
			}
		}

		if o.config.StepDelay > 0 {
			select {
			case <-ctx.Done():
				s.SetPaused(pausereason.New(pausereason.CodeCancelled,
					"run interrupted between steps"))
				if err := o.persist(s, "the pause (run interrupted between steps)"); err != nil {
					return errors.Join(ctx.Err(), err)
				}
				return ctx.Err()
			case <-time.After(o.config.StepDelay):
			}
		}
	}

	// The loop exits when nothing is left to schedule. That is the ordinary end
	// of a run rather than a fault, but it is still a pause: auto-evolve or an
	// operator may add work to the same plan, so the project is not complete.
	s.SetPaused(pausereason.New(pausereason.CodeIdle,
		"every runnable task is finished"))
	if err := o.persist(s, "the pause (every runnable task is finished)"); err != nil {
		return err
	}

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

// recoverStaleTasks resolves any task left `in_progress` by a prior crashed or
// killed run. Without this, NextTask() (which only returns pending tasks) would
// skip them forever and any dependent tasks would stay blocked.
//
// Recovery is adoption-first, not reset-first. A run can die between the agent
// finishing and that outcome reaching the database, and re-executing a task
// whose work is already done is destructive rather than merely wasteful — so
// where this orchestrator had already decided the outcome (its verdict
// sidecar, Task 20365), that decision is applied, and where the live artifact
// shows a terminal signal it had not overridden, that outcome is adopted; the
// task is not run again. Only genuinely unfinished tasks return to pending.
// pkg/taskrecover explains why that evidence is trustworthy.
//
// Used by both runners: the parallel one before it schedules work, the
// sequential one before its interactive skip prompt.
//
// The recovered statuses are stored before they are reported. An outcome
// adopted in memory only would be adopted — and announced — again by the next
// run, so a failed write is returned and ends this one.
func (o *Orchestrator) recoverStaleTasks(s *state.ProjectState) error {
	if s == nil || s.Plan == nil {
		return nil
	}
	outcomes := taskrecover.Reconcile(o.config.WorkDir, s.Plan)
	if len(outcomes) > 0 {
		o.requeuedMu.Lock()
		if o.requeued == nil {
			o.requeued = make(map[int]bool, len(outcomes))
		}
		for _, oc := range outcomes {
			if oc.Action == taskrecover.ActionRequeued {
				o.requeued[oc.TaskID] = true
			}
		}
		o.requeuedMu.Unlock()
	}

	// Drop any checkpoint left behind — either it pointed at a task we just
	// resolved, or it has no in-progress task to match and is fully stale.
	_ = checkpoint.Clear(o.config.WorkDir)

	if len(outcomes) > 0 {
		if err := o.persist(s, fmt.Sprintf("the outcome of %d task(s) recovered from an interrupted run", len(outcomes))); err != nil {
			return err
		}
		for _, oc := range outcomes {
			o.reportRecovery(oc)
		}
	}

	// Also recover stale queue entries left in "running" from a prior crash.
	o.recoverStaleQueueEntries()
	return nil
}

// reportRecovery narrates one recovered task to the terminal and hands it to
// the shared event writer, so a recovery reads the same in the timeline whether
// this run noticed it or the hub did.
func (o *Orchestrator) reportRecovery(oc taskrecover.Outcome) {
	switch {
	case oc.Action == taskrecover.ActionAdopted && oc.Verdict != nil:
		color.New(color.FgGreen).Printf("✓ Recovered task %d (%s) — the previous run had decided it (%s) but died before recording the result.\n",
			oc.TaskID, oc.Status, oc.Verdict.Describe())
	case oc.Action == taskrecover.ActionAdopted:
		color.New(color.FgGreen).Printf("✓ Recovered task %d (%s) — the previous run finished it but died before recording the result.\n",
			oc.TaskID, oc.Status)
	case oc.Action == taskrecover.ActionRequeued:
		color.New(color.Faint).Printf("↻ Task %d reset to pending — %s.\n", oc.TaskID, oc.Reason)
	}
	taskrecover.LogOutcome(o.config.WorkDir, oc)
}

// wasRequeued reports whether this run's stale-task recovery reset the given
// task, as opposed to adopting a finished outcome for it.
func (o *Orchestrator) wasRequeued(taskID int) bool {
	o.requeuedMu.Lock()
	defer o.requeuedMu.Unlock()
	return o.requeued[taskID]
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
		o.queueFailed(e.ID, "interrupted: previous run was killed or crashed")
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
	// continued is how many times the agent's turn was handed back because
	// it ended waiting on its own work (Task 20349).
	continued int
	// uncommitted is how many times it was handed back because the attempt's
	// changes were not committed (or pushed), and commitAbort the abort the
	// turn it ended with warrants under the project's commit policy (Task
	// 20370); pushed reports that the policy required pushes.
	uncommitted int
	commitAbort *Abort
	pushed      bool
	// commitNote says what the policy's check could not check, for a turn
	// it otherwise let through.
	commitNote string
	// gate is what the review gate decided (Task 20357); nil when the gate
	// is off or the task did not reach it.
	gate *gateOutcome
}

// parallelShutdownGracePeriod bounds how long runPMParallel will wait for
// in-flight task goroutines to report back after the parent context is
// cancelled. Workers' per-task contexts are derived from the parent, so a
// well-behaved provider should return promptly on cancellation. This watchdog
// defends against a misbehaving provider that ignores ctx.Done() and would
// otherwise hold the result loop (and thus the orchestrator) indefinitely.
// Declared as var so tests can shrink it.
var parallelShutdownGracePeriod = 30 * time.Second

// runPMParallel runs all dependency-ready tasks concurrently in each round,
// then waits for them to complete before starting the next round.
func (o *Orchestrator) runPMParallel(ctx context.Context) error {
	s := o.state
	s.Status = "running"
	if err := o.persist(s, "the run's status (running)"); err != nil {
		return err
	}

	// See runPMSequential: a mode switch or an adopted build re-enters the
	// loop without starting a new run (Task 20389).
	fresh, carry := o.enterLoop(s)
	sessionStart := carry.sessionStart
	startStep := carry.sessionStartStep
	defer func() {
		if !o.handingOver {
			printSessionSummary(sessionStart, startStep, s)
		}
	}()

	header := color.New(color.FgCyan, color.Bold)
	successColor := color.New(color.FgGreen, color.Bold)
	failColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)
	pmColor := color.New(color.FgMagenta, color.Bold)
	stepColor := color.New(color.FgYellow, color.Bold)

	if fresh {
		header.Printf("\n🧠 cloop PM — AI Product Manager Mode (parallel)\n")
		fmt.Printf("   Provider: %s\n", o.provider.Name())
		fmt.Printf("   Goal: %s\n", s.Goal)
		fmt.Println()
		o.logRunStarted(s)
	}

	// roundGates are the review gate's holds for the round in flight (Task
	// 20357), one per ready task; released after the round and on any exit.
	var roundGates []*gateRun
	defer func() {
		for _, g := range roundGates {
			g.close()
		}
	}()

	// Worktree-parallel mode: each task runs in an isolated git worktree under
	// .cloop/worktrees/task-<id>/ and its changes are merged back to the base
	// branch through a serialized merge queue. Disabled silently when WorkDir
	// is not a git repo so non-git projects still work in parallel mode.
	var (
		mergeQ          *mergequeue.Queue
		worktreeMode    bool
		worktreeBase    string
		activeWorktrees = map[int]*worktree.Worktree{}
		// reopenedWorktrees marks the worktrees an earlier attempt kept for
		// its task (Task 20370). They hold work that exists nowhere else, so
		// an early exit keeps them again instead of removing them.
		reopenedWorktrees = map[int]bool{}
		worktreeMu        sync.Mutex
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
					for id, w := range activeWorktrees {
						if reopenedWorktrees[id] {
							_ = w.Keep(o.config.WorkDir, "the run ended while it held an earlier attempt's work")
							continue
						}
						_ = w.Remove(o.config.WorkDir)
					}
					activeWorktrees = nil
					worktreeMu.Unlock()
				}()
			}
		}
	}

	// Replan / decompose phase (same as sequential).
	if fresh && o.config.Replan && s.Plan != nil {
		pmColor.Printf("Replanning: clearing existing plan (%d tasks) and re-decomposing.\n\n", len(s.Plan.Tasks))
		s.Plan = nil
		if err := o.persist(s, "the plan cleared for --replan"); err != nil {
			return err
		}
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
			return o.failRun(s, fmt.Errorf("decomposing the goal: %w", err))
		}
		if o.config.CalibrationFactor != 0 && o.config.CalibrationFactor != 1.0 {
			pm.ApplyCalibrationFactor(plan, o.config.CalibrationFactor)
		}
		s.Plan = plan
		if err := o.persist(s, "the plan decomposed from the goal"); err != nil {
			return err
		}
		fmt.Printf("\n")
		pmColor.Printf("Task Plan (%d tasks):\n", len(plan.Tasks))
		for _, t := range plan.Tasks {
			fmt.Printf("  %d. [P%d] %s\n", t.ID, t.Priority, t.Title)
			dimColor.Printf("       %s\n", truncate(t.Description, 120))
		}
		fmt.Println()
	} else {
		if fresh && o.config.RetryFailed {
			retried := 0
			for _, t := range s.Plan.Tasks {
				// Never a suspected node killer (Task 20391); see above.
				if t.Status == pm.TaskFailed && !t.Quarantined() {
					t.Status = pm.TaskPending
					retried++
				}
			}
			if retried > 0 {
				if err := o.persist(s, "failed tasks reset to pending by --retry-failed"); err != nil {
					return err
				}
				pmColor.Printf("Retrying %d failed task(s).\n\n", retried)
			}
		}
		pmColor.Printf("Resuming plan: %s\n\n", s.Plan.Summary())
	}

	// Optimization pass (parallel mode).
	if fresh && o.config.Optimize && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		if err := o.runOptimizer(ctx, s, pmColor, dimColor); err != nil {
			return err
		}
	}

	if fresh && o.config.PlanOnly {
		s.SetPaused(pausereason.New(pausereason.CodePlanOnly,
			"plan-only mode: the plan was generated but not executed"))
		return o.persist(s, "the pause (plan-only mode)")
	}

	// Recover any tasks left in_progress from a prior crashed/killed run before
	// scheduling work, so their slots in the dependency graph free up.
	if err := o.recoverStaleTasks(s); err != nil {
		return err
	}

	consecutiveErrors := carry.errors
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
	consecutiveEmptyEvolves := carry.emptyEvolves
	const maxEmptyEvolves = 3

	var mu sync.Mutex

	for {
		select {
		case <-ctx.Done():
			s.SetPaused(pausereason.New(pausereason.CodeCancelled, "run interrupted"))
			if err := o.persist(s, "the pause (run interrupted)"); err != nil {
				return errors.Join(ctx.Err(), err)
			}
			return ctx.Err()
		default:
		}

		if o.config.StepsLimit > 0 && s.CurrentStep >= startStep+o.config.StepsLimit {
			s.SetPaused(pausereason.New(pausereason.CodeStepLimit,
				fmt.Sprintf("--steps limit of %d reached", o.config.StepsLimit)))
			if err := o.persist(s, "the pause (--steps limit reached)"); err != nil {
				return err
			}
			color.New(color.FgYellow).Printf("⏸ Reached --steps limit (%d). Run 'cloop run' to continue.\n", o.config.StepsLimit)
			return nil
		}

		// Token budget check at the top of the loop so it fires during evolve cycles
		// (where the work-execution path's check would otherwise be skipped).
		if o.config.TokenBudget > 0 && s.TotalInputTokens+s.TotalOutputTokens >= o.config.TokenBudget {
			s.SetPaused(pausereason.New(pausereason.CodeTokenBudget,
				fmt.Sprintf("token budget of %d tokens spent", o.config.TokenBudget)))
			if err := o.persist(s, "the pause (token budget reached)"); err != nil {
				return err
			}
			color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
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
			o.queueDone(extID, fmt.Sprintf("merged from disk (status=%s)", t.Status))
		}
		// Reactivate recurring tasks whose schedule has fired.
		for _, t := range s.Plan.Tasks {
			if pm.ResetIfDue(t, time.Now()) {
				dimColor.Printf("↺ Task %d recurring: reset to pending (%s)\n", t.ID, t.Recurrence)
				o.persistBestEffort(s, "a recurring task's reset to pending",
					"every later write stores it, and if none lands the schedule, still due on disk, fires again at the next start")
			}
		}
		// Mid-run mode switch: if the user disabled parallel mode (and lowered
		// max_parallel back to ≤1) via the Web UI, surrender so runPM can
		// re-dispatch into runPMSequential without a process restart
		// (Task 20111). Safe at the top of the loop with no batch in flight.
		// CLI flag wins — if --parallel was passed, stay parallel.
		carry.errors, carry.emptyEvolves = consecutiveErrors, consecutiveEmptyEvolves
		if !o.config.Parallel && !o.wantParallel() {
			return errSwitchMode
		}
		// A newer build of cloop (Task 20389): handed over here, at the top of
		// the loop, where the last round has drained — rounds launch together
		// and wait for each other, so no new task is dispatched while an
		// adoption is pending and the tasks in flight have all finished.
		if err := o.atTaskBoundary(ctx, s, carry, true); err != nil {
			return err
		}
		// Same gate as the sequential loop: no completion and no evolve round
		// on top of tasks whose recorded "work" is a refusal (Task 20224).
		// Safe here for the same reason the mode switch above is — top of the
		// loop, no batch in flight.
		if n := o.sweepAbortedOutcomes(s); n > 0 {
			color.New(color.FgYellow).Printf(
				"↻ %d task(s) recorded as done never actually ran — reopened before checking completion\n", n)
			continue
		}
		if s.Plan.IsComplete() {
			// Same check, same place, as the sequential loop's (Task 20381).
			if s.AutoEvolve {
				if waited, err := o.awaitDiskSpace(ctx, s, nil, "an evolve round"); err != nil {
					return err
				} else if waited {
					continue
				}
			}
			// A run that ends here stores that it did before saying so. One
			// that goes on to evolve announces only what the tasks already
			// recorded.
			if !s.AutoEvolve {
				s.Status = "complete"
				if err := o.persist(s, "the run's status (complete)"); err != nil {
					return err
				}
			}
			line, achieved := settlementLine(s.Plan, s.AutoEvolve)
			banner := successColor
			if !achieved {
				banner = color.New(color.FgYellow, color.Bold)
			}
			banner.Printf("%s\n", line)
			banner.Printf("   %s\n\n", s.Plan.Summary())
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
				o.persistBestEffort(s, "the run's status (evolving)",
					"it only tells the dashboard which phase is running, and the next write replaces it")
				n, err := o.evolvePM(ctx)
				if err != nil {
					// The discovered tasks did not reach the database: the
					// run stops on that, not on the evolve round.
					if errors.Is(err, ErrStateNotPersisted) {
						return err
					}
					// Cancellation (Ctrl-C, deadline) is an interruption, not a
					// completed session — pause so the next run resumes evolving.
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
						s.SetPaused(pausereason.New(pausereason.CodeCancelled,
							"run interrupted while evolving the plan"))
						if saveErr := o.persist(s, "the pause (run interrupted while evolving)"); saveErr != nil {
							return errors.Join(err, saveErr)
						}
						color.New(color.FgMagenta, color.Bold).Printf("\n⏹ Evolve interrupted: %v\n", err)
						if ctxErr := ctx.Err(); ctxErr != nil {
							return ctxErr
						}
						return err
					}
					s.Status = "complete"
					if saveErr := o.persist(s, "the run's status (complete: evolve stopped)"); saveErr != nil {
						return saveErr
					}
					color.New(color.FgMagenta, color.Bold).Printf("\n⏹ Evolve stopped: %v\n", err)
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
						s.Status = "complete"
						if err := o.persist(s, "the run's status (complete: auto-evolve found nothing new)"); err != nil {
							return err
						}
						color.New(color.FgYellow).Printf("⏸ Auto-evolve found no new tasks in %d consecutive attempts and no token/step budget is set. Stopping.\n", maxEmptyEvolves)
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
			// Stored before the announcements above it ran (see the top of
			// this block).
			return nil
		}

		// Decide what runs: dependencies, the blocked sweep, the tag filter and
		// the condition gate, all in GateTasks so this path and
		// runPMSequential cannot disagree about the outcome or how it is
		// worded. Parallel mode differs only in taking every eligible task
		// rather than the single highest-priority one.
		gate := GateTasks(ctx, s.Plan, o.gateConfig(true))
		if gate.Skipped() > 0 {
			if err := o.persist(s, fmt.Sprintf("the execution gate's skips (tasks %v)", gate.SkippedIDs())); err != nil {
				return err
			}
		}
		printGateDecision(gate, failColor, dimColor)
		if len(gate.Runnable) == 0 {
			if gate.Exhausted {
				break
			}
			continue
		}
		ready := gate.Runnable

		// Daily budget enforcement: abort before spending tokens if any limit is exceeded.
		if budgetErr := budget.Enforce(o.config.WorkDir, o.config.Budget, o.config.NotifyCfg); budgetErr != nil {
			s.SetPaused(pausereason.New(pausereason.CodeBudget, budgetErr.Error()))
			if err := o.persist(s, "the pause (budget limit reached)"); err != nil {
				return errors.Join(budgetErr, err)
			}
			failColor.Printf("\n✗ Budget limit reached: %v\n", budgetErr)
			return budgetErr
		}

		// Per-project claudecode subscription cap enforcement. A cap whose
		// window reopens soon is waited out in place rather than ending the
		// run; a distant one pauses with the reset recorded as resumes_at, so
		// the hub can restart it without a human (Task 20285). Shared by both
		// loops so the sequential and parallel paths cannot disagree about
		// what a cap means.
		if ccErr := o.enforceClaudeCodeLimits(); ccErr != nil {
			stop, err := o.handleUsageCap(ctx, s, ccErr)
			if err != nil {
				return errors.Join(ccErr, err)
			}
			if stop {
				return ccErr
			}
			continue
		}

		// Apply worker pool limit: cap the batch to MaxParallel if set.
		// Read from live state (refreshed via SyncFromDisk above) so UI changes
		// to max-parallel take effect on the next iteration without a restart.
		// readyTotal is preserved for the launch-summary log so the operator
		// can see how many tasks were eligible vs. actually launched.
		readyTotal := len(ready)
		maxParallel := s.LiveMaxParallel()
		if maxParallel > 0 && len(ready) > maxParallel {
			ready = ready[:maxParallel]
		}

		// The free-space floor (Task 20381), where a round would launch: the
		// round before has finished and recorded its outcomes, so on a full
		// disk the workers start nothing new and nothing in flight is cut
		// short. The wait ends at the top of the loop, as in the sequential
		// one.
		if waited, err := o.awaitDiskSpace(ctx, s, nil, roundNoun(ready)); err != nil {
			return err
		} else if waited {
			continue
		}

		// A stop that landed while the gates above ran must not launch the
		// batch (Task 20348): every provider call would fail at once, for
		// attempts that never began. The top of the loop pauses the run.
		if runInterrupted(ctx) {
			continue
		}

		// Mark all ready tasks as in-progress before starting goroutines.
		// Each ready task is also enqueued in the central queue so the UI shows
		// a row per parallel task. queueIDs[i] is the id of ready[i] — we reuse
		// the slice index when marking results below to avoid an extra map.
		queueIDs := make([]int64, len(ready))
		now := time.Now()
		// One placement for the whole batch: every task in it runs inside this
		// same process on the executor the hub already chose (Task 20244).
		// Each still gets its own dispatch row — they are separate units of
		// work that end separately, and a batch-level row could not be joined
		// to the task.finish rows that follow (Task 20282).
		facts := make([]dispatchFacts, len(ready))
		for i, t := range ready {
			// A new attempt: see the sequential loop (Task 20365).
			o.clearVerdict(t.ID)
			t.Status = pm.TaskInProgress
			t.StartedAt = &now
			facts[i] = o.beginTaskExecution(t)
		}
		// Stored before the starts are announced or anything runs: a task the
		// database does not show running cannot be stopped from the dashboard,
		// and the start is what stale-task recovery reasons from.
		if err := o.persist(s, fmt.Sprintf("the start of %d task(s) (in progress)", len(ready))); err != nil {
			return err
		}
		for i, t := range ready {
			f := facts[i]
			queueIDs[i] = o.enqueueWork(taskqueue.Entry{
				Kind:        taskqueue.KindTask,
				TaskID:      t.ID,
				Title:       t.Title,
				Description: t.Description,
				Source:      "orchestrator",
			})
			o.queueRunning(queueIDs[i])
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
				"priority":      t.Priority,
				"role":          t.Role,
				"parallel":      true,
				"executor_id":   f.ExecutorID,
				"executor_kind": f.ExecutorKind,
				"isolation":     f.Isolation,
				"run_id":        f.RunID,
			})
		}

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
			o.ensureChainInput(s.Plan, t)
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
				// A worktree an earlier attempt kept — it ended with its work
				// uncommitted (Task 20370) — is where this attempt starts.
				wt, wErr := worktree.Reopen(o.config.WorkDir, t)
				reopened := wt != nil
				if wErr == nil && wt == nil {
					wt, wErr = worktree.Create(o.config.WorkDir, t)
				}
				if wErr != nil {
					dimColor.Printf("  worktree create failed for task %d (%v) — using shared workdir\n", t.ID, wErr)
					continue
				}
				taskWorkDirs[i] = wt.Path
				worktreeMu.Lock()
				activeWorktrees[t.ID] = wt
				reopenedWorktrees[t.ID] = reopened
				worktreeMu.Unlock()
				if reopened {
					dimColor.Printf("  worktree[task %d]: %s (branch %s), reopened as its last attempt left it\n", t.ID, wt.Path, wt.Branch)
				} else {
					dimColor.Printf("  worktree[task %d]: %s (branch %s)\n", t.ID, wt.Path, wt.Branch)
				}
			}
		}

		// Review gate (Task 20357): one hold per task, opened in the task's
		// own directory before any agent in the round starts. Settings and
		// the project facts the review reads are captured here, so the
		// workers never read the live state concurrently with its saves.
		for _, g := range roundGates {
			g.close()
		}
		roundGates = make([]*gateRun, len(ready))
		for i := range ready {
			roundGates[i] = o.openGate(ctx, s.ReviewGate, taskWorkDirs[i])
			if roundGates[i] != nil {
				o.awaitReview(ready[i])
			}
		}
		gateGoal, gateConventions, gateModel := s.Goal, s.Instructions, s.Model

		// Done means committed (Task 20370): one baseline per task, in its
		// own directory, before any agent in the round starts. Tasks that
		// share a working tree cannot have their changes told apart — each
		// would be blamed for the others' — so they are not checked; worktree
		// mode gives each task a tree of its own.
		roundGuards := make([]*commitGuard, len(ready))
		if s.CommitPolicy.Active() {
			sharing := map[string]int{}
			for _, d := range taskWorkDirs {
				sharing[d]++
			}
			for i, t := range ready {
				if n := sharing[taskWorkDirs[i]]; n > 1 {
					note := fmt.Sprintf("Done means committed was not checked: %d tasks shared one working tree in this round, so their changes could not be told apart (--worktree-parallel gives each its own).", n)
					pm.AddAnnotation(t, "cloop", note)
					dimColor.Printf("  done means committed: not checked for task %d — %d tasks share its working tree\n", t.ID, n)
					continue
				}
				g, note := o.openCommitGuard(ctx, s.CommitPolicy, taskWorkDirs[i], t, roundGates[i])
				if note != "" {
					dimColor.Printf("  %s\n", note)
				}
				roundGuards[i] = g
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
		// roundCtx is what this round's workers run under, so a loop that
		// leaves the round early can stop them (leaveRound, below) without
		// cancelling the run: a cancelled run context is how the result
		// handling recognises a stop, and leaving a round is not one.
		roundCtx, cancelRound := context.WithCancel(ctx)
		for i, task := range ready {
			// The worker writes its task's verdict; it gets the ID and start
			// as values so it never reads the shared task to do so.
			taskID, startedAt := task.ID, copyTime(task.StartedAt)
			go func(idx int, t *pm.Task, prompt string, workDir string) {
				// Send exactly one result whether the body completes normally
				// or panics: the consumer below counts results, so a worker
				// that sent none would stall the batch. The defer recovers any
				// panic from the provider call.
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
				opts, _ := o.makeOpts(s.Model, s.LiveEffort(), false) // no streaming in parallel
				opts = o.withBackgroundWaitNotice(opts, s, t, &mu)
				// Worktree-parallel: override the provider's working directory
				// so file edits land in this task's isolated worktree instead
				// of the shared project root. Falls through to o.config.WorkDir
				// when worktree mode is off or creation failed for this task.
				opts.WorkDir = workDir
				gate := roundGates[idx]
				prompt = withGateSection(prompt, gate.promptSection())
				opts.Env = gate.env()
				// Apply per-task time budget in parallel mode.
				tTaskCtx, tTaskCancel := o.taskContextWithTimeout(roundCtx, t)
				defer tTaskCancel()
				// Register the cancel with the watchdog registry so a manual
				// abort from the UI (Task 20140) can cancel a wedged provider
				// call. tTaskCancel is the wrapped cancel returned by
				// taskContextWithTimeout, which unregisters itself when the
				// deferred cancel fires — no explicit Unregister needed here.
				o.watchdog.Register(t.ID, tTaskCancel)
				// Tag context for the audit log so the call lands against this task.
				tAuditCtx := provideraudit.WithTaskContext(tTaskCtx, t.ID, t.Title)
				guard := roundGuards[idx]
				result, turns, err := completeTask(tAuditCtx, taskProvider, prompt, opts, guard)
				// Write live artifact for parallel task (non-streaming).
				if err == nil {
					if lf, lfErr := artifact.OpenLiveArtifact(o.config.WorkDir, t.ID); lfErr == nil {
						_, _ = lf.WriteString(result.Output)
						_ = lf.Close()
					}
				}
				// The decisions this result forces, written down before the
				// consumer prints a line about it (Task 20365). This path has
				// no clarification loop, so a question fails the task here.
				if err == nil && result != nil {
					o.noteEarlyVerdict(taskID, startedAt, result.Output, result.Background, false)
				}
				// Done means committed (Task 20370), decided here for the
				// same reason the review gate runs here, and before it: the
				// gate must not publish work the task has not finished.
				var commitAbort *Abort
				if err == nil && result != nil {
					commitAbort = guard.abortFor(tAuditCtx, result.Output, result.Background)
				}
				// The review gate runs here, in the worker, so reviews of a
				// round's tasks proceed side by side rather than one after
				// another in the consumer below. It sees what the consumer
				// would accept as done: a signalled or unsignalled finish,
				// not a clarification question, not unfinished background
				// work.
				var gateOut *gateOutcome
				if err == nil && result != nil && gate != nil && commitAbort == nil {
					sig := pm.CheckTaskSignal(result.Output)
					if (sig == pm.TaskDone || sig == pm.TaskInProgress) &&
						!looksLikeClarificationQuestion(result.Output) && !result.Background.Incomplete() {
						gateOut = o.passGate(tAuditCtx, gate, gateInput{
							task: t, goal: gateGoal, conventions: gateConventions, prompt: prompt,
							output: result.Output, signal: sig, sessionID: result.SessionID, background: result.Background,
							worker: taskProvider, workerOpts: opts, model: gateModel, commit: guard,
						})
						if len(gateOut.steps) > 0 {
							// The agent's last word is its fix turn's.
							result.Output, result.Background = gateOut.output, gateOut.background
							result.InputTokens += gateOut.workIn
							result.OutputTokens += gateOut.workOut
							result.ThinkingTokens += gateOut.workThinking
						}
						o.noteGateVerdict(taskID, startedAt, gateOut, result.Output, result.Background)
						// The gate's fix turns are the agent's too.
						if len(gateOut.steps) > 0 && !gateOut.fail {
							commitAbort = guard.abortFor(tAuditCtx, result.Output, result.Background)
						}
					}
				}
				dur := time.Since(start)
				timedOut := isTimeoutErr(tTaskCtx, err)
				res = taskResult{task: t, result: result, err: err, duration: dur, timedOut: timedOut,
					continued: turns.unfinished, uncommitted: turns.uncommitted, commitAbort: commitAbort,
					pushed: guard.pushed(), commitNote: guard.passNote(), gate: gateOut}
			}(i, task, prebuiltPrompts[i], taskWorkDirs[i])
		}

		// Consume results in completion order so each task's terminal status
		// is persisted (and pushed to the UI via WebSocket) the moment it
		// finishes — fixes the "task still in_progress after completion" bug
		// when running multiple tasks in parallel.
		parallelTotal := len(ready)
		parallelDone := 0
		// A stop does not abandon the batch where it stands (Task 20348). Every
		// worker shares ctx, so each is already being cancelled, and the
		// result each sends back is what decides its task: work that finished
		// keeps its outcome, and work that was cut short returns to pending
		// below. Abandoning the batch left every task in it in_progress, as if
		// still running, until something recovered it — and a result read just
		// before the cancellation was filed as a failure.
		//
		// runDone is watched until it fires, which arms grace. The grace period
		// bounds the wait for a provider that ignores cancellation.
		runDone := ctx.Done()
		var grace *time.Timer
		var graceC <-chan time.Time
		// leaveRound stops the workers still running and waits — at most
		// parallelShutdownGracePeriod — for them to report, for a loop that
		// returns before its round is over: a pause, a failed run, a write
		// that did not land. Their results are dropped; the run is ending,
		// and whatever they leave in progress is recovered by the next one.
		// Waiting means nothing of this round still touches the state once
		// the run returns — Run's account of why it stopped included. Call it
		// without mu held: a worker may need mu to finish.
		leaveRound := func() {
			cancelRound()
			wait := time.NewTimer(parallelShutdownGracePeriod)
			defer wait.Stop()
			for parallelDone < parallelTotal {
				select {
				case <-resultsCh:
					parallelDone++
				case <-wait.C:
					return
				}
			}
		}
		for parallelDone < parallelTotal {
			var ir indexedResult
			select {
			case ir = <-resultsCh:
				// fall through to per-result processing below
			case <-runDone:
				runDone = nil
				grace = time.NewTimer(parallelShutdownGracePeriod)
				graceC = grace.C
				continue
			case <-graceC:
				// Leaked goroutines may still send to resultsCh afterward; the
				// channel is buffered to len(ready) so the send never blocks,
				// and no one reads it after we return. Nothing in this process
				// will finish their tasks, so they go back to pending now
				// rather than waiting for the next run's recovery pass.
				color.New(color.FgYellow).Printf("⚠ %d task goroutine(s) did not exit within %s of cancellation; returning anyway\n", parallelTotal-parallelDone, parallelShutdownGracePeriod)
				cancelRound()
				mu.Lock()
				for i, t := range ready {
					if t.Status != pm.TaskInProgress {
						continue
					}
					o.requeueInterrupted(s, t, "while the agent was working on it", s.CurrentStep)
					o.queueFailed(queueIDs[i], interruptedQueueNote)
				}
				s.SetPaused(pausereason.New(pausereason.CodeCancelled,
					"run interrupted while parallel tasks were in flight"))
				err := o.persist(s, "the pause (run interrupted while parallel tasks were in flight)")
				mu.Unlock()
				if err != nil {
					return errors.Join(ctx.Err(), err)
				}
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
				reopened := reopenedWorktrees[taskID]
				if ok {
					delete(activeWorktrees, taskID)
					delete(reopenedWorktrees, taskID)
				}
				worktreeMu.Unlock()
				if ok && wt != nil {
					// A reopened worktree holds an earlier attempt's work
					// that exists nowhere else (Task 20370): kept again.
					if reopened {
						if kErr := wt.Keep(o.config.WorkDir, "an attempt that ended early held an earlier attempt's work"); kErr != nil {
							dimColor.Printf("  worktree keep task %d: %v\n", taskID, kErr)
						}
						return
					}
					if rmErr := wt.Remove(o.config.WorkDir); rmErr != nil {
						dimColor.Printf("  worktree remove task %d: %v\n", taskID, rmErr)
					}
				}
			}
			if res.err != nil {
				// Checked before the timeout: under a --timeout the task
				// context inherits the session deadline, so an expired session
				// reads as a task timeout too. Either way the run ending is
				// what stopped the task, not anything it did.
				if runInterrupted(ctx) {
					cleanupWorktree(task.ID)
					mu.Lock()
					o.requeueInterrupted(s, task, "while the agent was working on it", s.CurrentStep)
					o.queueFailed(parallelQueueID, interruptedQueueNote)
					mu.Unlock()
					continue
				}
				if res.timedOut {
					budgetMin := o.effectiveTaskBudgetMinutes(task)
					if err := o.handleTaskTimeout(ctx, s, task, res.partialOut, dimColor, &mu); err != nil {
						leaveRound()
						return err
					}
					color.New(color.FgYellow).Printf("⏱ Task %d timed out (%dm): %s\n", task.ID, budgetMin, task.Title)
					o.queueFailed(parallelQueueID, fmt.Sprintf("timeout (%dm)", budgetMin))
					cleanupWorktree(task.ID)
					consecutiveErrors++
					if consecutiveErrors >= maxConsecutiveErrors {
						leaveRound()
						return o.failRun(s, fmt.Errorf("%d consecutive errors", consecutiveErrors))
					}
					continue
				}
				if provider.IsRetryBudgetExhausted(res.err) {
					cleanupWorktree(task.ID)
					mu.Lock()
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: retry budget exhausted (parallel mode) — %s", truncate(res.err.Error(), 200)))
					task.Status = pm.TaskFailed
					err := o.persistOutcome(s, task, "failure (retry budget exhausted)",
						decidedBy(taskrecover.SourceProvider, "retry_budget_exhausted", truncate(res.err.Error(), 200)))
					mu.Unlock()
					if err != nil {
						leaveRound()
						return err
					}
					failColor.Printf("✗ Task %d: retry budget exhausted (parallel) — %v\n", task.ID, res.err)
					o.queueFailed(parallelQueueID, "retry budget exhausted")
					consecutiveErrors++
					if consecutiveErrors >= maxConsecutiveErrors {
						leaveRound()
						return o.failRun(s, fmt.Errorf("%d consecutive errors", consecutiveErrors))
					}
					continue
				}
				cleanupWorktree(task.ID)
				mu.Lock()
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed: provider error (parallel mode) — %s", truncate(res.err.Error(), 200)))
				task.Status = pm.TaskFailed
				err := o.persistOutcome(s, task, "failure (provider error)",
					decidedBy(taskrecover.SourceProvider, "provider_error", truncate(res.err.Error(), 200)))
				mu.Unlock()
				if err != nil {
					leaveRound()
					return err
				}
				failColor.Printf("✗ Provider error on task %d: %v\n", task.ID, res.err)
				o.queueFailed(parallelQueueID, truncate(res.err.Error(), 200))
				consecutiveErrors++
				if consecutiveErrors >= maxConsecutiveErrors {
					leaveRound()
					return o.failRun(s, fmt.Errorf("%d consecutive errors", consecutiveErrors))
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
				cleanupWorktree(task.ID)
				consecutiveErrors++
				ab := Abort{Class: AbortEmptyOutput, Reason: fmt.Sprintf("provider returned empty output (parallel mode, consecutive errors: %d/%d)", consecutiveErrors, maxConsecutiveErrors)}
				mu.Lock()
				err := o.abortTask(s, task, ab, s.CurrentStep)
				mu.Unlock()
				if err != nil {
					leaveRound()
					return err
				}
				o.queueFailed(parallelQueueID, abortSummaryForQueue(ab))
				if consecutiveErrors >= maxConsecutiveErrors {
					leaveRound()
					return o.failRun(s, fmt.Errorf("%d consecutive task failures (empty provider output)", consecutiveErrors))
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
			if res.continued > 0 {
				pm.AddAnnotation(task, "cloop", continuedTurnNote(res.continued))
			}
			if res.uncommitted > 0 {
				pm.AddAnnotation(task, "cloop", uncommittedTurnNote(res.uncommitted, res.pushed))
			}
			if res.commitNote != "" && res.commitAbort == nil {
				pm.AddAnnotation(task, "cloop", res.commitNote)
			}
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
				mu.Lock()
				task.Status = pm.TaskPending
				o.noteVerdict(task, pm.TaskPending, budgetWhy("token_budget", "the token budget ran out"))
				s.SetPaused(pausereason.New(pausereason.CodeTokenBudget,
					fmt.Sprintf("token budget of %d tokens spent", o.config.TokenBudget)))
				err := o.persist(s, "the pause (token budget reached), with the task back to pending")
				mu.Unlock()
				leaveRound()
				if err != nil {
					return err
				}
				color.New(color.FgYellow).Printf("⏸ Token budget reached (%d tokens). Run 'cloop run' to continue.\n", o.config.TokenBudget)
				return nil
			}
			if spent, over := o.costLimitReached(s); over {
				mu.Lock()
				task.Status = pm.TaskPending
				o.noteVerdict(task, pm.TaskPending, budgetWhy("cost_limit", "the cost limit was reached: "+spent))
				s.SetPaused(pausereason.New(pausereason.CodeBudget, "cost limit reached: "+spent))
				err := o.persist(s, "the pause (cost limit reached), with the task back to pending")
				mu.Unlock()
				leaveRound()
				if err != nil {
					return err
				}
				color.New(color.FgRed).Printf("⏸ Cost limit reached (%s). Run 'cloop run' to continue.\n", spent)
				return nil
			}

			signal := pm.CheckTaskSignal(result.Output)
			// Who settled the outcome, for the verdict recovery reads (Task
			// 20365); see the sequential loop.
			decided := agentWhy(signal)
			// Fail-closed for unanswered clarification questions: the parallel
			// path has no auto-resolve loop, so a TaskInProgress with
			// clarification questions would otherwise fall into the `default:`
			// arm of the switch below and be silently marked DONE.
			clarificationReroute := false
			if signal == pm.TaskInProgress && looksLikeClarificationQuestion(result.Output) {
				signal = pm.TaskFailed
				clarificationReroute = true
				decided = clarificationWhy()
			}
			completedAt := time.Now()
			task.CompletedAt = &completedAt
			task.Result = truncate(result.Output, 500)
			if task.StartedAt != nil {
				task.ActualMinutes = int(completedAt.Sub(*task.StartedAt).Minutes())
			}

			taskDur := res.duration.Round(time.Second).String()
			taskDurMs := res.duration.Milliseconds()
			// Set by the switch below when the run produced no work. Read
			// after mu is released, because the retry it schedules may sleep.
			var abortedTask *Abort
			mu.Lock()
			if clarificationReroute {
				pm.AddAnnotation(task, "ai", "Task failed: LLM asked clarification questions instead of completing the work (parallel mode has no auto-resolve loop).")
			}
			// Background work the agent left running (Task 20205). Held under
			// the same lock as the rest of the task mutation below: several of
			// these goroutines run at once, and this both writes task fields
			// and decides the signal the switch is about to act on.
			beforeBackground := signal
			signal = applyBackgroundOutcome(task, result.Background, signal)
			backgroundWork := task.Background
			if backgroundWork != nil && backgroundWork.State == pm.BackgroundAbandoned {
				task.FailureDiagnosis = backgroundFailureDiagnosis(backgroundWork)
			}
			if signal != beforeBackground {
				decided = backgroundWhy(backgroundWork)
			}
			// Review gate (Task 20357): the worker reviewed the task; what
			// the gate did not let through fails here.
			reviewReroute := false
			gateOut := res.gate
			if gateOut != nil {
				task.Review = gateOut.review
				pm.AddAnnotation(task, "reviewer", gateOut.note)
				s.TotalInputTokens += gateOut.reviewIn
				s.TotalOutputTokens += gateOut.reviewOut
				if gateOut.fail && signal != pm.TaskSkipped {
					signal = pm.TaskFailed
					reviewReroute = true
					task.FailureDiagnosis = gateOut.review.Diagnosis()
					if !gateOut.review.Blocked {
						task.FailureDiagnosis = gateOut.note
					}
				}
				if reviewReroute || signal == pm.TaskDone {
					decided = gateWhy(gateOut)
				}
			}
			// Decide the outcome first, store it, and only then announce it, so
			// a write that fails leaves nothing claiming a status the database
			// does not hold.
			implicitDone := false
			switch {
			case res.commitAbort != nil && (signal == pm.TaskDone || signal == pm.TaskInProgress):
				// Done means committed (Task 20370): the worker found the
				// attempt's work outstanding. Back to pending, the work left
				// where the agent put it.
				consecutiveErrors++
				abortedTask = res.commitAbort
			case signal == pm.TaskDone:
				task.Status = pm.TaskDone
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task completed successfully in %s.", taskDur))
				consecutiveErrors = 0
			case signal == pm.TaskSkipped:
				task.Status = pm.TaskSkipped
				pm.AddAnnotation(task, "ai", fmt.Sprintf("Task skipped per AI TASK_SKIPPED signal after %s.", taskDur))
				consecutiveErrors = 0
			case signal == pm.TaskFailed:
				task.Status = pm.TaskFailed
				task.FailCount++
				// Skip the explicit-signal annotation when the failure came from
				// the clarification reroute above — the reroute already added an
				// accurate annotation, and claiming "per AI TASK_FAILED signal"
				// would misattribute it. Likewise a review gate failure,
				// annotated where the gate's outcome was applied.
				if !clarificationReroute && !reviewReroute {
					pm.AddAnnotation(task, "ai", fmt.Sprintf("Task failed per AI TASK_FAILED signal after %s.", taskDur))
				}
				consecutiveErrors++
			default:
				// Same evidence rule as the sequential loop — see the
				// `default:` arm of runPMSequential. The diff half is not
				// available here: several workers mutate the tree at once, so
				// a repository fingerprint taken around one task would credit
				// it with another's changes. The artifact and the classifier
				// still apply, which is what catches provider refusals.
				if ab, aborted := decideUnsignalled(o.config.WorkDir, task.ArtifactPath, result.Output, false); aborted {
					consecutiveErrors++
					abortedTask = &ab
					break
				}
				task.Status = pm.TaskDone
				implicitDone = true
				pm.AddAnnotation(task, "ai", "Task implicitly completed (parallel mode): AI finished without an explicit TASK_DONE/TASK_FAILED/TASK_SKIPPED signal — treated as done.")
				consecutiveErrors = 0
			}
			var err error
			switch {
			case abortedTask != nil:
				// abortTask stores the task back at pending before it says so.
				err = o.abortTask(s, task, *abortedTask, s.CurrentStep)
			case implicitDone:
				err = o.persistOutcome(s, task, "completion (no explicit signal)", implicitDoneWhy())
			default:
				err = o.persistOutcome(s, task, outcomeNoun(task.Status), decided)
			}
			if err != nil {
				mu.Unlock()
				leaveRound()
				return err
			}

			switch {
			case abortedTask != nil:
				// The run produced no work: abortTask has said so, and the
				// task is pending — not an outcome to announce.
			case task.Status == pm.TaskDone:
				if !o.log.IsJSON() {
					if implicitDone {
						successColor.Printf("✓ Task %d complete (no explicit signal): %s\n\n", task.ID, task.Title)
					} else {
						successColor.Printf("✓ Task %d complete: %s\n\n", task.ID, task.Title)
					}
				}
				fields := map[string]interface{}{"duration_ms": taskDurMs}
				if implicitDone {
					fields["implicit"] = true
				}
				o.log.Info(logger.EventTaskDone, task.ID, task.Title, fields)
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
			case task.Status == pm.TaskSkipped:
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
			case task.Status == pm.TaskFailed:
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
			}

			// Central queue: mark this parallel work item terminal. An aborted
			// run marks its entry failed and leaves the task pending, which the
			// `default:` arm below would otherwise record as done — the same
			// fail-open shape the abort path exists to close.
			if abortedTask != nil {
				o.queueFailed(parallelQueueID, abortSummaryForQueue(*abortedTask))
			} else {
				switch task.Status {
				case pm.TaskDone:
					o.queueDone(parallelQueueID, stepSummaryLine(result.Output, 200))
				case pm.TaskFailed:
					o.queueFailed(parallelQueueID, stepSummaryLine(result.Output, 200))
				case pm.TaskSkipped:
					o.queueSkipped(parallelQueueID, "AI emitted TASK_SKIPPED")
				default:
					o.queueDone(parallelQueueID, stepSummaryLine(result.Output, 200))
				}
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
						// The review gate stands in front of the merge queue:
						// only the tree the reviewer approved is merged.
						if ok, why := o.gateAllowsMergeOf(ctx, roundGates[resIdx], gateOut, wt.Path, "HEAD"); !ok {
							dimColor.Printf("  worktree: not merging %s — %s\n", wt.Branch, why)
							pm.AddAnnotation(task, "reviewer", fmt.Sprintf("Review gate: branch %s was not merged — %s.", wt.Branch, why))
							break
						}
						mr := mergeQ.Submit(mergequeue.Request{
							Branch: wt.Branch,
							TaskID: task.ID,
							Title:  task.Title,
						})
						// Block on the merge so the next round's worktrees see
						// the merged base. Submissions are FIFO inside the
						// queue, so this preserves the requested ordering.
						// Also select on ctx: the mergequeue worker exits on
						// cancellation, so a Submit that landed in the buffered
						// channel after the worker stopped is never processed
						// and mr.Done would block forever.
						select {
						case <-mr.Done:
							if mr.Err != nil {
								dimColor.Printf("  worktree merge task %d: %v (branch %s left for manual resolution)\n", task.ID, mr.Err, wt.Branch)
								pm.AddAnnotation(task, "ai", fmt.Sprintf("Worktree merge conflict: %s — branch %s preserved.", truncate(mr.Err.Error(), 200), wt.Branch))
							} else {
								dimColor.Printf("  worktree merged: %s → %s (task %d)\n", wt.Branch, worktreeBase, task.ID)
							}
						case <-ctx.Done():
							// Treat as merge not performed — leave the branch for
							// manual resolution, mirroring the merge-error path.
							dimColor.Printf("  worktree merge task %d: skipped (run cancelled) — branch %s left for manual resolution\n", task.ID, wt.Branch)
							pm.AddAnnotation(task, "ai", fmt.Sprintf("Worktree merge skipped: run cancelled before merge completed — branch %s preserved.", wt.Branch))
						}
					case pm.TaskFailed, pm.TaskSkipped:
						dimColor.Printf("  worktree: keeping branch %s for inspection (task %s)\n", wt.Branch, task.Status)
					}
					worktreeMu.Lock()
					reopened := reopenedWorktrees[task.ID]
					worktreeMu.Unlock()
					// An attempt that stopped short, or left its work
					// uncommitted, keeps its worktree for the next attempt:
					// removing it would discard that work, since the branch
					// holds only what was committed (Task 20370). So does one
					// that held an earlier attempt's work and ended any way
					// but done.
					if keepsWorktree(abortedTask) || (reopened && task.Status != pm.TaskDone) {
						why := fmt.Sprintf("the task's attempt ended %s", task.Status)
						if abortedTask != nil {
							why = string(abortedTask.Class) + ": " + abortedTask.Reason
						}
						if kErr := wt.Keep(o.config.WorkDir, why); kErr != nil {
							dimColor.Printf("  worktree keep task %d: %v\n", task.ID, kErr)
						} else {
							dimColor.Printf("  worktree: kept %s for task %d's next attempt\n", wt.Path, task.ID)
						}
					} else if rmErr := wt.Remove(o.config.WorkDir); rmErr != nil {
						// Otherwise the on-disk worktree goes (the branch ref
						// survives).
						dimColor.Printf("  worktree remove task %d: %v\n", task.ID, rmErr)
					}
					worktreeMu.Lock()
					delete(activeWorktrees, task.ID)
					delete(reopenedWorktrees, task.ID)
					worktreeMu.Unlock()
				}
			}

			// Unified event journal — one terminal event per task outcome
			// (Task 20118). mu is already held from the switch above, so
			// re-acquiring it here would deadlock; just read s.CurrentStep
			// under the existing lock.
			parallelStep := s.CurrentStep
			o.logTaskOutcomeEvent(task, taskDur, parallelStep)

			// Review gate (Task 20357): journal and bill the review, and say
			// so when a task that never reached it had pushes waiting. The
			// hold is released now that the task is decided.
			if gateOut != nil {
				o.logReviewEvent(s, task, gateOut)
				o.recordReviewCost(task, gateOut)
			} else if resIdx < len(roundGates) {
				roundGates[resIdx].withheldNote(task)
			}
			if resIdx < len(roundGates) {
				roundGates[resIdx].close()
			}

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

			// Conditional branching: activate the matching branch, skip the
			// other. Stored before it is announced, with the rest of this
			// result: a branch skipped in memory only would run at the next
			// start.
			activations := pm.ResolveBranch(s.Plan, task)
			tooManyErrors := consecutiveErrors >= maxConsecutiveErrors
			err = o.saveOutcome(s, task, "step record: artifact, notes and the branch it chose")
			mu.Unlock()
			if err != nil {
				leaveRound()
				return err
			}
			if len(activations) > 0 {
				branchColor := color.New(color.FgCyan)
				for _, a := range activations {
					if a.Activated {
						branchColor.Printf("  branch [%s] activated  -> task %d: %s\n", a.Branch, a.TaskID, a.Title)
					} else {
						color.New(color.Faint).Printf("  branch [%s] skipped    -> task %d: %s\n", a.Branch, a.TaskID, a.Title)
					}
				}
			}

			// Wait out a usage window (or pause on a quota/credential wall)
			// before the next round picks the now-pending task straight back
			// up. Done outside the lock: it sleeps.
			if abortedTask != nil && !(tooManyErrors && abortedTask.Class == AbortUncommittedWork) {
				stop, err := o.scheduleAbortRetry(ctx, s, *abortedTask, &mu)
				if err != nil {
					leaveRound()
					return err
				}
				if stop {
					leaveRound()
					return nil
				}
			}

			// Journalled outside the lock: it writes to the event DB, not to
			// task state, and holding the shared mutex across that write would
			// serialise every parallel worker behind it.
			if backgroundWork != nil {
				o.logBackgroundEvent(s, task, backgroundWork)
			}

			if tooManyErrors {
				leaveRound()
				if abortedTask != nil && abortedTask.Class == AbortUncommittedWork {
					return o.pauseForUncommittedWork(s, task, *abortedTask, consecutiveErrors, &mu)
				}
				return o.failRun(s, fmt.Errorf("%d consecutive task failures", consecutiveErrors))
			}
		}
		cancelRound()
		// If the run was stopped, the whole batch reported back inside the
		// grace period; the top of the loop sees the cancellation and pauses.
		if grace != nil {
			grace.Stop()
		}
	}

	// The loop exits when nothing is left to schedule. That is the ordinary end
	// of a run rather than a fault, but it is still a pause: auto-evolve or an
	// operator may add work to the same plan, so the project is not complete.
	s.SetPaused(pausereason.New(pausereason.CodeIdle,
		"every runnable task is finished"))
	if err := o.persist(s, "the pause (every runnable task is finished)"); err != nil {
		return err
	}

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

// ensureChainInput gives a chained task its predecessor's output if nothing in
// this process has yet (Task 20361).
//
// injectChainOutput hands the output over the moment the predecessor finishes,
// but only in memory: ChainInput is not stored, because it is a copy of up to
// 16 MiB of transcript that every save would otherwise rewrite. So a run that
// stopped between the two tasks, a resumed project, and a parallel run (whose
// completion path never calls injectChainOutput) all dispatched the chained
// task without its input. Everything the hand-over needs is stored — the
// chain tag, DependsOn, the predecessor's status and its artifact or summary —
// so it is done again here, at dispatch, under the same rule: a predecessor
// that is done and whose chain tag this task carries. When several qualify,
// the one that finished last wins, as it does when injectChainOutput runs once
// per completion.
func (o *Orchestrator) ensureChainInput(plan *pm.Plan, task *pm.Task) {
	if task.ChainInput != "" || plan == nil {
		return
	}
	var from *pm.Task
	for _, id := range task.DependsOn {
		dep := plan.TaskByID(id)
		if dep == nil || dep.Status != pm.TaskDone {
			continue
		}
		if tag := chainTagOf(dep.Tags); tag == "" || !hasChainTag(task.Tags, tag) {
			continue
		}
		if from == nil || finishedAfter(dep, from) {
			from = dep
		}
	}
	if from == nil {
		return
	}
	task.ChainInput = artifact.ReadTaskOutput(o.config.WorkDir, from)
}

// finishedAfter reports whether a completed after b. A task with no completion
// time sorts first, so a recorded finish is preferred over a missing one.
func finishedAfter(a, b *pm.Task) bool {
	if a.CompletedAt == nil {
		return false
	}
	return b.CompletedAt == nil || a.CompletedAt.After(*b.CompletedAt)
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
func (o *Orchestrator) makeOpts(model, effort string, streaming bool) (provider.Options, func() bool) {
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
		Effort:           effort,
	}
	if streaming && o.config.Streaming {
		opts.OnToken = func(token string) {
			fmt.Print(token)
			streamed = true
		}
	}
	return opts, func() bool { return streamed }
}

// withBackgroundWaitNotice attaches the live notification for background work
// an agent left running (Task 20205), so a task blocked on somebody's training
// run is visibly blocked instead of merely slow.
//
// The callback fires from inside the provider call, while the task is still
// executing. It records the wait on the task and saves, which is what pushes
// the state to the dashboard; mu guards the task because the parallel path
// runs several of these at once. Passing a nil mutex is allowed for the
// sequential path, which has no contention.
func (o *Orchestrator) withBackgroundWaitNotice(opts provider.Options, s *state.ProjectState, task *pm.Task, mu sync.Locker) provider.Options {
	opts.OnBackgroundWait = func(activity provider.BackgroundActivity) {
		work := noteBackgroundWait(activity)
		if mu != nil {
			mu.Lock()
		}
		task.Background = work
		o.persistBestEffort(s, fmt.Sprintf("task #%d's wait on background work", task.ID),
			"it only tells the dashboard why the task looks slow, and the task's outcome write replaces it")
		if mu != nil {
			mu.Unlock()
		}
		o.logBackgroundEvent(s, task, work)
		color.New(color.FgYellow).Printf(
			"⏳ Task %d: waiting for %d background process(es) the agent left running (%v)\n",
			task.ID, work.Detected, work.Commands)
	}
	return opts
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
		Step:    state.NoStep,
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
	o.queueRunning(evolveQueueID)

	prompt := pm.EvolveDiscoverPrompt(s.Goal, s.Instructions, s.Plan, s.EvolveStep, s.InnovateMode)
	opts, _ := o.makeOpts(s.Model, s.LiveEffort(), true)
	result, err := safeComplete(ctx, o.provider, prompt, opts)
	if err != nil {
		o.queueFailed(evolveQueueID, truncate(err.Error(), 200))
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
		o.persistBestEffort(s, "an evolve round's bookkeeping (its step and tokens)",
			"no task and no plan content changed, and the next write stores them too")
		o.queueFailed(evolveQueueID, fmt.Sprintf("parse error: %v", err))
		dimColor.Printf("  Task discovery parse error: %v\n", err)
		return 0, nil
	}
	if len(newTasks) == 0 {
		o.persistBestEffort(s, "an evolve round's bookkeeping (its step and tokens)",
			"no task and no plan content changed, and the next write stores them too")
		o.queueDone(evolveQueueID, "no new tasks discovered")
		dimColor.Printf("  No new tasks discovered — project is fully evolved.\n")
		state.LogEventDetails(o.config.WorkDir, state.EventRow{
			Type:    state.EventEvolveNoOp,
			Step:    state.NoStep,
			Message: fmt.Sprintf("Evolve round #%d found no new tasks", s.EvolveStep),
		}, map[string]any{"evolve_step": s.EvolveStep})
		return 0, nil
	}

	// Semantic deduplication: filter out candidates that duplicate existing work.
	if !o.config.NoDedup {
		dedupOpts, _ := o.makeOpts(s.Model, s.LiveEffort(), false)
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
		o.persistBestEffort(s, "an evolve round's bookkeeping (its step and tokens)",
			"no task and no plan content changed, and the next write stores them too")
		o.queueDone(evolveQueueID, "all candidates were duplicates")
		dimColor.Printf("  No novel tasks after deduplication — project is fully evolved.\n")
		state.LogEventDetails(o.config.WorkDir, state.EventRow{
			Type:    state.EventEvolveNoOp,
			Step:    state.NoStep,
			Message: fmt.Sprintf("Evolve round #%d: all candidates duplicates", s.EvolveStep),
		}, map[string]any{"evolve_step": s.EvolveStep})
		return 0, nil
	}

	s.Plan.Tasks = append(s.Plan.Tasks, newTasks...)
	// The discovered tasks are only real once they are stored. Reporting a
	// count for tasks the next run will not find is how auto-evolve builds on
	// work that never existed.
	if err := o.persist(s, fmt.Sprintf("the %d task(s) auto-evolve discovered", len(newTasks))); err != nil {
		o.queueFailed(evolveQueueID, "discovered tasks not saved")
		return 0, err
	}
	o.queueDone(evolveQueueID, fmt.Sprintf("discovered %d new task(s)", len(newTasks)))

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
			Step:    state.NoStep,
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
	o.queueRunning(queueID)
	summary, err := learning.Distill(ctx, o.provider, o.state.Model, plan)
	if err != nil {
		o.queueFailed(queueID, truncate(err.Error(), 200))
		dimColor.Printf("  Memory distillation failed (ignored): %v\n", err)
		return
	}
	if summary == "" {
		o.queueDone(queueID, "no memory update needed")
		dimColor.Printf("  No memory update needed.\n")
		return
	}
	if err := learning.SaveMemory(o.config.WorkDir, summary); err != nil {
		o.queueFailed(queueID, fmt.Sprintf("save memory: %v", err))
		dimColor.Printf("  Failed to save memory (ignored): %v\n", err)
		return
	}
	o.queueDone(queueID, "memory updated")
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
	o.queueRunning(queueID)

	learnings, err := memory.ExtractLearnings(ctx, o.provider, o.state.Model, o.state.Goal, summary, o.memory)
	if err != nil {
		o.queueFailed(queueID, truncate(err.Error(), 200))
		dimColor.Printf("  Memory extraction failed: %v\n", err)
		return
	}
	if len(learnings) == 0 {
		o.queueDone(queueID, "no new learnings extracted")
		dimColor.Printf("  No new learnings extracted.\n")
		return
	}
	if err := o.memory.Save(o.config.WorkDir); err != nil {
		o.queueFailed(queueID, fmt.Sprintf("save memory: %v", err))
		dimColor.Printf("  Failed to save memory: %v\n", err)
		return
	}
	o.queueDone(queueID, fmt.Sprintf("saved %d learning(s)", len(learnings)))
	dimColor.Printf("  Saved %d learning(s) to project memory.\n", len(learnings))
}

// costLimitReached evaluates the current session cost against the configured
// CostLimit. It warns at 80% and reports over=true, with the spend formatted
// against the limit, once the limit is reached. The caller pauses the run and
// announces it — after the pause is stored. model and provider come from
// state/config respectively.
func (o *Orchestrator) costLimitReached(s *state.ProjectState) (spent string, over bool) {
	if o.config.CostLimit <= 0 {
		return "", false
	}
	model := s.Model
	if model == "" {
		model = o.config.Model
	}
	usd := cost.EstimateSessionCost(o.config.ProviderName, model, s.TotalInputTokens, s.TotalOutputTokens)
	if usd >= o.config.CostLimit {
		return cost.FormatCostWithLimit(usd, o.config.CostLimit), true
	}
	if usd >= o.config.CostLimit*0.8 {
		color.New(color.FgYellow).Printf(
			"  Cost warning: %s (80%% of limit %s)\n",
			cost.FormatCost(usd), cost.FormatCost(o.config.CostLimit),
		)
	}
	return "", false
}

// printSessionSummary prints a one-line summary after a run session ends.
// It is called via defer so it always runs, even on error paths.
// runOptimizer calls the AI plan optimizer, prints suggestions, and applies
// the reordering automatically (or interactively if OptimizeInteractive is set).
// A snapshot of the pre-optimization plan is saved before any changes. The
// error is the reordered plan's write, which the run cannot carry on without:
// it would execute in an order the database does not hold.
func (o *Orchestrator) runOptimizer(ctx context.Context, s *state.ProjectState, pmColor, dimColor *color.Color) error {
	pmColor.Printf("Running AI plan optimizer...\n")

	queueID := o.enqueueWork(taskqueue.Entry{
		Kind:        taskqueue.KindSession,
		Title:       "AI plan optimizer",
		Description: fmt.Sprintf("optimize plan with %d task(s)", len(s.Plan.Tasks)),
		Source:      "orchestrator",
	})
	o.queueRunning(queueID)

	result, err := optimizer.Optimize(ctx, o.provider, s.Model, o.config.StepTimeout, s.Plan)
	if err != nil {
		o.queueFailed(queueID, truncate(err.Error(), 200))
		fmt.Printf("  optimizer: %v (skipping)\n\n", err)
		return nil
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
		o.queueDone(queueID, "no reordering suggested")
		dimColor.Printf("  No reordering suggested.\n\n")
		return nil
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
		if err := o.persist(s, "the plan as the optimizer reordered it"); err != nil {
			o.queueFailed(queueID, "reordered plan not saved")
			return err
		}
		pmColor.Printf("Plan reordered. Updated Task Plan:\n")
		for _, t := range s.Plan.Tasks {
			fmt.Printf("  %d. [P%d] %s\n", t.ID, t.Priority, t.Title)
		}
		fmt.Println()
		o.queueDone(queueID, fmt.Sprintf("reordered %d task(s)", len(result.ReorderedIDs)))
	} else {
		dimColor.Printf("  Reordering skipped.\n\n")
		o.queueSkipped(queueID, "user declined reordering")
	}
	return nil
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
