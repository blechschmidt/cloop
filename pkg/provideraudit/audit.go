// Package provideraudit records every Provider.Complete invocation into a
// per-project SQLite audit log so the Web UI's "Provider Calls" panel can
// show recent calls in real time, let users open a modal with the full
// prompt/response/headers, and replay a call with edited input.
//
// The package wraps a provider.Provider in WithAudit and is composed by
// pkg/provider.Build above WithRequestIDTracing/WithPanicSafety. It is a
// best-effort observer: persistence failures (DB locked, disk full) MUST
// NOT fail the originating provider call. The wrapper therefore swallows
// every error from pkg/state once it has logged the failure to stderr.
//
// Redaction is applied to the headers blob before insert, never at read
// time, so on-disk rows are guaranteed safe even if a future caller forgets
// to redact. The prompt and response themselves are stored verbatim — they
// originate from user/orchestrator input and never carry the cloop binary's
// own credentials.
package provideraudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/reqid"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// taskCtxKey is the unexported context key used to propagate the active
// task ID/title from the orchestrator into provider.Complete calls so the
// audit log can correlate calls with tasks. Other code should use
// WithTaskContext to attach values.
type taskCtxKey struct{}

type taskContext struct {
	ID    int
	Title string
}

// WithTaskContext returns a copy of ctx that carries the active task's
// id and title. The orchestrator binds this just before invoking
// p.Complete so the audit row can record which task issued the call.
// Empty/zero values are accepted as "no task bound".
func WithTaskContext(ctx context.Context, id int, title string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if id <= 0 && title == "" {
		return ctx
	}
	return context.WithValue(ctx, taskCtxKey{}, taskContext{ID: id, Title: title})
}

func taskFromContext(ctx context.Context) (int, string) {
	if ctx == nil {
		return 0, ""
	}
	v, _ := ctx.Value(taskCtxKey{}).(taskContext)
	return v.ID, v.Title
}

// CallNotifier is the optional callback invoked when a new call has been
// persisted. The Web UI server registers one of these via SetGlobalNotifier
// so it can push the row over the active WebSocket connections immediately
// instead of waiting for the client to poll.
//
// Implementations MUST be non-blocking (no I/O in the calling goroutine —
// fan out to a worker channel) and MUST NOT panic. The audit wrapper does
// not recover from panics in the notifier path; that is the notifier's
// responsibility.
type CallNotifier func(workDir string, row statedb.ProviderCallRow)

var globalNotifier atomic.Pointer[CallNotifier]

// SetGlobalNotifier registers (or replaces) the global notifier. Pass nil
// to disable notifications. The pointer-based atomic swap means the audit
// wrapper can read the current notifier without locking on every call.
func SetGlobalNotifier(n CallNotifier) {
	if n == nil {
		globalNotifier.Store(nil)
		return
	}
	globalNotifier.Store(&n)
}

// WithAudit returns a Provider that records every Complete invocation to
// the per-project audit log identified by the WorkDir option. When WorkDir
// is empty the call is forwarded unmodified — observability is opt-in via
// the workdir, not mandatory.
//
// Idempotent: applying the wrapper twice has the same effect as applying
// it once. Composes safely with WithPanicSafety / WithRequestIDTracing in
// either order, but the canonical assembly in pkg/provider.Build places
// audit BELOW request-id tagging so the audit row records the same id
// the caller sees attached to errors.
func WithAudit(p provider.Provider) provider.Provider {
	if p == nil {
		return nil
	}
	if _, already := p.(*auditWrapper); already {
		return p
	}
	return &auditWrapper{inner: p}
}

type auditWrapper struct {
	inner provider.Provider
}

func (a *auditWrapper) Name() string         { return a.inner.Name() }
func (a *auditWrapper) DefaultModel() string { return a.inner.DefaultModel() }

func (a *auditWrapper) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	start := time.Now()
	res, err := a.inner.Complete(ctx, prompt, opts)
	latency := time.Since(start)

	// Never fail user work on observability errors. Wrap the persistence
	// step in defer/recover so a panic inside json.Marshal or pkg/state
	// surfaces as a stderr line, not a crash.
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Fprintf(os.Stderr, "provideraudit: panic recording call: %v\n", rec)
		}
	}()

	workDir := opts.WorkDir
	// Skip recording when no project is bound — ad-hoc CLI commands that
	// don't carry a workdir (e.g. tests, one-off `cloop ask`) shouldn't
	// litter every project's DB. The Web UI is the consumer; if there's
	// no project there's no panel to populate.
	if workDir == "" {
		return res, err
	}

	row := buildRow(workDir, ctx, prompt, opts, res, err, latency)
	persistAndNotify(workDir, row)
	return res, err
}

// buildRow assembles a ProviderCallRow from the call inputs and outputs.
// All redaction has already happened by the time the row is built — the
// headers blob is JSON, with API keys masked.
func buildRow(workDir string, ctx context.Context, prompt string, opts provider.Options, res *provider.Result, err error, latency time.Duration) statedb.ProviderCallRow {
	taskID, taskTitle := taskFromContext(ctx)

	headersJSON := buildHeadersJSON(opts)
	status := "ok"
	errMsg := ""
	output := ""
	in := 0
	out := 0
	think := 0
	providerName := ""
	model := opts.Model

	if res != nil {
		output = res.Output
		in = res.InputTokens
		out = res.OutputTokens
		think = res.ThinkingTokens
		if res.Provider != "" {
			providerName = res.Provider
		}
		if res.Model != "" {
			model = res.Model
		}
	}
	if err != nil {
		status = classifyError(err)
		errMsg = redactErrorMessage(err.Error())
		output = ""
	}

	return statedb.ProviderCallRow{
		Timestamp:      time.Now().UTC(),
		Provider:       providerName,
		Model:          model,
		TaskID:         taskID,
		TaskTitle:      taskTitle,
		RequestID:      reqid.FromContext(ctx),
		Prompt:         prompt,
		SystemPrompt:   opts.SystemPrompt,
		Response:       output,
		ErrorMessage:   errMsg,
		Status:         status,
		Headers:        headersJSON,
		InputTokens:    in,
		OutputTokens:   out,
		ThinkingTokens: think,
		LatencyMs:      int(latency / time.Millisecond),
	}
}

// persistAndNotify writes the row into the project DB then fires the
// global notifier (if any). Both paths are best-effort; failures are
// reported to stderr and otherwise discarded.
func persistAndNotify(workDir string, row statedb.ProviderCallRow) {
	id, err := state.AppendProviderCall(workDir, row)
	if err != nil {
		fmt.Fprintf(os.Stderr, "provideraudit: persist %s: %v\n", workDir, err)
		return
	}
	row.ID = id

	if np := globalNotifier.Load(); np != nil {
		(*np)(workDir, row)
	}
}

// classifyError maps an arbitrary error onto the small enum stored in the
// `status` column. The values are stable for the API consumer; never
// rename them in place.
func classifyError(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "context_canceled"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") {
		return "timeout"
	}
	if strings.Contains(msg, "context canceled") {
		return "context_canceled"
	}
	return "error"
}

// buildHeadersJSON synthesises a JSON blob describing the call's "headers"
// (request shape) for display in the inspector modal. We don't have the
// real HTTP headers at this layer — the wrapper sits above the provider's
// http.Request — so this is a synthetic projection of the Options struct
// plus any Bearer/key value we might know to be in scope (which we mark
// [REDACTED] without ever including the actual secret).
func buildHeadersJSON(opts provider.Options) string {
	h := map[string]any{
		"max_tokens":        opts.MaxTokens,
		"timeout_seconds":   int(opts.Timeout / time.Second),
		"extended_thinking": opts.ExtendedThinking,
		"thinking_budget":   opts.ThinkingBudget,
	}
	if opts.Temperature != nil {
		h["temperature"] = *opts.Temperature
	}
	if opts.TopP != nil {
		h["top_p"] = *opts.TopP
	}
	if opts.FrequencyPenalty != nil {
		h["frequency_penalty"] = *opts.FrequencyPenalty
	}
	// API keys never leave their provider package — record only the
	// presence indicator so operators can confirm "yes, the key was
	// attached" without exfiltrating it.
	h["authorization"] = "Bearer [REDACTED]"
	b, err := json.Marshal(h)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// secretKeyPattern matches Anthropic (sk-ant-*) and OpenAI-style (sk-*) API
// keys. Used to mask any accidental key leakage in error messages bubbled
// up from third-party SDKs that include the key in their error text.
var secretKeyPattern = regexp.MustCompile(`sk-(?:ant-)?[A-Za-z0-9_\-]{20,}`)

// bearerPattern catches "Authorization: Bearer ..." tokens that some
// providers echo verbatim into their error responses.
var bearerPattern = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]+`)

// redactErrorMessage strips known secret shapes (API keys, bearer tokens)
// from a free-form error message before persisting it. Defensive — most
// provider SDKs don't include the credential, but we'd rather not ship the
// one that does.
func redactErrorMessage(msg string) string {
	msg = secretKeyPattern.ReplaceAllString(msg, "sk-[REDACTED]")
	msg = bearerPattern.ReplaceAllString(msg, "Bearer [REDACTED]")
	return msg
}
