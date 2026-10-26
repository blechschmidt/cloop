package ui

// model_calls.go: the dashboard features that put a question to the project's
// model — the Split preview, dictation's Revise, the blocker analysis and the
// plan assistant — and the rule they follow since Task 20442: the model call is
// a workload, made by a cloop subcommand on the executor the project is bound
// to, with the caller's Claude account, never by the hub itself.
//
// Before, each of them built the project's provider inside the hub and called
// it in-process. With claudecode, the default, that execs `claude --print
// --permission-mode bypassPermissions` in the project directory with the hub
// process's whole environment: on a hub with executors.allow_host_process:
// false, or for a project bound to a sandbox, anyone who could edit a task got
// an agent with every tool on the hub host, prompted with text they wrote; on a
// hub with sign-in it spent the hub's own Claude login rather than theirs; and
// a project's base_url could be sent an API key from the hub's environment.
// tests/security's call-graph gate missed all four because the call went
// through the provider.Provider interface, which it now resolves.
//
// Each handler validates what it can on the hub, settles the harness
// preflight (a sandbox with no Claude login is refused with the 409 the
// dashboard opens the credential dialog on), dispatches `cloop … --json`
// through runCloopSubcommandFor with the caller's Claude environment, and reads
// the framed result back (pkg/clijson) — re-checking it, since it came from
// whatever cloop the executor runs.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/blocker"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/executor"
)

const (
	// decomposeCallTimeout bounds each of the (up to two) model calls a Split
	// preview makes; decomposePreviewTimeout bounds the whole dispatch.
	decomposeCallTimeout = 4 * time.Minute

	// reviseDispatchTimeout bounds a Revise dispatch: the model keeps its
	// reviseTimeout, and the rest is for starting the workload where the
	// project runs — a container, a device.
	reviseDispatchTimeout = reviseTimeout + 30*time.Second

	// blockerCallTimeout is the blocker analysis's model call, as it always
	// was; blockerDispatchTimeout adds the workload's start.
	blockerCallTimeout     = 3 * time.Minute
	blockerDispatchTimeout = blockerCallTimeout + time.Minute

	// planChatCallTimeout is the plan assistant's model call, as it always
	// was; planChatDispatchTimeout adds the workload's start.
	planChatCallTimeout     = 2 * time.Minute
	planChatDispatchTimeout = planChatCallTimeout + time.Minute

	// maxPlanChatMessageBytes bounds the question. It travels to the executor
	// as one argument, which Linux caps at 128 KiB; a question past this is
	// not a question.
	maxPlanChatMessageBytes = 32 << 10

	// planChatHistoryBytes bounds the earlier turns sent with it, kept from
	// the latest back (chat.RecentPlanHistory).
	planChatHistoryBytes = 64 << 10

	// maxPlanChatLineBytes bounds a line of the assistant's output the relay
	// holds while it waits for the line's end.
	maxPlanChatLineBytes = 1 << 20
)

// maxProposedTitleRunes bounds a proposed sub-task's title; maxBlockerTextRunes
// a blocker analysis's root cause and each of its actions. Both arrive from the
// executor's cloop and may end up in the plan.
const (
	maxProposedTitleRunes = 500
	maxBlockerTextRunes   = 4000
	maxBlockerActions     = 5
)

// checkBlockerReport keeps what a blocker analysis from an executor may put in
// the plan — one of the three recommendations the analysis offers, a root cause
// and a few actions of bounded length — and reports whether anything is left
// to show. Analyze checks the same on the executor; this is the hub's copy of
// the check, for the cloop it cannot vouch for.
func checkBlockerReport(r *blocker.BlockerReport) bool {
	switch rec := strings.ToLower(strings.TrimSpace(r.Recommendation)); rec {
	case "retry", "skip", "reassign":
		r.Recommendation = rec
	default:
		r.Recommendation = "retry"
	}
	r.RootCause = truncateRunes(strings.TrimSpace(r.RootCause), maxBlockerTextRunes)
	actions := make([]string, 0, len(r.Actions))
	for _, a := range r.Actions {
		if a = truncateRunes(strings.TrimSpace(a), maxBlockerTextRunes); a != "" && len(actions) < maxBlockerActions {
			actions = append(actions, a)
		}
	}
	r.Actions = actions
	return r.RootCause != "" && len(r.Actions) > 0
}

// modelCallFailure is the framed payload a helper subcommand writes when its
// model call fails (cmd/hub_helpers.go).
type modelCallFailure struct {
	Error string `json:"error"`
}

// readModelCall decodes the framed result of a dispatched model call into v
// and reports whether it got one. When it did not, the response has been
// written:
//
//   - a dispatch that was refused, or could not start, with the status its
//     kind carries (jsonWorkloadErr) — a sandbox with no Claude login is a 409
//     harness_credential_missing, strict mode with nowhere isolating to go a
//     409 naming allow_host_process;
//   - a workload that ran and produced no result — the model failed, the call
//     timed out, the executor's cloop exited without one — as a 502 whose
//     message starts with prefix: the hub is fine, what it depends on is not.
func readModelCall(w http.ResponseWriter, out []byte, err error, prefix string, v any) bool {
	payload, perr := clijson.Extract(out)
	if perr == nil {
		var failed modelCallFailure
		if json.Unmarshal(payload, &failed) == nil && failed.Error != "" {
			jsonErr(w, prefix+failed.Error, http.StatusBadGateway)
			return false
		}
		if err == nil {
			if uerr := json.Unmarshal(payload, v); uerr != nil {
				jsonErr(w, prefix+"could not read the result: "+uerr.Error(), http.StatusBadGateway)
				return false
			}
			return true
		}
	}
	if err == nil {
		jsonErr(w, prefix+perr.Error(), http.StatusBadGateway)
		return false
	}
	var ended *workloadEndedError
	if errors.As(err, &ended) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		jsonErr(w, prefix+modelCallReason(out, err), http.StatusBadGateway)
		return false
	}
	jsonWorkloadErr(w, err)
	return false
}

// modelCallReason says why a workload that ran left no result: its error, and
// the start of what it printed when that says more. A cloop that does not know
// the subcommand or its flags is older than this hub — an edge device's own
// binary, say — and the reason says so.
func modelCallReason(out []byte, err error) string {
	msg := err.Error()
	if text := strings.TrimSpace(string(out)); text != "" {
		if len(text) > 300 {
			text = text[:300] + "…"
		}
		msg += " (" + strings.Join(strings.Fields(text), " ") + ")"
	}
	if bytes.Contains(out, []byte(`unknown command "`)) || bytes.Contains(out, []byte("unknown flag: --")) {
		msg += ". The cloop where this project runs is older than this hub: upgrade it " +
			"(the executor's Upgrade, or the edge channel) to use this from the dashboard"
	}
	return msg
}

// refuseModelCallDispatch answers, before anything is written, the refusals a
// dispatch of workDir would meet: a directory the hub may not dispatch, no
// executor to resolve (strict mode with nothing isolating), a feature on an
// executor that cannot run it, or a sandbox with no Claude login. It reports
// whether it refused. The dispatch settles the same checks again; this is for
// the plan assistant, whose stream must start before its workload does.
func (s *Server) refuseModelCallDispatch(w http.ResponseWriter, c *harnessClearance) bool {
	registerBuiltinExecutors()
	if err := checkDispatchConfinement(c.workDir); err != nil {
		jsonWorkloadErr(w, err)
		return true
	}
	ex, err := executor.Resolve(c.workDir)
	if err != nil {
		jsonWorkloadErr(w, fmt.Errorf("no executor available for %s: %w", c.workDir, err))
		return true
	}
	if err := checkFeatureExecutor(c.workDir, ex); err != nil {
		jsonWorkloadErr(w, err)
		return true
	}
	if _, err := c.settle(ex, c.workDir); err != nil {
		jsonWorkloadErr(w, err)
		return true
	}
	return false
}

// denyInlineModelCall refuses a model call the hub would make in its own
// process — the provider-call and task replays, which compare a provider's
// answers side by side and so stay inline — where it would run something the
// project's own runs may not. With claudecode an inline call is `claude` with
// every tool, in the project directory, on the hub's host: refused on a strict
// hub (denyHostSideEffect, whose 409 names allow_host_process) and for a
// project bound to an executor that keeps its runs off the hub's host, or
// whose executor cannot be resolved to say otherwise. It reports whether it
// refused.
func denyInlineModelCall(w http.ResponseWriter, workDir, what string) bool {
	if denyHostSideEffect(w, workDir, what) {
		return true
	}
	registerBuiltinExecutors()
	ex, err := executor.Resolve(workDir)
	if err != nil {
		jsonWorkloadErr(w, fmt.Errorf("no executor available for %s: %w", workDir, err))
		return true
	}
	if executor.IsolatesFromHost(ex) {
		writeSandboxDenied(w, "inline_call_isolated",
			fmt.Sprintf("%s calls the project's provider inside the hub, on its host, and %s runs on %s, "+
				"which keeps its runs off that host", what, workDir, ex.ID()),
			"Run the task again instead: a run goes to the project's executor.", nil)
		return true
	}
	return false
}

// inlineClaudeEnv pins an inline model call to the caller's Claude account:
// their configuration directory, with every ambient credential cleared, so
// neither the hub's login nor a token in its environment answers for them
// (Task 20442). Nil in single-user mode, where the host's login is the one
// meant, and where no identity can be resolved, as for a dispatched run.
func (s *Server) inlineClaudeEnv(r *http.Request) []string {
	scope, err := s.claudeScopeFor(r)
	if err != nil || !scope.PerUser() {
		return nil
	}
	return claudecodeauth.ScopeEnv(nil, scope.ConfigDir)
}
