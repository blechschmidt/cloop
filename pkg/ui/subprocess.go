package ui

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Default per-handler caps for cloop subcommand invocations spawned from the
// Web UI. They exist to bound how long a misbehaving sub-binary (or its
// upstream — slow STT provider, unresponsive LLM, hung file lock) can pin a
// handler goroutine and the workload it started. Without these caps a single
// bad request would leak both the handler goroutine and the workload for the
// lifetime of the UI server.
const (
	// chatSubprocessTimeout caps `cloop do <message>` invoked by /api/chat.
	// `cloop do` parses intent via the configured AI provider; the provider
	// already self-times-out at 2m, so 3m gives a small safety margin for
	// process startup + writing chat history.
	chatSubprocessTimeout = 3 * time.Minute

	// voiceSubprocessTimeout caps `cloop listen --file <wav>` invoked by
	// /api/voice. STT (whisper local model on CPU) on a long recording can
	// take a while; 5m is generous but still bounded.
	voiceSubprocessTimeout = 5 * time.Minute

	// resetSubprocessTimeout caps `cloop reset` invoked by /api/reset.
	// Reset deletes a few state files — it should always be sub-second.
	// 30s is paranoia margin for slow disks.
	resetSubprocessTimeout = 30 * time.Second

	// suggestSubprocessTimeout caps the async `cloop suggest` job started by
	// /api/suggest/start. Without this cap a hung suggest run leaves
	// suggestRunning=true forever, blocking all future suggest requests with
	// "suggest already running" until the UI server is restarted.
	suggestSubprocessTimeout = 10 * time.Minute

	// initSubprocessTimeout caps `cloop init` invoked by /api/projects/new.
	// Init writes a handful of files and — unless --skip-clarify short-
	// circuits it — may make one provider call, so it is the same order as
	// the other provider-backed handlers.
	initSubprocessTimeout = 5 * time.Minute
)

// runCloopSubcommand executes the cloop binary at exe with args under workDir
// and returns combined stdout+stderr.
//
// Since Task 20156 the UI no longer forks processes itself: the workload is
// handed to whichever executor the project is bound to. The contract here is
// unchanged, but it means a project pinned to a container or a remote edge
// agent runs its subcommands there too, and a project bound to an
// unavailable executor fails closed rather than silently falling back to the
// control-plane host.
//
// It enforces both:
//
//   - The caller's ctx — used so e.g. a request handler can cancel the
//     workload when the client disconnects (`r.Context()`); and
//   - A hard timeout — so a wedged sub-binary cannot pin the calling
//     goroutine forever even if ctx never fires (e.g. async background jobs
//     whose only parent context is `context.Background()`).
//
// On context cancellation or timeout the workload is killed, which releases
// the calling goroutine promptly. The returned error wraps ctx.Err() /
// context.DeadlineExceeded so callers can distinguish "the command failed"
// from "we killed it" and surface a more useful message to the user.
func runCloopSubcommand(ctx context.Context, exe, workDir string, timeout time.Duration, args ...string) ([]byte, error) {
	return runCloopSubcommandEnv(ctx, exe, workDir, timeout, nil, args...)
}

// runCloopSubcommandEnv is runCloopSubcommand with extra "K=V" environment
// entries for the child, for handlers that must pass a credential without
// exposing it on the argv (Task 20188).
func runCloopSubcommandEnv(ctx context.Context, exe, workDir string, timeout time.Duration, extraEnv []string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, runErr := runWorkloadEnv(cctx, workDir, append([]string{exe}, args...), extraEnv,
		map[string]string{"handler": "subcommand"})

	// Distinguish ctx-driven kills from actual workload failures so the
	// caller can render a more accurate error string ("client cancelled" vs
	// "the underlying command failed with: ...").
	if cctx.Err() != nil {
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return out, fmt.Errorf("subprocess timeout after %s: %w", timeout, context.DeadlineExceeded)
		}
		return out, fmt.Errorf("subprocess cancelled: %w", cctx.Err())
	}
	return out, runErr
}
