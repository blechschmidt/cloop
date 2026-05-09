package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Default per-handler caps for cloop subcommand invocations spawned from the
// Web UI. They exist to bound how long a misbehaving sub-binary (or its
// upstream — slow STT provider, unresponsive LLM, hung file lock) can pin a
// handler goroutine and the OS process it forked. Without these caps a single
// bad request would leak both the handler goroutine and the child process for
// the lifetime of the UI server.
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
)

// runCloopSubcommand executes the cloop binary at exe with args under workDir
// and returns combined stdout+stderr. It enforces both:
//
//   - The caller's ctx — used so e.g. a request handler can cancel the child
//     when the client disconnects (`r.Context()`); and
//   - A hard timeout — so a wedged sub-binary cannot pin the calling goroutine
//     forever even if ctx never fires (e.g. async background jobs whose only
//     parent context is `context.Background()`).
//
// On context cancellation or timeout the child receives SIGKILL via
// exec.CommandContext, which cooperates with cmd.Wait() to release the
// goroutine promptly. The returned error wraps ctx.Err() / context.DeadlineExceeded
// so callers can distinguish "child failed" from "we killed it" and surface a
// more useful message to the user.
func runCloopSubcommand(ctx context.Context, exe, workDir string, timeout time.Duration, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, exe, args...)
	cmd.Dir = workDir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	runErr := cmd.Run()

	// Distinguish ctx-driven kills from actual subprocess failures so the
	// caller can render a more accurate error string ("client cancelled" vs
	// "the underlying command failed with: ...").
	if cctx.Err() != nil {
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return buf.Bytes(), fmt.Errorf("subprocess timeout after %s: %w", timeout, context.DeadlineExceeded)
		}
		return buf.Bytes(), fmt.Errorf("subprocess cancelled: %w", cctx.Err())
	}
	return buf.Bytes(), runErr
}
