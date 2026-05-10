-- 0005_provider_calls: real-time provider HTTP call inspector (Task 20123).
--
-- Captures one row per Provider.Complete invocation made by any cloop process
-- against the project's state.db. Powers the Web UI "Provider Calls" panel
-- (live timestamp/provider/model/tokens/latency table) and the per-call modal
-- showing prompt + response + headers, plus the replay-with-edits flow.
--
-- This is observability data, not authoritative state — it is safe to truncate
-- via cloop compact. Best-effort writes only: persistence failures here MUST
-- NOT abort the originating provider call.
--
-- Redaction rules (enforced in pkg/provideraudit before insert, never at read
-- time so on-disk rows are guaranteed safe even if a future caller forgets):
--   * Anthropic / OpenAI API keys (anything matching sk-ant-*, sk-*) are
--     replaced with [REDACTED] in headers.
--   * Bearer tokens in Authorization headers are replaced with [REDACTED].
--   * The prompt and response themselves are stored verbatim — they originated
--     from the user/orchestrator and never carry the cloop binary's own
--     credentials.
--
-- Columns:
--   id              monotonic insertion id (also the replay handle)
--   timestamp       RFC3339Nano UTC; insertion time (= request start time)
--   provider        registered provider name ("anthropic", "openai", ...)
--   model           the model string passed to Complete
--   task_id         pm.Task.ID when the call originated inside an orchestrated
--                   task; 0 for ad-hoc CLI commands (cloop ask, cloop suggest)
--   task_title      cached title for display (may go stale; the UI reads it
--                   for free instead of joining plan_tasks)
--   request_id      the X-Request-ID propagated through the call context
--   prompt          full user prompt as sent to the provider
--   system_prompt   provider system message; empty when not used
--   response        Result.Output verbatim; empty when err != nil
--   error_message   provider error string; empty on success
--   status          "ok" | "error" | "timeout" | "context_canceled"
--   headers         JSON map of synthetic request metadata (provider name,
--                   max_tokens, extended_thinking, etc.) with secrets
--                   already redacted
--   input_tokens    Result.InputTokens (estimated when provider didn't report)
--   output_tokens   Result.OutputTokens
--   thinking_tokens Result.ThinkingTokens (extended-thinking only)
--   latency_ms      wall-clock duration of the Complete call, in milliseconds

CREATE TABLE IF NOT EXISTS provider_calls (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL DEFAULT '',
    provider         TEXT    NOT NULL DEFAULT '',
    model            TEXT    NOT NULL DEFAULT '',
    task_id          INTEGER NOT NULL DEFAULT 0,
    task_title       TEXT    NOT NULL DEFAULT '',
    request_id       TEXT    NOT NULL DEFAULT '',
    prompt           TEXT    NOT NULL DEFAULT '',
    system_prompt    TEXT    NOT NULL DEFAULT '',
    response         TEXT    NOT NULL DEFAULT '',
    error_message    TEXT    NOT NULL DEFAULT '',
    status           TEXT    NOT NULL DEFAULT '',
    headers          TEXT    NOT NULL DEFAULT '',
    input_tokens     INTEGER NOT NULL DEFAULT 0,
    output_tokens    INTEGER NOT NULL DEFAULT 0,
    thinking_tokens  INTEGER NOT NULL DEFAULT 0,
    latency_ms       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS provider_calls_timestamp ON provider_calls(timestamp);
CREATE INDEX IF NOT EXISTS provider_calls_task_id ON provider_calls(task_id);
CREATE INDEX IF NOT EXISTS provider_calls_provider ON provider_calls(provider);
