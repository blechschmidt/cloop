-- network_denials — what a run's sandbox firewall refused (Task 20437).
--
-- A sandbox's IP firewall refuses a blocked connection and logs it, rate
-- limited, to an NFLOG group; the hub (for its own container executor) or the
-- device's agent reads the log, aggregates it per run and reports it, and the
-- hub records it here, in the project's database beside the run's history. One
-- row per run, task, deny path and destination:
--
--   id           monotonic; what the write-time bound trims by.
--   run_id       the execution the refusals happened in (artifact.NewRunID).
--   task_id      the task running when they were first recorded, or 0 when
--                the hub could not tell — a device's seeded run, or several
--                tasks at once. Such a row is matched to a task by time.
--   rule         the deny path's tag: default, deny:<prefix>, meta:<prefix>,
--                block:<prefix>, xlat:<prefix> — or 'unitemised' for the
--                run's refusals past what one run itemises (dst '' there).
--   dst, port    the destination, an address literal, and its port (0 for a
--   proto        protocol without ports); proto is tcp, udp, icmp, icmpv6,
--                sctp, udplite or other.
--   executor_id  the executor that ran the sandbox.
--   fingerprint  the rule set the sandbox was filtered by.
--   why          the hub's sentence for the refusal, from the levels the run
--                was composed of: "not in the project's allow list".
--   count        refusals recorded; the log is rate-limited per deny path,
--                so a flood is at least this many.
--   first_seen,  when, as fixed-width UTC text so they compare as strings.
--   last_seen
--
-- Bounded by its writer: at most 64 itemised rows per run plus its unitemised
-- row, and the oldest rows go past 20,000 or 30 days. Addresses, ports and
-- counts only — the payload of a refused packet is never read, let alone kept.
--
-- Additive in schema_compat.go's sense: a new table no shipped build reads.
CREATE TABLE IF NOT EXISTS network_denials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT    NOT NULL,
    task_id     INTEGER NOT NULL DEFAULT 0,
    rule        TEXT    NOT NULL,
    dst         TEXT    NOT NULL DEFAULT '',
    port        INTEGER NOT NULL DEFAULT 0,
    proto       TEXT    NOT NULL DEFAULT '',
    executor_id TEXT    NOT NULL DEFAULT '',
    fingerprint TEXT    NOT NULL DEFAULT '',
    why         TEXT    NOT NULL DEFAULT '',
    count       INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT    NOT NULL DEFAULT '',
    last_seen   TEXT    NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS network_denials_key
    ON network_denials(run_id, task_id, rule, dst, port, proto);
CREATE INDEX IF NOT EXISTS network_denials_last_seen ON network_denials(last_seen);
CREATE INDEX IF NOT EXISTS network_denials_task ON network_denials(task_id);
