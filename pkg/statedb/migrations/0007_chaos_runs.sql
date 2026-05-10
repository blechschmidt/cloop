-- 0007_chaos_runs: persistent log of chaos fault injections (Task 20121).
--
-- One row per `cloop chaos inject` invocation (or per case in `cloop chaos
-- suite`). Records the requested fault parameters at the head of the run and
-- gets stamped with the observed outcome when the fault window closes.
--
-- Used by `cloop chaos report` to summarise how the system handled each
-- fault. The table mirrors the live structure created in pkg/chaos/store.go
-- so `OpenStore` against an arbitrary sqlite file (tests, ad-hoc scripts)
-- still works without depending on the migration framework.
--
-- Outcome values: 'recovered', 'degraded', 'crashed', 'unknown'. Readers must
-- tolerate unknown values so downgrading the binary while a run is in flight
-- does not crash.

CREATE TABLE IF NOT EXISTS chaos_runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    fault_type          TEXT    NOT NULL DEFAULT '',
    probability         REAL    NOT NULL DEFAULT 1.0,
    started_at          TEXT    NOT NULL DEFAULT '',
    stopped_at          TEXT    NOT NULL DEFAULT '',
    duration_ms         INTEGER NOT NULL DEFAULT 0,
    outcome             TEXT    NOT NULL DEFAULT 'unknown',
    outcome_detail      TEXT    NOT NULL DEFAULT '',
    observed_errors     INTEGER NOT NULL DEFAULT 0,
    observed_retries    INTEGER NOT NULL DEFAULT 0,
    observed_recoveries INTEGER NOT NULL DEFAULT 0,
    note                TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS chaos_runs_started_at ON chaos_runs(started_at);
CREATE INDEX IF NOT EXISTS chaos_runs_fault_type ON chaos_runs(fault_type);
