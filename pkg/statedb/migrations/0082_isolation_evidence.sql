-- 0082_isolation_evidence: what each executor's runtime was found to be
-- (Task 20439).
--
-- An executor's Virtualized and KernelIsolated capabilities are read off its
-- runtime's name, and placement honoured a project's demand for a VM or a
-- userspace kernel on that name alone: a daemon.json alias, or a RuntimeClass
-- whose handler is runc, claimed a VM while running on the host kernel. The
-- hub now runs `cloop isolation-probe` under each executor's runtime — at
-- reconcile, at a device's hello, after a runtime change, and daily — and
-- records here what the kernel serving the sandbox said about itself, judged
-- against the executing host's own kernel. Placement refuses a project
-- requiring isolation on an executor whose evidence contradicts its claim.
--
-- One row per executor and runtime, because the evidence is about the runtime:
-- a device whose sandbox runtime changes has nothing verified about the new
-- one until a probe runs under it.
--
--   executor_id   the executor, a virtual executor's own ID included.
--   runtime       the runtime the claim rests on: an OCI runtime, a
--                 RuntimeClass, a device's sandbox runtime; '' for the
--                 engine's or the cluster's default.
--   engine        the container engine the probe ran through, when it ran on
--                 one ('docker', 'podman'); '' for Kubernetes.
--   claim         what the runtime's name claims: 'vm', 'userspace-kernel'
--                 or 'host-kernel' (it claims nothing).
--   verdict       what the latest probe that ran found: 'vm',
--                 'userspace-kernel', 'host-kernel' or 'unknown'. 'unknown'
--                 until a probe completes.
--   detail        the evidence the verdict rests on, in a sentence.
--   evidence      JSON: what the probe read inside the sandbox.
--   reference     JSON: the executing host's own kernel, and who read it.
--   image         the image whose root filesystem the probe ran in — the
--                 executor's own, never a project's.
--   probed_at     when the verdict was reached ('' before any probe ran).
--   attempted_at  the latest attempt, which may have failed to run at all.
--   error         why the latest attempt could not run, '' when it ran. A
--                 failed attempt never replaces a verdict.
--   point         where the latest attempt came from: reconcile, hello,
--                 runtime_change, daily or manual.
--   probed_by     the hub member that made it (hub_members.instance_id).
--
-- Times are RFC 3339 UTC. Bounded by the fleet: rows are written by upsert and
-- an executor's go when it is revoked or deleted.
--
-- Additive in schema_compat.go's sense: a new table, which no older binary —
-- the stable UI sharing this database included — reads or writes.

CREATE TABLE IF NOT EXISTS isolation_evidence (
    executor_id  TEXT NOT NULL,
    runtime      TEXT NOT NULL DEFAULT '',
    engine       TEXT NOT NULL DEFAULT '',
    claim        TEXT NOT NULL DEFAULT '',
    verdict      TEXT NOT NULL DEFAULT 'unknown',
    detail       TEXT NOT NULL DEFAULT '',
    evidence     TEXT NOT NULL DEFAULT '{}',
    reference    TEXT NOT NULL DEFAULT '{}',
    image        TEXT NOT NULL DEFAULT '',
    probed_at    TEXT NOT NULL DEFAULT '',
    attempted_at TEXT NOT NULL DEFAULT '',
    error        TEXT NOT NULL DEFAULT '',
    point        TEXT NOT NULL DEFAULT '',
    probed_by    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (executor_id, runtime)
);
