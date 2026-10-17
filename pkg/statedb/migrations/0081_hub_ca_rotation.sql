-- 0081_hub_ca_rotation: replacing the hub's certificate authority online
-- (Task 20438).
--
-- Migration 0065 gave the hub a CA of its own, minted once and valid ten
-- years, and nothing could replace it: a suspected leak of its key — a backup
-- taken with the root key, a misused KMS identity, a departed operator — had
-- no remedy short of rebuilding the control plane. A rotation is staged, so
-- that no running sandbox is cut off by surprise:
--
--   stage            a second CA is minted and sealed exactly as the first,
--                    in hub_tls row 'ca:next'. From then on every dispatch is
--                    told to trust both; leaves still come from the first.
--   activate         'ca' moves to 'ca:previous' and 'ca:next' to 'ca' in one
--                    transaction; the cluster leader reissues every leaf
--                    under the new CA and every member serves it within a
--                    minute. Refused while a run dispatched before the stage
--                    is still running, unless forced.
--   retire-previous  'ca:previous' is deleted with secure_delete on, so the
--                    old CA's sealed key is gone from the file, and the old CA
--                    leaves every bundle.
--
-- hub_tls keeps the certificates and their sealed keys; no column is added to
-- it. The two tables here say what the rows alone cannot.
--
-- hub_ca_rotations — one row per rotation, its journal.
--
--   id            'rot_' and 24 hex digits.
--   state         'staged', 'active' (activated, the previous CA still
--                 trusted), 'retired' (finished) or 'abandoned' (the staged
--                 CA destroyed without being activated).
--   from_serial   the CA being replaced; to_serial the one replacing it.
--   names         JSON array: the names the new CA's X.509 name constraints
--                 permit, '[]' when it carries none.
--   emergency     1 for `cloop hub ca rotate --now`, which does every step at
--                 once and ends the proxy sessions of runs that trusted only
--                 the old CA.
--   staged_at, staged_by, activated_at, activated_by, ended_at, ended_by
--                 RFC 3339 UTC, and who.
--   forced        JSON array: the runs an activation forced past — runs it
--                 knew would stop verifying the monitors.
--   cut_runs      JSON array: the runs whose proxy sessions an emergency
--                 rotation ended.
--   detail        why it was abandoned, in an operator's words.
--
-- hub_ca_members — what each hub process serves and hands out, so a rotation
-- can tell when every member has adopted a step. Each member that runs a
-- credential monitor under tls: auto writes its row at least once a minute.
--
--   instance_id   the member (hub_members.instance_id).
--   active        the serial of the CA it signs leaves with.
--   trusts        JSON array: the CA serials it tells new dispatches to trust.
--   leaves        JSON object: per monitor, the serial and issuer of the leaf
--                 it serves.
--   adopted_at    when it adopted the trust it reports.
--   seen_at       its last write.
--
-- Additive in schema_compat.go's sense: two new tables, which no older binary
-- reads or writes.

CREATE TABLE IF NOT EXISTS hub_ca_rotations (
    id           TEXT PRIMARY KEY,
    state        TEXT NOT NULL DEFAULT '',
    from_serial  TEXT NOT NULL DEFAULT '',
    to_serial    TEXT NOT NULL DEFAULT '',
    names        TEXT NOT NULL DEFAULT '[]',
    emergency    INTEGER NOT NULL DEFAULT 0,
    staged_at    TEXT NOT NULL DEFAULT '',
    staged_by    TEXT NOT NULL DEFAULT '',
    activated_at TEXT NOT NULL DEFAULT '',
    activated_by TEXT NOT NULL DEFAULT '',
    ended_at     TEXT NOT NULL DEFAULT '',
    ended_by     TEXT NOT NULL DEFAULT '',
    forced       TEXT NOT NULL DEFAULT '[]',
    cut_runs     TEXT NOT NULL DEFAULT '[]',
    detail       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_hub_ca_rotations_staged ON hub_ca_rotations(staged_at);

CREATE TABLE IF NOT EXISTS hub_ca_members (
    instance_id TEXT PRIMARY KEY,
    active      TEXT NOT NULL DEFAULT '',
    trusts      TEXT NOT NULL DEFAULT '[]',
    leaves      TEXT NOT NULL DEFAULT '{}',
    adopted_at  TEXT NOT NULL DEFAULT '',
    seen_at     TEXT NOT NULL DEFAULT ''
);
