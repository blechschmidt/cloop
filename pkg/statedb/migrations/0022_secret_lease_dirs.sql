-- 0022_secret_lease_dirs: a write-ahead record of every credential directory
-- this hub has put plaintext into, so a restart can find the ones it orphaned
-- (Task 20193).
--
-- The hole this closes. secretbroker.Materialize writes a lease's credential
-- files into /dev/shm/cloop-lease-*, and the only thing that ever removed them
-- was an unguarded `go wipeLeaseOnExit(...)` goroutine in the dispatching
-- process. Nothing outlived that process. The TTL janitor sweeps the in-memory
-- liveLeases registry, which is empty after a restart, so a hub killed between
-- Materialize and the wipe — a deploy, an OOM kill, a panic — left plaintext
-- GitHub PATs and kubeconfigs on disk with nothing left to collect them.
-- /dev/shm is a tmpfs and clears on reboot, but a hub *process* restart clears
-- nothing, and that is the case that actually happens.
--
-- Why a table and not a directory scan. "Wipe every /dev/shm/cloop-lease-* at
-- startup" is the obvious fix and it is wrong: two hubs can share a host — an
-- operator running a second instance, a dev hub beside a service — and a blind
-- sweep would destroy the live credentials of the other one mid-task. A row is
-- what makes ownership decidable. This hub wipes a directory when *its own*
-- control-plane database says it created it; a directory it has no row for
-- belongs to somebody else and is left alone.
--
-- Why the row is written before the directory exists. The row is the intent,
-- not the record of completion: NewLeaseDirPath names the directory without
-- creating it, the row goes in, and only then does MaterializeAt write
-- plaintext. A crash at any point after the insert leaves a row the sweep can
-- act on, and the sweep tolerates a row whose directory was never created —
-- the end state it wants is "no directory", which is already true. A crash
-- before the insert leaves no directory either. There is no window that
-- produces plaintext without a row.
--
-- Rows are deleted on the ordinary wipe, so a steady-state hub keeps this
-- table near-empty and a non-empty table at startup is exactly the orphan set.
--
-- Columns:
--   dir          absolute path of the lease directory; the primary key,
--                because the path is what the sweep has to act on and two
--                leases can never share one (MaterializeAt creates
--                exclusively)
--   lease_id     the lease whose material lives there, for the audit line
--   executor_id  executor the lease was issued to, '' when not yet bound
--   project_path project the work belongs to, '' when not project-scoped
--   created_at   RFC3339 instant the intent was recorded
--   expires_at   RFC3339 lease expiry, '' when unbounded. The sweep does not
--                need it to decide — at startup every row is an orphan — but
--                an operator reading a swept-lease audit event needs to know
--                whether the credential had already lapsed
--
-- No content, no environment, no file names: this table records *where* a
-- credential directory is, never what is in it. It is stored in the same
-- database as broker_secrets but carries none of their sensitivity, which is
-- why it needs no envelope encryption (see 0019).
--
-- Timestamps are RFC3339 TEXT with '' meaning "not set", matching every other
-- table in this database.

CREATE TABLE IF NOT EXISTS secret_lease_dirs (
    dir          TEXT PRIMARY KEY,
    lease_id     TEXT NOT NULL DEFAULT '',
    executor_id  TEXT NOT NULL DEFAULT '',
    project_path TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT '',
    expires_at   TEXT NOT NULL DEFAULT ''
);

-- Revocation and the TTL janitor both address a lease by id rather than by
-- path, so the delete-by-lease lookup gets an index. The startup sweep is a
-- full scan by design: every row is a candidate.
CREATE INDEX IF NOT EXISTS idx_secret_lease_dirs_lease ON secret_lease_dirs(lease_id);
