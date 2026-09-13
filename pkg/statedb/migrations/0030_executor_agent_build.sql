-- 0030_executor_agent_build: make an edge device's build version and hardware
-- inventory queryable, so the fleet stops being operationally opaque
-- (Task 20230).
--
-- The protocol already carried all of this. HelloPayload.AgentVersion was
-- declared with a comment about "diagnosing version-skew problems from the
-- control plane", and AgentCapabilities has reported OS, arch, CPU count,
-- memory, container runtimes and installed harnesses since remote executors
-- existed. Nothing on this side stored the version at all — there was no column
-- for it, so it was decoded at hello and discarded — and the capabilities went
-- into capabilities_json as an opaque blob nothing could filter on. An operator
-- could not answer "which devices are running last month's build" or "which
-- devices have the claude harness" from the hub at all.
--
-- Why discrete columns when capabilities_json already holds the same values:
-- a JSON blob answers "show me this one device" and nothing else. These are the
-- fields the scheduler matches on and the fields an operator sorts a fleet by,
-- so they need to be selectable, indexable, and typed on the way out. The blob
-- stays as the full advertisement — including fields that come along later and
-- have no column yet — so nothing is lost by parsing a subset out of it.
--
-- Columns:
--
--   agent_version       the cloop build the device reported at its last
--                       connect, e.g. 'v0.0.1' or 'dev+g4f7b5bc'. Empty means a
--                       build from before agents reported one. The literal '1'
--                       means the old hardcoded placeholder, which is a
--                       different and more actionable fact than 'unknown' —
--                       see pkg/version.LegacyAgentVersion.
--
--   agent_os,           GOOS/GOARCH of the device. Duplicated out of the blob
--   agent_arch          because "which arm64 devices trail the hub" is a
--                       two-column question and a JSON scan is the wrong tool.
--
--   agent_cpus,         logical cores and total memory. INTEGER so ordering is
--   agent_memory_mb     numeric; 0 means the agent could not detect it, which
--                       is deliberately not the same as "a device with no
--                       memory" and must never be treated as too small.
--
--   agent_harnesses,    JSON arrays of the agent CLIs ('claude', 'codex') and
--   agent_runtimes      container runtimes ('docker', 'podman') found on the
--                       device's PATH. Arrays rather than a delimited string so
--                       a harness whose name contains the delimiter cannot
--                       corrupt the list, and '[]' rather than NULL so readers
--                       need no NULL handling.
--
--   agent_workdir_root  the directory the agent confines every workload
--                       beneath: the sandbox boundary, which an operator
--                       auditing isolation needs to see without opening a blob.
--
-- Refreshed on every connect, not just at enrollment. Storing them once would
-- reproduce in the database exactly the staleness the hardcoded agent version
-- produced on the wire: an upgraded device would keep being reported as the
-- build it ran the day it joined.
--
-- NOT NULL DEFAULT means every row that predates this migration reads back as
-- an empty string or zero, so no backfill pass runs and the loaders need no
-- NULL handling. The next connect from each device fills its own row in.

ALTER TABLE executors ADD COLUMN agent_version      TEXT    NOT NULL DEFAULT '';
ALTER TABLE executors ADD COLUMN agent_os           TEXT    NOT NULL DEFAULT '';
ALTER TABLE executors ADD COLUMN agent_arch         TEXT    NOT NULL DEFAULT '';
ALTER TABLE executors ADD COLUMN agent_cpus         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE executors ADD COLUMN agent_memory_mb    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE executors ADD COLUMN agent_harnesses    TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE executors ADD COLUMN agent_runtimes     TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE executors ADD COLUMN agent_workdir_root TEXT    NOT NULL DEFAULT '';

-- Version skew is a fleet-wide question ("what is everything running"), so the
-- index is on the version alone rather than on (kind, version): the answer is
-- wanted across every executor, and a leading-column index already serves the
-- kind-filtered form well enough at fleet scale.
CREATE INDEX IF NOT EXISTS idx_executors_agent_version ON executors(agent_version);
