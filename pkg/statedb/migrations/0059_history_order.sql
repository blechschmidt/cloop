-- 0059: the journal in time order (Task 20384).
--
-- The dashboard's Event History panel shows steps and events as one feed,
-- newest first, a page at a time. Neither timestamp column orders correctly as
-- text: Go writes RFC 3339 with trailing zeros trimmed (".5Z" sorts after
-- ".25Z"), and events carry the writing process's own UTC offset. julianday()
-- reads both forms, and indexing it lets a page be a seek and a fifty-row read
-- of each table instead of a sort of the whole journal.
--
-- IFNULL: a timestamp julianday() cannot read sorts as the oldest rather than
-- dropping out of every range a page reads.
--
-- Plain indexes: an older binary sharing this database cannot see them, and
-- SQLite keeps them current for its writes too.
CREATE INDEX IF NOT EXISTS steps_history_order ON steps(IFNULL(julianday(time), 0));
CREATE INDEX IF NOT EXISTS events_history_order ON events(IFNULL(julianday(timestamp), 0));
