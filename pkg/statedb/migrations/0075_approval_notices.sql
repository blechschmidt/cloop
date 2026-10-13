-- 0075_approval_notices: what the hub has told approvers, and how far each
-- webhook has got (Task 20427).
--
-- The cluster leader notices that a grant request was filed, is twelve hours
-- from lapsing, was decided, withdrawn or lapsed, and that an API token started
-- waiting for an administrator's approval — and posts each to the webhooks in
-- notifications.webhooks. Both tables live in the control plane's database
-- only.
--
-- approval_notices is the outbox: one row per thing worth telling, ever.
--
--   notice_key  what the row is about, e.g. "request.reminder:req_…": UNIQUE,
--               so however many members or passes notice the same moment,
--               it is recorded — and therefore sent — once.
--   event       request.filed, request.reminder, request.approved,
--               request.denied, request.withdrawn, request.lapsed or
--               token.waiting.
--   payload     the notice as JSON: identities, the secret's name and kind,
--               the subject, deadlines. Never credential material — a
--               request has none to give, and a token's row holds a hash.
--   created_at  when the notice was recorded; old rows are pruned.
--
-- AUTOINCREMENT, so an id is never reused after a prune: a cursor names a
-- position in this table, and a reused id would be a notice it skips.
--
-- approval_notify_cursors is one row per configured webhook: the newest notice
-- it has been handed (acked_id — delivered, or given up on and counted in
-- dropped), the failures on the notice after it, and when to try again.
-- Advanced by compare-and-swap on acked_id, so a leader that lost its lease
-- mid-send cannot move a cursor its successor already moved. A webhook first
-- seen starts at the newest notice: adding a channel does not replay history
-- into it.
--
-- Additive — two new tables — so an older hub opens a database carrying them
-- and simply does not notify.

CREATE TABLE IF NOT EXISTS approval_notices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    notice_key TEXT    NOT NULL UNIQUE,
    event      TEXT    NOT NULL,
    payload    TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_notify_cursors (
    sink              TEXT    NOT NULL PRIMARY KEY,
    acked_id          INTEGER NOT NULL DEFAULT 0,
    delivered         INTEGER NOT NULL DEFAULT 0,
    dropped           INTEGER NOT NULL DEFAULT 0,
    failures          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   TEXT    NOT NULL DEFAULT '',
    last_error        TEXT    NOT NULL DEFAULT '',
    last_error_at     TEXT    NOT NULL DEFAULT '',
    last_delivered_at TEXT    NOT NULL DEFAULT '',
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL
);
