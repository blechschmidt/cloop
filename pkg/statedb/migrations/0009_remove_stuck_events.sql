-- Task 20151: remove stuck-task events.
--
-- The stuck-task watchdog (Task 20088) was removed: with per-task timeouts
-- disabled by default (Task 20148), long-running provider calls are expected
-- and the "task stuck" detections were pure noise. Purge the historical rows
-- so they disappear from the Event History panel.
--
-- The stuck_tasks table itself is kept (not dropped) so older binaries that
-- still write to it continue to work against this database.
DELETE FROM events WHERE type = 'task_stuck';
DELETE FROM stuck_tasks;
