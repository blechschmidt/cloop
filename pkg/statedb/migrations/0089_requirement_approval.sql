-- 0089_requirement_approval: who approved a requirement, and when (Task 20462).
--
-- The model can draft requirements now — from the project's goal or a pasted
-- specification — and a draft counts for nothing until a person approves it:
-- no check runs it, the requirements gate passes it by, and a task's agent is
-- not held to it. Approving one is the act that lets its tests run, so the
-- requirement records who did it.
--
--   approved_by  the person, token or service account that made it approved:
--                whoever added it approved, or moved it there from a draft or
--                from deprecated — in the dashboard, with `cloop requirements
--                approve`, by editing it, or by importing a spec file that
--                approves it. '' for a requirement that is not approved, and
--                for one approved before this column existed.
--   approved_at  when, as fixed-width UTC text; '' with approved_by.
--
-- Each approval is also an audit row, requirement.approve. Additive in
-- schema_compat.go's sense: defaulted columns appended to a table no shipped
-- build rewrites (UpdateRequirement and the import set the columns they know),
-- so an older build reading or editing a requirement leaves these as they are.

ALTER TABLE requirements ADD COLUMN IF NOT EXISTS approved_by TEXT NOT NULL DEFAULT '';
ALTER TABLE requirements ADD COLUMN IF NOT EXISTS approved_at TEXT NOT NULL DEFAULT '';
