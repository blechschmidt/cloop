-- project_members — who besides a project's owner may reach it, and at what
-- role (Task 20366, re-landing the stranded project-members feature).
--
-- On a hub with single sign-on an owned project is visible to its owner and the
-- hub's admins only, so the one way two engineers could work on a project was to
-- leave it unowned — which shares it with every signed-in user. A row here
-- admits one more identity to one project. pkg/projectmember reads the table
-- through a TTL cache and pkg/ui unions what a row grants with whatever the
-- identity already holds: a membership only ever adds access.
--
--   id            "pjm_" + 24 hex of SHA-256(project_path \x00 identity_key):
--                 one row per (project, person), so changing someone's role
--                 replaces their row instead of adding a second one.
--   project_path  the project's absolute, cleaned path — what the hub executes
--                 in and what authz.Scope.ProjectPath carries. A feature is
--                 shared with its project and never has rows of its own.
--   identity_key  the grantee in oidcauth.Identity.OwnerKey's namespace: a
--                 lowercased email, or "sub:<subject>".
--   role          viewer | operator | maintainer | admin (authz.Role). Checked
--                 by pkg/projectmember on every read, so a row this build cannot
--                 parse grants nothing instead of making the table unreadable.
--   reason        why the person was admitted; may be empty.
--   granted_at    RFC 3339 UTC. granted_by: who wrote the row.
--
-- # Why IF NOT EXISTS, in exactly this shape
--
-- Stranded builds created this table on the live hub database under versions
-- 47, 49 and 50, which collide with main's own migrations, and that database
-- still holds it, empty. This is the first version main applies there, and a
-- plain CREATE TABLE would fail on the existing table and keep the hub from
-- starting. The columns, defaults and index names below are the stranded ones
-- verbatim, so there every statement here is a no-op;
-- TestProjectMembersAdoptTheStrandedTable opens a database holding them.
--
-- Additive in schema_compat.go's sense, so an older binary sharing this control
-- plane keeps opening it. Such a binary does not read the table, so on it a
-- member sees nothing that was shared with them — memberships only add access,
-- and an older reader fails closed.
CREATE TABLE IF NOT EXISTS project_members (
    id           TEXT PRIMARY KEY,
    project_path TEXT NOT NULL DEFAULT '',
    identity_key TEXT NOT NULL DEFAULT '',
    role         TEXT NOT NULL DEFAULT 'viewer',
    reason       TEXT NOT NULL DEFAULT '',
    granted_at   TEXT NOT NULL DEFAULT '',
    granted_by   TEXT NOT NULL DEFAULT ''
);

-- "who is on this project": the Members card and every authorization check.
CREATE INDEX IF NOT EXISTS idx_project_members_path ON project_members(project_path);

-- "what does this person hold": offboarding (pkg/offboard) and the CLI.
CREATE INDEX IF NOT EXISTS idx_project_members_identity ON project_members(identity_key);
