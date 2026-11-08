-- 0098_teams: named groups of people a project can be shared with (Task 20478).
--
-- Projects on a hub with single sign-on are private to whoever created them.
-- Sharing one with a person adds a project_members row naming that person; a
-- team is the other kind of grantee, so that "the payments team may operate
-- this project" is one row rather than one per engineer, and stays true as the
-- team changes. A project shared with a team holds a project_members row whose
-- identity_key is "team:<slug>".
--
-- teams         one row per team. The hub's administrators keep this table
--               (user.manage): whoever decides who is on a team decides who
--               reaches every project shared with it.
--   slug        the team's stable name, lowercase letters, digits, "-", "_"
--               and "."; what project_members rows name. "everyone" is
--               reserved for the built-in team of every signed-in identity and
--               is never stored.
--   name, description   free text for people.
--   idp_group   optional: everyone whose ID token carries this group claim
--               value is a member, matched like a `group` role mapping.
--   scim_group  optional: everyone the identity provider provisioned into
--               this group over SCIM is a member, matched like a `scim_group`
--               role mapping.
--   created_at/by, updated_at/by   RFC 3339 UTC and the acting identity.
--
-- team_members  the people added to a team by name, in
--               oidcauth.Identity.OwnerKey's namespace (a lowercased email, or
--               "sub:<subject>"). A team's members are these rows plus whoever
--               its idp_group and scim_group admit.
--
-- New tables only, so additive in schema_compat.go's sense: an older binary
-- sharing this control plane never reads them, and a project shared with a
-- team grants nothing there — an older reader fails closed.
CREATE TABLE IF NOT EXISTS teams (
    slug        TEXT PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    idp_group   TEXT NOT NULL DEFAULT '',
    scim_group  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT '',
    updated_by  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS team_members (
    team_slug    TEXT NOT NULL,
    identity_key TEXT NOT NULL,
    added_at     TEXT NOT NULL DEFAULT '',
    added_by     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (team_slug, identity_key)
);

-- "which teams is this person on": offboarding and the CLI.
CREATE INDEX IF NOT EXISTS idx_team_members_identity ON team_members(identity_key);
