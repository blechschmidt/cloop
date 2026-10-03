package statedb

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// strandedMembersSQL is project_members exactly as the live :8888 database
// holds it, created there by stranded builds under versions 47, 49 and 50
// (`sqlite3 .cloop/state.db ".schema project_members"`, 2026-10-03).
const strandedMembersSQL = `
CREATE TABLE project_members (
    id           TEXT PRIMARY KEY,
    project_path TEXT NOT NULL DEFAULT '',
    identity_key TEXT NOT NULL DEFAULT '',
    role         TEXT NOT NULL DEFAULT 'viewer',
    reason       TEXT NOT NULL DEFAULT '',
    granted_at   TEXT NOT NULL DEFAULT '',
    granted_by   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_project_members_path ON project_members(project_path);
CREATE INDEX idx_project_members_identity ON project_members(identity_key);
`

// TestProjectMembersAdoptTheStrandedTable opens a database that already holds
// the stranded table — under the live hub's collided history, and under a
// clean one — and checks that 0056 applies over it without error and that this
// build reads and writes it. A plain CREATE TABLE in 0056 would fail here and
// keep :8888 from starting at the nightly deploy.
func TestProjectMembersAdoptTheStrandedTable(t *testing.T) {
	for name, collided := range map[string]bool{
		"live history (47/49/50 recorded from stranded files)": true,
		"table present, history clean":                         false,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			conn := openRaw(t, path)
			upTo := 55
			if collided {
				upTo = 48
			}
			if _, err := MigrateTo(conn, upTo); err != nil {
				t.Fatalf("MigrateTo(%d): %v", upTo, err)
			}
			if _, err := conn.Exec(strandedMembersSQL); err != nil {
				t.Fatalf("create the stranded table: %v", err)
			}
			if collided {
				// What the live database records: 47 from a stranded
				// 0047_project_members.sql, 49 and 50 from two more, all
				// before main's own 49 and 50 existed.
				if _, err := conn.Exec(`UPDATE schema_migrations SET name = '0047_project_members.sql' WHERE version = 47`); err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC().Format(time.RFC3339Nano)
				for v, file := range map[int]string{49: "0049_project_members.sql", 50: "0050_project_members.sql"} {
					if _, err := conn.Exec(`INSERT INTO schema_migrations(version, applied_at, name, applied_by, compat)
						VALUES (?, ?, ?, 'stranded', 'additive')`, v, now, file); err != nil {
						t.Fatal(err)
					}
				}
			}
			rep, err := Migrate(conn)
			if err != nil {
				t.Fatalf("Migrate over the stranded table: %v", err)
			}
			if !containsInt(rep.Applied, 56) {
				t.Fatalf("0056 was not applied: %+v", rep)
			}
			conn.Close()

			db, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer db.Close()
			stored, prev, err := db.PutProjectMember(ProjectMemberRow{
				ProjectPath: "/srv/payments", IdentityKey: "bob@corp.example", Role: "viewer", GrantedBy: "alice@corp.example",
			}, nil)
			if err != nil || prev != nil {
				t.Fatalf("write into the stranded table: %+v prev=%v err=%v", stored, prev, err)
			}
			rows, err := db.ListProjectMembers()
			if err != nil || len(rows) != 1 || rows[0].IdentityKey != "bob@corp.example" {
				t.Fatalf("read back %+v %v", rows, err)
			}
			var n int
			if err := db.conn.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name IN
				('project_members', 'idx_project_members_path', 'idx_project_members_identity')`).Scan(&n); err != nil || n != 3 {
				t.Fatalf("membership objects present: %d (%v), want 3", n, err)
			}
		})
	}
}

// TestProjectMembersMigrationIsAdditive: older binaries sharing the control
// plane must keep opening it.
func TestProjectMembersMigrationIsAdditive(t *testing.T) {
	m := embeddedMigration(t, 56)
	if got := classifyMigration(m.SQL); got != CompatAdditive {
		t.Fatalf("0056 classifies as %q, want additive", got)
	}
	// The shape is the stranded one, statement for statement: the same
	// columns, defaults and index names, so that on the live database every
	// statement is a no-op.
	for _, want := range []string{
		"id           TEXT PRIMARY KEY",
		"role         TEXT NOT NULL DEFAULT 'viewer'",
		"CREATE TABLE IF NOT EXISTS project_members",
		"CREATE INDEX IF NOT EXISTS idx_project_members_path ON project_members(project_path)",
		"CREATE INDEX IF NOT EXISTS idx_project_members_identity ON project_members(identity_key)",
	} {
		if !strings.Contains(m.SQL, want) {
			t.Errorf("0056 lacks %q", want)
		}
	}
}

// TestProjectMemberWritesCarryTheirAuditRow: a membership change and the row
// that records it commit together, or not at all.
func TestProjectMemberWritesCarryTheirAuditRow(t *testing.T) {
	db := newAuditDB(t).AsControlPlane()
	event := func(action auditaction.Action, id string) []*AuditEvent {
		return []*AuditEvent{{Actor: "alice@corp.example", EventType: string(action),
			EntityType: "project_member", EntityID: id, Payload: `{}`}}
	}

	t.Run("grant then change then revoke", func(t *testing.T) {
		var seen []string
		row, prev, err := db.PutProjectMember(ProjectMemberRow{ProjectPath: "/srv/a", IdentityKey: "bob@corp.example", Role: "viewer"},
			func(prev, next *ProjectMemberRow) ([]*AuditEvent, error) {
				if prev != nil || next == nil || next.Role != "viewer" {
					t.Errorf("grant audit saw prev=%v next=%v", prev, next)
				}
				seen = append(seen, "grant")
				return event(auditaction.ActionProjectMemberGrant, next.ID), nil
			})
		if err != nil || prev != nil || !strings.HasPrefix(row.ID, "pjm_") || len(row.ID) != 4+24 {
			t.Fatalf("grant: %+v prev=%v err=%v", row, prev, err)
		}
		_, prev, err = db.PutProjectMember(ProjectMemberRow{ProjectPath: "/srv/a", IdentityKey: "bob@corp.example", Role: "operator"},
			func(prev, next *ProjectMemberRow) ([]*AuditEvent, error) {
				if prev == nil || prev.Role != "viewer" || next.Role != "operator" {
					t.Errorf("change audit saw prev=%+v next=%+v", prev, next)
				}
				seen = append(seen, "change")
				return event(auditaction.ActionProjectMemberChange, next.ID), nil
			})
		if err != nil || prev == nil || prev.Role != "viewer" {
			t.Fatalf("change: prev=%+v err=%v", prev, err)
		}
		if rows, _ := db.ListProjectMembers(); len(rows) != 1 || rows[0].Role != "operator" {
			t.Fatalf("a role change left %+v, want one operator row", rows)
		}
		removed, err := db.DeleteProjectMember("/srv/a", "bob@corp.example",
			func(prev, next *ProjectMemberRow) ([]*AuditEvent, error) {
				seen = append(seen, "revoke")
				return event(auditaction.ActionProjectMemberRevoke, prev.ID), nil
			})
		if err != nil || removed == nil || removed.Role != "operator" {
			t.Fatalf("revoke: %+v %v", removed, err)
		}
		again, err := db.DeleteProjectMember("/srv/a", "bob@corp.example",
			func(prev, next *ProjectMemberRow) ([]*AuditEvent, error) {
				t.Error("audit called for a removal that removed nothing")
				return nil, nil
			})
		if err != nil || again != nil {
			t.Fatalf("a second revoke = %+v %v, want nothing", again, err)
		}
		if strings.Join(seen, ",") != "grant,change,revoke" {
			t.Errorf("audit builders ran %v", seen)
		}
		evs, _, err := db.ListAuditEvents(AuditFilter{EntityType: "project_member"})
		if err != nil || len(evs) != 3 {
			t.Fatalf("audit rows: %d (%v), want 3", len(evs), err)
		}
	})

	t.Run("a refused audit leaves the table untouched", func(t *testing.T) {
		refused := errors.New("journal refused")
		_, _, err := db.PutProjectMember(ProjectMemberRow{ProjectPath: "/srv/b", IdentityKey: "carol@corp.example", Role: "admin"},
			func(prev, next *ProjectMemberRow) ([]*AuditEvent, error) { return nil, refused })
		if !errors.Is(err, refused) {
			t.Fatalf("PutProjectMember = %v, want the audit builder's error", err)
		}
		if _, err := db.GetProjectMember("/srv/b", "carol@corp.example"); !errors.Is(err, ErrProjectMemberNotFound) {
			t.Fatalf("a grant whose audit row failed was stored anyway: %v", err)
		}
	})

	t.Run("removing a project removes its roster", func(t *testing.T) {
		for _, key := range []string{"dave@corp.example", "sub:Erin-123"} {
			if _, _, err := db.PutProjectMember(ProjectMemberRow{ProjectPath: "/srv/c", IdentityKey: key, Role: "viewer"}, nil); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := db.PutProjectMember(ProjectMemberRow{ProjectPath: "/srv/d", IdentityKey: "dave@corp.example", Role: "viewer"}, nil); err != nil {
			t.Fatal(err)
		}
		calls := 0
		removed, err := db.DeleteProjectMembersOf("/srv/c", func(prev, next *ProjectMemberRow) ([]*AuditEvent, error) {
			calls++
			return nil, nil
		})
		if err != nil || len(removed) != 2 || calls != 2 {
			t.Fatalf("DeleteProjectMembersOf = %d rows, %d audit calls, %v", len(removed), calls, err)
		}
		rows, _ := db.ListProjectMembers()
		if len(rows) != 1 || rows[0].ProjectPath != "/srv/d" {
			t.Fatalf("after removing /srv/c the table holds %+v", rows)
		}
	})

	t.Run("a row found by its pair, whatever its id", func(t *testing.T) {
		// A stranded build derived 48-bit ids. Its row is still the one a
		// change or a removal acts on.
		if _, err := db.conn.Exec(`INSERT INTO project_members (id, project_path, identity_key, role)
			VALUES ('pjm_0123456789ab', '/srv/e', 'frank@corp.example', 'viewer')`); err != nil {
			t.Fatal(err)
		}
		row, prev, err := db.PutProjectMember(ProjectMemberRow{ProjectPath: "/srv/e", IdentityKey: "frank@corp.example", Role: "operator"}, nil)
		if err != nil || prev == nil || prev.Role != "viewer" || row.ID != "pjm_0123456789ab" {
			t.Fatalf("a change to the stranded row: %+v prev=%+v err=%v", row, prev, err)
		}
		if rows, _ := db.ListProjectMembers(); countPair(rows, "/srv/e", "frank@corp.example") != 1 {
			t.Fatalf("the change added a second row for the pair: %+v", rows)
		}
		removed, err := db.DeleteProjectMember("/srv/e", "frank@corp.example", nil)
		if err != nil || removed == nil || removed.ID != "pjm_0123456789ab" {
			t.Fatalf("removing the stranded row: %+v %v", removed, err)
		}
	})

	t.Run("a new pair whose id is taken does not overwrite the holder", func(t *testing.T) {
		id := ProjectMemberID("/srv/g", "grace@corp.example")
		if _, err := db.conn.Exec(`INSERT INTO project_members (id, project_path, identity_key, role) VALUES (?, '/srv/other', 'mallory@corp.example', 'viewer')`, id); err != nil {
			t.Fatal(err)
		}
		if _, _, err := db.PutProjectMember(ProjectMemberRow{ProjectPath: "/srv/g", IdentityKey: "grace@corp.example", Role: "admin"}, nil); err == nil {
			t.Fatal("a write landed on a row that names another person")
		}
		row, err := db.GetProjectMember("/srv/other", "mallory@corp.example")
		if err != nil || row.Role != "viewer" {
			t.Fatalf("the colliding row changed: %+v %v", row, err)
		}
	})
}

func countPair(rows []ProjectMemberRow, path, key string) int {
	n := 0
	for _, r := range rows {
		if r.ProjectPath == path && r.IdentityKey == key {
			n++
		}
	}
	return n
}

// TestOffboardSeversEveryMembershipSpelling: one person recorded under an
// email and under their subject loses both in the offboarding commit.
func TestOffboardSeversEveryMembershipSpelling(t *testing.T) {
	db := newAuditDB(t)
	for _, r := range []ProjectMemberRow{
		{ProjectPath: "/srv/a", IdentityKey: "bob@corp.example", Role: "viewer"},
		{ProjectPath: "/srv/b", IdentityKey: "sub:bob-7", Role: "operator"},
		{ProjectPath: "/srv/a", IdentityKey: "carol@corp.example", Role: "viewer"},
	} {
		if _, _, err := db.PutProjectMember(r, nil); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := db.OffboardIdentity(OffboardWrite{
		IdentityKey: "bob@corp.example",
		MemberKeys:  []string{"bob@corp.example", "sub:bob-7", "bob@corp.example"},
	})
	if err != nil {
		t.Fatalf("OffboardIdentity: %v", err)
	}
	if len(applied.Members) != 2 || !applied.Severed() {
		t.Fatalf("severed %+v, want bob's two memberships", applied.Members)
	}
	rows, _ := db.ListProjectMembers()
	if len(rows) != 1 || rows[0].IdentityKey != "carol@corp.example" {
		t.Fatalf("after offboarding bob the table holds %+v", rows)
	}
}
