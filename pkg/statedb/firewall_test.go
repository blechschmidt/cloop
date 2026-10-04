package statedb

// Tests for the stored firewall levels (Task 20363).

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
)

// strandedFirewallSQL is what the stranded build of Task 20319 created on the
// live hub database, copied from `.schema` there (2026-10-03): both tables and
// both indexes, under a migration recorded as 48.
const strandedFirewallSQL = `
CREATE TABLE executor_firewall_rules (
    executor_id TEXT PRIMARY KEY,
    rules       TEXT NOT NULL DEFAULT '{}',
    fingerprint TEXT NOT NULL DEFAULT '',
    set_at      TEXT NOT NULL DEFAULT '',
    set_by      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_executor_firewall_rules_set_at
    ON executor_firewall_rules(set_at);
CREATE TABLE project_firewall_rules (
    project_path TEXT PRIMARY KEY,
    rules        TEXT NOT NULL DEFAULT '{}',
    fingerprint  TEXT NOT NULL DEFAULT '',
    set_at       TEXT NOT NULL DEFAULT '',
    set_by       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_project_firewall_rules_set_at
    ON project_firewall_rules(set_at);
`

func openFirewallDB(t *testing.T) *DB {
	t.Helper()
	return openFresh(t)
}

func TestExecutorAndProjectFirewallsRoundTrip(t *testing.T) {
	db := openFirewallDB(t)
	in := executor.FirewallRules{
		AllowPublicInternet: true,
		AllowCIDRs:          []string{"10.20.1.2/16", "10.20.0.0/16"},
		DenyCIDRs:           []string{"203.0.113.9"},
		AllowPorts:          []int{443, 80, 443},
		Resolvers:           []string{"1.1.1.1"},
	}
	if err := db.SetExecutorFirewall("sgx", in, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetProjectFirewall("/srv/p", executor.FirewallRules{AllowPorts: []int{443},
		AllowCIDRs: []string{"10.20.5.0/24"}}, "dev@example.com"); err != nil {
		t.Fatal(err)
	}

	rec, ok, err := db.ExecutorFirewall("sgx")
	if err != nil || !ok {
		t.Fatalf("ExecutorFirewall: %v %v", ok, err)
	}
	want, _ := in.Normalize()
	if !fwpolicy.Equal(rec.Rules, want) || rec.Fingerprint != fwpolicy.Fingerprint(want) {
		t.Errorf("stored %+v (%s), want the normalized %+v", rec.Rules, rec.Fingerprint, want)
	}
	if strings.Join(rec.Rules.AllowCIDRs, ",") != "10.20.0.0/16" || strings.Join(rec.Rules.DenyCIDRs, ",") != "203.0.113.9/32" {
		t.Errorf("rules are not stored in canonical form: %+v", rec.Rules)
	}
	if rec.SetBy != "admin@example.com" || time.Since(rec.SetAt) > time.Minute {
		t.Errorf("provenance = %q at %v", rec.SetBy, rec.SetAt)
	}
	if _, ok, _ := db.ExecutorFirewall("other"); ok {
		t.Error("an executor with no rules must read as absent")
	}
	prj, ok, err := db.ProjectFirewall("/srv/p")
	if err != nil || !ok || prj.SetBy != "dev@example.com" || len(prj.Rules.AllowCIDRs) != 1 {
		t.Fatalf("ProjectFirewall = %+v %v %v", prj, ok, err)
	}

	list, err := db.ListExecutorFirewalls()
	if err != nil || len(list) != 1 || list[0].Subject != "sgx" {
		t.Fatalf("ListExecutorFirewalls = %+v %v", list, err)
	}
	if err := db.ClearExecutorFirewall("sgx"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.ExecutorFirewall("sgx"); ok {
		t.Error("a cleared rule set must read as absent")
	}
	if err := db.ClearExecutorFirewall("sgx"); err != nil {
		t.Errorf("clearing an absent rule set must not fail: %v", err)
	}
}

// TestFirewallStoresReachNothing: an empty rule set is the strongest thing a
// level can say, and storing it must not be confused with clearing the level.
func TestFirewallStoresReachNothing(t *testing.T) {
	db := openFirewallDB(t)
	if err := db.SetExecutorFirewall("sgx", executor.FirewallRules{}, "admin"); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := db.ExecutorFirewall("sgx")
	if err != nil || !ok {
		t.Fatalf("an empty rule set must be stored as configured: %v %v", ok, err)
	}
	if rec.Rules.HasDestination() {
		t.Errorf("an empty rule set came back reaching something: %+v", rec.Rules)
	}
}

func TestSetFirewallRefusesInvalidRules(t *testing.T) {
	db := openFirewallDB(t)
	for _, bad := range []executor.FirewallRules{
		{AllowCIDRs: []string{"not-a-cidr"}},
		{AllowCIDRs: []string{"0.0.0.0/0"}},
		{AllowPorts: []int{70000}},
		{Resolvers: []string{"dns.example.com"}},
	} {
		if err := db.SetProjectFirewall("/srv/p", bad, "dev"); err == nil {
			t.Errorf("%+v was stored", bad)
		}
	}
	if err := db.SetExecutorFirewall("  ", executor.FirewallRules{}, "admin"); err == nil {
		t.Error("a rule set with no subject was stored")
	}
}

// TestFirewallReadFailsClosedOnUnreadableRow: a row this binary cannot read is
// an error, never "no rules" — absence means "this level adds no narrowing",
// so a decode fault read as absence would widen the firewall.
func TestFirewallReadFailsClosedOnUnreadableRow(t *testing.T) {
	db := openFirewallDB(t)
	for name, raw := range map[string]string{
		"not json":     `{"allow_cidrs":`,
		"bad cidr":     `{"allow_cidrs":["10.0.0.0/33"]}`,
		"unknown rule": `{"allow_public_internet":false,"allow_only_from":["10.0.0.0/8"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := db.conn.Exec(`INSERT OR REPLACE INTO project_firewall_rules(project_path, rules)
				VALUES ('/srv/bad', ?)`, raw); err != nil {
				t.Fatal(err)
			}
			if _, ok, err := db.ProjectFirewall("/srv/bad"); err == nil || ok {
				t.Errorf("an unreadable row read as (%v, %v)", ok, err)
			}
			if _, err := db.ListProjectFirewalls(); err == nil {
				t.Error("listing must fail on an unreadable row rather than drop it")
			}
		})
	}
}

// TestFirewallTablesAdoptTheStrandedShape opens a database that already has
// both tables — created by the stranded build under a collided version 48, as
// on the live hub — and checks that 0055 applies over them without error and
// that this build reads and writes them.
func TestFirewallTablesAdoptTheStrandedShape(t *testing.T) {
	for name, collided := range map[string]bool{
		"live history (48 and 47/49/50 collided)": true,
		"tables present, history clean":           false,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			conn := openRaw(t, path)
			upTo := 54
			if collided {
				upTo = 48
			}
			if _, err := MigrateTo(conn, upTo); err != nil {
				t.Fatalf("MigrateTo(%d): %v", upTo, err)
			}
			if _, err := conn.Exec(strandedFirewallSQL); err != nil {
				t.Fatalf("create the stranded tables: %v", err)
			}
			if collided {
				// What the live database records: 47 and 48 were applied from
				// stranded files, 49 and 50 too. Main's own 0047/0048 effects were
				// hand-applied there, which MigrateTo(48) stands in for.
				for v, file := range map[int]string{47: "0047_project_members.sql",
					48: "0048_egress_firewall_rules.sql"} {
					if _, err := conn.Exec(`UPDATE schema_migrations SET name = ? WHERE version = ?`, file, v); err != nil {
						t.Fatal(err)
					}
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
				t.Fatalf("Migrate over the stranded tables: %v", err)
			}
			if !containsInt(rep.Applied, 55) {
				t.Fatalf("0055 was not applied: %+v", rep)
			}
			conn.Close()

			db, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer db.Close()
			rules := executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}}
			if err := db.SetExecutorFirewall("sgx", rules, "admin"); err != nil {
				t.Fatalf("write into the stranded table: %v", err)
			}
			if err := db.SetProjectFirewall("/srv/p", executor.FirewallRules{}, "dev"); err != nil {
				t.Fatalf("write into the stranded table: %v", err)
			}
			if rec, ok, err := db.ExecutorFirewall("sgx"); err != nil || !ok || !fwpolicy.Equal(rec.Rules, rules) {
				t.Fatalf("read back %+v %v %v", rec, ok, err)
			}
			var n int
			if err := db.conn.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name IN
				('executor_firewall_rules', 'project_firewall_rules',
				 'idx_executor_firewall_rules_set_at', 'idx_project_firewall_rules_set_at')`).Scan(&n); err != nil || n != 4 {
				t.Fatalf("firewall objects present: %d (%v), want 4", n, err)
			}
		})
	}
}

// TestFirewallMigrationIsAdditive: older binaries sharing the control plane
// must keep opening it, which the guard allows only for additive migrations.
func TestFirewallMigrationIsAdditive(t *testing.T) {
	m := embeddedMigration(t, 55)
	if got := classifyMigration(m.SQL); got != CompatAdditive {
		t.Fatalf("0055 classifies as %q, want additive", got)
	}
}

func TestUpdateFirewallsRollsBackOnError(t *testing.T) {
	db := openFirewallDB(t)
	boom := errors.New("refused")
	err := db.UpdateFirewalls(func(tx *FirewallTx) error {
		if err := tx.SetExecutorFirewall("sgx", executor.FirewallRules{AllowPublicInternet: true}, "admin"); err != nil {
			return err
		}
		if err := tx.SetProjectFirewall("/srv/p", executor.FirewallRules{}, "admin"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("UpdateFirewalls = %v, want the callback's error", err)
	}
	if _, ok, _ := db.ExecutorFirewall("sgx"); ok {
		t.Error("a refused update left the device's rules behind")
	}
	if _, ok, _ := db.ProjectFirewall("/srv/p"); ok {
		t.Error("a refused update left the project's rules behind")
	}
}

func TestFirewallTxReachesVirtualExecutorsAndBindings(t *testing.T) {
	db := openFirewallDB(t)
	for _, id := range []string{"sgx", "elsewhere"} {
		if err := db.UpsertExecutor(ExecutorRow{ID: id, Name: id, Kind: executor.KindRemoteAgent}); err != nil {
			t.Fatal(err)
		}
	}
	spec := executor.VirtualSpec{
		Sandbox:  executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker"},
		Firewall: &executor.FirewallRules{AllowPublicInternet: true, Resolvers: []string{"1.1.1.1"}},
	}
	if err := db.CreateVirtualExecutor(VirtualExecutor{ID: "vx-a", ParentID: "sgx", Name: "a", Spec: spec}); err != nil {
		t.Fatal(err)
	}
	if err := db.BindProjectExecutor("/srv/p1", "vx-a", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := db.BindProjectExecutor("/srv/p2", "sgx", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := db.BindProjectExecutor("/srv/p3", "elsewhere", "admin"); err != nil {
		t.Fatal(err)
	}

	err := db.UpdateFirewalls(func(tx *FirewallTx) error {
		vs, err := tx.VirtualExecutorsOf("sgx")
		if err != nil || len(vs) != 1 || vs[0].ID != "vx-a" {
			t.Fatalf("VirtualExecutorsOf = %+v %v", vs, err)
		}
		paths, err := tx.ProjectsBoundTo("sgx", "vx-a")
		if err != nil || strings.Join(paths, ",") != "/srv/p1,/srv/p2" {
			t.Fatalf("ProjectsBoundTo = %v %v", paths, err)
		}
		narrowed := spec
		narrowed.Firewall = &executor.FirewallRules{AllowCIDRs: []string{"1.1.1.0/24"}, AllowPorts: []int{443}}
		return tx.SetVirtualExecutorSpec("vx-a", narrowed, "admin")
	})
	if err != nil {
		t.Fatal(err)
	}
	v, ok, err := db.VirtualExecutor("vx-a")
	if err != nil || !ok || v.Spec.Firewall == nil || v.Spec.Firewall.AllowPublicInternet ||
		v.Name != "a" || v.UpdatedBy != "admin" {
		t.Fatalf("virtual executor after the update: %+v %v %v", v, ok, err)
	}
}
