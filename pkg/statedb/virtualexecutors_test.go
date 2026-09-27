package statedb

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// enrollDevice records an enrolled remote executor for a virtual one to hang
// off.
func enrollDevice(t *testing.T, db *DB, id string) {
	t.Helper()
	if err := db.UpsertExecutor(ExecutorRow{ID: id, Name: id, Kind: executor.KindRemoteAgent}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
}

func hsmSpec() executor.VirtualSpec {
	return executor.VirtualSpec{
		Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker"},
		Firewall: &executor.FirewallRules{
			AllowPublicInternet: true,
			DenyCIDRs:           []string{"203.0.113.9"},
			Resolvers:           []string{"1.1.1.1"},
		},
		Devices: []executor.DeviceSelector{{
			Name: "yubihsm",
			USB:  &executor.USBMatch{VendorID: "0x1050", ProductID: "0030"},
		}},
	}
}

func TestVirtualExecutorLifecycle(t *testing.T) {
	db := openTestDB(t)
	enrollDevice(t, db, "sgx")

	err := db.CreateVirtualExecutor(VirtualExecutor{
		ID: "vx-hsm", ParentID: "sgx", Name: "HSM sandbox", Spec: hsmSpec(), CreatedBy: "admin@example.com",
	})
	if err != nil {
		t.Fatalf("CreateVirtualExecutor: %v", err)
	}

	got, ok, err := db.VirtualExecutor("vx-hsm")
	if err != nil || !ok {
		t.Fatalf("VirtualExecutor: %v %v", ok, err)
	}
	// Stored normalized: what the panel shows is what the device is sent.
	if got.Spec.Devices[0].USB.VendorID != "1050" || got.Spec.Firewall.DenyCIDRs[0] != "203.0.113.9/32" {
		t.Errorf("spec not normalized on write: %+v", got.Spec)
	}
	if got.CreatedBy != "admin@example.com" || got.CreatedAt.IsZero() {
		t.Errorf("provenance lost: %+v", got)
	}

	// It is bindable: an executors row exists, of the virtual kind.
	row, err := db.GetExecutor("vx-hsm")
	if err != nil || row.Kind != executor.KindVirtual || row.Labels["parent"] != "sgx" {
		t.Fatalf("executors row = %+v, %v", row, err)
	}
	if err := db.BindProjectExecutor("/srv/proj", "vx-hsm", "admin"); err != nil {
		t.Fatalf("BindProjectExecutor: %v", err)
	}

	// Update replaces name and spec, keeps the parent.
	spec := hsmSpec()
	spec.Firewall = nil
	if err := db.UpdateVirtualExecutor("vx-hsm", "HSM (no network)", spec, "admin2"); err != nil {
		t.Fatalf("UpdateVirtualExecutor: %v", err)
	}
	got, _, _ = db.VirtualExecutor("vx-hsm")
	if got.Name != "HSM (no network)" || got.Spec.Firewall != nil || got.ParentID != "sgx" || got.UpdatedBy != "admin2" {
		t.Errorf("after update: %+v", got)
	}
	if row, _ := db.GetExecutor("vx-hsm"); row.Name != "HSM (no network)" {
		t.Errorf("the executors row was not renamed: %q", row.Name)
	}

	// Delete removes everything keyed by the ID.
	if err := db.SetExecutorResourceLimit("vx-hsm", executor.ResourceCeiling{MemoryMB: 512}, "admin"); err != nil {
		t.Fatalf("SetExecutorResourceLimit: %v", err)
	}
	if err := db.AddExecutorAudience("vx-hsm", "group", "hsm-operators", "admin"); err != nil {
		t.Fatalf("AddExecutorAudience: %v", err)
	}
	if err := db.DeleteVirtualExecutor("vx-hsm"); err != nil {
		t.Fatalf("DeleteVirtualExecutor: %v", err)
	}
	if _, ok, _ := db.VirtualExecutor("vx-hsm"); ok {
		t.Error("the row survived deletion")
	}
	if _, err := db.GetExecutor("vx-hsm"); err == nil {
		t.Error("the executors row survived deletion")
	}
	if id, _, _ := db.ProjectExecutor("/srv/proj"); id != "" {
		t.Errorf("a binding to the deleted executor survived: %q", id)
	}
	if members, _ := db.ExecutorAudience("vx-hsm"); len(members) != 0 {
		t.Errorf("the access list survived deletion: %+v", members)
	}
	if c, _, _ := db.ExecutorResourceCeiling("vx-hsm"); !c.IsZero() {
		t.Errorf("the ceiling survived deletion: %+v", c)
	}
	if err := db.DeleteVirtualExecutor("vx-hsm"); !errors.Is(err, ErrVirtualExecutorNotFound) {
		t.Errorf("second delete = %v", err)
	}
}

func TestVirtualExecutorRefusals(t *testing.T) {
	db := openTestDB(t)
	enrollDevice(t, db, "sgx")
	if err := db.UpsertExecutor(ExecutorRow{ID: "container-default", Kind: executor.KindContainer}); err != nil {
		t.Fatal(err)
	}

	for name, v := range map[string]VirtualExecutor{
		"id of an existing executor": {ID: "sgx", ParentID: "sgx", Spec: hsmSpec()},
		"parent not a device":        {ID: "vx-a", ParentID: "container-default", Spec: hsmSpec()},
		"unknown parent":             {ID: "vx-b", ParentID: "nope", Spec: hsmSpec()},
		"host mode":                  {ID: "vx-c", ParentID: "sgx", Spec: executor.VirtualSpec{}},
		"multi-line name":            {ID: "vx-d", ParentID: "sgx", Name: "a\nb", Spec: hsmSpec()},
	} {
		t.Run(name, func(t *testing.T) {
			if err := db.CreateVirtualExecutor(v); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	if err := db.CreateVirtualExecutor(VirtualExecutor{ID: "vx-ok", ParentID: "sgx", Spec: hsmSpec()}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.CreateVirtualExecutor(VirtualExecutor{ID: "vx-ok", ParentID: "sgx", Spec: hsmSpec()}); !errors.Is(err, ErrVirtualExecutorExists) {
		t.Errorf("a duplicate id = %v", err)
	}
	if err := db.UpdateVirtualExecutor("vx-missing", "x", hsmSpec(), "a"); !errors.Is(err, ErrVirtualExecutorNotFound) {
		t.Errorf("update of a missing executor = %v", err)
	}
	list, err := db.ListVirtualExecutors()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListVirtualExecutors = %+v, %v", list, err)
	}
}

// TestVirtualExecutorsSurviveACollidedSchemaHistory reproduces the database the
// :8888 hub actually has: versions 49 and 50 recorded from a stranded build's
// own migrations, so this build's 0049 and 0050 are skipped there. 0051 has to
// create the table anyway, or the feature would be missing exactly where it
// was deployed.
//
// Both shapes seen in the field are covered: the :8888 control plane recorded
// 49 and 50 from stranded files, and a database on the sgx executor host
// recorded 49 only — where an index-only 0050 aborted the whole run.
func TestVirtualExecutorsSurviveACollidedSchemaHistory(t *testing.T) {
	for name, collided := range map[string]map[int]string{
		":8888 (49 and 50)": {49: "0049_project_members.sql", 50: "0050_project_members.sql"},
		"sgx (49 only)":     {49: "0049_project_members.sql"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			conn := openRaw(t, path)
			if _, err := MigrateTo(conn, 48); err != nil {
				t.Fatalf("MigrateTo(48): %v", err)
			}
			now := time.Now().UTC().Format(time.RFC3339Nano)
			for v, file := range collided {
				if _, err := conn.Exec(`INSERT INTO schema_migrations(version, applied_at, name, applied_by, compat)
					VALUES (?, ?, ?, 'stranded', 'additive')`, v, now, file); err != nil {
					t.Fatalf("record collided version %d: %v", v, err)
				}
			}
			if _, err := Migrate(conn); err != nil {
				t.Fatalf("Migrate: %v", err)
			}
			var n int
			if err := conn.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name IN
				('virtual_executors', 'idx_virtual_executors_parent')`).Scan(&n); err != nil || n != 2 {
				t.Fatalf("virtual_executors objects present: %d (%v), want 2", n, err)
			}
		})
	}
}
