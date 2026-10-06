package config

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestLoadRepairsRecordWhatTheLoaderChanged: Load repairs what it cannot
// honour and says so once on stderr. The record is what lets a reader of the
// result — `cloop hub doctor` — tell a section the loader switched off from
// one nobody enabled (Task 20387).
func TestLoadRepairsRecordWhatTheLoaderChanged(t *testing.T) {
	base := `provider: claudecode
max_parallel: 999
executors:
  git_proxy:
    enabled: true
    advertise_url: https://hub.example.com:8443
`
	dir := writeConfigs(t, base, "", 0)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Executors.GitProxy.Enabled {
		t.Fatal("premise: a git proxy without TLS material is switched off at load")
	}

	repairs := cfg.LoadRepairs()
	byField := map[string]LoadRepair{}
	for _, r := range repairs {
		byField[r.Field] = r
	}
	if r, ok := byField["max_parallel"]; !ok || r.SwitchedOff != "" || r.File != ConfigPath(dir) {
		t.Errorf("max_parallel repair = %+v (present=%v), want a field repair naming config.yaml", r, ok)
	}
	off, ok := byField["executors.git_proxy.enabled"]
	if !ok || off.SwitchedOff != "executors.git_proxy" {
		t.Fatalf("no switch-off recorded for executors.git_proxy: %+v", repairs)
	}
	if !strings.Contains(off.Detail, "cert_file") {
		t.Errorf("the switch-off should say why: %q", off.Detail)
	}

	// Recorded per Config, not per process: the stderr line is printed once,
	// but every load's result carries its own repairs.
	again, err := Load(dir)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if len(again.LoadRepairs()) != len(repairs) {
		t.Errorf("second load recorded %d repairs, first %d", len(again.LoadRepairs()), len(repairs))
	}
}

// TestLoadRepairsNameTheMirrorTheyCameFrom: with config.yaml gone, Load reads
// the copy mirrored in state.db, and a repair attributed to the missing file
// would send an operator to correct a file that is not there.
func TestLoadRepairsNameTheMirrorTheyCameFrom(t *testing.T) {
	dir := tempDir(t)
	initStateDB(t, dir)
	db, err := statedb.Open(stateDBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConfigBlob("provider: claudecode\nmax_parallel: 999\n"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Provider != "claudecode" {
		t.Fatalf("premise: Load falls back to the mirror (provider %q)", cfg.Provider)
	}
	var got []LoadRepair
	for _, r := range cfg.LoadRepairs() {
		if r.Field == "max_parallel" {
			got = append(got, r)
		}
	}
	if len(got) != 1 {
		t.Fatalf("max_parallel repairs = %+v, want one", cfg.LoadRepairs())
	}
	if !strings.HasPrefix(got[0].File, ConfigPath(dir)) || !strings.Contains(got[0].File, "mirrored in state.db") {
		t.Errorf("repair source = %q, want config.yaml named missing and the mirror named as the source", got[0].File)
	}
}

// TestLoadRepairsDropASwitchOffAnOverlayUndid: an overlay that re-enables a
// section with values that load leaves it running, so the record must not
// keep saying it is off.
func TestLoadRepairsDropASwitchOffAnOverlayUndid(t *testing.T) {
	base := `provider: claudecode
executors:
  kube_guard:
    enabled: true
`
	overlay := `executors:
  kube_guard:
    enabled: true
    cert_file: /etc/cloop/kg.crt
    key_file: /etc/cloop/kg.key
`
	dir := writeConfigs(t, base, overlay, 8081)
	cfg, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if !cfg.Executors.KubeGuard.Enabled {
		t.Fatal("premise: the overlay's complete section is in force")
	}
	for _, r := range cfg.LoadRepairs() {
		if r.SwitchedOff != "" {
			t.Errorf("a switch-off the overlay undid is still reported: %+v", r)
		}
	}

	// config.yaml read alone still has it off, and says so.
	alone, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	found := false
	for _, r := range alone.LoadRepairs() {
		found = found || r.SwitchedOff == "executors.kube_guard"
	}
	if !found {
		t.Error("config.yaml alone switches kube_guard off, and the record lost it")
	}
}

// TestLoadRepairsDescribeTheMergedConfig: with an overlay, the record keeps
// what is true of the configuration the hub runs, attributed to the file that
// holds the value. Each case was wrong before (Task 20387 review): a repair the
// overlay superseded survived, a repair config.yaml left as written was
// recorded a second time against the overlay, and a switch-off outlived an
// overlay that decided the section itself.
func TestLoadRepairsDescribeTheMergedConfig(t *testing.T) {
	type want struct {
		field, file string // file: "base" or "overlay"
		switchedOff bool
	}
	cases := []struct {
		name          string
		base, overlay string
		want          []want
	}{
		{"an overlay value replaces the repaired one",
			"max_parallel: 999\n", "max_parallel: 4\n", nil},
		{"an overlay that completes a section supersedes its switch-off",
			"executors:\n  kube_guard:\n    enabled: true\n",
			"executors:\n  kube_guard:\n    enabled: true\n    cert_file: /etc/kg.crt\n    key_file: /etc/kg.key\n", nil},
		{"an overlay that switches a section off chose to",
			"executors:\n  kube_guard:\n    enabled: true\n",
			"executors:\n  kube_guard:\n    enabled: false\n",
			[]want{{field: "executors.kube_guard.cert_file", file: "base"}}},
		{"a value config.yaml left as written is config.yaml's, once",
			"executors:\n  container:\n    enabled: true\n    oci_runtime: \"runsc --debug\"\n",
			"ui:\n  telemetry:\n    enabled: true\n",
			[]want{{field: "executors.container.oci_runtime", file: "base"},
				{field: "executors.container.enabled", file: "base", switchedOff: true}}},
		{"a switch-off the overlay causes is the overlay's",
			"executors:\n  kube_guard:\n    enabled: true\n",
			"executors:\n  kube_guard:\n    enabled: true\n    cert_file: /etc/kg.crt\n    key_file: /etc/kg.key\n" +
				"    advertise_url: http://hub.example.com\n",
			[]want{{field: "executors.kube_guard.advertise_url", file: "overlay"},
				{field: "executors.kube_guard.enabled", file: "overlay", switchedOff: true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeConfigs(t, "provider: claudecode\n"+tc.base, tc.overlay, 8081)
			cfg, _, err := LoadUIInstance(dir, 8081)
			if err != nil {
				t.Fatalf("LoadUIInstance: %v", err)
			}
			got := cfg.LoadRepairs()
			if len(got) != len(tc.want) {
				t.Fatalf("got %d repairs, want %d: %+v", len(got), len(tc.want), got)
			}
			files := map[string]string{"base": ConfigPath(dir), "overlay": UIInstanceConfigPath(dir, 8081)}
			for i, w := range tc.want {
				r := got[i]
				if r.Field != w.field || r.File != files[w.file] || (r.SwitchedOff != "") != w.switchedOff {
					t.Errorf("repair %d = %+v, want field %s in the %s file (switched off: %v)",
						i, r, w.field, w.file, w.switchedOff)
				}
			}
		})
	}
}
