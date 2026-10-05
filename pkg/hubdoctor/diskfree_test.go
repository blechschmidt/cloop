package hubdoctor

import (
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/diskusage"
)

// storage.free_space (Task 20381): pass with room, warn below twice the
// floor, fail below it, warn with the check off or unmeasurable. The volume is
// an injected probe, so no disk is filled to get there.
func TestFreeSpaceFinding(t *testing.T) {
	const mb = int64(1) << 20
	off := 0
	twoGB := 2048
	cases := []struct {
		name   string
		floor  *int
		free   int64
		err    error
		want   Severity
		inText string
	}{
		{"room", nil, 5000 * mb, nil, SeverityPass, "runs pause below 1.00 GB"},
		{"below twice the floor", nil, 1500 * mb, nil, SeverityWarn, "less than twice the 1.00 GB floor"},
		{"below the floor", nil, 900 * mb, nil, SeverityFail, "below the 1.00 GB floor"},
		{"a floor of its own", &twoGB, 3000 * mb, nil, SeverityWarn, "less than twice the 2.00 GB floor"},
		{"the check off", &off, 10 * mb, nil, SeverityWarn, "min_free_disk_mb is 0"},
		{"unmeasurable", nil, 0, errors.New("statfs: permission denied"), SeverityWarn, "could not measure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Orchestrator.MinFreeDiskMB = tc.floor
			var got []Finding
			probe := func(paths ...string) ([]diskusage.Volume, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return []diskusage.Volume{{Mount: "/srv", Path: paths[0], FreeBytes: tc.free}}, nil
			}
			checkFreeSpace(t.TempDir(), cfg, Options{DiskProbe: probe}, func(f Finding) { got = append(got, f) })
			if len(got) != 1 {
				t.Fatalf("findings = %+v, want exactly one", got)
			}
			f := got[0]
			if f.Check != "storage.free_space" {
				t.Errorf("Check = %q", f.Check)
			}
			if f.Severity != tc.want {
				t.Errorf("Severity = %s, want %s (%s)", f.Severity, tc.want, f.Message)
			}
			if !strings.Contains(f.Message, tc.inText) {
				t.Errorf("Message = %q, want it to contain %q", f.Message, tc.inText)
			}
			if f.Severity != SeverityPass && f.Remediation == "" {
				t.Error("a non-pass finding carries no remediation")
			}
		})
	}
}

// The check runs as part of every doctor run, against the hub's own volume.
func TestFreeSpaceRunsInEveryDiagnosis(t *testing.T) {
	probed := ""
	probe := func(paths ...string) ([]diskusage.Volume, error) {
		probed = paths[0]
		return []diskusage.Volume{{Mount: "/", Path: paths[0], FreeBytes: 900 << 20}}, nil
	}
	dir := t.TempDir()
	rep := Run(t.Context(), dir, config.Default(), Options{Offline: true, DiskProbe: probe})
	var found *Finding
	for i := range rep.Findings {
		if rep.Findings[i].Check == "storage.free_space" {
			found = &rep.Findings[i]
		}
	}
	if found == nil || found.Severity != SeverityFail {
		t.Fatalf("storage.free_space = %+v, want a failure for a volume below the floor", found)
	}
	if !strings.HasPrefix(probed, dir) {
		t.Errorf("probed %q, want the hub's own .cloop under %q", probed, dir)
	}
	if rep.ExitCode() != 1 {
		t.Error("a hub below its floor exits 0 from the doctor")
	}
}
