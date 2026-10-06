package hubdoctor

// The free-space check (Task 20381): whether the volume holding the hub's
// state has room for the hub to keep writing.
//
// The disk usage findings in retention.go say what .cloop costs. This says
// what is left, which is the number that decides whether the next write lands.
// A hub on a volume below orchestrator.min_free_disk_mb is one whose runs on
// that volume start nothing — they pause disk_low — and whose own database is a
// build or a test run away from refusing a write. Below twice the floor it is a
// warning: the runs still start, and that much headroom goes in an afternoon on
// a busy host.

import (
	"fmt"
	"path/filepath"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/diskusage"
)

func checkFreeSpace(dir string, cfg *config.Config, opts Options, add addFn) {
	floorMB := cfg.Orchestrator.EffectiveMinFreeDiskMB()
	path := filepath.Join(dir, ".cloop")
	probe := opts.DiskProbe
	if probe == nil {
		probe = diskusage.Volumes
	}
	vols, err := probe(path)
	if err != nil || len(vols) == 0 {
		if err == nil {
			err = fmt.Errorf("no volume found")
		}
		add(Finding{
			Check: "storage.free_space", Title: "Free disk space", Severity: SeverityWarn,
			Message:     "could not measure the volume holding " + path + ": " + err.Error(),
			Remediation: "Check that " + path + " exists and is readable by the hub's user",
		})
		return
	}
	v := vols[0]
	floor := int64(floorMB) << 20
	details := map[string]any{
		"volume":      v.Mount,
		"free_bytes":  v.FreeBytes,
		"floor_bytes": floor,
	}
	free := diskusage.HumanBytes(v.FreeBytes)
	freeUp := "Free space on " + v.Mount + " — `cloop compact`, `cloop db maintain` and the Go build cache " +
		"(`go clean -cache`) are the usual places — or move .cloop to a larger volume"
	switch v.AgainstFloor(floor) {
	case diskusage.FloorOff:
		add(Finding{
			Check: "storage.free_space", Title: "Free disk space", Severity: SeverityWarn,
			Message: fmt.Sprintf("volume %s has %s free, and orchestrator.min_free_disk_mb is 0: runs start "+
				"on any disk, and a task's outcome written onto a full one has no reserve to fall back on", v.Mount, free),
			Remediation: fmt.Sprintf("Remove orchestrator.min_free_disk_mb: 0 to restore the %d MB default, or set a floor "+
				"in Settings → Disk & Retention", config.MinFreeDiskMBDefault),
			Details: details,
		})
	case diskusage.FloorBelow:
		add(Finding{
			Check: "storage.free_space", Title: "Free disk space", Severity: SeverityFail,
			Message: fmt.Sprintf("volume %s has %s free, below the %s floor: runs writing there pause before "+
				"their next task, and the hub's own database is close to refusing writes", v.Mount, free, diskusage.HumanBytes(floor)),
			Remediation: freeUp,
			Details:     details,
		})
	case diskusage.FloorNear:
		add(Finding{
			Check: "storage.free_space", Title: "Free disk space", Severity: SeverityWarn,
			Message: fmt.Sprintf("volume %s has %s free, less than twice the %s floor runs pause at",
				v.Mount, free, diskusage.HumanBytes(floor)),
			Remediation: freeUp,
			Details:     details,
		})
	default:
		add(Finding{
			Check: "storage.free_space", Title: "Free disk space", Severity: SeverityPass,
			Message: fmt.Sprintf("volume %s has %s free; runs pause below %s", v.Mount, free, diskusage.HumanBytes(floor)),
			Details: details,
		})
	}
}
