//go:build linux

package diskwatch

import "os"

// mountInfoPath is this process's view of the mount table. It is the view that
// matters: the walk runs in this process, so a mount it cannot see is one it
// does not cross either.
const mountInfoPath = "/proc/self/mountinfo"

// mountPointsUnder reads the mount points below roots from the process's mount
// table, and whether it could. An unreadable table makes the walk fall back on
// st_dev, which still stops it at every mount of another filesystem.
func mountPointsUnder(roots []string) (map[string]bool, bool) {
	data, err := os.ReadFile(mountInfoPath)
	if err != nil {
		return nil, false
	}
	return parseMountPoints(string(data), roots), true
}
