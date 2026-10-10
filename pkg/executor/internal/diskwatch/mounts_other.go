//go:build !linux

package diskwatch

// mountPointsUnder has no mount table to read off Linux; the walk relies on
// st_dev, which stops it at every mount of another filesystem.
func mountPointsUnder(roots []string) (map[string]bool, bool) { return nil, false }
