//go:build !unix

package diskwatch

import "io/fs"

// statInfo is what a measurement needs of one entry.
type statInfo struct {
	bytes int64
	dev   uint64
	ino   uint64
	nlink uint64
}

// statOf falls back to the apparent size where the platform reports no
// allocation, and to no identity: every file is its only link and every
// directory is on the root's device.
func statOf(info fs.FileInfo) statInfo {
	return statInfo{bytes: info.Size(), nlink: 1}
}
