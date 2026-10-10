//go:build unix

package diskwatch

import (
	"io/fs"
	"syscall"
)

// statInfo is what a measurement needs of one entry.
type statInfo struct {
	// bytes is the allocated size: st_blocks counts 512-byte units on every
	// Unix, whatever the filesystem's own block size.
	bytes int64
	dev   uint64
	ino   uint64
	nlink uint64
}

// statOf reads an entry's allocation and identity from its lstat.
func statOf(info fs.FileInfo) statInfo {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return statInfo{bytes: info.Size(), nlink: 1}
	}
	return statInfo{
		bytes: int64(st.Blocks) * 512,
		dev:   uint64(st.Dev),
		ino:   uint64(st.Ino),
		nlink: uint64(st.Nlink),
	}
}
