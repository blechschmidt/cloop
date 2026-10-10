package diskwatch

import (
	"path/filepath"
	"strconv"
	"strings"
)

// parseMountPoints returns the mount points in a /proc/<pid>/mountinfo table
// that lie strictly below one of roots, keyed by cleaned path.
//
// A root that is itself a mount point is not in the result: the walk measures
// the root, and only refuses to cross into something mounted beneath it.
func parseMountPoints(table string, roots []string) map[string]bool {
	var out map[string]bool
	for _, line := range strings.Split(table, "\n") {
		// The kernel escapes whitespace inside a field, so splitting on it
		// is exact. Field 5 is the mount point.
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mp := filepath.Clean(unescapeMountField(fields[4]))
		for _, r := range roots {
			if below(mp, r) {
				if out == nil {
					out = make(map[string]bool)
				}
				out[mp] = true
				break
			}
		}
	}
	return out
}

// below reports whether path lies strictly under root.
func below(path, root string) bool {
	root = filepath.Clean(root)
	if path == root {
		return false
	}
	if root == string(filepath.Separator) {
		return strings.HasPrefix(path, root)
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

// unescapeMountField undoes the kernel's octal escaping of a mountinfo field:
// a space is written \040, a tab \011, a newline \012 and a backslash \134.
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
