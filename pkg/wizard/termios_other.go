//go:build !linux && !darwin

package wizard

import (
	"bufio"
	"strings"
)

// IsTTY reports whether stdin is an interactive terminal.
// On unsupported platforms we cannot determine this reliably; assume yes.
func IsTTY() bool {
	return true
}

// readMasked falls back to plain (echoing) scan on unsupported platforms.
func readMasked(scanner *bufio.Scanner) string {
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}
