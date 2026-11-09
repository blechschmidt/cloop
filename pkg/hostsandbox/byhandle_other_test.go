//go:build !linux

package hostsandbox

// openByHandle has no file handles to try off Linux.
func openByHandle(string, string) int { return 0 }
