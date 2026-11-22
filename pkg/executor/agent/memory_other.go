//go:build !linux

package agent

// sysinfoMemoryMB is Linux's fallback for an unreadable /proc/meminfo; other
// platforms report their memory as unknown, as detectMemoryMB says.
func sysinfoMemoryMB() int { return 0 }
