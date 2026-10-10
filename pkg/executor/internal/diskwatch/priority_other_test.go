//go:build !linux

package diskwatch

// ioprioClassIdle stands in for the Linux constant the shared priority test
// names; off Linux the test returns before comparing against it.
const ioprioClassIdle = 3

func threadPriority() (nice, class int) { return 0, 0 }
