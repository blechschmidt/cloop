//go:build linux

package agent

import "golang.org/x/sys/unix"

// sysinfoMemoryMB reads total RAM with sysinfo(2), which no /proc mount
// option can hide. The hardened unit the installer renders sets
// ProcSubset=pid, under which /proc/meminfo does not exist, so before this
// every installed agent reported its memory as unknown and the hub could not
// say how small a device was — sgx, which a build exhausted, among them (Task
// 20512).
func sysinfoMemoryMB() int {
	var si unix.Sysinfo_t
	if err := unix.Sysinfo(&si); err != nil {
		return 0
	}
	unit := uint64(si.Unit)
	if unit == 0 {
		unit = 1 // kernels before 2.3.23 report bytes and leave mem_unit 0
	}
	return int(uint64(si.Totalram) * unit / (1 << 20))
}
