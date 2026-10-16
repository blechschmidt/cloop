package agent

// usb.go reads this device's USB inventory (Task 20345). The sysfs reader
// itself lives in pkg/executor (executor.ScanUSB) since Task 20430, so the
// hub's in-process attach of a forwarded device reads exactly what an agent
// reads; this is the agent's name for it.

import "github.com/blechschmidt/cloop/pkg/executor"

// scanUSB returns the USB devices under sysfsRoot, sorted by port, reading
// their nodes' permissions under devRoot. See executor.ScanUSB.
func scanUSB(sysfsRoot, devRoot string) []executor.USBDevice {
	return executor.ScanUSB(sysfsRoot, devRoot)
}
