//go:build !linux

package deviceforward

import (
	"context"
	"fmt"
	"io"
	"runtime"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// USBSourceOptions configures a USB source. On non-Linux platforms a USB
// source cannot be built, because the whole mechanism is Linux's usbip-host
// driver and its sysfs interface.
type USBSourceOptions struct {
	SysfsRoot   string
	UsbipBinary string
	Logf        func(string, ...any)
}

// USBSource is unavailable off Linux.
type USBSource struct{}

// NewUSBSource reports that USB forwarding needs Linux.
func NewUSBSource(match executor.USBMatch, opts USBSourceOptions) (*USBSource, error) {
	return nil, fmt.Errorf("deviceforward: USB forwarding needs Linux and the usbip-host driver, not %s", runtime.GOOS)
}

// The methods below make *USBSource satisfy LocalSource on every platform so
// callers type-check; they are never reached because NewUSBSource errors here.

// Device is unavailable off Linux.
func (s *USBSource) Device() ForwardedDevice { return ForwardedDevice{} }

// Probe is unavailable off Linux.
func (s *USBSource) Probe(context.Context) (bool, string, *executor.USBDevice) {
	return false, "USB forwarding needs Linux", nil
}

// Open is unavailable off Linux.
func (s *USBSource) Open(context.Context) (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("deviceforward: USB forwarding needs Linux, not %s", runtime.GOOS)
}

// Close is a no-op off Linux.
func (s *USBSource) Close() error { return nil }
