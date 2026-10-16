//go:build !linux

package deviceforward

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// VHCI is unavailable off Linux.
type VHCI struct{ Root string }

// Available reports that USB/IP import needs Linux.
func (v VHCI) Available() error {
	return fmt.Errorf("importing a forwarded USB device needs Linux's vhci_hcd, not %s", runtime.GOOS)
}

// ImportOptions configures an import. USB/IP import needs Linux.
type ImportOptions struct {
	VHCI             VHCI
	SysfsRoot        string
	DevRoot          string
	Ledger           *Ledger
	EnumerateTimeout time.Duration
	Logf             func(string, ...any)
}

// USBImport is unavailable off Linux.
type USBImport struct {
	Port   int
	DevID  uint32
	Device executor.USBDevice
}

// Done is never closed off Linux; no import exists.
func (u *USBImport) Done() <-chan struct{} { return nil }

// HostDevices is empty off Linux.
func (u *USBImport) HostDevices(string) []executor.HostDevice { return nil }

// Close is a no-op off Linux.
func (u *USBImport) Close() error { return nil }

// ImportUSB reports that USB/IP import needs Linux.
func ImportUSB(ctx context.Context, stream io.ReadWriteCloser, busid string, opts ImportOptions) (*USBImport, error) {
	if stream != nil {
		_ = stream.Close()
	}
	return nil, fmt.Errorf("deviceforward: importing a forwarded USB device needs Linux's vhci_hcd, not %s", runtime.GOOS)
}

// processStartTime is unknown off Linux.
func processStartTime(int) uint64 { return 0 }

// processAlive treats every ledger as live off Linux, so nothing is swept.
func processAlive(pid int, _ uint64) bool {
	p, err := os.FindProcess(pid)
	return err == nil && p != nil
}

// undoLedgerEntry has nothing to undo off Linux: nothing is ever attached.
func undoLedgerEntry(LedgerEntry, *SweepReport, func(string, ...any)) {}
