//go:build !linux

package deviceforward

import (
	"context"
	"fmt"
	"io"
	"runtime"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// L2SourceOptions configures an L2 source. Layer-2 forwarding needs Linux
// (AF_PACKET and TAP), so there is no off-Linux implementation.
type L2SourceOptions struct {
	Logf func(string, ...any)
}

// L2Source is unavailable off Linux.
type L2Source struct{}

// Device is unavailable off Linux.
func (s *L2Source) Device() ForwardedDevice { return ForwardedDevice{} }

// Probe is unavailable off Linux.
func (s *L2Source) Probe(context.Context) (bool, string, *executor.USBDevice) {
	return false, "L2 forwarding needs Linux", nil
}

// Open is unavailable off Linux.
func (s *L2Source) Open(context.Context) (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("deviceforward: L2 forwarding needs Linux, not %s", runtime.GOOS)
}

// Close is a no-op off Linux.
func (s *L2Source) Close() error { return nil }

// NewL2Source reports that L2 forwarding needs Linux.
func NewL2Source(iface string, opts L2SourceOptions) (*L2Source, error) {
	return nil, fmt.Errorf("deviceforward: layer-2 forwarding needs Linux (AF_PACKET), not %s", runtime.GOOS)
}

// TAPBridge is unavailable off Linux.
type TAPBridge struct{}

// Name returns the empty string off Linux.
func (b *TAPBridge) Name() string { return "" }

// Close is a no-op off Linux.
func (b *TAPBridge) Close() error { return nil }

// AttachL2 reports that L2 forwarding needs Linux.
func (h *Hub) AttachL2(ctx context.Context, forwarderID, tapName string) (*TAPBridge, error) {
	return nil, fmt.Errorf("deviceforward: layer-2 forwarding needs Linux (TAP), not %s", runtime.GOOS)
}
