package remote

// inventoryproto.go lets the control plane re-read a device's inventory on
// demand (Task 20345, protocol v14).
//
// The hello already carries the inventory, and for most of it — CPUs, memory,
// the engines on PATH — the connect-time snapshot is as fresh as anyone needs.
// USB hardware is the exception, because plugging it in is the thing an admin
// does *immediately before* opening the dashboard to give a sandbox the device
// they just plugged in. Waiting for the agent to reconnect to see it would make
// the panel wrong at exactly the moment it is being read, so the Refresh button
// asks the device instead.

import (
	"context"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const (
	// TypeInventoryReq (control plane → agent) asks the device to re-detect
	// its capabilities now. Added in v14.
	TypeInventoryReq FrameType = "inventory_req"
	// TypeInventory (agent → control plane) answers with them.
	TypeInventory FrameType = "inventory"
)

// InventoryTimeout bounds a refresh. Detection reads sysfs and asks the
// container engine for its runtimes, which is well under a second on a healthy
// device; the bound is for the one that is not.
const InventoryTimeout = 20 * time.Second

// InventoryRequestPayload is the (empty) request. A struct rather than nothing
// because every frame carries a payload, and a future field — "only USB" — has
// somewhere to go.
type InventoryRequestPayload struct{}

// InventoryPayload is the device's freshly detected capabilities.
type InventoryPayload struct {
	Capabilities AgentCapabilities `json:"capabilities"`
}

// DecodeInventory decodes and cleans an inventory answer.
func DecodeInventory(f Frame) (InventoryPayload, error) {
	var p InventoryPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	p.Capabilities.USBDevices = CleanUSBInventory(p.Capabilities.USBDevices)
	return p, nil
}

// CleanUSBInventory keeps the well-formed entries of an inventory a device
// reported, up to the bound.
//
// Dropping rather than refusing the whole report: a device with one odd USB
// gadget attached must not lose its hello — and with it every other capability
// — over it. What is dropped never reaches the database or the dashboard, which
// is the property that matters, since these strings come from device firmware.
func CleanUSBInventory(devs []executor.USBDevice) []executor.USBDevice {
	if len(devs) == 0 {
		return nil
	}
	out := make([]executor.USBDevice, 0, len(devs))
	for _, d := range devs {
		if len(out) >= executor.MaxUSBDevices {
			break
		}
		if d.Validate() == nil {
			out = append(out, d)
		}
	}
	return out
}

// RefreshInventory asks the device to re-detect its capabilities and adopts the
// answer as this executor's cached inventory.
//
// The cache is refreshed wholesale on every hello anyway, so this is the same
// value the device would report on its next connection, fetched early.
func (e *Executor) RefreshInventory(ctx context.Context) (AgentCapabilities, error) {
	sess := e.currentSession()
	if sess == nil {
		return AgentCapabilities{}, fmt.Errorf("%w: %s (%s) is not connected, so its hardware "+
			"cannot be re-read; showing what it reported when it was last online",
			ErrAgentUnreachable, e.id, e.name)
	}
	if v := sess.Version(); !SupportsVirtualExecutor(v) {
		return AgentCapabilities{}, fmt.Errorf("%w: %s (%s) speaks protocol v%d, and re-reading its "+
			"hardware on request needs v%d; upgrade the agent", ErrProtocol, e.id, e.name, v,
			MinVirtualExecutorVersion)
	}
	frame, err := sess.frame(TypeInventoryReq, newCorrelationID(), "", InventoryRequestPayload{})
	if err != nil {
		return AgentCapabilities{}, fmt.Errorf("remote: build inventory request for %s: %w", e.id, err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, InventoryTimeout)
	defer cancel()
	reply, err := sess.request(reqCtx, frame, TypeInventory)
	if err != nil {
		return AgentCapabilities{}, fmt.Errorf("remote: ask %s (%s) for its inventory: %w", e.id, e.name, err)
	}
	inv, err := DecodeInventory(reply)
	if err != nil {
		return AgentCapabilities{}, fmt.Errorf("remote: decode inventory from %s: %w", e.id, err)
	}
	e.mu.Lock()
	e.caps = inv.Capabilities
	e.mu.Unlock()
	return inv.Capabilities, nil
}
