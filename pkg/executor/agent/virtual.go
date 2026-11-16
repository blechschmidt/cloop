package agent

// virtual.go is the device half of a virtual executor (Task 20345): turning a
// start frame's Virtual section into the hardware a sandbox is given and the
// firewall its bridge is filtered by.
//
// Both are resolved here, on the device, from the device's own live view —
// never from the hub's copy of the inventory. The hub's copy is a snapshot
// from the last hello; the device knows what is plugged in *now*, and a USB
// device that re-enumerated since then has a node path the hub has never seen.

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// virtualDevices is what a virtual executor's device list resolved to.
type virtualDevices struct {
	// Devices are the nodes to pass through, at the paths the device found.
	Devices []executor.HostDevice
	// Groups are the supplementary group IDs the sandbox user needs to open
	// them, sorted and unique.
	Groups []string
	// Log lines describe the resolution for the device's own log.
	Log []string
}

// resolveVirtualDevices resolves every selector against this device's live
// sysfs. Any selector that does not resolve fails the whole start: a hardware
// task started without its hardware produces a run that looks like a software
// bug, on a machine whose operator would have to be told the device was
// unplugged by reading a stack trace.
//
// heldFor names the devices this agent attached for forwarders (Task 20502),
// asked after the scan, so a device that was in it was recorded before it.
// Each is on this host's USB bus like any other device, and each belongs to
// the run whose project its binding names, so no selector may choose one and
// no path may name one: otherwise a virtual executor bound to another project,
// asking for "any 1050:0030", would hand that project's sandbox somebody
// else's on-prem hardware.
func resolveVirtualDevices(sels []executor.DeviceSelector, sysfsRoot, devRoot string,
	heldFor func([]executor.USBDevice) forwardedSet) (virtualDevices, error) {
	var out virtualDevices
	if len(sels) == 0 {
		return out, nil
	}
	if devRoot == "" {
		devRoot = "/dev"
	}
	scanned := scanUSB(sysfsRoot, devRoot)
	var held forwardedSet
	if heldFor != nil {
		held = heldFor(scanned)
	}
	inventory, forwarded := withoutForwarded(scanned, held)
	groups := map[int]bool{}
	for _, sel := range sels {
		var nodes []executor.HostDevice
		var gid *int
		switch {
		case sel.USB != nil:
			d, err := executor.ResolveUSB(inventory, *sel.USB)
			if err != nil {
				for _, f := range forwarded {
					if sel.USB.Matches(f) {
						return virtualDevices{}, fmt.Errorf("device %q: %w: the %s on port %s is a device "+
							"forwarder's, attached on %s for another run, and is not this executor's to give",
							sel.Name, executor.ErrUSBDeviceNotFound, f.Label(), f.Port, deviceName())
					}
				}
				return virtualDevices{}, fmt.Errorf("device %q: %w", sel.Name, err)
			}
			nodes = executor.USBHostDevices(sel, d)
			gid = d.GID
			out.Log = append(out.Log, fmt.Sprintf("%s → %s at %s (port %s)", sel.Name, d.Label(), d.Node, d.Port))
		default:
			if held.holds(devRoot, sel.Path) {
				return virtualDevices{}, fmt.Errorf("device %q: %s is a node of a USB device a device "+
					"forwarder brought in on %s for another run, and is not this executor's to give",
					sel.Name, sel.Path, deviceName())
			}
			nodes = []executor.HostDevice{{
				Name: sel.Name, Source: sel.Path, Target: sel.Path, Permissions: sel.Permissions,
			}}
			gid = nodeGID(devRoot, sel.Path)
			out.Log = append(out.Log, fmt.Sprintf("%s → %s", sel.Name, sel.Path))
		}
		out.Devices = append(out.Devices, nodes...)

		switch {
		case sel.Group != "":
			n, err := resolveGroup(sel.Group)
			if err != nil {
				return virtualDevices{}, fmt.Errorf("device %q: %w", sel.Name, err)
			}
			groups[n] = true
		case gid != nil && *gid > 0:
			// Inferred from the node when the agent can see it. A node owned by
			// a dedicated group (the udev convention: plugdev, dialout) opens
			// for the unprivileged sandbox user only with that group; root's is
			// never inferred, see executor.ParseGroupID.
			groups[*gid] = true
		}
	}
	if err := executor.ValidateDevices(out.Devices); err != nil {
		return virtualDevices{}, err
	}
	for g := range groups {
		out.Groups = append(out.Groups, strconv.Itoa(g))
	}
	sort.Strings(out.Groups)
	return out, nil
}

// forwardedSet is what this agent holds for device forwarders (Task 20502):
// the local bus ids of the USB devices it attached, and their nodes.
type forwardedSet struct {
	ports map[string]bool
	nodes map[string]bool
}

// holds reports whether path, or what it resolves to under devRoot, is the
// node of a forwarded device. A link (/dev/serial/by-id/…) names its target.
func (f forwardedSet) holds(devRoot, path string) bool {
	if len(f.nodes) == 0 {
		return false
	}
	if f.nodes[filepath.Clean(path)] {
		return true
	}
	return f.nodes[resolveDevPath(devRoot, path)]
}

// resolveDevPath resolves a /dev path through devRoot's links and returns it
// in /dev form, or the cleaned path when it does not resolve.
func resolveDevPath(devRoot, path string) string {
	clean := filepath.Clean(path)
	rel, ok := strings.CutPrefix(clean, "/dev/")
	if !ok {
		return clean
	}
	if devRoot == "" {
		devRoot = "/dev"
	}
	root, err := filepath.EvalSymlinks(devRoot)
	if err != nil {
		return clean
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, rel))
	if err != nil {
		return clean
	}
	inside, err := filepath.Rel(root, real)
	if err != nil || inside == ".." || strings.HasPrefix(inside, "../") {
		return clean
	}
	return "/dev/" + inside
}

// withoutForwarded splits an inventory into the devices a selector may choose
// from and the forwarded ones it may not (Task 20502).
func withoutForwarded(inventory []executor.USBDevice, held forwardedSet) (free, forwarded []executor.USBDevice) {
	if len(held.ports) == 0 && len(held.nodes) == 0 {
		return inventory, nil
	}
	for _, d := range inventory {
		if held.ports[d.Port] || held.nodes[d.Node] {
			forwarded = append(forwarded, d)
			continue
		}
		free = append(free, d)
	}
	return free, forwarded
}

// forwardedHeld is what this agent holds for forwarders, given a USB scan
// taken just before: the ports its ledger records — written before the kernel
// holds anything — and the devices its live attachments report, which covers
// an agent that could not keep a ledger. The nodes are every node of those
// devices in the scan, and the ones the attachments themselves give.
func (a *Agent) forwardedHeld(inventory []executor.USBDevice) forwardedSet {
	set := forwardedSet{ports: map[string]bool{}, nodes: map[string]bool{}}
	if a == nil {
		return set
	}
	if a.ledger != nil {
		for b := range a.ledger.HeldUSBBusIDs() {
			set.ports[b] = true
		}
	}
	for _, d := range a.devices.all() {
		d.mu.Lock()
		att := d.attached
		d.mu.Unlock()
		if att == nil || d.payload.Kind != executor.ForwardedUSB {
			continue
		}
		if o := att.Opened(); o.LocalBusID != "" {
			set.ports[o.LocalBusID] = true
		}
		nodes, _ := att.Give(d.payload.Name, executor.HostInterface{})
		for _, n := range nodes {
			set.nodes[filepath.Clean(n.Source)] = true
		}
	}
	for _, dev := range inventory {
		if !set.ports[dev.Port] {
			continue
		}
		set.nodes[filepath.Clean(dev.Node)] = true
		for _, n := range dev.Nodes {
			set.nodes[filepath.Clean(n.Path)] = true
		}
	}
	return set
}

// refuseForwardedNodes refuses device grants the hub dispatched that name a
// node of a device this agent holds for a forwarder (Task 20502): a grant names
// a path, and the path a forwarded device enumerated at may be the one a
// granted device had before it was unplugged. The workload's own forwarded
// devices are added after this check, from its own claim.
func (a *Agent) refuseForwardedNodes(devs []executor.HostDevice, sysfsRoot, devRoot string) error {
	if len(devs) == 0 {
		return nil
	}
	held := a.forwardedHeld(scanUSB(sysfsRoot, devRoot))
	for _, d := range devs {
		if held.holds(devRoot, d.Source) {
			return fmt.Errorf("device %q: %s is a node of a USB device a device forwarder brought in on %s "+
				"for another run, and no grant gives it", d.Name, d.Source, deviceName())
		}
	}
	return nil
}

// resolveGroup turns a group name or number into a GID on this device.
func resolveGroup(name string) (int, error) {
	if n, numeric, err := executor.ParseGroupID(name); numeric {
		return n, err
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("group %q does not exist on %s", name, deviceName())
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("group %q is root's on %s; give the device node a group of its own", name, deviceName())
	}
	return n, nil
}

// nodeGID is the owning group of a node the agent can see, or nil.
func nodeGID(devRoot, node string) *int {
	fi, err := os.Stat(filepath.Join(devRoot, strings.TrimPrefix(node, "/dev/")))
	if err != nil {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	gid := int(st.Gid)
	return &gid
}

// egressFilterFor translates a virtual executor's firewall into the container
// driver's filter. The translation is container.FilterFromRules, shared with
// the driver's own path for a workload's firewall rules (Task 20363) so the two
// cannot drift; an empty network means "the sandbox's own".
func egressFilterFor(fw *executor.FirewallRules) (container.EgressFilter, string) {
	return container.FilterFromRules(fw, "")
}

// virtualDriverKey identifies one virtual executor's driver configuration. The
// firewall and groups are in it because both are baked into the driver's
// Options; the ID is in it because it names the bridge and the table, and two
// virtual executors with identical settings still need two firewalls.
func virtualDriverKey(s executor.SandboxSettings, v *remote.VirtualStart, groups []string) string {
	fw := "none"
	if v.Firewall != nil {
		fw = v.Firewall.Describe()
	}
	return strings.Join([]string{"virtual", v.ID, string(s.Mode), s.Engine, s.Runtime, s.Image, s.Network,
		fw, strings.Join(groups, ",")}, "\x00")
}

// virtualDriverFor returns the container driver for a virtual executor's
// dispatch, building it on first use.
//
// stageDir is where the driver writes the files it bind-mounts into a sandbox —
// the resolv.conf of a filtered one. It is the agent's work root, because the
// engine resolves bind-mount sources in the host's mount namespace, and the
// agent's own /tmp is private to its service unit.
func (c *driverCache) virtualDriverFor(s executor.SandboxSettings, v *remote.VirtualStart, groups []string,
	stageDir string) (payloadDriver, error) {
	s = s.Normalize()
	if err := v.Validate(s); err != nil {
		return nil, fmt.Errorf("agent: refusing virtual executor configuration from the control plane: %w", err)
	}
	key := virtualDriverKey(s, v, groups)

	c.mu.Lock()
	defer c.mu.Unlock()
	if d, ok := c.virtual[key]; ok {
		return d, nil
	}
	filter, network := egressFilterFor(v.Firewall)
	if network == "" {
		network = s.Network
	}
	opts := container.Options{
		// The virtual executor's own ID, so its bridge and nftables table are
		// its own: cloop-sbx-<id> and cloop_sbx_<id>. A shared ID would let the
		// second virtual executor's Apply replace the first one's ruleset on a
		// bridge the first one's sandboxes are still attached to.
		ID:           v.ID,
		Runtime:      s.Engine,
		OCIRuntime:   s.Runtime,
		Image:        s.Image,
		Network:      network,
		EgressFilter: filter,
		GroupAdd:     groups,
		StageDir:     stageDir,
	}
	ex, err := container.New(opts)
	if err != nil {
		return nil, fmt.Errorf("agent: virtual executor %s (%s) runs payloads in a container (%s) but this "+
			"device cannot: %w", v.ID, v.Name, s.Describe(), err)
	}
	if c.virtual == nil {
		c.virtual = make(map[string]payloadDriver)
	}
	c.virtual[key] = ex
	sweepIdleNetworks(ex)
	return ex, nil
}

// virtualRunner resolves a virtual executor's devices onto spec and returns the
// driver that must start it.
func (a *Agent) virtualRunner(payload remote.StartPayload, spec *executor.Spec, handleID string) (payloadDriver, error) {
	v := payload.Virtual
	if err := v.Validate(payload.Sandbox.Normalize()); err != nil {
		return nil, fmt.Errorf("agent: refusing virtual executor configuration from the control plane: %w", err)
	}
	devs, err := resolveVirtualDevices(v.Devices, a.cfg.SysfsRoot, a.cfg.DevRoot, a.forwardedHeld)
	if err != nil {
		return nil, fmt.Errorf("virtual executor %s (%s) on %s: %w", v.ID, v.Name, deviceName(), err)
	}
	for _, line := range devs.Log {
		a.cfg.logf("workload %s: virtual executor %s: device %s", handleID, v.ID, line)
	}
	if len(devs.Devices) > 0 {
		// Copied, not appended in place: the Spec's slices may alias the frame
		// the hub sent, and the start path above has already recorded parts of
		// it for revocation and write-back.
		spec.Devices = append(append([]executor.HostDevice(nil), spec.Devices...), devs.Devices...)
	}
	return a.drivers.virtualDriverFor(payload.Sandbox, v, devs.Groups, a.root)
}

// handleInventoryReq answers the control plane's request to re-read this
// device's capabilities (protocol v14).
func (a *Agent) handleInventoryReq(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	defer func() {
		if r := recover(); r != nil {
			a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, fmt.Sprintf("panic: %v", r))
		}
	}()
	a.reply(ctx, sess, remote.TypeInventory, frame.ID, "", remote.InventoryPayload{Capabilities: a.Capabilities()})
}
