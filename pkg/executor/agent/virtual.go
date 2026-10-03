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
func resolveVirtualDevices(sels []executor.DeviceSelector, sysfsRoot, devRoot string) (virtualDevices, error) {
	var out virtualDevices
	if len(sels) == 0 {
		return out, nil
	}
	if devRoot == "" {
		devRoot = "/dev"
	}
	inventory := scanUSB(sysfsRoot, devRoot)
	groups := map[int]bool{}
	for _, sel := range sels {
		var nodes []executor.HostDevice
		var gid *int
		switch {
		case sel.USB != nil:
			d, err := executor.ResolveUSB(inventory, *sel.USB)
			if err != nil {
				return virtualDevices{}, fmt.Errorf("device %q: %w", sel.Name, err)
			}
			nodes = executor.USBHostDevices(sel, d)
			gid = d.GID
			out.Log = append(out.Log, fmt.Sprintf("%s → %s at %s (port %s)", sel.Name, d.Label(), d.Node, d.Port))
		default:
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
	return ex, nil
}

// virtualRunner resolves a virtual executor's devices onto spec and returns the
// driver that must start it.
func (a *Agent) virtualRunner(payload remote.StartPayload, spec *executor.Spec, handleID string) (payloadDriver, error) {
	v := payload.Virtual
	if err := v.Validate(payload.Sandbox.Normalize()); err != nil {
		return nil, fmt.Errorf("agent: refusing virtual executor configuration from the control plane: %w", err)
	}
	devs, err := resolveVirtualDevices(v.Devices, a.cfg.SysfsRoot, a.cfg.DevRoot)
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
