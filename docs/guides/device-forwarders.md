# Device forwarders

A **device forwarder** connects one piece of on-prem hardware, a USB device or
a layer-2 network interface, to a cloop hub over a single authenticated
outbound connection. It is a minimal binary (`cloop
forward`, or the standalone `cmd/cloop-forward`) that does nothing else: it
runs no harness, executes no task and reads no project.

## Why it exists

In cloop's trust model, the agent runs in an isolated environment in the cloud
with limited access to on-prem hardware. A machine wired to hardware (a bench
with a hardware security module, a board under test on a lab VLAN, a radio on
its own segment) is useful as a remote executor only if a cloud sandbox can
reach what it is plugged into. Running the full executor agent there would give
the cloud much more than the hardware: a harness, the filesystem and the
ability to run any work. A forwarder gives it one device.

The forwarder dials out, like the executor agent, so the on-prem machine needs
no inbound firewall rule and can sit behind NAT. It authenticates with its own
enrollment token and long-lived credential, which the hub stores only as a
SHA-256 hash. A forwarder credential can never authenticate as something that
runs work.

## Enrolling a forwarder

In the dashboard, open **Executors → Device forwarders → + Enroll forwarder**.
Choose a USB device (by `vendor:product[:serial]`) or an interface name, and the
hub prints a single-use command to run on the on-prem machine.

From the CLI on the hub:

```
cloop forward enroll --name bench-usb --usb 1050:0030
cloop forward enroll --name lab-net  --interface eth1
```

Either command prints a `cloop forward --bundle …` command. Run it on the
on-prem machine:

```
cloop forward --bundle cloopfwd1.…
```

The bundle contains the hub URL, the single-use token and the hub's certificate
pin. The token proves who the forwarder is, and the pin proves the forwarder
reached the hub and not something else answering on that hostname. The token
is redeemed once for a long-lived credential, saved with mode `0600` at
`~/.cloop/forwarder.json`. After that, plain `cloop forward` reconnects by
itself.

To list and revoke:

```
cloop forward list
cloop forward revoke <id>
```

## Binding a device to a project

A connected forwarder's device reaches nothing until a **binding** says which
project's runs get it. A binding needs `executor.manage`, like enrolling, and
lasts for a TTL (24 hours by default, 90 days at most). Bindings are audited as
`forwarder.bind` and `forwarder.unbind`. You can create one in three places:

- **Executors → Device forwarders**: each forwarder's card lists its bindings
  and has **Bind…** (choose the project, optionally a virtual executor, how long
  it lasts, and for a network segment the interface's name and address inside
  the sandbox) and **Unbind**.
- **The project's Overview → Forwarded devices**: what is bound to this
  project, with **Bind** for an administrator and **Request** for a maintainer.
  A request takes the same path as a secret grant request: it appears in the
  approvals inbox of everyone who may decide it, and an administrator other
  than the requester approves it, which creates the binding (narrowed, if they
  choose).
- **The CLI on the hub**:

```
cloop forward bind <forwarder-id> --project /srv/projects/bench --ttl 8h
cloop forward bind <forwarder-id> --project /srv/projects/lab \
    --virtual-executor lab-vx --target eth1 --address 10.77.0.2/24
cloop forward bindings [--project DIR] [--all]
cloop forward unbind <binding-id> --reason "bench returned"
```

A binding narrowed to a virtual executor applies only to the project's runs on
that executor. Revoking a forwarder revokes its bindings.

## What happens at dispatch

When a run of a bound project is dispatched, the hub:

1. reads the project's current bindings (if there are none, none of the
   following steps happen);
2. refuses the run, naming the forwarder, if a bound forwarder has no live
   session anywhere in the hub cluster;
3. refuses the run if its executor can't give the device to a sandbox: a
   host-process run, an agent in host mode, a gVisor or Kata sandbox, an agent
   older than protocol v22 (with the upgrade path), or an agent that reports it
   can't attach this kind of device (with its reason);
4. opens a stream to the forwarder's device, over its own tunnel to the
   forwarder or through the hub member that holds it, and hands the stream to
   the executor:
   - an **executor agent** gets it on a device channel of the tunnel it already
     has open, and attaches the device on its own host before the start frame.
     For USB, it speaks the client half of the USB/IP handshake itself and gives
     `vhci_hcd` one end of an anonymous socketpair through
     `/sys/devices/platform/vhci_hcd.0/attach`. For a segment, it creates a TAP
     fed by the stream.
   - the hub's own **container executor** gets the same attachment, made in
     the hub's process.
5. The device then reaches the sandbox through the usual passthrough: the USB
   device's nodes as devices, and the TAP moved into the sandbox's network
   namespace under the binding's interface name, with its address.
   `CLOOP_FORWARDED_DEVICES` tells the workload what it has
   (`fwd-bench=usb:/dev/bus/usb/003/014,fwd-lab=l2:fwd0`). A segment's interface
   appears a moment after the sandbox starts, so a workload that needs it has
   to wait for the name.

Nothing listens anywhere along the way: no `usbipd` and no TCP port on the
forwarder, the hub or the executor. Only the sandbox the device was given to
can reach it. That sandbox's `/sys/bus/usb/devices` still lists the executor
host's other USB devices, as any container's `/sys` does, but it holds a node
for the forwarded device alone and can open nothing else.

The device is detached (the vhci port freed, the TAP removed) when the run
ends, the binding is revoked or expires, the forwarder is revoked, or the
forwarder or the agent disconnects. A revocation takes effect at once on the
hub member that received it and within one bus poll on the others, and each
member re-checks what it holds every few seconds. A restarted agent removes any
vhci port or TAP its previous process left behind, and touches nothing it did
not record attaching.

**Test** on a forwarder's card probes the device through the hub. It opens a
stream to the forwarder and, for USB, reads the device list the forwarder
exports. It doesn't hand the device to anything.

## How a USB device is carried

The forwarder is the USB/IP server, but it runs no `usbipd` and opens no port
on any interface. It answers a consumer's opening request itself, with either a
device list from sysfs or an import of the one bus id it carries (it refuses
any other). Only for an import does it bind the device to the kernel's
`usbip-host` driver and hand the kernel one end of an anonymous socketpair, by
writing to the device's `usbip_sockfd`. From then on the kernels at both ends
move every USB packet, and the forwarder, the hub and the agent only copy
bytes. A device that is itself imported over USB/IP is never forwarded again.

Requirements: on the on-prem machine, root (to bind the device), the `usbip`
tool and the `usbip-host` module. On the executor, the `vhci_hcd` module and an
agent that may write its `attach` and `detach` files, so either root or a
drop-in that grants that. If the agent runs as root, give its work root to a
dedicated user to keep its sandboxes unprivileged: the agent then hands each
container workload's workspace to that user.

## How a network interface is carried

For a layer-2 forward, the forwarder opens a promiscuous raw socket on the
configured interface and streams the segment's Ethernet frames up the tunnel,
completing checksums the kernel left to offload and restoring VLAN tags the NIC
stripped. Frames from the tunnel go back out onto the wire. The consumer
creates a TAP fed by those frames, and the sandbox's passthrough moves it into
the sandbox's network namespace. The sandbox is then on the on-prem segment at
the link layer: ARP, DHCP, raw Ethernet and everything else a route can't
carry. Moving an interface needs the executor's agent to run as
root, `ip(8)` and `nsenter(1)`, and a runtime other than gVisor or Kata. The
segment is not behind the sandbox's IP firewall, so a binding of a segment
grants access to whatever that segment can reach.

## In a hub cluster

A forwarder's tunnel lives on the hub member it dialled. Every member lists it
from the cluster's shared records (whether it is connected, and through which
member), and forwards the dashboard's probe to the holder. A run dispatched by
another member (the one holding its agent) opens the device's stream through
the holder over the
[peer channel](../architecture/hub-cluster.md#the-peer-channel). A revocation
through any member, or from the CLI, cuts the live session on the holder and
the run's device on every member.

## What a forwarder cannot do

- It can't carry a device it wasn't enrolled for. The device named at
  enrollment decides what it carries, and a USB import of any other bus id is
  refused on the wire.
- It can't run a workload, read a project or reach the filesystem. The
  forwarder has no code path that does any of those things.
- It can't be reached inbound. A revoked credential drops the live session and
  is refused on the next reconnect.
- Its device reaches no project without a binding, and no process other than
  the sandbox of a bound project's run.

## Testing it on real hardware

`tests/forwarder` runs the whole chain on one Linux host as root: a forwarder
on a local USB device, a token-protected test hub (and a two-member cluster), a
second agent, container sandboxes, and a veth pair into a network namespace
standing in for an on-prem segment:

```
CLOOP_FORWARDER_E2E=1 go test ./tests/forwarder -run TestForwardedDevices -v
```

The test picks the USB device by bus id (`CLOOP_FORWARDER_USB_BUSID`, default
`1-1`) as well as by vendor and product. It skips a device that is itself
imported over USB/IP, detaches only what it attached, and unbinds the device
from `usbip-host` afterwards.
