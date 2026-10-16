# Device forwarders

A **device forwarder** bridges one piece of on-prem hardware — a USB device or
a layer-2 network interface — to a cloop hub over a single authenticated,
outbound connection, and does nothing else. It is a minimal binary (`cloop
forward`, or the standalone `cmd/cloop-forward`): it runs no harness, executes
no task, reads no project. Its only job is to carry that one device.

## Why it exists

The trust model is "the agent runs in an isolated environment in the cloud with
limited access to on-prem hardware." A machine wired to hardware — a bench with
a hardware security module, a board under test on a lab VLAN, a radio on its own
segment — is useful as a remote executor only to the extent that a cloud sandbox
can reach what the machine is plugged into. Running the full executor agent on
that machine would give the cloud far more than the hardware: a harness, the
filesystem, the ability to run arbitrary work. A forwarder gives it exactly one
device and nothing more.

Because the forwarder dials **out**, the on-prem machine needs no inbound
firewall rule and may sit behind NAT, exactly like the executor agent. It
authenticates with its own enrollment token and long-lived credential, stored
only as a SHA-256 hash on the hub; a forwarder credential can never authenticate
as something that runs work.

## Enrolling a forwarder

From the dashboard: **Executors → Device forwarders → + Enroll forwarder**.
Choose a USB device (by `vendor:product[:serial]`) or an interface name, and the
hub prints a single-use command to run on the on-prem machine.

From the CLI on the hub:

```
cloop forward enroll --name bench-usb --usb 1050:0030
cloop forward enroll --name lab-net  --interface eth1
```

Either prints a `cloop forward --bundle …` command. Run it on the on-prem
machine:

```
cloop forward --bundle cloopfwd1.…
```

The bundle carries the hub URL, the single-use token and the hub's certificate
pin together, so the forwarder proves who it is and the pin proves the hub is
the hub rather than whatever answers that hostname. The token is redeemed once
for a long-lived credential saved `0600` at `~/.cloop/forwarder.json`; after
that, plain `cloop forward` reconnects on its own.

List and revoke:

```
cloop forward list
cloop forward revoke <id>
```

## Binding a device to a project

A connected forwarder reaches nothing until a **binding** says which project's
runs get its device. Binding takes `executor.manage`, as enrolling does; it
lasts a TTL (24 hours unless you say otherwise, 90 days at most); and it is
audited as `forwarder.bind` and `forwarder.unbind`. Three places make one:

- **Executors → Device forwarders**: each forwarder's card lists its bindings
  and has **Bind…** (choose the project, optionally a virtual executor, how long
  it lasts, and for a network segment the interface's name and address inside
  the sandbox) and **Unbind**.
- **The project's Overview → Forwarded devices**: what is bound to this
  project, with **Bind** for an administrator — and **Request** for a
  maintainer, which files a request through the same flow as a secret grant
  request: it appears in the approvals inbox of everyone who may decide it, and
  an administrator other than the requester approves it, which mints the
  binding (narrowed if they choose).
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

When a bound project's run is dispatched, the hub:

1. reads the bindings in force for the project — none, and nothing below
   happens at all;
2. refuses the run, naming the forwarder, if a bound forwarder has no live
   session anywhere in the hub cluster;
3. refuses the run if its executor cannot give the device to a sandbox: a
   host-process run, an agent in host mode, a gVisor or Kata sandbox, an agent
   older than protocol v22 (with the upgrade path), or an agent that reports it
   cannot attach the kind (with its reason);
4. opens a stream to the forwarder's device — on its own tunnel to the
   forwarder, or through the hub member that holds it — and hands it to the
   executor:
   - an **executor agent** gets it on a device channel of the tunnel it already
     holds open, and attaches the device on its own host *before* the start
     frame: for USB it speaks the client half of the USB/IP handshake itself
     and gives `vhci_hcd` one end of an anonymous socketpair through
     `/sys/devices/platform/vhci_hcd.0/attach`; for a segment it creates a TAP
     fed by the stream;
   - the hub's own **container executor** gets the same attachment made in the
     hub's process.
5. The device then reaches the sandbox through the ordinary passthrough: the
   USB device's nodes as devices, the TAP moved into the sandbox's network
   namespace under the binding's interface name, with its address.
   `CLOOP_FORWARDED_DEVICES` tells the workload what it has
   (`fwd-bench=usb:/dev/bus/usb/003/014,fwd-lab=l2:fwd0`); a segment's interface
   arrives a moment after the sandbox starts, so a workload that needs it waits
   for the name.

Nothing listens anywhere along the way: no `usbipd`, no TCP port, on the
forwarder, the hub or the executor. The only process that can reach the device
is the sandbox it was given to. That sandbox's `/sys/bus/usb/devices` still
lists the executor host's other USB devices, as any container's `/sys` does,
but it holds a node for the forwarded device alone and can open nothing else.

The device is detached — the vhci port freed, the TAP removed — when the run
ends, when the binding is revoked or lapses, when the forwarder is revoked, and
when either the forwarder or the agent disconnects. A revocation takes effect at
once on the hub member that took it and within a bus poll on the others; each
member also re-checks what it holds every few seconds. A restarted agent sweeps
any vhci port or TAP its previous process left behind, and touches nothing it
did not record attaching.

**Test** on a forwarder's card probes the device through the hub: it opens a
stream to the forwarder and, for USB, reads the device list the forwarder
exports. It hands the device to nothing.

## How a USB device is carried

The forwarder is the USB/IP *server*, but it runs no `usbipd` and opens no port
on any interface. When a consumer opens the device, the forwarder answers the
opening request itself — a device list from sysfs, or an import of the one bus
id it carries, refusing any other — and only for an import binds the device to
the kernel's `usbip-host` driver and hands the kernel one end of an anonymous
socketpair by writing to the device's `usbip_sockfd`. From there the kernels at
both ends move every USB packet; the forwarder, the hub and the agent only copy
bytes. A device that is itself imported over USB/IP is never forwarded again.

Requirements: on the on-prem machine, root (to bind the device), the `usbip`
tool and the `usbip-host` module. On the executor, the `vhci_hcd` module and an
agent that may write its `attach` and `detach` files — root, or a drop-in that
grants it. An agent that runs as root keeps its sandboxes unprivileged: give its
work root to a dedicated user, and it hands each container workload's workspace
to that user.

## How a network interface is carried

For a layer-2 forward the forwarder opens a promiscuous raw socket on the
configured interface and streams the segment's Ethernet frames up the tunnel,
completing checksums the kernel left to offload and restoring VLAN tags the NIC
stripped; frames from the tunnel are injected back onto the wire. The consumer
creates a TAP fed by those frames and the sandbox's passthrough moves it into
the sandbox's network namespace, which puts the sandbox on the on-prem segment
at the link layer — ARP, DHCP, raw Ethernet and everything else a route cannot
carry. Moving an interface needs the executor's agent to run as root, `ip(8)`
and `nsenter(1)`, and a runtime other than gVisor or Kata. The segment is not
behind the sandbox's IP firewall: a binding of a segment grants whatever that
segment can reach.

## In a hub cluster

A forwarder's tunnel lives on the hub member it dialled. Every member lists it
from the cluster's shared records — connected, and through which member — and
the dashboard's probe is forwarded to the holder. A run dispatched by another
member (the one holding its agent) opens the device's stream through the holder
over the [peer channel](../architecture/hub-cluster.md#the-peer-channel). A
revocation through any member, or from the CLI, cuts the live session on the
holder and the run's device on every member.

## What a forwarder cannot do

- It cannot carry a device it was not enrolled for: the enrolled device is
  authoritative, and a USB import of any other bus id is refused on the wire.
- It cannot run a workload, read a project, or reach the filesystem. There is no
  code path in the forwarder that does any of those things.
- It cannot be reached inbound. A revoked credential drops the live session and
  is refused on the next reconnect.
- Its device reaches no project without a binding, and no process but the
  sandbox of a bound project's run.

## Testing it on real hardware

`tests/forwarder` drives the whole chain on one Linux host as root — a
forwarder on a local USB device, a token-protected test hub (and a two-member
cluster), a second agent and container sandboxes — and a veth pair into a
network namespace standing in for an on-prem segment:

```
CLOOP_FORWARDER_E2E=1 go test ./tests/forwarder -run TestForwardedDevices -v
```

It names the USB device by bus id (`CLOOP_FORWARDER_USB_BUSID`, default `1-1`)
as well as by vendor and product, skips a device that is itself imported over
USB/IP, detaches only what it attached, and unbinds the device from
`usbip-host` afterwards.
