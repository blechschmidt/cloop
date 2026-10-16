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

## How a USB device is carried

The forwarder is the USB/IP *server*, but it runs no `usbipd` and opens no port
on any interface — the whole exposure is the one outbound tunnel. When a
consumer asks for the device, the forwarder binds it to the kernel's
`usbip-host` driver, answers the import request itself (refusing any device but
the one it was configured for), and hands the kernel one end of an anonymous
socketpair by writing to the device's `usbip_sockfd`. From there the kernel
moves every USB packet; the forwarder only copies bytes between its end of the
socketpair and the tunnel.

On the hub, **Expose** opens a loopback endpoint and prints the standard command
to import the device:

```
usbip --tcp-port <port> attach -r 127.0.0.1 -b <busid>
```

Run it on the host that should hold the device — the hub itself, or a cloud
executor host. The device then appears in `usbip port` as if it were plugged in
locally, and the existing per-project device passthrough carries it into a
sandbox.

Requirements on the on-prem machine: root (or `CAP_NET_ADMIN` for the agent),
the `usbip` tool, and the `usbip-host` kernel module. On the consuming host:
`vhci_hcd` and root.

## How a network interface is carried

For a layer-2 forward the forwarder opens a promiscuous raw socket on the
configured interface and streams its Ethernet frames up the tunnel; frames that
arrive from the tunnel are injected back onto the wire. The consumer builds a
TAP interface fed by those frames, which puts the sandbox on the on-prem segment
at the link layer — ARP, DHCP, raw Ethernet and everything else a route cannot
carry. The TAP is created on the executor host and granted to a project with the
existing interface passthrough.

## What a forwarder cannot do

- It cannot carry a device it was not enrolled for: the enrolled device is
  authoritative, and a USB import of any other bus id is refused on the wire.
- It cannot run a workload, read a project, or reach the filesystem. There is no
  code path in the forwarder that does any of those things.
- It cannot be reached inbound. A revoked credential drops the live session and
  is refused on the next reconnect.
