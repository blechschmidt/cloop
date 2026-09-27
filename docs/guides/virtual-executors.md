# Virtual executors

A **virtual executor** is a named sub-executor of an enrolled device. It
dispatches through its device's connection, like the device itself, and carries
its own containment:

- the container **engine** and OCI **runtime** (`runc`, `crun`, `runsc`, `kata`…)
  and the **image** its sandboxes start from;
- an **IP firewall** with an allowlist and a denylist, installed on a bridge of
  its own;
- the **host devices** its sandboxes are given, chosen from the device's USB
  inventory or named by path.

Everything else that is per-executor applies to it under its own ID, unchanged:
resource **limits**, the **access** list, and project bindings. So one bench
machine can offer a locked-down sandbox with no network to everyone, and a
sandbox with its hardware security module in it to the three people allowed near
the module — each a separate executor a project is bound to.

## When to use one

| you want | use |
|---|---|
| one containment for everything a device runs | the device's own **Sandbox** panel |
| two or more differently-contained sandboxes on one device | virtual executors |
| a USB device, serial line or other node inside a device's sandbox | a virtual executor |
| an IP allowlist or denylist for a device's sandboxes | a virtual executor |

A virtual executor always runs its payloads in a container. Host mode could
enforce neither its firewall — there is no per-workload network namespace to
filter — nor its device list, since the host already has every device.

## What the device needs

| for | the device needs |
|---|---|
| any virtual executor | a container engine (`docker`, `podman` or `nerdctl`) on the agent's PATH, and an agent speaking protocol v8 |
| a firewall or devices | an agent speaking protocol **v14** — the Executors panel shows the version |
| a firewall | `nft(8)` on the device, and the agent holding `CAP_NET_ADMIN` and the netlink socket family: install it with `cloop executor agent install --packet-filter` |

The hardened service unit `cloop executor agent install` writes grants the agent
no capabilities and no netlink sockets, so by default a device **cannot** install
a firewall. The panel says so on the device and on every virtual executor that
has one, and a dispatch to it is refused rather than started unfiltered.
`--packet-filter` relaxes exactly three directives and nothing else:

```ini
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
```

On a device installed without it, re-run the installer with the flag, or add
those three lines in a drop-in (`/etc/systemd/system/cloop-executor.service.d/`)
and restart the agent. An agent that can already drive a rootful container
engine holds a stronger privilege than this through the engine's socket.

## Creating one

In the **Executors** tab, press **Virtual** on the device's card. The dialog shows:

- the device's **USB devices**, as it reported them — vendor and product IDs,
  serial, the node under `/dev/bus/usb`, and the node's mode and group when the
  agent can see them. **Refresh** asks the device to re-read its hardware now,
  which is what you want right after plugging something in;
- its existing virtual executors, each with an **Edit** button;
- the form: name, engine, runtime (the device's registered runtimes are
  offered), image, network, the firewall and the devices.

The same through the API (`executor.manage`):

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  https://hub.example.com/api/executors/$DEVICE/virtuals -d '{
  "name": "HSM sandbox",
  "spec": {
    "sandbox":  {"mode": "container", "engine": "docker", "image": "ghcr.io/acme/hsm-tools:1"},
    "firewall": {"allow_public_internet": true,
                 "deny_cidrs": ["203.0.113.0/24"],
                 "resolvers": ["1.1.1.1"]},
    "devices":  [{"name": "yubihsm", "group": "plugdev",
                  "usb": {"vendor_id": "1050", "product_id": "0030", "serial": "0031650425"}}]
  }}'
```

`GET /api/executors/<device>/virtuals` lists a device's virtual executors with its
USB inventory (`?refresh=1` re-reads it from the device);
`GET|PUT|DELETE /api/executors/<id>/virtual` reads, replaces or deletes one. Every
change is an `executor.virtual` audit event carrying the configuration before and
after.

Then bind a project to it like to any executor — the **Executor** card on the
project's overview — and set its **Limits** and **Access** from its own card.

## The firewall

Nothing is reachable unless an allow names it:

| field | meaning |
|---|---|
| **Allow the public Internet** | every address outside the block set: RFC1918, link-local and the cloud metadata endpoint, CGNAT, loopback and multicast stay dropped |
| **Allowlist** | ranges the sandbox may reach directly, private ones included — the only thing that reaches into blocked space |
| **Denylist** | ranges the sandbox may never reach, whatever is allowed. Checked before every allow |
| **Ports** | bounds the allows; empty means every port |
| **DNS resolvers** | opened on UDP and TCP, and the sandbox is told to resolve through them |

A single address is read as a host (`198.51.100.7` means `/32`). An allow of
`0.0.0.0/0` is refused, because it would waive the metadata service along with
the rest of the block set; use **Allow the public Internet** instead.

The resolvers matter more than they look. A firewall that drops private address
space also drops the resolver the container engine hands a sandbox by default —
on a cloud VM that is usually the provider's resolver in CGNAT or link-local
space — so without resolvers of its own, every hostname fails to resolve. The
panel pre-fills `1.1.1.1` when you turn the firewall on.

How it is enforced: the device creates a bridge for the virtual executor
(`cloop-sbx-<id>`) and installs an nftables table (`cloop_sbx_<id>`) that filters
traffic arriving from it, **before** any sandbox joins the bridge — so no sandbox
ever runs unfiltered, whatever the OCI runtime. On the device:

```bash
sudo nft list table inet cloop_sbx_vx_abcdefghij
```

A project can narrow its virtual executor's firewall further with
`capabilities.egress` in `.cloop/sandbox.yaml`, and never widen it: `egress:
public` on a virtual executor whose firewall allows only a private range is
refused rather than handed the public Internet.

## Devices

A USB device is selected by **identity** — vendor, product and, when there are
two of a kind, serial or port — and resolved against the device's live sysfs at
every dispatch. The node under `/dev/bus/usb` is an enumeration counter that
changes whenever the device is unplugged or reattached, so storing it would name
whatever enumerated there next. An unplugged or ambiguous device fails the start,
naming it.

The sandbox receives the device's usbfs node at the same path (so libusb finds
it through the sandbox's read-only `/sys`) and every tty or hidraw node its
interfaces created. **Other device nodes** passes a node that is not USB, by path;
the same rules as a device grant apply, so `/dev/mem` and whole disks are refused.

### Permissions

Sandboxes run as an unprivileged user — the owner of the project directory — so
the node's own mode decides what they can do with it. A USB node is `root:root
0664` on most distributions: readable, not writable, and a userspace driver needs
to write. Give the device a group with a udev rule, and name that group in the
virtual executor:

```
# /etc/udev/rules.d/70-yubihsm.rules on the device
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0030", GROUP="plugdev", MODE="0664"
```

```bash
sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=usb
```

The sandbox user is then given that group (`--group-add`). Root's group is
refused: on a rootful engine GID 0 inside the sandbox is GID 0 on the host for
every file a bind mount exposes. When the agent can see `/dev` it infers the
group from the node itself; under the hardened unit (`PrivateDevices=yes`) it
cannot, which is why the group is a field.

### Runtimes

Devices are refused under `runsc` (gVisor) and Kata. Measured on a gVisor host:
the node is created in the sandbox and every open of it fails with `ENXIO`, and
`/sys/bus/usb` does not exist for libusb to enumerate; Kata can only hand a guest
a device through VFIO. Put hardware on a virtual executor with the engine's
default runtime (`runc` or `crun`), and untrusted work on a separate one with
`runsc`.

## Worked example: a YubiHSM on an edge device

The sgx executor host has a YubiHSM 2 attached over USB/IP. With a udev rule
giving it the `plugdev` group, the panel lists it as `Yubico YubiHSM
(1050:0030) serial 0031650425` at `/dev/bus/usb/001/002`. A virtual executor on
sgx — docker, `runc`, an image with `yubihsm-shell`, the public Internet with
`1.0.0.0/24` denied, resolver `1.1.1.1`, and the YubiHSM with group `plugdev` —
ran a task whose transcript, from inside the sandbox, reads:

```
$ id
uid=995 gid=985 groups=985,46(plugdev)
$ ls -l /dev/bus/usb/001/
crw-rw-r-- 1 root plugdev 189, 1 Sep 27 08:16 002
$ head -c 18 /dev/bus/usb/001/002 | od -An -tx1
 12 01 00 02 00 00 00 40 50 10 30 00 40 02 01 02
 03 01
$ timeout 30 yubihsm-shell --connector=yhusb:// -a get-device-info
Version number:		2.4.0
Serial number:		31650425
Log used:		0/62
…
$ curl -sS -m 10 -o /dev/null -w 'github %{http_code}' https://api.github.com/
github 200
$ curl -sS -m 6 -o /dev/null https://1.0.0.1/            # denylist
curl: (28) Connection timed out after 6000 milliseconds
$ curl -sS -m 6 -o /dev/null http://10.0.0.1/            # private space
curl: (28) Connection timed out after 6001 milliseconds
$ curl -sS -m 6 -o /dev/null http://100.100.100.200/     # the cloud metadata service
curl: (28) Connection timed out after 6001 milliseconds
```

— the sandbox holds exactly one device node, talks to the HSM over libusb as an
unprivileged user, and reaches the Internet but not the denied range, the
private network or the metadata service. The same device's second virtual
executor, on `runsc`, is refused the YubiHSM at creation and runs untrusted work
under the same firewall on a bridge of its own.
