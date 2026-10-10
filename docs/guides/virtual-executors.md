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
| a device or project [firewall rule set](firewall.md) | an agent speaking protocol **v15** |
| a firewall | `nft(8)` on the device, and the agent holding `CAP_NET_ADMIN` and the netlink socket family — which `cloop executor agent install` grants by default |

The hardened service unit `cloop executor agent install` writes grants the agent
no capabilities and no netlink sockets. The installer then adds exactly one
capability and one socket family, in a drop-in beside the unit,
`/etc/systemd/system/cloop-executor.service.d/10-packet-filter.conf`:

```ini
[Service]
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
RestrictAddressFamilies=AF_NETLINK
```

Each line adds to the unit rather than replacing it — systemd merges these
across a unit and its drop-ins — so the effective set is `CAP_NET_ADMIN` and
nothing else, and the address families are the unit's `AF_INET AF_INET6
AF_UNIX` plus `AF_NETLINK`. `NoNewPrivileges` and the rest of the hardening
stay as they are.

**The capability stays with the agent.** systemd hands a capability to a
service that runs as an ordinary user through the *ambient* set, which every
program it starts would inherit — the harness, its shell, git and the hooks git
runs from a workload's repository. So the first thing a cloop process does is
clear its ambient and inheritable sets on every thread (`pkg/caps`), keeping the
capability for itself; the only program it hands it back to is `nft(8)`. A
host-mode workload on the device holds no capability at all
(`grep Cap /proc/self/status` shows `CapPrm`, `CapEff`, `CapInh` and `CapAmb` all
zero), and a sandbox is a container the engine starts, which never sees it.

A device installed before the installer granted this by default — or with
`--packet-filter=false` — **cannot** install a firewall. The panel says so on
the device, with the reason the device gave, under **Firewalled** in its
virtual-executor dialog, and on every virtual executor that has one, and a
dispatch to it is refused rather than started unfiltered. Grant it on the
device, without the enrollment bundle:

```bash
sudo cloop executor agent install --upgrade --packet-filter
```

That writes the drop-in and restarts the agent even when its build is already
current, and restores the previous configuration if the agent does not come
back. A plain `--upgrade` never changes the grant either way;
`--upgrade --packet-filter=false` withdraws it. The agent's startup log says
where it stands: `firewall: nft(8) — CAP_NET_ADMIN held by the agent, never by
its workloads`, or `firewall: unavailable:` and the reason.

An agent that can already drive a rootful container engine holds a stronger
privilege than `CAP_NET_ADMIN` through the engine's socket; the grant matters on
a device whose agent cannot.

## Creating one

The **Settings** tab's **USB devices** section lists the USB hardware every
enrolled device reported; **Expose…** beside one opens that device's dialog. From
the **Executors** tab, press **Virtual** on the device's card. The dialog shows:

- the device's **USB devices**, as it reported them — vendor and product IDs,
  serial, the node under `/dev/bus/usb`, and the node's mode and group when the
  agent can see them. **Refresh** asks the device to re-read its hardware now,
  which is what you want right after plugging something in;
- its existing virtual executors, each with an **Edit** button;
- the form: name, engine, runtime (the device's registered runtimes are
  offered), image, the **network access** — with the firewall's rules under
  **Firewalled** — and the devices.

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

## Network access

A virtual executor's sandboxes are networked in one of three ways, and the
dialog offers them as one choice, in order of reach:

| choice | what a sandbox gets | in the spec |
|---|---|---|
| **No network** (the default) | no interface at all: it cannot clone a repository, reach the git proxy or resolve a name | `"network": "none"`, no `firewall` |
| **Firewalled** | a bridge of the executor's own, filtered on the device: nothing is reachable unless a rule allows it | a `firewall` object, `network` unset |
| **Unfiltered** | the engine's `bridge`, or a network created on the device, with no firewall — on `bridge`, whatever the device can reach, private networks and the cloud metadata service included | `"network": "bridge"` or the network's name, no `firewall` |

The firewall's rules — **Allow the public Internet** among them — belong to
**Firewalled** and to nothing else: the dialog shows them only under that
choice, and saving another choice sends none of them. Rules typed and then left
for another choice stay in the form, out of sight, in case you come back.

## The firewall

Nothing is reachable unless an allow names it:

| field | meaning |
|---|---|
| **Allow the public Internet** | every address outside the block set, over TCP: RFC1918, link-local, the cloud metadata services, CGNAT, loopback and multicast stay dropped |
| **Allowlist** | ranges the sandbox may reach directly over TCP, private ones included — the only thing that reaches into blocked space |
| **Denylist** | ranges the sandbox may never reach, over any protocol, whatever is allowed. Checked before every allow, the resolvers included |
| **Ports** | bounds the two allows above to these TCP ports; empty means every port |
| **DNS resolvers** | opened on UDP and TCP, and the sandbox is told to resolve through them |

Everything else is dropped: UDP reaches only the resolvers, and nothing answers
a ping. Under the rules, the dialog reads them back as one sentence — what
sandboxes can reach, what they never can — and flags two rule sets: one that
allows nothing, which the device applies as no network at all, and one that
opens the Internet with no resolver, under which no host name resolves.

A single address is read as a host (`198.51.100.7` means `/32`). An allow of
`0.0.0.0/0` is refused, because it would waive the metadata service along with
the rest of the block set; use **Allow the public Internet** instead. An allow
of a range that *contains* a cloud metadata service but does not name it — say
`100.64.0.0/10`, which holds Alibaba Cloud's `100.100.100.200` — is refused the
same way, naming the service: add its `/32` or `/128` to the allowlist to reach
it, or to the denylist to keep it closed while allowing the range around it.

The resolvers matter more than they look. A firewall that drops private address
space also drops the resolver the container engine hands a sandbox by default —
on a cloud VM that is usually the provider's resolver in CGNAT or link-local
space — so without resolvers of its own, every hostname fails to resolve. The
dialog pre-fills `1.1.1.1` for a new executor's firewall.

How it is enforced: the device creates a bridge for the virtual executor
(`cloop-sbx-<id>`) and installs an nftables table (`cloop_sbx_<id>`) that filters
traffic arriving from it, **before** any sandbox joins the bridge — so no sandbox
ever runs unfiltered, whatever the OCI runtime. On the device:

```bash
sudo nft list table inet cloop_sbx_vx_abcdefghij
```

A project can narrow its virtual executor's firewall further — with
`capabilities.egress` in `.cloop/sandbox.yaml`, or with a rule set its
maintainers save on its Overview page — and never widen it: `egress: public` on
a virtual executor whose firewall allows only a private range is refused rather
than handed the public Internet.

And the firewall itself must fit inside **the device's rule set**, when an admin
has set one (the device's card → **Firewall**). The dialog shows it read-only at
the top, starts a new firewall from it, and offers no **Unfiltered** network
under it; a save reaching further is refused, naming what is outside. Tightening
the device narrows every virtual executor on it to fit. See
[firewall rules](firewall.md).

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
