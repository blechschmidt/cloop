# Virtual executors

A **virtual executor** is a named sub-executor of an enrolled device. Its runs go
through the device's connection, like the device's own, but it has its own
containment:

- the container **engine** and OCI **runtime** (`runc`, `crun`, `runsc`, `kata`…)
  and the **image** its sandboxes start from;
- an **IP firewall** with an allowlist and a denylist, installed on a bridge of
  its own;
- the **host devices** its sandboxes are given, chosen from the device's USB
  inventory or named by path.

Other per-executor settings apply to it under its own ID: resource **limits**,
the **access** list and project bindings. So one bench machine can offer
everyone a locked-down sandbox with no network, and offer the three people
allowed near its hardware security module a sandbox with the module in it, each
as a separate executor that projects bind to.

## When to use one

| you want | use |
|---|---|
| one containment for everything a device runs | the device's own **Sandbox** panel |
| two or more differently-contained sandboxes on one device | virtual executors |
| a USB device, serial line or other node inside a device's sandbox | a virtual executor |
| an IP allowlist or denylist for a device's sandboxes | a virtual executor |

A virtual executor always runs its payloads in a container. Host mode could not
enforce its firewall, because there is no per-workload network namespace to
filter, or its device list, because the host already has every device.

## What the device needs

| for | the device needs |
|---|---|
| any virtual executor | a container engine (`docker`, `podman` or `nerdctl`) on the agent's PATH, and an agent speaking protocol v8 |
| a firewall or devices | an agent speaking protocol **v14** (the Executors panel shows the version) |
| a device or project [firewall rule set](firewall.md) | an agent speaking protocol **v15** |
| a firewall | `nft(8)` on the device, and the agent holding `CAP_NET_ADMIN` and the netlink socket family, which `cloop executor agent install` grants by default |

The hardened service unit that `cloop executor agent install` writes gives the
agent no capabilities and no netlink sockets. The installer then adds one
capability and one socket family in a drop-in next to the unit,
`/etc/systemd/system/cloop-executor.service.d/10-packet-filter.conf`:

```ini
[Service]
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
RestrictAddressFamilies=AF_NETLINK
```

systemd merges these settings across a unit and its drop-ins, so each line adds
to the unit. The effective capability set is `CAP_NET_ADMIN` and nothing else,
and the address families are the unit's `AF_INET AF_INET6
AF_UNIX` plus `AF_NETLINK`. `NoNewPrivileges` and the rest of the hardening
stay as they are.

**The capability stays with the agent.** systemd gives a capability to a service
that runs as an ordinary user through the *ambient* set, which every program the
service starts would inherit: the harness, its shell, git, and the hooks git
runs from a workload's repository. So the first thing a cloop process does is
clear its ambient and inheritable sets on every thread (`pkg/caps`), keeping the
capability for itself. The only program it passes the capability on to is
`nft(8)`. A host-mode workload on the device holds no capabilities at all
(`grep Cap /proc/self/status` shows `CapPrm`, `CapEff`, `CapInh` and `CapAmb` all
zero), and a sandbox is a container the engine starts, which never sees the
capability.

A device installed before the installer granted this by default, or installed
with `--packet-filter=false`, can't install a firewall. The panel says so on the
device (with the reason the device gave), under **Firewalled** in its
virtual-executor dialog, and on every virtual executor that has a firewall, and
a run sent to one is refused instead of starting unfiltered. To grant it, run
this on the device (no enrollment bundle needed):

```bash
sudo cloop executor agent install --upgrade --packet-filter
```

This writes the drop-in and restarts the agent even if its build is already
current, and restores the previous configuration if the agent doesn't come
back. A plain `--upgrade` leaves the grant as it is, and
`--upgrade --packet-filter=false` removes it. The agent's startup log shows the
state: `firewall: nft(8) — CAP_NET_ADMIN held by the agent, never by
its workloads`, or `firewall: unavailable:` and the reason.

An agent that can already use a rootful container engine has a stronger
privilege than `CAP_NET_ADMIN` through the engine's socket. The grant matters on
devices where the agent can't.

## Creating one

The **USB devices** section of the **Settings** tab lists the USB hardware every
enrolled device has reported, and **Expose…** next to an entry opens that
device's dialog. You can also press **Virtual** on the device's card in the
**Executors** tab. The dialog shows:

- the device's **USB devices** as it reported them: vendor and product IDs,
  serial number, the node under `/dev/bus/usb`, and the node's mode and group
  when the agent can see them. **Refresh** asks the device to read its hardware
  again, which you want right after plugging something in;
- its existing virtual executors, each with an **Edit** button;
- the form: name, engine, runtime (chosen from the device's registered
  runtimes), image, **network access** (with the firewall's rules under
  **Firewalled**) and devices.

The same through the API (needs `executor.manage`):

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
USB inventory (`?refresh=1` reads the inventory from the device again), and
`GET|PUT|DELETE /api/executors/<id>/virtual` reads, replaces or deletes one. Every
change is an `executor.virtual` audit event with the configuration before and
after.

Then bind a project to it as to any executor, with the **Executor** card on the
project's overview, and set its **Limits** and **Access** on its own card.

### The image, and the project's harness

A virtual executor's sandboxes run the image it names. If it names none, they
run the device's default, the published `ghcr.io/blechschmidt/cloop-harness`,
which contains `claude`, `cloop` and `git`. A project on the `copilot` provider
needs the `copilot` CLI in the image: use
`ghcr.io/blechschmidt/cloop-harness-copilot`, which is the same image with the
GitHub Copilot CLI added, or an image of your own built on it
(`FROM ghcr.io/blechschmidt/cloop-harness-copilot:latest`). Because the
container brings its own harness, the device never installs one on its host for
a virtual executor's run.

Both published images list the harnesses they contain in an
`org.cloop.harnesses` label. The device's container driver reads the label
before it starts a sandbox. A `copilot` project bound to a virtual executor
whose image doesn't list `copilot` is refused before anything runs (409
`sandbox_image_lacks_harness`), with an error that names the copilot image, so
the run doesn't fail inside the sandbox after it has received its credentials.
Agents from before this check don't read the label, and an image without the
label is not refused. [The published
images](../reference/sandbox.md#the-published-images-and-what-an-image-carries)
lists what each image contains and why the copilot one is separate.

## Network access

A virtual executor's sandboxes get one of three kinds of network access. The
dialog offers them as a single choice, from least to most reach:

| choice | what a sandbox gets | in the spec |
|---|---|---|
| **No network** (the default) | no interface at all: it can't clone a repository, reach the git proxy or resolve a name | `"network": "none"`, no `firewall` |
| **Firewalled** | a bridge of the executor's own, filtered on the device. Nothing is reachable unless a rule allows it | a `firewall` object, `network` unset |
| **Unfiltered** | the engine's `bridge`, or a network created on the device, with no firewall. On `bridge` that means whatever the device can reach, including private networks and the cloud metadata service | `"network": "bridge"` or the network's name, no `firewall` |

The firewall's rules, including **Allow the public Internet**, apply only to
**Firewalled**. The dialog shows them only under that choice, and saving another
choice sends none of them. If you type rules and then pick another choice, the
rules stay in the form, hidden, in case you switch back.

## The firewall

Nothing is reachable unless an allow names it:

| field | meaning |
|---|---|
| **Allow the public Internet** | every address outside the block set, over TCP. RFC1918, link-local, the cloud metadata services, CGNAT, loopback and multicast stay dropped |
| **Allowlist** | ranges the sandbox may reach directly over TCP, including private ones. This is the only way into blocked space |
| **Denylist** | ranges the sandbox may never reach, over any protocol, whatever is allowed. Checked before every allow, including the resolvers |
| **Ports** | limits the two allows above to these TCP ports. Empty means every port |
| **DNS resolvers** | opened on UDP and TCP, and the sandbox is set up to resolve names through them |

Everything else is dropped: UDP reaches only the resolvers, and nothing answers
a ping. Below the rules, the dialog sums them up in one sentence (what sandboxes
can reach, and what they never can) and warns about two kinds of rule set: one
that allows nothing, which the device applies as no network at all, and one that
opens the Internet without a resolver, so that no host name resolves.

A single address is read as a host (`198.51.100.7` means `/32`). An allow of
`0.0.0.0/0` is refused, because it would open the metadata service along with
the rest of the block set. Use **Allow the public Internet** instead. An allow
of a range that contains a cloud metadata service without naming it, such as
`100.64.0.0/10`, which contains Alibaba Cloud's `100.100.100.200`, is refused
in the same way, and the error names the service. Add the service's `/32` or
`/128` to the allowlist to reach it, or to the denylist to keep it closed while
allowing the range around it.

Don't forget the resolvers. A firewall that drops private address space also
drops the resolver the container engine gives a sandbox by default (on a cloud
VM, usually the provider's resolver in CGNAT or link-local space), so without
resolvers of its own, no hostname resolves. The dialog fills in `1.1.1.1` for a
new executor's firewall.

To enforce the rules, the device creates a bridge for the virtual executor
(`cloop-sbx-<id>`) and installs an nftables table (`cloop_sbx_<id>`) that filters
traffic arriving from it. It does this before any sandbox joins the bridge, so
no sandbox runs unfiltered, whatever the OCI runtime. On the device:

```bash
sudo nft list table inet cloop_sbx_vx_abcdefghij
```

A project can narrow its virtual executor's firewall further, with
`capabilities.egress` in `.cloop/sandbox.yaml` or with a rule set its
maintainers save on its Overview page, but it can't widen it. `egress: public`
on a virtual executor whose firewall allows only a private range is refused; the
project doesn't get the public Internet.

The firewall itself must fit inside the device's rule set, if an admin has set
one (the device's card → **Firewall**). The dialog shows the device's rules
read-only at the top, starts a new firewall from them, and doesn't offer
**Unfiltered** under them. A save that reaches further is refused, and the error
says what lies outside. Tightening the device narrows every virtual executor on
it to fit. See [firewall rules](firewall.md).

## Devices

A USB device is selected by identity (vendor, product and, when there are two of
a kind, serial or port) and looked up in the device's live sysfs at every
dispatch. The node under `/dev/bus/usb` is an enumeration counter that changes
whenever the device is unplugged or reattached, so a stored node would point at
whatever was enumerated there next. If a device is unplugged or ambiguous, the
run fails to start and the error names the device.

The sandbox gets the device's usbfs node at the same path (so libusb finds it
through the sandbox's read-only `/sys`) and every tty or hidraw node its
interfaces created. **Other device nodes** passes a node that isn't USB, by path.
The same rules as for a device grant apply, so `/dev/mem` and whole disks are
refused.

### Permissions

Sandboxes run as an unprivileged user, the owner of the project directory, so
the node's own mode decides what they can do with it. On most distributions a
USB node is `root:root 0664`: readable but not writable, and a userspace driver
needs to write. Give the device a group with a udev rule, and name that group in
the virtual executor:

```
# /etc/udev/rules.d/70-yubihsm.rules on the device
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0030", GROUP="plugdev", MODE="0664"
```

```bash
sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=usb
```

The sandbox user is then added to that group (`--group-add`). Root's group is
refused, because on a rootful engine GID 0 inside the sandbox is GID 0 on the
host for every file a bind mount exposes. When the agent can see `/dev` it works
out the group from the node itself. Under the hardened unit
(`PrivateDevices=yes`) it can't, which is why the group is a field.

### Runtimes

Devices are refused under `runsc` (gVisor) and Kata. On a gVisor host the node
is created in the sandbox, but every open of it fails with `ENXIO`, and
`/sys/bus/usb` doesn't exist for libusb to enumerate. Kata can only give a guest
a device through VFIO. Put hardware on a virtual executor with the engine's
default runtime (`runc` or `crun`), and untrusted work on a separate one with
`runsc`.

A virtual executor's runtime is verified like any executor's. When it is created
or edited, when its device connects, and once a day, the hub asks the device to
run `cloop isolation-probe` in a sandbox under the virtual executor's own engine
and runtime. The agent binds its own binary in read-only, so the image can't
answer for it. The hub then compares what the kernel serving that sandbox
reported with the device's own kernel. The dialog shows the result next to each
virtual executor, with a **Re-probe** button:

- `claims runsc, verified: a userspace kernel (gVisor)`: gVisor's Sentry answered;
- `claims kata, runs on the host kernel`: the device's `kata` is an alias for
  runc, and a project whose `.cloop/sandbox.yaml` requires kernel isolation or
  virtualization is refused on this virtual executor, with the evidence in the
  error;
- `claims kata, not verified: the probe could not run`: hover over it to see
  why. An agent older than protocol v26 can't be asked, and the card names the
  upgrade it needs.

Changing a virtual executor's engine discards what was verified under the old
one, because the same runtime name can be a different runtime under another
engine.

## Worked example: a YubiHSM on an edge device

The sgx executor host has a YubiHSM 2 attached over USB/IP. With a udev rule
giving it the `plugdev` group, the panel lists it as `Yubico YubiHSM
(1050:0030) serial 0031650425` at `/dev/bus/usb/001/002`. A virtual executor on
sgx with docker, `runc`, an image with `yubihsm-shell`, the public Internet with
`1.0.0.0/24` denied, resolver `1.1.1.1`, and the YubiHSM with group `plugdev`
ran a task. Its transcript, from inside the sandbox, reads:

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
```

The sandbox holds one device node, talks to the HSM over libusb as an
unprivileged user, and reaches the Internet but not the denied range, the
private network or the metadata service. The same device's second virtual
executor, on `runsc`, was refused the YubiHSM when it was created, and runs
untrusted work under the same firewall on a bridge of its own.

A connection the firewall denies fails at once. TCP is answered with a reset and
everything else with an ICMP "administratively prohibited", so the workload sees
"Connection refused" instead of waiting for a timeout. A virtual executor on sgx
with the public Internet on 443, resolver `1.1.1.1` and `1.0.0.1/32` denied ran
a probe whose output reads

```
RESULT 1.1.1.1:443 open
RESULT 1.0.0.1:443 blocked (Connection refused after 2 ms)
RESULT 8.8.8.8:80 blocked (Connection refused after 2 ms)
```

and the run's history says which rule refused each:

```
blocked 1.0.0.1:443/tcp, in virtual executor vx-wj7bbgym43's deny list (1.0.0.1/32)
blocked 8.8.8.8:80/tcp, port 80 is not one virtual executor vx-wj7bbgym43's allow list opens (443)
```

The task's details show the same under **Network**, and the project's firewall
card lists them under **Recently blocked** (see
[diagnosing a blocked connection](firewall.md#diagnosing-a-blocked-connection)).
**Drop denied connections silently** in the dialog keeps the old behaviour: the
same connection attempt then waits for its timeout (8,001 ms for the probe
above), and is still recorded.
