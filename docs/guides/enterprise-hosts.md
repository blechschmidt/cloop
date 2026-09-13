# Critical hosts as cloop executors

You have a few high-performance machines — a build box with 128 cores, a bench
with instruments on serial lines, a node with GPUs — and you want cloop to run
agent tasks on them without those tasks being able to reach the rest of your
estate. This page is the configuration for that, end to end.

Four capabilities, four sections:

1. [Per-project repository access](#1-per-project-repository-access) — give one
   project one or more internal git repositories, and nothing else.
2. [Per-project firewall rules](#2-per-project-firewall-rules) — let a project
   out to the Internet while dropping every non-public address.
3. [Per-project sandbox with gVisor](#3-per-project-sandbox-with-gvisor) — a
   confined environment whose syscalls never reach the host kernel, with a bind
   mount as its only view of the filesystem.
4. [Hardware and network devices](#4-hardware-and-network-devices) — pass a
   serial port, a GPU or a TUN device into that sandbox.

## The rule that shapes all four

cloop splits every one of these between two files, and which file a setting
lives in is not a matter of taste:

| | who writes it | what it may do |
|---|---|---|
| **`.cloop/config.yaml`** on the hub | an operator, out of band | grant reach |
| **`.cloop/sandbox.yaml`** in the repo | anyone who can open a pull request | give reach up |

`.cloop/sandbox.yaml` is committed to the project's repository. On a hub the
person who merges a pull request is not the person whose infrastructure runs it,
so that file is treated as untrusted input: it can make a run **more** confined
than your default and never less. There is no key in it that names an address
range, a host path, or a device path.

Everything that widens reach is a **grant** — issued by a human with the
`secret.grant` permission, scoped to one project, with a TTL and an audit row.
The repo may then *select* from what it holds.

If you remember one thing: **grants add, sandbox.yaml subtracts.**

## Topology first

Sections 3 and 4 need the container executor to be running **on the machine
that has the hardware**, because a device path and a bind mount are statements
about one machine's filesystem. That constrains your topology, and it is worth
settling before you configure anything:

| you want | run | gVisor? | devices? | local repos? |
|---|---|---|---|---|
| sandboxes on the hub's own host | `executors.container` | yes | yes | yes |
| sandboxes on **another** host | a hub on that host | yes | yes | yes |
| sandboxes across a cluster | `executors.kubernetes` | yes (RuntimeClass) | no | no |
| work on a NAT'd edge device | `cloop executor agent` | no | no | no |

The remote agent (`cloop executor agent`) is for reaching devices behind NAT,
and it runs each workload as a plain process in its own namespaces — it has no
sandbox to put a device *into*. A grant naming `/dev/ttyUSB0` on the hub also
says nothing about `/dev/ttyUSB0` on a machine in another building. Both facts
are why it reports `SupportsDevices: false`, and why cloop refuses the placement
instead of exposing whatever that machine happens to have at the same path.

For "critical hosts with hardware", the shape that works is **a hub per site**,
each with a container executor on the machine it manages. Projects are bound to
executors explicitly, so a developer picks the site by picking the executor.

Every refusal below is a placement refusal that names the constraint. That is
deliberate: a sandbox spec quietly ignored is worse than one rejected, because
the task then runs in an environment nobody described.

## Before you start

Every `cloop secret` command on this page seals or opens a payload, so the hub's
master key has to be in the environment:

```bash
export CLOOP_SECRET_KEY=…   # from the hub's hub.env
```

Without it the first `mint` stops with `CLOOP_SECRET_KEY is not set`. It belongs
in `hub.env` at mode `0600` and never in a repository — see
[installation](../getting-started/installation.md) for generating it and the
[runbook](../operations/runbook.md) for backup and rotation. Losing it loses
every stored secret, grants included.

## 1. Per-project repository access

Two kinds, depending on where the repositories live.

### Repositories checked out on the host

The hub host holds the trees; a project gets a bind mount of some of them.

Store the inventory once — the **root** directory that holds the checkouts:

```bash
cloop secret mint host-src --kind local_repo --value /srv/git
```

Then grant slices of it, one grant per project:

```bash
# the api team's project sees two checkouts, read-only
cloop secret grant host-src \
  --to project:/srv/projects/api \
  --repos api-service,shared-protos \
  --ttl 168h

# the platform project sees every repo whose name starts with infra-, and may commit
cloop secret grant host-src \
  --to project:/srv/projects/platform \
  --repos 'infra-*' \
  --writable \
  --ttl 168h
```

Inside the sandbox they appear under `/repos`:

```
/repos/api-service      (read-only)
/repos/shared-protos    (read-only)
```

with `CLOOP_LOCAL_REPOS=api-service,shared-protos`,
`CLOOP_LOCAL_REPO_ROOT=/repos`, and one `CLOOP_LOCAL_REPO_<NAME>` per
repository.

Read-only is the default and it is enforced by the bind mount, not by
convention — a runaway harness cannot rewrite the history of a checkout that
exists nowhere else. `--writable` is a decision someone makes.

Two things worth knowing:

- **Symlinks cannot escape the root.** Every candidate path is resolved with
  `EvalSymlinks` and re-checked against the resolved root, so a link planted
  inside `/srv/git` by a dependency's postinstall script cannot redirect a bind
  to `/`.
- **Only direct children are considered.** A root of `/srv/git` will not match
  `/srv/git/.cache/some-dep/vendor/x`.

### Repositories on an internal git server

Grant a PAT constrained to the repositories it may reach:

```bash
cloop secret mint gh-internal --kind github_pat --file ./pat.txt
cloop secret grant gh-internal \
  --to project:/srv/projects/api \
  --repos 'acme-internal/api-*' \
  --permissions contents:read \
  --ttl 24h
```

The token is not exported as `GITHUB_TOKEN`. cloop installs a git credential
helper that releases it only for paths matching the allowlist, so a harness that
tries to clone an unlisted repository gets an authentication failure rather than
a checkout. See [the secrets guide](secrets.md) for the full mechanism, and
[the git interception proxy](../git-interception-proxy.md) for restricting which
branches a sandbox may push to.

## 2. Per-project firewall rules

"Let the task reach the Internet, and nothing on our network." Two layers, and
you want both.

### The host-wide default

Enable the IP-layer egress filter on the executor. This needs `nft(8)` and
`CAP_NET_ADMIN` on the host:

```yaml
# .cloop/config.yaml on the hub
executors:
  container:
    enabled: true
    image: ghcr.io/acme/cloop-harness:2024-11
    # Required alongside a filter. The default is network: none, and the
    # driver refuses that combination outright — "a workload with no
    # interfaces has nothing to filter".
    network: bridge
    egress_filter:
      enabled: true
      allow_public_internet: true
      allow_ports: [80, 443, 22]
      resolvers: ["9.9.9.9:53"]
```

`allow_public_internet: true` allows everything **outside** the hard-block set
and drops everything inside it. The block set is not configurable, and it is the
answer to "blacklist non-public IP addresses":

| dropped | why |
|---|---|
| `169.254.169.254/32` | cloud metadata service — hands out instance credentials |
| `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` | RFC1918 / ULA private space |
| `100.64/10` | carrier-grade NAT |
| `169.254/16`, `fe80::/10` | link-local |
| `127/8`, `::1/128` | loopback beyond the sandbox's own |
| `224/4`, `ff00::/8` | multicast |
| `64:ff9b::/96`, `2002::/16`, … | IPv6 transition prefixes a packet filter cannot unwrap |

Rules are installed on the sandbox bridge **before** any container can join it,
so there is no window in which a workload is up and unfiltered.

Render what a configuration would install, without touching the host. The same
compiler the driver uses, so this is the ruleset, not an approximation of it:

```console
$ cloop egress firewall --internet --ports 443 --resolver 9.9.9.9:53
IP-layer egress filter  mode filtered, 25 rules, from flags

warning: every public address is reachable on port 443; only the private,
loopback, link-local, CGNAT and metadata ranges are filtered

  allow  127.0.0.0/8                any          sandbox-local loopback [namespace-local]
  allow  9.9.9.9/32             udp 53           DNS resolver
  allow  9.9.9.9/32             tcp 53           DNS resolver (truncated answers retry over TCP)
  drop   169.254.169.254/32         any          cloud metadata service (169.254.169.254)
  drop   127.0.0.0/8                any          loopback
  drop   169.254.0.0/16             any          link-local
  drop   10.0.0.0/8                 any          private (RFC1918/ULA)
  drop   172.16.0.0/12              any          private (RFC1918/ULA)
  drop   192.168.0.0/16             any          private (RFC1918/ULA)
  drop   100.64.0.0/10              any          carrier-grade NAT (RFC6598)
  ...
  allow  0.0.0.0/0              tcp 443          public Internet
  drop   0.0.0.0/0                  any          default deny
```

`--check` answers the question directly for one address, which is the form worth
putting in a CI job:

```console
$ cloop egress firewall --internet --ports 443 --resolver 9.9.9.9:53 --check 93.184.216.34:443
ALLOW 93.184.216.34 93.184.216.34:443/tcp — public Internet

$ cloop egress firewall --internet --ports 443 --resolver 9.9.9.9:53 --check 10.4.5.6:443
DROP  10.4.5.6 10.4.5.6:443/tcp — private (RFC1918/ULA)
```

`--format nft` and `--format networkpolicy` emit the nft script and the
Kubernetes NetworkPolicy respectively, for review before anything is installed.

### Per-project narrowing

A project narrows itself further in its own repository:

```yaml
# .cloop/sandbox.yaml in the project
capabilities:
  egress: public      # public Internet only; all private space dropped
```

or

```yaml
capabilities:
  egress: none        # no network interfaces at all
```

`egress: public` works **even when the executor has no filter of its own** —
that is the point of it. A project on a shared build host can renounce the
intranet without the operator changing anything, and its neighbours are
unaffected: each scope gets its own bridge and its own nftables table, so one
project's confinement never becomes another's.

Two constraints to know about:

- **`resolvers` is required** on the executor for `egress: public`. Dropping
  private space drops whatever resolver the container runtime handed the
  sandbox, and the symptom — every hostname failing to resolve — reads as "the
  Internet is blocked" and is not fixed by anything in the allow list. cloop
  refuses the run and names the config key rather than installing a policy with
  no working DNS. The named resolver is waived as one address on port 53, not as
  its subnet.
- **`egress: public` is refused on a broker-only executor.** If you configured
  `egress_filter.internal: true`, the sandbox's only route out is the egress
  broker's hostname allowlist, so "the public Internet" is *more* reach than you
  granted. That is a widening request and it is rejected, not downgraded.

`egress: none` needs no `nft`, no `CAP_NET_ADMIN` and no bridge — taking the
interfaces away is not a filter. The strongest scope is available on the hosts
least able to install a ruleset.

### Reaching a specific internal service

A project that genuinely needs one internal endpoint does **not** get it from
`sandbox.yaml`. Issue an egress grant, and name it from the repo:

```bash
cloop egress grant \
  --to project:/srv/projects/api \
  --hosts registry.internal.acme.com,artifacts.internal.acme.com \
  --ports 443 \
  --max-down 2g --max-up 100m \
  --session-ttl 15m --ttl 24h
```

```yaml
# .cloop/sandbox.yaml
capabilities:
  network: <grant-id>
```

The grant must already exist and be active; a spec naming one the project does
not hold is refused. See [the secrets guide](secrets.md).

## 3. Per-project sandbox with gVisor

### Configuring the runtime

Install gVisor and register `runsc` with your container runtime, then name it:

```yaml
executors:
  container:
    enabled: true
    runtime: podman            # or docker
    oci_runtime: runsc         # gVisor
    image: ghcr.io/acme/cloop-harness:2024-11
    network: bridge
    cpus: 8
    memory: 16g
    pids_limit: 2048
```

`oci_runtime` is a **registered runtime name**, never a path. docker resolves it
against `/etc/docker/daemon.json` and podman against `containers.conf`, both
root-owned files you already control — so the name is an indirection through a
trusted table rather than a path to a binary the daemon would run as root.

Confirm cloop recognises it. Preflight is phase one of `cloop executor test`,
which then runs a real workload in the sandbox — the only thing that proves the
runtime actually boots:

```bash
cloop executor test <executor-id>
```

```
ok    oci-runtime  runsc is registered with docker
ok    gvisor       runsc is recognised as gVisor: workload syscalls are served by
                   the Sentry rather than the host kernel, so this executor
                   satisfies capabilities.kernel_isolated
```

That finding matters. A typo like `runcs` is a valid runtime name and would be
silently treated as a plain container, so the check is that *cloop* agrees it is
gVisor — not just that the runtime starts.

Use `--skip-preflight` to attempt the workload anyway when a finding is wrong
about your host, and read the exit code: `2` means preflight found something
fatal and the smoke test was not attempted.

### Requiring it from a project

```yaml
# .cloop/sandbox.yaml
capabilities:
  kernel_isolated: true
```

This asks that the workload's system calls are **not served by the executing
machine's kernel**. Both gVisor and Kata satisfy it.

Use `kernel_isolated`, not `virtualized`, unless you specifically need a
hypervisor:

| key | satisfied by | ask |
|---|---|---|
| `kernel_isolated: true` | gVisor **and** Kata | "a kernel bug in my task must not be a kernel bug on the host" |
| `virtualized: true` | Kata only | "there must be a hypervisor" |

Demanding a VM when a userspace kernel would do refuses every gVisor executor in
the fleet — the ones that met the requirement exactly. See
[the Kata guide](kata.md) for the hypervisor path and its `/dev/kvm`
prerequisite.

Requiring more confinement needs no grant. The worst a repository can do with
either key is refuse to run anywhere, and it refuses loudly.

### The workspace is a bind mount and nothing else

The container executor's filesystem model is already what you asked for:

- `/workspace` is a bind mount of the project directory — the same inodes,
  mounted through. Nothing is copied and nothing else on the host is visible.
- the image's root filesystem is mounted **read-only**;
- `/tmp` is a `tmpfs` with `nosuid,nodev`, sized against the memory cap;
- all capabilities are dropped (`--cap-drop=ALL`) with `no-new-privileges`;
- the workload runs as the project directory's owner UID, never root;
- `--volume`, `--mount`, `--tmpfs`, `--privileged`, `--cap-add`,
  `--security-opt`, `--pid`, `--ipc` and `--device` are all **rejected** in
  `extra_args`, so operator config cannot dismantle the boundary the executor
  advertises.

A project can rearrange what it was given — `mounts:` re-exposes sub-paths of
the workspace elsewhere — but sources are workspace-relative with no `..`, so it
can never reach past it.

Per-project resources and toolchain:

```yaml
# .cloop/sandbox.yaml
image: ghcr.io/acme/rust-harness:1.79
setup:
  - cargo install cargo-nextest
resources:
  cpu: 8
  memory: 16g
  pids: 2048
  disk: 20g
capabilities:
  kernel_isolated: true
  egress: public
mounts:
  - source: target
    target: /cache/target
```

Numbers are clamped to the same bounds `pkg/config` enforces on your own
executor config, so a repository cannot request 4096 cores. Clamps are reported
as warnings, and the clamped value is what gets hashed and recorded — the
artifact never claims a limit the sandbox did not have.

Pin what may run with an image trust policy (`sandbox.image_policy`:
`allowed_registries`, `require_digest`, signature verification) so a repo cannot
name an arbitrary image. It sits at the top level rather than under an executor
because it governs every image any project names, whichever driver runs it. See
[configuration](../reference/configuration.md).

## 4. Hardware and network devices

A device node is the widest thing a sandbox request can ask for: `/dev/ttyUSB0`
is a serial line into whatever is plugged in, `/dev/nvidia0` is a compute unit
with its own memory, `/dev/net/tun` is an interface the sandbox can build its
own path out of. So it is a grant, and `sandbox.yaml` can only select from it.

### Inventory the host's hardware

One secret per host, `name=/dev/path` per line:

```bash
cloop secret mint bench-hw --kind host_device --file - <<'EOF'
# rack 3, bench A
serial0=/dev/ttyUSB0
serial1=/dev/ttyUSB1
# a logic analyser, read-only: nothing should be able to reprogram it
analyser=/dev/ttyACM0:r
# remapped, so a project's code does not change when the hardware moves
accel=/dev/nvidia0:/dev/accel0:rw
accelctl=/dev/nvidiactl:rw
tun=/dev/net/tun:rwm
EOF
```

The line format is `name=/dev/source[:/dev/target][:mode]`, where mode is `r`,
`rw` (the default) or `rwm`. The name is the handle everything downstream refers
to; remapping means a project told it has `accel` does not need to know that
*this* node enumerates the card as `nvidia0`.

The inventory refuses paths whose exposure would waive the sandbox entirely —
`/dev/mem`, `/dev/kmem`, `/dev/kcore`, `/dev/port`, `/dev/msr`, `/dev/cpu`, and
whole host disks — and refuses anything outside `/dev`, because a regular file is
a `local_repo` grant. Existence is *not* checked at mint time: the device may
belong to an executor on another host, which is preflight's question.

### Grant a slice to a project

```bash
cloop secret grant bench-hw \
  --to project:/srv/projects/firmware \
  --devices serial0,analyser \
  --writable \
  --ttl 8h
```

Without `--writable` every device in the grant is narrowed to read. A grant can
take access away and never add it: an inventory entry recorded as `:r` stays
read-only even under `--writable`.

### Select from the grant

```yaml
# .cloop/sandbox.yaml
capabilities:
  devices: [serial0]
```

Omitting `devices:` exposes everything the project was granted. Naming a device
the project holds **no grant for is an error**, not a request — unlike `env:`,
where an unheld name silently forwards nothing. A missing variable degrades a
run; a missing device node makes a firmware build meaningless, so it is better
to refuse than to start it with no serial port.

Inside the sandbox, `CLOOP_HOST_DEVICES=serial0` lists what arrived. Host paths
are deliberately not in the environment — the machine's hardware layout is not
something every process in the sandbox needs.

### What the access mode does and does not enforce

**Read the following before relying on a read-only device grant.**

The mode becomes the third field of the runtime's `--device src:dst:perms`,
which programs the container's *device cgroup*. On cgroup v2 that is an eBPF
program whose attachment depends on the kernel, the runtime build and cgroup
delegation — none of which cloop can interrogate. **On many hosts it is not
enforced at all**, and a device granted `r` is then writable, because the node
inside the sandbox keeps its host file mode and `/dev/zero` is `0666` nearly
everywhere.

Preflight says so, unconditionally — a driver that said nothing about a boundary
would read as a driver that provides it:

```
warn  devices   a host_device grant's access mode (r/rw/rwm) is programmed into the
                container's device cgroup, whose enforcement depends on this host's
                cgroup version and runtime build and cannot be verified from here
      fix       where read-only access must be enforced, set it on the host node
                itself (chown root:cloop-ro /dev/… && chmod 0640) so the sandbox UID
                cannot open it for writing regardless of cgroups
```

The control that holds on **every** host is the node's own ownership and mode.
The sandbox runs as the project directory's owner UID, so:

```bash
# make the analyser unwritable by the sandbox UID, whatever the cgroup does
chown root:cloop-ro /dev/ttyACM0
chmod 0640 /dev/ttyACM0
usermod -aG cloop-ro cloop-project-api
```

Use a udev rule to make that survive a reboot or a re-plug:

```
# /etc/udev/rules.d/70-cloop-bench.rules
SUBSYSTEM=="tty", ATTRS{idVendor}=="0403", GROUP="cloop-ro", MODE="0640"
```

cloop still emits the mode — on hosts where the cgroup rule *is* enforced it is
enforced exactly, and withholding `mknod` by default costs nothing. It is
defence in depth, not the boundary.

### GPUs on Kubernetes

`executors.kubernetes` reports `SupportsDevices: false`, and that is honest
rather than missing. Kubernetes does not take device paths: a device plugin owns
the node and hands the container whichever unit it has free in response to an
extended resource request. Mounting `/dev/nvidia0` as a hostPath from whatever
node the scheduler picked would expose an unrelated piece of that node's
hardware — worse than refusing.

A project holding a `host_device` grant and bound to a Kubernetes executor is
refused at placement, naming both facts. For GPU work on a cluster, bind the
project to a container executor on the GPU host.

### Revocation, honestly

A device already in a running sandbox's cgroup and mount namespace cannot be
taken back from outside it — the same limitation bind mounts have, and for the
same reason. Revoking a `host_device` grant stops the **next** lease; the
current workload keeps the device until it exits.

`cloop secret revoke <grant-id>` withdraws the grant, and it says so plainly:
"Credentials already materialised inside a running workload survive until that
workload's lease expires ... To cut access immediately, revoke and then stop the
run." Stop the run from the dashboard's Stop button, or by signalling the task —
there is no `cloop stop`.

Grant TTLs are the routine control, and they are the reason the above is usually
academic. Eight hours for a bench session is better than a week, because the
grant lapsing is what makes it a session rather than a standing entitlement.

## Putting it together

A bench host with instruments, serving one firmware project:

```yaml
# /srv/cloop/.cloop/config.yaml — the hub, on the bench host
executors:
  allow_host_process: false      # nothing runs unsandboxed
  container:
    enabled: true
    runtime: podman
    oci_runtime: runsc           # gVisor
    # Digest-pinned, because require_digest below is hub-wide and
    # `cloop hub doctor` checks this field against it too — a tag here
    # reports "would be refused by this hub's own image policy".
    image: ghcr.io/acme/cloop-harness@sha256:…
    network: bridge
    cpus: 16
    memory: 32g
    pids_limit: 4096
    egress_filter:
      enabled: true
      allow_public_internet: true
      allow_ports: [443]
      resolvers: ["9.9.9.9:53"]

# image trust is hub-wide, not per executor: one policy governs every image
# any project may name, whichever driver ends up running it.
sandbox:
  image_policy:
    # Registries are hosts. An entry containing "/" fails validation —
    # "names a path; registries are hosts" — so narrowing to one org is
    # allowed_repos' job, not this field's.
    allowed_registries: [ghcr.io]
    allowed_repos: ["ghcr.io/acme/*"]
    require_digest: true
```

```bash
# hardware inventory and the project's slice of it
cloop secret mint bench-hw --kind host_device --file ./bench-hw.txt
cloop secret grant bench-hw --to project:/srv/projects/firmware \
  --devices serial0,analyser --writable --ttl 8h

# the two internal checkouts it builds against
cloop secret mint host-src --kind local_repo --value /srv/git
cloop secret grant host-src --to project:/srv/projects/firmware \
  --repos 'firmware-*',shared-protos --ttl 168h
```

```yaml
# /srv/projects/firmware/.cloop/sandbox.yaml — committed to the repo
# Digest-pinned: the hub above sets require_digest, and a project-supplied
# tag is denied outright ("is pinned to a tag, and this hub requires a
# digest") before the run starts.
image: ghcr.io/acme/cloop-harness@sha256:…
resources:
  cpu: 8
  memory: 16g
capabilities:
  kernel_isolated: true    # syscalls never reach the bench host's kernel
  egress: public           # crates.io yes, the corporate network no
  devices: [serial0]       # the analyser is granted but this task does not need it
  git: true
```

What that produces: a gVisor sandbox on the bench host, `/workspace` a bind
mount of the project and nothing else on the filesystem visible, two checkouts
read-only at `/repos`, one serial port at `/dev/ttyUSB0`, the public Internet
reachable on 443 and every private address dropped — and a task that asks for
anything else refused at placement with the constraint named.

Verify before you trust it:

```bash
cloop executor test <id>          # preflight, then a real workload in the real sandbox
cloop secret grants --subject project:/srv/projects/firmware
cloop egress firewall --internet --ports 443 --resolver 9.9.9.9:53 \
  --check 10.4.5.6:443            # must print DROP
```

## Where the guarantees are written down

- [Executor architecture](../architecture/executors.md) — drivers, capabilities,
  placement, and which refusal comes from where
- [Security model](../security/model.md) — the boundaries, stated as claims
- [Threat model](../security/threat-model.md) — what each one is and is not
  worth
- [`tests/security/`](../../tests/security/) — the executable specification;
  every guarantee on this page that can be machine-checked is checked there
- [Sandbox spec reference](../reference/sandbox.md) — every
  `.cloop/sandbox.yaml` key
- [Configuration reference](../reference/configuration.md) — every
  `.cloop/config.yaml` key
