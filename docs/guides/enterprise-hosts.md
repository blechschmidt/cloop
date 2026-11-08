# Critical hosts as cloop executors

You have a few high-performance machines (a build box with 128 cores, a bench
with instruments on serial lines, a node with GPUs), and you want cloop to run
agent tasks on them without those tasks being able to reach the rest of your
network. This page describes the complete configuration for that.

The page has four sections, one per capability:

1. [Per-project repository access](#1-per-project-repository-access): give one
   project one or more internal git repositories, and nothing else.
2. [Per-project firewall rules](#2-per-project-firewall-rules): let a project
   reach the Internet while dropping every non-public address.
3. [Per-project sandbox with gVisor](#3-per-project-sandbox-with-gvisor): a
   confined environment whose syscalls never reach the host kernel, with a bind
   mount as its only view of the filesystem.
4. [Hardware and network devices](#4-hardware-and-network-devices): pass a
   serial port, a GPU or a TUN device into that sandbox.

## The rule that shapes all four

cloop splits each of these between two files, and which file a setting goes in
matters:

| | who writes it | what it may do |
|---|---|---|
| **`.cloop/config.yaml`** on the hub | an operator, out of band | grant reach |
| **`.cloop/sandbox.yaml`** in the repo | anyone who can open a pull request | give reach up |

`.cloop/sandbox.yaml` is committed to the project's repository. On a hub, the
person who merges a pull request is not the person whose infrastructure runs
it, so that file is treated as untrusted input: it can make a run *more*
confined than your default, never less. It has no key that names an address
range, a host path or a device path.

Everything that widens reach is a **grant**: issued by a person with the
`secret.grant` permission, scoped to one project, with a TTL and an audit row.
The repository can then *select* from what the project holds.

In short, grants add access, and `sandbox.yaml` can only take it away.

## Topology first

Sections 3 and 4 need the container executor to run on the machine that has the
hardware, because a device path and a bind mount refer to one machine's
filesystem. That limits your topology, so settle it before you configure
anything:

| you want | run | gVisor? | devices? | local repos? |
|---|---|---|---|---|
| sandboxes on the hub's own host | `executors.container` | yes | yes | yes |
| sandboxes on another host | a hub on that host | yes | yes | yes |
| sandboxes across a cluster | `executors.kubernetes` | yes (RuntimeClass) | no | no |
| sandboxes on a NAT'd edge device | `cloop executor agent` + [virtual executors](virtual-executors.md) | yes | yes | no |

A host_device *grant* names a path without saying which machine it is on, so
the remote agent does not accept one: `/dev/ttyUSB0` on the hub says nothing
about `/dev/ttyUSB0` in another building. Hardware on an edge device reaches a
sandbox the other way round, through a
[virtual executor](virtual-executors.md): a sub-executor of that device whose
devices an admin chooses from the device's own USB inventory, along with its
own runtime and IP firewall. Projects are bound to executors explicitly, so a
developer chooses the machine and the containment by choosing the executor.

Devices and gVisor do not work together, on any driver. On a gVisor host, a
node passed with `--device` exists in the sandbox but every attempt to open it
fails with `ENXIO`, and `/sys/bus/usb` is absent. cloop refuses the combination
at placement instead of starting a hardware task that cannot touch its
hardware. Put hardware on an executor with the engine's default runtime, and
untrusted work on a separate one with `runsc`.

Every refusal below happens at placement, with an error naming the constraint.
A sandbox spec that was ignored without an error would be worse than one that
is rejected, because the task would then run in an environment nobody
described.

## Before you start

Without sign-in, anyone who can reach a hub can drive it. So a hub without
sign-in (`ui.oidc`, or `CLOOP_UI_TOKEN` from `hub.env`) listens on `127.0.0.1`
only and refuses an address beyond loopback. Give the hub sign-in before it
listens on the network, or reach it through an SSH tunnel. Behind a TLS proxy on
the same host, pin it to `ui.listen: 127.0.0.1`. `cloop hub doctor` reports
where it actually listens (`ui.exposure`). See
[the Web UI section of the configuration reference](../reference/configuration.md#web-ui-cloop-ui).

Every `cloop secret` command on this page seals or opens a payload, so your
shell needs the hub's master key, read the same way the hub reads it, from its
key file:

```bash
export CLOOP_SECRET_KEY_FILE=/srv/cloop/cloop-secret-key   # the file `cloop hub bootstrap` wrote
```

Without it, the first `mint` stops with `CLOOP_SECRET_KEY is not set`. The key
belongs in that file, beside `.cloop/` and never inside it, at mode `0400` or
`0600`, and never in a repository or an environment file. See
[the root key](../operations/runbook.md#the-root-key),
[installation](../getting-started/installation.md) for generating it, and the
[runbook](../operations/runbook.md) for backup and rotation. If you lose the
key, you lose every stored secret, grants included, and under `tls: auto`
(below) also the hub's CA, which every sandbox trusts for the proxy's URL,
unless the key was escrowed (`cloop hub key escrow export`; see the
[runbook](../operations/runbook.md#escrowing-the-sealing-key)).

### Keep forge and cluster credentials on the hub

By default, a GitHub token or a kubeconfig granted to a project is delivered
into the sandbox: a `github_pat` as a token file that a git credential helper
releases, a `github_app` grant as its installation token. A hostile workload
then holds a credential it can use against GitHub's REST API, or to push
wherever the token reaches. The [git interception proxy](../git-interception-proxy.md)
and the [Kubernetes access monitor](../architecture/kubernetes-access.md) keep
both credentials on the hub. The sandbox gets a session token that is good for
one grant's repositories and branches, or its verbs and namespaces, checked
outside the sandbox on every push and every API request.

`cloop hub bootstrap` turns both on:

```bash
cloop hub bootstrap --external-url https://hub.internal:8080
#   git_proxy:  tls: auto, listen 0.0.0.0:8443, advertised https://hub.internal:8443
#   kube_guard: tls: auto, listen 0.0.0.0:8444, advertised https://hub.internal:8444
```

`--git-proxy-port` and `--kube-guard-port` change the ports. `tls: auto` needs
no certificate from you: the hub mints a CA the first time it starts, seals its
key under `CLOOP_SECRET_KEY` in its own database, and serves each monitor a
short-lived leaf certificate for the advertised name, renewed before it
expires. Every sandbox (a container on this host, a Pod, an edge device or a
virtual executor on one) is told to trust that CA for those two URLs only, so
no image needs it built in and nothing else the sandbox talks to is affected. A
device's agent must speak protocol v21 or later. An older agent is refused the
workloads that would talk to the proxy, with an error naming the upgrade.

You need to provide a network route. Executors must reach TCP 8443 and 8444 on
the hub at the advertised name. Both ports terminate their own TLS, so route
them to the hub directly, not through a TLS-terminating proxy. A container
executor with `network: none` reaches nothing, and a firewall or egress filter
needs the hub's address and both ports in its allow lists; see
[the network between sandbox and proxy](../architecture/git-proxy.md#the-network-between-sandbox-and-proxy).
`cloop hub doctor` checks the certificates (`gitproxy.tls`, `kubeguard.tls`)
and dials both ports. On a hub with `allow_host_process: false` and no proxy,
it lists every GitHub grant the hub delivers into sandboxes
(`gitproxy.forge_credentials`).

## 1. Per-project repository access

There are two kinds, depending on where the repositories live.

### Repositories checked out on the host

The hub host holds the checkouts, and a project gets a bind mount of some of
them.

Store the inventory once. It is the **root** directory that holds the checkouts:

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

Read-only is the default, and the bind mount enforces it, so a runaway harness
cannot rewrite the history of a checkout that exists nowhere else. Write access
needs `--writable` on the grant.

Two more things to know:

- **Symlinks cannot escape the root.** Every candidate path is resolved with
  `EvalSymlinks` and checked again against the resolved root, so a link that a
  dependency's postinstall script planted inside `/srv/git` cannot redirect a
  bind to `/`.
- **Only direct children are considered.** A root of `/srv/git` will not match
  `/srv/git/.cache/some-dep/vendor/x`.

### Repositories on an internal git server

What cloop can authenticate to depends on the kind of server. Only `github.com`
and GitHub Enterprise Server hosts receive brokered credentials. A GitHub
credential is bound to the forge host its secret names, and is never presented
to any other host, even if that host's repository paths match the grant's
allowlist.

**A GitHub Enterprise Server.** Mint the PAT for the server, so the host is
sealed with the token, and constrain it to the repositories it may reach:

```bash
cloop secret mint gh-internal --kind github_pat \
  --github-host git.acme.internal --file ./pat.txt
cloop secret grant gh-internal \
  --to project:/srv/projects/api \
  --repos 'acme-internal/api-*' \
  --permissions contents:read \
  --ttl 24h
```

A GitHub App installed on the server works the same way, with
`"base_url": "https://git.acme.internal/api/v3"` in its payload, and its tokens
are bound to `git.acme.internal`. Either credential is presented to
`git.acme.internal` only, never to `github.com`, even for a repository with the
same `owner/name`, and a `github.com` grant is never presented to the server. A
project whose origin is on another host is refused with an error naming both
hosts; it is not fetched with the token.

With the [git proxy](#keep-forge-and-cluster-credentials-on-the-hub) on, the
token stays on the hub. The sandbox's git rewrites `https://git.acme.internal/`
to the proxy's route for that host and presents a session token for
`acme-internal/api-*`. The proxy presents the PAT upstream, to
`git.acme.internal` and nowhere else, only for those repositories and only for
the pushes its policy allows. A lease that also holds a `github.com` grant gets
a separate rewrite and route for it, so the two never mix. cloop's provisioning
fetch of a project's checkout goes to that checkout's own `https` origin,
verified against the hub host's trust store (`SSL_CERT_FILE` or `SSL_CERT_DIR`
for a private CA), and carries the credential only when the origin is on the
grant's host. Without the proxy, the token is not exported as `GITHUB_TOKEN`,
because a tool reading it would send it to `github.com` (a wildcard grant
exports it as `GH_ENTERPRISE_TOKEN` instead). cloop installs a git credential
helper that releases the token only for `git.acme.internal` and only for paths
matching the allowlist, so a harness that tries to clone an unlisted repository
gets an authentication failure instead of a checkout. The token file itself is
still in the sandbox, though. See
[the secrets guide](secrets.md#github-enterprise-server) for the full
mechanism, and [the git interception proxy](../git-interception-proxy.md) for
restricting which branches a sandbox may push to.

**Any other forge (GitLab, Gitea, Bitbucket, a plain `git-http-backend`).** No
brokered credential is ever presented to it. Its repositories are fetched
without a credential where no grant could apply (a path that is not
`owner/name`, such as a GitLab subgroup, or a hub that does not run the secret
broker). Otherwise they are refused by name, with an error saying that the host
receives no brokered credential, and never fetched with a GitHub token. To give
a project such repositories, check them out on the host and grant them as
[repositories checked out on the host](#repositories-checked-out-on-the-host),
described above.

## 2. Per-project firewall rules

The goal: let the task reach the Internet, and nothing on your network. There
are two layers, and you want both.

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

`allow_public_internet: true` allows everything outside the fixed block set and
drops everything inside it. The block set is not configurable, and it is what
blocks every non-public IP address:

| dropped | why |
|---|---|
| `169.254.169.254/32`, AWS's `fd00:ec2::254`, Alibaba's `100.100.100.200`, … | cloud metadata services (`pkg/cloudmeta`). Each hands out instance credentials, and can be reached only by naming its own address, never through a range that contains it |
| `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` | RFC1918 / ULA private space |
| `100.64/10` | carrier-grade NAT |
| `169.254/16`, `fe80::/10` | link-local |
| `127/8`, `::1/128` | loopback beyond the sandbox's own |
| `224/4`, `ff00::/8` | multicast |
| `64:ff9b::/96`, `2002::/16`, … | IPv6 transition prefixes a packet filter cannot unwrap |

Rules are installed on the sandbox bridge before any container can join it, so
a workload is never up without its filter.

You can render what a configuration would install without touching the host.
This uses the same compiler as the driver, so the output is the actual ruleset:

```console
$ cloop egress firewall --internet --ports 443 --resolver 9.9.9.9:53
IP-layer egress filter  mode filtered, 38 rules, from flags

warning: every public address is reachable on port 443; only the private,
loopback, link-local, CGNAT and metadata ranges are filtered

  allow  127.0.0.0/8                any          sandbox-local loopback [namespace-local]
  allow  9.9.9.9/32             udp 53           DNS resolver
  allow  9.9.9.9/32             tcp 53           DNS resolver (truncated answers retry over TCP)
  drop   100.100.100.200/32         any          cloud metadata service (100.100.100.200)
  drop   168.63.129.16/32           any          cloud metadata service (168.63.129.16)
  drop   169.254.169.254/32         any          cloud metadata service (169.254.169.254)
  ...
  drop   fd00:ec2::254/128          any          cloud metadata service (fd00:ec2::254)
  ...
  drop   127.0.0.0/8                any          loopback
  drop   169.254.0.0/16             any          link-local
  drop   10.0.0.0/8                 any          private (RFC1918/ULA)
  drop   100.64.0.0/10              any          carrier-grade NAT (RFC6598)
  ...
  allow  0.0.0.0/0              tcp 443          public Internet
  drop   0.0.0.0/0                  any          default deny
```

`--check` answers the question for one address, which makes it useful in a CI
job:

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

`egress: public` works even when the executor has no filter of its own. A
project on a shared build host can give up intranet access without the operator
changing anything, and its neighbours are unaffected: each scope gets its own
bridge and its own nftables table, so one project's confinement never applies
to another.

Two constraints to know about:

- **`resolvers` is required** on the executor for `egress: public`. Dropping
  private address space also drops whatever resolver the container runtime gave
  the sandbox. The symptom, every hostname failing to resolve, looks like "the
  Internet is blocked", and nothing in the allow list fixes it. So cloop
  refuses the run with an error naming the config key, instead of installing a
  policy with no working DNS. The named resolver is allowed as one address on
  port 53, not as its whole subnet.
- **`egress: public` is refused on a broker-only executor.** If you configured
  `egress_filter.internal: true`, the sandbox's only route out is the egress
  broker's hostname allowlist, so "the public Internet" is *more* than you
  granted. A request that widens access is rejected, not downgraded.

`egress: none` needs no `nft`, no `CAP_NET_ADMIN` and no bridge, because
removing the interfaces needs no filter. So the strongest scope is also
available on the hosts least able to install a ruleset.

For a finer narrowing than the two scopes ("this project reaches our registry
and GitHub, on 443, and nothing else"), the project's maintainers save a rule
set on the project's Overview page, not in the repository. A file in the
repository that could name addresses would put the network one pull request
away. The project's rule set can only narrow the executor's, and an admin can
set a rule set on the executor itself that limits every project on it. See
[firewall rules](firewall.md).

### Reaching a specific internal service

A project that needs one internal endpoint does not get it from `sandbox.yaml`.
Issue an egress grant, and name it from the repository:

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

The grant must already exist and be active. A spec naming a grant the project
does not hold is refused. See [the secrets guide](secrets.md).

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

`oci_runtime` is a registered runtime name, never a path. docker looks it up in
`/etc/docker/daemon.json` and podman in `containers.conf`, both root-owned files
you already control. The name is therefore looked up in a trusted table, and
cannot point at an arbitrary binary for the daemon to run as root.

Check that cloop recognises it. Preflight is the first phase of
`cloop executor test`, which then runs a real workload in the sandbox. That is
the only way to prove the runtime actually boots:

```bash
cloop executor test <executor-id>
```

```
ok    oci-runtime  runsc is registered with docker
ok    gvisor       runsc is recognised as gVisor: workload syscalls are served by
                   the Sentry rather than the host kernel, so this executor
                   satisfies capabilities.kernel_isolated
```

The `gvisor` line is the one that matters. A typo like `runcs` is a valid
runtime name and would be treated as a plain container without any warning, so
the check is that *cloop* agrees the runtime is gVisor, not just that it starts.

If a finding is wrong about your host, use `--skip-preflight` to run the
workload anyway. Exit code `2` means preflight found something fatal and the
smoke test was not attempted.

### Requiring it from a project

```yaml
# .cloop/sandbox.yaml
capabilities:
  kernel_isolated: true
```

This requires that the workload's system calls are not served by the executing
machine's kernel. Both gVisor and Kata satisfy it.

Use `kernel_isolated`, not `virtualized`, unless you specifically need a
hypervisor:

| key | satisfied by | ask |
|---|---|---|
| `kernel_isolated: true` | gVisor and Kata | "a kernel bug in my task must not be a kernel bug on the host" |
| `virtualized: true` | Kata only | "there must be a hypervisor" |

Requiring a VM when a userspace kernel would do rules out every gVisor executor
in the fleet, even though they meet the actual requirement. See
[the Kata guide](kata.md) for the hypervisor option and its `/dev/kvm`
prerequisite.

Requiring more confinement needs no grant. The worst a repository can do with
either key is make itself impossible to place, and that fails with an error.

### The workspace is a bind mount and nothing else

The container executor's filesystem model already gives you this:

- `/workspace` is a bind mount of the project directory (the same inodes).
  Nothing is copied, and nothing else on the host is visible.
- The image's root filesystem is mounted read-only.
- `/tmp` is a `tmpfs` with `nosuid,nodev`, sized against the memory cap.
- All capabilities are dropped (`--cap-drop=ALL`), with `no-new-privileges`.
- The workload runs as the project directory's owner UID, never root.
- `--volume`, `--mount`, `--tmpfs`, `--privileged`, `--cap-add`,
  `--security-opt`, `--pid`, `--ipc` and `--device` are all rejected in
  `extra_args`, so operator config cannot undo the boundary the executor
  advertises.

A project can rearrange what it was given (`mounts:` exposes sub-paths of the
workspace at other locations), but sources are relative to the workspace and
cannot contain `..`, so a project can never reach outside it.

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

Numbers are clamped to the same bounds that `pkg/config` enforces on your own
executor config, so a repository cannot request 4096 cores. Clamps are reported
as warnings, and the clamped value is what gets hashed and recorded, so the
artifact never claims a limit the sandbox did not have.

`disk: 20g` limits the workspace: the bind-mounted project directory, with its
`.cloop/` counted by what the run adds to it. The container executor enforces
the limit by measuring the tree. A workspace already over 20 GB is refused at
the start, with both sizes in the error, and a workload that grows past the
limit is stopped and its run paused with reason `disk_limit` instead of
retried. Free the space or raise the limit, then press Run. The size is sampled
(every 5 seconds to 2 minutes, at idle priority, and less often for a tree that
is costly to walk), not enforced as a quota, so a burst can overshoot by
whatever the workload writes between two samples. Keep
`orchestrator.min_free_disk_mb` on, because the free-space floor is what stops
such a burst from filling the host's volume. A disk ceiling you set on the
executor (its **Limits** in the Executors panel, or
`executors.limits.max_disk`) applies the same way, and also limits every
project that sets no `disk:` at all. The executor's card shows `disk: enforced
(sampled)`; see [`resources.disk` and the workspace](../reference/sandbox.md#resourcesdisk-and-the-workspace).

Restrict what may run with an image trust policy (`sandbox.image_policy`:
`allowed_registries`, `require_digest`, signature verification), so that a
repository cannot name an arbitrary image. It sits at the top level, not under
an executor, because it governs every image any project names, whichever driver
runs it. On a critical host enrolled as a device, that includes the host
itself. Its agent applies no policy of its own, so the hub checks a project's
image before it dispatches. Under `require_signature` the hub resolves a tag at
its registry, verifies the digest with cosign *on the hub*, and sends the device
that digest. The hub therefore needs `cosign`, and a route to the registries the
policy names, even when no executor on it runs an image. The image you
configure for the device's own sandbox is yours, and is exempt. See
[configuration](../reference/configuration.md) and
[what is not mitigated](../security/model.md#what-is-not-mitigated).

## 4. Hardware and network devices

A device node is the widest thing a sandbox can ask for: `/dev/ttyUSB0` is a
serial line into whatever is plugged in, `/dev/nvidia0` is a compute unit with
its own memory, and `/dev/net/tun` lets the sandbox build its own way out. So
devices are granted, and `sandbox.yaml` can only select from a grant.

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
`rw` (the default) or `rwm`. The name is the handle everything else refers to.
With remapping, a project that is told it has `accel` does not need to know
that *this* node enumerates the card as `nvidia0`.

The inventory refuses paths that would make the sandbox pointless (`/dev/mem`,
`/dev/kmem`, `/dev/kcore`, `/dev/port`, `/dev/msr`, `/dev/cpu`, and whole host
disks), and refuses anything outside `/dev`, because a regular file is a
`local_repo` grant. Whether the device exists is *not* checked at mint time,
because it may belong to an executor on another host; preflight checks that.

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
the project has no grant for is an error. This differs from `env:`, where a
name the project does not hold forwards nothing, without an error. A missing
variable degrades a run, but a missing device node makes a firmware build
meaningless, so it is better to refuse than to start it with no serial port.

Inside the sandbox, `CLOOP_HOST_DEVICES=serial0` lists what arrived. Host paths
are not in the environment, because not every process in the sandbox needs to
know the machine's hardware layout.

### What the access mode does and does not enforce

**Read this before relying on a read-only device grant.**

The mode becomes the third field of the runtime's `--device src:dst:perms`,
which programs the container's *device cgroup*. On cgroup v2 that is an eBPF
program whose attachment depends on the kernel, the runtime build and cgroup
delegation, none of which cloop can query. On many hosts it is not enforced at
all, and a device granted `r` is then writable, because the node inside the
sandbox keeps its host file mode and `/dev/zero` is `0666` nearly everywhere.

Preflight always warns about this, because a driver that said nothing about a
boundary would look like a driver that provides it:

```
warn  devices   a host_device grant's access mode (r/rw/rwm) is programmed into the
                container's device cgroup, whose enforcement depends on this host's
                cgroup version and runtime build and cannot be verified from here
      fix       where read-only access must be enforced, set it on the host node
                itself (chown root:cloop-ro /dev/… && chmod 0640) so the sandbox UID
                cannot open it for writing regardless of cgroups
```

The control that works on every host is the node's own ownership and mode. The
sandbox runs as the project directory's owner UID, so:

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

cloop still passes the mode on: on hosts where the cgroup rule *is* enforced, it
is enforced as written, and withholding `mknod` by default costs nothing. It is
an extra layer of defence, not the boundary.

### GPUs on Kubernetes

`executors.kubernetes` reports `SupportsDevices: false`, which reflects how
Kubernetes works and is not a missing feature. Kubernetes does not take device
paths: a device plugin owns the node and gives the container whichever unit it
has free in response to an extended resource request. Mounting `/dev/nvidia0`
as a hostPath on whatever node the scheduler picked would expose an unrelated
piece of that node's hardware, which is worse than refusing.

A project that holds a `host_device` grant and is bound to a Kubernetes
executor is refused at placement, with an error that names both. For GPU work
on a cluster, bind the project to a container executor on the GPU host.

### Revocation, honestly

A device already in a running sandbox's cgroup and mount namespace cannot be
taken back from outside it. Bind mounts have the same limitation, for the same
reason. Revoking a `host_device` grant takes it out of the run's lease at once
and out of every later lease, but the current workload keeps the device until it
exits.

`cloop secret revoke <grant-id>` withdraws the grant, and its help text says:
"What no revocation reaches is what is already inside a running sandbox: … a
device or network interface passed through. … To stop the others now, revoke
their lease with action=kill from the Secrets panel, or stop the run." Stop the
run with the dashboard's Stop button or by signalling the task. There is no
`cloop stop`.

Grant TTLs are the routine control, and they are why this rarely matters in
practice. Eight hours for a bench session is better than a week, because the
grant lapsing is what makes it a session and not a standing entitlement.

### Network interfaces: L2 passthrough

A device grant cannot carry a network interface. A netdev is not a node under
`/dev`, so there is nothing to bind and no cgroup rule to write, and neither
runtime has a flag for it. (`/dev/net/tun` lets a sandbox *build* an interface,
which is not the same as being given one.)

`host_interface` gives the sandbox an interface. It moves an interface out of
the executor's network namespace and into the sandbox's, which puts the
workload on the segment the interface is attached to, instead of behind a route
through the host. That is what makes ARP, DHCP, PTP, raw Ethernet and every
other link-layer protocol work. A bring-up engineer needs these, and no egress
rule can carry them.

**Read this before granting one.** Two properties have no equivalent anywhere
else in cloop:

- **The host gives the interface up.** A netdev lives in exactly one namespace,
  so for the life of the run the executor cannot use it at all. Naming the wrong
  interface cuts the machine off the network, and on a remote bench that means
  losing access to the machine. cloop refuses `lo`, the container runtimes' own
  bridges (`docker0`, `podman0`, `cni-podman0`, `virbr0`, any `br-*`) and, at
  attach time on the executor itself, whichever interface carries that host's
  default route.
- **Teardown is the kernel's decision.** When a network namespace is destroyed,
  the kernel returns *physical* devices to the initial namespace and *deletes*
  virtual ones. A passed-through NIC comes back by itself, but a passed-through
  veth end is destroyed, and its peer with it. cloop moves interfaces back while
  the container is still up, so a graceful stop preserves a veth bench. A
  workload that is killed outright, or a host that loses power, leaves it to the
  kernel's rules.

#### Which executors can honour it

Only a container executor running as root, on the machine the interface is
attached to, with `ip(8)` and `nsenter(1)` installed, under `runc` or `crun`.

The last condition matters most. Kata and gVisor build their view of the network
when the sandbox starts and never see a link that arrives later. The move would
succeed, the host would lose the interface, and `/proc/net/dev` inside the
container would still list only `lo`. So cloop reports the capability as false
on those runtimes and refuses at placement. A bench that needs both a wire and a
guest kernel needs a different mechanism (SR-IOV VF assignment at VM creation),
which cloop does not drive.

#### Wire the bench

The usual setup is a veth pair with one end on a bridge and the other granted to
the sandbox. cloop's own integration test builds this bench:

```bash
# a segment with the device under test on it
docker network create --driver bridge --subnet 172.31.99.0/24 bench
BR=br-$(docker network inspect -f '{{.Id}}' bench | cut -c1-12)

# the veth pair: one end on the bridge, one end for the sandbox
ip link add bench-sbx type veth peer name bench-br
ip link set bench-br master "$BR"
ip link set bench-br up
ip link set bench-sbx up
```

For a *physical* bench port (a NIC wired to the board), skip the veth and grant
the interface itself. The kernel handles this case best: the interface comes
back to the host on its own when the sandbox ends.

#### Inventory and grant

```bash
cloop secret mint bench-net --kind host_interface --file - <<'EOF'
# rack 3, bench A — the veth end that lands on the bench bridge
dut=bench-sbx,target=eth1,address=172.31.99.200/24
# a physical port wired straight to the board, addressed by DHCP in-sandbox
can0=enp3s0,target=eth1
# a capture port: no address, jumbo frames, raw L2 only
capture=enp4s0f1,mtu=9000
EOF

cloop secret grant bench-net \
  --to project:/srv/projects/firmware \
  --interfaces dut \
  --ttl 8h
```

The line format is `name=ifname` followed by optional comma-separated
attributes: `target=` (the name inside the sandbox), `address=` (a CIDR, that
is, an address with a prefix length), `gateway=` (needs `address=`; points the
sandbox's default route at the bench) and `mtu=`. The attributes are separated
by commas, not colons, because `fd00::10/64` is full of colons.

Omit `address=` for a segment with DHCP on it, or for a workload doing raw L2:
the interface arrives up and without an address.

#### Select from the grant

```yaml
# .cloop/sandbox.yaml
capabilities:
  network: bench-egress   # `interfaces:` with `network:` unset is a 400
  interfaces: [dut]
```

Omitting `interfaces:` moves in everything the project was granted. Naming an
interface the project has no grant for is an error, for the same reason as a
missing device: starting a bring-up task on a board it has no wire to is worse
than refusing.

`interfaces:` together with `network: none` is refused. The two settings
contradict each other, and honouring either one without an error would discard
the other: either the repository renounced the network and would be given one,
or the host would hand over an interface the workload cannot see.

Inside the sandbox, `CLOOP_HOST_INTERFACES=dut` lists the handles that arrived.
Host interface names are not in the environment, because not every process in
the sandbox needs to know the bench's wiring.

#### The start-up window

The interface is moved in *after* the container starts, because the namespace it
moves into does not exist until then. cloop does this before `Start` returns, so
the task is never dispatched to a sandbox whose interface has not arrived. But a
workload whose very first instruction probes for the link can still miss it by a
few tens of milliseconds.

The window only ever shows a workload *less* than it was granted, never more. A
workload that needs to synchronise should wait for the link named by
`$CLOOP_HOST_INTERFACES` to come *up*, not just to exist. The kernel only
renames a link while it is down, so the name appears first, then the MTU and
address, and bringing the link up is the last step (apart from a granted
gateway's default route, which is installed just after it):

```sh
# IFF_UP is bit 0 of the link's flags
until [ $(( $(cat /sys/class/net/eth1/flags 2>/dev/null || echo 0) & 1 )) -eq 1 ]; do
  sleep 0.05
done
```

If a workload exits before the move completes, the start fails with an error:
the container is destroyed, and the error says what to do.

## Putting it together

A bench host with instruments, serving one firmware project:

```yaml
# /srv/cloop/.cloop/config.yaml — the hub, on the bench host
executors:
  allow_host_process: false      # nothing runs unsandboxed
  container:
    enabled: true
    runtime: podman
    # The engine's default runtime (runc or crun), not runsc: the serial
    # lines below are opened through the host kernel, and under gVisor every
    # open of a passed-through node fails with ENXIO. Untrusted work belongs
    # on a second executor that does set oci_runtime: runsc.
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
# any project may name, whichever driver ends up running it — a device's
# included, which the hub verifies before dispatch (cosign runs on the hub).
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
  egress: public           # crates.io yes, the corporate network no
  devices: [serial0]       # the analyser is granted but this task does not need it
  git: true
```

No `kernel_isolated: true` here: it would place the project on a gVisor
executor, where the serial line cannot be opened (see the topology section).

The result is a container sandbox on the bench host with `/workspace` as a bind
mount of the project and nothing else on the filesystem visible, two read-only
checkouts at `/repos`, one serial port at `/dev/ttyUSB0`, the public Internet
reachable on port 443, and every private address dropped. A task that asks for
anything else is refused at placement, with an error naming the constraint.

Check it before you rely on it:

```bash
cloop executor test <id>          # preflight, then a real workload in the real sandbox
cloop secret grants --subject project:/srv/projects/firmware
cloop egress firewall --internet --ports 443 --resolver 9.9.9.9:53 \
  --check 10.4.5.6:443            # must print DROP
```

## Where the guarantees are written down

- [Executor architecture](../architecture/executors.md): drivers, capabilities,
  placement, and which component refuses what
- [Security model](../security/model.md): the boundaries, stated as claims
- [Threat model](../security/threat-model.md): what each boundary protects
  against and what it does not
- [`tests/security/`](../../tests/security/): the tests that check every
  guarantee on this page that can be checked automatically
- [Sandbox spec reference](../reference/sandbox.md): every
  `.cloop/sandbox.yaml` key
- [Configuration reference](../reference/configuration.md): every
  `.cloop/config.yaml` key
