# Configuration reference

Executor backends, sandbox settings, transport security and hardening keys for
`.cloop/config.yaml`.

Conceptual documentation lives elsewhere: [how executors work](../architecture/executors.md),
[what each boundary authenticates with](../security/model.md), and
[granting credentials](../guides/secrets.md). This file is the key-by-key
reference those documents refer to.

---

## Per-user state: `CLOOP_HOME`

Most configuration is per-project and lives in `.cloop/config.yaml` inside the
working tree. A few things are per-*user* and deliberately outside it — the
multi-project registry the dashboard lists, the global budget and cost ledger,
named profiles, and cached provider credentials:

| Path | Contents | Relocated by `CLOOP_HOME` |
| --- | --- | --- |
| `~/.cloop/projects.json` | The multi-project registry: which projects the dashboard shows | **yes** |
| `~/.cloop/profiles.yaml` | Named provider profiles | no |
| `~/.cloop/agent.json` | Remote executor agent credential and pinned certificate | no |
| `~/.cloop/plugins/` | User-level plugins | no |
| `~/.config/cloop/budget.yaml` | Global spend caps | no |
| `~/.config/cloop/costs.jsonl` | Global cost ledger | no |
| `~/.config/cloop/workspaces.json` | Registered workspaces | no |

**`CLOOP_HOME`** overrides the directory that would otherwise be `~/.cloop`,
following the `CARGO_HOME` convention: it names the directory itself, not a home
that contains it. A relative value is resolved against the process working
directory; an empty or whitespace-only value is treated as unset.

```bash
CLOOP_HOME=/var/lib/cloop/alice cloop ui
```

**It currently affects the registry only** — the right-hand column above is not
decoration. Profiles, plugins and the agent credential still resolve from
`$HOME` directly, so setting `CLOOP_HOME` alone does not give a second hub its
own copy of those. To relocate everything, set `HOME`; `CLOOP_HOME` then
narrows the registry further if you want it somewhere else again.

Two reasons to set it:

- **Running more than one hub under one Unix account.** Without it they share a
  registry, so projects registered by one appear in the other.
- **Testing.** The registry is process-global state at a fixed path outside the
  working tree, which makes it easy for a test to write to the machine it runs
  on and leave it there. That is not theoretical: a dashboard test accumulated
  99 entries into a developer's real `projects.json`, one per run, until project
  index 99 resolved to a deleted directory and three unrelated authorization
  tests began failing — on that machine only, since CI always starts from an
  empty `$HOME`. Go tests here isolate via `internal/hometest.Isolate` in
  `TestMain`, which redirects `$HOME` and clears `CLOOP_HOME`; `tests/hermetic`
  fails the build if a package that reads `$HOME` and has tests does not.

---

## Background work left by an agent

An agent can start a long job and exit before it finishes — `nohup python
train.py &`, a background build, a test run it never waits on — and then print
`TASK_DONE`. Its transcript is honest about what it *started* and silent about
what it *finished*, so without help cloop marks the task complete and runs the
next one against an artifact that is still being written. The incident this
guards against had three consecutive tasks operating on a model the task before
them was still training.

cloop detects this. The `claude` CLI runs in its own process group, so anything
it forks is still identifiable after it exits. When the harness returns, cloop
scans that group:

- **Nothing left running** — the common case. Costs one procfs scan, and the
  task proceeds normally.
- **Something exits within the grace window** — ordinary teardown, ignored.
- **Real background work** — cloop blocks until it finishes, then accepts the
  task. The wait is visible in the UI and the event log while it happens.
- **Work outlives the budget** — the task is *not* accepted as complete, whatever
  its output claimed. It is marked failed with a diagnosis naming the surviving
  processes, dependent tasks stay blocked, and the orphans are terminated so a
  retry cannot race the leftovers.

Configure it under the provider:

```yaml
claudecode:
  background:
    disabled: false      # true restores the old trust-the-transcript behaviour
    grace_seconds: 2     # teardown window before survivors count as real work
    wait_minutes: 30     # how long to wait; negative reports without waiting
    keep_orphans: false  # true leaves survivors running (task still fails)
```

`grace_seconds` is capped at 120 and `wait_minutes` at 1440; a value beyond
either is clamped with a warning rather than silently reinterpreted.

Raise `wait_minutes` if your tasks legitimately start long jobs — the cost of
waiting too long is a slow task, while the cost of waiting too briefly is a task
retried when it would have succeeded. Set `keep_orphans: true` only if something
outside cloop is responsible for reaping those processes.

**Limit:** a child that calls `setsid()` leaves the process group and is not
detected. That is deliberate — `setsid` is the explicit "I intend to outlive my
parent" gesture, and the case this exists to catch is the opposite one, where
the work was meant to be waited for.

---

## Execution Backends (Executors)

An **executor** decides *where* a cloop workload actually runs. By default it is
a child process on the same host as cloop itself, with the same user, the same
filesystem, and the same network. That is fine on a laptop. It is not fine for a
hosted deployment where the agent executes model-authored code on someone else's
behalf.

Projects are pinned to an executor. A project bound to an executor that is not
available **fails** rather than silently falling back to host execution — an
isolation boundary you opted into is never downgraded because the backend
happened to be unreachable.

| Kind | Isolation | Where it runs | Notes |
|------|-----------|---------------|-------|
| `localprocess` | none | this host | Default. Zero-config, no sandbox. |
| `container` | container, or `vm` | this host | Docker/Podman sandbox. Opt-in via config. `vm` with a Kata [`oci_runtime`](#vm-isolated-sandboxes-kata-containers). |
| `remote` | remote | an enrolled device | Edge box that dialled out to the control plane. |
| `kubernetes` | remote | an ephemeral Pod | One Pod per workload. Also VM-backed with a Kata [`runtime_class`](#vm-isolated-sandboxes-kata-containers). |

```bash
cloop executor list              # what is registered, and what it isolates
cloop executor ls                # fleet health: state, in-flight work, last seen
cloop executor test <id>         # preflight + run `cloop version` inside it
cloop executor reap <id>         # remove containers/Pods left by a killed control plane
cloop executor cordon <id>       # stop new placement; in-flight work continues
cloop executor uncordon <id>     # back in rotation, at the health its probes justify
cloop executor drain <id>        # stop placement, wait for in-flight to reach zero
cloop executor enroll            # mint a token for a remote device
cloop executor agent --server …  # run *on* the device
cloop executor revoke <id>       # kill a leaked token or a decommissioned device
```

### The Executors panel

The web dashboard has a global **Executors** tab: one card per backend with a
live status dot, a kind badge (host / container / remote), capability chips,
current load, and enroll/revoke actions. Status changes arrive over the same
WebSocket the rest of the dashboard uses — nothing polls.

Each project's execution target is a one-click setting: the **Executor** card on
the project Overview page, next to the provider card. Changing it takes effect
on the next run; work already in flight stays on the executor that started it.

The tab's banner always states the effective host-execution mode, so "can this
server still fork a harness next to itself" is never something you have to infer
from a config file.

### Container sandbox

Enable it in `.cloop/config.yaml`:

```yaml
executors:
  container:
    enabled: true
    runtime: podman          # or docker; empty auto-detects (podman preferred)
    oci_runtime: ""          # low-level runtime the CLI delegates to; empty = runc/crun
    image: ghcr.io/blechschmidt/cloop-harness:latest
    cpus: 2                  # core allowance per workload
    memory: 2g               # 512m / 2g / 1024k; a bare integer means MB
    pids_limit: 1024         # process cap; -1 disables
    network: none            # none (default) | bridge | <named network>
    extra_args: []           # additional runtime flags, --flag=value form only
    selinux_label: ""        # "z" or "Z" — required when SELinux is enforcing
    orphan_grace_period_seconds: 600   # 0 means 600; see below
```

or with `cloop config set executors.container.<key> <value>`. `oci_runtime` is
the exception: the setter's key list does not cover it, so it is edited here.

`orphan_grace_period_seconds` is how old a **running** container has to be before
the startup sweep and `cloop executor reap` will kill it. Exited containers are
collected immediately and ignore it entirely.

It is what makes reaping a running orphan safe rather than reckless. A container
listed moments ago may belong to a control plane that is starting right now, or
to this one in the microseconds between `run -d` returning and the handle being
recorded, and neither is an orphan — but a container that has been running
untracked for longer than this has a demonstrably absent owner. Zero means the
600-second default, because treating an unset field as "reap on sight" would make
the least-configured executor the most destructive one; the accepted range is
0–604800 (7 days), and a value outside it is reported and reset to the default
rather than silently clamped. `executors.kubernetes.orphan_grace_period_seconds`
is the same key with the same default and the same meaning for Pods.

Ten minutes is far wider than the millisecond-scale race it guards, and that is
the correct direction to be wrong in: an orphan reaped ten minutes late costs
CPU, an orphan reaped ten milliseconds early costs somebody's run. Lower it only
on a host where nothing else shares the runtime. See
[orphan grace periods](../architecture/executors.md#orphan-grace-periods) for
what else has to be true before a running container is touched, and
[after a control-plane restart](../operations/runbook.md#after-a-control-plane-restart)
for the log line that reports one.

Every container is started with:

- **only the project directory** bind-mounted, at the fixed path `/workspace`.
  Nothing else of the host is visible.
- a **non-root UID** taken from the project directory's owner, so files the
  workload creates are owned correctly on the host and an escape lands on an
  unprivileged user. Under rootless podman the same is achieved with
  `--userns=keep-id`.
- **`--network=none`** by default. Egress is opt-in, per executor.
- **all Linux capabilities dropped** and `no-new-privileges` set, so a setuid
  binary in the image cannot undo the UID choice.
- **`--cpus` / `--memory` / `--pids-limit`**, with swap pinned to the memory
  ceiling so paging cannot evade it.
- a deterministic name, `cloop-<project>-<runID>`, so orphans stay reapable.

**Secrets** (provider API keys, brokered credentials) are injected as
environment at start using the bare `--env NAME` form: the runtime reads each
value from its own environment, so no secret ever appears in the host's process
table. Nothing is baked into an image and nothing is written to the mounted
workdir.

Unlike host execution, a container workload does **not** inherit the control
plane's environment. Forwarding it would hand the sandbox every credential the
server holds, so variables are passed explicitly or not at all.

### What the container sandbox does not do

- **It does not filter egress unless you configure it to.** Anything other than
  `network: none` grants unrestricted outbound access unless the named network
  carries its own policy, and `cloop executor test` warns rather than implying a
  guarantee. Two supported ways to give a sandbox *scoped* network access:
  leave it on `network: none` and grant egress through the broker
  ([Scoped network egress](#scoped-network-egress)), or turn on
  [`egress_filter`](#ip-layer-egress-filtering), which enforces the same
  allowlist at the IP layer. They compose, and the second is what binds a
  workload that ignores the first.
- **It does not pull images.** Runs use `--pull=never` so a cold image cache
  fails immediately with an actionable error instead of turning a UI click into
  a multi-minute hang. Preflight tells you what to pull.
- **It does not enforce disk quotas.** A `DiskMB` request is refused rather
  than accepted and ignored, because writable-layer quotas only work on a
  minority of storage-driver configurations.

`extra_args` is validated: flags that would dismantle the sandbox
(`--privileged`, `--cap-add`, `--volume`, `--network`, `--user`, `--entrypoint`,
`--env`, …) are rejected, and every entry must be a flag in `--flag=value` form
so a bare value cannot be consumed as the image reference.

### IP-layer egress filtering

[Scoped network egress](#scoped-network-egress) below is an HTTP proxy: it
enforces hosts, methods and quotas, and it only ever sees traffic the workload
chose to send it. A harness that opens a raw socket, or runs
`curl --noproxy '*'`, or speaks anything that is not HTTP, walks past all of it.
`egress_filter` is what binds that harness — a packet filter compiled from the
same allowlist, enforced by the kernel rather than by the workload's
cooperation.

The recommended configuration is two lines:

```yaml
executors:
  container:
    enabled: true
    network: bridge
    egress_filter:
      enabled: true
      internal: true
```

`internal: true` puts sandboxes on a runtime network the runtime installs no
route off. Nothing on it reaches the Internet at all, so put the egress broker
on the host and it becomes the only way out — which is what makes the broker's
*host* allowlist meaningful rather than advisory. It needs no `nft`, no
`CAP_NET_ADMIN` and no host privileges of any kind.

Everything else in the section describes **direct** egress, for destinations a
sandbox must dial itself — a Kubernetes API server, an internal registry. That
form installs an nftables ruleset on the sandbox bridge from the host side, so
it needs `nft(8)` on the host and `CAP_NET_ADMIN` in the control plane.

```yaml
executors:
  container:
    network: bridge
    egress_filter:
      enabled: false               # default; see "off by default", below
      internal: false              # route sandboxes through the broker only
      allow_cidrs: []              # ranges a sandbox may dial directly
      allow_ports: []              # required whenever a destination is allowed
      allow_public_internet: false # every address outside the block set
      resolvers: []                # DNS servers it may query directly
      broker: ""                   # egress proxy endpoint, address:port literal
      host_patterns: []            # the L7 allowlist this filter cannot enforce
```

| Key | Meaning |
| --- | --- |
| `enabled` | Turns the filter on. With it off the configured `network` is used as-is and the remaining keys are inert |
| `internal` | Sandboxes join a network with no route off the host. Needs no privileges |
| `allow_cidrs` | Address ranges a sandbox may dial directly (`10.8.0.0/24`). The **only** setting that opens private space, and it opens exactly what it names |
| `allow_ports` | Destination ports every allow above is bounded by. **Required** whenever `allow_cidrs` or `allow_public_internet` is set |
| `allow_public_internet` | Every address outside the block set, on `allow_ports`. This is what a hostname allowlist becomes at layer 3 |
| `resolvers` | DNS servers the sandbox may query directly, as address literals (`10.7.0.10`, or with a port). Opened on UDP *and* TCP |
| `broker` | The egress proxy endpoint, as an `address:port` literal. Only needed alongside direct egress — on an internal network the broker shares the bridge |
| `host_patterns` | Records the L7 allowlist this filter cannot enforce, so the rendered ruleset and the preflight report can name what was widened |

**Off by default, and the default is load-bearing.** Silently firewalling an
existing deployment on upgrade would break it in a way that looks like a network
outage, and a security control that arrives switched on without being asked for
is one operators learn to switch off. Enabling it is a decision, made once, in a
file. Preflight reports the unconfigured case as a *warning* rather than staying
silent, because a driver that says nothing about egress reads as one that
constrains it.

Four rules the section is validated against, all of them refusals rather than
guesses:

- **`allow_cidrs` opens exactly what it names.** Listing `10.8.0.0/24` does not
  lift the block on the rest of `10.0.0.0/8`. A `/0` is refused outright — it is
  not an allowlist entry, it is the removal of the block set — and so is any
  prefix that covers `169.254.169.254` without naming the address exactly.
- **Destinations without ports are an error.** An allow rule with no port
  restriction is a hole, and "they probably meant 80 and 443" is not a decision
  a firewall compiler makes on an operator's behalf.
- **`broker` and `resolvers` take address literals, never names.** A packet
  filter matches addresses, so a name here would be resolved once at
  configuration time and pinned silently — the DNS rebinding hazard the broker's
  own resolve-once discipline exists to prevent.
- **`enabled: true` with `network: none` is refused**, because a workload with
  no interfaces has nothing to filter, and the refusal says which of the two to
  change.

**`host_patterns` cannot be enforced and says so.** `*.github.com` is a name;
names do not exist at layer 3. Direct egress compiled from a host allowlist is
"every public address on `allow_ports`" and nothing narrower is possible. Listing
the patterns here does not enforce them — it makes the compiled policy carry a
warning naming them and what they became, which lands in the nft ruleset as a
comment and in `cloop executor test` as an `egress-scope` finding. If the host
allowlist is the control you are relying on, use `internal: true`.

#### On Kubernetes: a NetworkPolicy per Pod

`executors.kubernetes.egress_filter` compiles the same allowlist into a
`NetworkPolicy` created alongside each Pod and selecting that Pod alone. The
keys differ slightly from the container section — there is no `internal` and no
`broker`, because a Pod's network is the cluster's — and one is new:

```yaml
executors:
  kubernetes:
    enabled: true
    egress_filter:
      enabled: false               # default
      cidrs: []                    # destination ranges (note: not allow_cidrs)
      ports: []                    # required whenever a destination is allowed
      allow_public_internet: false
      resolvers: []                # only when not using cluster DNS
      allow_cluster_dns: true      # UDP and TCP 53 to kube-system; unset means true
```

`allow_cluster_dns` is on unless you set it to `false`, and should stay on: a
default-deny egress policy without it breaks name resolution, and that failure
reads to everyone involved as "the network is broken" rather than "DNS is
denied". It is expressed as a `namespaceSelector` on `kube-system` rather than
an address, because cluster DNS lives on a Service ClusterIP in private space
and which side of the policy the CNI applies its DNAT on varies by CNI.

Off by default for the same reason as the container section, plus one more: an
empty allowlist denies everything, including whatever your harness clones from.
Turning it on wants `cidrs`/`ports` or `allow_public_internet` set alongside it.

Two things it needs from the cluster, neither of which cloop can supply:

- **RBAC.** The executor's identity needs
  `networkpolicies: [create delete list]` in the workload namespace. Preflight
  lists them to prove the leased identity actually has it; a `403` is a `fail`,
  because every `Start` will then refuse rather than run a Pod with unfiltered
  egress. The Helm chart's `executor.kubernetes.rbac.create` grants them.
- **A CNI that implements NetworkPolicy.** flannel does not; Calico, Cilium,
  Antrea and most managed CNIs do. The API server stores the object either way,
  so a cluster with the wrong CNI looks identical to a working one from the
  hub's side. `cloop executor test kubernetes` carries this as a standing
  `egress-enforcement` warning.

A malformed `egress_filter` **disables the Kubernetes executor** rather than
being cleared to a default, with a message naming what would not compile. The
container section is validated the same way but through its driver options, so
a bad value there is a refusal to build the executor rather than a silent
fallback. In the chart, the same settings are
`executor.kubernetes.egressFilter.{enabled,cidrs,ports,allowPublicInternet,resolvers,allowClusterDNS}`.

Preview any of this before writing it, without touching the host:

```bash
cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --format rules
cloop egress firewall --internet --ports 443 --check 169.254.169.254:80
```

See [`cloop egress firewall`](commands.md#cloop-egress-firewall) for the full
command, and [the executor architecture](../architecture/executors.md#sandbox-network-isolation)
for how the two mechanisms are chosen and why the ruleset is installed on the
host side.

### VM-isolated sandboxes: Kata Containers

Everything above confines a workload with namespaces, cgroups and seccomp, on
the **host's kernel**. A kernel bug is therefore a host bug. Two keys move the
boundary up a level by running each workload inside a lightweight VM with a
kernel of its own — [Kata Containers](https://katacontainers.io) — so an escape
reaches the guest kernel and the host's sits behind a hypervisor. Neither key is
set by default, and an empty value is exactly the behaviour every deployment had
before they existed.

**Locally — `executors.container.oci_runtime`.** `runtime:` above picks the CLI;
this picks what that CLI hands each container to, passed through as
`--runtime <name>`:

```yaml
executors:
  container:
    enabled: true
    runtime: docker          # or podman
    oci_runtime: kata-qemu   # kata | kata-qemu | kata-clh | kata-runtime
    image: ghcr.io/blechschmidt/cloop-harness:latest
    cpus: 2
    memory: 2g
    network: none
```

It must be a **registered runtime name, never a path**. docker resolves it
against `/etc/docker/daemon.json` and podman against `containers.conf`, both
root-owned files you already control, so the name is a lookup in a trusted table
rather than a binary the daemon is told to execute as root. Names are validated
for shape only — letters, digits, `.`, `_`, `-`, no path separator, no leading
dash — because operators legitimately register Kata under many names and a fixed
allow-list would reject working hosts.

A value that fails that check **disables the container executor**. It is the one
key here that is not clamped back to its default, because for this field the
default is *weaker*: falling back to runc would turn the VM sandbox you asked
for into a container one while the executor kept running and reporting success.
A hub that starts with one fewer executor is a failure you can see.

Kata needs `/dev/kvm`, and needs it openable by the user cloop runs as.
`cloop executor test <id>` checks both, plus that the CLI actually knows the
name — see [the Kata guide](../guides/kata.md) for installation, the
nested-virtualization prerequisite, and what the checks print.

**On Kubernetes — `executors.kubernetes.runtime_class`.** This sets
`runtimeClassName` on every workload Pod, so kube-scheduler places it on a node
advertising that handler:

```yaml
executors:
  kubernetes:
    enabled: true
    namespace: cloop-workloads
    image: ghcr.io/acme/cloop-harness@sha256:…
    runtime_class: kata          # must already exist in the cluster
    node_selector:
      katacontainers.io/kata-runtime: "true"
    tolerations:
      - key: kata
        operator: Exists
        effect: NoSchedule
```

The three keys travel together in practice. A RuntimeClass names a handler; it
does not by itself keep ordinary workloads off the Kata pool, so those nodes are
conventionally **tainted** — which means Pods need a matching `toleration` to
land there at all, and a `node_selector` to be steered there rather than merely
permitted. Set only `runtime_class` on a tainted pool and Pods stay unscheduled.

cloop does not create the RuntimeClass. It is a cluster-scoped object installed
with the Kata node pool, and the hub deliberately holds no cluster-scoped
authority — so it also cannot preflight it. The name is checked as an RFC 1123
subdomain at startup, which catches a typo against the config line rather than at
someone's first run; a *valid* name for a class that does not exist surfaces at
dispatch, as a Pod that never runs.

The Helm chart's ConfigMap does not render `runtime_class`, `node_selector` or
`tolerations` yet, so a chart-based install sets them in the hub's
`config.yaml` directly.

Only the keys above change; credentials, resources and deadlines are whatever the
executor already had.

In both cases the executor reports the change rather than leaving you to infer
it: `cloop executor list` appends `hypervisor-backed` (and, for the container
driver, names the pair as `docker via kata-qemu`), the Executors tab grows a
**kata / VM** chip, and `cloop hub doctor` reports `virtualized` per executor.
Placement can also *require* it: a workload that does is refused a candidate
sharing the executing machine's kernel, under the constraint `virtualization`,
rather than run on a weaker sandbox than it asked for — see
[Placement](../architecture/executors.md#placement).

### Sandbox image contract

`executors.container.image` must provide:

- the cloop binary at `/usr/local/bin/cloop`;
- the agent harness the project's provider needs (for the default `claudecode`
  provider, the `claude` CLI on `PATH`);
- `git` and a CA bundle;
- a non-root user, since the workload runs as the project directory's owner UID.

`cloop executor test` bind-mounts the control plane's *own* binary read-only at
`/usr/local/bin/cloop`, so the smoke test is meaningful even against an image
that does not yet ship cloop.

### Per-project images: `.cloop/sandbox.yaml`

`executors.container.image` is one image for every project on the hub. A project
needing a different toolchain overrides it from its own repository, without an
operator editing this file:

```yaml
# <project>/.cloop/sandbox.yaml
image: ghcr.io/acme/rust-toolchain:1.79
resources:
  cpu: 4
  memory: 8g
```

The spec is repo-committed and therefore untrusted: it is schema-validated,
every number is clamped to the same bounds as the keys above, and it can only
make a run *more* confined than this file allows — omitting
`capabilities.network` takes the network away, and there is no field that adds
it. A spec asking for something the bound executor cannot do is refused before
the run, with the constraint named.

Full schema, the narrowing rules, per-executor support, and the digest pinning
that keeps a run reproducible: **[Per-project sandbox](sandbox.md)**.

### Image trust: `sandbox.image_policy`

`image:` above is the one field the narrowing rules do not cover, because it is
not a knob on the sandbox — it *is* the sandbox. Constrain which images a
project may name:

```yaml
sandbox:
  image_policy:
    allowed_registries: [ghcr.io]     # also "*.example.com" or "*"
    allowed_repos: [ghcr.io/acme/*]   # optional; empty means any repo there
    require_digest: true              # refuse a reference pinned to a tag
    require_signature: false          # cosign; needs the binary on the hub
```

Matching is on the **parsed** reference, so `ghcr.io` here admits neither
`evil.example/ghcr.io/x` nor `ghcr.io.evil.example/x`, and a Unicode lookalike
of it is refused as malformed. An accepted tag is resolved to a digest and the
digest is what runs. An absent section constrains nothing, which keeps existing
single-machine installs working across an upgrade.

`require_digest` matters most on Kubernetes: the control plane cannot read a
cluster's image store, so an unpinned reference is resolved by a kubelet, on a
node, when it schedules. The [Helm chart](../../deploy/helm/cloop-hub) sets it,
and defaults `allowed_registries` to the registry the hub's own image comes
from.

Rules, denial codes, the cosign contract and the audit record:
**[Image trust policy](sandbox.md#image-trust-policy)**.

### Remote executors (edge devices)

A remote executor runs work on a machine the control plane **cannot dial** —
an edge device behind NAT, a build box on an office network, a laptop on hotel
wifi. The connection is inverted: the device dials out and holds one multiplexed
WebSocket open, so there is no inbound port to forward, no VPN, and no firewall
rule.

Enrollment is therefore a two-step, out-of-band flow. On the control plane
(or in the Executors tab, **+ Enroll device**):

```bash
cloop executor enroll --name edge-1 --ttl 15m
```

It prints a single-use, expiring token and the exact command to paste on the
device — including the control plane's certificate pin, derived automatically
from `ui.tls.cert_file`:

```bash
cloop executor agent --server wss://cloop.example.com/api/executors/connect \
  --token <token> --pin sha256:<base64>
```

The token is **shown once** — only its hash is stored, so it cannot be
recovered. On first connect the device redeems it for a long-lived credential,
persists that 0600 at `~/.cloop/agent.json`, and reconnects with it from then
on. If a token leaks, `cloop executor revoke <id>` (or **Revoke** on the card)
kills it; if it was already redeemed, that revokes the resulting credential too,
drops the device's session, and unbinds every project that pointed at it.

That command runs the agent in the *foreground* and installs nothing. For a
device you intend to keep, install it as a supervised service instead:

```bash
CLOOP_ENROLL_BUNDLE='cloopenroll1.…' sudo -E cloop executor agent install
```

This writes a hardened systemd unit with `Restart=always` and the certificate
pin baked in, creates a dedicated non-login system user, and stores the token in
a `0600` file that the unit references by path — never on the command line,
where `systemctl show` and `ps` would print it. `--output docker` and
`--output shell` cover devices without systemd, `--dry-run` shows the unit
without writing it, and `--uninstall` reverses it idempotently. See
[Installing the agent as a service](../architecture/executors.md#installing-the-agent-as-a-service).

The Executors panel shows a one-command form of the same thing, backed by
`GET /install.sh` on the hub. That route is gated on `executor.manage` and
refuses to answer over plaintext HTTP: its body is piped into a root shell on a
device that does not yet know which control plane to trust.

#### Transport security

A token proves the *device* is authorised. It says nothing about whether the
server that answered is the control plane — so the agent verifies that
independently, before it sends anything:

- **Plaintext is refused.** `ws://` to a non-loopback host fails at startup,
  because the enrollment token and the long-lived credential would both travel
  in the clear and an agent retries forever, making one interception permanent.
  `--insecure-transport` overrides it for links already protected some other
  way, and logs a warning on every connection attempt while it is on.
- **`--pin sha256:<base64>`** requires the server's public key to be exactly the
  expected one, *in addition to* normal certificate-chain verification — never
  instead of it. cloop sets `InsecureSkipVerify` on no outbound dial, and
  `tests/security/transport_test.go` machine-checks that across the agent's
  whole import closure.
- The pin is over the **SPKI** (public key), not the certificate, so a routine
  renewal that reuses the key does not break the fleet. Rotating onto a new key
  does, deliberately — stage it by passing both pins comma-separated until every
  device has crossed over.
- The pin is stored in `~/.cloop/agent.json`, so every reconnect for the life of
  the device is pinned, not just the first one.
- **`--ca-file`** adds a PEM bundle to the trusted roots — the supported way to
  reach a private CA or a `cloop hub tls-init` certificate. There is
  deliberately no flag that disables verification instead.

Read the current pin at any time with `cloop hub pin`.

The agent endpoint deliberately sits outside the dashboard's token/OIDC auth.
Agents are not users: they carry their own scoped, individually revocable
credential rather than one that would grant full UI access. It stays behind the
rate limiter, which is what absorbs an unauthenticated flood of connect
attempts.

### Scoped network egress

A sandbox with `network: none` is safe and, on its own, not very useful: it
cannot fetch a dependency, clone a repo, or call an API. The usual escape is to
give it a real network and hope. `cloop egress` is the alternative — the
control plane lends its own connection, one destination at a time.

The sandbox keeps no route of its own. It reaches the outside world only
through an authenticated forward proxy hosted by the control plane, which
decides per connection:

```bash
cloop egress grant --to project:/srv/app \
    --hosts 'api.github.com,*.githubusercontent.com' --ports 443 \
    --max-down 500m --ttl 8h

cloop egress list                                  # who may reach what, until when
cloop egress test https://api.github.com/rate_limit  # ...and does it actually work?
cloop egress revoke egress_2f1c…                   # withdraw, closing live tunnels
```

Turn the proxy on under `executors.egress`:

```yaml
executors:
  egress:
    enabled: true
    listen_addr: "10.88.0.1:8899"                      # reachable from the sandbox
    advertise_addr: "host.containers.internal:8899"    # what goes into HTTPS_PROXY
    max_session_minutes: 15
    default_max_bytes_down: 1g
```

A grant carries hosts, CIDRs, ports, methods, byte quotas, and a TTL, targeted
with the same `--to` syntax as `cloop secret grant`. Redeeming one mints a
**single-use, per-session credential** — 256 random bits, compared in constant
time, stored only as a SHA-256 — which the workload receives as
`HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`. It never sees the grant itself.

What the proxy enforces:

- **Host, port, and method** are checked before a byte leaves. Methods gate
  plain HTTP only; a CONNECT tunnel's method lives inside TLS and is not
  observable (see below).
- **Resolve-once pinning.** The destination name is resolved exactly once,
  *every* returned address must pass policy, and the dial goes to the resolved
  literal. There is no second lookup for a hostile DNS server to answer
  differently, so rebinding has nowhere to put the second answer.
- **SSRF hard-block.** Loopback, RFC1918, CGNAT, link-local — which is where
  the cloud metadata service at `169.254.169.254` lives — multicast, and
  unspecified addresses are refused *even under `--hosts '*'`*. Reaching one
  requires naming its range in `--cidrs`, so an internal destination is always
  a sentence somebody wrote on purpose. The v4-in-v6 encodings
  (`::ffff:127.0.0.1`, NAT64, `::127.0.0.1`) are unwrapped before the check.
- **Quotas, mid-stream.** An over-budget transfer is cut while it is in
  flight, not flagged after it finishes.
- **TTL, mid-tunnel.** An open tunnel does not outlive its session, including
  when idle.

Every decision — allow and deny — lands in the same hash-chained audit log as
the credential broker, with the identity, task, host, port, byte counts, and
verdict, and no credential material.

**The tunnel is CA-free.** cloop does not terminate, inspect, or re-sign TLS,
and installs no certificate in the sandbox: the workload validates the origin's
certificate itself, exactly as it would without a proxy. That costs visibility
into tunnelled requests, deliberately — a proxy that could read every sandbox's
traffic would be a far more valuable thing to compromise than the credentials
it protects.

Revocation is immediate rather than TTL-bounded, which is the payoff for
brokering a *capability* instead of handing over a token: a leaked PAT cannot
be recalled from a running container, but a proxy session is torn down at the
proxy, mid-tunnel, by the control plane that holds it.

**What the proxy cannot do is bind a workload that does not use it.** Every
check above applies to traffic the harness chose to send through `$HTTP_PROXY`.
Pair it with [`egress_filter`](#ip-layer-egress-filtering) — ideally
`internal: true`, where the proxy is the only address the sandbox can reach at
all — so that the allowlist above is enforced on everything rather than on the
cooperative case.

### Git interception proxy

A sandbox that clones the project and pushes its work back needs a forge
credential, and the branch rule that keeps it inside `cloop/` runs in code the
sandbox itself executes — which makes it a convention rather than a boundary.
`executors.git_proxy` inverts that: the hub keeps the PAT, runs a git smart-HTTP
proxy, and hands the sandbox a session token good for one repository under one
policy. The proxy parses each push's ref-update list and refuses anything outside
the allowlist before presenting the credential upstream.

```yaml
executors:
  git_proxy:
    enabled: true
    listen_addr: "0.0.0.0:8443"                    # where it binds
    advertise_url: "https://hub.internal:8443"     # what the SANDBOX connects to
    cert_file: /etc/cloop/tls/git-proxy.crt
    key_file: /etc/cloop/tls/git-proxy.key
    min_tls_version: "1.2"                         # or "1.3"
    session_minutes: 60                            # 0 means 60; ceiling is 720
    allowed_refs: ["refs/heads/cloop/**"]          # the default
    allow_delete: false
```

- **Off by default.** Interposing a proxy changes the URL sandboxes push to, so
  it is an operator's decision rather than something a config file acquires on
  upgrade. With it off, workspaces are provisioned exactly as before.
- **TLS is required**, and the certificate is validated by *the sandbox's* git,
  not by the hub — a self-signed one needs its CA in the sandbox image. An
  enabled section without both `cert_file` and `key_file` is switched off at
  load rather than serving session tokens in cleartext.
- **`advertise_url` must be reachable from where git runs** — a Kubernetes
  Service for the Pod backend, the hub's address on the link for an edge device,
  or `host.docker.internal` / `host.containers.internal` for a containerised
  agent. Empty falls back to the bound address, which is right only when that
  process shares the hub's network namespace.
- **A session lasts `session_minutes` from dispatch, not for the run.** A run
  that outlives it fails its push.
- Every decision lands in the hash-chained audit log as
  `gitproxy.push_denied`, `gitproxy.push_allowed`, `gitproxy.session_minted`,
  `gitproxy.session_closed`, `gitproxy.fetch` and `gitproxy.rejected`. Alert on
  the first.

The proxy runs inside the hub process — sessions are in memory, so the process
that mints them must be the one that serves them — and there is deliberately no
standalone command. Full design and operations:
[git interception proxy](../git-interception-proxy.md).

### Hardened (enterprise) configuration

By default cloop may run workloads as child processes of the control plane. To
guarantee that the web UI **never** spawns a harness on the host, turn host
execution off:

```yaml
executors:
  allow_host_process: false   # strict no-host-execution mode
  container:
    enabled: true             # …and give it somewhere else to run

sandbox:
  image_policy:               # …and constrain what "somewhere else" may be
    allowed_registries: [ghcr.io]
    require_digest: true
```

or `cloop config set executors.allow_host_process false`.

The image policy belongs in the same breath as the executor. Moving execution
off the host and then letting a repo-committed file choose the image puts the
untrusted code back on the trusted side of the boundary — the container is not
the host, but its contents were still chosen by a pull request.

This is the one setting a hosted deployment must flip. Absent means `true`, so
existing single-machine installs keep working across an upgrade.

With it `false`:

- the `localprocess` driver refuses to start anything;
- `executor.Resolve` refuses to hand that driver out, so background paths are
  covered too, not just the ones with an explicit check;
- every Web UI path that would have dispatched work returns **HTTP 409** with a
  machine-readable `code: host_execution_denied` and a `remediation` string
  naming the executors that *are* available; and
- the Executors tab shows the mode as a banner.

Hardening before any device has enrolled is a supported intermediate state —
remote executors arrive at runtime, not through this file — so the config still
loads and warns rather than refusing to boot.

The policy is a **ratchet**: it can only tighten at runtime. A control plane
manages many projects, each with its own `config.yaml`, and applying them
symmetrically would let a tenant re-enable host execution by editing a file they
control. Loosening requires a restart with a permissive config.

---


## Security Model

### What data leaves the machine

When you run cloop in any AI-powered mode (PM, suggest, explain, etc.) cloop sends
**only the following** to your configured AI provider:

| Data sent | When |
|-----------|------|
| Your project **goal** and **task descriptions** | Every prompt |
| **Step output** from previous tasks (for context) | When building task context |
| **Codebase snippets** injected by `--inject-context` or `cloop context` | When context injection is enabled |
| Git log / diff excerpts | Commands that require them (pr, commit-msg, trace, …) |

**No API keys, passwords, or environment variables** are ever included in prompts.
**No telemetry** is sent to Anthropic or any third party by cloop itself.

### API key storage

| Location | What is stored |
|----------|----------------|
| `.cloop/config.yaml` | API keys (optional — env vars are preferred) |
| Environment variables | Recommended: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN` |
| `.cloop/state.db` | Goal, task list, step outputs — **no API keys** |

**Config file permissions:** cloop writes `.cloop/config.yaml` with mode `0600`
(owner read/write only). On load, cloop warns if the file has world- or
group-readable permissions so you can run `chmod 600 .cloop/config.yaml`.

**Encrypted secrets** (`cloop secret`) are stored in `.cloop/secrets.enc` using
AES-256-GCM and never written to any AI prompt.

### State file integrity (optional HMAC)

Set the `CLOOP_STATE_HMAC_KEY` environment variable to enable HMAC-SHA256
signing of exported state. The `pkg/security` package provides `Sign()` /
`Verify()` utilities; tooling that exports or imports state can use these to
detect tampering.

### Non-interactive access: API tokens

CI jobs, deploy scripts, and edge devices cannot hold a browser session. Give
them a **scoped API token** (`cloop_pat_…`):

```bash
# Read-only, one project, expires in 30 days
cloop hub token create ci-payments --role operator --project payments --expires-in 30d

cloop hub token list              # id, roles, scope, status, last use
cloop hub token list --active     # hide revoked and expired
cloop hub token revoke <id>       # effective on the next request
```

Or use the **Tokens** section of the Secrets panel, or `POST /api/tokens`.
Either way the value is printed **exactly once** — cloop stores a salted hash,
so a lost token is re-minted, never recovered.

A token is not an authorization bypass. It carries roles, and every RBAC check
applies to it exactly as it does to a signed-in user:

| Field | Meaning |
| --- | --- |
| `--role` | roles the bearer acts with (repeatable). You can only grant roles you hold yourself. |
| `--project` | restrict to these projects (repeatable). Out-of-scope projects are reported as nonexistent, not forbidden. |
| `--expires-in` | `90d`, `12h`, an RFC3339 timestamp, or `0` for no expiry. |

Use it as `Authorization: Bearer cloop_pat_…` (or `?token=…` for EventSource).
Minting requires the `token.admin` permission, which only `admin` holds; the
API additionally refuses to issue a token stronger or wider than its creator.
Creation, revocation, and every failed authentication are recorded in the audit
trail (`cloop events`).

### Interactive access: single sign-on and sessions

`ui.oidc.*` configures OpenID Connect for the dashboard. The full setup is in
[the security model](../security/model.md#configuring-oidc-single-sign-on);
these are the keys that govern how long a session lives and how quickly it can
be taken away.

```yaml
ui:
  oidc:
    session_ttl_hours: 24          # absolute ceiling, set at sign-in
    idle_timeout_hours: 8          # ends an unused session sooner
    refresh_interval_minutes: 15   # how often the IdP is re-asked
```

| Key | Default | Range | What it bounds |
| --- | --- | --- | --- |
| `session_ttl_hours` | `24` | `1`–`720` | The hard ceiling. No amount of activity extends it; when it lapses the user signs in again. |
| `idle_timeout_hours` | `8` | `1`–`720`, and never above `session_ttl_hours` | How long a session may go unused. This is the clock that bounds an unattended browser, and usually the one to tighten first — shortening it costs a re-login after a long meeting, while shortening the ceiling interrupts people mid-task. |
| `refresh_interval_minutes` | `15` | `1`–`1440`, or `-1` to disable | Worst-case lag between the identity provider disabling a user and their cloop session ending. Requires `CLOOP_SECRET_KEY`. |

Out-of-range values are clamped rather than rejected, and an
`idle_timeout_hours` larger than `session_ttl_hours` is held down to it — an
idle clock that can never fire would silently remove the protection you
believe is on.

Sessions are stored in the hub's own `state.db` and survive a restart or a
rolling upgrade. The refresh token used for revalidation is sealed with
AES-256-GCM under **`CLOOP_SECRET_KEY`** — the same variable
[`cloop secret`](../guides/secrets.md) uses. Without it cloop does not retain
refresh tokens at all (rather than storing a live credential in plaintext), so
`refresh_interval_minutes` has no effect and IdP-side revocation is
unavailable. `cloop ui` says so at startup and the **Active sessions** panel
shows a banner.

Operators with the `session.admin` permission get an Active sessions table in
the Secrets tab — subject, IP, device, sign-in time, idle time, and a
Terminate button — backed by `GET /api/sessions` and
`DELETE /api/sessions/{id}`. Any signed-in user can end their other sessions
from the header (`POST /api/session/logout-all`). Signing out also redirects to
the provider's `end_session_endpoint` when it advertises one, so the browser's
session at the IdP ends too. Revocation semantics, including what happens when
the IdP is unreachable, are in
[Session lifecycle and revocation](../security/model.md#session-lifecycle-and-revocation).

### Web UI (`cloop ui`)

The web dashboard binds to **localhost only** by default.

> **`--token` / `CLOOP_UI_TOKEN` is deprecated.** It still works and will keep
> working, but it bypasses RBAC entirely, sees every project on the hub, and
> cannot be revoked for one caller without breaking every other. Mint a scoped
> API token per caller (above), then drop the flag and the environment
> variable. `cloop ui` prints a warning at startup while it is still set, and
> the Tokens panel shows a banner. See
> [Migrating off the static token](../security/model.md#migrating-off-the-static-token).

When a `--token` is set:

- Every `/api/*` request must present `Authorization: Bearer <token>` or
  `?token=<token>`.
- Failed authentication attempts are **rate-limited**: after 5 consecutive
  failures from the same IP the endpoint returns HTTP 429 and blocks that IP
  for 60 seconds.
- All responses include hardened HTTP headers:
  - `Content-Security-Policy` — restricts resource loading to same-origin
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
- CORS is restricted to `localhost` / `127.0.0.1` origins only (no wildcard).

### TLS

**Serving.** `cloop ui` and `cloop serve` can terminate TLS themselves, or sit
behind a proxy that does. Both are supported; a *half*-configuration is not —
a certificate without a key (or the reverse) fails at startup rather than
falling back to plaintext, because a server that quietly serves HTTP after
being asked for HTTPS is discovered from a packet capture, if at all.

```yaml
ui:
  external_url: https://cloop.example.com   # also an accepted WebSocket Origin
  allowed_origins: [ops.example.com]        # deployment-wide (dashboard + agents)
  allowed_ws_origins: [legacy.example.com]  # dashboard socket only
  tls:
    cert_file: /etc/cloop/tls/fullchain.pem
    key_file:  /etc/cloop/tls/privkey.pem   # mode 0600
    min_version: "1.2"                      # or "1.3"; 1.0/1.1 are rejected
```

Or per-invocation: `cloop ui --tls-cert <pem> --tls-key <pem>` (the flags
override the config block, as a pair). Only AEAD cipher suites with forward
secrecy are offered — no CBC, no static RSA. For local development,
`cloop hub tls-init` generates a self-signed pair (key written 0600 through
`pkg/atomicfile`, never briefly world-readable) and prints the pin to give
devices.

**HSTS and cookies.** Responses delivered over TLS carry
`Strict-Transport-Security: max-age=31536000; includeSubDomains`, and the OIDC
session cookie becomes `Secure` + `SameSite=Strict`. Both are keyed off the
request's real scheme, so they are also correct behind a TLS-terminating
reverse proxy (`X-Forwarded-Proto`, trusted only from a loopback peer). Neither
is applied on plaintext: HSTS on `http://localhost` would pin a developer's
browser to HTTPS for a year and break every other local project on that
hostname.

**WebSocket origins.** Both the dashboard socket and the executor-agent
endpoint accept an upgrade only from a recognised `Origin` — loopback,
same-origin, `ui.external_url`, or `ui.allowed_origins`. A request with *no*
`Origin` is allowed, because that is what every non-browser agent sends and a
browser cannot suppress the header. A cross-origin upgrade gets 403 with the
reason, before any token is examined — so it cannot burn a single-use
enrollment token on the way to being refused.

The two allowlists differ in blast radius and are deliberately not merged:
`allowed_origins` is deployment-wide and reaches `/api/executors/connect`,
where an entry can open an agent connection; `allowed_ws_origins` is scoped to
the dashboard socket only. Prefer setting `external_url` — it covers the
reverse-proxy case without either list.

Note that same-origin matching falls back to comparing hostnames when the
`Origin` and `Host` ports differ, which is what makes a proxy that rewrites
`Host` work. The consequence is that another *port* on the same hostname counts
as same-origin. If something you do not control is served from the hub's
hostname, set `external_url` and treat that hostname as part of the trust
boundary.

**Outbound.** All three remote providers (Anthropic, OpenAI, custom
OpenAI-compatible) and the executor agent validate certificates against the
system CA pool. There is **no `InsecureSkipVerify` option** in cloop, and
`tests/security/transport_test.go` fails the build if one appears on the
agent's dial path. Reaching a server with a private CA is done by *adding* a
root (`--ca-file`), not by removing verification.

For self-hosted models on plain HTTP (Ollama), set `ollama.base_url` to the
local endpoint. Outbound traffic to Anthropic/OpenAI is always TLS.

### Shell hooks and command injection

Pre/post task hooks (`hooks.pre_task`, `hooks.post_task`, etc.) are **user-
configured shell commands** from `.cloop/config.yaml`. Task context
(title, status, role) is passed as **environment variables** — never
interpolated into the hook command string — so task content cannot inject shell
commands through the hook mechanism.

### Dependency security

cloop uses `govulncheck` (golang.org/x/vuln) for dependency audits. The
`toolchain` directive in `go.mod` pins the minimum Go version to one that
resolves all known stdlib vulnerabilities.

