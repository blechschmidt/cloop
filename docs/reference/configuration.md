# Configuration reference

Executor backends, sandbox settings, transport security and hardening keys for
`.cloop/config.yaml`.

This page is the key-by-key reference. For the concepts, see
[how executors work](../architecture/executors.md),
[what each boundary authenticates with](../security/model.md) and
[granting credentials](../guides/secrets.md).

---

## Per-user state: `CLOOP_HOME`

Most configuration is per project and lives in `.cloop/config.yaml` in the
working tree. A few things are per user and live outside it: the multi-project
registry the dashboard lists, the global budget and cost ledger, named profiles,
and cached provider credentials:

| Path | Contents | Relocated by `CLOOP_HOME` |
| --- | --- | --- |
| `~/.cloop/projects.json` | The multi-project registry: which projects the dashboard shows | **yes** |
| `~/.cloop/profiles.yaml` | Named provider profiles | no |
| `~/.cloop/agent.json` | Remote executor agent credential and pinned certificate | no |
| `~/.cloop/plugins/` | User-level plugins | no |
| `~/.config/cloop/budget.yaml` | Global spend caps | no |
| `~/.config/cloop/costs.jsonl` | Global cost ledger | no |
| `~/.config/cloop/workspaces.json` | Registered workspaces | no |

**`CLOOP_HOME`** replaces `~/.cloop`. Like `CARGO_HOME`, it names the directory
itself, not a home directory that contains it. A relative value is resolved
against the process's working directory, and an empty or whitespace-only value
counts as unset.

```bash
CLOOP_HOME=/var/lib/cloop/alice cloop ui
```

It currently moves only the registry, as the right-hand column shows. Profiles,
plugins and the agent credential still resolve from `$HOME`, so setting
`CLOOP_HOME` alone doesn't give a second hub its own copy of them. To move
everything, set `HOME`. You can then also set `CLOOP_HOME` to put the registry
somewhere else again.

There are two reasons to set it:

- **Running more than one hub under one Unix account.** Without it the hubs
  share a registry, so projects registered in one appear in the other. Members
  of one [hub cluster](../architecture/hub-cluster.md) need that sharing, so
  don't give them different values.
- **Testing.** The registry is process-wide state at a fixed path outside the
  working tree, so a test can leave entries in the real registry of the machine
  it runs on. One dashboard test added an entry to a developer's `projects.json`
  on every run until project index 99 pointed at a deleted directory, which broke
  three unrelated tests on that machine only (CI always starts with an empty
  `$HOME`). cloop's Go tests isolate themselves with `internal/hometest.Isolate`
  in `TestMain`, which redirects `$HOME` and clears `CLOOP_HOME`.
  `tests/hermetic` fails the build if a package that reads `$HOME` and has tests
  doesn't do this.

---

## Background work left by an agent

An agent can start a long job (`nohup python train.py &`, a background build, a
test run it never waits for), exit before the job finishes, and print
`TASK_DONE`. The transcript shows what the agent started but not whether it
finished, so without a check cloop would mark the task complete and run the next
one against output that is still being written. In the case that led to this
check, three tasks in a row worked on a model that the task before them was
still training.

cloop detects this. The `claude` CLI (and the `copilot` CLI, for the
[copilot provider](../getting-started/providers.md#github-copilot)) runs in its
own process group, so cloop can still find anything it started after it exits.
When the harness returns, cloop scans that group:

- **Nothing left running**: the common case. It costs one procfs scan, and the
  task proceeds normally.
- **Something exits within the grace window**: ordinary teardown, ignored.
- **Real background work**: cloop waits until it finishes, then accepts the
  task. The UI and the event log show the wait while it happens.
- **Work outlives the wait**: the task is not accepted as complete, whatever its
  output says. It is marked failed with a diagnosis naming the surviving
  processes, dependent tasks stay blocked, and the leftover processes are
  terminated so a retry can't collide with them.

Configure it under the provider:

```yaml
claudecode:
  background:
    disabled: false      # true restores the old trust-the-transcript behaviour
    grace_seconds: 2     # teardown window before survivors count as real work
    wait_minutes: 30     # how long to wait; negative reports without waiting
    keep_orphans: false  # true leaves survivors running (task still fails)
```

`copilot.background` takes the same four keys for the `copilot` provider.
`grace_seconds` is capped at 120 and `wait_minutes` at 1440. A larger value is
clamped, with a warning.

Raise `wait_minutes` if your tasks are expected to start long jobs. Waiting too
long costs a slow task; waiting too briefly costs a retry of a task that would
have succeeded. Set `keep_orphans: true` only if something outside cloop cleans
up those processes.

**Limit:** a child that calls `setsid()` leaves the process group and is not
detected. This is intended: calling `setsid` is how a process says it means to
outlive its parent, and this check is for work that was meant to be waited for.

---

## Requirement-gated completion (`requirements`)

A project can require its tasks to meet their requirements. With the gate on, a
task the agent reports as done is accepted only once its linked requirements
pass their tests on the project's executor. In `linked+must` mode, every
approved must requirement that has tests has to pass too. The setting is stored
with the project, and `config.yaml` can declare it:

```yaml
requirements:
  gate: linked        # off | linked | linked+must
  assess: false       # ask the model about linked requirements without tests
```

| Key | Default | What it does |
| --- | --- | --- |
| `requirements.gate` | not declared | `cloop run` writes it into the project before it starts. If it isn't declared, the project keeps whatever the dashboard's *Requirements* badge or `cloop requirements gate` set last. A mode this build doesn't know declares nothing (it is not treated as `off`), and every load warns about it. `cloop config set` and `cloop config validate` refuse it. |
| `requirements.assess` | not declared | With the gate on, asks the model about linked requirements that have no tests. One it finds unmet blocks the task. Without it, such requirements are reported as unverified and never block. |

See [Requirement-gated completion](../guides/requirements.md#requirement-gated-completion)
for what a check does, how a task is sent back, and how a regression is
reported.

## Following new builds

A deploy replaces the cloop binary but not the runs started from it, and a run
in auto-evolve doesn't end on its own, so it would keep running its original
build indefinitely. Two settings let a run on this host switch to a newly
deployed build at a task boundary, keeping its process, its pid and the hub's
live log. The runbook's *Long-lived runs after an upgrade* describes what
happens and what each refusal means.

| Setting | Where | Default | What it does |
| --- | --- | --- | --- |
| **Follow New Builds** | Per project: the Overview's Active Options badge, `cloop run --follow-builds` (`=false` to turn off), `POST /api/options/toggle` `{"flag":"follow_builds"}`. Stored in the project's `state.db` (metadata key `follow_builds`), not in `config.yaml` | off | At every task boundary the run checks the binary at the path it was started from. It switches to that binary once it is a different file that has been in place for three minutes (a deploy that fails its health check is rolled back well within that), answers `version --json` with a higher `sequence` and a `schema` at least the database's, and accepts the run's command line. A file it refused isn't checked again until it changes. A failed probe is tried three times. |
| **Adopt at next task boundary** | One-shot, per run: the Overview button, or `POST /api/run/adopt-build` (`run.start`) | — | The same check and switch, once, for the current run, without the three-minute wait but never to a build newer than the hub that asked. The request names that run's process and is cleared once the run has acted on it or refused it. |

Both apply only to host-process runs (the local executor) on Linux. A run in a
container or on a remote device uses the binary its image or agent provides,
and changes when they do: rebuild the image, or upgrade the device from the
Executors panel. For those runs the dashboard says so instead of offering the
button.

What the run records about itself, and where:

- The **run-owner record** (metadata key `run_owner`): pid, start time and boot
  id, host, the path it was started from, executor kind, run id, and its build
  (`version`, `commit`, `sequence`, `schema`), plus `reexecs` and the `previous`
  build once it has switched. Only the run writes it. The dashboard
  (`run_build` in `/api/state`), `cloop status` and `cloop hub doctor`
  (`runs.build_lag`) read it.
- A pending request (metadata key `run_adopt_request`), written only by the hub.
- `CLOOP_RUN_HANDOFF` names `.cloop/run-handoff-<pid>.json`. A run sets it in its
  own environment as it re-executes itself, and the new image reads the file,
  removes it and unsets the variable. Never set it yourself: a process started
  with it skips everything a fresh run does at startup.

A candidate build must report `schema` in `cloop version --json`. Older builds
don't, and are refused.

## Execution Backends (Executors)

An **executor** decides where a cloop workload runs. By default it is a child
process on the same host as cloop, with the same user, filesystem and network.
That is fine on a laptop, but not for a hosted deployment where the agent runs
model-written code on someone else's behalf.

Each project is bound to an executor. If that executor isn't available, the
project's runs fail. They never fall back to running on the host, so an
isolation boundary you chose isn't lost because a backend was unreachable.

| Kind | Isolation | Where it runs | Notes |
|------|-----------|---------------|-------|
| `localprocess` | none | this host | Default. No configuration, no sandbox. |
| `container` | container, or `vm` | this host | Docker/Podman sandbox, enabled in the config. `vm` with a Kata [`oci_runtime`](#vm-isolated-sandboxes-kata-containers). |
| `remote` | remote | an enrolled device | An edge machine that connects out to the control plane. |
| `kubernetes` | remote | an ephemeral Pod | One Pod per workload. Also VM-backed with a Kata [`runtime_class`](#vm-isolated-sandboxes-kata-containers). |

```bash
cloop executor list              # what is registered, and what it isolates
cloop executor ls                # fleet health: state, in-flight work, last seen
cloop executor test <id>         # preflight + run `cloop version` inside it
cloop executor reap <id>         # remove containers/Pods left by a killed control plane
cloop executor cordon <id>       # stop new placement; in-flight work continues; a device's leases come back
cloop executor uncordon <id>     # back in rotation, at the health its probes justify
cloop executor drain <id>        # as cordon, then wait for in-flight to reach zero
cloop executor enroll            # mint a token for a remote device
cloop executor agent --server …  # run *on* the device
cloop executor revoke <id>       # kill a leaked token or a decommissioned device; drops it at once
```

### The Executors panel

The web dashboard has a global **Executors** tab with one card per backend: a
live status dot, a kind badge (host / container / remote), capability chips,
current load, and enroll and revoke actions. Status changes arrive over the
same WebSocket as the rest of the dashboard, without polling.

You choose a project's executor on the **Executor** card of its Overview page,
next to the provider card. A change takes effect on the next run. Work already
in progress stays on the executor that started it.

The tab's banner always shows the effective host-execution mode, so you can see
whether this server may still run a harness on its own host without reading
config files.

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
    extra_args: []           # additional runtime flags; each must start with "-"
    selinux_label: ""        # "z" or "Z" — required when SELinux is enforcing
    orphan_grace_period_seconds: 600   # 0 means 600; see below
    labels:                  # what a grant to label:k=v is matched against
      region: eu
```

Or use `cloop config set executors.container.<key> <value>`. The setter accepts
`enabled`, `id`, `runtime`, `oci_runtime`, `image`, `cpus`, `memory`,
`pids_limit`, `network`, `allow_hosts`, `extra_args` and `selinux_label`.
`orphan_grace_period_seconds`, `allow_root_user` and the whole `egress_filter`
subtree have no setter key, so you edit them in the file.

`labels` are the executor's labels, which a [grant to a label
selector](../guides/secrets.md#label-subjects) is matched against.
`executors.kubernetes.labels` does the same for the Kubernetes executor. Like
the rest of the section, they are read from the configuration the hub starts
with. After a restart that changes them, the leases the hub adopts are checked
against the new labels, and credentials the new labels no longer match are
given back. A key containing a space, `,` or `=`, or a value containing `,`, is
refused by `cloop config validate` and dropped with a warning on load, because
no selector could name it.

`orphan_grace_period_seconds` is how old a running container must be before the
startup sweep and `cloop executor reap` will kill it. Exited containers are
removed immediately, whatever this says.

The grace period is what makes it safe to remove running orphans. A container
listed a moment ago may belong to a control plane that is starting right now,
or to this one in the instant between `run -d` returning and the handle being
recorded, and neither is an orphan. A container that has run untracked for
longer than the grace period has no owner. Zero means the 600-second default,
so an unset field never means "remove on sight". The accepted range is
0–604800 (7 days). A value outside it is reported and reset to the default, not
clamped. `executors.kubernetes.orphan_grace_period_seconds` is the same key,
with the same default and meaning, for Pods.

Ten minutes is far longer than the millisecond race it guards against, which
errs on the safe side: removing an orphan late costs some CPU, but removing one
early kills someone's run. Lower it only on a host where nothing else shares the
container runtime. See
[orphan grace periods](../architecture/executors.md#orphan-grace-periods) for
the other conditions before a running container is touched, and
[after a control-plane restart](../operations/runbook.md#after-a-control-plane-restart)
for the log line that reports one.

Every container is started with:

- **only the project directory** bind-mounted, at the fixed path `/workspace`.
  Nothing else on the host is visible.
- a **non-root UID**, taken from the owner of the project directory, so files
  the workload creates have the right owner on the host and an escape lands on
  an unprivileged user. Under rootless podman, `--userns=keep-id` does the same.
- **`--network=none`** by default. Egress is enabled per executor.
- **all Linux capabilities dropped** and `no-new-privileges` set, so a setuid
  binary in the image can't change the UID.
- **`--cpus` / `--memory` / `--pids-limit`**, with swap set to the memory limit
  so swapping can't get around it.
- a predictable name, `cloop-<project>-<runID>`, so orphans can be found and
  removed.

**Secrets** (provider API keys, brokered credentials) are passed as environment
variables at start, using the bare `--env NAME` form. The runtime reads each
value from its own environment, so no secret appears in the host's process
table. Nothing is baked into an image or written to the mounted working
directory.

Unlike a host process, a container workload doesn't inherit the control plane's
environment, which would hand the sandbox every credential the server holds.
Variables are passed explicitly or not at all.

### What the container sandbox does not do

- **It doesn't filter egress unless you configure it to.** Any `network` other
  than `none` gives unrestricted outbound access unless the named network has
  its own policy, and `cloop executor test` warns about this. There are two
  supported ways to give a sandbox limited network access: keep
  `network: none` and grant egress through the broker
  ([Scoped network egress](#scoped-network-egress)), or turn on
  [`egress_filter`](#ip-layer-egress-filtering), which enforces the same
  allowlist at the IP layer. You can use both, and the filter is what stops a
  workload that ignores the broker.
- **It doesn't pull images.** Runs use `--pull=never`, so a missing image fails
  at once with an error that says what to do, instead of a click in the UI
  hanging for minutes. Preflight tells you what to pull.
- **It doesn't set disk quotas.** Writable-layer quotas work on only a few
  storage-driver configurations, so a `DiskMB` limit (`resources.disk`, or the
  operator's disk ceiling) is enforced by measurement instead. The image's root
  filesystem is read-only and `/tmp` is a capped tmpfs, so the work lands in
  the mounted workspace. The driver measures that tree before the run starts
  and at intervals while it runs, and stops the workload once it is over the
  limit. A burst of writes can overshoot the limit until the next measurement.

`extra_args` is validated. Flags that would undo the sandbox (`--privileged`,
`--cap-add`, `--volume`, `--network`, `--user`, `--entrypoint`, `--env`, …) are
rejected, and every entry must start with `-`, so a bare value can't be taken as
the image reference. Prefer `--flag=value`: only the part before the `=` is
checked against the denylist.

### IP-layer egress filtering

[Scoped network egress](#scoped-network-egress), below, is an HTTP proxy. It
enforces hosts, methods and quotas, but it only sees traffic the workload
chooses to send through it. A harness that opens a raw socket, runs
`curl --noproxy '*'`, or uses a protocol other than HTTP bypasses it.
`egress_filter` covers that case: a packet filter compiled from the same
allowlist and enforced by the kernel, whether or not the workload cooperates.

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

`internal: true` puts sandboxes on a container network with no route off the
host. Nothing on it can reach the Internet, so with the egress broker on the
host, the broker is the only way out, and its host allowlist is actually
enforced. This needs no `nft`, no `CAP_NET_ADMIN` and no other host privileges.

The rest of the section describes **direct** egress, for destinations a sandbox
must connect to itself, such as a Kubernetes API server or an internal registry.
Direct egress installs an nftables ruleset on the sandbox bridge from the host
side, so it needs `nft(8)` on the host and `CAP_NET_ADMIN` in the control plane.

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
      drop_denied: false           # drop denied packets instead of refusing them
```

| Key | Meaning |
| --- | --- |
| `enabled` | Turns the filter on. When it is off, the configured `network` is used as it is and the other keys have no effect |
| `internal` | Sandboxes join a network with no route off the host. Needs no privileges |
| `allow_cidrs` | Address ranges a sandbox may connect to directly (`10.8.0.0/24`). The only setting that opens private address space, and it opens only what it names |
| `allow_ports` | Destination ports that limit every allow rule above. Required whenever `allow_cidrs` or `allow_public_internet` is set |
| `allow_public_internet` | Every address outside the blocked ranges, on `allow_ports`. This is what a hostname allowlist turns into at layer 3 |
| `resolvers` | DNS servers the sandbox may query directly, as address literals (`10.7.0.10`, or with a port). Opened on both UDP and TCP |
| `broker` | The egress proxy endpoint, as an `address:port` literal. Only needed with direct egress; on an internal network the broker shares the bridge |
| `host_patterns` | Records the L7 allowlist this filter can't enforce, so the rendered ruleset and the preflight report can show what was widened |
| `drop_denied` | Drops a denied packet without a reply instead of refusing it. When off, a blocked connection gets a TCP reset or an ICMP "administratively prohibited", so the workload fails at once instead of after its own timeout, and the refusal is logged and shown on the run ([diagnosing a blocked connection](../guides/firewall.md#diagnosing-a-blocked-connection)) |

**Off by default.** Turning a firewall on during an upgrade could break an
existing deployment in a way that looks like a network outage, so you turn it on
yourself, once, in the file. Until then, preflight reports a warning, because
saying nothing would suggest that egress is restricted.

The section is validated against four rules. Each one refuses the configuration
instead of guessing:

- **`allow_cidrs` opens only what it names.** Listing `10.8.0.0/24` doesn't lift
  the block on the rest of `10.0.0.0/8`. A `/0` is refused, because it would
  remove the blocked ranges altogether, and so is any prefix that covers a cloud
  metadata service without naming its address exactly. The services are listed
  in one table (`pkg/cloudmeta`): `169.254.169.254`, AWS's IPv6 `fd00:ec2::254`
  inside `fc00::/7`, Alibaba Cloud's `100.100.100.200` inside `100.64.0.0/10`,
  and the others each cloud publishes. `cloop ui` refuses to start while an
  `allow_cidrs`/`cidrs` entry contains one without naming it. The error names
  the service and the alternatives: add its `/32` to the allowlist, or allow a
  range that leaves it out. `cloop hub doctor` fails the same check
  (`firewall.metadata`). A filter compiled from a stored rule keeps the service
  closed in any case, because it is dropped before the allow rule.
- **Destinations without ports are an error.** An allow rule with no port
  restriction is a hole, and the compiler won't guess ports such as 80 and 443
  for you.
- **`broker` and `resolvers` take address literals, never names.** A packet
  filter matches addresses, so a name would be resolved once when the
  configuration is loaded and then fixed without notice. That is the DNS
  rebinding risk the broker's own resolve-once rule prevents.
- **`enabled: true` with `network: none` is refused**, because a workload with
  no network interface has nothing to filter. The error says which of the two to
  change.

**`host_patterns` can't be enforced, and the output says so.** `*.github.com` is
a name, and names don't exist at layer 3. Direct egress compiled from a host
allowlist is "every public address on `allow_ports`"; nothing narrower is
possible. Listing the patterns here doesn't enforce them. It adds a warning to
the compiled policy that names them and what they became, which appears in the
nft ruleset as a comment and in `cloop executor test` as an `egress-scope`
finding. If you rely on the host allowlist, use `internal: true`.

#### On Kubernetes: a NetworkPolicy per Pod

`executors.kubernetes.egress_filter` compiles the same allowlist into a
`NetworkPolicy` that is created with each Pod and selects only that Pod. The
keys differ slightly from the container section. There is no `internal` and no
`broker`, because a Pod's network belongs to the cluster, and there is one new
key:

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

`allow_cluster_dns` is on unless you set it to `false`, and should stay on. A
default-deny egress policy without it breaks name resolution, which looks like
a broken network instead of blocked DNS. It is written as a `namespaceSelector`
on `kube-system` instead of an address, because cluster DNS runs on a Service
ClusterIP in private address space, and CNIs differ in which side of the policy
they apply DNAT on.

The Kubernetes filter is off by default for the same reason as the container
filter, and also because an empty allowlist denies everything, including
wherever your harness clones from. When you turn it on, also set
`cidrs`/`ports` or `allow_public_internet`.

The filter needs two things from the cluster that cloop can't provide:

- **RBAC.** The executor's identity needs
  `networkpolicies: [create delete list]` in the workload namespace. Preflight
  lists NetworkPolicies to confirm the leased identity has these permissions. A
  `403` is a `fail`, because every `Start` would then refuse to run instead of
  starting a Pod with unfiltered egress. The Helm chart's
  `executor.kubernetes.rbac.create` grants them.
- **A CNI that implements NetworkPolicy.** flannel doesn't; Calico, Cilium,
  Antrea and most managed CNIs do. The API server stores the object either way,
  so from the hub's side a cluster with the wrong CNI looks the same as a
  working one. `cloop executor test kubernetes` always shows this as an
  `egress-enforcement` warning.

A malformed `egress_filter` disables the Kubernetes executor, with a message
naming what wouldn't compile. It is never reset to a default. The container
section is validated the same way, through its driver options, so a bad value
there stops the executor from being built. In the chart, the same settings are
`executor.kubernetes.egressFilter.{enabled,cidrs,ports,allowPublicInternet,resolvers,allowClusterDNS}`.

You can preview any of this before writing it, without changing the host:

```bash
cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --format rules
cloop egress firewall --internet --ports 443 --check 169.254.169.254:80
```

See [`cloop egress firewall`](commands.md#cloop-egress-firewall) for the
command, and [the executor architecture](../architecture/executors.md#sandbox-network-isolation)
for how the two mechanisms are chosen and why the ruleset is installed from the
host side.

#### On Kubernetes: the git proxy's CA, for its URL only

Git in a Pod verifies the certificate of the
[git interception proxy](#git-interception-proxy), and a proxy served under an
in-cluster Service name has a certificate that no public CA issued. On a device
the operator handles this in the image or with `GIT_SSL_CAINFO`. A Pod's spec is
written by the driver, so the driver handles it:

```yaml
executors:
  kubernetes:
    git_ca_bundle:
      config_map: cloop-hub-monitor-ca          # in the workload namespace
      key: ca.crt                                # the default
      urls: ["https://cloop-hub.cloop.svc:8443"] # executors.git_proxy.advertise_url
```

Every Pod mounts the entry read-only at `/etc/cloop/git-ca/ca.crt`, in both the
harness and the workspace provisioner, and git trusts it for the listed URLs
only. This uses `http.<url>.sslCAInfo`, set through the `GIT_CONFIG_COUNT`
protocol and appended to any entries the workload's environment already
numbers. It doesn't use `GIT_SSL_CAINFO`, which replaces git's whole trust
store: a bundle holding only the proxy's CA would break every forge the workload
reaches directly. cloop's own provisioning and write-back git commands run with
a closed environment and import only these keys from it
(`http.<https-url>.sslCAInfo` and `.sslCAPath`).

A hub whose git proxy runs under `tls: auto` needs none of this. Each Pod gets
the hub's own CA from its run's lease Secret, mounted read-only at
`/etc/cloop/hub-ca/ca.crt` in both containers and trusted the same way, for the
proxy's URL only. If a `git_ca_bundle` already names the proxy's URL, the bundle
keeps it (with two `sslCAInfo` values for one URL, git would use whichever came
last), and the hub's CA is delivered for the remaining URLs.

The kubelet fetches the ConfigMap for the Pod, so the executor's Role needs no
rule for it. If the ConfigMap is missing, the Pod stays in `ContainerCreating`
with an event naming it. `config_map` without `urls` is refused, as are URLs
that aren't bare `https://` bases, and an unusable section disables the executor
with the reason, as a malformed `egress_filter` does. The Helm chart renders
this section, and the ConfigMap, from `executor.monitorTLS`; see
[deploy/README.md](../../deploy/README.md#the-git-proxy-and-the-kubernetes-access-monitor).

### VM-isolated sandboxes: Kata Containers

Everything above confines a workload with namespaces, cgroups and seccomp on the
host's kernel, so a kernel bug affects the host. Two keys instead run each
workload in a lightweight VM with its own kernel, using
[Kata Containers](https://katacontainers.io). An escape then reaches the guest
kernel, and the host's kernel is behind a hypervisor. Neither key is set by
default, and an empty value keeps the behaviour from before the keys existed.

**Locally: `executors.container.oci_runtime`.** `runtime:` above picks the CLI.
This key picks the low-level runtime the CLI hands each container to, passed as
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

It must be a registered runtime name, never a path. docker resolves it from
`/etc/docker/daemon.json` and podman from `containers.conf`, both root-owned
files you already control, so the name refers to an entry in a trusted table
and the daemon is never told to run an arbitrary binary as root. Names are checked for
form only (letters, digits, `.`, `_`, `-`, no path separator, no leading dash),
because Kata is registered under many different names and a fixed allowlist
would reject working hosts.

A value that fails that check disables the container executor. Unlike the other
keys here, it isn't reset to its default, because the default is weaker:
falling back to runc would turn the VM sandbox you asked for into a plain
container while the executor kept reporting success. A missing executor is a
failure you can see.

Kata needs `/dev/kvm`, and the user cloop runs as must be able to open it.
`cloop executor test <id>` checks both, and that the CLI knows the runtime name.
See [the Kata guide](../guides/kata.md) for installation, the
nested-virtualization prerequisite, and what the checks print.

**On Kubernetes: `executors.kubernetes.runtime_class`.** This sets
`runtimeClassName` on every workload Pod, so kube-scheduler places it on a node
that offers that handler:

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

In practice you set all three keys together. A RuntimeClass names a handler,
but it doesn't keep ordinary workloads off the Kata nodes, so those nodes are
usually **tainted**. Pods then need a matching `toleration` to run there at
all, and a `node_selector` to be sent there. If you set only `runtime_class` on
a tainted pool, Pods are never scheduled.

cloop doesn't create the RuntimeClass. It is a cluster-scoped object installed
with the Kata node pool, and the hub has no cluster-scoped permissions, so it
can't check it in preflight either. The name is checked as an RFC 1123
subdomain at startup, which catches typos before the first run. A valid name
for a class that doesn't exist shows up at dispatch, as a Pod that never runs.

The Helm chart's ConfigMap doesn't render `runtime_class`, `node_selector` or
`tolerations` yet, so with a chart-based install you set them in the hub's
`config.yaml` directly.

Only these keys change. Credentials, resources and deadlines stay as the
executor already had them.

In both cases the executor reports the change: `cloop executor list` appends
`hypervisor-backed` (and, for the container driver, shows the pair as
`docker via kata-qemu`), the Executors tab shows a **kata / VM** chip, and
`cloop hub doctor` reports `virtualized` per executor. A workload can also
require it. Placement then refuses any executor that shares the host machine's
kernel, under the constraint `virtualization`, instead of running the workload
in a weaker sandbox than it asked for. See
[Placement](../architecture/executors.md#placement).

### Sandbox image contract

`executors.container.image` must provide:

- the cloop binary at `/usr/local/bin/cloop`;
- the agent harness the project's provider needs: the `claude` CLI on `PATH`
  for the default `claudecode` provider, or the `copilot` CLI for `copilot`.
  The default `cloop-harness` image doesn't include `copilot`, so a `copilot`
  project uses the published variant, `ghcr.io/blechschmidt/cloop-harness-copilot`,
  or its own image (see [the published
  images](sandbox.md#the-published-images-and-what-an-image-carries));
- `git` and a CA bundle;
- a non-root user, since the workload runs as the UID that owns the project
  directory.

`cloop executor test` bind-mounts the control plane's own binary read-only at
`/usr/local/bin/cloop`, so the smoke test works even with an image that doesn't
contain cloop yet.

### Per-project images: `.cloop/sandbox.yaml`

`executors.container.image` is one image for every project on the hub. A project
that needs a different toolchain can override it from its own repository,
without an operator editing this file:

```yaml
# <project>/.cloop/sandbox.yaml
image: ghcr.io/acme/rust-toolchain:1.79
resources:
  cpu: 4
  memory: 8g
```

The spec is committed to the repository, so it is untrusted. It is validated
against a schema, every number is clamped to the same bounds as the keys above,
and it can only make a run more restricted than this file allows: leaving out
`capabilities.network` removes the network, and no field adds it. A spec asking
for something the bound executor can't do is refused before the run, with the
constraint named.

For the full schema, the restriction rules, per-executor support, and the
digest pinning that keeps a run reproducible, see
**[Per-project sandbox](sandbox.md)**.

### Image trust: `sandbox.image_policy`

The restriction rules don't cover `image:` above, because the image is the
sandbox's whole environment. To restrict which images a project may name:

```yaml
sandbox:
  image_policy:
    allowed_registries: [ghcr.io]     # also "*.example.com" or "*"
    allowed_repos: [ghcr.io/acme/*]   # optional; empty means any repo there
    require_digest: true              # refuse a reference pinned to a tag
    require_signature: false          # cosign; the published hub image bundles it
    govern_operator_images: false     # also check the operator's own images
```

Matching uses the parsed reference, so `ghcr.io` here admits neither
`evil.example/ghcr.io/x` nor `ghcr.io.evil.example/x`, and a Unicode lookalike
of it is refused as malformed. An accepted tag is resolved to a digest, and the
digest is what runs. Without the section nothing is restricted, so existing
single-machine installs keep working after an upgrade.

On Kubernetes, the hub resolves the tag at the registry the kubelet pulls from
before it builds the Pod, and the Pod carries the digest. See
[`registry_secret`](#resolving-image-tags-for-kubernetes-pods) for the login it
uses with a private registry. There, `require_digest` and `require_signature`
also refuse a tag the hub can't resolve, including the executor's own image;
under other policies such a tag runs as a tag, with a warning. The
[Helm chart](../../deploy/helm/cloop-hub) leaves `require_digest` off, since the
hub pins tags itself, and sets `allowed_registries` by default to the registry
the hub's own image comes from.

The policy applies to the images a project names. The operator's own images
(`executors.container.image`, `executors.kubernetes.image`, a device's or
virtual executor's sandbox image) run as configured, unless
`govern_operator_images: true` holds them to the same registry, digest and
signature rules. cloop's own images are handled separately: whoever chose them,
they are checked against the workflow that publishes them. See
[Image provenance](#image-provenance).

For the rules, denial codes, the cosign requirements and the audit record, see
**[Image trust policy](sandbox.md#image-trust-policy)**.

#### Resolving image tags for Kubernetes Pods

A kubelet acts on a Pod spec later, on whichever node the Pod lands on, and
would resolve a tag in it then. So before building a Pod, the hub resolves every
tag the Pod would carry (the image a project names, `executors.kubernetes.image`,
or one of cloop's own) to the digest the registry serves at that moment. It
verifies that digest's signature when the policy requires it, and writes
`repo@sha256:…` into the spec. The run's log starts with each tag and the digest
it resolved to, and the handle, its stored row and the task's `task.dispatch`
audit row name the digest (`pinned_image`, `image_digest`).

A private registry needs a login. The login belongs to the hub, not the
workload:

```yaml
executors:
  kubernetes:
    registry_secret: ghcr-robot   # a shared registry secret, by name or ID
```

```bash
cloop secret mint ghcr-robot --kind registry --file config.json
```

The secret is the `config.json` that `docker login` writes: a Docker
configuration whose `"auths"` say which registry each login is for. Each login
is sent only to its own registry. For an image on another registry, the hub asks
anonymously. The hub opens the secret as its own credential at every dispatch,
so a rotated secret takes effect on the next Pod. It is not granted to the
executor, because a grant to `executor:<id>` is leased to every run on it and
would put the login in every Pod. Only the shared Docker-configuration form is
accepted: a personal secret is for its owner to use, and a bare `user:password`
names no registry the hub could limit it to. If the secret can't be read,
resolution fails with an error naming it; the hub doesn't fall back to an
anonymous request. The same login is given to cosign when it fetches the
signature from that registry, in a `DOCKER_CONFIG` directory private to the hub
(0700) that holds only that login and is removed when the verification ends.

It is never the namespace's `image_pull_secrets`. Those belong to the kubelet,
for pulling, and the executor's Role grants no access to Secrets.

| The hub couldn't resolve a tag (its registry is unreachable from the hub, refuses, or doesn't know the tag) | |
| --- | --- |
| `require_digest` or `require_signature` | refused, naming the registry and the fix: pin the image by digest, or let the hub reach the registry (with a login in `registry_secret` if it is private) |
| any other policy | the tag goes into the Pod as written, with a warning in the run's log and the hub's; the kubelet resolves it when it pulls |

`cloop executor test kubernetes` and `cloop hub doctor` report `registry-login`
(which registries the secret covers, or why it can't be read) and
`image-resolution` (what `executors.kubernetes.image` resolves to now).

With `image_pull_policy: Never`, whenever the hub could resolve the tag, a node
must hold the image under the digest the tag resolved to. That means pulled from
the registry, not loaded from a tarball, which records no digest.

### Remote executors (edge devices)

A remote executor runs work on a machine the control plane can't connect to: an
edge device behind NAT, a build machine on an office network, a laptop on hotel
Wi-Fi. The device connects out instead and keeps one multiplexed WebSocket
open, so you need no inbound port forwarding, VPN or firewall rule.

Enrollment takes two steps, out of band. On the control plane (or in the
Executors tab, **+ Enroll device**):

```bash
cloop executor enroll --name edge-1 --ttl 15m
```

This prints a single-use, expiring token and the command to paste on the
device, including the control plane's certificate pin, which is derived from
`ui.tls.cert_file`:

```bash
cloop executor agent --server wss://cloop.example.com/api/executors/connect \
  --token <token> --pin sha256:<base64>
```

The token is shown once. Only its hash is stored, so it can't be recovered. On
first connect the device exchanges it for a long-lived credential, saves that
with mode 0600 at `~/.cloop/agent.json`, and reconnects with it from then on.
If a token leaks, `cloop executor revoke <id>` (or **Revoke** on the card)
invalidates it. If it was already redeemed, this also revokes the resulting
credential, drops the device's session, and unbinds every project that used the
device.

`--label region=eu` (repeatable), or the Labels field of the Enroll dialog,
gives the device labels, which a [grant to a label
selector](../guides/secrets.md#label-subjects) is matched against. They are
stored with the device's credential on the hub. An admin can change them later
with **Labels** on the device's card (`PUT /api/executors/{id}/labels`, audited
as `executor.labels`). When they are saved, a running task holding a credential
from a label grant that the new labels no longer match gives it back. Labels the
device reports itself (`cloop executor agent --label`) don't count, and match no
grant.

That command runs the agent in the foreground and installs nothing. For a device
you want to keep, install the agent as a supervised service:

```bash
CLOOP_ENROLL_BUNDLE='cloopenroll1.…' sudo -E cloop executor agent install
```

This writes a hardened systemd unit with `Restart=always` and the certificate
pin built in, creates a dedicated system user that can't log in, and stores the
token in a `0600` file that the unit refers to by path. The token is never on
the command line, where `systemctl show` and `ps` would show it.
`--output docker` and `--output shell` cover devices without systemd,
`--dry-run` shows the unit without writing it, and `--uninstall` removes it (and
is safe to run more than once). See
[Installing the agent as a service](../architecture/executors.md#installing-the-agent-as-a-service).

The Executors panel shows a one-line version of the same thing, served by
`GET /install.sh` on the hub. That route requires `executor.manage` and refuses
to answer over plain HTTP, because its output is piped into a root shell on a
device that doesn't yet know which control plane to trust.

#### Transport security

A token proves the device is authorised. It doesn't prove that the server that
answered is the control plane, so the agent checks that separately before it
sends anything:

- **Plaintext is refused.** `ws://` to a non-loopback host fails at startup.
  Both the enrollment token and the long-lived credential would travel
  unencrypted, and since an agent retries forever, one interception would give
  lasting access. `--insecure-transport` overrides this for links protected in
  some other way, and logs a warning on every connection attempt while it is on.
- **`--pin sha256:<base64>`** requires the server's public key to match the
  expected one, in addition to normal certificate-chain verification. cloop sets
  `InsecureSkipVerify` on no outbound connection, and
  `tests/security/transport_test.go` checks this across all the code the agent
  imports.
- The pin covers the **SPKI** (the public key), not the certificate, so a
  routine renewal that keeps the key doesn't break the fleet. Moving to a new
  key does. To stage that, pass both pins, comma-separated, until every device
  has switched over.
- The pin is stored in `~/.cloop/agent.json`, so every reconnect for the life of
  the device is pinned, not only the first.
- **`--ca-file`** adds a PEM bundle to the trusted roots. This is how you reach a
  server with a private CA or a `cloop hub tls-init` certificate. No flag turns
  verification off.

Read the current pin at any time with `cloop hub pin`.

The agent endpoint isn't behind the dashboard's token or OIDC authentication.
Agents aren't users: each has its own scoped credential that can be revoked
individually, instead of one that would grant full UI access. The endpoint is
still behind the rate limiter, which absorbs floods of unauthenticated
connection attempts.

### Scoped network egress

A sandbox with `network: none` is safe but can't fetch a dependency, clone a
repository or call an API. Instead of giving it a full network, `cloop egress`
lets it use the control plane's connection, one destination at a time.

The sandbox has no route of its own. It reaches the outside world only through
an authenticated forward proxy hosted by the control plane, which decides on
each connection:

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
    listen_addr: "0.0.0.0:8899"           # every interface: a container reaches it at its bridge's gateway
    advertise_addr: "203.0.113.5:8899"    # what a Pod or an edge device is pointed at
    max_session_minutes: 15               # one session period; renewed while the run lives
    dial_timeout_seconds: 15
    default_max_bytes_down: 1g            # quota for a grant that names none
```

| Key | Meaning |
| --- | --- |
| `enabled` | `cloop ui` binds `listen_addr` at startup and hosts the proxy. Off by default |
| `listen_addr` | Bind address. Empty binds an ephemeral loopback port, which only host-process runs can reach. Container sandboxes need `0.0.0.0:<port>` (or the bridge's own address). On every interface, the per-session credential is what protects the proxy |
| `advertise_addr` | The address a **Pod** or an **edge device** connects to. A bare host gets the bound port. Not used for the hub's own containers, which connect to their bridge's gateway |
| `max_session_minutes` | One session period, 15 by default, at most 240. A session is renewed while its run lives, but never past its grant's expiry |
| `dial_timeout_seconds` | Time limit for the proxy's connection to an authorised origin |
| `default_max_bytes_up` / `default_max_bytes_down` | The per-session quota for a grant that names none. A grant's own quota takes precedence |

**What the hub does with it.** `cloop ui` binds the proxy when it starts, before
anything can be dispatched, and logs `egress proxy listening on X, advertised as Y`.
`cloop hub doctor` reports the same line for every running hub, or why its proxy
couldn't bind (`egress.hosted`). A proxy that fails to bind doesn't stop the hub.
Every member of a [hub cluster](../architecture/hub-cluster.md) binds its own
proxy, because a session lives in the memory of the member that issued it, and
the member that dispatches a run issues its session. So in a cluster,
`listen_addr` usually comes from each member's
[per-instance overlay](#two-dashboards-in-one-directory) or uses port 0.
`cloop serve` hosts no proxy (it dispatches nothing to a sandbox), and neither
does `cloop run` on a laptop or an executor agent on a device; a device's
sandboxes use the proxy of the hub that dispatched to them. `cloop egress test`
runs its own proxy for the length of one test.

A session is never shared between processes, and its token is never stored,
but a record of the session is: the token's SHA-256, the grant snapshot, the
deadline and the byte counters, saved in `proxy_sessions` every minute. So a
run that outlives the
process that issued its session (the hub restarted, or another cluster member
took over the run after the dispatching member died) gets its session back. The
process that adopts the run re-reads the grant and restores the session under
the same credential, continuing from the saved totals against the same quota,
never a larger one. If the grant leaves the quota to the defaults above, the
restored quota is the smaller of the one the session was redeemed with and the
current one, and the deadline is capped at the session ceiling, counted from
the restore.
A hub that is stopped cleanly saves and suspends each run's session instead of
closing it; after a SIGKILL, at most a minute of traffic can be missing from the
count. A session whose grant was revoked or expired in the meantime isn't
restored, and its proxy requests are refused (`407`) from then on. If a session
couldn't be restored for a reason that may pass, such as an unreadable grant
store, the restore is tried again after two seconds, then with the wait doubling
up to a minute, and on its next request, until it succeeds or its recorded
expiry passes. Meanwhile the run's history and `cloop hub doctor` report it. A
request made before the run is adopted waits up to 60 seconds for the restore.

The adopting process's proxy serves the restored session at the address the run
was given, so `advertise_addr` must reach that process. On a single hub, that is
the address the restarted process binds again. Egress isn't forwarded between
cluster members, so a session is restored only from a member that is gone. When
a run moves between two live members, the old member keeps serving its egress
session until the run ends (it learns this from the run's owner row) and then
ends the session. Meanwhile the run's owner row keeps naming the session, and
the member that owns the run takes it over if the old member stops first.

**One session per run.** When a run is dispatched (a task run, a helper
subcommand such as `cloop suggest`, or `cloop task reproduce`) and its project
holds an active grant aimed at it (`project:`, `executor:` or `any`; a feature
uses its parent project's grants, never grants for its own path), the hub
redeems one session for it. The session is issued to the run's user and run id,
which every audit row it produces carries. Its quotas are the grant's, or the
defaults above. It lasts one session period and is renewed while the run lives,
never past the grant's expiry. It is closed when the run ends, when the run is
stopped, and when the hub shuts down. Revoking the grant (in the dashboard, with
`cloop egress revoke`, or on another hub member) closes the session within a
minute (at once through the dashboard of the hub holding it) and cuts its open
tunnels. The project's event journal records each of these as an `egress` row.
It also records why a project that holds a grant got no session: the hub has no
proxy, the grant is used up, the run has no network, or the executor has no
route to the proxy. The journal always gives the reason, and never contains a
credential.

**What the workload receives.** `HTTPS_PROXY`, `HTTP_PROXY`, their lowercase
forms, and `NO_PROXY` (loopback plus the hub's own git proxy and Kubernetes
monitor, which git and kubectl would otherwise send through the egress proxy),
along with `CLOOP_EGRESS_SESSION`, `CLOOP_EGRESS_ALLOW`,
`CLOOP_EGRESS_GRANT_ID` and `CLOOP_EGRESS_EXPIRES` (the deadline when the
session was issued; renewals move the real deadline). The proxy variables
contain the session's credential, so they are marked sensitive: they are
scrubbed from the run's live log, artifacts, transcript and provider call log,
left out of the dispatch record the hub stores, and never appear in a journal or
audit row. A harness that honours `HTTPS_PROXY` (Claude Code does, as do git,
curl, and Go's and Node's HTTP clients) sends all of its HTTP through the proxy,
including its own model API calls. So a grant for a sandbox with no other way
out must include the model API's host (`api.anthropic.com`).

**How each executor reaches it.**

| Executor | Address in `HTTPS_PROXY` | Needs |
| --- | --- | --- |
| host process | the bound address (`127.0.0.1` for a wildcard bind) | — |
| container (the hub's engine) | `host.containers.internal`, pinned in the sandbox to the gateway of the bridge it joins, including an `--internal` bridge | `listen_addr` on every interface, or on that bridge's address. A loopback bind is refused, with an error naming the fix |
| Kubernetes | `advertise_addr` (a Service) | the Pod's `NetworkPolicy` must already allow it when `egress_filter` or stored rules apply; the hub checks this before issuing the session |
| remote agent, virtual executor | `advertise_addr` | an address the device can reach. Loopback, link-local, `host.docker.internal`/`host.containers.internal` and cluster-internal names are refused, with a journal row. Behind a device firewall it must be an IP address, and the agent must speak protocol v18 |

**Firewalls open the proxy and nothing else.** When the container executor
installs an nftables ruleset for a sandbox (its own `egress_filter`, or a
[device or project firewall](../guides/firewall.md)), the driver adds the
proxy's address and port (the bridge gateway, TCP, that port only) to the
compiled allow set. Before installing anything, it checks with the policy's own
`Evaluate` that the sandbox can reach the proxy. An operator deny list that
covers the proxy still takes precedence, and then the run is refused instead of
starting with a session it can't use. An `--internal` bridge with no ruleset
needs no opening, because its gateway is on-link. A v18 agent does the same on a
device.

**`.cloop/sandbox.yaml`.** A spec that names a grant in `capabilities.network`
asks for that grant's session. If the hub can't provide it (no proxy, a proxy
that failed to bind, or no route from the bound executor), the run is refused
with a `409` (`sandbox_egress_unavailable`) and the fix, instead of starting
without the egress its author asked for. A spec that names no grant removes the
network, so its runs get no session.

A grant has hosts, CIDRs, ports, methods, byte quotas and a TTL, and is targeted
with the same `--to` syntax as `cloop secret grant`. Redeeming it creates a
**single-use, per-session credential** (256 random bits, compared in constant
time, stored only as a SHA-256), which the workload receives in
`HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`. The workload never sees the grant
itself.

What the proxy enforces:

- **Host, port and method** are checked before any data is sent. Methods apply
  to plain HTTP only, because a CONNECT tunnel's method is inside TLS and can't
  be seen (see below).
- **Resolve-once pinning.** The destination name is resolved once, every
  returned address must pass the policy, and the connection goes to the
  resolved address. There is no second lookup that a hostile DNS server could
  answer differently, so DNS rebinding doesn't work.
- **SSRF hard-block.** Loopback, RFC1918, CGNAT, link-local (where the cloud
  metadata service at `169.254.169.254` lives), multicast and unspecified
  addresses are refused, even under `--hosts '*'`. To reach one, you must name
  its range in `--cidrs`, so an internal destination is always allowed
  explicitly. IPv4-in-IPv6 encodings (`::ffff:127.0.0.1`, NAT64, `::127.0.0.1`)
  are unwrapped before the check.
- **Quotas, mid-stream.** A transfer that goes over quota is cut off while in
  progress.
- **TTL, mid-tunnel.** An open tunnel, even an idle one, ends when its session
  does.

Every decision, allow or deny, is written to the same hash-chained audit log as
the credential broker's, with the identity, task, host, port, byte counts and
verdict, and no credential material.

**The tunnel needs no CA.** cloop doesn't terminate, inspect or re-sign TLS, and
installs no certificate in the sandbox. The workload validates the origin's
certificate itself, as it would without a proxy. The cost is that cloop can't
see inside tunnelled requests, but a proxy that could read every sandbox's
traffic would be a much more valuable target than the credentials it protects.

Revocation takes effect immediately, not at the TTL. That is the advantage of
brokering access instead of handing over a token: a leaked PAT can't be taken
back from a running container, but the control plane can end a proxy session at
the proxy, even mid-tunnel.

**The proxy can't restrict a workload that doesn't use it.** Every check above
applies only to traffic the harness sends through `$HTTP_PROXY`. Combine it with
[`egress_filter`](#ip-layer-egress-filtering), ideally with `internal: true`,
where the proxy is the only address the sandbox can reach, so the allowlist
applies to all traffic.

### Git interception proxy

A sandbox that clones the project and pushes its work back needs a forge
credential, and the rule that keeps its pushes inside `cloop/` branches runs in
code the sandbox itself executes, so the sandbox could ignore it. With
`executors.git_proxy`, the hub keeps the PAT, runs a git smart-HTTP proxy, and
gives the sandbox a session token that works for one repository under one
policy. The proxy parses each push's list of ref updates and refuses anything
outside the allowlist before it presents the credential upstream.

```yaml
executors:
  git_proxy:
    enabled: true
    tls: auto                                      # the hub issues the certificate
    listen_addr: "0.0.0.0:8443"                    # where it binds
    advertise_url: "https://hub.internal:8443"     # what the SANDBOX connects to
    min_tls_version: "1.2"                         # or "1.3"
    session_minutes: 60                            # 0 means 60; ceiling is 720
    allowed_refs: ["refs/heads/cloop/**"]          # the default
    allow_delete: false
    push_scan: values                              # the default; shapes or off
    push_scan_max_object_mb: 1024                  # 0 means 1024; ceiling 65536
    push_scan_max_push_mb: 4096                    # 0 means 4096; ceiling 1048576
    push_scan_seconds: 300                         # 0 means 300; ceiling 3600
```

`cloop hub bootstrap` writes the first eight keys, deriving `advertise_url` from
`--external-url`. The push scan keys keep their defaults.

- **Off by default.** The proxy changes the URL sandboxes push to, so the
  operator turns it on; an upgrade doesn't. With it off, workspaces are
  provisioned as before, and a GitHub grant delivers the forge credential itself
  into the sandbox. On a hub with `allow_host_process: false`, `cloop hub doctor`
  reports this as `gitproxy.forge_credentials`.
- **TLS is required**, because the session token is sent with every request,
  and the certificate is validated by the sandbox's git, not by the hub. There
  are two ways to provide it:
  - **`tls: auto`** has the hub issue the certificate. A CA is created the first
    time any hub process serving this control plane starts a monitor under
    `tls: auto`. Its private key is sealed under the KEK registry in the
    control-plane database (never stored as a separate file), so every
    [hub-cluster](../architecture/hub-cluster.md) member serves the same
    identity, a database backup includes it, and `cloop hub key rotate`
    re-wraps it. The proxy serves a leaf certificate from that CA naming the
    host of `advertise_url` and of `listen_addr` (when it names one), valid for
    72 hours. The cluster leader replaces it when 48 hours are left, and every
    member serves the new one within a minute, per handshake, so a push in
    progress isn't interrupted. Every sandbox the hub dispatches is told to
    trust the CA for `advertise_url` only, through
    `http.<advertise_url>.sslCAInfo` in the `GIT_CONFIG_COUNT` block. It never
    uses `GIT_SSL_CAINFO`, which would replace the image's trust store and trust
    every host the CA signed. No image needs the CA built in: a host process and
    a container get a read-only file, a Pod gets it from its run's lease Secret,
    and an edge device gets it in the start frame (agents speaking protocol v21
    or later). An older agent is refused any workload that would talk to the
    proxy, with an error naming the upgrade, instead of being given the forge
    credential. Needs `CLOOP_SECRET_KEY`; can't be combined with `cert_file`
    and `key_file`.
  - **`cert_file` and `key_file`**, a certificate and key the operator
    provides. A self-signed certificate needs its CA in the sandbox image, or on
    Kubernetes in
    [`executors.kubernetes.git_ca_bundle`](#on-kubernetes-the-git-proxys-ca-for-its-url-only).

  `tls: auto` must be set explicitly; it is never assumed. An enabled section
  with neither `tls: auto` nor certificate files is switched off at load, as in
  older versions, so an upgrade never starts a proxy by itself. `tls: auto`
  together with `cert_file`/`key_file` is refused by `cloop config validate`,
  and at load the files are used and `tls: auto` is dropped.
- **`advertise_url` must be reachable from where git runs**: a Kubernetes
  Service for the Pod backend, the hub's address on the local network for an
  edge device, or `host.docker.internal` / `host.containers.internal` for a
  containerised agent. If it is empty, the bound address is used, which works
  only when that process shares the hub's network namespace.
- **A workspace session lasts as long as its run.** It is created for
  `session_minutes`, renewed by the same amount while the run lives, and closed
  once the run is done with it, so a run longer than `session_minutes` can still
  push its work back. A session that a GitHub lease creates for the workload's
  own git lasts at most `session_minutes` from dispatch.
- **`allowed_refs` is the upper limit for every grant.** A GitHub grant can
  narrow it to particular branches (`--branches`, or **Push to branches** in the
  dashboard) but never widen it. A hub that wants projects to push to branches
  of their own choosing sets it wider, to `["refs/heads/**"]`, and lets each
  grant say which. The proxy is also the only thing that can enforce a grant's
  branch list: without it, such a grant is delivered read-only (`github_app`) or
  not at all (`github_pat`). See
  [limiting pushes to particular branches](../guides/secrets.md#limiting-pushes-to-particular-branches).
- **Every push is scanned for the credentials its run was given** before the
  forge can accept it. `push_scan: values` looks for the exact values the run's
  lease and spec delivered (env values, kubeconfig tokens and client keys,
  registry auth, egress and model relay credentials, GitHub tokens), as
  delivered and base64- and percent-encoded. `shapes` also looks for
  pkg/redact's credential formats. `off` forwards packs without reading them. A
  push that contains a credential is refused with no ref moved, and the error
  names the objects, the grant and the secret, never the value. A project's own
  `.cloop/config.yaml` can set a stricter `push_scan`, never a weaker one. A
  push that inflates past `push_scan_max_object_mb` or `push_scan_max_push_mb`,
  or needs more than `push_scan_seconds` of scanning (time spent waiting on the
  network doesn't count), is refused with an error naming the setting, because a
  scan that gave up hasn't shown the push is clean. An unreadable `push_scan`
  loads as `values`, never as `off`. See
  [the push scan](../architecture/git-proxy.md#the-push-scan).
- Every decision is written to the hash-chained audit log as
  `gitproxy.push_denied`, `gitproxy.push_secret_refused`,
  `gitproxy.push_allowed`, `gitproxy.session_minted`,
  `gitproxy.session_renewed`, `gitproxy.session_closed`, `gitproxy.fetch` or
  `gitproxy.rejected`. Alert on the first two. Under `tls: auto`,
  `hub_ca.minted` and `hub_ca.leaf_issued` record the CA and every certificate
  issued from it.

The proxy runs inside the hub process, because sessions are held in memory and
the process that creates them must also serve them. There is no standalone
command. For the full design and operations, see
[git interception proxy](../git-interception-proxy.md).

### Kubernetes access monitor

A kubeconfig grant is delivered by rewriting the kubeconfig: contexts outside
`--contexts` are dropped, along with the clusters and users nothing references
any more. That controls which clusters the sandbox can reach, and nothing else.
The namespace in a delivered context is only a client-side default
(`kubectl -n kube-system get secrets` ignores it), and a kubeconfig has no way
to express read-only access. Its credential has whatever permissions the
cluster's RBAC gives it, which for a kubeconfig a developer uploaded is often
cluster-admin.

With `executors.kube_guard`, the hub keeps the cluster credential, runs an API
interception proxy, and gives the sandbox a kubeconfig that points at the
monitor, with a short-lived bearer token. Every request is parsed into verb,
group, resource, subresource, namespace and name, and checked against the grant
before the credential is attached.

```yaml
executors:
  kube_guard:
    enabled: true
    tls: auto                                    # the hub issues the certificate
    listen_addr: "0.0.0.0:8444"                  # where it binds
    advertise_url: "https://hub.internal:8444"   # what the SANDBOX connects to
    # or, instead of tls: auto:
    # cert_file: /etc/cloop/tls/kube-guard.crt
    # key_file: /etc/cloop/tls/kube-guard.key
    # ca_file: /etc/cloop/tls/kube-guard-ca.pem  # empty falls back to cert_file
    min_tls_version: "1.2"                       # or "1.3"
    session_minutes: 60                          # 0 means 60; ceiling is 720
    verbs: [get, list, watch]                    # a hub-wide ceiling; omit to let grants decide
    namespaces: ["team-*"]
    resources: ["pods", "configmaps", "apps/deployments"]
    audit_allowed: false                         # true: a row per forwarded request too
```

- **Off by default.** The monitor changes the server a sandbox's `kubectl` talks
  to, so the operator turns it on; an upgrade doesn't. With it off, kubeconfigs
  are minimised and delivered as before.
- **TLS is required.** The session token is sent in an `Authorization` header on
  every request. `tls: auto` has the hub issue the certificate from the same CA
  as the [git proxy's](#git-interception-proxy), for the host of `advertise_url`
  and of `listen_addr`, and embed the CA in every kubeconfig the monitor issues.
  It needs `CLOOP_SECRET_KEY` and can't be combined with `cert_file`, `key_file`
  and `ca_file`. Without `tls: auto`, an enabled section that lacks `cert_file`
  or `key_file` is switched off at load instead of sending tokens unencrypted.
  Either way the sandbox image needs no change: the hub's CA, or `ca_file` (else
  `cert_file`), is embedded in the delivered kubeconfig as
  `certificate-authority-data`. Only that kubeconfig's `kubectl` trusts it, for
  that server; nothing else in the sandbox does.
- **`advertise_url` must be reachable from where `kubectl` runs**, and must be a
  bare `https://` base with no path, because it becomes the kubeconfig's
  `server:`. If it is empty, the bound address is used, which works only when
  the sandbox shares the hub's network namespace.
- **`verbs` is a hub-wide upper limit, not a grant**, and is intersected with
  each grant's own verbs. Empty means no limit: each grant decides, and a grant
  that names no verbs is read-only. Setting it to `[get, list, watch]` means no
  project on this hub can write to a cluster, whatever a grant asks for.
  `namespaces` and `resources` are intersected the same way. If the
  intersection for any of the three is empty, the lease is refused and no
  session is created, because an empty namespace list would otherwise mean "no
  restriction", and narrowing would widen access. Write these as a literal
  superset of every grant, or leave them empty. See
  [the floor](../architecture/kubernetes-access.md#the-deployment-floor-and-the-grant-intersect).
- **`exec`, `attach`, `portforward` and `proxy` are refused for every verb**, and
  no policy can re-enable them: `GET .../pods/x/exec` opens a shell, which is
  not a read. Protocol upgrades are refused; ordinary watches still work.
- **A hub that can't start the monitor refuses kubeconfig leases** instead of
  falling back to delivering the cluster credential. Everything else keeps
  working.
- Every decision is written to the hash-chained audit log as
  `kubeguard.request_denied`, `kubeguard.session_minted`,
  `kubeguard.session_closed` or `kubeguard.rejected`, and counted by
  `cloop_kubeguard_requests_total` and `cloop_kubeguard_denials_total`. Alert on
  the first.
- **`audit_allowed` adds a `kubeguard.request_allowed` row for every forwarded
  request.** It is off by default, because one `kubectl get pods` sends a burst
  of discovery requests and a watch never ends, so those rows would bury the
  denials. Turn it on if the audit trail must show what a sandbox read from the
  cluster.

Like the git proxy, it runs inside the hub process and has no standalone
command. For the full design and operations, see
[Kubernetes access monitor](../architecture/kubernetes-access.md).

### Hardened (enterprise) configuration

By default cloop may run workloads as child processes of the control plane. To
make sure the web UI never starts a harness on the host, turn host execution
off:

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

or run `cloop config set executors.allow_host_process false`.

Set the image policy at the same time. If execution moves off the host but a
committed file can still choose the image, a pull request still decides what
runs inside the container.

A hosted deployment must change this setting. If it is absent, it counts as
`true`, so existing single-machine installs keep working after an upgrade.

With it `false`:

- the `localprocess` driver refuses to start anything;
- `executor.Resolve` refuses to return that driver, so background code paths
  are covered too, not only those with an explicit check;
- every web UI path that would have dispatched work returns HTTP 409 with a
  machine-readable `code: host_execution_denied` and a `remediation` string
  naming the executors that are available; and
- the Executors tab shows the mode in a banner.

You can harden a hub before any device has enrolled. Remote executors are added
at runtime, not through this file, so the config still loads, with a warning,
instead of stopping the hub from starting.

Hardening also means controlling who can reach the hub. A hub without sign-in
listens on `127.0.0.1` only, and refuses an address beyond loopback unless
`ui.allow_unauthenticated_network` is set, which a hosted deployment should
never do. Configure `ui.oidc` before the hub listens on a network. Behind a TLS
proxy on the same host, set `ui.listen: 127.0.0.1` so the plaintext port can be
reached only through the proxy. `cloop hub doctor` checks both (`ui.exposure`);
see [Web UI](#web-ui-cloop-ui).

### Minimum agent build

The oldest cloop build a remote executor agent can run and still receive work,
for the whole fleet:

```yaml
executors:
  min_agent_build: v0.1.0
```

By default it is absent, which means there is no minimum, so existing
deployments place work as before.

The negotiated protocol version doesn't capture most changes between builds. It
changes only when a message frame changes, so two devices can speak the current
protocol and still differ by a year of fixes to things that never cross the
wire. With a minimum, you can stop scheduling onto devices that lack a fix you
have deployed, instead of finding out which ones they are from failures.

A device below the minimum is refused at placement, under the `agent_build`
constraint, with a message naming both versions and the upgrade command, instead
of being selected and then failing at run time. A device that can't show it meets
the minimum (it reports no build, the legacy `1` placeholder, or an unreleased
`dev+g…` build) is refused too, with a message saying which. Container,
Kubernetes and local-process executors are never checked: they run the hub's
own binary and have no separate build to compare.

The value must be a `vMAJOR.MINOR.PATCH` release that can be compared.
`cloop config set` refuses anything else. A bad value in a hand-edited
`config.yaml` doesn't stop the hub from starting, but the Executors tab then
shows a banner saying **no floor is being enforced**, so you know the minimum
isn't in effect.

Like `allow_host_process`, it is applied as a **ratchet**: a hub reads many
tenants' `config.yaml` files, and a file a tenant controls must not be able to
lower a fleet-wide minimum. To lower it, restart with the looser config.

See [Placement](../architecture/executors.md#placement) for how the constraint
is ranked and enforced when scheduling and when binding projects.

### Isolation evidence

What placement does with an executor whose isolation claim has never been
verified:

```yaml
executors:
  isolation_evidence: required   # or warn, the default
```

An executor's `Virtualized` and `KernelIsolated` capabilities come from its
runtime's name: `kata` claims a VM, `runsc` a userspace kernel. The hub checks
the claim by running `cloop isolation-probe` under the runtime when configured
executors are reconciled, at each device's hello, after a runtime change, daily,
and when you press **Re-probe** on the card. It records what the kernel serving
the sandbox reported about itself, compared with the host's own kernel.

| Evidence | A project requiring kernel isolation or virtualization |
| --- | --- |
| verifies the claim | is placed |
| contradicts it (a `kata` that is runc or gVisor, a `runsc` that is runc) | is **refused** under the `isolation_evidence` constraint, naming the evidence, whatever this key says |
| none yet, or the probe couldn't run or was inconclusive | `warn`: placed, with a warning in the run's journal; `required`: refused |

`warn` and `required` are the only values. `cloop config set` refuses anything
else, and an unknown value in a hand-edited file shows a banner on the
Executors tab saying unverified executors are being admitted. Like
`min_agent_build`, it is a **ratchet**: once a hub requires evidence, a tenant's
`config.yaml` saying `warn` doesn't relax it. It is a hub-scope key, so the
per-instance overlay `config.ui-<port>.yaml` can set it for one hub only.

Before turning on `required`, check the Executors panel or `cloop hub doctor`
(`executors.isolation`). A device whose agent predates protocol v26 can't be
probed, so every project requiring isolation on it would be refused until the
agent is upgraded. See [The name is checked](../architecture/executors.md#the-name-is-checked-isolation-evidence).

### Image provenance

What a dispatch does with one of cloop's own images whose signature it couldn't
verify:

```yaml
executors:
  image_provenance: required   # or warn, the default
```

cloop's published images (`ghcr.io/blechschmidt/cloop`, `cloop-harness` and
`cloop-harness-copilot`) are signed keyless by
`.github/workflows/publish-images.yml`, for every digest it pushes. The hub
checks one of them before a sandbox runs it, however it was chosen: as the
default image, configured for an executor, as a device's or virtual executor's
sandbox image, or named by a project. The tag is resolved to a digest (from the
local image store after the pull on the container executor, and at the registry
for a device or a Kubernetes Pod). cosign verifies the digest against that
workflow's identity on `main` or a release tag, and the dispatch names the
digest.

| cosign finds | `warn` (default) | `required` |
| --- | --- | --- |
| the workflow's signature | runs the verified digest | runs the verified digest |
| a signature from anyone else, or bytes that don't match | **refused** | **refused** |
| no signature (an image published before signing began, or pushed unsigned) | runs, with a warning on the run and in `cloop hub doctor` | refused |
| no check possible: no cosign on the hub, the registry or Sigstore unreachable, or an image built locally | runs, with the warning | refused |

On Kubernetes the Pod carries the digest that was checked, whether or not it
verified, so a kubelet pulling later gets that same image. A tag the hub
couldn't resolve runs as the tag, with the warning, unless `required` refuses
it, or `require_digest` or `require_signature` is set (both send no tag to a
Pod). On a device, the start frame names the verified digest, and the device's
engine never pulls: a device with an older copy of the tag refuses to start,
naming `docker pull <digest>`. For an image that couldn't be verified, the
device uses its own copy of the tag, with the warning.

The published hub image includes cosign (v3.1.4, pinned by checksum); elsewhere,
install it on the hub's `PATH`. `cloop hub verify-image <image>` runs the check
by hand, and `cloop hub doctor` reports it as `images.provenance`: whether
cosign is installed and its version, the setting, and what each image in use
resolved to. Before turning on `required`, check that the images in use are
signed. Images published before signing began are not: pull `:edge`, or a
release after v0.0.7. An organisation that rebuilds and signs the images itself
can point the check at its own signer with `CLOOP_PROVENANCE_IMAGES_ISSUER` and
`CLOOP_PROVENANCE_IMAGES_IDENTITY`. These are separate from the release and edge
pins, which they don't change.

Like `isolation_evidence`, it is a **ratchet**: once a hub requires verified
images, a tenant's `config.yaml` saying `warn` doesn't relax it.
`cloop config set` refuses any value other than `warn` and `required`. It is a
hub-scope key, so the
per-instance overlay `config.ui-<port>.yaml` can set it for one hub only.

### Feature bundles

A [feature](../guides/features.md) that runs on an executor isolated from the
hub (a container, a remote device, a virtual executor) is sent there as a git
bundle of its branch, and its run's commits come back as another bundle. This
setting caps the size of both:

```yaml
executors:
  feature_bundle_mb: 32   # the default; at most 128
```

The hub applies the cap when it bundles the branch (falling back to the newest
50 commits, then the newest one, before refusing), the sandbox applies it when
it bundles its own work, and the hub applies it again when that work arrives.
The error says which bundle was too large and names this setting. Values outside
`0..128` are refused when the configuration is loaded; `0` means the default.

### Failover

When an executor stops responding while it holds a run, the hub's supervisor
restarts the run on another executor. This setting limits how many times one
dispatch can be restarted elsewhere:

```yaml
executors:
  failover:
    max_attempts: 2   # the default; 0 = never re-dispatch; at most 10
```

Past the cap, the run isn't dispatched again: its session closes as
`failover_exhausted`, and the tasks it was running fail, with a message naming
every node the run was lost on and when each became unreachable. Separately
from the cap, a task that two or more different executors went down under is
quarantined as a suspected node killer. Its run isn't dispatched again, and the
task runs again only after an explicit reset (`cloop task reset <id>`, or a
reset to pending from the dashboard). `cloop executor list --inventory` lists
the quarantined tasks.

A replacement is dispatched like any run and tracked as the project's run. It
never goes to an executor restricted to an access list. When no replacement is
possible, the project is paused with reason `executor_lost`, naming the
executor.

This is a hub-scope key, read at every failover, so a per-instance overlay can
set it for one hub only, and a change applies without a restart.
`cloop config set` refuses a value outside `0..10`. Such a value written into
the file by hand is reset to the default when the configuration is loaded, with
a warning; it never means "no cap". See
[the failover cap](../architecture/executors.md#the-failover-cap-and-the-node-killer-quarantine-task-20391).

### Returned work held in memory

A remote executor sends a run's work back as a write-back bundle, streamed in
chunks, and a seeded run's project state as one document. The hub holds both in
memory until it collects them. Each is capped per run (a bundle at the cap its
dispatch asked for, a document at 640 KiB), and these two settings cap the
total:

```yaml
executors:
  remote:
    max_pinned_writeback_bytes: 268435456          # per executor; the default, 256 MiB
    max_pinned_writeback_total_bytes: 1073741824   # every executor together; the default, 1 GiB
```

Both are byte counts, not megabytes. Values outside 1 MiB to 64 GiB are refused
by `cloop config set` and `cloop config validate`, and such a value written into
the file by hand is reset to its default when the configuration is loaded, with
a warning; it never means "unbounded". A per-executor budget above the ceiling
is refused too, and lowered to the ceiling at load.

The first is how much one device can make the hub hold, across all the runs it
is returning work for. The second is how much the whole fleet can, and keeps
the hub serving everyone else when several devices misbehave at once. A frame
that would exceed either fails that run's write-back: none of it is kept, the
run's journal names the limit and how much was already held, and work held for
other runs isn't affected. Held work is released as soon as it is collected,
when its run ends without a result that would make it collectable, when the
device is revoked or removed, and fifteen minutes after its run ended if
nothing has collected it. `cloop_writeback_pinned_bytes` and
`cloop_writeback_pinned_bytes_max` report the current level; see
[the metrics](../operations/metrics.md#returned-work-held-in-memory).

Keep `executors.remote.max_pinned_writeback_bytes` at least as large as
`executors.feature_bundle_mb`, or a feature run's work is refused when it
arrives; the Executors panel warns when it isn't. These are hub-scope keys,
read when the hub starts its agent endpoint, so a per-instance overlay can set
them for one hub only, and a change takes effect at the next restart. In a hub
cluster, each member applies them to the memory it holds itself. See
[what a device's returned work may hold](../architecture/executors.md#what-a-devices-returned-work-may-hold-on-the-hub-task-20399).

### Pushing a run's work back

A run on an executor that doesn't share the hub's filesystem (a remote device, a
Pod) works in a clone of the project's repository there. By default its changes
stay there, unless the run's own git pushes them. This setting makes the
executor push them back:

```yaml
executors:
  write_back: push   # the default is unset: no work is pushed back
```

Once a run's workload exits successfully, the executor commits everything the
run changed in the checkout (as git sees it, so `.gitignore` applies) to a new
branch `cloop/run-<UTC time>-<random>`, and pushes it to the project's `origin`
with the workspace's credential. When the
[git proxy](../git-interception-proxy.md) runs, the push goes through the
proxy's pinned session for the workspace, so the proxy's ref policy decides it,
and a write-back after a hub restart is served by the
[restored session](../architecture/git-proxy.md#a-hub-restarted-mid-run). The
project's journal records the branch and commit, or why the push failed, as a
`write_back` row.

It applies to a project whose checkout on the hub has an https `origin` and a
GitHub grant that covers it, on an executor that can return work (a device
whose agent has git). The workspace is fetched at the commit the hub's checkout
records for `origin/<branch>`, which is the base the push is measured from, so
fetch the origin on the hub before a run. A project with no such ref, or no
branch checked out, is dispatched as before, without a write-back, and its
journal says why. The push uses the workspace's git proxy session, which is
renewed while the run lives and closed once its write-back has run, so a run
longer than `executors.git_proxy.session_minutes` can still push its work back.
A value other than `push` is refused by `cloop config validate` and
`cloop config set`. Such a value written into the file by hand is treated as
unset and shown as a warning on the Executors tab. The setting is read from the
hub's own configuration, including its instance overlay, on every dispatch.

It is a hub-scope key: read once at startup, from `config.yaml` with the hub's
overlay merged in.

### Executors that bring their own Claude credential

A `claudecode`, `anthropic` or `copilot` run on an executor isolated from the
hub gets its harness credential (a Claude credential, or a Copilot one for
`copilot`) only through a secret grant. The hub refuses to dispatch a run whose
lease would carry none (`harness_credential_missing`; see [the Claude
credential of a sandboxed run](../guides/secrets.md#the-claude-credential-of-a-sandboxed-run)).
If an executor supplies the credential itself (a device whose agent user is
signed in to `claude`, an image with a key in its environment, a cloud role
behind Bedrock or Vertex), list it here to skip the check for it:

```yaml
executors:
  harness_credential_exempt: [sgx, build-box-2]   # executor IDs
```

It skips nothing on the hub's own host. There, a `copilot` project on a hub with
single sign-on needs a credential for the person each run acts for, because the
only credential the host could supply is the hub's own ([per-person
Copilot credentials](../security/copilot-identity.md)).

Only the check is skipped. The grants such a run holds are delivered as before,
and another user's personal Claude credential is still withheld from it. Only
the hub's own configuration can set this list, because a project's
`config.yaml` is written by whoever can push to the project. An entry that is
empty or contains whitespace is refused when the configuration is loaded.

### The model relay for sandboxed runs

A `claudecode` or `anthropic` run on an executor isolated from the hub (a
container, a Pod, an enrolled device, a virtual executor) gets its Claude
credential as a leased environment variable. The workload then holds the
plaintext credential for the whole run: it can print it, commit it or send it
anywhere, revoking it doesn't remove it from a running device task, and the hub
charges the run's budgets whatever the run reports it spent.
`executors.model_relay` keeps the credential on the hub instead:

```yaml
executors:
  git_proxy:
    enabled: true
    tls: auto                     # the relay rides this listener by default
  model_relay:
    enabled: true
    # listener: git_proxy         # the default; or dashboard
    # models: ["claude-sonnet-*", "claude-haiku-*"]   # default: every Claude model
    # max_output_tokens: 32000    # 0 means 32000
    # upstream_base_url: https://api.anthropic.com
    # hub_credential: ["project:/srv/app", "executor:build-box"]
```

With it on, each such dispatch creates a relay session bound to the run's
secret lease. The sandbox gets `ANTHROPIC_BASE_URL` pointing at the relay and a
`cloop_relay_…` session token in `ANTHROPIC_AUTH_TOKEN` (`ANTHROPIC_API_KEY`,
with the URL ending in `/v1`, for the `anthropic` provider). Every Claude
credential the lease delivered is removed from the sandbox's environment, and
the hub uses it upstream. The session lasts as long as the lease. It is recorded
for the hub process that adopts the run after a restart, renewed by the lease's
keepalive, and ended at once when the lease is released or revoked or its grant
is withdrawn; the run's next model call is then refused with the reason. Any hub
member can serve it. The usage in each response is read from the API's own
counts as it streams through, and charged to the identity that started the run,
in the same `daily_token_budget` and `daily_cost_usd` counters that
[quotas](../security/model.md#quotas-how-much-not-whether) enforce. A call that
would exceed one of them is refused before it reaches the API. See [the Claude
credential of a sandboxed
run](../guides/secrets.md#with-the-model-relay-on-the-claude-credential-stays-on-the-hub)
for what a run and its card show.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Sends the model calls of every `claudecode` and `anthropic` run on an isolating executor through the relay. Off by default, because it changes the endpoint every sandboxed harness talks to; the operator decides whether to turn it on. |
| `listener` | `git_proxy` | Where sandboxes reach it. `git_proxy` serves it on the git interception proxy's listener at `<advertise_url>/_anthropic`, so `executors.git_proxy` must be on; under `tls: auto` the harness gets the hub's CA in a separate file through `NODE_EXTRA_CA_CERTS`. `dashboard` serves it on the hub's own listener at `<ui.external_url>/_anthropic`, which must be `https` with a certificate the sandbox already trusts; nothing is added to the sandbox's trust store. |
| `models` | every Claude model (`claude-*`) | The hub's model allowlist for relayed runs, as globs. A project's maintainers can narrow it for their project from its Claude credential card (`PUT /api/projects/{idx}/model-relay`), but never widen it. A call for any other model is refused before it reaches the API. |
| `max_output_tokens` | `32000` | Clamps `max_tokens` on every relayed call, as the CI relay does. It also lowers an extended-thinking budget that would otherwise end up at or above `max_tokens`, which the API refuses. |
| `upstream_base_url` | `https://api.anthropic.com` | Your own gateway in front of the API: an `https` origin, or loopback, with no path. |
| `hub_credential` | none | Where the hub's own `anthropic.api_key` may be used for a run that has no Claude credential granted: `project:<path>` (a feature through its parent) or `executor:<id>`. It is never a fallback: if nothing is listed, the hub's key is used nowhere. Has no effect until API keys are relayed (see below). |

**Only tested credential kinds are relayed.** A Claude OAuth token (`claude
setup-token`, `CLAUDE_CODE_OAUTH_TOKEN`) is relayed. This was tested on
2026-10-16 with real Claude Code through a hub and an enrolled device, and is
covered by `TestLiveModelRelay`, which relays real calls with a credential of a
given kind. API keys aren't relayed yet. A run with an API key gets its
credential delivered as before; its journal and the `model_relay.not_relayed`
audit row say so, and the project's Claude credential card shows *not relayed*
and why. The same applies to a run on a device whose agent predates protocol
v23, when the relay needs the harness's Node to trust the hub's CA (the
`git_proxy` listener under `tls: auto`): that agent can't pass the CA on, so the
hub records this in the journal and delivers the credential as before. While the
hub's CA is being [rotated](../operations/runbook.md#rotating-the-hub-ca), an
agent older than protocol v25 gets only the active CA for Node, because it can't
take two. Its relayed run therefore trusts only that CA, and holds back an
activation like a run dispatched before the new CA was staged.

**It fails closed.** If the relay should serve a run but can't (it isn't
running, its listener is missing, or its session wasn't created), the dispatch
is refused with the reason, instead of handing the run its credential. The same
happens when the section doesn't load. A `listener`, `models` or
`upstream_base_url` the relay can't use is kept as written and marked, not reset
to a default that would allow more. The hub starts no relay, `cloop hub doctor`
fails `config.repaired`, and every run it would relay is refused until the
section loads. This also applies if the section is edited into a state that
doesn't load while the hub runs.

**Reachability.** On the `git_proxy` listener, the relay uses the same host and
port as the git proxy, so a firewall (a device's, a virtual executor's or a
project's egress rules) that lets a sandbox reach the git proxy also lets it
reach the relay, and nothing else needs allowing. With `dashboard`, the sandbox
must be allowed to reach the dashboard's address instead.

**What Node trusts.** `NODE_EXTRA_CA_CERTS` applies to the whole process: Node
trusts the hub's CA for every TLS connection the harness makes, not only for
the relay's URL, unlike git's per-URL setting. The file holds only the hub's CA,
and the CA's key never leaves the hub. `listener: dashboard` with a publicly
trusted certificate adds nothing at all.

`enabled`, `listener` and `upstream_base_url` are read at startup. `models`,
`max_output_tokens` and `hub_credential` are read on each dispatch while the
hub's configuration keeps the relay on. If you switch it off in the file, a
running relay keeps the section it started with until the restart that stops
it. A project's own `config.yaml` can't set any of these keys.

### Automatic harness installation

A project that uses the `claudecode` provider needs the `claude` CLI wherever it
runs, and a `copilot` project needs the `copilot` CLI. A newly enrolled edge
device has neither, so by default the hub asks the device to install the one a
dispatch needs, using the vendor's official installer, the first time it is
needed:

```yaml
executors:
  auto_install_harness: true    # the default; absent means true
```

The device reports what it did, and the dispatch continues. Turn it off to get
the older behaviour, where the dispatch is refused with a message explaining how
to install the CLI by hand:

```yaml
executors:
  auto_install_harness: false
```

Set it to `false` where you don't want the control plane to download and run a
vendor's shell script: a critical host, an air-gapped site, or anywhere changes
to installed software must be reviewed. It doesn't control what can be
installed; see below.

**What the hub can ask for.** The install frame names a harness, never a URL, a
script, an argv or an interpreter. The table that maps a name to an installer is
compiled into the agent binary on the device. Its entries are:

| Harness   | Installer                                                       |
| --------- | --------------------------------------------------------------- |
| `claude`  | `https://claude.ai/install.sh` (Anthropic's documented install), then `https://downloads.claude.ai/claude-code-releases/bootstrap.sh` |
| `copilot` | `https://gh.io/copilot-install` (GitHub's documented install), accepted only from `raw.githubusercontent.com/github/copilot-cli/` |

The second URL is where the first one redirects to, fetched directly. It is
tried only when the documented URL doesn't serve the script: the claude.ai
website answers many datacenter networks with a Cloudflare bot challenge (HTTP
403), but the download host, which the script downloads the binary from anyway,
doesn't. A cloud VM enrolled as an executor is typically such a machine. A
source refused by a safety rule (a redirect away from `claude.ai`, a downgrade
to plaintext, an oversized response) isn't retried elsewhere; the install stops
and says why.

GitHub's URL also redirects: `gh.io` answers 301 with the script in GitHub's own
`github/copilot-cli` repository on `raw.githubusercontent.com`. That host serves
every repository on GitHub, so allowing the domain alone would admit any user's
script. The entry therefore also pins the repository's path, and a redirect
anywhere else on the host is refused by a safety rule. There is no fallback URL
for it: the cloud VMs that the claude fallback exists for can reach `gh.io`, the
script and the release download it fetches. The script installs into
`~/.local/bin` from the CLI's release on github.com, checking the release's
checksums, and needs `bash`, `curl` or `wget`, `tar` and `gzip`. The CLI unpacks
a runtime of about 250 MB under `~/.cache/copilot` the first time it starts.

So a compromised hub can ask a device to install Claude Code from Anthropic,
and nothing else. The agent downloads the script itself instead of piping
`curl` into a shell. That lets it reject a redirect that leaves the vendor's
domain, limit the response size, and capture the script's output, so a failure
is reported to the hub instead of scrolling past on a machine nobody is logged
in to. `cloop` itself isn't in the table: it already has
[remote upgrade](../architecture/executors.md#upgrading-a-device), which
verifies Sigstore provenance against a pinned identity, and a shell script would
be less secure.

**Where it is installed.** The official installers need no root and write to no
system path: the binary goes to `~/.local/bin/claude` or `~/.local/bin/copilot`.
That directory isn't on a systemd unit's `PATH`, so the agent adds it to its own
environment and to any payload environment that sets an explicit `PATH`. When
debugging, you can read the resolved path in the Fleet panel. A device that
installed the harness but still can't find it reports that instead of success.

**When it is skipped.** In container sandbox mode nothing is installed on the
device's host. The harness comes from the image, which is also how to fix a
device that lacks one. An agent older than protocol v12 doesn't know the install
frame, and gets the plain refusal instead of an error about its version. An
agent built before its table had `copilot` answers that it has no installer for
it, and the refusal includes that answer: upgrade the agent, or install the CLI
on the device by hand.

The setting is a **ratchet**: at runtime it can only be tightened. A control
plane manages many projects, each with its own `config.yaml`, and if any of them
could loosen it, a tenant could re-enable host execution by editing a file they
control. To loosen it, restart with a permissive config.

### Resource ceilings

An upper limit on what any single workload can get, whichever executor runs it:

```yaml
executors:
  limits:
    max_cpu: 4        # cores
    max_memory: 8g    # 512m, 2g, or a bare integer read as megabytes
    max_disk: 20g     # the workspace; see "Disk" below
    max_pids: 2048    # processes/threads
```

Every field is optional. A missing field leaves that resource uncapped, so
adding the section to an existing deployment changes nothing until you set a
key.

This is the only resource setting in the file that is a limit and not a
default. `executors.container.memory` and the Kubernetes requests and limits say
what a workload gets when it asks for nothing, and a project's
[`.cloop/sandbox.yaml`](sandbox.md) overrides them. That is right for a default
but no use as a policy, because the file is committed to the repository by
whoever can push to it. With overrides alone, a project could ask for
`memory: 900g` and get it, limited only by a built-in 1 TiB constant meant to
catch typos.

A ceiling also applies when nothing was requested. In a spec, a missing
`resources.memory` means no limit, not "the default", so a cap that only
lowered stated numbers could be avoided by deleting a line. That is also the
state of every project that has no sandbox spec.

The executor handles that case, in this order: the driver first resolves the
request against its own configured default (`executors.container.memory` and
similar keys), and then applies the ceiling to the result. So a project that
asks for nothing on a hub with `container.memory: 4g` and an 8 GB ceiling still
gets 4 GB, because a ceiling only ever lowers a limit. The ceiling sets a limit
itself only where nothing else did.

Like `min_agent_build`, it is applied as a **ratchet**: a hub reads many
tenants' `config.yaml` files, and otherwise one tenant could raise a cap that
applies to everyone else in the process. To loosen it, restart with the looser
config.

A malformed section doesn't stop the hub from starting, but it sets no ceilings
at all, and a banner says that no ceiling is being enforced. `cloop config set`
refuses a malformed value.

**Disk** (`max_disk`, and the Disk field of an executor's Limits) limits the
workspace: the tree the workload works in, counting what the run adds to its
`.cloop/`. It is applied like memory: a larger `resources.disk` is lowered to
it, and a project that sets none gets it. A Kubernetes executor enforces it by
eviction. A container executor, on the hub or on a device whose agent speaks
protocol v20 or later, measures the workspace while the workload runs and stops
the workload once it is over, which pauses the run with reason `disk_limit`.
This is enforcement by sampling, not a quota: a burst can overshoot by the write
rate times the sampling interval, which is why the
[free-space floor](#free-space-floor) still matters. Where nothing can enforce a
disk ceiling (the host-process driver, a device running payloads on its host, an
agent older than v20), every dispatch says so in the project's journal, and the
executor card shows `disk: not supported`. See
[`resources.disk` and the workspace](sandbox.md#resourcesdisk-and-the-workspace).

**Upgrading from an older build turns these ceilings on.** On a container
executor, older builds recorded no limit for a `max_disk`, or for a Disk value
in an executor's Limits. Current builds refuse runs there that are over it and
stop runs that go past it. A remote device running payloads in a container now
also gets its ceilings (CPU, memory and processes as well as disk) written into
the spec for a project that asked for nothing, where older builds limited only
the project's stated requests. Check the ceilings you have set before
upgrading.

### Per-project resource ceilings

The fleet ceiling applies one limit to everything. To hold a single project
lower (a noisy neighbour, an untrusted tenant), set a ceiling on it directly:

```console
$ cloop hub limits set /srv/projects/noisy --memory 2g --reason "OOMing the box"
$ cloop hub limits list
$ cloop hub limits clear /srv/projects/noisy --reason "moved to its own node"
```

These are stored in the hub's control-plane database, not in any file the
project can reach. A project states what it needs in its own repository, and the
operator states what it may have somewhere the project can't edit.

The two ceilings combine resource by resource, and the lower one applies. The
project can't raise either. A per-project ceiling above the fleet's is stored as
written but has no effect: it is a second limit, never an exemption.

Ceilings are read on every dispatch, so a change applies to the next task that
starts, without a hub restart, and `cloop hub limits` works while a hub is
running. When a ceiling lowers a workload's limits, the project's event log
records the resource, both numbers and which ceiling applied. Otherwise a
sandbox that got 2 GB instead of 8 would look like a slow machine, with nothing
in the repository to explain it.

---


## Security Model

### What data leaves the machine

When you run cloop in any mode that uses a model (PM, suggest, explain and so
on), it sends only the following to your configured provider:

| Data sent | When |
|-----------|------|
| Your project **goal** and **task descriptions** | Every prompt |
| **Step output** from previous tasks (for context) | When building task context |
| **Codebase snippets** injected by `--inject-context` or `cloop context` | When context injection is enabled |
| Git log / diff excerpts | Commands that require them (pr, commit-msg, trace, …) |

API keys, passwords and environment variables are never included in prompts.
cloop itself sends no telemetry to Anthropic or any third party.

A hub with [semantic knowledge search](#semantic-knowledge-search-knowledgeembeddings)
turned on also sends the text of its knowledge chunks, and every knowledge
search query, to the embedding endpoint that `knowledge.embeddings` names. It
is off unless an administrator turns it on.

The hub can collect a diagnostic trail from browsers, but it never leaves the
deployment: your own front ends send it to your own hub, it is stored in your
own database, and credentials are scrubbed on the way in. See
[front-end telemetry](../operations/telemetry.md), including how to turn it
off.

### API key storage

| Location | What is stored |
|----------|----------------|
| `.cloop/config.yaml` | API keys (optional; environment variables are preferred) |
| Environment variables | Recommended: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN` |
| `.cloop/state.db` | Goal, task list, step outputs; no API keys |

**Config file permissions:** cloop writes `.cloop/config.yaml` with mode `0600`
(owner read/write only). On load, it warns if the file is readable by the group
or by others, so you can run `chmod 600 .cloop/config.yaml`.

**Encrypted secrets** (`cloop secret`) are stored in `.cloop/secrets.enc` with
AES-256-GCM and never included in a prompt.

### The root key: `CLOOP_SECRET_KEY`

Every sealed credential, session refresh token and hub CA key, every audit
checkpoint seal and backup sidecar seal, the key escrow and `.cloop/secrets.enc`
are derived from one root secret. The hub and every command read it through one
resolver, from the first of these that is set, and refuse to run if two of them
hold different keys:

| Setting | Holds |
| --- | --- |
| `CLOOP_SECRET_KEY_FILE` | absolute path to a file holding the key: a regular file owned by the hub's user, mode `0400` or `0600`, outside every `.cloop/` directory (one trailing newline is ignored). A Kubernetes Secret volume (owned by root, mode `0440`, readable through the Pod's `fsGroup`) is accepted too, and so is a file owned by root that an ACL lets only the hub's user read, which is how systemd 255 and later pass credentials to a unit with `User=` |
| `$CREDENTIALS_DIRECTORY/cloop-secret-key` | the systemd credential: `LoadCredential=cloop-secret-key:<file>`, or `LoadCredentialEncrypted=` with a file sealed by `systemd-creds encrypt` to the host's credential secret and, where there is one, its TPM |
| `CLOOP_SECRET_KEY` | the key itself, in the environment. Use this only as a last resort: it is readable in `/proc/<pid>/environ` and inherited by child processes |
| `CLOOP_SECRET_KEY_PREVIOUS_FILE`, `cloop-secret-key-previous`, `CLOOP_SECRET_KEY_PREVIOUS` | the key that a [change of root](../operations/runbook.md#changing-cloop_secret_key-itself) is replacing, read the same way. It opens what it sealed and creates nothing new. Refused without a current key, or when it is the current key |

`cloop hub bootstrap` writes the key to `cloop-secret-key` next to `.cloop/`
(`--key-file`), encrypted with `systemd-creds` when the host supports it
(`--systemd-creds auto|always|never`). A running hub resolves the key once at
startup, prints the source and the key's fingerprint, and advertises the
fingerprint to its cluster peers. A changed file takes effect at the next
restart. The hub refuses to start if a live sealing key is derived from neither
configured root. See [the root key](../operations/runbook.md#the-root-key) in
the runbook. With [`secrets.kms`](#sealing-keys-in-a-kms-secrets), the secret
store's keys come from a KMS instead, and the root key seals everything else.

### Sealing keys in a KMS: `secrets`

By default, every key-encryption key (KEK) is derived from `CLOOP_SECRET_KEY`
and a salt stored with it, so the database and the key file together open every
sealed credential, offline, for as long as anyone keeps a copy. With
`secrets.kms`, each KEK is random, and the database keeps only the ciphertext an
external key-management service (KMS) produced from it. Opening the store
requires a call to the KMS, which logs it and whose owner can refuse it.

```yaml
secrets:
  kms:
    provider: kmsv2                 # or transit
    name: azure-prod                # optional; derived from the endpoint or key
    timeout: 5s                     # per call (100ms–1m)
    startup_timeout: 30s            # how long `cloop ui` waits for the KMS (0s–10m)
    kmsv2:
      endpoint: unix:///var/run/kmsplugin/socket.sock
  # previous_root: passphrase       # while moving from CLOOP_SECRET_KEY onto the KMS
  # kms_previous: { … }             # while moving off this KMS, or from one KMS to another
```

| Key | Meaning |
| --- | --- |
| `kms.provider` | `kmsv2`: a [Kubernetes KMS v2](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/) plugin over a unix socket, which covers Azure Key Vault, AWS KMS, Google Cloud KMS and Vault through the plugins their vendors publish for the API server. `transit`: HashiCorp Vault or OpenBao Transit over HTTPS |
| `kms.name` | what the key registry records as each key's root, and what a hub cluster member advertises. Defaults to `kmsv2:<socket path>` or `transit:<host>/<mount>/<key>`; set it if the endpoint may change |
| `kms.kmsv2.endpoint` | the plugin's socket: `unix:///abs/path` or `/abs/path`, nothing else, because a KMS reached over a network would send the keys it unwraps across that network. A socket in a directory all users share (`/tmp`, `/dev/shm`) is refused, because whoever bound it first would receive every key the hub wraps |
| `kms.transit.address` | `https://vault.example.com:8200`; plain `http` only to a loopback host. A redirect to another server is not followed |
| `kms.transit.mount`, `key`, `namespace` | the Transit mount (`transit`), key name, and Vault Enterprise / OpenBao namespace |
| `kms.transit.token_file` | a Vault token, re-read on every call (a Vault Agent sink renews it in place); a file other users can write is refused |
| `kms.transit.kubernetes.role`, `mount`, `token_file` | Vault's Kubernetes auth method instead: logs in as `role` with the service account token at `token_file` (default the Pod's), and again when the lease runs out |
| `kms.transit.ca_file` | a PEM bundle trusted beside the system roots |
| `previous_root` | `passphrase` while moving from `CLOOP_SECRET_KEY` onto `secrets.kms`: the passphrase still opens the keys it derives, and creates nothing new |
| `kms_previous` | a second KMS block: the KMS a change of root is moving off. Its `name` must differ from `kms.name` |

The keyring holds a current root and, during a change of root, a previous one:

| Configured | Current root | Previous root |
| --- | --- | --- |
| nothing | `CLOOP_SECRET_KEY` | none |
| `CLOOP_SECRET_KEY_PREVIOUS` | `CLOOP_SECRET_KEY` | `CLOOP_SECRET_KEY_PREVIOUS` |
| `secrets.kms` | the KMS | none |
| `secrets.kms`, `previous_root: passphrase` | the KMS | `CLOOP_SECRET_KEY` |
| `secrets.kms_previous` | `CLOOP_SECRET_KEY` | the KMS |
| `secrets.kms`, `secrets.kms_previous` | the new KMS | the old one |

There is at most one previous root: two are refused, and so is
`CLOOP_SECRET_KEY_PREVIOUS` together with a KMS root.
`cloop hub key rotate --retire-previous` completes any of these changes; see
[keys in a KMS](../operations/runbook.md#keys-in-a-kms).

This section is hub-scope. The `cloop
hub key` commands and `cloop db restore` read it with the overlay of the hub
their `--port` names, and `cloop ui` reads it with its per-instance overlay
merged in. Every member of a hub cluster opens the same store, so
`config.yaml` is the usual place for it. Nothing falls back. `cloop ui` refuses
to start with a section it doesn't accept, and, after waiting
`startup_timeout`, with a KMS it can't reach. A key that no configured root
opens still stops the hub from starting. With a KMS as the current root, the
store doesn't need `CLOOP_SECRET_KEY`, but the key still seals the audit
checkpoints, backup sidecars and the escrow.

### State file integrity (optional HMAC)

Set the `CLOOP_STATE_HMAC_KEY` environment variable to sign exported state with
HMAC-SHA256. The `pkg/security` package provides `Sign()` / `Verify()`, which
tools that export or import state can use to detect tampering.

### Non-interactive access: API tokens

CI jobs, deploy scripts and edge devices can't hold a browser session. Give them
a **scoped API token** (`cloop_pat_…`):

```bash
# Read-only, one project, expires in 30 days
cloop hub token create ci-payments --role operator --project payments --expires-in 30d

cloop hub token list              # id, roles, scope, status, last use
cloop hub token list --active     # hide revoked and expired
cloop hub token revoke <id>       # effective on the next request
cloop hub token approve <id>      # a token minted while no role policy was in force
```

You can also use the **Tokens** section of the Secrets panel, or
`POST /api/tokens`. Either way, the value is shown once. cloop stores only a
salted hash, so a lost token can't be recovered; you create a new one instead.

A token doesn't bypass authorization. It carries roles, and every RBAC check
applies to it as it does to a signed-in user:

| Field | Meaning |
| --- | --- |
| `--role` | roles the bearer acts with (repeatable). You can only grant roles you hold yourself. |
| `--project` | restrict to these projects (repeatable). Out-of-scope projects are reported as nonexistent, not forbidden. |
| `--expires-in` | `90d`, `12h`, an RFC3339 timestamp, or `0` for no expiry. |

Send it as `Authorization: Bearer cloop_pat_…` (or `?token=…` for
EventSource). Creating a token requires the `token.admin` permission, which only
`admin` holds, and the API also refuses to issue a token with more authority or
a wider scope than its creator. Creation, revocation and every failed
authentication are recorded in the audit trail (`cloop events`).

With single sign-on and no role policy, every signed-in identity holds every
role, so a token created from the dashboard in that state is only as
trustworthy as whoever was signed in. The hub records which policy applied when
each token was created. Once a role policy is in force, it refuses a token
created without one (or before the hub recorded this) until an administrator
approves it, with **Approve** in the tokens section (the approver must hold
every role the token carries) or `cloop hub token
approve <id>`. Such a token is listed `suspended`. A token that acts for an
owner, such as a glasses link, never is. The enforce prompt in Settings lists
every token it will suspend, and `cloop hub doctor` fails
`api_tokens.unapproved` while any remain.

### Audit-trail retention

The hash-chained audit trail only grows. `audit:` limits it. It is off by
default, because deleting from a compliance record on a schedule nobody chose is
worse than the disk space it saves.

```yaml
audit:
  retention_days: 90              # 0 or absent: keep everything
  export_dir: /srv/audit-archive  # default: .cloop/audit-archive
  prune_on_maintain: true         # apply it during `cloop db maintain`
```

| Key | Default | Range | What it does |
| --- | --- | --- | --- |
| `retention_days` | `0` (disabled) | `1`–`3650` | How long rows stay in the database. Older rows are archived, then removed, never deleted outright. Out-of-range values fall back to `0`, not to a default window. |
| `export_dir` | `.cloop/audit-archive` | — | Where sealed prefixes are written. Put it on storage the hub doesn't otherwise control, so the archive can be compared with a database an attacker may have edited. |
| `prune_on_maintain` | `false` | — | Lets `cloop db maintain` apply the window before it runs VACUUM, so the freed pages are returned to the filesystem. Otherwise only `cloop hub audit prune` applies it. |

The procedure, what an anchor is, and why a pruned chain still verifies are in
[the runbook](../operations/runbook.md#retention-keeping-the-trail-bounded).

### Audit head checkpoints

A hash chain reveals edits anywhere, and deletions anywhere except at the newest
end: if the newest rows are deleted, the rest still verify. With
`audit.checkpoints`, the hub records how long each chain was, somewhere the
database can't reach. It is on by default, writing to stderr.

```yaml
audit:
  checkpoints:
    interval: 5m                                  # default 5m
    file: /var/log/cloop/audit-checkpoints.jsonl  # optional; outside .cloop/
    stderr: true                                  # default true
```

| Key | Default | Range | What it does |
| --- | --- | --- | --- |
| `interval` | `5m` | `1m`–`24h` | How often the cluster leader writes one record per chain: the control plane's every time, and a project's when its head has moved (and at least daily). Windows are numbered by the clock and claimed in a marker the control plane holds, so a leader change never writes a window twice. If a leader dies between claiming a window and writing it, the next leader writes it (late, if the window has ended by then) instead of skipping it. A value that doesn't parse, or is outside the range, runs at the default. |
| `file` | — | absolute path | Appended to and fsynced, one JSON record per line, mode 0600. Must be outside every `.cloop/` directory, after resolving symlinks, and its directory must exist: cloop doesn't create it, so a missing directory causes an error. An unmounted mount point is still an existing, empty directory, so put the file in a subdirectory that exists only on the mounted volume (`/mnt/audit/cloop/`, not `/mnt/audit/`), or the records end up on the root disk underneath. A path that breaks these rules is dropped at load with a warning; `cloop config set` and `cloop config validate` refuse it. Put it on storage the database doesn't share. |
| `stderr` | `true` | — | Prints each record as one JSON line on the hub's stderr, for a container platform's log pipeline to send off the machine. With `false` and no `file`, no checkpoints are written and `cloop hub doctor` warns. |

Each record holds the chain (`control-plane` or `project`), the database path,
the newest row's id and hash, the row count, the newest prune anchor and whether
the hub verified that anchor's archive (it reads each new anchor's archive
once), the time, and the hub member that wrote it. It is sealed with HMAC-SHA256
under a key derived from `CLOOP_SECRET_KEY` with its own label, and stamped with
the key's fingerprint. Without `CLOOP_SECRET_KEY` the records are unsigned. The
leading hub also writes every chain at a clean shutdown. Check the chains
against the records with `cloop hub audit verify --checkpoints <file>`; the
[runbook](../operations/runbook.md#checkpoints-catching-a-shortened-trail) lists
what it can detect. Like the rest of `audit`, the section is read from the hub's
effective configuration, including its overlay, at every window.

### Audit forwarding (`audit.forward`)

Checkpoints record how long each chain is. `audit.forward` sends the rows
themselves off the hub as they are written. The cluster leader follows every
chain (the control plane's and each registered project's) and sends each row to
every sink. It advances a cursor per sink and chain in the control plane only
after the sink acknowledges. It is off unless sinks are listed.

```yaml
audit:
  forward:
    hostname: hub-prod-1
    max_lag: 15m
    sinks:
      - name: siem
        type: syslog
        address: siem.corp.example:6514
        format: json
        ca_file: /etc/cloop/siem-ca.pem
        client_cert: /etc/cloop/hub-client.pem
        client_key_secret: siem-client-key
      - name: splunk
        type: https
        variant: splunk_hec
        url: https://splunk.corp.example:8088/services/collector/event
        token_secret: splunk-hec
      - name: archive
        type: file
        path: /mnt/audit/cloop/audit.jsonl
```

| Key | Default | Range | What it does |
| --- | --- | --- | --- |
| `hostname` | the host name | printable ASCII, no spaces | Names this hub in what it sends: the syslog HOSTNAME, `hub` in every JSON record, the HEC `host`, the CEF `dvchost`. The host name follows the cluster leader, so a cluster should set it. |
| `max_lag` | `15m` | `1m`–`168h` | How old the oldest row a sink has not acknowledged may be before `cloop hub doctor` and `cloop hub audit forward status` report the sink. |
| `sinks` | — | at most 16 | The destinations. Each is described below. |

Every sink:

| Key | Default | What it does |
| --- | --- | --- |
| `name` | required | Lower-case letters, digits, `-`, `_`, at most 32. Identifies the sink's cursors, its metric label and its rows in the audit trail; renaming a sink restarts it from `start`. |
| `type` | required | `syslog`, `https` or `file`. |
| `format` | `json` | `json` (the `cloop audit-log export --format jsonl` record, with `source`, `dir` and `hub`) or `cef` (the export's CEF line). An `https` sink sends `json`. |
| `batch_size` | `500` | Rows read, sent and acknowledged as one, `1`–`5000`. |
| `timeout` | `30s` | How long one send may take, `1s`–`10m`. |
| `start` | `oldest` | Where the sink starts on a chain it has never sent: every row still in the database, or `latest`, the chain's head when the forwarder first sees it. |
| `ca_file` | — | A PEM bundle added to the system roots for this sink. |
| `client_cert`, `client_key_secret` | — | Mutual TLS: the certificate file, and the secret holding its private key. Both or neither. |
| `server_name` | from the address | The name the receiver's certificate is checked against. |
| `allow_plaintext_loopback` | `false` | Acknowledges a plaintext sink (`transport: tcp`, an `http://` URL) to a loopback address. Plaintext to any other address is refused whatever this says. |

`syslog` sinks send RFC 5424 messages in RFC 5425 octet-counted framing:

| Key | Default | What it does |
| --- | --- | --- |
| `address` | required | `host:port` of the receiver; 6514 is the registered port for syslog over TLS. |
| `transport` | `tls` | `tls`, or `tcp` to a loopback collector with `allow_plaintext_loopback`. |
| `facility` | `local0` | A syslog facility name: `auth`, `audit`, `local0`–`local7`, … |
| `app_name` | `cloop` | The APP-NAME field, at most 48 characters. |
| `max_message_bytes` | `8192` | `2048`–`1048576`. A row larger than this is sent with its payload left out, and the record says so. |

A syslog batch counts as acknowledged once the receiver's TCP stack has
acknowledged every byte on a connection it hasn't closed, because the protocol
has no acknowledgement of its own.

`https` sinks send one POST per batch:

| Key | Default | What it does |
| --- | --- | --- |
| `url` | required | `https://…`, or `http://` to a loopback collector with `allow_plaintext_loopback`. Must not carry `user:password@`, or a query parameter whose name reads as a credential (`token`, `key`, `secret`, `sig`, `auth`, …). |
| `variant` | NDJSON | `splunk_hec` wraps each record as a HEC event and checks the reply's `code`. |
| `token_secret` | — | The secret holding the token presented in `Authorization`. Required for `splunk_hec`. |
| `auth_scheme` | `bearer` | `bearer`, `apikey` (Elasticsearch), `basic` (the secret holds `user:password`) or `splunk`; `splunk_hec` always uses `splunk`. |
| `splunk_index`, `splunk_sourcetype`, `splunk_source` | token default, `cloop:audit`, `cloop` | The HEC envelope's fields. |
| `max_batch_bytes` | `1048576` | `65536`–`67108864` bytes per POST; a batch always carries at least one row. |

A batch is acknowledged by a 2xx (and, for HEC, `code` 0). A redirect is a
failed send, never followed, and no proxy from the environment is used.

`file` sinks append to the file and fsync it after each batch, mode 0600:

| Key | Default | What it does |
| --- | --- | --- |
| `path` | required | An absolute path outside every `.cloop/` directory, after resolving symlinks. Its directory must exist (the sink never creates it), so put the file in a subdirectory that exists only on the mounted volume: an unmounted mount point is an existing, empty directory. |

Secrets are referenced by name, never written here: a shared `env` secret in the
hub's secret store (`cloop secret mint <name> --kind env --file …`), as `name`,
or `name#KEY` for one key of a secret holding several. A sink that fails
validation (plaintext off the host, a file inside `.cloop/`, credentials in a
URL, a missing field) is dropped at load and recorded as switched off;
`cloop hub doctor` fails it, and `cloop config set` and `cloop config validate`
refuse it. Every member of a hub cluster must run the same section, because only
the leader forwards, using its own configuration. Keep it in `config.yaml`, or
in the same overlay on every member. Changes are recorded as
`audit.forward.configured` rows. The hub reads a sink's secrets when it starts
the sink, after a failed send, and at least hourly. The procedure, delivery
semantics and SIEM examples are in
[the runbook](../operations/runbook.md#forwarding-the-trail-off-the-box).

### Approval notifications (`notifications`)

Two kinds of decision wait for someone allowed to make them: a self-service
grant request, which needs a holder of `secret.grant` (and an administrator for
a request aimed at every project or executor), and an API token that a role
policy suspends until an administrator approves it. The dashboard's header
counts what is waiting for whoever is signed in, and its inbox lists it; see
[the secrets guide](../guides/secrets.md#approvals-the-inbox-and-notifications).
`notifications:` sends the same news to where approvers already are. The
cluster leader posts once per cluster: when a request is filed, 12 hours before
it lapses, when it is approved, denied, withdrawn or lapses, and when a token
starts waiting. It is off unless webhooks are listed.

```yaml
notifications:
  dashboard_url: https://hub.example.com
  webhooks:
    - name: approvers
      type: slack
      url_env: CLOOP_NOTIFY_APPROVERS      # the hub's environment holds the URL
    - name: security-team
      type: teams
      url_env: CLOOP_NOTIFY_SECURITY
      events: [request.filed, request.reminder, token.waiting]
    - name: ticketing
      type: json
      url: https://hooks.corp.example/cloop/approvals
      allow_addresses: [10.20.0.15]       # the receiver is on the internal network
      ca_file: /etc/cloop/corp-ca.pem
```

| Key | Default | What it does |
| --- | --- | --- |
| `dashboard_url` | `ui.external_url`, then the origin of `ui.oidc.redirect_url` | The address every message links to, opened on the approvals inbox (`/?approvals=1`). With none of the three, messages carry no link. |
| `webhooks` | — | At most 8 destinations, each described below. |

Every webhook:

| Key | Default | What it does |
| --- | --- | --- |
| `name` | required | Lower-case letters, digits, `-`, `_`, at most 32. Identifies the webhook's delivery cursor and its metric label. A webhook added under a new name gets events from then on, not the backlog. |
| `type` | required | `slack` (an incoming webhook), `teams` (a Microsoft Teams Workflows trigger, "Post to a channel when a webhook request is received", sent an Adaptive Card), `discord` (one embed, with all mentions switched off), or `json` (one object: `event`, `title`, `link`, `at`, and `request` or `token`). |
| `url`, `url_env` | one of them | The webhook's address, `https://` only. The URL is the credential for its channel, so it never crosses the network unencrypted, not even over loopback. `url` keeps it in this file (the Settings panel writes it there, and no API returns it). `url_env` names an environment variable of the hub process that holds it: `CLOOP_NOTIFY_` followed by upper-case letters, digits or `_`. Use that form for a file kept in version control (with a Kubernetes Secret mapped into the environment, or a systemd `EnvironmentFile`). It is read at every send, on whichever member leads, so set it on every member. It isn't kept in the hub's secret store, because a maintainer can delete and re-create a shared secret, and the URL decides who hears about every request. |
| `events` | every event but `requirement.regression` | Any of `request.filed`, `request.reminder`, `request.approved`, `request.denied`, `request.withdrawn`, `request.lapsed`, `token.waiting`, and `requirement.regression`: a requirement that passed its previous check and fails a later one, most often in the [requirements gate](../guides/requirements.md#regressions)'s check of a task. `requirement.regression` is opt-in: it is sent only to a webhook whose `events` name it, so a channel set up for approvals doesn't hear about a project's tests unless it asks. |
| `allow_addresses` | — | IP addresses or CIDR prefixes a receiver on a loopback, private, link-local or carrier-grade-NAT address may be reached at. A prefix of every address, a cloud metadata service, or a prefix containing one is refused. |
| `ca_file` | — | A PEM bundle added to the system roots for this webhook. |
| `timeout` | `10s` | How long one POST may take, `1s`–`1m`. |

The sender checks the address it actually connects to, after DNS resolution, so
a public name that resolves or rebinds to a private address is refused at
connection time. It refuses a cloud metadata service whatever
`allow_addresses` says. It follows no redirects (a 3xx is a failed send), uses
no proxy from the environment, sends at most 32 KiB and reads at most 8 KiB of
the response. A message contains identities, the credential's name and kind, the
subject, the deadline and the link. It never contains credential material, the
requester's justification or an approver's note, and every string in it goes
through the [credential-pattern scrubber](credential-patterns.md) first.

A failed delivery is retried with increasing backoff (30 seconds, doubling, at
most 30 minutes). A notice is dropped after 8 failed sends, on a refusal that
retrying can't change (a 4xx other than 408, 425 and 429, a redirect, a refused
address), or once it is a day old. A filing or reminder for a request that was
decided before it could be sent isn't sent. Deliveries are counted in
[`cloop_approval_notifications_total`](../operations/metrics.md#approval-notifications).

A webhook that fails validation is dropped at load and recorded as switched off;
`cloop hub doctor` reports it, and `cloop config set` and `cloop config validate`
refuse it. **Settings → Notifications** edits the section (administrators only),
writing it into the hub's overlay once the hub has one, and can send a test
message to a configured webhook. Each change is a
[`notifications.config.updated`](audit-events.md#notifications) row. A webhook
removed there loses its place at once, so adding it back starts from new
events. One removed from a file is forgotten a day later. Only the leader sends,
using its own configuration, so a cluster's members should run the same
section: a webhook that only some members configure is sent to only while one of
them leads. Decisions are picked up from the time the leader last scanned, minus
two minutes, so members' clocks must agree to within that; run NTP. Delivery is
at least once: while two members both believe they lead, a notice can be posted
twice.

### Semantic knowledge search (`knowledge.embeddings`)

The knowledge index ranks a project's chunks by their words, using SQLite's
full-text index and BM25, on the hub only. `knowledge.embeddings` adds ranking
by meaning. Each chunk gets a vector from an embedding endpoint when its source
syncs, and a search compares the query's vector with the vectors from the
project's bound sources and combines that ranking with the word ranking. It is
off unless enabled. When it is on, the hub sends the text of every chunk of
every synced source, and every search query, to the endpoint, so turn it on only
if that is acceptable. `cloop hub doctor` and **Settings → Hub health** always
show a `knowledge.embeddings` finding naming the endpoint.

```yaml
knowledge:
  embeddings:
    enabled: true
    provider: openai                     # any OpenAI-compatible API
    endpoint: https://api.openai.com/v1  # posts to <endpoint>/embeddings
    model: text-embedding-3-small
    dimensions: 1536
    secret_ref: openai-embeddings        # a shared env secret holding the key
```

The same `provider: openai` reaches the other OpenAI-compatible endpoints:

| Endpoint | `endpoint` | Notes |
| --- | --- | --- |
| OpenAI | `https://api.openai.com/v1` | `request_dimensions: true` shortens a `text-embedding-3` model's vectors to `dimensions`. |
| Azure OpenAI | `https://<resource>.openai.azure.com/openai/deployments/<deployment>?api-version=2024-10-21` | The key goes in the `api-key` header, the default for an Azure OpenAI host. The `v1` API (`…/openai/v1`) takes it too. |
| Ollama | `http://localhost:11434/v1` | No `secret_ref`. `model: nomic-embed-text`, `dimensions: 768`. |
| vLLM | `http://<host>:8000/v1` | `secret_ref` when the server runs with `--api-key`. |

`provider: voyage` uses Voyage AI's API (`endpoint` defaults to
`https://api.voyageai.com/v1`) and tells it whether it is embedding documents or
a query.

| Key | Default | What it does |
| --- | --- | --- |
| `enabled` | `false` | Turns semantic search on. |
| `provider` | required | `openai` or `voyage`. |
| `endpoint` | required for `openai` | The API's base URL. An `http` endpoint that is not loopback sends chunk text, queries and the key unencrypted, and the doctor warns. A cloud metadata service is refused, here and at every connection. |
| `model` | required | The embedding model, as the endpoint names it. |
| `dimensions` | required | The length of the model's vectors, 1–8192. A vector of any other length is refused, stored nowhere and compared with nothing. |
| `request_dimensions` | `false` | Ask the endpoint for `dimensions`-long vectors (OpenAI's `dimensions`, Voyage's `output_dimension`), for a model that can shorten its vectors. |
| `secret_ref` | — | The endpoint's key: a **shared env secret** (`cloop secret mint <name> --kind env`), `name` or `name#KEY`, opened by the hub as its own credential and never handed to an executor. Re-opened every 5 minutes and after the endpoint refuses it, so a rotated secret takes effect without a restart. |
| `auth` | `api-key` for an Azure OpenAI host, else `bearer` | How the key is sent: `Authorization: Bearer`, or the `api-key` header. |
| `batch_size` | `64` | Chunks per request, 1–512. |
| `timeout` | `30s` | How long one request may take, `1s`–`5m`. A search waits at most 5 seconds for its query's vector, whatever this says. |
| `max_candidates` | `50000` | How many vectors one search compares its query with, 1,000–1,000,000. A project whose sources hold more is searched by meaning over that many and by words over all of them; `cloop_knowledge_search_vectors_capped_total` counts the searches it cut. |

The comparison is a brute-force scan of every current vector from the project's
bound sources, read from the hub's database, so its cost grows with the amount
of knowledge. On a 4-core host, comparing 50,000 vectors of 768 dimensions takes
about half a second, and ranking the same 50,000 chunks by words about 20 ms
(`go test ./pkg/knowledge -run '^$' -bench Search50k`). Lower `max_candidates`
to limit it; `cloop_knowledge_search_vector_scan_seconds` shows the cost.

Keys never go in the file. An `api_key` field, or an endpoint whose query string
has a parameter that looks like a credential, switches the section off at load,
as does a missing endpoint, model or dimensions. `cloop hub doctor` reports this
as a failure, and `cloop config validate` refuses it. The client follows no
redirects, uses the proxy named in the hub's environment (`HTTPS_PROXY`, never
for loopback), and reads a response only up to the size the requested vectors
could need.

**What a sync does.** After listing its source, each sync embeds, in batches,
the chunks that have no current vector: new chunks, chunks of a document that
changed, and every chunk when embeddings are first turned on or the model,
provider or dimensions change. A model change makes every source due at once,
so the backfill starts within a minute. A chunk whose document changed but whose
own text didn't keeps its vector without a request. A pass stops after 10
minutes, and a source with more chunks waiting is synced again within a minute.
Vectors are stored in the hub's database, one per chunk and model, as float32
values. They are deleted with their chunk, and the cluster leader purges other
models' vectors hourly. Turning embeddings off keeps the vectors for when they
are turned back on.

**What a search does.** The query's vector is requested while the words are
ranked. Then every current vector from the project's bound sources is compared
with it, through the same bindings and filters (spaces, query matches) as the
full-text search, never another project's. The two rankings are combined by
reciprocal rank (`1/(60+rank)` from each), and each hit says whether it was
found by words, meaning or both (`found_by`). The search response includes
`retrieval`: `mode` `hybrid`, the model and how many vectors it compared.

**When the endpoint fails.** Neither syncs nor searches fail because of the
endpoint. A sync whose endpoint is down, refuses the key, or returns vectors of
the wrong length ends `ok` with a `warning` in its status, and the chunks wait
for the next sync. A search falls back to ranking by words (`mode` `lexical`,
with a `warning` saying why), and for 30 seconds after a failure doesn't
contact the endpoint at all. The doctor's `knowledge.embeddings.sync` finding
lists the sources whose last sync couldn't embed. See
[the metrics](../operations/metrics.md#knowledge-search-and-embeddings).

In a hub cluster, the leader's section decides what syncs embed, and each
member's section decides what its own searches compare, so every member should
run the same section. A member configured with a different model finds no
vectors for it and ranks by words.

### Disk retention

`retention:` controls the janitor the hub runs on a timer to keep `.cloop` from
growing without limit. Unlike `audit:` above, it is on by default: it reclaims
derived data and dead database pages, not a compliance record, and a hub that
fills its disk stops working.

A zero value for any key means "use the default", not "off", so a config file
written before this section existed gets the default policy. You turn it off
explicitly.

```yaml
retention:
  enabled: true                   # false disables the janitor entirely
  interval_hours: 24              # how often a pass runs
  keep_snapshots: 50              # .cloop/plan-history bound
  vacuum_free_ratio: 0.30         # VACUUM once this fraction of state.db is free pages
  vacuum_min_free_mb: 64          # ...but not for less than this
  vacuum_max_inline_mb: 1024      # ...and not more than this without stopping the hub
  archive_max_mb: 0               # 0: keep every audit seal
  archive_max_age_days: 0         # 0: keep every audit seal
```

| Key | Default | Range | What it does |
| --- | --- | --- | --- |
| `enabled` | `true` | — | Runs a pass every `interval_hours`. Set `false` and nothing reclaims `.cloop` automatically, including the row limits below. |
| `interval_hours` | `24` | `1`–`336` | How often a pass runs. The stamp at `.cloop/retention-last-run` makes the cadence survive a restart. |
| `keep_snapshots` | `50` | `1`–`10000` | How many plan snapshots are kept. Enforced at write time inside `SaveSnapshot` as well as by the pass, so a busy project can't get ahead of the interval. |
| `vacuum_free_ratio` | `0.30` | `≥ 0.01` | Free-page fraction at which `state.db` is rewritten. `1` or more never vacuums. A ratio, not a size: 2 GB of freelist is urgent in a 2.3 GB file and unremarkable in a 200 GB one. |
| `vacuum_min_free_mb` | `64` | `1`–`1048576` | An absolute minimum below the ratio, so a small database isn't rewritten daily to reclaim a few hundred kilobytes. |
| `vacuum_max_inline_mb` | `1024` | `1`–`1048576` | The most live data the hub will rewrite while it is running. The control-plane database holds the hub's own lease, so a VACUUM that takes longer than the lease TTL blocks the lease heartbeat, and the hub stands down, assuming another instance took over. Above this size the janitor skips the VACUUM and points to `cloop hub retention --apply`, which has no heartbeat to lose. Measured against live data, not file size: a 2.3 GB file holding 300 MB is quick to rewrite. |
| `archive_max_mb` | `0` (disabled) | `1`–`1048576` | Caps `.cloop/audit-archive`; the oldest seals are deleted first. Off by default, because a seal is the only remaining copy of the rows it holds. |
| `archive_max_age_days` | `0` (disabled) | `1`–`3650` | Deletes seals older than this. Off by default, for the same reason. |

Two safety rules can't be configured. The newest audit seal is never deleted,
so a cap smaller than one seal can't empty the directory. And a VACUUM is
refused while another hub holds the control-plane lease, or when the filesystem
lacks room for the rebuild: SQLite needs free space before it returns any, so a
nearly full disk is the worst time to try.

Every pass also removes the task verdicts the orchestrator writes next to each
live artifact (`.cloop/artifacts/<id>_verdict.json`, read by stale-task
recovery) once they are a week old and their task is no longer in progress. A
verdict whose task is still in progress is never removed, because recovery needs
it. `cloop compact` removes them on the same terms, after
`--keep-artifacts-days` (at least an hour).

#### Row tables

The keys above limit files and dead pages. These limit the tables that gain a
row per unit of work. Without limits these tables keep growing: on cloop's own
control plane, `provider_calls` once held 47.5 MB in 265 rows, 14% of the live
data in the database, because each row stores the full prompt and response of
one provider call.

```yaml
retention:
  provider_call_body_age_days: 30 # clear recorded prompts/responses after 30 days
  provider_call_max_rows: 10000   # ...and delete the rows themselves past this many
  step_max_rows: 20000
  event_max_rows: 20000
  cost_max_rows: 50000
  telemetry_max_age_days: 30
  knowledge_deleted_days: 30
```

| Key | Default | Range | What it does |
| --- | --- | --- | --- |
| `provider_call_body_age_days` | `30` | `1`–`3650`, or `-1` | Clears the stored prompt, system prompt and response of older calls, but keeps the row. The inspector's list and every cost report read only the metadata (timestamp, model, tokens, latency), which takes about 200 bytes; the bodies are the other 99%. A cleared call is marked as such, so the panel says "dropped by retention" instead of showing an empty prompt, and Replay asks for a new prompt instead of re-running an empty one. |
| `provider_call_max_rows` | `10000` | `100`–`100000000`, or `-1` | Maximum rows in `provider_calls`; the newest are kept. |
| `step_max_rows` | `20000` | `100`–`100000000`, or `-1` | Maximum rows in `steps`. This also limits a run's memory use, since `state.Load` reads every step. Skipped while a run is executing, because a live run rewrites its step history from memory, so rows deleted under it would come straight back. |
| `event_max_rows` | `20000` | `100`–`100000000`, or `-1` | Maximum rows in the unified event journal. |
| `cost_max_rows` | `50000` | `100`–`100000000`, or `-1` | Maximum rows in the cost ledger. The highest of these limits, because a cost row is tiny, `cloop cost report` aggregates over the whole table, and the ledger is mirrored to `.cloop/costs.jsonl`. It is there to keep the table bounded, not to prune it regularly. |
| `telemetry_max_age_days` | `30` | `1`–`3650`, or `-1` | Deletes browser telemetry older than this. There is no row key, because the write path already caps that table: a public ingest endpoint must not be able to fill a disk between two passes. |
| `knowledge_deleted_days` | `30` | `1`–`3650`, or `-1` | Purges the tombstone a knowledge document leaves when its source deletes it. The document's content (its chunks, full-text entries and matches) leaves the index at once. The tombstone keeps only its id and external id, so an earlier citation still resolves to "deleted" and a document that comes back keeps its id. Every pass also purges the documents and chunks of a deleted knowledge source, whatever this says: deleting a source removes them itself, and only an interrupted deletion leaves any behind. |

`-1` keeps a table in full while the rest of the policy stays in force. These
keys need that opt-out because they are on by default; the archive keys don't.
A value outside the range falls back to the default, not to "off", so a typo
can't turn this policy off without anyone noticing.

Row pruning and VACUUM report separate numbers. Deleting a row frees a page
inside `state.db`; only a VACUUM returns pages to the filesystem. So the row
steps run first in a pass, and the same pass can then reclaim what they freed.

Every pass ends by truncating the database's write-ahead log, `state.db-wal`,
which all of the steps above wrote through and which SQLite never shrinks by
itself. This step has no key. It runs whenever the pass does, even alongside a
live run or other hub processes, because its checkpoint waits at most a quarter
of a second for another connection and reports "busy" instead of holding up
writers. The hub's leader also truncates its own database's log within a minute
of finding it over 64 MiB. See
[The write-ahead log](../operations/runbook.md#the-write-ahead-log).

Preview or force a pass with `cloop hub retention` (a dry run unless you pass
`--apply`). `cloop doctor` and `cloop hub doctor` both report usage per
directory and an estimate of reclaimable pages. `cloop hub doctor` also reports
row counts per table and names any table the active policy leaves unbounded.

### Free-space floor

`orchestrator.min_free_disk_mb` is how much free space a run needs before it
starts work. Without it, a full disk shows up as a failed write, and the first
write to fail is often the one recording a task's outcome. The run then stops
with `state_not_persisted`, sometimes losing the verdict sidecar at the same
time, and stale-task recovery falls back to the agent's own `TASK_DONE`.

```yaml
orchestrator:
  min_free_disk_mb: 1024   # the default; 0 turns the check and the reserve off
```

| Key | Default | Range | What it does |
| --- | --- | --- | --- |
| `orchestrator.min_free_disk_mb` | `1024` | `0`, or `64`–`1048576` | Before every task attempt and every evolve round, the run measures the volume holding the project's `.cloop` and the working tree's volume (the same volume, unless `.cloop` is a symlink to another disk). Below the floor nothing starts: the run pauses with reason `disk_low`, checks again every minute, and continues by itself once every volume is back above the floor plus a tenth. `0` turns the check off. |

What a `disk_low` pause looks like:

- **The run stays up.** Unlike every other pause, the process keeps running and
  waits; **Stop** ends it. The dashboard shows *Paused: volume / has 812.3 MB
  free, below the 1.00 GB floor* with a Stop button. The event history has a
  `session_paused` row naming the volume, the free space, the floor and what
  was about to start, then a `session_started` row ("Run resumed: disk space
  recovered") when it continues. In parallel mode, the round in progress
  finishes and records its outcomes, but no new task starts.
- **A reserve backs it up.** Each project keeps `.cloop/reserve`, 16 MiB of
  preallocated blocks, created whenever the check passes. If writing a task's
  verdict or outcome still fails for lack of space (because its own build filled
  the disk between the check and the write), the run deletes the reserve and
  writes again, then pauses with `disk_low` before starting anything else. It
  stops with `state_not_persisted` only if that retry fails too. Snapshots,
  `cloop compact`, the janitor and the disk-usage reports all leave the reserve
  out.
- **A run on another machine measures its own disk.** A container or device
  run applies the project's own setting to the volume it writes to.
- **A disk limit doesn't replace it.** A container executor enforces a
  workload's `resources.disk` or disk ceiling by sampling its workspace, and a
  burst can overshoot by the write rate times the sampling interval before the
  next sample stops it. The floor stops that burst from filling the volume
  everything else writes to.

The hub applies the same floor to its own state volume. `cloop hub doctor`
reports `storage.free_space` (a warning below twice the floor, a failure below
it), admins see a banner across the dashboard while free space is below the
floor, and every hub process exports `cloop_hub_disk_free_bytes{volume}`.
Admins can edit the floor in **Settings → Disk & Retention**, which writes it
where the hub reads it: its per-instance overlay if it has one, otherwise
`config.yaml`. A run reads its project's `config.yaml`, so for runs in the hub's
own directory the hub passes the Settings value down as
`CLOOP_MIN_FREE_DISK_MB`. `cloop config set orchestrator.min_free_disk_mb <MB>`
and `cloop config validate` apply the same bounds. A value outside the range in
a file falls back to the default, not to "off".

### Interactive access: single sign-on and sessions

`ui.oidc.*` configures OpenID Connect for the dashboard. The full setup is in
[the security model](../security/model.md#configuring-oidc-single-sign-on).
This section covers the keys that control how long a session lasts and how
quickly it can be revoked.

You can edit all of `ui.oidc` in three ways: in this file, with
`cloop config set ui.oidc.<key> <value>`, and in **Settings → Single sign-on**
in the dashboard. The panel requires `user.manage` (not `config.write`),
refuses a block that would stop the hub from starting, and its changes take
effect when the hub restarts; see
[editing it from the dashboard](../security/model.md#editing-it-from-the-dashboard).
`role_mappings` is a list of records, so `cloop config set` can't edit it; use
the file or the panel's table.

`default_role` and `role_mappings` together decide whether a role policy is in
force. With neither set, single sign-on runs with RBAC off: every identity the
issuer authenticates holds every permission except executor administration
(`admin_emails`). The hub keeps this behaviour for deployments that enabled SSO
before RBAC existed, and warns about it: a warning on stderr at every start, a
failing `rbac.enforced` in `cloop hub doctor`, and a notice in Settings with an
**Enforce deny-by-default** button. With `require_rbac: true`, the hub refuses
to start in this state; see
[when RBAC is in force](../security/model.md#when-rbac-is-in-force).

If two hubs share a working directory, put `ui.oidc` in that hub's
[`.cloop/config.ui-<port>.yaml`](#two-dashboards-in-one-directory) instead:
`redirect_url` names one origin, and the other hub can't serve the callback.

For Microsoft Entra ID there is a complete Terraform module at
[`deploy/terraform/azure-entra-id/`](../../deploy/terraform/azure-entra-id/README.md).
It creates the application registration, declares cloop's four roles as Entra
app roles, and prints the `ui.oidc` block to paste in here. The block gets
right the provider-specific details you otherwise discover only when a sign-in
fails: the
issuer must end in `/v2.0` and name one tenant, the hub's bare origin must be a
registered redirect URI or sign-out leads nowhere, and `offline_access` must be
in `scopes`, or Entra issues no refresh token and both revocation settings below
stop working without an error.

```yaml
ui:
  oidc:
    session_ttl_hours: 24          # absolute ceiling, set at sign-in
    idle_timeout_hours: 8          # ends an unused session sooner
    refresh_interval_minutes: 15   # how often the IdP is re-asked
    max_claim_age_minutes: 5       # claim freshness required for privileged actions
    sudo_max_age_minutes: 120      # privileged actions need a sign-in this recent; -1 off
    clock_skew_seconds: 300        # leeway on an ID token's exp/iat
    require_idp: false             # refuse to start if the issuer will not resolve
    require_rbac: false            # refuse to start with SSO on and no role policy
```

| Key | Default | Range | What it bounds |
| --- | --- | --- | --- |
| `session_ttl_hours` | `24` | `1`–`720` | The absolute limit. Activity never extends it; when it runs out, the user signs in again. |
| `idle_timeout_hours` | `8` | `1`–`720`, and never above `session_ttl_hours` | How long a session can go unused. This limits an unattended browser, and is usually the one to shorten first: a shorter idle timeout means signing in again after a long meeting, while a shorter absolute limit interrupts people in the middle of their work. |
| `refresh_interval_minutes` | `15` | `1`–`1440`, or `-1` to disable | The longest delay between the identity provider disabling a user and their cloop session ending. Requires `CLOOP_SECRET_KEY`. |
| `max_claim_age_minutes` | `5` | `1`–`60`, or `-1` to disable | How old a session's group and role claims can be when it performs an action above operator. Past this age, the provider is asked again before the action, and the action is refused if the provider can't answer. With `CLOOP_SECRET_KEY` the hub asks using the session's refresh token; without it, the dashboard renews the claims from the user's browser instead (see below). |
| `sudo_max_age_minutes` | `120` | `1`–`1440`, or `-1` to turn off | **Sudo mode**: how recently the person behind a session must have signed in interactively to perform a privileged action. The privileged actions are: creating or deleting a secret or a grant, creating or approving an API token, creating an enrollment token, editing this block, retiring the static token, rotating the hub CA, upgrading or deregistering an executor, attaching to a sandbox, granting maintainer membership, ending someone else's session, offboarding, creating a SCIM credential or a glasses link, and setting a provider's API key or base URL, the dictation key or the CI relay's settings. Measured from the `id_token`'s `auth_time` or, where the provider doesn't report it (Entra ID doesn't, unless that optional claim is configured), from a sign-in the hub itself started with `prompt=login`. Silent renewal never counts. If the sign-in is older, the action is refused with `401 REAUTH_REQUIRED`, and the dashboard asks the person to confirm their identity at the provider (`prompt=login&max_age=0`). A terminal session counts from the sign-in behind its `cloop login` approval (the approval itself, if it asked you to sign in, which it does whenever the approving browser's sign-in isn't recent), and is told to run `cloop login` again. API tokens and the static token aren't sessions and are never asked. `-1` turns it off, and `cloop hub doctor` and Hub health then warn (`oidc.sudo`). Editable in **Settings → Single sign-on**, and honoured in a per-hub overlay like the rest of this block. See [Recent sign-in for privileged actions](../security/model.md#recent-sign-in-for-privileged-actions). |
| `clock_skew_seconds` | `300` | `0`–`600`, or `-1` for none | Leeway applied to an ID token's `exp` and `iat`, for hosts whose clocks disagree with the provider's. |
| `require_idp` | `false` | — | Makes an unresolvable issuer fatal at startup instead of a warning. Also available as `cloop ui --require-idp`. |
| `require_rbac` | `false` | — | Makes single sign-on without a role policy (no `role_mappings` and no `default_role`) fatal at startup instead of a warning. The Settings panel refuses to save a block that would fail this check, and `cloop hub doctor` says the start will fail. |

Out-of-range values are clamped, not rejected, and an `idle_timeout_hours`
larger than `session_ttl_hours` is lowered to it, because an idle timeout that
can never fire would remove the protection without any sign.

`clock_skew_seconds` is the exception: above the limit it is rejected, not
clamped. It exists for deployments that can't fix the underlying problem, such
as an on-premises provider on a host whose NTP is blocked by the same firewall
that keeps the provider on-premises. Raising it means accepting tokens that
expired that long ago, so raise it only as far as the drift you have measured.
If a value of an hour were clamped to ten minutes without a warning, the
operator would end up debugging the wrong problem.

#### Failing fast on a misconfigured provider

The hub resolves its issuer at startup instead of at the first sign-in: it runs
discovery and fetches the JWKS, with ten seconds for both.

- **It logs** the issuer URL, the HTTP status and a one-line fix if that fails.
  Otherwise the failure would show up hours later as an error page from the
  provider, in the provider's terms, about a value the provider never saw.
- **It reports `/readyz` as unready** (`503` with `"check": "identity"`) for as
  long as the issuer has never resolved. Once it has resolved, the check keeps
  passing: existing sessions keep working through a later provider outage, and
  removing the hub from its Service during one would turn a sign-in outage into
  a complete outage.
- **With `require_idp`** (or `--require-idp`) it refuses to start, so a
  Kubernetes rollout fails and rolls back instead of replacing a working hub
  with one nobody can sign in to.

A failed startup check never disables normal sign-in, so if a provider is down
for a minute, the next sign-in works again without a restart. `cloop hub doctor`
makes the same two requests and prints the resolved authorization, token and
JWKS endpoints. That is usually the quickest way to check the hub is using the
realm you expect: a wrong realm looks fine in the config file but is obvious in
its authorization endpoint.

A role mapping the provider can't satisfy gets its own warning. `ui.oidc`
validates role names and claim kinds at startup, but it can't see whether the
provider actually sends the claim a binding reads. So on a deployment whose
`groups` scope was never granted, a `group` binding has no effect, and every
user falls back to `default_role` without an error. After the first identity the
hub authenticates, it logs one warning per such binding, naming the claims that
were present. See
[Configuring role mappings](../security/model.md#configuring-role-mappings).

Sessions are stored in the hub's own `state.db` and survive a restart or a
rolling upgrade. The refresh token used to revalidate a session is sealed with
AES-256-GCM under `CLOOP_SECRET_KEY`, the same variable
[`cloop secret`](../guides/secrets.md) uses. Without that key, cloop keeps no
refresh tokens at all (instead of storing a live credential in plaintext), so
`refresh_interval_minutes` has no effect and revocation at the IdP doesn't
reach cloop. `cloop ui` says so at startup, and the **Active sessions** panel
shows a banner.

`max_claim_age_minutes` has a second way to renew claims, so it keeps working
without a key. With no refresh token, the hub can't ask the provider itself and
refuses actions above operator once the claims are too old. The dashboard then
asks from the user's browser: a hidden frame makes a `prompt=none` round trip
through `GET /auth/renew` shortly before the claims expire, and again, followed
by one retry, if a call is refused because of their age. When this works,
nothing changes on screen. When the provider needs to see the user (they are
signed out there, or their browser blocks the provider's cookies in frames, as
Safari and Firefox do), a banner offers a sign-in that returns to the same tab
and view. See
[Silent renewal from the browser](../security/model.md#silent-renewal-from-the-browser).

Where browsers can't complete the silent round trip, privileged actions need a
visible sign-in once per `max_claim_age_minutes` period. The lasting fix is
`CLOOP_SECRET_KEY` with `offline_access` in `scopes`. The alternative is
`max_claim_age_minutes: -1`, which explicitly accepts acting on the claims from
sign-in time.

A session that has ended (its idle or absolute timeout ran out, or it was
revoked) no longer shows the access-token prompt either. Every `401` an SSO hub
sends says where to sign in again, and the dashboard goes there through the
provider and returns to the same view. If the user is still signed in at the
provider, that takes two redirects and no prompt.

### Claim freshness for privileged actions

`refresh_interval_minutes` is a background interval: it limits how long a
disabled account keeps a working session. It doesn't limit how old the claims
inside a live session are, and on most providers those are very different
numbers. RFC 6749 doesn't require an `id_token` on a refresh, and Okta, Auth0
and Keycloak all leave it out in common configurations, so the grant is renewed
every interval while the groups and roles stay as they were at sign-in. cloop
asks the `userinfo` endpoint in that case, but on a deployment with neither, a
session keeps its sign-in-time permissions for its whole life.

`max_claim_age_minutes` limits the age of the claims, and only where it
matters. Before using a permission above the operator tier (`secret.grant`,
`secret.revoke`, `user.manage`, `token.admin`, `session.admin`,
`executor.manage`, `config.write`, `project.write`, `project.share`,
`audit.read`, `sandbox.attach`, `knowledge.admin`), cloop checks when the
provider last confirmed that session's claims. If that was longer ago than this
limit, cloop asks the provider before acting, decides based on its current
answer, and refuses the action if the provider can't be reached.

Three things keep this cheap:

- **Reads never wait for it.** Everything a viewer or operator can do, including
  running and stopping plans, stays on the background interval, so an IdP
  outage makes the hub slow to revoke access, never slow to respond.
- **Concurrent checks share one request.** A dashboard panel that sends six
  admin requests at once causes one call to the provider, and all six get the
  same answer. Sending more requests can't get ahead of a demotion.
- **Fresh claims cost nothing.** Only the first privileged call in each window
  contacts the provider; the rest need one indexed read.

The provider's own `expires_in` can shorten the limit but never lengthen it. An
IdP that issues five-minute access tokens is saying how long it vouches for the
claims, and cloop uses whichever deadline comes first.

The **Active sessions** panel and `cloop hub session list` show each session's
claim age next to its last grant check, so you can see the gap between them. A
session whose claims the provider has refused to confirm (a `401` or
`invalid_token` from `userinfo`) keeps working for reads and is refused for
everything above operator until a later check succeeds. Both outcomes are
written to the audit trail, as `session.claims_rejected` and
`session.claims_stale`.

Users with the `session.admin` permission get an Active sessions table in the
Secrets tab (subject, IP, device, sign-in time, idle time and a **Terminate**
button), backed by `GET /api/sessions` and `DELETE /api/sessions/{id}`. Any
signed-in user can end their other sessions from the header
(`POST /api/session/logout-all`). Signing out also redirects to the provider's
`end_session_endpoint` when it has one, so the browser's session at the IdP
ends too. How revocation works, including when the IdP is unreachable, is
described in
[Session lifecycle and revocation](../security/model.md#session-lifecycle-and-revocation).

### Terminal sign-in (`cloop login`)

A hub with single sign-on can also sign in terminals. `cloop login <hub>` prints
a code, a signed-in browser approves it at `/device`, and the terminal gets a
CLI session: a row of kind `cli` in the same session store, authenticated with
`Authorization: Bearer cloop_cli_…`. For a walkthrough, see
[Working from a terminal](../getting-started/terminal.md).

```yaml
ui:
  oidc:
    device_login: true                    # on wherever SSO is; false turns it off
    cli_session_ttl_hours: 24             # default and ceiling: session_ttl_hours
    cli_idle_timeout_hours: 8             # default and ceiling: idle_timeout_hours
    device_approval_max_age_minutes: 120  # a sign-in longer ago re-authenticates to approve
```

| Key | Default | Range | What it bounds |
| --- | --- | --- | --- |
| `device_login` | `true` | — | Whether `POST /api/device/code` and `/api/device/token` answer, and `/device` is served. When off, `cloop login` reports that terminal sign-in is turned off. |
| `cli_session_ttl_hours` | `session_ttl_hours` | `1`–`session_ttl_hours` | A terminal session's absolute lifetime, from its approval. Never longer than a browser session's, because a credential stored in a file should expire first. |
| `cli_idle_timeout_hours` | `idle_timeout_hours` | `1`–`idle_timeout_hours`, and never above `cli_session_ttl_hours` | How long a terminal session can go unused. The janitor applies each kind of session's own idle timeout. |
| `device_approval_max_age_minutes` | `120` | `1`–`1440`, or `-1` never to ask | How long ago the approving person may have signed in. The approval's round trip asks the provider for this `max_age`; a browser session older than this is sent with `prompt=login&max_age=0` instead. Where the `id_token` includes `auth_time`, the hub checks it: a sign-in older than this behind a fresh dashboard session (a silent re-login) goes round again with `prompt=login`, and one that ignored the prompt is refused, so a provider that ignored either parameter is caught. A provider that reports no `auth_time` (Entra ID, unless that optional claim is configured) is trusted to have honoured them. |

Everything else works as for browser sessions: `refresh_interval_minutes`,
`max_claim_age_minutes` and `sudo_max_age_minutes` apply unchanged, because the
approval is itself an authorization-code sign-in whose `id_token` and refresh
grant become the CLI session's own (never a copy of the browser's). Without
`CLOOP_SECRET_KEY` no refresh grant is kept, so a terminal session's claims stay
as they were at approval, and actions above operator need a new `cloop login`
once the claims are older than `max_claim_age_minutes`. The terminal is told
this when it signs in. Sudo mode counts a terminal session from the sign-in
behind its approval. Approving from a browser whose own sign-in is older than
`sudo_max_age_minutes` makes the approval a `prompt=login` sign-in, which the
terminal then counts from; a silent approval leaves the terminal no more recent
than the browser. A privileged action (creating a token, approving a request,
opening a sandbox terminal) from a terminal outside the window is refused, and
the terminal says to run `cloop login`.

Two endpoints answer before authentication, because a terminal asking for a code
has no credential yet. They accept JSON only, like every state-changing request,
and are rate-limited instead of authenticated: twelve codes per client address
per ten minutes, two thousand pending across the hub, each code expiring after
ten minutes and useless until a signed-in person approves it, and polling held
to the interval by `slow_down`. The browser's three routes
(`/api/device/lookup`, `approve`, `deny`) accept a browser session cookie and
nothing else: not a terminal's session, an API token or the static token. See
the [HTTP API](http-api.md) for each.

### Projects created by name (`ui.projects_root`)

`cloop remote init` creates a hub project from a checkout on a developer's
machine, which can't know where the hub keeps projects. It asks for a project
by name, and the hub creates it under its projects root:

```yaml
ui:
  projects_root: /srv/cloop/projects   # absolute; default: projects/ in the hub's home
```

If unset, it is `projects/` in the home directory of the user the hub runs as:
`/var/lib/cloop/projects` in the packaged image, whose `HOME` is its state
volume. The Helm chart mounts its state volume's `projects/` there, because
everything else in its container is read-only and a project can't be inside the
state directory itself.
A name is one path segment of letters, digits, dots, hyphens and underscores,
starting with a letter or digit. A relative `projects_root` is refused when it
is used, with an error naming the setting.

Projects are also confined to the root. Every sandbox a project runs in gets the
project's directory mounted read-write, so:

- **Anyone without `executor.manage`** (maintainers using the dashboard's New
  Project dialog, `cloop remote init --dir`) can create a project only strictly
  inside the root, and not in a hidden directory. Outside it, the answer is
  `403 FORBIDDEN`, naming `executor.manage` and the root. A project created by
  name is always inside the root.
- **Nobody** can create a project at the root itself or at a directory that
  contains it; at, inside or above the hub's own directory or another hub's (one
  holding `.cloop/hub.env`, or at or above a running `cloop ui`'s); overlapping
  another project; or anywhere the older rules refuse (system directories, `/`,
  top-level directories, the hub user's home). The exception is a root inside
  the hub's own directory, as in the packaged image: projects inside such a root
  are allowed. Symbolic links are resolved before any of this is checked.
- A directory that already holds a project isn't initialised again, because
  `cloop init` would overwrite the state it finds. To anyone other than an
  administrator or someone who can see that project, this refusal is the same
  `409 CONFLICT`, with the same wording, as every other refusal that depends on
  what is on the host, so creating projects can't be used to discover what
  exists where.
- `?delete_root=true` on a project's removal deletes its directory only if this
  hub created that directory itself, inside the root. For an adopted directory
  (a checkout that existed first, a path an operator registered), the request is
  refused with `409`, and the directory and the project stay.

Projects registered before these rules, or named with `cloop ui --projects`, are
listed but flagged on the Projects tab, refused at every run, and failed by `cloop
hub doctor` (`projects.confinement`) until an administrator moves or removes
them. Nothing is moved or deleted automatically. See
[which directory a project may be](../architecture/executors.md#which-directory-a-project-may-be).

### SCIM provisioning (`ui.oidc.scim`)

The identity provider provisions the hub's users and groups at `/scim/v2`, and
deactivating a person there suspends them here without an administrator: their
sessions, API tokens, glasses links, leases and running tasks are ended, and a
deny binding is written. The provider authenticates with a credential created
by `cloop hub scim credential create` or under
**Settings → Provisioning (SCIM)**; it isn't stored in this file. `/scim/v2` is
served only with `ui.oidc.enabled`. For a walkthrough, including Entra and
Okta, see [SCIM provisioning](../guides/scim-provisioning.md).

```yaml
ui:
  oidc:
    scim:
      match_claim: email          # email | preferred_username | oid | sub
      offboard_after_days: 0      # 0: only the provider's DELETE offboards
      rate_limit_per_minute: 600  # per credential
```

| Key | Default | Range | What it decides |
| --- | --- | --- | --- |
| `match_claim` | `email` | `email`, `preferred_username`, `oid`, `sub` | How a provisioned user is matched to a signed-in identity: the user's primary email against the `email` claim, `userName` against `preferred_username`, or `externalId` against `oid` (Entra, with `objectId` mapped to `externalId`) or `sub` (Okta). If two identities carry the same value, cloop doesn't guess between them. Any other setting value stops the hub from starting. |
| `offboard_after_days` | `0` | `0`–`3650` | Runs the full offboarding (honouring a legal hold) for a user the provider has kept deactivated this long. `0` never does. Entra sends no `DELETE` for an account that was only unassigned, so this setting is what completes those. |
| `rate_limit_per_minute` | `600` | `10`–`60000` | Each credential's request budget, refilled continuously, with bursts of a sixth. Past it, `429` with `Retry-After`. |

Out-of-range values are clamped. All three can be set with `cloop config set
ui.oidc.scim.<key>`, and take effect when the hub restarts.

Provisioned groups are a claim kind, `scim_group`, which `role_mappings` and
runtime bindings can name by the group's display name or `externalId`. The hub
reads membership from its directory at every authorization decision, so it
needs no group claim in the token. The provider's accounts add two more kinds a
binding can name: `username` (`preferred_username`) and `oid`.

### Web UI (`cloop ui`)

Where the dashboard listens depends on whether it has sign-in. A hub with no
sign-in (neither `ui.oidc` nor a static `--token`/`CLOOP_UI_TOKEN`) answers
every request from anyone who can reach it: it lists the projects, queues tasks
and starts agent runs on this host. So it listens on `127.0.0.1` only, and says
so at startup:

```
cloop dashboard running at http://127.0.0.1:8080, listening on 127.0.0.1:8080
No sign-in is configured, so the dashboard listens on 127.0.0.1:8080 only. To reach it from another machine, configure SSO (ui.oidc) or a token (CLOOP_UI_TOKEN) — the hub then listens on every interface — or tunnel: ssh -L 8080:127.0.0.1:8080 <this-host>.
```

A hub with sign-in listens on every interface. `ui.listen` (or `--listen`, which
overrides it) sets a specific address instead. It doesn't include the port,
which is still set by `--port`:

| | `ui.listen` unset | loopback: `127.0.0.1`, `::1`, `localhost` | beyond loopback: `0.0.0.0`, `::`, an interface's address, a host name |
| --- | --- | --- | --- |
| no sign-in | `127.0.0.1` | as named | **refused**, or with `ui.allow_unauthenticated_network: true`, as named, with a warning at every start |
| static token | every interface | as named | as named |
| `ui.oidc` | every interface | as named | as named |

```yaml
ui:
  # The address, never the port. --listen overrides it.
  listen: 127.0.0.1
  # Only for a hub without sign-in that must listen beyond loopback anyway:
  # a lab network, a container published on the host's loopback. It never
  # widens the default, and the hub warns at every start while it applies.
  allow_unauthenticated_network: false
```

- **A scoped API token is not sign-in.** API tokens restrict the callers that
  present one, but a hub without `ui.oidc` or a static token still serves
  requests that present none. Such a hub counts as having no sign-in, so
  removing the static token from a hub without SSO
  ([migrating off it](../security/model.md#migrating-off-the-static-token))
  takes the hub off the network instead of leaving it open there.
- **The error says what to do.** A hub without sign-in that is asked to listen
  beyond loopback exits before it touches the control plane:

  ```
  Error: refusing to listen on *:8080 (--listen): this hub has no sign-in — ui.oidc is off and no --token or CLOOP_UI_TOKEN is set — so anyone who can reach that address could list its projects, queue tasks and start agent runs on this host.
    Remote executor agents need to reach the hub, and a hub that serves them over the network needs SSO (ui.oidc) or a token (CLOOP_UI_TOKEN).
    To keep it on this machine, drop --listen: a hub without sign-in listens on 127.0.0.1, which an SSH tunnel (ssh -L 8080:127.0.0.1:8080 <this-host>) or an authenticating reverse proxy can reach.
    To serve it without sign-in anyway, set ui.allow_unauthenticated_network: true in .cloop/config.yaml.
  ```

- **Remote executor agents connect to the hub**, so a hub that enrolls devices
  over the network needs SSO or a token. A loopback-only hub serves agents on
  its own machine, or through a tunnel.
- **Loopback is judged from the address, never by resolving it.** IP literals
  count by their value, and `localhost` is bound as `127.0.0.1`. Every other
  host name (`hub.localhost`, or this machine's own name mapped to `127.0.1.1`)
  counts as beyond loopback, whatever it resolves to now.
- **Behind a TLS proxy on the same host**, set `listen: 127.0.0.1` on a hub
  with sign-in too: the proxy can reach it there, and nothing else can reach the
  plaintext port. While a hub serves plaintext beyond loopback and its public
  URL (`ui.external_url`, or `ui.oidc.redirect_url` if that is unset) is https,
  startup prints a note and `cloop hub doctor` warns (`ui.exposure`).
- **Per process.** Where two hubs share a directory, put `ui.listen` in each
  hub's own overlay, `config.ui-<port>.yaml` (see below).
- **Containers set the address.** A container has its own loopback, so the
  image, the Helm chart and the compose stack start
  `cloop ui --listen 0.0.0.0`. A container hub without sign-in refuses that and
  exits. See
  [Deploying the cloop hub](../../deploy/README.md#listening-on-the-network).
- **Hub-cluster members** reach each other at their advertise URLs, which
  default to the address the member is bound to, or to
  `http(s)://127.0.0.1:<port>` for a member on every interface.

`cloop hub doctor --port N` reports `ui.exposure`. It reads where the process on
port `N` actually listens from the kernel's socket table, and requests
`/api/projects` from it without credentials. It reports **fail** for a hub
without sign-in that can be reached beyond loopback, whatever its build, so an
older binary that binds every interface regardless is caught too. It reports
**warn** for plaintext behind an https URL, as described above. If nothing is
listening on the port, it judges what `cloop ui --port N` would do with this
configuration (a static token counts when `CLOOP_UI_TOKEN` is exported in the
doctor's shell).

> **`--token` / `CLOOP_UI_TOKEN` is deprecated.** It works until you retire it,
> but it bypasses RBAC entirely, sees every project on the hub, never expires,
> and can't be revoked for one caller without breaking all the others. Create a
> scoped API token per caller (see above). Once single sign-on works, retire the
> static token with `cloop hub token static retire --reason "..."` or
> **Settings → Static admin token → Retire**, and remove the flag and the
> environment variable at the next rollout. While it is still set, `cloop ui`
> prints a warning at startup and the Tokens panel shows a banner, and while it
> is accepted alongside an enforced role policy, `cloop hub doctor` warns
> `ui.static_token`. See
> [Migrating off the static token](../security/model.md#migrating-off-the-static-token)
> and [Retiring the static token](../security/model.md#retiring-the-static-token).

When a `--token` is set:

- Every `/api/*` request must present `Authorization: Bearer <token>` or
  `?token=<token>`.
- A retired token is refused by every hub member, without a restart, with a
  `401` saying when and by whom it was retired and what to present instead.
  This applies in the header and as `?token=`, and doesn't count toward the
  rate-limit lockout below. The token stays configured: a token-only hub whose
  token is retired stays closed and accepts only API tokens. Retirements are
  stored in the control plane's `retired_static_tokens` table, keyed by the
  token's fingerprint. A member reads them before it starts serving, when a
  retirement posts its notice on the hub bus, and every 30 seconds. To issue a
  new token, deploy a new value.
- Failed authentication attempts are rate-limited: after 5 consecutive failures
  from the same IP, the endpoint returns HTTP 429 and blocks that IP for 60
  seconds.
- The dashboard's assets under `/assets/` are served before authentication, like
  the page that references them. They are static files compiled into the binary,
  the same on every hub.
- All responses include these security headers:
  - `Content-Security-Policy`: only the hub's own script files run; see
    [below](#content-security-policy-and-violation-reports)
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`. With single sign-on configured, it is `SAMEORIGIN`
    on `/auth/renew` and the OIDC callback only, which the dashboard loads in a
    frame to renew a session's claims (`frame-ancestors 'self'` in the CSP,
    whose `frame-src` then also names the identity provider)
  - `Referrer-Policy: no-referrer`
- No CORS headers are sent to anyone.

#### Content-Security-Policy and violation reports

Every response the hub sends (the dashboard, the display-glasses page, the
sign-in documents, assets and API responses alike) carries one policy:

```text
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; connect-src 'self'; frame-src 'self' [identity provider];
frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none';
report-uri /api/csp-report
```

`frame-src` names the identity provider when single sign-on is configured, and
`frame-ancestors` is `'self'` on `/auth/renew` and the OIDC callback, the two
documents that silent renewal loads in a frame. Nothing else varies, and nothing
is configurable.

Only the hub's own script files run: no inline scripts, inline event handlers,
`eval` or `javascript:` URLs. The dashboard routes every control through one
delegated dispatcher. A control names an action in a `data-action` attribute,
which `pkg/ui/assets/js/00-core.js` looks up in a registry, and a pointer
passing over an element or a drag crossing it runs only what was registered for
that specific event. So a string written by a workload or a peer that reaches
the page through a missed escape can't run, and neither can an event handler
someone adds back into the markup: `TestNoInlineEventHandlers` fails the build
first. The theme bootstrap and the display-glasses page's script are separate
assets, and the two sign-in documents carry their values in the markup and load
`GET /auth/sign-in.js`. Inline styles are still allowed; see the
[threat model](../security/threat-model.md#out-of-scope).

`report-uri` names the hub's own `POST /api/csp-report`. A browser sends it a
report for each violation, and the hub:

- counts it in [`cloop_csp_violations_total`](../operations/metrics.md#what-the-pages-policy-blocked),
  by effective directive and by which of its documents it came from;
- logs it at warn level as `csp_violation`, with credentials scrubbed from its
  URLs;
- records it as a telemetry event of kind `csp` where `ui.telemetry` collects
  that document's front end ([telemetry](../operations/telemetry.md)).

The log line and the event name the signed-in user whose browser sent the
report (the report carries the session cookie, which a browser sends with a
same-origin report), or nobody. Reading that session doesn't count as activity
by the user.

The endpoint takes no credential and is served before authentication. The
glasses page's credential is a header its script adds, and the sign-in
documents are for someone not yet signed in, so a browser has no credential to
send with a report from either. The endpoint is limited accordingly: `POST`
only, `application/csp-report` or `application/reports+json` and nothing a form
can send, a 64 KiB body, the first 32 reports of a batch, and the per-IP rate
limit that applies to every route. Log lines and telemetry rows come from two
hub-wide budgets. One allows 30 at once and 60 a minute, for a signed-in
browser's reports and for every report on a hub that requires no credential.
The other allows 10 at once and one a minute for everything else (the glasses
page's, a static-token dashboard's, a sign-in error page's, anyone's). So
anonymous senders can't fill the log, push older rows out of the telemetry table
(which keeps its newest 50,000 rows), or crowd out a signed-in user's reports.
The counter counts every report, as reported. Anyone who can reach the hub can
send one, so treat a rising rate as a reason to read the log lines' `client_ip`
and `actor`, not as proof on its own.

A violation on the dashboard means either a control the dispatcher doesn't route
(a button that does nothing) or injected markup that the policy stopped. Both
are defects to fix, so alert on any rate.

The policy doesn't use `report-to`. A browser that supports it ignores
`report-uri` when both are present, and delivers through the Reporting API in
batches, later, and only to an endpoint it considers trustworthy, so a hub
reached over plain HTTP on a LAN address would get nothing. In a test with
Chrome 151, `report-uri` reports arrived at once, and `report-to` reports didn't
arrive at all within ninety seconds.

#### Two dashboards in one directory

A hub reads `.cloop/config.yaml` from its working directory. When two hubs share
that directory (for example a stable dashboard and a development one), both read
everything in that file, including settings that can only apply to one of
them:

```ini
# /etc/systemd/system/cloop-ui.service
ExecStart=/usr/local/bin/cloop ui --port 8080          # reachable at :1234
# /etc/systemd/system/cloop-ui-latest.service
ExecStart=/usr/local/bin/cloop-latest ui --port 8081   # reachable at :8888
```

`ui.oidc.redirect_url` names one origin. If you configure SSO for the second hub
in the shared file, the first one starts sending people to a callback it doesn't
serve. The result is an endless sign-in loop or, on a binary older than the
public-client support in `ui.oidc`, a hub that refuses to start.

So `cloop ui --port N` reads `.cloop/config.ui-N.yaml` after `config.yaml` and
merges it on top. The file is named after the listen port because the port
already distinguishes the two hubs. When an overlay applies, startup names it:

```
Instance config: /srv/app/.cloop/config.ui-8081.yaml merged over /srv/app/.cloop/config.yaml
```

```yaml
# /srv/app/.cloop/config.ui-8081.yaml — read only by the hub on :8081
ui:
  oidc:
    enabled: true
    issuer: https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0
    client_id: 00000000-0000-0000-0000-000000000000
    redirect_url: https://hub.example.com:8888/auth/oidc
    default_role: none
    admin_emails: [ops@example.com]
```

- **Merging is per key.** A key in the overlay replaces the value from
  `config.yaml`; a key missing from the overlay leaves the project's value
  unchanged. Lists replace instead of appending: a `scopes` list in the overlay
  means those scopes only, not those plus whatever `config.yaml` lists.
- **Limits still apply.** Overlay values are clamped like `config.yaml` values,
  so moving a setting to the overlay doesn't get around a limit.
- **A parse error is fatal**, as it is in `config.yaml`, because the file
  decides whether anyone has to sign in.
- **Only `cloop ui` reads it.** Put settings that describe this hub in it: the
  hub-scope keys below. Leave API keys, budgets, the provider and the model in
  `config.yaml`, where every other command reads them. `cloop run` never reads
  an overlay, so a provider set there would have no effect on any run.
- **The Settings panel writes to the overlay.** Once an overlay exists, the
  panels that save hub settings (`PUT /api/config/oidc`,
  `/api/config/telemetry`, `/api/ci/config` and `/api/config/stt`) write the
  keys they edit into the overlay. They keep the rest of that file and its
  comments, and leave `config.yaml` unchanged. Without an overlay they write
  `config.yaml`.
- Give it mode `0600`: it can hold a client secret, and `cloop ui` warns if it
  is readable by anyone else.

**Hub-scope keys.** `cloop ui` reads each of these with its overlay merged in:

| Key | What the hub does with it |
| --- | --- |
| `executors.allow_host_process` | Whether a harness may run on this host at all. `false` in the overlay puts this hub in strict mode; `true` there relaxes a shared `config.yaml` that says `false`, for this hub only. |
| `executors.min_agent_build`, `executors.limits`, `executors.isolation_evidence`, `executors.image_provenance` | The oldest agent build the hub will place work on, the fleet resource ceiling, whether an executor whose isolation claim was never verified is refused, and whether one of cloop's own images with an unverified signature is refused. As with `allow_host_process`, a value set in the overlay replaces the one in `config.yaml`. Once applied, nothing the process reads later can loosen any of them. |
| `executors.container`, `executors.kubernetes`, `executors.orphan_sweep_interval_minutes` | Which isolating drivers the hub registers at startup, and how often it sweeps their orphans. |
| `executors.git_proxy`, `executors.kube_guard` | The git interception proxy and the Kubernetes access monitor, started at startup. |
| `executors.egress` | The egress proxy, bound at startup. In a cluster each member binds its own, so `listen_addr` belongs here when two members share a host. |
| `executors.auto_install_harness` | Whether a device may be asked to install a missing harness. Read on each dispatch. |
| `executors.feature_bundle_mb` | The cap on a feature's branch and returned work when it runs on an isolating executor. Read at startup. |
| `executors.failover` | `max_attempts`, the cap on re-dispatching a run whose executor went unreachable. Read at every failover. |
| `executors.remote` | The memory remote executors' returned work may occupy on this hub: one executor's budget and every executor's ceiling. Read at startup. |
| `executors.write_back` | Whether a run on an executor that does not share this hub's filesystem pushes its work back to the project's origin. Read on each dispatch. |
| `executors.harness_credential_exempt` | Executors whose harness brings its own Claude credential, so a dispatch to them is not refused for want of a granted one. Read on each dispatch. |
| `executors.model_relay` | The model relay for sandboxed runs. Started at startup with `enabled`, `listener` and `upstream_base_url`; `models`, `max_output_tokens` and `hub_credential` read on each dispatch. |
| `sandbox.image_policy` | The image trust policy. The hub checks a project's image against it before dispatch, and each driver takes its own copy at startup. |
| `ui.*` | Where it listens (`listen`, `allow_unauthenticated_network`, read at startup), sign-in, TLS, origins, WebSocket caps, quotas, clustering, CI federation, telemetry, resuming capped runs. |
| `stt` | Dictation settings and key. A project's own `stt` section still overrides them for requests about that project. |
| `retention`, `audit` | The janitor's policy for the hub's own directory. Every other project keeps its own. `audit.checkpoints` is the hub's alone, read at every checkpoint window. |
| `backup` | Auto-backup of the hub's own directory. |
| `github.token` | The token the hub hands a pull request that runs on its own host. |

Settings read at startup (the drivers, the git proxy, the Kubernetes monitor,
the egress proxy, the executor ratchets) take effect at the next restart,
whichever file they are in. The rest are read on each use.

`cloop hub doctor --port N` diagnoses the hub on port `N` with its overlay
merged. Without `--port`, it diagnoses the hub that a plain `cloop ui` starts
(port 8080, with `config.ui-8080.yaml` if there is one), and `--port 0` reads
`config.yaml` alone. It lists any overlay it didn't merge.

The overlay is a separate file, not a port-keyed section of `config.yaml`,
because an older binary sharing the directory doesn't ignore a key it doesn't
know: it drops it the next time anything calls `Save()`. A block that makes
sign-in required must not be deleted that way, and no binary opens a file name
it doesn't know about.

#### Several hubs, one control plane

Hubs that share a directory are members of one
[hub cluster](../architecture/hub-cluster.md): they serve the same state, forward
to each other the requests only one of them can answer, and elect one leader.
`ui.cluster` says how a member is reached and whether other members are
allowed:

```yaml
ui:
  cluster:
    peer_server_name: hub.example.com      # verify peers' certificates as this name
    peer_ca_file: /etc/cloop/peer-ca.pem   # trust this CA for them, too
    # exclusive: true                      # one process, and refuse any other
```

| Key | Default | Meaning |
| --- | --- | --- |
| `advertise_url` | `http(s)://127.0.0.1:<port>` | Where the other members reach this one. Set it per process: in the instance overlay, or with `--advertise-url`, `CLOOP_CLUSTER_ADVERTISE_URL` or `CLOOP_CLUSTER_ADVERTISE_HOST` (a host only; cloop adds the scheme, brackets an IPv6 address and appends its port), which take precedence in that order. A bare origin: no path, query or credentials. |
| `peer_server_name` | host of `ui.external_url` | The name an `https://` peer's certificate is verified against when the peer is advertised by IP address. |
| `peer_ca_file` | — | PEM bundle trusted for peers' certificates, in addition to the system roots and this hub's own `ui.tls` certificate. |
| `exclusive` | `false` | Use the control plane alone: refuse to start while another hub serves it, and make any other hub refuse to start while this one does. |

On one machine the defaults work and nothing needs setting. Forwarded requests
carry the caller's credentials, so members that reach each other over a network
others can observe should advertise `https://` URLs; see
[the peer channel](../architecture/hub-cluster.md#the-peer-channel).

#### Front-end telemetry

The dashboard and the display-glasses page can record a diagnostic trail (the
gestures they received, the views they opened, the requests they sent and any
errors) and post it to the hub, where `cloop hub telemetry` and the Telemetry
tab show it. It never leaves the deployment.

**Collection is off by default.** Nothing is sent, and each front end asks the
hub before it sends anything.

```yaml
ui:
  telemetry:
    enabled: true          # off unless you set this
    sources: [glasses]     # optional; omit for every front end
```

| Key | Default | What it does |
| --- | --- | --- |
| `enabled` | `false` | The main switch. While it is off, both ingest routes answer `404` instead of discarding data without notice, so you can verify the setting, and the front ends don't post anything. |
| `sources` | all | Restricts collection to the named front ends: `dashboard`, `glasses`. An empty or absent list means all of them. |

It is off by default because a trail contains the URLs someone visited, the
views they opened, their user agent and their address, and collecting that is a
decision each deployment should make for itself.

Turn it on in **Settings → Telemetry** in the dashboard. It takes effect on the
next page load, needs no restart, and leaves a `telemetry.config.updated` audit
row naming who turned it on. You can also edit this block by hand. The setting
describes the hub, so where two hubs share a directory it belongs in that hub's
[`.cloop/config.ui-<port>.yaml`](#two-dashboards-in-one-directory), which is
where the panel saves it once the file exists.

`sources: [glasses]` is a useful setting: the display-glasses page has no
console and no network inspector, so it can't be debugged any other way, while
the dashboard produces most of the volume and most of the privacy cost.

While collection is on, credentials are scrubbed before storage and the table
keeps at most 50,000 rows. Turning collection off stops new events but deletes
none; remove what was already collected with `cloop hub telemetry prune`. See
[front-end telemetry](../operations/telemetry.md).

#### Resuming a capped run

A run stopped by a Claude Code subscription cap records when the usage window it
hit reopens, because the OAuth usage API reports each window's reset time. This
covers both kinds of cap: a configured `claudecode.max_*_pct`, and a window used
up entirely while `budget.block_extra_usage` (on by default) keeps the run from
going into extra usage. If the window reopens within 90 minutes, the run waits
and then continues. Otherwise the run pauses, shown as *Paused: 5-hour window
exhausted, resumes 23:30* in the dashboard. The hub checks every five minutes
and restarts such runs once the reset time has passed.

A task that the harness cuts off at the limit, ending with *"You've hit your
session limit · resets 11:30pm (UTC)"*, goes back to pending instead of being
recorded as done. The run retries it after the reset time in the message, read
in the time zone the message gives. An auto-evolve round is held the same way,
both before it starts and when the provider answers it with a limit message, so
a plan that runs out of tasks as its window runs out pauses instead of
ending as complete.

```yaml
ui:
  auto_resume_on_cap_reset: true   # the default; set false to require a human
```

| Key | Default | What it does |
| --- | --- | --- |
| `auto_resume_on_cap_reset` | `true` | When false, a run paused by a cap stays paused until someone presses **Run**. The pause reason and its `resumes_at` are recorded either way, so the dashboard still shows when the window reopened. |

Only a usage cap is resumed this way, and only once its reset time has passed.
A run paused by a declined approval, a spent budget, an operator's Stop or a
rejected credential is never restarted on a timer, because each of those is a
decision a resume would override, and none of them ends by itself. A cap whose
reset time the API didn't report is also left alone, because nothing says the
limit has lifted.

Older builds recorded the extra-usage hold as a spent budget with no reset
time: *"Claude Code 5-hour window exhausted (100%) — pausing to avoid
extra usage …"*. A run keeps the build it started with, and an edge device runs
its own build, so such pauses can still appear after the hub is upgraded. The
hub recognises that wording and restarts the run once the usage API shows no
exhausted window. Every other budget pause stays paused.

**Whose account a resume runs on.** On a hub with single sign-on, a resumed run
acts for the person who started the original run (recorded in the hub's own
database when that run was dispatched, or the project's owner for a run older
than that record), and runs on that person's Claude account. On an executor that
shares the hub's filesystem, it uses their own Claude home with the hub's
ambient token cleared, as when they pressed Run. On an isolating executor, it
uses the credential the project is granted for them. The older builds' pauses
described above are judged by that person's own usage windows, not the hub's. A
resume never creates a Claude home and never falls back to the hub's own login.
If the person's home is gone (they were offboarded, or never signed in here),
the hub denies them, or nobody can be named (the hub can't name anyone for a run
started from a shell with `cloop run`), the run stays paused as *starter's
Claude account unavailable*, naming them, and the project's Event History says
why. Press **Run** to start it as yourself. A run started by a token that acts
for no one (the static bearer token, a service token) ran on the hub's own login
and resumes on it. A failover's replacement run follows the same rules. See
[resumed and failed-over runs](../security/claude-code-identity.md#resumed-and-failed-over-runs).

It is on by default because otherwise an unattended fleet would stay paused for
the rest of a weekly window over a limit that had already lifted, at a time the
hub already knew.

#### Hub health cadence

Each hub member runs `cloop hub doctor`'s checks on itself for
**Settings → Hub health** and its header indicator, and pushes a summary of each
report to the dashboards of the administrators connected to it. It reports at a
regular interval, and sooner when one of its configuration files changes, when
an executor, a hub CA rotation step or a sealing key changes, and when someone
presses **Run the checks again**. Open dashboards don't cause extra reports: a
page asks for the report only when its socket opens.

```yaml
ui:
  hub_health_interval: 5m   # the default; a Go duration between 1m and 1h
```

| Key | Default | What it does |
| --- | --- | --- |
| `hub_health_interval` | `5m` | How often a member reports on itself when nothing else triggered a report. A shorter interval shows a certificate nearing expiry or a filling disk sooner, at the cost of one doctor run per interval per member. A value that doesn't parse, or is outside `[1m, 1h]`, runs at the default, and `config.repaired` says so. |

This is per process: where several hub processes share a directory, a member can
set its own value in its `config.ui-<port>.yaml` overlay. See [Hub health in the
dashboard](../operations/runbook.md#hub-health-in-the-dashboard).

### TLS

**Serving.** `cloop ui` and `cloop serve` can terminate TLS themselves, or run
behind a proxy that does. A partial configuration (a certificate without a key,
or the reverse) fails at startup instead of falling back to plaintext, because
a server that serves HTTP after being asked for HTTPS might never be noticed.

```yaml
ui:
  external_url: https://cloop.example.com   # one of the hub's own origins
  allowed_origins: [ops.example.com]        # deployment-wide (dashboard + agents)
  allowed_ws_origins: [legacy.example.com]  # dashboard socket only
  trusted_proxies: [10.42.0.0/16]           # whose X-Forwarded-* to believe (loopback always)
  allowed_hosts: [devbox.lan]               # names a hub WITHOUT sign-in answers to
  tls:
    cert_file: /etc/cloop/tls/fullchain.pem
    key_file:  /etc/cloop/tls/privkey.pem   # mode 0600
    min_version: "1.2"                      # or "1.3"; 1.0/1.1 are rejected
```

Or per invocation: `cloop ui --tls-cert <pem> --tls-key <pem>` (the two flags
together override the config block). Only AEAD cipher suites with forward
secrecy are offered: no CBC and no static RSA. For local development,
`cloop hub tls-init` generates a self-signed pair (the key is written with mode
0600 through `pkg/atomicfile`, so it is never readable by others, even briefly)
and prints the pin to give to devices.

**Proxies: `ui.trusted_proxies`.** Behind a reverse proxy, the hub can't see
the browser's scheme, the host name it used (when the proxy rewrites `Host`), or
the client's address. The proxy passes them in `X-Forwarded-Proto`,
`X-Forwarded-Host` and `X-Forwarded-For`, but any client can send those headers
too. So the hub trusts them only from a peer on loopback (a proxy on this
machine, always trusted) or inside a prefix of `ui.trusted_proxies` (CIDR
prefixes or addresses; one covering every address, `0.0.0.0/0` or `::/0`, is
refused at startup), and ignores them from every other peer. Older builds also
trusted `X-Forwarded-Proto` from any peer once `ui.external_url` was https, and
read `X-Forwarded-For` from its leftmost entry, which a proxy that appends
(nginx's `$proxy_add_x_forwarded_for`) passes through from the client, so anyone
could pick a new address to get around the rate limiter and the sign-in lockout.
`X-Forwarded-For` is now read from the right, skipping trusted proxies, up to
the first address that isn't one.

Add a TLS terminator on another host (an Ingress controller, a load balancer) to
`trusted_proxies`. Otherwise the hub treats that proxy's requests as plaintext:
it refuses `/install.sh`, offers no one-line installer at enrollment, builds
`ws://` agent URLs, and checks a browser without `Sec-Fetch-Site` against an
`http://` origin (with `external_url` set, it still matches). The same list
applies to `cloop serve`. Members of a hub cluster need no entry, because a
request forwarded by another member is signed and carries the browser's scheme
and host with it.

**HSTS and cookies.** Responses delivered over TLS (by the hub's own listener,
or with a trusted proxy's `X-Forwarded-Proto: https`) carry
`Strict-Transport-Security: max-age=31536000; includeSubDomains`. So does every
response from a hub whose public URL (`ui.external_url`, otherwise
`ui.oidc.redirect_url`) is https: the operator has declared the deployment
HTTPS, and a browser ignores the header on a response that arrived over
plaintext. Under `cookie_secure: auto`, the OIDC session cookie becomes
`Secure` + `SameSite=Strict` when the request arrived over TLS by the same rule,
or when `ui.oidc.redirect_url` is https, because the cookie is set on the
response to that URL and so reached the browser over TLS whatever a proxy said.
Otherwise neither is applied on plaintext: HSTS on `http://localhost` would
force a developer's browser to use HTTPS there for a year and break every other
local project on that host name.

**The hub's own origins.** Several checks below ask whether a browser's request
came from one of the hub's own pages. The hub's own origins, matched exactly by
scheme, host and port, are: the origin the request was addressed to (its scheme
and `Host`, or a trusted proxy's `X-Forwarded-Proto` and `X-Forwarded-Host`),
`ui.external_url`, the origin of `ui.oidc.redirect_url`, and
`ui.allowed_origins` (plus `ui.allowed_ws_origins` for the dashboard socket). An
entry is a full origin (`https://ops.example.com`, `http://hub.lan:8081`) or
`host[:port]`, which means https. An `http` origin must be written out in full,
because anyone on the network path can serve one. An entry that doesn't parse
matches nothing and is named in a warning at startup. Loopback isn't treated
specially: a page on `http://localhost:3000` is a different origin from a hub on
`:8080`, and so is another port on the hub's own host name.

**State-changing requests.** A `POST`, `PUT`, `PATCH` or `DELETE` (any method
except `GET`, `HEAD` and `OPTIONS`) is refused with 403 `CROSS_ORIGIN` unless it
carries an `Authorization: Bearer` credential (API tokens, the static token, the
CI relay, executor agents; a page on another origin can attach one only after a
CORS preflight, and the hub allows none), or:

- the browser's `Sec-Fetch-Site` (which every current browser sends and no page
  can set) is `same-origin` or `none`. `same-site` (another port on the hub's
  host, a sibling subdomain) and `cross-site` are refused, whatever else the
  request says;
- without `Sec-Fetch-Site`, its `Origin` is absent (not a browser) or exactly one
  of the hub's own origins.

This applies on every hub, with or without sign-in: a hub with no credential has
nothing for SameSite to protect, and an authenticating proxy's own cookie or
Basic credential is sent along like a session cookie. The request body, if
it has a `Content-Type`, must be `application/json` (`multipart/form-data` on
the three upload routes, `/api/voice`, `/api/transcribe` and
`/api/glasses/transcribe`), or the request is refused with 415
`UNSUPPORTED_MEDIA_TYPE`. Without a preflight, a form or a `fetch(…,
{mode: 'no-cors'})` on another origin can send only form data and `text/plain`.
Every handler reads its JSON body through one decoder (`pkg/jsonbody`) that
refuses the same, and a body with no `Content-Type`. The Anthropic relay under
`/api/ci/anthropic/` passes bodies through unread, and is exempt from the media
type check only. No route accepts a cross-site write. The only one that would
need to, an OIDC callback with `response_mode=form_post`, doesn't exist, because
the hub's callback is a `GET`.

A refusal names `ui.allowed_origins` and the origin the hub thinks the request
was addressed to, is counted in `cloop_cross_origin_refusals_total` and is
audited as `request.origin_refused` (at most 30 rows a minute). The hub sends no
CORS headers to any origin.

**Host names a hub without sign-in answers to: `ui.allowed_hosts`.** On a hub
with neither SSO nor a static token, a request whose `Host` (or trusted
`X-Forwarded-Host`) is not one the hub answers to gets 421
`MISDIRECTED_REQUEST`. DNS rebinding points a name the attacker controls at
127.0.0.1, which makes a page on that name same-origin with a loopback hub, so
every check above would correctly report "same-origin". The hub therefore
refuses the name itself. It answers to `localhost` and `*.localhost`, any IP
address (a browser sends an IP-literal `Host` only to a page whose own origin is
that address), `ui.external_url`'s host, the advertise hosts of its cluster
members, and the entries of `ui.allowed_hosts` (a host name, any port, or
`host:port`). `/healthz` and `/readyz` answer any name. A hub with sign-in
doesn't check, because a rebound name carries none of its credentials. Refusals
are counted (`reason="unknown_host"`) and audited as `request.host_refused`.

**WebSocket origins.** Both the dashboard socket and the executor-agent endpoint
accept an upgrade only from an `Origin` that is exactly one of the hub's own
(see above). A request with no `Origin` is allowed, because every non-browser
agent sends none and a browser can't leave the header out. A cross-origin
upgrade gets 403 with the reason before any token is examined, so it can't use
up a single-use enrollment token on the way to being refused.

The two allowlists differ in what they expose and are kept separate:
`allowed_origins` is deployment-wide and reaches `/api/executors/connect`, where
an entry can open an agent connection; `allowed_ws_origins` applies to the
dashboard socket only. Prefer setting `external_url`, which covers the
reverse-proxy case without either list. Older builds also admitted every
loopback origin and every port of the hub's host name on both endpoints.

**Outbound.** All three remote providers (Anthropic, OpenAI, custom
OpenAI-compatible) and the executor agent validate certificates against the
system CA pool. cloop has no `InsecureSkipVerify` option, and
`tests/security/transport_test.go` fails the build if one appears on the
agent's dial path. To reach a server with a private CA, add a root
(`--ca-file`) instead of turning verification off.

For self-hosted models on plain HTTP (Ollama), set `ollama.base_url` to the
local endpoint. Outbound traffic to Anthropic and OpenAI always uses TLS.

### Shell hooks and command injection

Pre- and post-task hooks (`hooks.pre_task`, `hooks.post_task`, etc.) are shell
commands that users configure in `.cloop/config.yaml`. Task context (title,
status, role) is passed to them as environment variables and never inserted
into the hook command string, so task content can't inject shell commands
through a hook.

### Dependency security

cloop uses `govulncheck` (golang.org/x/vuln) for dependency audits. The
`toolchain` directive in `go.mod` pins the minimum Go version to one that fixes
all known standard library vulnerabilities.

